// Round-trip smoke test for the disrobe-wasm C-ABI in a real WebAssembly runtime.
//
// Loads target/wasm32-unknown-unknown/release/disrobe_wasm.wasm, marshals tracked
// sample inputs through the documented [u32 LE len][JSON] protocol, and prints the
// JSON each entry point returns. Run with: node crates/disrobe-wasm/tools/smoke.mjs

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const wasmPath = resolve(
  repoRoot,
  "target/wasm32-unknown-unknown/release/disrobe_wasm.wasm",
);

const fixtures = resolve(here, "..", "tests", "fixtures");
const samplePyc = readFileSync(resolve(fixtures, "sample.pyc"));
const benignPickle = readFileSync(resolve(fixtures, "benign_list.pkl"));
const maliciousPickle = readFileSync(resolve(fixtures, "reduce_os_system.pkl"));
const minimalWasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

const bytes = readFileSync(wasmPath);
const { instance } = await WebAssembly.instantiate(bytes, {});
const wasm = instance.exports;
const memory = wasm.memory;

const RESULT_HEADER_LEN = 4;

function writeInput(data) {
  const len = data.length;
  const ptr = wasm.disrobe_alloc(len);
  if (ptr === 0 && len !== 0) throw new Error("disrobe_alloc returned null");
  new Uint8Array(memory.buffer, ptr, len).set(data);
  return ptr;
}

function readResult(ptr) {
  if (ptr === 0) throw new Error("entry point returned null result");
  const header = new DataView(memory.buffer, ptr, RESULT_HEADER_LEN);
  const payloadLen = header.getUint32(0, true);
  const payload = new Uint8Array(
    memory.buffer,
    ptr + RESULT_HEADER_LEN,
    payloadLen,
  );
  const json = JSON.parse(new TextDecoder("utf-8").decode(payload));
  wasm.disrobe_result_free(ptr);
  return json;
}

function call(name, data) {
  const input = writeInput(data);
  let result;
  try {
    result = wasm[name](input, data.length);
  } finally {
    wasm.disrobe_free(input, data.length);
  }
  return readResult(result);
}

function show(label, json) {
  const text = JSON.stringify(json);
  const trimmed = text.length > 1400 ? `${text.slice(0, 1400)}…` : text;
  console.log(`\n=== ${label} ===`);
  console.log(trimmed);
}

const exportNames = Object.keys(wasm).sort();
console.log("wasm exports:", exportNames.join(", "));
console.log(`wasm size: ${bytes.length} bytes`);
console.log(
  `wasm imports: ${WebAssembly.Module.imports(await WebAssembly.compile(bytes)).length}`,
);

let failures = 0;
function expect(label, cond) {
  if (!cond) {
    failures += 1;
    console.error(`ASSERT FAILED: ${label}`);
  }
}

const detectPyc = call("detect", samplePyc);
show("detect(sample.pyc)", detectPyc);
expect("detect pyc", detectPyc.format === "pyc");

const detectPickle = call("detect", maliciousPickle);
show("detect(reduce_os_system.pkl)", detectPickle);
expect("detect pickle", detectPickle.format === "pickle");

const detectWasm = call("detect", minimalWasm);
show("detect(minimal .wasm)", detectWasm);
expect("detect wasm", detectWasm.format === "wasm");

const disasm = call("py_disasm", samplePyc);
show("py_disasm(sample.pyc)", disasm);
expect("py_disasm ok", disasm.ok === true && disasm.instruction_count > 0);

const decompile = call("py_decompile", samplePyc);
show("py_decompile(sample.pyc)", decompile);
expect("py_decompile ok", decompile.ok === true && decompile.source.length > 0);

const pickleDisasm = call("pickle_disasm", benignPickle);
show("pickle_disasm(benign_list.pkl)", pickleDisasm);
expect("pickle_disasm ok", pickleDisasm.ok === true && pickleDisasm.opcode_count > 0);

const safety = call("pickle_safety", maliciousPickle);
show("pickle_safety(reduce_os_system.pkl)", safety);
expect(
  "pickle_safety flags",
  safety.ok === true && safety.severity !== "Benign" && safety.finding_count > 0,
);

const wasmAnalyze = call("wasm_analyze", minimalWasm);
show("wasm_analyze(minimal .wasm)", wasmAnalyze);
expect("wasm_analyze ok", wasmAnalyze.ok === true);

const malformed = call("py_disasm", Uint8Array.from([0, 1, 2]));
show("py_disasm(malformed) -> error path", malformed);
expect("malformed is error", malformed.ok === false);

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall smoke assertions passed");
