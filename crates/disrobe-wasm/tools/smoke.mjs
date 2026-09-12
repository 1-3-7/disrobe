import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "..", "..", "..");
const wasmPath = resolve(
  process.env.CARGO_TARGET_DIR ?? resolve(repoRoot, "target"),
  "wasm32-unknown-unknown/release/disrobe_wasm.wasm",
);

const fixtures = resolve(here, "..", "tests", "fixtures");
const samplePyc = readFileSync(resolve(fixtures, "sample.pyc"));
const benignPickle = readFileSync(resolve(fixtures, "benign_list.pkl"));
const maliciousPickle = readFileSync(resolve(fixtures, "reduce_os_system.pkl"));
const minimalWasm = Uint8Array.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);

const bytes = readFileSync(wasmPath);
const { module, instance } = await WebAssembly.instantiate(bytes, {});
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
const importCount = WebAssembly.Module.imports(module).length;
console.log(`wasm imports: ${importCount}`);

let failures = 0;
function expect(label, cond) {
  if (!cond) {
    failures += 1;
    console.error(`ASSERT FAILED: ${label}`);
  }
}

expect("standalone module has no imports", importCount === 0);

const dartFixtureRoot = resolve(repoRoot, "crates/disrobe-pass-mobile/tests/fixtures/flutter_symbol_dart_3_12_2");
const dart = call("dart_kernel", readFileSync(resolve(dartFixtureRoot, "symbol_probe.app.dill")));
expect("Dart source matches the compiled original", dart.ok === true && dart.kernel.sources.length === 1 && dart.kernel.sources[0].text === readFileSync(resolve(dartFixtureRoot, "symbol_probe.dart"), "utf8"));

const pharInput = readFileSync(resolve(repoRoot, "corpus/php/phar/bzip2.phar"));
const phar = call("phar_list", pharInput);
expect("PHAR member listing", phar.ok === true && phar.entries.length === 3 && phar.entries[2].name === "lib/math.php");
const pharPtr = writeInput(pharInput);
const memberPtr = wasm.phar_extract(pharPtr, pharInput.length, 2);
if (memberPtr === 0) throw new Error("PHAR extraction returned null");
const memberLength = wasm.disrobe_result_len(memberPtr);
const memberFrame = new Uint8Array(memory.buffer, memberPtr + RESULT_HEADER_LEN, memberLength);
expect("PHAR binary framing and original bytes", memberFrame[0] === 0 && Buffer.from(memberFrame.subarray(1)).equals(readFileSync(resolve(repoRoot, "corpus/php/phar-bz2/src/lib/math.php"))));
wasm.disrobe_result_free(memberPtr);
wasm.disrobe_free(pharPtr, pharInput.length);

const memoryLayout = call("wasm_memories", bytes);
const memories = Object.values(memoryLayout.report.memories);
expect("engine has one bounded memory", memories.length === 1 && memories[0].maximum === 8192);
show("engine memory limits", memoryLayout);

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

const phpSource = new TextEncoder().encode(
  "<?php\n$code = base64_decode('ZWNobyAiaGVsbG8gZnJvbSBkaXNyb2JlIjs=');\neval($code);\n?>",
);
const php = call("php_detect", phpSource);
show("php_detect(base64 eval chain)", php);
expect("PHP source classification", php.ok === true && php.detection.kind === "Source");
expect("PHP recovered echo", php.recovery.output.includes('echo "hello from disrobe";'));

const malformed = call("py_disasm", Uint8Array.from([0, 1, 2]));
show("py_disasm(malformed) -> error path", malformed);
expect("malformed is error", malformed.ok === false);

if (failures > 0) {
  console.error(`\n${failures} assertion(s) failed`);
  process.exit(1);
}
console.log("\nall smoke assertions passed");
