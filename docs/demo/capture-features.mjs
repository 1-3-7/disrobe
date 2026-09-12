import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
assert.equal(args.length, 6, "usage: node docs/demo/capture-features.mjs --binary <disrobe> --python <python> --lua <lua5.1>");
assert.deepEqual([args[0], args[2], args[4]], ["--binary", "--python", "--lua"]);
const binary = resolve(args[1]);
const python = resolve(args[3]);
const lua = resolve(args[5]);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const scratch = mkdtempSync(join(root, "docs/demo/.features-"));
const normalize = (text) => text.replaceAll(JSON.stringify(scratch).slice(1, -1), "recovered").replaceAll(scratch, "recovered").replaceAll(scratch.replaceAll("\\", "/"), "recovered").replaceAll("\r\n", "\n");
const started = performance.now();
const capturedAt = new Date().toISOString();
const steps = [];
const inputs = [];
const checks = {};

function treeBytes(directory) {
  let bytes = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    assert.ok(!entry.isSymbolicLink(), "capture output contains a symbolic link");
    const path = join(directory, entry.name);
    bytes += entry.isDirectory() ? treeBytes(path) : statSync(path).size;
    assert.ok(bytes <= 16 * 1024 * 1024, "capture output exceeds 16 MiB");
  }
  return bytes;
}

function run(id, executable, argv, expectedExit = 0) {
  const start = performance.now();
  const env = { ...process.env, NO_COLOR: "1", RUST_LOG: "off", LUA_PATH: "", LUA_CPATH: "" };
  delete env.LUA_INIT;
  const result = spawnSync(executable, argv, {
    cwd: root, env, encoding: "utf8", windowsHide: true,
    timeout: 30_000, maxBuffer: 512 * 1024, shell: false,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, expectedExit, `${id}: ${result.stdout}${result.stderr}`);
  treeBytes(scratch);
  const step = {
    id, argv: [executable === binary ? "disrobe" : executable === python ? "python" : "lua", ...argv.map(normalize)],
    exit_code: result.status, started_ms: start - started, elapsed_ms: performance.now() - start,
    stdout: normalize(result.stdout), stderr: normalize(result.stderr),
  };
  steps.push(step);
  return step;
}

function fixture(path, expectedHash) {
  const bytes = readFileSync(join(root, path));
  if (expectedHash !== undefined) assert.equal(hash(bytes), expectedHash, `${path} changed`);
  inputs.push({ path, bytes: bytes.length, sha256: hash(bytes) });
  return bytes;
}

function textSection(bytes) {
  assert.equal(bytes.toString("ascii", 0, 2), "MZ");
  const pe = bytes.readUInt32LE(0x3c);
  assert.equal(bytes.readUInt32LE(pe), 0x4550);
  const sections = bytes.readUInt16LE(pe + 6);
  const first = pe + 24 + bytes.readUInt16LE(pe + 20);
  for (let index = 0; index < sections; index += 1) {
    const offset = first + index * 40;
    if (bytes.toString("ascii", offset, offset + 8).replace(/\0.*$/u, "") !== ".text") continue;
    const length = bytes.readUInt32LE(offset + 8);
    const rawSize = bytes.readUInt32LE(offset + 16);
    const start = bytes.readUInt32LE(offset + 20);
    assert.ok(length > 0 && rawSize >= length && start + length <= bytes.length);
    return bytes.subarray(start, start + length);
  }
  throw new Error("the PE fixture has no .text section");
}

try {
  const wasmPath = "playground/public/samples/add.wasm";
  const wasm = fixture(wasmPath, "41590e7a5a80a64230506645b52617f1978df6e07132f96839cb96b753d7ab9e");
  const pythonPath = "docs/demo/fixtures/add.py";
  const pythonBytes = fixture(pythonPath);
  const iocText = "https://example.org/download\nanalyst@example.org\n192.0.2.42\n";
  const iocPath = join(scratch, "indicators.txt");
  writeFileSync(iocPath, iocText, { flag: "wx" });
  const report = JSON.parse(run("indicators", binary, ["ioc", iocPath, "--json"]).stdout);
  for (const value of ["https://example.org/download", "analyst@example.org", "192.0.2.42"]) {
    assert.ok(report.indicators.some((item) => item.value === value && item.offset === iocText.indexOf(value)), `missing indicator or incorrect offset: ${value}`);
  }
  checks.indicators = { matched: 3, expected: 3, input: iocText, report };

  const archive = join(scratch, "bundle.zip");
  run("archive-create", python, ["-m", "zipfile", "-c", archive, wasmPath, pythonPath]);
  const extracted = join(scratch, "extracted");
  const extraction = JSON.parse(run("archive-extract", binary, ["extract", archive, "--out", extracted, "--json"]).stdout);
  assert.equal(hash(readFileSync(join(extracted, "add.wasm"))), hash(wasm));
  assert.equal(hash(readFileSync(join(extracted, "add.py"))), hash(pythonBytes));
  checks.archive = { matched_files: 2, expected_files: 2, report: extraction };

  const packedPath = "corpus/native/packers/upx/hello.packed.nrv2b.exe";
  fixture(packedPath);
  const original = fixture("corpus/native/packers/upx/hello.original.exe", "37d55b50d63cc0005e0ec2b3070e4d16019f8358ac48c54b4f8e71fc114ee70a");
  const nativeOut = join(scratch, "hello.unpacked.bin");
  run("native-unpack", binary, ["native", "unpack", packedPath, "--out", nativeOut]);
  const expectedText = textSection(original);
  const payload = readFileSync(nativeOut);
  const textOffset = payload.indexOf(expectedText);
  assert.ok(textOffset >= 0, "the decoded payload does not contain the original .text bytes");
  const recoveredText = payload.subarray(textOffset, textOffset + expectedText.length);
  assert.deepEqual(recoveredText, expectedText, "recovered .text differs from the original PE");
  checks.native = { matched_text_bytes: recoveredText.length, expected_text_bytes: expectedText.length, text_offset_in_payload: textOffset, decoded_payload_bytes: payload.length, text_sha256: hash(expectedText), execution: "The packed PE, original PE and decoded payload are read statically." };

  const apkPath = "corpus/apk/fixture-v2v3-signed.apk";
  fixture(apkPath);
  const apkOut = join(scratch, "android");
  const apk = JSON.parse(run("apk-resources", binary, ["apk", apkPath, "--out", apkOut, "--json"]).stdout);
  const manifest = readFileSync(join(apkOut, "AndroidManifest.xml"), "utf8");
  assert.match(manifest, /package="com\.disrobe\.fixture"/u);
  assert.equal(apk.manifest_xml, manifest);
  checks.apk = { package: "com.disrobe.fixture", manifest, report: apk };

  const luaPath = "corpus/lua/obfuscators/hello.prometheus.lua";
  fixture(luaPath);
  fixture("corpus/lua/baseline/hello.lua", "4660ab1ff310887b8f4727933f68eeb74012a5fbc7107d500b146796f0d95b6b");
  const recoveredLua = join(scratch, "hello.recovered.lua");
  run("lua-recover", binary, ["lua", "deobfuscate", luaPath, "--out", recoveredLua]);
  const recoveredLuaBytes = readFileSync(recoveredLua);
  assert.equal(hash(recoveredLuaBytes), "6760aeb071ee1339281b8668eb3d740e9b16c8349f9b49754d2ac28c3b6157e7", "recovered Lua changed; inspect its complete source before execution");
  const baseline = run("lua-baseline", lua, ["corpus/lua/baseline/hello.lua"]);
  const recovered = run("lua-recovered-output", lua, [recoveredLua]);
  assert.equal(baseline.stdout, "hello world\n");
  assert.equal(recovered.stdout, baseline.stdout);
  assert.equal(baseline.stderr, "");
  assert.equal(recovered.stderr, "");
  checks.lua = { compared_programs: 2, matching_outputs: 2, stdout: baseline.stdout, recovered_sha256: hash(recoveredLuaBytes), execution: "Only the baseline and the reviewed recovered greeting are run. The obfuscated input is read statically." };

  const envelope = join(scratch, "add.dr");
  run("envelope-create", binary, ["envelope", "create", wasmPath, "--out", envelope, "--format", "wasm", "--no-cache"]);
  const inspected = run("envelope-inspect", binary, ["envelope", "inspect", envelope]);
  assert.match(inspected.stdout, /rung:\s+Raw/u);
  assert.match(inspected.stdout, /Produces raw v1/u);
  const verified = run("envelope-verify", binary, ["envelope", "verify", envelope]);
  assert.match(verified.stdout, /envelope verify: OK/u);
  const altered = readFileSync(envelope);
  const payloadOffset = altered.indexOf(wasm);
  assert.ok(payloadOffset >= 0, "envelope does not contain the known raw payload");
  altered[payloadOffset + wasm.length - 1] ^= 1;
  const alteredPath = join(scratch, "add.changed.dr");
  writeFileSync(alteredPath, altered, { flag: "wx" });
  const rejected = run("envelope-changed-payload", binary, ["envelope", "verify", alteredPath], 1);
  assert.match(rejected.stderr, /DR-CLI-0087.*envelope failed verification/su);
  checks.envelope = { verified_original: true, rejected_changed_payload: true, changed_payload_bytes: 1 };

  for (const input of inputs) assert.equal(hash(readFileSync(join(root, input.path))), input.sha256, `${input.path} changed during capture`);
  const receipt = {
    schema: "disrobe.demo.features/v1", captured_at: capturedAt,
    reproduction: "node docs/demo/capture-features.mjs --binary <disrobe> --python <python> --lua <lua5.1>",
    binary_sha256: hash(readFileSync(binary)),
    interpreters: { python_sha256: hash(readFileSync(python)), lua_sha256: hash(readFileSync(lua)) },
    normalization: "Executable names, the owned output directory and LF newlines are normalized; command output is otherwise retained.",
    inputs, checks, steps,
  };
  const encoded = JSON.stringify(receipt, null, 2) + "\n";
  assert.ok(Buffer.byteLength(encoded) <= 512 * 1024, "feature receipt exceeds 512 KiB");
  writeFileSync(join(root, "docs/demo/features.json"), encoded);
  process.stdout.write(`captured ${steps.length} commands across ${Object.keys(checks).length} feature groups\n`);
} finally {
  const owned = resolve(scratch);
  assert.ok(owned.startsWith(resolve(root, "docs/demo") + sep) && basename(owned).startsWith(".features-") && !lstatSync(owned).isSymbolicLink(), "unexpected capture cleanup path");
  rmSync(owned, { recursive: true });
}
