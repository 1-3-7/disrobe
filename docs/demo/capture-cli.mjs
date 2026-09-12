import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { verifyMediaVersion, workspaceVersion } from "./media-version.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const { values } = parseArgs({ options: { binary: { type: "string" }, "release-tag": { type: "string" } } });
assert.ok(values.binary, "Usage: node docs/demo/capture-cli.mjs --binary <disrobe> [--release-tag <vX.Y.Z|latest>]");
const binary = resolve(values.binary);
const expectedVersion = workspaceVersion(join(root, "Cargo.toml"));
const scratch = mkdtempSync(join(root, "docs/demo/.cli-"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const inputs = [];
const scenes = [];
const capturedAt = new Date().toISOString();

function checkTree(directory) {
  let bytes = 0;
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      assert.ok(realpathSync(path).startsWith(scratch + sep), "Capture link escapes its output directory");
      bytes += lstatSync(path).size;
    } else {
      bytes += entry.isDirectory() ? checkTree(path) : statSync(path).size;
    }
    assert.ok(bytes < 16 * 1024 * 1024, "Capture output exceeds 16 MiB");
  }
  return bytes;
}

function run(executable, argv) {
  const start = performance.now();
  const result = spawnSync(executable, argv, {
    cwd: scratch, encoding: "utf8", shell: false, windowsHide: true,
    env: { ...process.env, NO_COLOR: "1", RUST_LOG: "off" },
    timeout: 15_000, maxBuffer: 128 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${argv.join(" ")}: ${result.stdout}${result.stderr}`);
  checkTree(scratch);
  return { exitCode: result.status, elapsedMs: performance.now() - start, stdout: result.stdout.replaceAll("\r\n", "\n"), stderr: result.stderr.replaceAll("\r\n", "\n") };
}

function scene(id, title, description, durationMs, argv, markers) {
  const result = run(binary, argv);
  for (const marker of markers) assert.ok((result.stdout + result.stderr).includes(marker), `${id} is missing ${marker}: ${result.stdout}${result.stderr}`);
  scenes.push({ id, title, description, durationMs, command: ["disrobe", ...argv].join(" "), argv: ["disrobe", ...argv], ...result });
}

try {
  const version = run(binary, ["--version"]).stdout.trim();
  verifyMediaVersion(version, expectedVersion, values["release-tag"]);
  mkdirSync(join(scratch, "recovered"));
  for (const [source, name] of [
    ["corpus/native/packers/upx/hello.packed.nrv2b.exe", "hello.packed.exe"],
    ["playground/public/samples/greet.luac", "greet.luac"],
    ["playground/public/samples/add.wasm", "add.wasm"],
  ]) {
    const bytes = readFileSync(join(root, source));
    assert.ok(bytes.length < 1024 * 1024);
    copyFileSync(join(root, source), join(scratch, name));
    inputs.push({ source, name, bytes: bytes.length, sha256: hash(bytes) });
  }
  const indicators = "https://example.org/download\nanalyst@example.org\n192.0.2.42\n";
  writeFileSync(join(scratch, "indicators.txt"), indicators, { flag: "wx" });
  inputs.push({ name: "indicators.txt", text: indicators, bytes: Buffer.byteLength(indicators), sha256: hash(indicators) });
  scene("native", "Unpack a native binary", "Decode the UPX payload from a packed executable.", 6_000,
    ["native", "unpack", "hello.packed.exe", "--out", "recovered/hello.bin"], ["upx"]);
  scene("indicators", "Extract indicators", "Find the URL, email address, and IP address in a file.", 5_000,
    ["ioc", "indicators.txt"], ["https://example.org/download", "analyst@example.org", "192.0.2.42"]);
  scene("auto", "Let Disrobe choose the recovery path", "Identify the module and save its recovery reports and stages.", 5_000,
    ["auto", "add.wasm", "--out", "recovered/auto", "--capture-stages"], ["chain.json", "recovery.json"]);
  scene("lua", "Decompile Lua bytecode", "Recover source from a compiled Lua chunk.", 6_000,
    ["lua", "decompile", "greet.luac", "--out", "recovered/greet.lua"], ["fidelity"]);
  scene("wasm", "Lift WebAssembly to WAT", "Write the module's functions and instructions as text.", 6_000,
    ["wasm", "decompile", "add.wasm", "--target", "wat", "--out", "recovered/add.wat"], ["target=wat"]);
  const wat = readFileSync(join(scratch, "recovered/add.wat"), "utf8").replaceAll("\r\n", "\n");
  assert.ok(wat.includes("i32.add") && wat.includes('(export "add"'));
  const windows = process.platform === "win32";
  const shell = windows ? join(process.env.SystemRoot, "System32/WindowsPowerShell/v1.0/powershell.exe") : "cat";
  const command = windows ? "Get-Content -LiteralPath recovered/add.wat" : "cat recovered/add.wat";
  const argv = windows ? ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command] : ["recovered/add.wat"];
  const result = run(shell, argv);
  assert.equal(result.stdout.trimEnd(), wat.trimEnd());
  scenes.push({ id: "source", title: "Read the recovered instructions", description: "The exported add function retains its two inputs and i32.add instruction.", durationMs: 8_000, command, argv: [windows ? "powershell" : "cat", ...argv], ...result });
  const artifacts = readdirSync(join(scratch, "recovered"), { recursive: true }).filter((name) => statSync(join(scratch, "recovered", name)).isFile()).map((name) => {
    const bytes = readFileSync(join(scratch, "recovered", name));
    return { name: "recovered/" + name, bytes: bytes.length, sha256: hash(bytes) };
  });
  const receipt = { schema: "disrobe.cli-recording.v1", capturedAt, binary: { version, sha256: hash(readFileSync(binary)) }, workspaceVersion: expectedVersion, releaseTag: values["release-tag"] ?? null, presentation: { width: 1920, height: 1080, fps: 60, timing: "Edited command entry and reading time; elapsedMs records each process separately." }, inputs, artifacts, scenes };
  writeFileSync(join(root, "docs/demo/cli-recording.json"), JSON.stringify(receipt, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ commands: scenes.length, durationSeconds: scenes.reduce((sum, value) => sum + value.durationMs, 0) / 1000, binary: receipt.binary, scenes: scenes.map(({ id, stdout, stderr }) => ({ id, stdout, stderr })) }, null, 2) + "\n");
} finally {
  assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".cli-") && !lstatSync(scratch).isSymbolicLink());
  rmSync(scratch, { recursive: true });
}
