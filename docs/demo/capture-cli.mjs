import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { commandTimeoutMs, fixtures, presentation, publicCommands, scenes as plan, validateRecording } from "./cli-plan.mjs";
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
const normalize = (text) => text.replaceAll("\r\n", "\n").replaceAll(scratch.replaceAll("\\", "\\\\"), ".").replaceAll(scratch, ".");
const shellWord = (word) => /^[\w./-]+$/u.test(word) ? word : `'${word.replaceAll("'", "'\\''")}'`;

function files(directory) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const path = join(directory, entry.name);
    if (entry.isSymbolicLink()) {
      assert.ok(realpathSync(path).startsWith(scratch + sep), "Capture link escapes its output directory");
      return [];
    }
    return entry.isDirectory() ? files(path) : [path];
  }).sort();
}

function checkTree() {
  let bytes = 0;
  for (const path of files(scratch)) {
    bytes += statSync(path).size;
    assert.ok(bytes < 16 * 1024 * 1024, "Capture output exceeds 16 MiB");
  }
}

function run(argv) {
  const start = performance.now();
  const result = spawnSync(binary, argv, {
    cwd: scratch, encoding: "utf8", shell: false, windowsHide: true,
    env: { ...process.env, NO_COLOR: "1", RUST_LOG: "off" },
    timeout: commandTimeoutMs, maxBuffer: 1024 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${argv.join(" ")}: ${result.stdout}${result.stderr}`);
  checkTree();
  return { exitCode: result.status, elapsedMs: performance.now() - start, stdout: normalize(result.stdout), stderr: normalize(result.stderr) };
}

function preview(spec) {
  let path;
  if (spec.path) path = join(scratch, spec.path);
  else {
    const candidates = files(join(scratch, spec.directory)).filter((path) => path.endsWith(spec.suffix));
    assert.equal(candidates.length, 1, `Expected one recovered ${spec.suffix} in ${spec.directory}; found ${files(join(scratch, spec.directory)).map((path) => relative(scratch, path)).join(", ")}`);
    [path] = candidates;
  }
  const bytes = readFileSync(path);
  assert.ok(bytes.length > 0 && bytes.length < 1024 * 1024, `Recovered text preview must fit 1 MiB: ${path} has ${bytes.length} bytes`);
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes).replaceAll("\r\n", "\n");
  const startLine = spec.contains ? text.split("\n").findIndex((line) => line.includes(spec.contains)) : 0;
  assert.ok(startLine >= 0, `Preview marker missing in ${path}`);
  return { name: relative(scratch, path).replaceAll("\\", "/"), bytes: bytes.length, sha256: hash(bytes), text, startLine, lineCount: spec.lineCount ?? null, maximumRows: spec.maximumRows ?? 10 };
}

try {
  const version = run(["--version"]).stdout.trim();
  verifyMediaVersion(version, expectedVersion, values["release-tag"]);
  const help = run(["--help"]);
  const catalog = { command: "disrobe --help", commands: publicCommands(help.stdout), ...help };
  mkdirSync(join(scratch, "recovered"));
  for (const [source, name] of fixtures) {
    const bytes = readFileSync(join(root, source));
    assert.ok(bytes.length < 1024 * 1024);
    copyFileSync(join(root, source), join(scratch, name));
    inputs.push({ source, name, bytes: bytes.length, sha256: hash(bytes) });
  }
  const indicators = "https://example.org/download\nanalyst@example.org\n192.0.2.42\n";
  writeFileSync(join(scratch, "indicators.txt"), indicators, { flag: "wx" });
  inputs.push({ name: "indicators.txt", text: indicators, bytes: Buffer.byteLength(indicators), sha256: hash(indicators) });
  for (const spec of plan) {
    const result = run(spec.argv);
    if (spec.redirect) writeFileSync(join(scratch, spec.redirect), result.stdout, { flag: "wx" });
    const command = ["disrobe", ...spec.argv].map(shellWord).join(" ") + (spec.redirect ? ` > ${spec.redirect}` : "");
    scenes.push({ id: spec.id, chapter: spec.chapter, title: spec.title, description: spec.description, durationMs: spec.durationMs, command, argv: ["disrobe", ...spec.argv], redirect: spec.redirect ?? null, outputLineCount: spec.outputLineCount ?? null, ...result, preview: spec.preview ? preview(spec.preview) : null });
    process.stdout.write(`captured ${scenes.length}/${plan.length}: ${spec.id}\n`);
  }
  const wat = scenes.find((scene) => scene.id === "wasm").preview.text;
  assert.ok(wat.includes("i32.add") && wat.includes('(export "add"'));
  const sourceMap = JSON.parse(readFileSync(join(scratch, "bundle.js.map"), "utf8"));
  assert.equal(scenes.find((scene) => scene.id === "sourcemap").preview.text, sourceMap.sourcesContent[sourceMap.sources.indexOf("../src/math.js")]);
  const artifacts = files(scratch).filter((path) => !inputs.some((input) => path === join(scratch, input.name))).map((path) => {
    const bytes = readFileSync(path);
    return { name: relative(scratch, path).replaceAll("\\", "/"), bytes: bytes.length, sha256: hash(bytes) };
  });
  const receipt = { schema: "disrobe.cli-recording.v2", capturedAt, binary: { version, sha256: hash(readFileSync(binary)) }, workspaceVersion: expectedVersion, releaseTag: values["release-tag"] ?? null, presentation, normalization: "Executable name is disrobe; the temporary workspace prefix is '.'; newlines are LF. Redirected stdout is saved as shown. Output excerpts are labeled; complete captured output and preview text are retained here.", catalog, inputs, artifacts, scenes };
  validateRecording(receipt);
  writeFileSync(join(root, "docs/demo/cli-recording.json"), JSON.stringify(receipt, null, 2) + "\n");
  process.stdout.write(JSON.stringify({ commands: scenes.length, publicCommands: catalog.commands.length, durationSeconds: (presentation.openingMs + presentation.closingMs + scenes.reduce((sum, value) => sum + value.durationMs, 0)) / 1000, binary: receipt.binary }, null, 2) + "\n");
} finally {
  assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".cli-") && !lstatSync(scratch).isSymbolicLink());
  rmSync(scratch, { recursive: true });
}
