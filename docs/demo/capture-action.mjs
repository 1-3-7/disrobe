import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, delimiter, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 6 || args[0] !== "--binary" || args[2] !== "--bash" || args[4] !== "--python") {
  throw new Error("usage: node docs/demo/capture-action.mjs --binary <disrobe> --bash <bash> --python <python>");
}
const binary = resolve(args[1]);
const bash = resolve(args[3]);
const python = resolve(args[5]);
const action = readFileSync(join(root, "action.yml"), "utf8");
const step = action.match(/^      id: run\r?\n[\s\S]*?^      run: \|\r?\n([\s\S]*?)(?=^    - name:)/mu);
assert.ok(step, "action.yml has no run step");
const script = step[1].split(/\r?\n/u).map((line) => {
  assert.ok(line.length === 0 || line.startsWith("        "), "unexpected run-step indentation");
  return line.slice(8);
}).join("\n");
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const portable = (path) => path.replaceAll("\\", "/");
const scratch = mkdtempSync(join(root, "docs/demo/.action-"));
const normalize = (text) => text.replaceAll(JSON.stringify(scratch).slice(1, -1), "demo-project").replaceAll(scratch, "demo-project").replaceAll(portable(scratch), "demo-project").replaceAll("\r\n", "\n");
const fixture = "playground/public/samples/add.wasm";
const cases = [];

try {
  const version = spawnSync(python, ["--version"], { encoding: "utf8", windowsHide: true, timeout: 10_000, maxBuffer: 4096 });
  if (version.error) throw version.error;
  assert.equal(version.status, 0, version.stderr);
  mkdirSync(join(scratch, "bin"));
  writeFileSync(join(scratch, "bin/python3"), '#!/usr/bin/env bash\nexec "${DISROBE_DEMO_PYTHON:?}" "$@"\n', { flag: "wx" });
  chmodSync(join(scratch, "bin/python3"), 0o755);
  writeFileSync(join(scratch, "run-action.sh"), script, { flag: "wx" });
  for (const command of ["detect", "auto"]) {
    const directory = join(scratch, command);
    mkdirSync(directory);
    copyFileSync(join(root, fixture), join(directory, "add.wasm"));
    const started = performance.now();
    const result = spawnSync(bash, ["--noprofile", "--norc", "../run-action.sh"], {
      cwd: directory,
      env: {
        ...process.env,
        PATH: join(scratch, "bin") + delimiter + process.env.PATH,
        DISROBE_DEMO_PYTHON: portable(python),
        RUST_LOG: "off", NO_COLOR: "1",
        DR_COMMAND: command, DR_ARGS: "", DR_PATH: "add.wasm", DR_OUT: "recovered",
        DR_SARIF: "disrobe.sarif", DR_FAIL_ON: "failed", DR_BIN: portable(binary),
        GITHUB_OUTPUT: "github-output.txt", GITHUB_STEP_SUMMARY: "github-summary.md",
      },
      encoding: "utf8", windowsHide: true, timeout: 45_000, maxBuffer: 256 * 1024,
    });
    if (result.error) throw result.error;
    assert.equal(result.status, 0, result.stdout + result.stderr);
    const sarifBytes = readFileSync(join(directory, "disrobe.sarif"));
    const sarif = JSON.parse(sarifBytes.toString("utf8"));
    assert.equal(sarif.version, "2.1.0");
    assert.ok(sarif.runs.length > 0);
    for (const run of sarif.runs) {
      assert.equal(run.tool.driver.name, "disrobe");
      assert.ok(Array.isArray(run.results));
    }
    const output = readFileSync(join(directory, "github-output.txt"), "utf8");
    assert.match(output, /^sarif=disrobe\.sarif$/mu);
    assert.match(output, /^verdict=ok$/mu);
    if (command === "auto") assert.match(output, /from the chain recovery report/u);
    assert.equal(hash(readFileSync(join(directory, "add.wasm"))), hash(readFileSync(join(root, fixture))));
    cases.push({
      command, fail_on: "failed", exit_code: result.status, elapsed_ms: performance.now() - started,
      stdout: normalize(result.stdout), stderr: normalize(result.stderr),
      analyzer_log: normalize(readFileSync(join(directory, "disrobe.log"), "utf8")),
      outputs: normalize(output), summary: normalize(readFileSync(join(directory, "github-summary.md"), "utf8")),
      sarif_sha256: hash(sarifBytes), sarif,
    });
  }
  const receipt = {
    schema: "disrobe.demo.github-action/v1", captured_at: new Date().toISOString(),
    scope: "Local execution of the composite Action's exact run step with the built CLI, including SARIF validation and recovery grading.",
    python: version.stdout.trim(),
    python_command: "python3 invokes the supplied Python interpreter.",
    binary_sha256: hash(readFileSync(binary)),
    action: { path: "action.yml", sha256: hash(readFileSync(join(root, "action.yml"))), run_step_sha256: hash(script) },
    input: { path: fixture, sha256: hash(readFileSync(join(root, fixture))), bytes: readFileSync(join(root, fixture)).length },
    reproduction: "node docs/demo/capture-action.mjs --binary <disrobe> --bash <bash> --python <python>",
    cases,
  };
  writeFileSync(join(root, "docs/demo/github-action.json"), JSON.stringify(receipt, null, 2) + "\n");
  process.stdout.write("captured Action detect and auto runs with validated SARIF and recovery grading\n");
} finally {
  const owned = resolve(scratch);
  if (!owned.startsWith(resolve(root, "docs/demo") + sep) || !basename(owned).startsWith(".action-") || lstatSync(owned).isSymbolicLink()) {
    throw new Error("Action capture cleanup refused an unexpected scratch path");
  }
  rmSync(owned, { recursive: true });
}
