import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== "--binary" || args[2] !== "--python") {
  throw new Error("usage: node docs/demo/capture-precommit.mjs --binary <disrobe> --python <python-with-pre-commit>");
}
const binary = resolve(args[1]);
const python = resolve(args[3]);
const scratch = mkdtempSync(join(root, "docs/demo/.precommit-"));
const hook = "hooks/pre-commit-gate.sh";
const fixtures = [
  { path: "playground/public/samples/add.wasm", name: "add.wasm", expected_exit: 0 },
  { path: "corpus/native/packers/upx/hello.packed.nrv2b.exe", name: "hello.packed.exe", expected_exit: 1 },
];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const portable = (path) => path.replaceAll("\\", "/");
const normalize = (text) => text.replaceAll(JSON.stringify(scratch).slice(1, -1), "demo-project").replaceAll(scratch, "demo-project").replaceAll(portable(scratch), "demo-project").replaceAll("\r\n", "\n");
const steps = [];
const environment = {
  ...process.env,
  DISROBE_BIN: portable(binary),
  DISROBE_PYTHON: portable(python),
  PRE_COMMIT_HOME: join(scratch, "cache"),
  TMPDIR: portable(join(scratch, "tmp")),
  PRE_COMMIT_COLOR: "never",
  GIT_TERMINAL_PROMPT: "0",
};

function run(executable, arguments_, expected = 0) {
  const started = performance.now();
  const result = spawnSync(executable, arguments_, {
    cwd: scratch, env: environment, encoding: "utf8", windowsHide: true,
    timeout: 45_000, maxBuffer: 256 * 1024,
  });
  if (result.error) throw result.error;
  assert.equal(result.status, expected, result.stdout + result.stderr);
  const record = { argv: [executable === python ? "python" : executable, ...arguments_], exit_code: result.status, elapsed_ms: performance.now() - started, stdout: normalize(result.stdout), stderr: normalize(result.stderr) };
  steps.push(record);
  return record;
}

try {
  mkdirSync(join(scratch, "hooks"));
  mkdirSync(join(scratch, "tmp"));
  copyFileSync(join(root, hook), join(scratch, hook));
  chmodSync(join(scratch, hook), 0o755);
  const manifest = readFileSync(join(root, ".pre-commit-hooks.yaml"), "utf8");
  const config = `repos:\n  - repo: local\n    hooks:\n${manifest.trimEnd().split(/\r?\n/u).map((line) => `      ${line}`).join("\n")}\n`;
  writeFileSync(join(scratch, ".pre-commit-config.yaml"), config, { flag: "wx" });
  for (const fixture of fixtures) copyFileSync(join(root, fixture.path), join(scratch, fixture.name));
  run("git", ["init", "--quiet"]);
  run("git", ["add", "--", ".pre-commit-config.yaml", hook, ...fixtures.map((fixture) => fixture.name)]);
  const version = run(python, ["-m", "pre_commit", "--version"]);
  run(python, ["-m", "pre_commit", "install"]);
  assert.match(readFileSync(join(scratch, ".git/hooks/pre-commit"), "utf8"), /pre_commit/u);
  for (const fixture of fixtures) {
    const result = run(python, ["-m", "pre_commit", "run", "disrobe", "--files", fixture.name, "--verbose"], fixture.expected_exit);
    assert.doesNotMatch(result.stdout + result.stderr, /Skipped|analysis did not complete|analyzer exited|invalid JSON/u);
    if (fixture.expected_exit === 0) assert.match(result.stdout, /Passed/u);
    else assert.match(result.stdout + result.stderr, /native\.packer-unpack/u);
    assert.equal(hash(readFileSync(join(scratch, fixture.name))), hash(readFileSync(join(root, fixture.path))));
  }
  const receipt = {
    schema: "disrobe.demo.precommit/v1", captured_at: new Date().toISOString(),
    binary_sha256: hash(readFileSync(binary)), pre_commit: version.stdout.trim(),
    hook: { path: hook, sha256: hash(readFileSync(join(root, hook))) },
    configuration: config,
    inputs: fixtures.map((fixture) => ({ ...fixture, sha256: hash(readFileSync(join(root, fixture.path))) })),
    steps,
  };
  writeFileSync(join(root, "docs/demo/precommit.json"), JSON.stringify(receipt, null, 2) + "\n");
  process.stdout.write("captured pre-commit installation, allowed WebAssembly, and rejected UPX fixture\n");
} finally {
  const owned = resolve(scratch);
  if (!owned.startsWith(resolve(root, "docs/demo") + sep) || !basename(owned).startsWith(".precommit-") || lstatSync(owned).isSymbolicLink()) {
    throw new Error("pre-commit capture cleanup refused an unexpected scratch path");
  }
  rmSync(owned, { recursive: true });
}
