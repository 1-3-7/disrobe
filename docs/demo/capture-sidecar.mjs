import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
if (args.length !== 4 || args[0] !== "--binary" || args[2] !== "--python") {
  throw new Error("usage: node docs/demo/capture-sidecar.mjs --binary <disrobe> --python <python>");
}
const binary = resolve(args[1]);
const python = resolve(args[3]);
const scratch = mkdtempSync(join(root, "docs/demo/.sidecar-"));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const normalize = (text) => text.replaceAll(JSON.stringify(scratch).slice(1, -1), "demo-project").replaceAll(scratch, "demo-project").replaceAll(scratch.replaceAll("\\", "/"), "demo-project").replaceAll("\r\n", "\n");
const steps = [];
const environment = { ...process.env, PYTHONHASHSEED: "0", PYTHONOPTIMIZE: "0", PYTHONNOUSERSITE: "1", NO_COLOR: "1" };

function run(executable, arguments_) {
  const started = performance.now();
  const result = spawnSync(executable, arguments_, { cwd: scratch, env: environment, encoding: "utf8", windowsHide: true, timeout: 30_000, maxBuffer: 256 * 1024 });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, result.stdout + result.stderr);
  steps.push({ command: [executable === binary ? "disrobe" : "python", ...arguments_.map(normalize)], exit_code: result.status, elapsed_ms: performance.now() - started, stdout: normalize(result.stdout), stderr: normalize(result.stderr) });
  return result.stdout;
}

try {
  const sourcePath = "docs/demo/fixtures/add.py";
  copyFileSync(join(root, sourcePath), join(scratch, "add.py"));
  const initialized = JSON.parse(run(binary, ["init", "--ide", "claude", "--json"]));
  assert.equal(initialized.ide, "claude");
  const skills = readdirSync(join(scratch, ".disrobe/skills")).sort();
  assert.equal(skills.length, 7);
  for (const skill of skills) {
    assert(readFileSync(join(scratch, ".disrobe/skills", skill, "SKILL.md"), "utf8").startsWith("---\n"));
  }
  run(python, ["-m", "py_compile", "add.py"]);
  const compiled = readdirSync(join(scratch, "__pycache__")).filter((name) => name.endsWith(".pyc"));
  assert.equal(compiled.length, 1);
  const bytecode = join("__pycache__", compiled[0]);
  run(binary, ["py", "decompile", bytecode, "--out", "recovered", "--metadata-pack-4", "--llm-briefs", "--metadata-out", "metadata.json"]);
  const recoveredFiles = readdirSync(join(scratch, "recovered"), { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(".py"));
  assert.equal(recoveredFiles.length, 1);
  const recovered = readFileSync(join(recoveredFiles[0].parentPath, recoveredFiles[0].name), "utf8");
  assert.match(recovered, /def add\(/u);
  assert.match(recovered, /return left \+ right/u);
  const metadata = JSON.parse(readFileSync(join(scratch, "metadata.json"), "utf8"));
  assert.equal(metadata.schema, "disrobe.metadata.llm.v1");
  assert.equal(metadata.schema_version, "1.0.0");
  assert.equal(metadata.selection.pack, "pack-4");
  assert.equal(metadata.selection.authorized_decryption_keys, false);
  assert.equal(metadata.input.size_bytes, readFileSync(join(scratch, bytecode)).length);
  assert.equal(Object.keys(metadata.categories).length, 17);
  assert.equal(metadata.categories.ast.entries[0].applicable, true);
  assert.match(metadata.categories.ast.entries[0].value.root.attrs.source, /return left \+ right/u);
  const briefs = Object.fromEntries(["AGENTS.md", "SKILL.md"].map((name) => [name, readFileSync(join(scratch, name), "utf8")]));
  for (const brief of Object.values(briefs)) assert(brief.includes("add"));
  run(python, ["-m", "py_compile", relative(scratch, join(recoveredFiles[0].parentPath, recoveredFiles[0].name))]);
  const files = readdirSync(scratch, { recursive: true, withFileTypes: true }).filter((entry) => entry.isFile());
  assert(files.length <= 100);
  const artifacts = files.map((entry) => {
    const path = join(entry.parentPath, entry.name);
    const bytes = readFileSync(path);
    assert(bytes.length <= 1024 * 1024);
    return { path: relative(scratch, path).replaceAll("\\", "/"), bytes: bytes.length, sha256: hash(bytes) };
  }).sort((left, right) => left.path.localeCompare(right.path));
  const receipt = { schema: "disrobe.demo.sidecar/v1", captured_at: new Date().toISOString(), binary_sha256: hash(readFileSync(binary)), source: { path: sourcePath, sha256: hash(readFileSync(join(root, sourcePath))) }, skills, steps, artifacts, recovered_source: recovered, metadata, reconstruction_briefs: briefs };
  const encoded = JSON.stringify(receipt, (_key, value) => typeof value === "string" ? normalize(value) : value, 2) + "\n";
  assert(Buffer.byteLength(encoded) <= 256 * 1024);
  writeFileSync(join(root, "docs/demo/sidecar.json"), encoded);
  process.stdout.write(`captured ${steps.length} commands, ${skills.length} skills, and the metadata bundle\n`);
} finally {
  const parent = resolve(root, "docs/demo") + sep;
  assert(resolve(scratch).startsWith(parent));
  assert(!lstatSync(scratch).isSymbolicLink());
  rmSync(scratch, { recursive: true, force: false });
}
