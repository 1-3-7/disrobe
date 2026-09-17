import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const arguments_ = process.argv.slice(2);
if (arguments_.length !== 2 || arguments_[0] !== "--binary") {
  throw new Error("usage: node docs/demo/capture.mjs --binary <path-to-full-disrobe-binary>");
}
const binary = resolve(arguments_[1]);
if (!statSync(binary).isFile()) throw new Error("--binary must name a regular executable file");
const source = "playground/public/samples/add.wasm";
const input = readFileSync(join(root, source));
const module_ = new WebAssembly.Module(input);
const exports_ = WebAssembly.Module.exports(module_);
if (WebAssembly.Module.imports(module_).length !== 0 ||
    JSON.stringify(exports_) !== JSON.stringify([{ name: "add", kind: "function" }])) {
  throw new Error("the quickstart fixture must export only add and have no imports");
}
const scratch = mkdtempSync(join(root, "docs", "demo", ".capture-"));
const receipt = join(root, "docs", "demo", "quickstart.json");
const castPath = join(root, "docs", "demo", "disrobe.cast");
const temporaryReceipt = join(scratch, "receipt.json");
const captureTime = new Date();
const captureStart = performance.now();
const maximumBytes = 16 * 1024 * 1024;
const hash = (value) => createHash("sha256").update(value).digest("hex");
const normalize = (value) => value.replaceAll(JSON.stringify(scratch).slice(1, -1), "recovered").replaceAll(scratch, "recovered").replaceAll("\r\n", "\n");

function checkOutputTree(path) {
  let size = 0;
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isSymbolicLink()) {
      const target = realpathSync(child);
      if (!target.startsWith(scratch + sep)) throw new Error("capture link escapes its owned output directory");
      size += lstatSync(child).size;
      continue;
    }
    size += entry.isDirectory() ? checkOutputTree(child) : statSync(child).size;
    if (size > maximumBytes) throw new Error("capture exceeds its 16 MiB output limit");
  }
  return size;
}

function run(id, args) {
  const startedMs = performance.now() - captureStart;
  const result = spawnSync(binary, args, {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, NO_COLOR: "1", RUST_LOG: "off" },
    timeout: 15_000,
    maxBuffer: 128 * 1024,
    windowsHide: true,
    shell: false,
  });
  const elapsedMs = performance.now() - captureStart - startedMs;
  if (result.error) throw result.error;
  if (result.status !== 0) {
    throw new Error(`${id} exited ${result.status}: ${result.stderr}`);
  }
  checkOutputTree(scratch);
  return {
    id,
    argv: ["disrobe", ...args.map(normalize)],
    exit_code: result.status,
    started_ms: startedMs,
    elapsed_ms: elapsedMs,
    stdout: normalize(result.stdout),
    stderr: normalize(result.stderr),
  };
}

try {
  const version = run("version", ["--version"]);
  if (!/^disrobe \d+\.\d+\.\d+(?:[^\r\n]*)?\n?$/.test(version.stdout)) {
    throw new Error("--binary did not identify itself as disrobe");
  }
  const steps = [
    run("module", ["wasm", "decompile", source, "--target", "json", "--out", join(scratch, "add.summary.json")]),
    run("wat", ["wasm", "decompile", source, "--target", "wat", "--out", join(scratch, "add.lifted.wat")]),
    run("auto", ["auto", source, "--out", join(scratch, "auto"), "--capture-stages"]),
  ];
  const watPath = join(scratch, "add.lifted.wat");
  const summary = JSON.parse(readFileSync(join(scratch, "add.summary.json"), "utf8"));
  if (summary.func_count !== 1 || summary.imports.length !== 0 ||
      JSON.stringify(summary.exports) !== JSON.stringify(["add"])) {
    throw new Error("the module summary did not retain the fixture's function and export inventory");
  }
  const wat = readFileSync(watPath, "utf8");
  if (!wat.includes('(export "add"') || !wat.includes("i32.add")) {
    throw new Error("the WAT output did not retain the expected export and addition instruction");
  }
  const chain = JSON.parse(readFileSync(join(scratch, "auto", "chain.json"), "utf8"));
  if (chain.input.size !== input.length || chain.input.path !== source) {
    throw new Error("the automatic recovery report does not identify the captured fixture");
  }
  const record = {
    schema: "disrobe.demo.quickstart/v1",
    captured_at: captureTime.toISOString(),
    binary: { version: version.stdout.trim(), sha256: hash(readFileSync(binary)) },
    input: { path: source, sha256: hash(input), bytes: input.length, exports: exports_ },
    normalization: "Executable path is shown as disrobe; the owned output directory is shown as recovered; newlines are LF. Output is otherwise captured verbatim.",
    checks: { commands_succeeded: steps.length, functions: summary.func_count, imports: summary.imports.length, exports: summary.exports, recovered_instruction: "i32.add" },
    steps,
    artifact: { path: "recovered/add.lifted.wat", sha256: hash(wat), text: wat },
  };
  const encoded = `${JSON.stringify(record, null, 2)}\n`;
  if (Buffer.byteLength(encoded) > 128 * 1024) throw new Error("capture receipt exceeds 128 KiB");
  mkdirSync(dirname(receipt), { recursive: true });
  writeFileSync(temporaryReceipt, encoded, { flag: "wx" });
  renameSync(temporaryReceipt, receipt);
  const events = steps.flatMap((step) => [
    [step.started_ms / 1000, "o", `$ ${step.argv.join(" ")}\r\n`],
    [(step.started_ms + step.elapsed_ms) / 1000, "o", `${step.stdout}${step.stderr}`.replaceAll("\n", "\r\n")],
  ]);
  const cast = [
    { version: 2, width: 128, height: 24, timestamp: Math.floor(captureTime.getTime() / 1000), title: "Disrobe quickstart", theme: { fg: "#ededed", bg: "#0a0a0a" }, description: "Command output captured at process completion. Timings come from quickstart.json." },
    ...events,
  ].map((value) => JSON.stringify(value)).join("\n") + "\n";
  const temporaryCast = join(scratch, "disrobe.cast");
  writeFileSync(temporaryCast, cast, { flag: "wx" });
  renameSync(temporaryCast, castPath);
  process.stdout.write(`captured ${steps.length} commands in ${relative(root, receipt)}\n`);
} finally {
  const owned = resolve(scratch);
  const parent = resolve(root, "docs", "demo") + sep;
  if (!owned.startsWith(parent) || !basename(owned).startsWith(".capture-") || lstatSync(owned).isSymbolicLink()) {
    throw new Error("capture cleanup refused an unexpected scratch path");
  }
  rmSync(owned, { recursive: true });
}
