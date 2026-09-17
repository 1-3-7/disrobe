import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
if (args.length === 0 || args.length % 2 !== 0) {
  throw new Error("usage: node docs/demo/collect-browser.mjs --playground <report.json> [--performance <report.json>] [--docs <report.json>]");
}

const reports = new Map();
for (let index = 0; index < args.length; index += 2) {
  const [id, path] = args.slice(index, index + 2);
  if (id !== "--playground" && id !== "--performance" && id !== "--docs") throw new Error(`unknown report selector: ${id}`);
  if (reports.has(id.slice(2))) throw new Error(`duplicate report selector: ${id}`);
  reports.set(id.slice(2), resolve(path));
}

function flatten(suites) {
  return suites.flatMap((suite) => [
    ...(suite.specs ?? []).flatMap((spec) => spec.tests.flatMap((test) => test.results.map((result) => ({
      name: spec.title,
      file: spec.file,
      project: test.projectName,
      result,
    })))),
    ...flatten(suite.suites ?? []),
  ]);
}

function requireSummary(report, rows, path) {
  if (!Array.isArray(report.errors) || report.errors.length !== 0) {
    throw new Error(`${path} must report no global Playwright errors`);
  }
  const { stats } = report;
  if (stats === null || typeof stats !== "object") throw new Error(`${path} has no Playwright summary`);
  if (!Number.isInteger(stats.expected) || stats.expected <= 0) {
    throw new Error(`${path} must report a positive expected case count`);
  }
  for (const name of ["skipped", "unexpected", "flaky"]) {
    if (!Number.isInteger(stats[name]) || stats[name] !== 0) {
      throw new Error(`${path} reports ${stats[name]} ${name} case(s)`);
    }
  }
  if (rows.length !== stats.expected) {
    throw new Error(`${path} lists ${rows.length} result(s) for ${stats.expected} expected case(s)`);
  }
}

async function collect(path) {
  const bytes = await readFile(path);
  const report = JSON.parse(bytes);
  const rows = flatten(report.suites);
  requireSummary(report, rows, path);
  if (rows.some(({ result }) => result.status !== "passed")) throw new Error(`${path} contains a non-passing result`);
  return {
    report_sha256: createHash("sha256").update(bytes).digest("hex"),
    stats: report.stats,
    cases: rows.map(({ name, file, project }) => ({ name, file, project })),
    rows,
  };
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function accessibility(rows) {
  const values = [];
  for (const { name, project, result } of rows) {
    for (const attachment of result.attachments ?? []) {
      if (!attachment.name.startsWith("accessibility-")) continue;
      const bytes = await readFile(attachment.path);
      const report = JSON.parse(bytes);
      values.push({
        case: name,
        project,
        theme: report.theme,
        engine: report.engine,
        violations: report.violations,
        incomplete_rules: report.incomplete.map((rule) => rule.id),
        passed_rules: report.passes.length,
        sha256: sha256(bytes),
      });
    }
  }
  return values;
}

async function performance(rows) {
  const values = [];
  for (const { result } of rows) {
    for (const attachment of result.attachments ?? []) {
      if (attachment.name !== "performance") continue;
      const bytes = await readFile(attachment.path);
      values.push({ ...JSON.parse(bytes), sha256: sha256(bytes) });
    }
  }
  return values;
}

const receiptPath = resolve(root, "docs/demo/browser.json");
const receipt = JSON.parse(await readFile(receiptPath, "utf8"));
const wasm = await readFile(resolve(root, "playground/src/wasm/disrobe_wasm.wasm"));
receipt.wasm.sha256 = sha256(wasm);

for (const [id, path] of reports) {
  const target = receipt.runs.find((run) => run.id === id);
  if (target === undefined) throw new Error(`browser receipt has no ${id} run`);
  const fresh = await collect(path);
  target.report_sha256 = fresh.report_sha256;
  target.stats = fresh.stats;
  target.cases = fresh.cases;
  if (id === "playground") target.accessibility = await accessibility(fresh.rows);
  if (id === "performance") target.performance = await performance(fresh.rows);
}

await writeFile(receiptPath, `${JSON.stringify(receipt, null, 2)}\n`);
