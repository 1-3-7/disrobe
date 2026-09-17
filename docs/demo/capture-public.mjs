import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../", import.meta.url));
const args = process.argv.slice(2);
assert.ok(args.length === 2 && args[0] === "--binary", "usage: node docs/demo/capture-public.mjs --binary <disrobe>");
const binary = resolve(args[1]);
const argv = ["prowl", "example.org", "--sources", "commoncrawl", "--max-pages", "1", "--max-urls", "10", "--max-iocs", "10", "--retries", "0", "--timeout", "10", "--concurrency", "1", "--per-host-rps", "1", "--no-iocs", "--json"];
const capturedAt = new Date().toISOString();
const started = performance.now();
const result = spawnSync(binary, argv, {
  cwd: root, env: { ...process.env, NO_COLOR: "1", RUST_LOG: "off" },
  encoding: "utf8", windowsHide: true, timeout: 20_000, maxBuffer: 128 * 1024, shell: false,
});
if (result.error) throw result.error;
assert.equal(result.status, 0, result.stdout + result.stderr);
const report = JSON.parse(result.stdout);
assert.deepEqual(report.targets, ["example.org"]);
assert.deepEqual(report.sources, ["common_crawl"]);
assert.equal(report.providers.length, 1);
assert.equal(report.providers[0].outcome, "ok", JSON.stringify(report.providers[0]));
assert.equal(report.url_total, report.urls.length);
assert.ok(report.url_total > 0 && report.url_total <= 10);
for (const row of report.urls) {
  const url = new URL(row.url);
  assert.equal(url.hostname, "example.org");
  assert.equal(row.source, "common_crawl");
}
assert.equal(report.ioc_total, 0);
const receipt = {
  schema: "disrobe.demo.public-collection/v1", captured_at: capturedAt,
  scope: "One Common Crawl archive index queried for the reserved example.org domain.",
  reproduction: "node docs/demo/capture-public.mjs --binary <disrobe>",
  binary_sha256: createHash("sha256").update(readFileSync(binary)).digest("hex"),
  argv: ["disrobe", ...argv], exit_code: result.status, elapsed_ms: performance.now() - started,
  stdout: result.stdout.replaceAll("\r\n", "\n"), stderr: result.stderr.replaceAll("\r\n", "\n"), report,
};
writeFileSync(join(root, "docs/demo/public-collection.json"), JSON.stringify(receipt, null, 2) + "\n");
process.stdout.write(`captured ${report.url_total} archived example.org URLs\n`);
