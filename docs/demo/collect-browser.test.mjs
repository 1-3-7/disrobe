import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = fileURLToPath(new URL("../../", import.meta.url));
const collector = fileURLToPath(new URL("./collect-browser.mjs", import.meta.url));
const browserReceipt = join(root, "docs/demo/browser.json");

function report(stats, status = "passed", errors = []) {
  return {
    stats,
    errors,
    suites: [{ specs: [{ title: "case", file: "fixture.spec.ts", tests: [{ projectName: "fixture", results: [{ status }] }] }] }],
  };
}

test("collector rejects incomplete Playwright summaries without changing the receipt", () => {
  const scratch = mkdtempSync(join(tmpdir(), "disrobe-browser-receipt-"));
  const before = createHash("sha256").update(readFileSync(browserReceipt)).digest("hex");
  const cases = [
    ["empty", { expected: 0, skipped: 0, unexpected: 0, flaky: 0 }, "passed"],
    ["skipped", { expected: 1, skipped: 1, unexpected: 0, flaky: 0 }, "skipped"],
    ["flaky", { expected: 1, skipped: 0, unexpected: 0, flaky: 1 }, "passed"],
    ["failed", { expected: 1, skipped: 0, unexpected: 1, flaky: 0 }, "failed"],
    ["global-error", { expected: 1, skipped: 0, unexpected: 0, flaky: 0 }, "passed", [{ message: "global teardown failed" }]],
  ];
  try {
    for (const [name, stats, status, errors] of cases) {
      const fixture = join(scratch, `${name}.json`);
      writeFileSync(fixture, JSON.stringify(report(stats, status, errors)));
      const result = spawnSync(process.execPath, [collector, "--playground", fixture], {
        cwd: root,
        encoding: "utf8",
      });
      assert.notEqual(result.status, 0, `${name} report unexpectedly produced a receipt`);
    }
    const after = createHash("sha256").update(readFileSync(browserReceipt)).digest("hex");
    assert.equal(after, before);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
