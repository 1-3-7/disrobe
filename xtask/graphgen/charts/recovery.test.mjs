import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { renderRecovery } from "./recovery.mjs";

function recoveryDoc() {
  return JSON.parse(
    readFileSync(new URL("../../data/recovery.json", import.meta.url), "utf8"),
  );
}

function countPair(doc) {
  for (const group of doc.groups) {
    if (group.kind !== "count_pair") continue;
    const bar = group.bars[0];
    if (bar) return bar;
  }
  throw new Error("recovery.json has no count_pair bar");
}

test("recovery renders every value as an owned root label", () => {
  const svg = renderRecovery(recoveryDoc());
  const percentIds = [...svg.matchAll(/id="disrobe-recovery-percent-value-(\d+)"/g)];
  const pairIds = [...svg.matchAll(/id="disrobe-recovery-count-pair-value-(\d+)"/g)];
  assert.ok(percentIds.length > 0);
  assert.ok(pairIds.length > 0);
  assert.match(
    svg,
    /id="disrobe-recovery-count-pair-value-0"[^>]*dominant-baseline="central"[^>]*xml:space="preserve"/,
  );
  assert.match(svg, />72 decoded root CodeObjects \/ 72<\/text>/);
  assert.match(svg, />v8\/v9 default-trial wrappers<\/text>/);
  assert.doesNotMatch(svg, /<style(?:\s|>)/i);
  assert.doesNotMatch(svg, /:hover/i);
});

test("recovery rejects invalid count-pair values before rendering", () => {
  for (const [delivered, detected] of [
    [0, 0],
    [2, 1],
    [1, Number.MAX_SAFE_INTEGER + 1],
  ]) {
    const doc = recoveryDoc();
    const bar = countPair(doc);
    bar.delivered = delivered;
    bar.detected = detected;
    assert.throws(() => renderRecovery(doc), /count_pair group/);
  }
});
