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

test("recovery tags every bar with how it was graded", () => {
  const doc = recoveryDoc();
  const counts = { percent: 0, count_pair: 0, stat: 0 };
  for (const group of doc.groups) {
    if (group.kind === "percent") counts.percent += group.bars.length;
    else if (group.kind === "count_pair") counts.count_pair += group.bars.length;
    else counts.stat += group.bars.length;
  }
  const svg = renderRecovery(doc);
  const drawn = (prefix) => [...svg.matchAll(new RegExp(`id="${prefix}(\\d+)"`, "g"))].length;
  assert.equal(drawn("disrobe-recovery-percent-tier-"), counts.percent);
  assert.equal(drawn("disrobe-recovery-count-pair-tier-"), counts.count_pair);
  assert.equal(drawn("disrobe-recovery-stat-tier-"), counts.stat);
  assert.match(svg, /<desc>graded from evidence\/descriptors sha256:[0-9a-f]{32}<\/desc>/);
  for (const [, tag] of svg.matchAll(/id="disrobe-recovery-[a-z-]*tier-\d+"[^>]*>([^<]+)</g)) {
    assert.match(tag, /^(strong|recompile|pass-gated|self-reported) (CI|local)$/);
  }
});

test("recovery refuses to draw a bar no evidence grades", () => {
  const doc = recoveryDoc();
  const group = doc.groups.find((g) => g.kind === "percent");
  group.bars.push({
    label: "a bar nothing grades",
    value: 100,
    source: "a sentence that cites no grading instrument at all",
  });
  assert.throws(() => renderRecovery(doc), /carries no recorded grading strength/);
});

test("recovery refuses a fallback tier that outruns the bar's own record", () => {
  const doc = recoveryDoc();
  for (const g of doc.groups) {
    for (const bar of g.bars) {
      if (bar.label !== ".NET protectors") continue;
      bar.source = bar.source.replace(
        "This is a detection roster, not an aggregate claim",
        "This roster is graded end to end",
      );
    }
  }
  assert.throws(() => renderRecovery(doc), /no longer contains/);
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
