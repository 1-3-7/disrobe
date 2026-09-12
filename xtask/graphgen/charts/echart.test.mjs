import assert from "node:assert/strict";
import test from "node:test";

import { renderChart } from "../lib/echart.mjs";

test("ECharts static output excludes document-wide style sheets", () => {
  const svg = renderChart(120, 80, {
    xAxis: { type: "value", show: false },
    yAxis: { type: "category", data: ["fixture"], show: false },
    series: [{ type: "bar", data: [1], itemStyle: { color: "#4798ff" } }],
  });
  assert.doesNotMatch(svg, /<style(?:\s|>)/i);
  assert.doesNotMatch(svg, /:hover/i);
  assert.match(svg, /<path\b/);
  assert.match(svg, /fill="#4798ff"/);
});
