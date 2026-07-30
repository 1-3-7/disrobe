import { renderChart } from "../lib/echart.mjs";
import {
  Svg,
  C,
  MONO,
  sansWidth,
  monoWidth,
  thousands,
  firstSentence,
} from "../lib/kit.mjs";
import { TIERS, percentBarTiers, tierFor } from "../lib/tiers.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const BAR_WIDTH = 13;
const BAR_RADIUS = 3;
const VALUE_LABEL_SIZE = 11.5;
const PERCENT_LABEL_GAP = 8;
const PAIR_LABEL_GAP = 10;
const LABEL_GUTTER_PAD = 8;

function labelGutter(labels, gap) {
  const widest = Math.max(
    ...labels.map((text) => monoWidth(text, VALUE_LABEL_SIZE)),
  );
  return Math.ceil(widest + gap + LABEL_GUTTER_PAD);
}

function trackSeries(rowCount, color, labels, gap) {
  return {
    type: "bar",
    data: Array.from({ length: rowCount }, () => 100),
    barGap: "-100%",
    barWidth: BAR_WIDTH,
    itemStyle: { color, borderRadius: BAR_RADIUS },
    z: 1,
    label: {
      show: true,
      position: "right",
      distance: gap,
      color: C.text,
      fontFamily: MONO,
      fontSize: VALUE_LABEL_SIZE,
      fontWeight: 500,
      formatter: (p) => labels[p.dataIndex],
    },
  };
}

function ecoShort(heading) {
  const h = heading.toLowerCase();
  if (h.startsWith("python bytecode")) return "python";
  if (h.startsWith("cpython legacy")) return "python legacy";
  if (h.startsWith("webassembly")) return "wasm";
  if (h.startsWith("jvm")) return "jvm";
  if (h.startsWith("go ")) return "go";
  if (h.startsWith("dalvik")) return "dalvik";
  if (h.startsWith("ruby")) return "ruby";
  if (h.startsWith("react native hermes")) return "hermes";
  return heading.split(" ")[0].toLowerCase();
}

function qualShort(label) {
  let q = label.replace(/\([^)]*\)/g, "").trim();
  q = q
    .replace(/\bfull\b\s*/i, "")
    .replace(/\bpinned\b\s*/i, "")
    .replace(/\bmodule\b/gi, "mod")
    .replace(/body-lowering/i, "bodies");
  return q.replace(/\s+/g, " ").trim();
}

function sectionLabel(svg, y, label, unit) {
  svg.rect(LEFT, y - 9, 3.5, 12, { fill: C.accent });
  svg.text(LEFT + 11, y, label, { size: 12, fill: C.text, weight: 600 });
  if (unit)
    svg.text(WIDTH - LEFT, y, unit, {
      size: 10.5,
      fill: C.faint,
      mono: true,
      anchor: "end",
    });
}

function parentheticalHint(label) {
  const inner = label.match(/\(([^)]*)\)/);
  if (!inner) return "";
  const words = inner[1]
    .split(/[\s,]+/)
    .filter((w) => w && !/^(the|of|all|full|set|and)$/i.test(w));
  return words[0] ? words[0].toLowerCase() : "";
}

function tierLegend(svg, y) {
  let x = LEFT;
  for (const tier of TIERS) {
    svg.rect(x, y - 7.5, 9, 9, { rx: 2, fill: tier.color });
    svg.text(x + 14, y, tier.label, { size: 10.5, fill: C.muted });
    x += 14 + Math.ceil(sansWidth(tier.label, 10.5)) + 20;
  }
}

export function renderRecovery(doc) {
  const tiers = percentBarTiers(doc);
  const percentBars = [];
  for (const group of doc.groups) {
    if (group.kind !== "percent") continue;
    const eco = ecoShort(group.heading);
    for (const bar of group.bars) {
      const qual = qualShort(bar.label);
      const resolved = tiers.resolved.get(tiers.key(group.heading, bar.label));
      percentBars.push({
        label: `${eco} ${qual}`.trim(),
        hint: parentheticalHint(bar.label),
        value: bar.value,
        color: tierFor(resolved.strength).color,
      });
    }
  }

  const seen = new Map();
  for (const bar of percentBars) {
    seen.set(bar.label, (seen.get(bar.label) || 0) + 1);
  }
  const used = new Set();
  for (const bar of percentBars) {
    if (seen.get(bar.label) < 2) continue;
    const candidate = bar.hint ? `${bar.label} ${bar.hint}` : bar.label;
    if (candidate !== bar.label && !used.has(candidate)) {
      used.add(candidate);
      bar.label = candidate;
    }
  }
  if (new Set(percentBars.map((b) => b.label)).size !== percentBars.length) {
    const dupes = percentBars
      .map((b) => b.label)
      .filter((l, i, all) => all.indexOf(l) !== i);
    throw new Error(
      `recovery chart would render two bars under the same label (${dupes.join(", ")}); ` +
        "a reader cannot tell which measurement is which, so give the bar a distinguishing " +
        "parenthetical in recovery.json",
    );
  }

  const pairBars = [];
  for (const group of doc.groups) {
    if (group.kind !== "count_pair") continue;
    for (const bar of group.bars) {
      const verb = (bar.delivered_label || "delivered").split(" ")[0];
      pairBars.push({
        label: bar.label.toLowerCase(),
        detected: bar.detected,
        delivered: bar.delivered,
        verb,
      });
    }
  }

  const stats = [];
  for (const group of doc.groups) {
    if (group.kind === "count") {
      for (const bar of group.bars) {
        stats.push({ value: thousands(bar.value), label: statLabel(bar.label) });
      }
    }
    if (group.kind === "scalar") {
      for (const bar of group.bars) {
        stats.push({
          value: thousands(bar.value),
          label: `${ecoShort(group.heading)} fns parsed`,
        });
      }
    }
  }

  const percentLabels = percentBars.map((b) => `${b.value.toFixed(2)}%`);
  const labelMax = Math.max(...percentBars.map((b) => sansWidth(b.label, 12)));
  const gridLeftA = Math.min(240, Math.max(150, Math.ceil(labelMax) + 18));
  const gridRightA = labelGutter(percentLabels, PERCENT_LABEL_GAP);
  const rowA = 27;
  const chartAh = 16 + percentBars.length * rowA;
  const chartA = renderChart(INNER, chartAh, {
    grid: {
      left: gridLeftA,
      right: gridRightA,
      top: 8,
      bottom: 8,
      containLabel: false,
    },
    xAxis: { type: "value", min: 0, max: 100, show: false },
    yAxis: {
      type: "category",
      inverse: true,
      data: percentBars.map((b) => b.label),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: C.muted, fontSize: 12 },
    },
    series: [
      trackSeries(
        percentBars.length,
        C.panel,
        percentLabels,
        PERCENT_LABEL_GAP,
      ),
      {
        type: "bar",
        data: percentBars.map((b) => ({
          value: b.value,
          itemStyle: { color: b.color },
        })),
        barWidth: BAR_WIDTH,
        itemStyle: { borderRadius: BAR_RADIUS },
        z: 2,
      },
    ],
  });

  const pairLabels = pairBars.map(
    (b) => `${thousands(b.delivered)} / ${thousands(b.detected)} ${b.verb}`,
  );
  const pairLabelMax = Math.max(...pairBars.map((b) => sansWidth(b.label, 12)));
  const gridLeftB = Math.min(200, Math.max(120, Math.ceil(pairLabelMax) + 18));
  const gridRightB = labelGutter(pairLabels, PAIR_LABEL_GAP);
  const rowB = 30;
  const chartBh = 14 + pairBars.length * rowB;
  const chartB = renderChart(INNER, chartBh, {
    grid: {
      left: gridLeftB,
      right: gridRightB,
      top: 7,
      bottom: 7,
      containLabel: false,
    },
    xAxis: { type: "value", min: 0, max: 100, show: false },
    yAxis: {
      type: "category",
      inverse: true,
      data: pairBars.map((b) => b.label),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: C.muted, fontSize: 12 },
    },
    series: [
      trackSeries(pairBars.length, C.subtle, pairLabels, PAIR_LABEL_GAP),
      {
        type: "bar",
        data: pairBars.map((b) =>
          b.detected > 0 ? (b.delivered / b.detected) * 100 : 0,
        ),
        barWidth: BAR_WIDTH,
        itemStyle: { color: C.accent, borderRadius: BAR_RADIUS },
        z: 2,
      },
    ],
  });

  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  let y = 104;
  sectionLabel(svg, y, "measured recovery", "bar color = how the number was checked, %");
  y += 17;
  tierLegend(svg, y);
  y += 9;
  svg.embed(chartA, LEFT, y);
  y += chartAh + 22;

  sectionLabel(svg, y, "detection and coverage breadth", "delivered / detected");
  y += 12;
  svg.embed(chartB, LEFT, y);
  y += chartBh + 24;

  sectionLabel(svg, y, "families and scale", null);
  y += 20;
  const colGap = INNER / 2;
  const perCol = Math.ceil(stats.length / 2);
  stats.forEach((s, i) => {
    const col = Math.floor(i / perCol);
    const row = i % perCol;
    const sx = LEFT + col * colGap;
    const sy = y + row * 24;
    svg.text(sx, sy, s.value, {
      size: 15,
      fill: C.accent,
      mono: true,
      weight: 600,
    });
    const vw = Math.ceil(s.value.length * 15 * 0.6) + 12;
    svg.text(sx + vw, sy, s.label, { size: 12, fill: C.muted });
  });
  y += perCol * 24 + 10;

  const footEnd = svg.footnote(y + 4, firstSentence(doc.note));
  return svg.finish(Math.ceil(footEnd + 18));
}

function statLabel(label) {
  return label
    .replace(/\([^)]*\)/g, "")
    .replace(/catalog entries/i, "entries")
    .replace(/obfuscator reversers/i, "reversers")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}
