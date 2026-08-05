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
import {
  REPRODUCIBILITY,
  TIERS,
  barTiers,
  reproducibilityFor,
  tierFor,
} from "../lib/tiers.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const BAR_WIDTH = 13;
const BAR_RADIUS = 3;
const VALUE_LABEL_SIZE = 11.5;
const PERCENT_LABEL_GAP = 8;
const PAIR_LABEL_GAP = 10;
const LABEL_GUTTER_PAD = 8;
const MIN_PAIR_PLOT_WIDTH = 300;
const TAG_SIZE = 9.5;
const TAG_MARKER = 8;
const TAG_MARKER_GAP = 5;
const TAG_GUTTER_PAD = 10;
const PERCENT_GRID_TOP = 8;
const PERCENT_GRID_BOTTOM = 8;
const PERCENT_ROW_HEIGHT = 27;
const PAIR_GRID_TOP = 7;
const PAIR_GRID_BOTTOM = 7;
const PAIR_ROW_HEIGHT = 36;
const PAIR_STACKED_OFFSET = 8;

function labelGutter(labels, gap) {
  const widest = Math.max(
    ...labels.map((text) => monoWidth(text, VALUE_LABEL_SIZE)),
  );
  return Math.ceil(widest + gap + LABEL_GUTTER_PAD);
}

function trackSeries(rowCount, color) {
  return {
    type: "bar",
    data: Array.from({ length: rowCount }, () => 100),
    barGap: "-100%",
    barWidth: BAR_WIDTH,
    itemStyle: { color, borderRadius: BAR_RADIUS },
    z: 1,
  };
}

function emitValueLabels(svg, labels, x, chartTop, gridTop, rowHeight, prefix, dy = 0) {
  labels.forEach((label, index) => {
    svg.text(x, chartTop + gridTop + (index + 0.5) * rowHeight + dy, label, {
      size: VALUE_LABEL_SIZE,
      fill: C.text,
      mono: true,
      weight: 500,
      anchor: "start",
      id: `${prefix}${index}`,
      dominantBaseline: "central",
      preserveSpace: true,
    });
  });
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
  if (h.startsWith("secret recall")) return "planted apk";
  if (h.startsWith("frisk ioc category recall")) return "";
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

function tierTag(resolved) {
  return `${tierFor(resolved.strength).tag} ${reproducibilityFor(resolved.ci).tag}`;
}

function tagGutter(tags) {
  const widest = Math.max(...tags.map((tag) => monoWidth(tag, TAG_SIZE)));
  return Math.ceil(TAG_MARKER + TAG_MARKER_GAP + widest + TAG_GUTTER_PAD);
}

function emitTierTags(svg, rows, x, chartTop, gridTop, rowHeight, prefix, dy = 0) {
  rows.forEach((row, index) => {
    const centre = chartTop + gridTop + (index + 0.5) * rowHeight + dy;
    const tier = tierFor(row.strength);
    if (row.ci) {
      svg.rect(x, centre - TAG_MARKER / 2, TAG_MARKER, TAG_MARKER, {
        rx: 1.5,
        fill: tier.color,
      });
    } else {
      svg.rect(x + 0.5, centre - TAG_MARKER / 2 + 0.5, TAG_MARKER - 1, TAG_MARKER - 1, {
        rx: 1.5,
        fill: "none",
        stroke: tier.color,
      });
    }
    svg.text(x + TAG_MARKER + TAG_MARKER_GAP, centre, row.tag, {
      size: TAG_SIZE,
      fill: C.muted,
      mono: true,
      anchor: "start",
      id: `${prefix}${index}`,
      dominantBaseline: "central",
      preserveSpace: true,
    });
  });
}

function tierLegend(svg, y) {
  let x = LEFT;
  for (const tier of TIERS) {
    svg.rect(x, y - 7.5, 9, 9, { rx: 2, fill: tier.color });
    svg.text(x + 14, y, tier.label, { size: 10.5, fill: C.muted });
    x += 14 + Math.ceil(sansWidth(tier.label, 10.5)) + 18;
  }
}

function reproducibilityLegend(svg, y) {
  let x = LEFT;
  for (const entry of REPRODUCIBILITY) {
    if (entry.ci) svg.rect(x, y - 7.5, 9, 9, { rx: 2, fill: C.muted });
    else svg.rect(x + 0.5, y - 7, 8, 8, { rx: 2, fill: "none", stroke: C.muted });
    const text = `${entry.tag}, ${entry.label}`;
    svg.text(x + 14, y, text, { size: 10.5, fill: C.faint });
    x += 14 + Math.ceil(sansWidth(text, 10.5)) + 18;
  }
}

function countPairLabel(group, bar, field, fallback) {
  const raw = bar[field];
  if (raw === undefined || raw === null) return fallback;
  if (group.kind !== "count_pair") {
    throw new Error(
      `recovery.json bar ${bar.label} has ${field} outside a count_pair group`,
    );
  }
  if (
    typeof raw !== "string" ||
    !raw ||
    raw.trim() !== raw ||
    /[\u0000-\u001F\u007F-\u009F|]/.test(raw)
  ) {
    throw new Error(`recovery.json bar ${bar.label} has an invalid ${field}`);
  }
  return raw;
}

function countPairDeliveredLabel(group, bar) {
  return countPairLabel(group, bar, "delivered_label", "delivered");
}

function countPairDenominatorLabel(group, bar) {
  return countPairLabel(group, bar, "denominator_label", "detected");
}

function validateCountPairValues(group, bar) {
  if (group.kind !== "count_pair") return;
  if (
    !Number.isSafeInteger(bar.delivered) ||
    bar.delivered < 0 ||
    !Number.isSafeInteger(bar.detected) ||
    bar.detected <= 0 ||
    bar.delivered > bar.detected
  ) {
    throw new Error(
      `recovery.json bar ${bar.label} must carry a non-negative delivered count and a positive detected count no smaller than delivered for a count_pair group`,
    );
  }
}

function validateCountPairBars(doc) {
  for (const group of doc.groups) {
    for (const bar of group.bars) {
      validateCountPairValues(group, bar);
      countPairDeliveredLabel(group, bar);
      countPairDenominatorLabel(group, bar);
    }
  }
}

export function renderRecovery(doc) {
  validateCountPairBars(doc);
  const tiers = barTiers(doc);
  const tierOf = (group, bar) => {
    const resolved = tiers.resolved.get(tiers.key(group.heading, bar.label));
    if (!resolved) {
      throw new Error(
        `recovery.json bar "${tiers.key(group.heading, bar.label)}" reached the renderer with no ` +
          "grading tier, so the chart would present it as strongly as a proven one",
      );
    }
    return {
      strength: resolved.strength,
      ci: resolved.ci,
      tag: tierTag(resolved),
      color: tierFor(resolved.strength).color,
    };
  };
  const percentBars = [];
  for (const group of doc.groups) {
    if (group.kind !== "percent") continue;
    const eco = ecoShort(group.heading);
    for (const bar of group.bars) {
      const qual = qualShort(bar.label);
      percentBars.push({
        label: `${eco} ${qual}`.trim(),
        hint: parentheticalHint(bar.label),
        value: bar.value,
        ...tierOf(group, bar),
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
      const denominatorLabel = countPairDenominatorLabel(group, bar);
      const deliveredLabel = countPairDeliveredLabel(group, bar);
      const pairLabel = `${thousands(bar.delivered)} ${deliveredLabel} / ${thousands(bar.detected)}`;
      pairBars.push({
        label: bar.label.toLowerCase(),
        detected: bar.detected,
        delivered: bar.delivered,
        denominatorLabel,
        pairLabel,
        ...tierOf(group, bar),
      });
    }
  }

  const stats = [];
  for (const group of doc.groups) {
    if (group.kind === "count") {
      for (const bar of group.bars) {
        stats.push({
          value: thousands(bar.value),
          label: statLabel(bar.label),
          ...tierOf(group, bar),
        });
      }
    }
    if (group.kind === "scalar") {
      for (const bar of group.bars) {
        stats.push({
          value: thousands(bar.value),
          label: `${ecoShort(group.heading)} fns parsed`,
          ...tierOf(group, bar),
        });
      }
    }
  }

  const tagGutterWidth = tagGutter(
    [...percentBars, ...pairBars, ...stats].map((b) => b.tag),
  );
  const percentLabels = percentBars.map((b) => `${b.value.toFixed(2)}%`);
  const labelMax = Math.max(...percentBars.map((b) => sansWidth(b.label, 12)));
  const gridLeftA = Math.min(240, Math.max(150, Math.ceil(labelMax) + 18));
  const gridRightA =
    labelGutter(percentLabels, PERCENT_LABEL_GAP) + tagGutterWidth;
  const chartAh = 16 + percentBars.length * PERCENT_ROW_HEIGHT;
  const chartA = renderChart(INNER, chartAh, {
    grid: {
      left: gridLeftA,
      right: gridRightA,
      top: PERCENT_GRID_TOP,
      bottom: PERCENT_GRID_BOTTOM,
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
      trackSeries(percentBars.length, C.panel),
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

  const pairLabels = pairBars.map((b) => b.pairLabel);
  const pairLabelMax = Math.max(...pairBars.map((b) => sansWidth(b.label, 12)));
  const gridLeftB = Math.min(200, Math.max(120, Math.ceil(pairLabelMax) + 18));
  const gridRightB = labelGutter(pairLabels, PAIR_LABEL_GAP);
  if (gridLeftB + gridRightB + MIN_PAIR_PLOT_WIDTH > INNER) {
    throw new Error("recovery count-pair labels leave too little plot width");
  }
  const chartBh = 14 + pairBars.length * PAIR_ROW_HEIGHT;
  const chartB = renderChart(INNER, chartBh, {
    grid: {
      left: gridLeftB,
      right: gridRightB,
      top: PAIR_GRID_TOP,
      bottom: PAIR_GRID_BOTTOM,
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
      trackSeries(pairBars.length, C.subtle),
      {
        type: "bar",
        data: pairBars.map((b) => ({
          value: b.detected > 0 ? (b.delivered / b.detected) * 100 : 0,
          itemStyle: { color: b.color },
        })),
        barWidth: BAR_WIDTH,
        itemStyle: { borderRadius: BAR_RADIUS },
        z: 2,
      },
    ],
  });

  const svg = new Svg(WIDTH);
  svg.push(
    `  <desc>graded from evidence/descriptors sha256:${tiers.digest}</desc>`,
  );
  svg.header(doc.title, doc.subtitle);

  let y = 104;
  sectionLabel(
    svg,
    y,
    "measured recovery",
    "color and tag = how the number was checked, %",
  );
  y += 17;
  tierLegend(svg, y);
  y += 15;
  reproducibilityLegend(svg, y);
  y += 9;
  svg.embed(chartA, LEFT, y);
  emitValueLabels(
    svg,
    percentLabels,
    LEFT + INNER - gridRightA + PERCENT_LABEL_GAP,
    y,
    PERCENT_GRID_TOP,
    PERCENT_ROW_HEIGHT,
    "disrobe-recovery-percent-value-",
  );
  emitTierTags(
    svg,
    percentBars,
    LEFT + INNER - tagGutterWidth,
    y,
    PERCENT_GRID_TOP,
    PERCENT_ROW_HEIGHT,
    "disrobe-recovery-percent-tier-",
  );
  y += chartAh + 22;

  const pairUnit = pairBars.some((b) => b.denominatorLabel !== "detected")
    ? "numerator / denominator"
    : "delivered / detected";
  sectionLabel(svg, y, "detection and coverage breadth", pairUnit);
  y += 12;
  svg.embed(chartB, LEFT, y);
  emitValueLabels(
    svg,
    pairLabels,
    LEFT + INNER - gridRightB + PAIR_LABEL_GAP,
    y,
    PAIR_GRID_TOP,
    PAIR_ROW_HEIGHT,
    "disrobe-recovery-count-pair-value-",
    -PAIR_STACKED_OFFSET,
  );
  emitTierTags(
    svg,
    pairBars,
    LEFT + INNER - gridRightB + PAIR_LABEL_GAP,
    y,
    PAIR_GRID_TOP,
    PAIR_ROW_HEIGHT,
    "disrobe-recovery-count-pair-tier-",
    PAIR_STACKED_OFFSET,
  );
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
      fill: s.color,
      mono: true,
      weight: 600,
    });
    const vw = Math.ceil(s.value.length * 15 * 0.6) + 12;
    svg.text(sx + vw, sy, s.label, { size: 12, fill: C.muted });
    svg.text(sx + vw + Math.ceil(sansWidth(s.label, 12)) + 8, sy, s.tag, {
      size: TAG_SIZE,
      fill: C.faint,
      mono: true,
      id: `disrobe-recovery-stat-tier-${i}`,
      preserveSpace: true,
    });
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
