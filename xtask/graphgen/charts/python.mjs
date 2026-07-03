import { renderChart } from "../lib/echart.mjs";
import { Svg, C, MONO, SANS, wrapSans } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;

function versionLabel(value) {
  const major = Math.floor(value);
  const minor = Math.round((value - major) * 100);
  return `${major}.${minor}`;
}

const KIND_COLOR = {
  disasm: C.faint,
  verified: C.accent,
  range: C.blue,
  partial: C.amber,
};

function baseSegment(tool) {
  return (
    tool.segments.find((s) => s.kind !== "verified") || tool.segments[0]
  );
}

function overSegment(tool) {
  return tool.segments.find((s) => s.kind === "verified") || null;
}

export function renderPython(doc) {
  const { min, max, ticks } = doc.axis;
  const tools = doc.tools;
  const modeByName = {};
  const wrappedByName = {};
  for (const t of tools) {
    modeByName[t.name] = t.mode;
    wrappedByName[t.name] = wrapSans(t.mode, 9.5, 190).slice(0, 2);
  }

  const baseData = tools.map((t) => {
    const seg = baseSegment(t);
    const partial = seg.kind === "partial";
    return {
      value: seg.to - seg.from,
      itemStyle: partial
        ? {
            color: C.panel,
            borderColor: C.amber,
            borderType: "dashed",
            borderWidth: 1,
            borderRadius: 3,
          }
        : { color: KIND_COLOR[seg.kind] || C.blue, borderRadius: 3 },
    };
  });
  const basePad = tools.map((t) => baseSegment(t).from);
  const overData = tools.map((t) => {
    const seg = overSegment(t);
    return seg ? { value: seg.to - seg.from, itemStyle: { color: C.accent, borderRadius: 3 } } : { value: 0 };
  });
  const overPad = tools.map((t) => {
    const seg = overSegment(t);
    return seg ? seg.from : 0;
  });

  const plotH = 20 + tools.length * 54;
  const chart = renderChart(INNER, plotH, {
    grid: { left: 224, right: 20, top: 34, bottom: 8, containLabel: false },
    xAxis: {
      type: "value",
      min,
      max,
      interval: 0.03,
      position: "top",
      axisLine: { show: false },
      axisTick: { show: false },
      splitLine: {
        show: true,
        lineStyle: { color: C.hairline, type: [2, 4] },
      },
      axisLabel: {
        color: C.faint,
        fontFamily: MONO,
        fontSize: 10.5,
        formatter: (v) => versionLabel(v),
      },
    },
    yAxis: {
      type: "category",
      inverse: true,
      data: tools.map((t) => t.name),
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: {
        margin: 14,
        formatter: (name) => {
          const head =
            name === "disrobe" ? `{hi|${name}}` : `{nm|${name}}`;
          const modeLines = wrappedByName[name]
            .map((l) => `{md|${l}}`)
            .join("\n");
          return `${head}\n${modeLines}`;
        },
        rich: {
          hi: { color: C.accent, fontSize: 13, fontWeight: 700, lineHeight: 18, fontFamily: SANS },
          nm: { color: C.text, fontSize: 13, fontWeight: 400, lineHeight: 18, fontFamily: SANS },
          md: { color: C.faint, fontSize: 9.5, lineHeight: 13, fontFamily: SANS },
        },
      },
    },
    series: [
      {
        type: "bar",
        stack: "main",
        barWidth: 15,
        silent: true,
        itemStyle: { color: "transparent" },
        data: basePad,
        z: 1,
      },
      {
        type: "bar",
        stack: "main",
        barWidth: 15,
        data: baseData,
        z: 2,
      },
      {
        type: "bar",
        stack: "over",
        barGap: "-100%",
        barWidth: 15,
        silent: true,
        itemStyle: { color: "transparent" },
        data: overPad,
        z: 3,
      },
      {
        type: "bar",
        stack: "over",
        barGap: "-100%",
        barWidth: 15,
        data: overData,
        z: 4,
      },
    ],
  });

  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);
  const plotTop = 92;
  svg.embed(chart, LEFT, plotTop);

  let y = plotTop + plotH + 18;
  svg.rect(LEFT, y - 9, 3.5, 12, { fill: C.accent });
  svg.text(LEFT + 11, y, "coverage kind", { size: 11.5, fill: C.text, weight: 600 });
  y += 20;
  let lx = LEFT;
  for (const entry of doc.legend) {
    const color = KIND_COLOR[entry.kind] || C.blue;
    if (entry.kind === "partial") {
      svg.rect(lx, y - 9, 16, 10, {
        rx: 2,
        fill: C.panel,
        stroke: C.amber,
      });
    } else {
      svg.rect(lx, y - 9, 16, 10, { rx: 2, fill: color });
    }
    svg.text(lx + 22, y, entry.label, { size: 10.5, fill: C.muted });
    lx += 22 + Math.ceil(entry.label.length * 6.4) + 26;
  }

  const footEnd = svg.footnote(y + 22, doc.footnote);
  return svg.finish(Math.ceil(footEnd + 18));
}
