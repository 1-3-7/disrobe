import { Svg, C, wrapSans, monoWidth } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const PLOT_TOP = 100;
const NODE_H = 58;
const ARROW = 26;
const GAP = 14;
const DETAIL_TOP = 190;
const DETAIL_ROW = 30;

function arrow(svg, x0, x1, y) {
  svg.line(x0, y, x1 - 5, y, { stroke: C.accent, strokeWidth: 1.4 });
  svg.path(
    `M${(x1 - 5).toFixed(1)},${(y - 4.5).toFixed(1)} L${(x1 + 1).toFixed(1)},${y.toFixed(1)} L${(x1 - 5).toFixed(1)},${(y + 4.5).toFixed(1)} Z`,
    { fill: C.accent },
  );
}

export function renderLadder(doc) {
  const n = doc.rungs.length;
  const nodeW = (INNER - (n - 1) * (GAP + ARROW)) / n;
  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  let nx = LEFT;
  doc.rungs.forEach((rung, idx) => {
    const terminal = idx + 1 === n;
    const st = terminal
      ? { fill: C.surface, stroke: C.accent, label: C.accent }
      : idx === 0
        ? { fill: C.surface, stroke: C.subtle, label: C.text }
        : { fill: C.panel, stroke: C.hairline, label: C.text };
    svg.rect(nx, PLOT_TOP, nodeW, NODE_H, { rx: 8, fill: st.fill, stroke: st.stroke });
    const cx = nx + nodeW / 2;
    svg.text(cx, PLOT_TOP + 26, rung.label, {
      size: 16,
      fill: st.label,
      mono: true,
      anchor: "middle",
      weight: 600,
    });
    svg.text(cx, PLOT_TOP + 44, rung.sub, {
      size: 10.5,
      fill: C.faint,
      anchor: "middle",
    });
    if (!terminal) {
      arrow(svg, nx + nodeW + 5, nx + nodeW + GAP + ARROW - 5, PLOT_TOP + NODE_H / 2);
    }
    nx += nodeW + GAP + ARROW;
  });

  const labelW = Math.max(...doc.rungs.map((r) => monoWidth(r.label, 12))) + 20;
  let dy = DETAIL_TOP;
  for (const rung of doc.rungs) {
    svg.text(LEFT, dy, rung.label, { size: 12, fill: C.text, mono: true, weight: 600 });
    const lines = wrapSans(rung.detail, 11.5, INNER - labelW);
    lines.forEach((ln, li) => {
      svg.text(LEFT + labelW, dy + li * 15, ln, { size: 11.5, fill: C.muted });
    });
    dy += Math.max(DETAIL_ROW, lines.length * 15 + 12);
  }

  const footEnd = svg.footnote(dy + 2, doc.footnote);
  return svg.finish(Math.ceil(footEnd + 18));
}
