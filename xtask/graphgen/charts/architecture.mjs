import { Svg, C, wrapSans } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const ROW_H = 96;
const NODE_H = 52;
const ARROW = 26;
const GAP = 22;

function nodeStyle(kind) {
  if (kind === "input") return { fill: C.surface, stroke: C.subtle, label: C.text };
  if (kind === "output") return { fill: C.surface, stroke: C.accent, label: C.accent };
  return { fill: C.panel, stroke: C.hairline, label: C.text };
}

function arrow(svg, x0, x1, y) {
  svg.line(x0, y, x1 - 5, y, { stroke: C.accent, strokeWidth: 1.4 });
  svg.path(
    `M${(x1 - 5).toFixed(1)},${(y - 4).toFixed(1)} L${(x1 + 1).toFixed(1)},${y.toFixed(1)} L${(x1 - 5).toFixed(1)},${(y + 4).toFixed(1)} Z`,
    { fill: C.accent },
  );
}

export function renderArchitecture(doc) {
  const plotTop = 92;
  const height = plotTop + doc.chains.length * ROW_H + 8;
  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  let y = plotTop;
  for (const chain of doc.chains) {
    svg.text(LEFT, y + 12, chain.name, { size: 12, fill: C.muted, weight: 500 });
    const rowY = y + 22;
    const n = chain.nodes.length;
    const nodeW = (INNER - (n - 1) * (GAP + ARROW)) / n;
    let nx = LEFT;
    chain.nodes.forEach((node, idx) => {
      const st = nodeStyle(node.kind);
      svg.rect(nx, rowY, nodeW, NODE_H, { rx: 7, fill: st.fill, stroke: st.stroke });
      const cx = nx + nodeW / 2;
      if (node.note) {
        svg.text(cx, rowY + NODE_H / 2 - 3, node.label, {
          size: 13,
          fill: st.label,
          mono: true,
          anchor: "middle",
          weight: 600,
        });
        const noteLines = wrapSans(node.note, 9.5, nodeW - 16).slice(0, 2);
        noteLines.forEach((ln, li) => {
          svg.text(cx, rowY + NODE_H / 2 + 12 + li * 11, ln, {
            size: 9.5,
            fill: C.faint,
            anchor: "middle",
          });
        });
      } else {
        svg.text(cx, rowY + NODE_H / 2 + 5, node.label, {
          size: 13,
          fill: st.label,
          mono: true,
          anchor: "middle",
          weight: 600,
        });
      }
      if (idx + 1 < n) {
        arrow(svg, nx + nodeW + 6, nx + nodeW + GAP + ARROW - 6, rowY + NODE_H / 2);
      }
      nx += nodeW + GAP + ARROW;
    });
    y += ROW_H;
  }
  return svg.finish(Math.ceil(height));
}
