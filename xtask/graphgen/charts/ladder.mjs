import { Svg, C } from "../lib/kit.mjs";

const WIDTH = 880;
const FIRST_ROW = 148;
const ROW_HEIGHT = 76;

export function renderLadder(doc) {
  const svg = new Svg(WIDTH);
  svg.text(40, 49, doc.title, { size: 26, weight: 600 });
  svg.text(40, 77, doc.subtitle, { size: 14, fill: C.muted });
  const lastRow = FIRST_ROW + (doc.rungs.length - 1) * ROW_HEIGHT;
  svg.line(54, FIRST_ROW, 54, lastRow, { stroke: C.muted });

  for (const [index, rung] of doc.rungs.entries()) {
    const y = FIRST_ROW + index * ROW_HEIGHT;
    svg.circle(54, y, 5, { fill: C.text });
    svg.text(82, y + 6, rung.label, { size: 19, mono: true, weight: 600 });
    svg.text(254, y - 5, rung.sub, { size: 16, weight: 600 });
    svg.text(254, y + 20, rung.detail, { size: 13, fill: C.muted });
    if (index < doc.rungs.length - 1) {
      svg.line(82, y + 43, WIDTH - 40, y + 43);
      svg.path(`M50 ${y + 35}l4 5 4-5`, { stroke: C.muted, strokeWidth: 1.2 });
    }
  }

  svg.line(40, lastRow + 58, WIDTH - 40, lastRow + 58);
  svg.text(40, lastRow + 87, doc.footnote, { size: 13, fill: C.muted });
  return svg.finish(lastRow + 112);
}
