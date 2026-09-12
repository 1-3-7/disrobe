import { Svg, C, sansWidth } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const ECO_X = 28;
const ORACLE_X = 200;
const RESULT_X = 470;
const ROW_H = 40;

export function renderVerification(doc) {
  const plotTop = 92;
  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  svg.text(ECO_X, plotTop, "ecosystem", { size: 10.5, fill: C.faint, weight: 600, letterSpacing: 0.5 });
  svg.text(ORACLE_X, plotTop, "independent oracle", { size: 10.5, fill: C.faint, weight: 600, letterSpacing: 0.5 });
  svg.text(RESULT_X, plotTop, "result", { size: 10.5, fill: C.faint, weight: 600, letterSpacing: 0.5 });
  svg.text(WIDTH - LEFT, plotTop, "gate", { size: 10.5, fill: C.faint, weight: 600, letterSpacing: 0.5, anchor: "end" });

  let y = plotTop + 14;
  for (const row of doc.rows) {
    svg.line(LEFT, y, WIDTH - LEFT, y, { stroke: C.subtle });
    const cy = y + ROW_H / 2 + 4;
    svg.text(ECO_X, cy, row.ecosystem, { size: 12.5, fill: C.text, weight: 600 });
    svg.text(ORACLE_X, cy, row.oracle, { size: 11.5, fill: C.muted });
    svg.text(RESULT_X, cy, row.result, { size: 11.5, fill: C.accent, mono: true, weight: 500 });
    const label = row.ci ? "CI" : "local";
    const badgeColor = row.ci ? C.accent : C.faint;
    const bw = row.ci ? 32 : 44;
    const bx = WIDTH - LEFT - bw;
    svg.rect(bx, cy - 13, bw, 18, { rx: 4, fill: C.surface, stroke: badgeColor });
    svg.text(bx + bw / 2, cy, label, {
      size: 9.5,
      fill: badgeColor,
      mono: true,
      anchor: "middle",
      weight: 600,
    });
    y += ROW_H;
  }
  svg.line(LEFT, y, WIDTH - LEFT, y, { stroke: C.subtle });

  const footEnd = svg.footnote(y + 24, doc.footnote);
  return svg.finish(Math.ceil(footEnd + 18));
}
