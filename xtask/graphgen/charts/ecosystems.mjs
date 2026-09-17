import { Svg, C, sansWidth } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const COLS = 3;
const COL_GAP = 16;
const CELL_H = 50;
const CELL_GAP = 10;

function kindColor(kind) {
  if (kind === "source") return C.accent;
  if (kind === "bytecode") return C.teal;
  if (kind === "unpack") return C.blue;
  if (kind === "symbols") return C.amber;
  return C.faint;
}

export function renderEcosystems(doc) {
  const cellW = (INNER - (COLS - 1) * COL_GAP) / COLS;
  const rows = Math.ceil(doc.cells.length / COLS);
  const plotTop = 92;

  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  doc.cells.forEach((cell, i) => {
    const col = i % COLS;
    const row = Math.floor(i / COLS);
    const x = LEFT + col * (cellW + COL_GAP);
    const y = plotTop + row * (CELL_H + CELL_GAP);
    svg.rect(x, y, cellW, CELL_H, {
      rx: 7,
      fill: C.surface,
      stroke: C.hairline,
    });
    svg.rect(x, y, 3.5, CELL_H, { fill: kindColor(cell.kind) });
    svg.text(x + 14, y + 21, cell.label, {
      size: 12.5,
      fill: C.text,
      weight: 600,
    });
    svg.text(x + 14, y + 38, cell.note, { size: 10.5, fill: C.faint });
  });

  let y = plotTop + rows * (CELL_H + CELL_GAP) + 8;
  let lx = LEFT;
  for (const [kind, label] of Object.entries(doc.kinds)) {
    svg.rect(lx, y - 9, 16, 10, { rx: 2, fill: kindColor(kind) });
    svg.text(lx + 22, y, label, { size: 10.5, fill: C.muted });
    lx += 22 + Math.ceil(sansWidth(label, 10.5)) + 26;
  }

  const footEnd = svg.footnote(y + 26, doc.footnote);
  return svg.finish(Math.ceil(footEnd + 18));
}
