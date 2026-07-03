import { Svg, C, monoWidth } from "../lib/kit.mjs";

const WIDTH = 920;
const LEFT = 28;
const INNER = WIDTH - LEFT * 2;
const PLOT_TOP = 96;
const CHIP_H = 26;
const CHIP_GAP = 8;
const ROW_GAP = 8;
const CHIP_PAD = 14;
const TIER_LABEL_H = 40;
const TIER_GAP = 22;

function tierColor(kind) {
  if (kind === "frontend") return C.accent;
  if (kind === "pass") return C.blue;
  return C.amber;
}

function layoutTier(nodes) {
  const placed = [];
  let x = LEFT;
  let row = 0;
  for (const node of nodes) {
    const w = monoWidth(node, 11) + CHIP_PAD * 2;
    if (x + w > LEFT + INNER && x > LEFT) {
      row += 1;
      x = LEFT;
    }
    placed.push({ node, x, w, row });
    x += w + CHIP_GAP;
  }
  const maxRow = placed.reduce((m, p) => Math.max(m, p.row), 0);
  return { placed, rows: maxRow + 1 };
}

export function renderCrateGraph(doc) {
  const svg = new Svg(WIDTH);
  svg.header(doc.title, doc.subtitle);

  const tiers = doc.tiers.map((t) => ({ tier: t, ...layoutTier(t.nodes) }));

  let y = PLOT_TOP;
  for (const { tier, placed, rows } of tiers) {
    const color = tierColor(tier.kind);
    svg.rect(LEFT, y + 2, 3.5, 24, { fill: color });
    svg.text(LEFT + 14, y + 14, tier.name, { size: 13, fill: C.text, weight: 600 });
    svg.text(LEFT + 14, y + 30, tier.note, { size: 10.5, fill: C.faint });
    const chipsTop = y + TIER_LABEL_H;
    for (const p of placed) {
      const cy = chipsTop + p.row * (CHIP_H + ROW_GAP);
      svg.rect(p.x, cy, p.w, CHIP_H, { rx: 5, fill: C.surface, stroke: C.hairline });
      svg.text(p.x + p.w / 2, cy + 17, p.node, {
        size: 11,
        fill: C.muted,
        mono: true,
        anchor: "middle",
      });
    }
    y = chipsTop + rows * (CHIP_H + ROW_GAP) - ROW_GAP + TIER_GAP;
  }

  const footEnd = svg.footnote(y + 4, doc.footnote);
  return svg.finish(Math.ceil(footEnd + 18));
}
