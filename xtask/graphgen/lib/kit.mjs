export const C = {
  canvas: "#0a0a0a",
  surface: "#161616",
  panel: "#101010",
  hairline: "#262626",
  subtle: "#333333",
  text: "#ededed",
  muted: "#a1a1a1",
  faint: "#828282",
  accent: "#8fb3d9",
  teal: "#9cc2c4",
  blue: "#b0a2d0",
  amber: "#c9a98e",
  orange: "#cfc9a8",
  red: "#d08c8c",
};

export const SANS =
  "system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif";
export const MONO =
  "'JetBrains Mono', ui-monospace, 'Cascadia Mono', 'Fira Code', SFMono-Regular, Menlo, Consolas, monospace";

const XML_HEADER = '<?xml version="1.0" encoding="UTF-8"?>\n';

const SANS_ADVANCE = {
  " ": 0.3,
  "!": 0.32,
  '"': 0.42,
  "#": 0.62,
  $: 0.56,
  "%": 0.9,
  "&": 0.68,
  "'": 0.24,
  "(": 0.36,
  ")": 0.36,
  "*": 0.44,
  "+": 0.6,
  ",": 0.28,
  "-": 0.36,
  ".": 0.28,
  "/": 0.32,
  ":": 0.3,
  ";": 0.3,
  "<": 0.6,
  "=": 0.6,
  ">": 0.6,
  "?": 0.5,
  "@": 1.0,
  "[": 0.32,
  "]": 0.32,
  _: 0.5,
  "{": 0.36,
  "|": 0.28,
  "}": 0.36,
  i: 0.26,
  j: 0.26,
  l: 0.26,
  f: 0.32,
  t: 0.32,
  r: 0.38,
  I: 0.32,
  m: 0.86,
  w: 0.74,
  M: 0.86,
  W: 0.96,
};

export function sansWidth(text, size) {
  let units = 0;
  for (const ch of text) {
    const a = SANS_ADVANCE[ch];
    if (a !== undefined) units += a;
    else if (ch >= "A" && ch <= "Z") units += 0.68;
    else if (ch >= "0" && ch <= "9") units += 0.56;
    else units += 0.52;
  }
  return units * size;
}

export function monoWidth(text, size) {
  return [...text].length * size * 0.6;
}

export function esc(s) {
  let out = "";
  for (const ch of String(s)) {
    if (ch === "&") out += "&amp;";
    else if (ch === "<") out += "&lt;";
    else if (ch === ">") out += "&gt;";
    else if (ch === '"') out += "&quot;";
    else if (ch === "'") out += "&#39;";
    else out += ch;
  }
  return out;
}

export function wrapSans(text, size, maxWidth) {
  const words = text.split(/\s+/).filter(Boolean);
  const lines = [];
  let line = "";
  for (const word of words) {
    const trial = line ? `${line} ${word}` : word;
    if (line && sansWidth(trial, size) > maxWidth) {
      lines.push(line);
      line = word;
    } else {
      line = trial;
    }
  }
  if (line) lines.push(line);
  return lines;
}

export function firstSentence(text) {
  const dot = text.indexOf(". ");
  return dot === -1 ? text : `${text.slice(0, dot + 1)}`;
}

export function num(value) {
  return Number.isInteger(value) ? String(value) : value.toFixed(2);
}

export function thousands(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

export class Svg {
  constructor(width) {
    this.width = width;
    this.parts = [];
  }

  push(fragment) {
    this.parts.push(fragment);
    return this;
  }

  rect(x, y, w, h, opts = {}) {
    const {
      rx = 0,
      fill = "none",
      stroke = null,
      strokeWidth = 1,
      opacity = null,
    } = opts;
    const attrs = [
      `x="${x.toFixed(2)}"`,
      `y="${y.toFixed(2)}"`,
      `width="${w.toFixed(2)}"`,
      `height="${h.toFixed(2)}"`,
    ];
    if (rx) attrs.push(`rx="${rx.toFixed(2)}"`);
    attrs.push(`fill="${fill}"`);
    if (stroke) attrs.push(`stroke="${stroke}"`, `stroke-width="${strokeWidth}"`);
    if (opacity !== null) attrs.push(`opacity="${opacity}"`);
    return this.push(`  <rect ${attrs.join(" ")}/>`);
  }

  line(x1, y1, x2, y2, opts = {}) {
    const { stroke = C.hairline, dash = null, strokeWidth = 1 } = opts;
    const attrs = [
      `x1="${x1.toFixed(2)}"`,
      `y1="${y1.toFixed(2)}"`,
      `x2="${x2.toFixed(2)}"`,
      `y2="${y2.toFixed(2)}"`,
      `stroke="${stroke}"`,
      `stroke-width="${strokeWidth}"`,
    ];
    if (dash) attrs.push(`stroke-dasharray="${dash}"`);
    return this.push(`  <line ${attrs.join(" ")}/>`);
  }

  path(d, opts = {}) {
    const { fill = "none", stroke = null, strokeWidth = 1 } = opts;
    const attrs = [`d="${d}"`, `fill="${fill}"`];
    if (stroke) attrs.push(`stroke="${stroke}"`, `stroke-width="${strokeWidth}"`);
    return this.push(`  <path ${attrs.join(" ")}/>`);
  }

  circle(cx, cy, r, opts = {}) {
    const { fill = "none", stroke = null, strokeWidth = 1 } = opts;
    const attrs = [
      `cx="${cx.toFixed(2)}"`,
      `cy="${cy.toFixed(2)}"`,
      `r="${r.toFixed(2)}"`,
      `fill="${fill}"`,
    ];
    if (stroke) attrs.push(`stroke="${stroke}"`, `stroke-width="${strokeWidth}"`);
    return this.push(`  <circle ${attrs.join(" ")}/>`);
  }

  text(x, y, content, opts = {}) {
    const {
      size = 12,
      fill = C.text,
      family = SANS,
      anchor = "start",
      weight = 400,
      mono = false,
      letterSpacing = null,
      opacity = null,
    } = opts;
    const attrs = [
      `x="${x.toFixed(2)}"`,
      `y="${y.toFixed(2)}"`,
      `font-size="${size}"`,
      `fill="${fill}"`,
      `font-family="${mono ? MONO : family}"`,
      `text-anchor="${anchor}"`,
      `font-weight="${weight}"`,
    ];
    if (letterSpacing !== null) attrs.push(`letter-spacing="${letterSpacing}"`);
    if (opacity !== null) attrs.push(`opacity="${opacity}"`);
    return this.push(`  <text ${attrs.join(" ")}>${esc(content)}</text>`);
  }

  embed(echartsSvg, x, y) {
    const nested = echartsSvg
      .replace(/^<\?xml[^>]*>\s*/, "")
      .replace("<svg ", `<svg x="${x.toFixed(2)}" y="${y.toFixed(2)}" `);
    return this.push(nested);
  }

  header(title, subtitle) {
    this.text(28, 40, title, { size: 19, fill: C.text, weight: 600 });
    if (subtitle) this.text(28, 61, subtitle, { size: 12.5, fill: C.muted });
    this.line(28, 74, this.width - 28, 74, { stroke: C.subtle });
    return this;
  }

  footnote(top, text, maxChars = 128) {
    this.line(28, top - 12, this.width - 28, top - 12, { stroke: C.subtle });
    const maxWidth = this.width - 56;
    const lines = wrapSans(text, 10, maxWidth);
    lines.forEach((ln, i) => {
      this.text(28, top + i * 14, ln, { size: 10, fill: C.faint });
    });
    return top + lines.length * 14;
  }

  finish(height) {
    const chrome = [
      `${XML_HEADER}<svg xmlns="http://www.w3.org/2000/svg" width="${this.width}" height="${height}" viewBox="0 0 ${this.width} ${height}" font-family="${SANS}">`,
      `  <rect x="0" y="0" width="${this.width}" height="${height}" rx="10" fill="${C.canvas}"/>`,
      `  <rect x="0.5" y="0.5" width="${this.width - 1}" height="${height - 1}" rx="9.5" fill="none" stroke="${C.hairline}"/>`,
    ];
    return `${chrome.join("\n")}\n${this.parts.join("\n")}\n</svg>\n`;
  }
}
