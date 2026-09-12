import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

import { Resvg } from "@resvg/resvg-js";

import { esc } from "./lib/kit.mjs";
import { brand, brandDigest as digest } from "./lib/brand.mjs";
import { vendoredFontFiles } from "./lib/social_card.mjs";

const root = new URL("../../", import.meta.url);
const fontFiles = vendoredFontFiles();
const outputs = [];
const expectedPaths = new Set();
const stale = [];
const check = process.argv.includes("--check");

if (process.argv.slice(2).some((arg) => arg !== "--check")) {
  throw new Error("Usage: node brand.mjs [--check]");
}

function sync(path, content) {
  const url = new URL(path, root);
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  expectedPaths.add(path);
  if (check) {
    if (!existsSync(url) || !readFileSync(url).equals(bytes)) stale.push(path);
  } else {
    mkdirSync(dirname(fileURLToPath(url)), { recursive: true });
    writeFileSync(url, bytes);
  }
  outputs.push({ path, bytes: bytes.length });
}

function text(value, x, y, size, family, color, weight = 400, extra = "") {
  return '<text x="' + x + '" y="' + y + '" font-family="' + esc(family) +
    '" font-size="' + size + '" font-weight="' + weight + '" fill="' + color +
    '" ' + extra + ">" + esc(value) + "</text>";
}

function mark(direction, color) {
  switch (brand.directions[direction].mark ?? direction) {
    case "index":
      return '<path d="M8 8h40v16H24v80h24v16H8Zm56 0h16c26 0 40 16 40 40v32c0 24-14 40-40 40H64v-16h16c16 0 24-8 24-24V48c0-16-8-24-24-24H64Z" fill="' + color + '"/><path d="M40 40h40v16H40Zm0 32h40v16H40Z" fill="' + color + '"/>';
    case "section":
      return '<path d="M8 22h44l24 24H32Zm20 38h44l24 24H52Zm20 38h44l24 24H72Z" fill="' + color + '"/><path d="M76 8h24l20 20v52l-16 16V34L88 18H76Z" fill="' + color + '"/>';
    case "specimen":
      return '<path fill-rule="evenodd" d="M80 8h32v112H80v-8c-6 6-14 10-26 10C24 122 8 102 8 72s16-50 46-50c12 0 20 4 26 10Zm0 64c0-14-8-24-20-24S40 58 40 72s8 24 20 24 20-10 20-24Z" fill="' + color + '"/>';
    default:
      throw new Error("Unknown logo direction: " + direction);
  }
}

function svg(body, width, height, label) {
  return '<svg xmlns="http://www.w3.org/2000/svg" width="' + width +
    '" height="' + height + '" viewBox="0 0 ' + width + " " + height +
    '" role="img" aria-labelledby="title description"><title id="title">' +
    esc(label) + '</title><desc id="description">Original geometric identity for disrobe. ' +
    "Editable source: xtask/graphgen/brand.mjs. Design tokens sha256:" + digest +
    "</desc>" + body + "</svg>";
}

function card(id, direction) {
  const palette = brand.themes.dark;
  const base = palette.canvas;
  const ink = palette.text;
  const title = text("disrobe", 64, 220, 176, direction.display, ink, direction.weight);
  const footer = text("github.com/1-3-7/disrobe", 64, 590, 22, brand.code, ink);

  if (id === "index") {
    const labels = ["source", "structure", "bytes"];
    const rows = labels.map((label, index) => {
      const y = 204 + index * 104;
      return '<path d="M758 ' + y + 'h426v80H758Z" fill="' + palette.surface + '"/>' +
        text(label, 788, y + 51, 34, brand.body, ink) +
        '<path d="M1138 ' + (y + 26) + 'h20v28h-20m8-14h20" fill="none" stroke="' + ink + '" stroke-width="3"/>';
    }).join("");
    return svg('<rect width="1280" height="640" fill="' + base + '"/>' +
      title + text("Static software recovery.", 68, 294, 32, brand.body, ink) +
      text("Decompile. Deobfuscate. Unpack.", 68, 342, 25, brand.body, ink) +
      '<g transform="translate(72 406) scale(.72)">' + mark(id, ink) + "</g>" +
      '<path d="M710 82v454" fill="none" stroke="#FFFFFF" stroke-opacity=".45"/>' +
      text("artifact", 760, 138, 24, brand.code, ink) +
      '<path d="M1104 125h68m-16-12 16 12-16 12" fill="none" stroke="#FFFFFF" stroke-width="3"/>' +
      rows + footer, 1280, 640, "disrobe: source, structure and bytes");
  }

  if (id === "section") {
    return svg('<rect width="1280" height="640" fill="' + base + '"/>' +
      '<g transform="translate(98 212) scale(1.8)">' + mark(id, ink) + "</g>" +
      text("disrobe", 414, 242, 128, direction.display, ink, direction.weight) +
      text("See the software underneath.", 422, 322, 34, brand.body, ink) +
      text("Recover source, structure and unpacked bytes.", 422, 372, 24, brand.body, palette.muted) +
      '<path d="M422 430h748" stroke="' + palette.line + '"/>' +
      text("decompile / deobfuscate / unpack", 422, 478, 24, brand.code, ink) +
      text("github.com/1-3-7/disrobe", 64, 592, 22, brand.code, palette.muted),
      1280, 640, "disrobe: see the software underneath");
  }

  return svg('<rect width="1280" height="640" fill="' + base + '"/>' +
    '<g transform="translate(26 32) scale(4.1)">' + mark(id, ink) + "</g>" +
    text("disrobe", 552, 194, 110, direction.display, ink, direction.weight) +
    text("Make compiled software", 560, 288, 34, brand.body, ink) +
    text("readable again.", 560, 334, 34, brand.body, ink) +
    '<path d="M560 378h646" stroke="' + ink + '" stroke-width="2"/>' +
    text("Source. Structure. Bytes.", 560, 432, 26, brand.body, ink) +
    text("Static recovery. Explicit limits.", 560, 476, 24, brand.body, ink) +
    footer, 1280, 640, "disrobe: static recovery with explicit limits");
}

function banner(id, direction, mode) {
  const palette = brand.themes[mode];
  return svg('<rect width="1280" height="360" fill="' + palette.canvas + '"/>' +
    '<g transform="translate(64 93) scale(1.3)">' + mark(id, palette.accent) + "</g>" +
    text("disrobe", 284, 192, 140, direction.display, palette.text, direction.weight) +
    text("Decompile, deobfuscate and unpack compiled software.", 292, 255, 29, brand.body, palette.muted) +
    '<path d="M1170 72v216m-26-190h52m-52 82h52m-52 82h52" stroke="' + palette.line + '" stroke-width="3"/>',
    1280, 360, "disrobe: decompile, deobfuscate and unpack");
}

function writeVector(name, source, raster = false) {
  const renderer = new Resvg(source, {
    font: { fontFiles, loadSystemFonts: false, defaultFontFamily: brand.body },
    logLevel: "error",
  });
  const outlined = renderer.toString();
  const vector = outlined.replace(/<svg\b[^>]*>/u, (opening) =>
    opening.replace(/>$/u, ' role="img" aria-label="' + esc(name.replaceAll("-", " ")) + '">') +
    '<title>' + esc(name.replaceAll("-", " ")) + '</title><desc>Editable source: xtask/graphgen/brand.mjs. ' +
    'Design tokens sha256:' + digest + '</desc>');
  if (/<text(?:\s|>)/u.test(vector)) {
    throw new Error(name + " retains text dependent on fonts outside the exported SVG");
  }
  sync("docs/assets/brand/" + name + ".svg", vector);
  const png = raster ? renderer.render().asPng() : null;
  if (png !== null) {
    if (png.length >= 1_000_000) {
      throw new Error(name + " exceeds GitHub's social-preview size limit");
    }
    sync("docs/assets/brand/" + name + ".png", png);
  }
  return { vector, png };
}

for (const [id, direction] of Object.entries(brand.directions).filter(([id]) => id === brand.active)) {
  const social = writeVector(id + "-social", card(id, direction), true);
  if (id === brand.active) {
    for (const dir of ["docs/assets", "docs/src/assets"]) {
      sync(dir + "/social-card.svg", social.vector);
      sync(dir + "/social-card.png", social.png);
    }
  }
  for (const mode of ["light", "dark"]) {
    const hero = writeVector(id + "-banner-" + mode, banner(id, direction, mode));
    const color = brand.themes[mode].accent;
    const logo = writeVector(id + "-mark-" + mode, svg(mark(id, color), 128, 128, "disrobe " + id + " mark"));
    sync("docs/src/assets/brand/" + id + "-mark-" + mode + ".svg", logo.vector);
    sync("playground/public/brand/" + id + "-mark-" + mode + ".svg", logo.vector);
    if (id === brand.active) {
      sync("docs/assets/banner-" + mode + ".svg", hero.vector);
      sync("docs/src/assets/brand-mark-" + mode + ".svg", logo.vector);
      sync("playground/public/brand/mark-" + mode + ".svg", logo.vector);
    }
  }
}

function properties(id, direction, mode, assetPrefix) {
  const p = brand.themes[mode];
  const s = brand.semantic[mode];
  const values = {
    "brand-display": '"' + direction.display + '", sans-serif',
    "brand-weight": direction.weight,
    "brand-wordmark-size": "24px",
    "brand-mark-size": "24px",
    "brand-lockup-gap": "8px",
    "brand-letter-spacing": "-0.02em",
    "brand-mark": `url("${assetPrefix}${id}-mark-${mode}.svg")`,
    "c-canvas": p.canvas, "c-surface": p.surface, "c-inset": p.canvas,
    "c-hairline": p.line, "c-hairline-strong": p.muted,
    "c-ink": p.text, "c-ink-muted": p.muted, "c-ink-faint": p.muted,
    "c-accent": p.accent, "c-on-accent": p.onAccent,
    "c-accent-dim": `color-mix(in srgb, ${p.accent} 25%, ${p.canvas})`,
    "c-warn": s.partial, "c-danger": s.danger, "c-yellow": s.partial,
    "c-cyan": s.detection, "c-blue": p.accent, "c-purple": s.experimental,
    ...Object.fromEntries(Object.entries(brand.syntax[mode]).map(([name, color]) => [`syntax-${name}`, color])),
    "card-canvas": p.canvas, "card-surface": p.surface, "card-panel": p.canvas,
    "card-hairline": p.line, "card-subtle": p.line, "card-text": p.text,
    "card-text2": p.muted, "card-muted": p.muted, "card-faint": p.muted,
    "card-green": p.accent, "card-keyword": s.success, "card-blue": s.detection,
    "card-amber": s.partial, "card-orange": s.experimental, "card-red": s.danger,
    "card-punctuation": p.text, "card-decor": p.line,
    "card-sans": '"' + brand.body + '", sans-serif',
    "card-mono": '"JetBrains Mono", ui-monospace, monospace',
    "mono-font": '"JetBrains Mono", ui-monospace, monospace',
  };
  return `  color-scheme: ${mode};\n` + Object.entries(values)
    .map(([key, value]) => `  --${key}: ${value};`).join("\n");
}

function stylesheet(assetPrefix) {
  const id = brand.active;
  const direction = brand.directions[id];
  return [
    `:root {\n${properties(id, direction, "dark", assetPrefix)}\n}`,
    `:root:is(.light,[data-theme="light"]) {\n${properties(id, direction, "light", assetPrefix)}\n}`,
  ].join("\n");
}

const displayFonts = [
  ["Barlow Condensed", "BarlowCondensed-Bold.ttf", "700", "BarlowCondensed-OFL.txt"],
  ["Archivo Black", "ArchivoBlack-Regular.ttf", "400", "ArchivoBlack-OFL.txt"],
  ["Manrope", "Manrope.ttf", "200 800", "Manrope-OFL.txt"],
  ["Inter", "Inter-Regular.ttf", "400", "Inter-OFL.txt"],
].filter(([family]) => family === brand.body || family === brand.directions[brand.active].display);
for (const [, file, , license] of displayFonts) {
  for (const name of [file, license]) {
    const bytes = readFileSync(new URL("fonts/" + name, import.meta.url));
    sync("docs/src/assets/fonts/" + name, bytes);
    sync("playground/public/brand/fonts/" + name, bytes);
  }
}
for (const [path, fontPrefix, assetPrefix] of [["docs/theme/tokens.css", "../../assets/fonts/", "../../assets/brand/"], ["playground/src/brand.css", "/brand/fonts/", "/brand/"]]) {
  const faces = displayFonts.map(([family, file, weight]) =>
    `@font-face { font-family: "${family}"; src: url("${fontPrefix}${file}") format("truetype"); font-weight: ${weight}; font-display: swap; }`);
  if (path === "docs/theme/tokens.css") {
    for (const file of ["JetBrainsMono-Regular.ttf", "JetBrainsMono-OFL.txt"]) {
      sync("docs/src/assets/fonts/" + file, readFileSync(new URL("fonts/" + file, import.meta.url)));
    }
    faces.push(`@font-face { font-family: "JetBrains Mono"; src: url("${fontPrefix}JetBrainsMono-Regular.ttf") format("truetype"); font-weight: 400; font-display: swap; }`);
  }
  sync(path, faces.join("\n") + "\n" + stylesheet(assetPrefix) + "\n");
}
const pending = ["docs/assets/brand", "docs/src/assets/brand", "docs/src/assets/fonts", "playground/public/brand"];
while (pending.length > 0) {
  const dir = pending.pop();
  if (!existsSync(new URL(dir, root))) continue;
  for (const entry of readdirSync(new URL(dir, root), { withFileTypes: true })) {
    const path = dir + "/" + entry.name;
    if (entry.isDirectory()) pending.push(path);
    else if (!expectedPaths.has(path)) stale.push("unowned generated file: " + path);
  }
}
if (stale.length > 0) throw new Error("Brand artifacts are stale:\n" + stale.join("\n"));
console.log(JSON.stringify({ source: "xtask/data/brand.json", sha256: digest, checked: check, files: outputs.length, bytes: outputs.reduce((sum, item) => sum + item.bytes, 0) }));
