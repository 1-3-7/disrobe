import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

const bytes = readFileSync(new URL("../../data/brand.json", import.meta.url));

export const brand = JSON.parse(bytes);
export const brandDigest = createHash("sha256").update(bytes).digest("hex");

function luminance(hex) {
  const channels = [1, 3, 5].map((offset) => {
    const value = Number.parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return channels[0] * 0.2126 + channels[1] * 0.7152 + channels[2] * 0.0722;
}

export function contrast(first, second) {
  const a = luminance(first);
  const b = luminance(second);
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05);
}

if (brand.schemaVersion !== 1 || !Object.hasOwn(brand.directions, brand.active)) {
  throw new Error("brand.json must name an existing active direction using schema 1");
}

for (const mode of ["light", "dark"]) {
  const palette = brand.themes[mode];
  for (const [key, color] of Object.entries({ ...palette, ...brand.semantic[mode] })) {
    if (!/^#[\da-f]{6}$/iu.test(color)) {
      throw new Error(`${mode}.${key} must be a six-digit RGB color`);
    }
    if (color.slice(1, 3) !== color.slice(3, 5) || color.slice(3, 5) !== color.slice(5, 7)) {
      throw new Error(`${mode}.${key} must be a neutral gray`);
    }
  }
  for (const foreground of [palette.text, palette.muted, palette.accent, ...Object.values(brand.semantic[mode]), ...Object.values(brand.syntax[mode])]) {
    if (!/^#[\da-f]{6}$/iu.test(foreground)) {
      throw new Error(`${mode}: ${foreground} must be a six-digit RGB color`);
    }
    for (const background of [palette.canvas, palette.surface]) {
      if (contrast(foreground, background) < 4.5) {
        throw new Error(`${mode}: ${foreground} on ${background} fails 4.5:1 text contrast`);
      }
    }
  }
  if (contrast(palette.onAccent, palette.accent) < 4.5) {
    throw new Error(`${mode}: accent button text fails 4.5:1 contrast`);
  }
}

export const palette = brand.themes.dark;
