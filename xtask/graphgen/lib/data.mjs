import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
export const ROOT = join(here, "..", "..", "..");
export const DATA_DIR = join(ROOT, "xtask", "data");
export const ASSETS_DIR = join(ROOT, "docs", "assets");
export const DEMO_SVG = join(ROOT, "docs", "src", "demo", "disrobe-demo.svg");
export const CAST = join(ROOT, "docs", "demo", "disrobe.cast");

export function load(name) {
  return JSON.parse(readFileSync(join(DATA_DIR, name), "utf8"));
}
