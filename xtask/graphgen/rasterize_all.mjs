import { Resvg } from "@resvg/resvg-js";
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";

const OUT = process.argv[2];
if (!OUT) {
  console.error("usage: node rasterize_all.mjs <out-dir>");
  process.exit(1);
}

const ROOT = join(import.meta.dirname, "..", "..");
const TARGETS = [
  ["docs/assets/recovery.svg", "recovery.png"],
  ["docs/assets/python-versions.svg", "python-versions.png"],
  ["docs/assets/ecosystems.svg", "ecosystems.png"],
  ["docs/assets/verification.svg", "verification.png"],
  ["docs/assets/architecture.svg", "architecture.png"],
  ["docs/assets/ir-ladder.svg", "ir-ladder.png"],
  ["docs/assets/social-card.svg", "social-card.png"],
];

for (const [rel, name] of TARGETS) {
  const path = join(ROOT, rel);
  if (!existsSync(path)) {
    console.log(`missing ${rel}`);
    continue;
  }
  const svg = readFileSync(path, "utf8");
  const resvg = new Resvg(svg, { fitTo: { mode: "width", value: 1100 } });
  const png = resvg.render().asPng();
  writeFileSync(join(OUT, name), png);
  console.log(`${rel} -> ${name} (${png.length} bytes)`);
}
