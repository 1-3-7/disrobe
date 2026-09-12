import { readFileSync, writeFileSync } from "node:fs";

import {
  renderSocialCard,
  vendoredFontFiles,
} from "./lib/social_card.mjs";

const args = process.argv.slice(2);
if (args.length !== 2) {
  throw new Error(
    "usage: node xtask/graphgen/render_social_card.mjs <input.svg> <output.png>",
  );
}

const [inputPath, outputPath] = args;
const svg = readFileSync(inputPath);
const png = renderSocialCard(svg, vendoredFontFiles());
writeFileSync(outputPath, png);
