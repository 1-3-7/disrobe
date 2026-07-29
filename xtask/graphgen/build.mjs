import { Resvg } from "@resvg/resvg-js";
import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { load, ASSETS_DIR } from "./lib/data.mjs";
import { renderRecovery } from "./charts/recovery.mjs";
import { renderPython } from "./charts/python.mjs";
import { renderEcosystems } from "./charts/ecosystems.mjs";
import { renderVerification } from "./charts/verification.mjs";
import { renderArchitecture } from "./charts/architecture.mjs";
import { renderLadder } from "./charts/ladder.mjs";
import { renderCrateGraph } from "./charts/crategraph.mjs";

const graphs = [
  ["recovery.svg", "recovery.json", renderRecovery],
  ["python-versions.svg", "python_versions.json", renderPython],
  ["ecosystems.svg", "ecosystems.json", renderEcosystems],
  ["verification.svg", "verification.json", renderVerification],
  ["architecture.svg", "architecture.json", renderArchitecture],
  ["ir-ladder.svg", "ir_ladder.json", renderLadder],
  ["crate-graph.svg", "crate_graph.json", renderCrateGraph],
];

const DATA_DIR = new URL("../data/", import.meta.url);

function sourceDigest(dataFile) {
  const raw = readFileSync(new URL(dataFile, DATA_DIR));
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

function stamp(svg, dataFile, digest) {
  const marker = `<desc>generated from ${dataFile} sha256:${digest}</desc>`;
  const at = svg.indexOf(">");
  if (at < 0) {
    throw new Error(`rendered svg for ${dataFile} has no root element`);
  }
  return `${svg.slice(0, at + 1)}${marker}${svg.slice(at + 1)}`;
}

for (const [name, dataFile, render] of graphs) {
  const digest = sourceDigest(dataFile);
  const svg = stamp(render(load(dataFile)), dataFile, digest);
  writeFileSync(join(ASSETS_DIR, name), svg);
  console.log("graphgen: wrote", name, `(${svg.length} bytes, ${dataFile} sha256:${digest})`);
}

const cardSvgPath = join(ASSETS_DIR, "social-card.svg");
const cardPngPath = join(ASSETS_DIR, "social-card.png");
const cardSvg = readFileSync(cardSvgPath, "utf8");
const resvg = new Resvg(cardSvg, {
  fitTo: { mode: "width", value: 1280 },
  font: { loadSystemFonts: true, defaultFontFamily: "Segoe UI" },
  background: "#0a0a0a",
});
writeFileSync(cardPngPath, resvg.render().asPng());
console.log("graphgen: rasterized social-card.png from social-card.svg");
