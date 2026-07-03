import { Resvg } from "@resvg/resvg-js";
import { readFileSync, writeFileSync } from "node:fs";
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
  ["recovery.svg", () => renderRecovery(load("recovery.json"))],
  ["python-versions.svg", () => renderPython(load("python_versions.json"))],
  ["ecosystems.svg", () => renderEcosystems(load("ecosystems.json"))],
  ["verification.svg", () => renderVerification(load("verification.json"))],
  ["architecture.svg", () => renderArchitecture(load("architecture.json"))],
  ["ir-ladder.svg", () => renderLadder(load("ir_ladder.json"))],
  ["crate-graph.svg", () => renderCrateGraph(load("crate_graph.json"))],
];

for (const [name, build] of graphs) {
  const svg = build();
  writeFileSync(join(ASSETS_DIR, name), svg);
  console.log("graphgen: wrote", name, `(${svg.length} bytes)`);
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
