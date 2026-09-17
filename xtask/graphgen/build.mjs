import { readFileSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { Resvg } from "@resvg/resvg-js";
import { vendoredFontFiles } from "./lib/social_card.mjs";
import { load, ASSETS_DIR } from "./lib/data.mjs";
import { renderRecovery } from "./charts/recovery.mjs";
import { renderPython } from "./charts/python.mjs";
import { renderEcosystems } from "./charts/ecosystems.mjs";
import { renderVerification } from "./charts/verification.mjs";
import { renderArchitecture } from "./charts/architecture.mjs";
import { renderLadder } from "./charts/ladder.mjs";

const graphs = [
  ["recovery.svg", "recovery.json", renderRecovery],
  ["python-versions.svg", "python_versions.json", renderPython],
  ["ecosystems.svg", "ecosystems.json", renderEcosystems],
  ["verification.svg", "verification.json", renderVerification],
  ["architecture.svg", "architecture.json", renderArchitecture],
  ["ir-ladder.svg", "ir_ladder.json", renderLadder],
];

const DATA_DIR = new URL("../data/", import.meta.url);
const fontFiles = vendoredFontFiles();
const args = process.argv.slice(2);
const check = args.length === 1 && args[0] === "--check";
if (args.length !== 0 && !check) throw new Error("usage: node xtask/graphgen/build.mjs [--check]");

function publish(path, contents) {
  const expected = Buffer.from(contents);
  if (check) {
    if (!readFileSync(path).equals(expected)) {
      throw new Error("generated chart differs: " + path + "; run node xtask/graphgen/build.mjs");
    }
  } else {
    writeFileSync(path, expected);
  }
}

function sourceDigest(dataFile) {
  const raw = readFileSync(new URL(dataFile, DATA_DIR));
  return createHash("sha256").update(raw).digest("hex").slice(0, 32);
}

function stamp(svg, dataFile, digest) {
  const marker = `<desc>generated from ${dataFile} sha256:${digest}</desc>`;
  const rootStart = svg.indexOf("<svg");
  if (rootStart < 0) {
    throw new Error(`rendered svg for ${dataFile} has no <svg> root element`);
  }
  const at = svg.indexOf(">", rootStart);
  if (at < 0) {
    throw new Error(`rendered svg for ${dataFile} has an unterminated <svg> tag`);
  }
  return `${svg.slice(0, at + 1)}${marker}${svg.slice(at + 1)}`;
}

for (const [name, dataFile, render] of graphs) {
  const digest = sourceDigest(dataFile);
  const svg = stamp(render(load(dataFile)), dataFile, digest);
  publish(join(ASSETS_DIR, name), svg);
  const renderer = new Resvg(svg, {
    fitTo: { mode: "zoom", value: 2 },
    font: { fontFiles, loadSystemFonts: false, defaultFontFamily: "Manrope", sansSerifFamily: "Manrope", monospaceFamily: "JetBrains Mono" },
  });
  publish(join(ASSETS_DIR, name.replace(/\.svg$/u, ".png")), renderer.render().asPng());
  console.log(check ? "graphgen: checked" : "graphgen: wrote", name, `(${svg.length} bytes, ${dataFile} sha256:${digest})`);
}

const PUBLISHED_DIR = new URL("../../docs/src/assets/", import.meta.url);

for (const name of ["recovery.svg", "recovery.png", "ir-ladder.svg", "ir-ladder.png"]) {
  const published = new URL(name, PUBLISHED_DIR);
  publish(published, readFileSync(join(ASSETS_DIR, name)));
  console.log(check ? "graphgen: checked published" : "graphgen: published", name, "to docs/src/assets (the copy mdbook serves)");
}
