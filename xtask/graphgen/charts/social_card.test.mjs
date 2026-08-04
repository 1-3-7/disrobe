import assert from "node:assert/strict";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import test from "node:test";

import {
  renderSocialCard,
  vendoredFontFiles,
} from "../lib/social_card.mjs";

const WIDTH = 1280;
const HEIGHT = 640;
const PNG_SIGNATURE = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
const SVG = Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" width="${WIDTH}" height="${HEIGHT}" viewBox="0 0 ${WIDTH} ${HEIGHT}"><rect width="${WIDTH}" height="${HEIGHT}" fill="#0a0a0a"/><text x="40" y="80" font-family="JetBrains Mono" font-size="24" fill="#ededed">950k+ lines of Rust</text><text x="40" y="130" font-family="Inter" font-size="24" fill="#ededed">deterministic social card</text></svg>`,
);

test("social-card rendering is byte-stable at 1280 by 640", () => {
  const fonts = vendoredFontFiles();
  const first = renderSocialCard(SVG, fonts);
  const second = renderSocialCard(SVG, fonts);

  assert.deepEqual(first, second);
  assert.deepEqual(first.subarray(0, PNG_SIGNATURE.length), PNG_SIGNATURE);
  assert.equal(first.readUInt32BE(16), WIDTH);
  assert.equal(first.readUInt32BE(20), HEIGHT);
});

test("social-card CLI writes only the requested PNG", async (context) => {
  const dir = await mkdtemp(join(tmpdir(), "disrobe-social-card-"));
  context.after(async () => rm(dir, { recursive: true, force: true }));
  const input = join(dir, "card.svg");
  const output = join(dir, "card.png");
  const cli = fileURLToPath(
    new URL("../render_social_card.mjs", import.meta.url),
  );
  await writeFile(input, SVG);

  const result = spawnSync(process.execPath, [cli, input, output], {
    encoding: "utf8",
  });

  assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
  assert.deepEqual((await readdir(dir)).sort(), ["card.png", "card.svg"]);
  const png = await readFile(output);
  assert.deepEqual(png, renderSocialCard(SVG, vendoredFontFiles()));
  assert.deepEqual(png.subarray(0, PNG_SIGNATURE.length), PNG_SIGNATURE);
  assert.equal(png.readUInt32BE(16), WIDTH);
  assert.equal(png.readUInt32BE(20), HEIGHT);
});
