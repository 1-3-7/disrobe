import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const source = fileURLToPath(new URL("../", import.meta.url));

test("brand generation detects changed outputs, unowned files, bad contrast and changed fonts", { timeout: 60_000 }, () => {
  const root = mkdtempSync(join(source, ".brand-test-"));
  const renderer = join(root, "xtask", "graphgen");
  const tokens = join(root, "xtask", "data", "brand.json");
  function run(...args) {
    const result = spawnSync(process.execPath, [join(renderer, "brand.mjs"), ...args], {
      cwd: root, encoding: "utf8", timeout: 20_000, maxBuffer: 1_048_576,
    });
    if (result.error) throw result.error;
    return result;
  }
  try {
    mkdirSync(join(renderer, "lib"), { recursive: true });
    mkdirSync(dirname(tokens), { recursive: true });
    for (const file of ["brand.mjs", "lib/brand.mjs", "lib/kit.mjs", "lib/social_card.mjs", "fonts"]) {
      cpSync(join(source, file), join(renderer, file), { recursive: true });
    }
    cpSync(new URL("../../data/brand.json", import.meta.url), tokens);
    const generated = run();
    assert.equal(generated.status, 0, generated.stderr);
    const checked = run("--check");
    assert.equal(checked.status, 0, checked.stderr);
    assert.deepEqual(readdirSync(join(root, "docs/assets/brand")).sort(), [
      "section-banner-dark.svg", "section-banner-light.svg", "section-mark-dark.svg",
      "section-mark-light.svg", "section-social.png", "section-social.svg",
    ]);
    assert.deepEqual(readdirSync(join(root, "docs/src/assets/brand")).sort(), [
      "section-mark-dark.svg", "section-mark-light.svg",
    ]);
    assert.deepEqual(readdirSync(join(root, "playground/public/brand")).sort(), [
      "fonts", "mark-dark.svg", "mark-light.svg", "section-mark-dark.svg", "section-mark-light.svg",
    ]);
    assert.deepEqual(readdirSync(join(root, "docs/src/assets/fonts")).sort(), [
      "JetBrainsMono-OFL.txt", "JetBrainsMono-Regular.ttf", "Manrope-OFL.txt", "Manrope.ttf",
    ]);
    assert.deepEqual(readdirSync(join(root, "playground/public/brand/fonts")).sort(), [
      "Manrope-OFL.txt", "Manrope.ttf",
    ]);
    const png = readFileSync(join(root, "docs/assets/brand/section-social.png"));
    assert.deepEqual(png.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    assert.equal(png.readUInt32BE(16), 1280);
    assert.equal(png.readUInt32BE(20), 640);
    assert.ok(png.length < 1_000_000);
    for (const directory of ["docs/assets", "docs/src/assets"]) {
      assert.deepEqual(readFileSync(join(root, directory, "social-card.png")), png);
    }
    for (const mode of ["light", "dark"]) {
      const svg = readFileSync(join(root, "docs/assets/brand", `section-banner-${mode}.svg`), "utf8");
      assert.match(svg, /<title>/u);
      assert.match(svg, /<desc>/u);
      assert.doesNotMatch(svg, /<text(?:\s|>)/u);
    }

    const exported = join(root, "docs/assets/banner-light.svg");
    const expected = readFileSync(exported);
    writeFileSync(exported, "changed export");
    const stale = run("--check");
    assert.notEqual(stale.status, 0);
    assert.match(stale.stderr, /docs\/assets\/banner-light\.svg/u);
    assert.equal(readFileSync(exported, "utf8"), "changed export");
    writeFileSync(exported, expected);

    const orphan = join(root, "playground/public/brand/fonts/unused.txt");
    writeFileSync(orphan, "unowned");
    const unowned = run("--check");
    assert.notEqual(unowned.status, 0);
    assert.match(unowned.stderr, /unowned generated file: playground\/public\/brand\/fonts\/unused.txt/u);
    rmSync(orphan);

    const original = readFileSync(tokens);
    const bad = JSON.parse(original);
    bad.themes.light.text = bad.themes.light.canvas;
    writeFileSync(tokens, JSON.stringify(bad));
    const contrast = run("--check");
    assert.notEqual(contrast.status, 0);
    assert.match(contrast.stderr, /contrast/iu);
    writeFileSync(tokens, original);

    const tinted = JSON.parse(original);
    tinted.themes.dark.canvas = "#10182A";
    writeFileSync(tokens, JSON.stringify(tinted));
    const neutral = run("--check");
    assert.notEqual(neutral.status, 0);
    assert.match(neutral.stderr, /neutral gray/u);
    writeFileSync(tokens, original);

    const font = join(renderer, "fonts/BarlowCondensed-Bold.ttf");
    writeFileSync(font, "changed font");
    const unpinned = run("--check");
    assert.notEqual(unpinned.status, 0);
    assert.match(unpinned.stderr, /vendored font.*sha256/u);
  } finally {
    assert.equal(dirname(resolve(root)), resolve(source));
    assert.ok(root.startsWith(join(source, ".brand-test-")));
    rmSync(root, { recursive: true, force: true });
  }
});
