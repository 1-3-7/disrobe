import assert from "node:assert/strict";
import { copyFileSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { renderPreview } from "./render-preview.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));

function withSource(inspect) {
  const scratch = mkdtempSync(join(root, "docs/demo/.preview-test-"));
  try {
    const source = join(root, "docs/src/assets/walkthrough");
    for (const name of ["media.json", "teaser.mp4"]) copyFileSync(join(source, name), join(scratch, name));
    inspect(scratch, JSON.parse(readFileSync(join(scratch, "media.json"), "utf8")));
  } finally {
    assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".preview-test-") && !lstatSync(scratch).isSymbolicLink());
    rmSync(scratch, { recursive: true });
  }
}

test("preview renders the existing recording without relabeling its binary version", () => {
  withSource((directory, source) => {
    const completed = renderPreview(directory);
    assert.deepEqual(completed.binary, source.binary);
    assert.equal(completed.recordingSha256, source.recordingSha256);
    assert.equal(completed.capturedAt, source.capturedAt);
    assert.deepEqual(completed.files.filter((file) => file.name !== "preview.gif"), source.files.filter((file) => file.name !== "preview.gif"));
    assert.equal(readFileSync(join(directory, "preview.gif")).subarray(0, 6).toString("ascii"), "GIF89a");
  });
});

test("preview rejects changed source bytes before replacing existing output", () => {
  withSource((directory) => {
    writeFileSync(join(directory, "teaser.mp4"), "different source");
    writeFileSync(join(directory, "preview.gif"), "existing preview");
    const before = readFileSync(join(directory, "media.json"));
    assert.throws(() => renderPreview(directory), /teaser.mp4 has a different size/u);
    assert.equal(readFileSync(join(directory, "preview.gif"), "utf8"), "existing preview");
    assert.deepEqual(readFileSync(join(directory, "media.json")), before);
  });
});
