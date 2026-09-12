import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { copyFileSync, lstatSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { basename, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { verifyReleaseMedia } from "./verify-release-media.mjs";

const root = fileURLToPath(new URL("../../", import.meta.url));
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

function withBundle(inspect) {
  const scratch = mkdtempSync(join(root, "docs/demo/.release-media-test-"));
  try {
    const source = join(root, "docs/src/assets/walkthrough");
    const manifest = JSON.parse(readFileSync(join(source, "media.json"), "utf8"));
    const recording = JSON.parse(readFileSync(join(root, "docs/demo/cli-recording.json"), "utf8"));
    const version = recording.binary.version.match(/^disrobe ([^\s]+)$/u)?.[1];
    assert.ok(version);
    const tag = `v${version}`;
    recording.workspaceVersion = version;
    recording.releaseTag = tag;
    const bytes = Buffer.from(JSON.stringify(recording));
    manifest.workspaceVersion = version;
    manifest.releaseTag = tag;
    manifest.recordingSha256 = hash(bytes);
    for (const file of manifest.files) copyFileSync(join(source, file.name), join(scratch, file.name));
    writeFileSync(join(scratch, "cli-recording.json"), bytes);
    writeFileSync(join(scratch, "media.json"), JSON.stringify(manifest));
    inspect(scratch, tag, manifest);
  } finally {
    assert.ok(resolve(scratch).startsWith(resolve(root, "docs/demo") + sep) && basename(scratch).startsWith(".release-media-test-") && !lstatSync(scratch).isSymbolicLink());
    rmSync(scratch, { recursive: true });
  }
}

test("release media verifies the original capture version and all file hashes", () => {
  withBundle((directory, tag, manifest) => {
    assert.deepEqual(verifyReleaseMedia(directory, tag).binary, manifest.binary);
  });
});

test("release media rejects a different tag", () => {
  withBundle((directory) => {
    assert.throws(() => verifyReleaseMedia(directory, "v999.0.0"), /release tag .* does not match workspace version/u);
  });
});

test("release media rejects an extra page that could replace the existing player", () => {
  withBundle((directory, tag) => {
    writeFileSync(join(directory, "watch.html"), "unexpected player");
    assert.throws(() => verifyReleaseMedia(directory, tag), /unexpected release media files/u);
  });
});

test("release media rejects a bundle missing its animated preview", () => {
  withBundle((directory, tag, manifest) => {
    rmSync(join(directory, "preview.gif"), { force: true });
    manifest.files = manifest.files.filter((file) => file.name !== "preview.gif");
    writeFileSync(join(directory, "media.json"), JSON.stringify(manifest));
    assert.throws(() => verifyReleaseMedia(directory, tag), /unexpected release media files/u);
  });
});

test("release media rejects changed video bytes", () => {
  withBundle((directory, tag) => {
    writeFileSync(join(directory, "walkthrough.mp4"), "changed video");
    assert.throws(() => verifyReleaseMedia(directory, tag), /walkthrough.mp4 has a different size/u);
  });
});

test("release media rejects a preview attributed to different source bytes", () => {
  withBundle((directory, tag, manifest) => {
    manifest.preview.sourceSha256 = "0".repeat(64);
    writeFileSync(join(directory, "media.json"), JSON.stringify(manifest));
    assert.throws(() => verifyReleaseMedia(directory, tag), { code: "ERR_ASSERTION" });
  });
});

test("release media rejects a changed command recording", () => {
  withBundle((directory, tag) => {
    const path = join(directory, "cli-recording.json");
    const recording = JSON.parse(readFileSync(path, "utf8"));
    recording.scenes[0].stdout += "changed output";
    writeFileSync(path, JSON.stringify(recording));
    assert.throws(() => verifyReleaseMedia(directory, tag), /media does not match the command recording/u);
  });
});

test("release media rejects a relabeled transcript even when its file hash is updated", () => {
  withBundle((directory, tag, manifest) => {
    const path = join(directory, "transcript.txt");
    const transcript = readFileSync(path, "utf8").replace(manifest.binary.version, "disrobe 999.0.0");
    writeFileSync(path, transcript);
    const file = manifest.files.find((entry) => entry.name === "transcript.txt");
    file.bytes = Buffer.byteLength(transcript);
    file.sha256 = hash(transcript);
    writeFileSync(join(directory, "media.json"), JSON.stringify(manifest));
    assert.throws(() => verifyReleaseMedia(directory, tag), { code: "ERR_ASSERTION" });
  });
});
