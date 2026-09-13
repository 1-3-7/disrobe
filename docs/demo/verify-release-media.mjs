import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyMediaVersion } from "./media-version.mjs";
import { presentation, validateRecording } from "./cli-plan.mjs";

const fileNames = ["walkthrough.mp4", "teaser.mp4", "preview.gif", "poster.png", "captions.vtt", "chapters.vtt", "teaser.vtt", "transcript.txt"];
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function verifyReleaseMedia(directory, releaseTag) {
  const expectedFiles = [...fileNames, "media.json", "cli-recording.json"].sort();
  assert.deepEqual(readdirSync(directory).sort(), expectedFiles, "unexpected release media files");
  for (const name of expectedFiles) {
    const info = lstatSync(join(directory, name));
    assert.ok(info.isFile() && !info.isSymbolicLink(), `${name} must be a regular file`);
    assert.ok(info.size > 0 && info.size < 10 * 1024 * 1024, `${name} exceeds the media size boundary`);
  }
  const manifest = JSON.parse(readFileSync(join(directory, "media.json"), "utf8"));
  const recordingBytes = readFileSync(join(directory, "cli-recording.json"));
  const recording = JSON.parse(recordingBytes);
  assert.equal(manifest.schema, "disrobe.walkthrough-media.v4");
  validateRecording(recording);
  verifyMediaVersion(manifest.binary.version, manifest.workspaceVersion, releaseTag);
  assert.equal(manifest.releaseTag, releaseTag, "media was not captured for this release tag");
  assert.equal(recording.releaseTag, releaseTag, "recording was not captured for this release tag");
  assert.equal(recording.workspaceVersion, manifest.workspaceVersion);
  assert.deepEqual(recording.binary, manifest.binary, "media and recording identify different binaries");
  assert.equal(manifest.recordingSha256, hash(recordingBytes), "media does not match the command recording");
  assert.equal(manifest.capturedAt, recording.capturedAt);
  assert.deepEqual(manifest.presentation, recording.presentation);
  assert.deepEqual([manifest.presentation.width, manifest.presentation.height, manifest.presentation.fps], [1920, 1080, 60]);
  const durationMs = presentation.openingMs + presentation.closingMs + recording.scenes.reduce((sum, scene) => sum + scene.durationMs, 0);
  assert.deepEqual([manifest.durationSeconds, manifest.teaserDurationSeconds], [durationMs / 1000, 20]);
  assert.equal(manifest.commandCount, recording.scenes.length);
  assert.equal(manifest.publicCommandCount, recording.catalog.commands.length);
  assert.equal(manifest.chapters.length, 5);
  assert.equal(manifest.chapters[0].startMs, 0);
  assert.equal(manifest.chapters.at(-1).endMs, durationMs);
  assert.deepEqual(manifest.cues.map((cue) => cue.command), recording.scenes.map((scene) => scene.command));
  assert.deepEqual(manifest.files.map((file) => file.name), fileNames);
  assert.deepEqual(manifest.preview, { source: "teaser.mp4", sourceSha256: manifest.files.find((file) => file.name === "teaser.mp4").sha256, width: 960, height: 540, fps: 10, durationSeconds: 20, loop: true });
  for (const file of manifest.files) {
    const bytes = readFileSync(join(directory, file.name));
    assert.ok(bytes.length > 0 && bytes.length < 10 * 1024 * 1024, `${file.name} exceeds the media size boundary`);
    assert.equal(bytes.length, file.bytes, `${file.name} has a different size`);
    assert.equal(hash(bytes), file.sha256, `${file.name} has different content`);
  }
  assert.deepEqual(readFileSync(join(directory, "transcript.txt"), "utf8").split(/\r?\n/u).slice(0, 2), ["Disrobe CLI walkthrough", manifest.binary.version]);
  return { releaseTag, binary: manifest.binary, recordingSha256: manifest.recordingSha256 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 4, "Usage: node docs/demo/verify-release-media.mjs <walkthrough-directory> <release-tag>");
  process.stdout.write(JSON.stringify(verifyReleaseMedia(resolve(process.argv[2]), process.argv[3]), null, 2) + "\n");
}
