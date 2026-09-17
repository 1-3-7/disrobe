import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { verifyMediaVersion } from "./media-version.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");

export function runMediaTool(executable, args) {
  const result = spawnSync(executable, args, { encoding: "utf8", timeout: 180_000, maxBuffer: 1024 * 1024, windowsHide: true });
  if (result.error) throw result.error;
  assert.equal(result.status, 0, `${executable}: ${result.stderr}`);
  return result.stdout;
}

export function renderPreview(directory) {
  const manifestPath = join(directory, "media.json");
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const recordingBytes = readFileSync(new URL("cli-recording.json", import.meta.url));
  const recording = JSON.parse(recordingBytes);
  assert.equal(manifest.schema, "disrobe.walkthrough-media.v4");
  assert.equal(recording.schema, "disrobe.cli-recording.v2");
  assert.equal(manifest.recordingSha256, hash(recordingBytes), "media does not match the command recording");
  assert.deepEqual(manifest.binary, recording.binary);
  assert.equal(manifest.workspaceVersion, recording.workspaceVersion);
  assert.equal(manifest.releaseTag, recording.releaseTag);
  if (recording.workspaceVersion !== undefined) verifyMediaVersion(recording.binary.version, recording.workspaceVersion, recording.releaseTag);
  const source = manifest.files.find((file) => file.name === "teaser.mp4");
  assert.ok(source, "media manifest has no teaser");
  const teaser = join(directory, "teaser.mp4");
  assert.ok(statSync(teaser).size > 0 && statSync(teaser).size < 10 * 1024 * 1024);
  const sourceBytes = readFileSync(teaser);
  assert.equal(sourceBytes.length, source.bytes, "teaser.mp4 has a different size");
  assert.equal(hash(sourceBytes), source.sha256, "teaser.mp4 has different content");
  const destination = join(directory, "preview.gif");
  const filter = "fps=10,format=rgb24,scale=960:540:flags=lanczos,split[frames][colors];[colors]palettegen=max_colors=256:stats_mode=diff[palette];[frames][palette]paletteuse=dither=none:diff_mode=rectangle";
  runMediaTool("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-i", teaser, "-filter_complex", filter, "-threads", "4", "-loop", "0", destination]);
  const media = JSON.parse(runMediaTool("ffprobe", ["-v", "error", "-count_frames", "-show_format", "-show_streams", "-of", "json", destination]));
  assert.equal(media.streams.length, 1);
  const video = media.streams[0];
  assert.deepEqual([video.codec_name, video.width, video.height, Number(video.nb_read_frames)], ["gif", 960, 540, 200]);
  assert.ok(Math.abs(Number(media.format.duration) - 20) < 0.02);
  assert.ok(statSync(destination).size < 5 * 1024 * 1024, "preview.gif exceeds 5 MiB");
  const decoded = runMediaTool("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-xerror", "-i", destination, "-f", "framemd5", "-"]);
  const frames = decoded.split("\n").filter((line) => line && !line.startsWith("#")).map((line) => line.split(",").at(-1).trim());
  assert.ok(new Set(frames).size > 4, "preview.gif must animate within its four scenes");
  const bytes = readFileSync(destination);
  manifest.preview = { source: "teaser.mp4", sourceSha256: source.sha256, width: 960, height: 540, fps: 10, durationSeconds: 20, loop: true };
  manifest.files = manifest.files.filter((file) => file.name !== "preview.gif");
  manifest.files.splice(2, 0, { name: "preview.gif", bytes: bytes.length, sha256: hash(bytes) });
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 2, "Usage: node docs/demo/render-preview.mjs");
  const manifest = renderPreview(fileURLToPath(new URL("../src/assets/walkthrough/", import.meta.url)));
  process.stdout.write(JSON.stringify({ preview: manifest.preview, file: manifest.files.find((file) => file.name === "preview.gif") }, null, 2) + "\n");
}
