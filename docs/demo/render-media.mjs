import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { vendoredFontFiles } from "../../xtask/graphgen/lib/social_card.mjs";
import { brand } from "../../xtask/graphgen/lib/brand.mjs";
import { verifyMediaVersion, workspaceVersion } from "./media-version.mjs";
import { renderPreview, runMediaTool as run } from "./render-preview.mjs";

const require = createRequire(new URL("../../xtask/graphgen/package.json", import.meta.url));
const { Resvg } = require("@resvg/resvg-js");
const { values } = parseArgs({ options: { "release-tag": { type: "string" } } });
const receiptBytes = readFileSync(new URL("cli-recording.json", import.meta.url));
const receipt = JSON.parse(receiptBytes);
assert.equal(receipt.schema, "disrobe.cli-recording.v1");
const expectedVersion = workspaceVersion(new URL("../../Cargo.toml", import.meta.url));
verifyMediaVersion(receipt.binary.version, expectedVersion, values["release-tag"]);
if (values["release-tag"] !== undefined) {
  assert.equal(receipt.workspaceVersion, expectedVersion, "recording does not attest the release workspace version");
  assert.equal(receipt.releaseTag, values["release-tag"], "recording was not captured for this release tag");
}
assert.deepEqual(receipt.scenes.map((scene) => scene.id), ["native", "indicators", "auto", "lua", "wasm", "source"]);
const { width, height, fps } = receipt.presentation;
assert.deepEqual([width, height, fps], [1920, 1080, 60]);
const output = fileURLToPath(new URL("../src/assets/walkthrough/", import.meta.url));
const fonts = vendoredFontFiles();
const mark = readFileSync(new URL("../src/assets/brand-mark-dark.svg", import.meta.url), "utf8").match(/<path[^>]+\/>/gu).join("");
const colors = brand.syntax.dark;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const escape = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const stamp = (milliseconds) => new Date(milliseconds).toISOString().slice(11, 23);
let elapsed = 0;
const cues = receipt.scenes.map((scene) => {
  assert.equal(scene.exitCode, 0);
  assert.ok(scene.elapsedMs >= 0 && scene.elapsedMs < 15_000);
  assert.ok(scene.durationMs >= 5_000 && scene.durationMs <= 8_000);
  assert.ok(scene.command.length < 94 && !scene.command.includes("\n"));
  const startMs = elapsed;
  elapsed += scene.durationMs;
  return { ...scene, startMs, endMs: elapsed };
});

function lines(text) {
  return text.trimEnd().split("\n").flatMap((line) => {
    let expanded = "";
    for (const character of line) expanded += character === "\t" ? " ".repeat(8 - expanded.length % 8) : character;
    const result = [];
    while (expanded.length > 94) {
      const space = expanded.lastIndexOf(" ", 93);
      const boundary = space > 0 ? space + 1 : 94;
      result.push(expanded.slice(0, boundary));
      expanded = expanded.slice(boundary);
    }
    return [...result, expanded];
  });
}

function colorize(line, source) {
  if (source && line.startsWith(";;")) return `<tspan fill="${colors.comment}">${escape(line)}</tspan>`;
  return line.split(/("[^"\n]*"|\$[\w]+|\b(?:module|memory|table|func|param|result|export|funcref|i32\.add|i32|local\.get|OK|Lossless|Implemented)\b|\b\d+\b)/gu).map((token) => {
    const color = /^(?:OK|Lossless|Implemented)$/u.test(token) ? "#f5f5f5" : /^"/u.test(token) ? colors.string : /^\$/u.test(token) ? colors.variable : /^(?:\d+|i32)$/u.test(token) ? colors.number : /^(?:module|memory|table|func|param|result|export|funcref|i32\.add|local\.get)$/u.test(token) ? colors.keyword : "#e5e5e5";
    return `<tspan fill="${color}">${escape(token)}</tspan>`;
  }).join("");
}

function frame(scene, index, characters, revealed, opacity) {
  const command = scene.command.slice(0, characters);
  const outputLines = lines(scene.stdout + scene.stderr);
  assert.ok(outputLines.length <= 13, `${scene.id}: terminal output needs more than 13 lines`);
  const commandMarkup = command.split(/(disrobe|Get-Content|\bcat\b|--?[A-Za-z][A-Za-z-]*)/gu).map((token) => `<tspan fill="${token === "disrobe" || token === "Get-Content" || token === "cat" ? colors.function : /^--?/u.test(token) ? colors.keyword : "#f5f5f5"}">${escape(token)}</tspan>`).join("");
  const cursorX = 132 + command.length * 18;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <rect width="1920" height="1080" fill="#101010"/>
    <g transform="translate(65 48) scale(.4)">${mark}</g>
    <text x="136" y="94" font-family="Manrope" font-size="48" fill="#f5f5f5" letter-spacing="-2">disrobe</text>
    <text x="1856" y="86" text-anchor="end" font-family="JetBrains Mono" font-size="22" fill="#a3a3a3">${escape(receipt.binary.version)}</text>
    <path d="M64 126H1856" stroke="#353535"/>
    <g opacity="${opacity}">
      <text x="64" y="192" font-family="Manrope" font-size="38" font-weight="600" fill="#f5f5f5">${escape(scene.title)}</text>
      <text x="1856" y="187" text-anchor="end" font-family="JetBrains Mono" font-size="24" fill="#a3a3a3">${String(index + 1).padStart(2, "0")} / 06</text>
      <rect x="64" y="226" width="1792" height="710" rx="12" fill="#171717" stroke="#3a3a3a"/>
      <g font-family="JetBrains Mono" font-size="30" xml:space="preserve">
        <text x="96" y="289" fill="#a3a3a3">›</text>
        <text x="132" y="289">${commandMarkup}</text>
        ${!revealed ? `<rect x="${cursorX}" y="264" width="2" height="32" fill="#f5f5f5"/>` : ""}
        ${revealed ? outputLines.map((line, row) => `<text x="96" y="${355 + row * 43}">${colorize(line, scene.id === "source")}</text>`).join("") : ""}
      </g>
      <text x="64" y="990" font-family="Manrope" font-size="27" fill="#b3b3b3">${escape(scene.description)}</text>
    </g>
    ${cues.map((_, item) => `<rect x="${64 + item * 302}" y="1034" width="282" height="3" fill="${item <= index ? "#f5f5f5" : "#353535"}"/>`).join("")}
  </svg>`;
  return new Resvg(svg, { font: { loadSystemFonts: false, fontFiles: fonts, defaultFontFamily: "JetBrains Mono" } }).render().asPng();
}

const captions = (values) => ["WEBVTT", "", ...values.flatMap((cue) => [`${stamp(cue.startMs)} --> ${stamp(cue.endMs)}`, cue.title, cue.description, ""])].join("\n");
writeFileSync(join(output, "captions.vtt"), captions(cues));
writeFileSync(join(output, "chapters.vtt"), captions(cues.map((cue) => ({ ...cue, description: "" }))));
writeFileSync(join(output, "transcript.txt"), ["Disrobe CLI walkthrough", receipt.binary.version, "", ...cues.flatMap((cue) => [`${stamp(cue.startMs)}  ${cue.title}`, `> ${cue.command}`, cue.stdout + cue.stderr, ""])].join("\n"));
writeFileSync(join(output, "chapters.ffmetadata"), [";FFMETADATA1", "title=Disrobe CLI walkthrough", ...cues.flatMap((cue) => ["[CHAPTER]", "TIMEBASE=1/1000", `START=${cue.startMs}`, `END=${cue.endMs}`, `title=${cue.title}`])].join("\n"));
const encoding = ["-c:v", "libx264", "-preset", "slow", "-crf", "17", "-pix_fmt", "yuv420p", "-movflags", "+faststart", "-threads", "4", "-an"];
const encoder = spawn("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-f", "image2pipe", "-framerate", String(fps), "-vcodec", "png", "-i", "pipe:0", "-i", join(output, "chapters.ffmetadata"), "-map_metadata", "1", ...encoding, join(output, "walkthrough.mp4")], { windowsHide: true, stdio: ["pipe", "ignore", "pipe"], timeout: 300_000 });
let diagnostics = "";
encoder.stderr.on("data", (chunk) => { diagnostics = (diagnostics + chunk.toString()).slice(-16_384); });
const completion = once(encoder, "close");
let streamError;
encoder.stdin.on("error", (error) => { streamError = error; });
try {
  for (const [index, scene] of cues.entries()) {
    let previousKey;
    let pixels;
    const total = Math.round(scene.durationMs * fps / 1000);
    for (let position = 0; position < total; position += 1) {
      const time = position * 1000 / fps;
      const characters = Math.min(scene.command.length, Math.floor(time / 550 * scene.command.length));
      const revealed = time >= 750;
      const fadeOut = index === cues.length - 1 ? 1 : (scene.durationMs - time) / 100;
      const opacity = Math.min(1, (time + 1000 / fps) / 100, fadeOut).toFixed(3);
      const key = `${characters}:${revealed}:${opacity}`;
      if (key !== previousKey) {
        pixels = frame(scene, index, characters, revealed, opacity);
        previousKey = key;
      }
      if (streamError) throw streamError;
      if (!encoder.stdin.write(pixels)) await once(encoder.stdin, "drain");
    }
    process.stdout.write(`rendered ${index + 1}/${cues.length}: ${scene.title}\n`);
  }
  encoder.stdin.end();
  const [code] = await completion;
  assert.equal(code, 0, diagnostics);
} catch (error) {
  encoder.kill();
  await completion;
  throw error;
}

writeFileSync(join(output, "poster.png"), frame(cues[0], 0, cues[0].command.length, true, "1"));
const excerpts = [0, 1, 3, 5].map((index, order) => ({ ...cues[index], sourceStartMs: cues[index].startMs, startMs: order * 5_000, endMs: (order + 1) * 5_000 }));
const filters = excerpts.map((cue, index) => `[0:v]trim=start=${cue.sourceStartMs / 1000}:duration=5,setpts=PTS-STARTPTS[v${index}]`);
filters.push(`${excerpts.map((_, index) => `[v${index}]`).join("")}concat=n=4:v=1:a=0[out]`);
run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-i", join(output, "walkthrough.mp4"), "-filter_complex", filters.join(";"), "-map", "[out]", "-map_metadata", "-1", "-map_chapters", "-1", ...encoding, join(output, "teaser.mp4")]);
writeFileSync(join(output, "teaser.vtt"), captions(excerpts));
for (const [name, seconds, chapterCount] of [["walkthrough.mp4", 36, 6], ["teaser.mp4", 20, 0]]) {
  const media = JSON.parse(run("ffprobe", ["-v", "error", "-show_format", "-show_streams", "-show_chapters", "-of", "json", join(output, name)]));
  const video = media.streams.find((stream) => stream.codec_type === "video");
  assert.equal(video.codec_name, "h264");
  assert.equal(video.width, width);
  assert.equal(video.height, height);
  assert.equal(video.avg_frame_rate, "60/1");
  assert.equal(Number(video.nb_frames), seconds * fps);
  assert.equal(media.chapters.length, chapterCount);
  assert.ok(Math.abs(Number(media.format.duration) - seconds) < 0.02);
  assert.ok(statSync(join(output, name)).size < 10 * 1024 * 1024);
  run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-xerror", "-i", join(output, name), "-f", "null", "-"]);
}
const manifest = { schema: "disrobe.walkthrough-media.v3", capturedAt: receipt.capturedAt, binary: receipt.binary, workspaceVersion: receipt.workspaceVersion, releaseTag: receipt.releaseTag, recordingSha256: hash(receiptBytes), presentation: receipt.presentation, durationSeconds: 36, teaserDurationSeconds: 20, cues: cues.map(({ id, title, description, startMs, endMs, command }) => ({ id, title, description, startMs, endMs, command })), excerpts: excerpts.map(({ id, sourceStartMs, startMs, endMs }) => ({ id, sourceStartMs, startMs, endMs })), tools: { ffmpeg: run("ffmpeg", ["-version"]).split("\n")[0] }, files: ["walkthrough.mp4", "teaser.mp4", "poster.png", "captions.vtt", "chapters.vtt", "teaser.vtt", "transcript.txt"].map((name) => { const bytes = readFileSync(join(output, name)); return { name, bytes: bytes.length, sha256: hash(bytes) }; }) };
writeFileSync(join(output, "media.json"), JSON.stringify(manifest, null, 2) + "\n");
const completed = renderPreview(output);
process.stdout.write(JSON.stringify({ durationSeconds: 36, fps, preview: completed.preview, files: completed.files }, null, 2) + "\n");
