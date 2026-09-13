import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { vendoredFontFiles } from "../../xtask/graphgen/lib/social_card.mjs";
import { brand } from "../../xtask/graphgen/lib/brand.mjs";
import { commandGroups, teaserIds, validateRecording } from "./cli-plan.mjs";
import { verifyMediaVersion, workspaceVersion } from "./media-version.mjs";
import { renderPreview, runMediaTool as run } from "./render-preview.mjs";

const require = createRequire(new URL("../../xtask/graphgen/package.json", import.meta.url));
const { Resvg } = require("@resvg/resvg-js");
const { values } = parseArgs({ options: { "release-tag": { type: "string" }, "proof-dir": { type: "string" }, "frames-only": { type: "boolean", default: false } } });
assert.ok(!values["frames-only"] || values["proof-dir"], "--frames-only requires --proof-dir");
const receiptBytes = readFileSync(new URL("cli-recording.json", import.meta.url));
const receipt = JSON.parse(receiptBytes);
validateRecording(receipt);
const expectedVersion = workspaceVersion(new URL("../../Cargo.toml", import.meta.url));
verifyMediaVersion(receipt.binary.version, expectedVersion, values["release-tag"]);
if (values["release-tag"] !== undefined) {
  assert.equal(receipt.workspaceVersion, expectedVersion);
  assert.equal(receipt.releaseTag, values["release-tag"], "recording was not captured for this release tag");
}
const { width, height, fps, openingMs, closingMs } = receipt.presentation;
const output = fileURLToPath(new URL("../src/assets/walkthrough/", import.meta.url));
const fonts = vendoredFontFiles().filter((path) => /(?:Manrope|JetBrainsMono)/u.test(path));
const mark = readFileSync(new URL("../src/assets/brand-mark-dark.svg", import.meta.url), "utf8").match(/<path[^>]+\/>/gu).join("");
const socialCard = readFileSync(new URL("../src/assets/social-card.png", import.meta.url));
const socialSvg = readFileSync(new URL("../src/assets/social-card.svg", import.meta.url), "utf8");
const palette = brand.themes.dark;
const colors = brand.syntax.dark;
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const escape = (value) => value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;");
const stamp = (milliseconds) => new Date(milliseconds).toISOString().slice(11, 23);
let elapsed = openingMs;
const cues = receipt.scenes.map((scene) => {
  const startMs = elapsed;
  elapsed += scene.durationMs;
  return { ...scene, startMs, endMs: elapsed };
});
const durationSeconds = (elapsed + closingMs) / 1000;
const chapters = [];
for (const cue of cues) {
  if (chapters.at(-1)?.title !== cue.chapter) chapters.push({ title: cue.chapter, startMs: cue.startMs, endMs: cue.endMs });
  else chapters.at(-1).endMs = cue.endMs;
}
chapters[0].startMs = 0;
chapters.at(-1).endMs += closingMs;

function wrap(text, columns = 94) {
  return text.trimEnd().split("\n").flatMap((line) => {
    let expanded = "";
    for (const character of line) expanded += character === "\t" ? " ".repeat(4 - expanded.length % 4) : character;
    const rows = [];
    while (expanded.length > columns) {
      const space = expanded.lastIndexOf(" ", columns - 1);
      const boundary = space > 0 ? space + 1 : columns;
      rows.push(expanded.slice(0, boundary));
      expanded = expanded.slice(boundary);
    }
    return [...rows, expanded];
  });
}

function colorize(line, source) {
  if (source && /^\s*(?:#|\/\/|;;)/u.test(line)) return `<tspan fill="${colors.comment}">${escape(line)}</tspan>`;
  return line.split(/("[^"\n]*"|'[^'\n]*'|\$[\w]+|\b(?:def|return|class|function|const|let|export|import|from|if|else|local|end|module|func|param|result|i32\.add|local\.get|true|false|null|None)\b|\b\d+(?:\.\d+)*\b)/gu).map((token) => {
    const color = /^["']/u.test(token) ? colors.string : /^\$/u.test(token) ? colors.variable : /^\d/u.test(token) ? colors.number : /^(?:def|return|class|function|const|let|export|import|from|if|else|local|end|module|func|param|result|i32\.add|local\.get|true|false|null|None)$/u.test(token) ? colors.keyword : palette.text;
    return `<tspan fill="${color}">${escape(token)}</tspan>`;
  }).join("");
}

function excerpt(scene, source) {
  const text = source ? scene.preview.text : scene.stdout + scene.stderr;
  const startLine = source ? scene.preview.startLine : 0;
  const lineCount = source ? scene.preview.lineCount : scene.outputLineCount;
  const lines = text.trimEnd().split("\n");
  const selected = lines.slice(startLine, lineCount === null ? undefined : startLine + lineCount);
  const rows = wrap(selected.join("\n"));
  const shown = rows.slice(0, source ? scene.preview.maximumRows : 10);
  const start = source ? scene.preview.startLine + 1 : 1;
  const shortened = rows.length > shown.length || selected.length < lines.length;
  const label = source ? scene.preview.name : scene.redirect ? `stdout → ${scene.redirect}` : "Command output";
  return { rows: shown, text: selected.join("\n"), label: label + (shortened ? ` · excerpt from line ${start}` : ""), shortened };
}

function frame(scene, index, time) {
  const source = Boolean(scene.preview) && (scene.redirect !== null || time >= 2_400);
  const shown = excerpt(scene, source);
  const characters = Math.min(scene.command.length, Math.floor(time / 350 * scene.command.length));
  const commandRows = wrap(scene.command.slice(0, characters), 94);
  assert.ok(commandRows.length <= 2, `${scene.id}: command exceeds two lines`);
  const revealed = time >= 500;
  const commandMarkup = commandRows.map((line, row) => `<text x="112" y="${337 + row * 39}">${escape(line)}</text>`).join("");
  const title = scene.title;
  assert.ok(title.length <= 65 && scene.description.length <= 118, `${scene.id}: heading or description is too long`);
  const phaseLabel = source ? "Recovered file" : "Terminal";
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080" viewBox="0 0 1920 1080">
    <rect width="1920" height="1080" fill="${palette.canvas}"/>
    <g transform="translate(66 46) scale(.42)">${mark}</g>
    <text x="140" y="92" font-family="Manrope" font-size="48" font-weight="200" fill="${palette.text}" letter-spacing="-1.4">disrobe</text>
    <text x="1856" y="84" text-anchor="end" font-family="JetBrains Mono" font-size="22" fill="${palette.muted}">${escape(receipt.binary.version)}</text>
    <path d="M64 128H1856" stroke="${palette.line}"/>
    <text x="64" y="219" font-family="Manrope" font-size="46" font-weight="600" fill="${palette.text}" letter-spacing="-1.1">${escape(title)}</text>
    <text x="1856" y="214" text-anchor="end" font-family="JetBrains Mono" font-size="22" fill="${palette.muted}">${String(index + 1).padStart(2, "0")} / ${cues.length}</text>
    <rect x="64" y="272" width="1792" height="658" rx="8" fill="${palette.surface}"/>
    <g font-family="JetBrains Mono" font-size="30" fill="${palette.text}" xml:space="preserve">
      <path d="m88 318 9 8-9 8" fill="none" stroke="${palette.muted}" stroke-width="2"/>
      ${commandMarkup}
      ${revealed ? `<path d="M96 393H1824" stroke="${palette.line}"/><text x="96" y="436" font-size="21" fill="${palette.muted}">${escape(shown.label)}</text>${shown.rows.map((line, row) => `<text x="96" y="${490 + row * 41}">${colorize(line, source)}</text>`).join("")}` : ""}
    </g>
    <text x="64" y="986" font-family="Manrope" font-size="26" fill="${palette.muted}">${escape(scene.description)}</text>
    ${chapters.map((chapter, order) => `<text x="${64 + order * 365}" y="1040" font-family="Manrope" font-size="21" font-weight="${chapter.title === scene.chapter ? 600 : 400}" fill="${chapter.title === scene.chapter ? palette.text : palette.muted}">${escape(chapter.title)}</text><rect x="${64 + order * 365}" y="1056" width="332" height="2" fill="${chapter.title === scene.chapter ? palette.text : palette.line}"/>`).join("")}
    <title>${escape(title)} — ${phaseLabel}</title>
  </svg>`;
  return raster(svg);
}

function raster(svg) {
  return new Resvg(svg, { font: { loadSystemFonts: false, fontFiles: fonts, defaultFontFamily: "JetBrains Mono" } }).render().asPng();
}

function bookend(opening) {
  if (opening) return raster(`<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080"><rect width="1920" height="1080" fill="${palette.canvas}"/><g transform="translate(0 60) scale(1.5)">${socialSvg.replace(/^<svg[^>]*>/u, "").replace(/<\/svg>\s*$/u, "")}</g><text x="1824" y="1015" text-anchor="end" font-family="JetBrains Mono" font-size="24" fill="${palette.muted}">${escape(receipt.binary.version)}</text></svg>`);
  const paths = ["recovered/hello.bin", "recovered/greet.lua", "recovered/add.wat", "recovered/report.md", "recovered/add.dr", ".disrobe/notes/renames.json", ".disrobe.toml", "recovered/disrobe.bash"];
  for (const path of paths) assert.ok(receipt.artifacts.some((artifact) => artifact.name === path), `Closing frame refers to missing ${path}`);
  return raster(`<svg xmlns="http://www.w3.org/2000/svg" width="1920" height="1080"><rect width="1920" height="1080" fill="${palette.canvas}"/><g transform="translate(64 72) scale(.7)">${mark}</g><text x="184" y="142" font-family="Manrope" font-size="72" font-weight="200" letter-spacing="-2" fill="${palette.text}">disrobe</text><text x="64" y="290" font-family="Manrope" font-size="60" font-weight="600" letter-spacing="-1.8" fill="${palette.text}">Source. Structure. Unpacked bytes.</text><text x="64" y="354" font-family="Manrope" font-size="30" fill="${palette.muted}">Continue with the recovered files, reports and your own tools.</text><path d="M64 410H1856" stroke="${palette.line}"/>${paths.map((path, index) => `<text x="${64 + (index > 3 ? 930 : 0)}" y="${490 + index % 4 * 88}" font-family="JetBrains Mono" font-size="32" fill="${palette.text}">${escape(path)}</text>`).join("")}<text x="64" y="954" font-family="JetBrains Mono" font-size="28" fill="${palette.muted}">github.com/1-3-7/disrobe</text><text x="1856" y="954" text-anchor="end" font-family="JetBrains Mono" font-size="24" fill="${palette.muted}">${escape(receipt.binary.version)}</text></svg>`);
}

const openingFrame = bookend(true);
const closingFrame = bookend(false);
if (values["proof-dir"]) {
  const proof = resolve(values["proof-dir"]);
  mkdirSync(proof, { recursive: true });
  writeFileSync(join(proof, "00-opening.png"), openingFrame);
  for (const [index, cue] of cues.entries()) {
    writeFileSync(join(proof, `${String(index + 1).padStart(2, "0")}-${cue.id}-output.png`), frame(cue, index, 1_800));
    if (cue.preview) writeFileSync(join(proof, `${String(index + 1).padStart(2, "0")}-${cue.id}-file.png`), frame(cue, index, 4_000));
  }
  writeFileSync(join(proof, "21-closing.png"), closingFrame);
}

if (!values["frames-only"]) {
  const captions = (items) => ["WEBVTT", "", ...items.flatMap((cue) => [`${stamp(cue.startMs)} --> ${stamp(cue.endMs)}`, cue.title, cue.description ?? "", ""])].join("\n").trimEnd() + "\n";
  writeFileSync(join(output, "captions.vtt"), captions([{ startMs: 0, endMs: openingMs, title: "Disrobe: see the software underneath.", description: "Recover source, structure and unpacked bytes." }, ...cues, { startMs: elapsed, endMs: elapsed + closingMs, title: "Continue with the recovered files, reports and your own tools." }]));
  writeFileSync(join(output, "chapters.vtt"), captions(chapters));
  writeFileSync(join(output, "transcript.txt"), ["Disrobe CLI walkthrough", receipt.binary.version, "", "Demonstrated commands", "", ...cues.flatMap((cue) => [`${stamp(cue.startMs)}  ${cue.title}`, cue.description, `> ${cue.command}`, ...(!cue.redirect ? [cue.stdout + cue.stderr] : []), ...(cue.preview ? [`File: ${cue.preview.name}`, cue.preview.bytes <= 16_384 ? cue.preview.text : `${excerpt(cue, true).label}\n${excerpt(cue, true).text}`] : []), ""]), `Command reference: all ${receipt.catalog.commands.length} public top-level commands, including help`, "", ...commandGroups.flatMap((group) => [group.title, group.commands.join("  "), ""])].join("\n"));
  writeFileSync(join(output, "chapters.ffmetadata"), [";FFMETADATA1", "title=Disrobe CLI walkthrough", ...chapters.flatMap((cue) => ["[CHAPTER]", "TIMEBASE=1/1000", `START=${cue.startMs}`, `END=${cue.endMs}`, `title=${cue.title}`])].join("\n"));
  const encoding = ["-c:v", "libx264", "-preset", "slow", "-crf", "17", "-pix_fmt", "yuv420p", "-color_range", "tv", "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709", "-movflags", "+faststart", "-threads", "4", "-an"];
  const encoder = spawn("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-f", "image2pipe", "-framerate", String(fps), "-vcodec", "png", "-i", "pipe:0", "-i", join(output, "chapters.ffmetadata"), "-map_metadata", "1", "-vf", "scale=in_range=full:out_range=limited:out_color_matrix=bt709", ...encoding, join(output, "walkthrough.mp4")], { windowsHide: true, stdio: ["pipe", "ignore", "pipe"], timeout: 900_000 });
  let diagnostics = "";
  encoder.stderr.on("data", (chunk) => { diagnostics = (diagnostics + chunk.toString()).slice(-16_384); });
  const completion = once(encoder, "close");
  let streamError;
  encoder.stdin.on("error", (error) => { streamError = error; });
  async function writeFrames(total, pixelsAt) {
    let previousKey;
    let pixels;
    for (let position = 0; position < total; position += 1) {
      const time = position * 1000 / fps;
      const key = time < 500 ? position : time < 2_400 ? "output" : "file";
      if (key !== previousKey) { pixels = pixelsAt(time); previousKey = key; }
      if (streamError) throw streamError;
      if (!encoder.stdin.write(pixels)) await once(encoder.stdin, "drain");
    }
  }
  try {
    await writeFrames(openingMs * fps / 1000, () => openingFrame);
    for (const [index, cue] of cues.entries()) {
      await writeFrames(cue.durationMs * fps / 1000, (time) => frame(cue, index, time));
      process.stdout.write(`rendered ${index + 1}/${cues.length}: ${cue.title}\n`);
    }
    await writeFrames(closingMs * fps / 1000, () => closingFrame);
    encoder.stdin.end();
    const [code] = await completion;
    assert.equal(code, 0, diagnostics);
  } catch (error) {
    encoder.kill();
    await completion;
    throw error;
  }
  writeFileSync(join(output, "poster.png"), openingFrame);
  const excerpts = teaserIds.map((id, order) => { const cue = cues.find((cue) => cue.id === id); assert.ok(cue); return { ...cue, sourceStartMs: cue.startMs, startMs: order * 5_000, endMs: (order + 1) * 5_000 }; });
  const filters = excerpts.map((cue, index) => `[0:v]trim=start=${cue.sourceStartMs / 1000}:duration=5,setpts=PTS-STARTPTS[v${index}]`);
  filters.push(`${excerpts.map((_, index) => `[v${index}]`).join("")}concat=n=4:v=1:a=0[out]`);
  run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-y", "-i", join(output, "walkthrough.mp4"), "-filter_complex", filters.join(";"), "-map", "[out]", "-map_metadata", "-1", "-map_chapters", "-1", ...encoding, join(output, "teaser.mp4")]);
  writeFileSync(join(output, "teaser.vtt"), captions(excerpts));
  for (const [name, seconds, chapterCount] of [["walkthrough.mp4", durationSeconds, chapters.length], ["teaser.mp4", 20, 0]]) {
    const media = JSON.parse(run("ffprobe", ["-v", "error", "-show_format", "-show_streams", "-show_chapters", "-of", "json", join(output, name)]));
    const video = media.streams.find((stream) => stream.codec_type === "video");
    assert.deepEqual([video.codec_name, video.width, video.height, video.avg_frame_rate, video.color_space, video.color_range], ["h264", width, height, "60/1", "bt709", "tv"]);
    assert.equal(Number(video.nb_frames), seconds * fps);
    assert.equal(media.chapters.length, chapterCount);
    assert.ok(Math.abs(Number(media.format.duration) - seconds) < 0.02);
    assert.ok(statSync(join(output, name)).size < 10 * 1024 * 1024, `${name} exceeds 10 MiB`);
    run("ffmpeg", ["-hide_banner", "-loglevel", "error", "-nostdin", "-xerror", "-i", join(output, name), "-f", "null", "-"]);
  }
  const manifest = { schema: "disrobe.walkthrough-media.v4", capturedAt: receipt.capturedAt, binary: receipt.binary, workspaceVersion: receipt.workspaceVersion, releaseTag: receipt.releaseTag, recordingSha256: hash(receiptBytes), socialCardSha256: hash(socialCard), presentation: receipt.presentation, durationSeconds, teaserDurationSeconds: 20, commandCount: cues.length, publicCommandCount: receipt.catalog.commands.length, chapters, cues: cues.map(({ id, chapter, title, description, startMs, endMs, command }) => ({ id, chapter, title, description, startMs, endMs, command })), excerpts: excerpts.map(({ id, sourceStartMs, startMs, endMs }) => ({ id, sourceStartMs, startMs, endMs })), tools: { ffmpeg: run("ffmpeg", ["-version"]).split("\n")[0] }, files: ["walkthrough.mp4", "teaser.mp4", "poster.png", "captions.vtt", "chapters.vtt", "teaser.vtt", "transcript.txt"].map((name) => { const bytes = readFileSync(join(output, name)); return { name, bytes: bytes.length, sha256: hash(bytes) }; }) };
  writeFileSync(join(output, "media.json"), JSON.stringify(manifest, null, 2) + "\n");
  const completed = renderPreview(output);
  process.stdout.write(JSON.stringify({ durationSeconds, fps, preview: completed.preview, files: completed.files }, null, 2) + "\n");
}
