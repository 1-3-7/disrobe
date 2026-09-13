# CLI walkthrough

The 2-minute 12-second video shows 20 CLI commands across five chapters: unpacking and routing, readable code, analysis, recovery evidence and tool integrations. The player and transcript include all 66 public top-level command names, including `help`. The 20-second excerpt contains four demonstrations. Both videos are 1920 × 1080 at 60 fps, encoded as H.264 with CRF 17 and fast-start metadata. A looping GIF renders the excerpt at 960 × 540 and 10 fps for the GitHub README.

Install the graph renderer's pinned dependencies in `xtask/graphgen` with `pnpm install --frozen-lockfile`. Node 24, FFmpeg, and ffprobe must be available. From the repository root:

```powershell
node docs/demo/capture-cli.mjs --binary C:/path/to/disrobe.exe
node docs/demo/render-media.mjs
mdbook build
```

The capture checks that the binary's actual `--version` output matches `workspace.package.version` in `Cargo.toml`, and that its public command list matches `cli-plan.mjs`. It copies the repository's small fixtures into a temporary working directory, invokes Disrobe, and records complete command output, exit codes, input hashes and recovered-file hashes in `cli-recording.json`. Recovered programs are read as text. Each command has a 30-second timeout and a 1 MiB output limit; the temporary tree stays below 16 MiB and is removed after capture.

The renderer uses the canonical social card's SVG, shared neutral color tokens, Manrope and JetBrains Mono. Command entry and reading time are edited for pace; process durations remain separate in the capture receipt. Syntax colors apply to the captured text. Longer output and source excerpts are labeled. The transcript preserves command output and recovered source, with an excerpt of the large generated completion script; `cli-recording.json` retains that script in full.

Media, captions, chapters, the poster, and their hashes are written under `docs/src/assets/walkthrough`. The renderer checks frame count, dimensions, codec, duration, chapter count, complete decoding, and file size. Each file stays below 10 MiB; the GIF stays below 5 MiB. Its manifest identifies the source excerpt by hash.

The README embeds the [release-following GIF](https://1-3-7.github.io/disrobe/latest/assets/walkthrough/preview.gif) and links to the [full video](https://1-3-7.github.io/disrobe/latest/assets/walkthrough/walkthrough.mp4). The GIF is an animated preview; the link opens the full video. To regenerate only the preview from an existing matching capture, run `node docs/demo/render-preview.mjs`.

## Release updates

The Linux x86-64 release job captures fresh output from its built, stripped release binary. Both capture and rendering receive `--release-tag`. For a versioned release, the tag, workspace version, and actual binary version must agree. The rolling `latest` alias still requires binary/workspace agreement. A mismatch fails before capture or rendering can replace the existing output.

The release includes `disrobe-<tag>-walkthrough.tar.zst`, containing the media, its manifest, and `cli-recording.json`. The archive is signed, included in `SHA256SUMS`, and covered by build-provenance attestation alongside the binary distributions. The media manifest retains the binary hash, capture version, release tag, command-recording hash, and output-file hashes.

After a successful release, the docs workflow refreshes Pages from this archive. Subsequent docs builds reuse the latest released media, so a source checkout containing an older recording does not restore an old walkthrough. Before extraction, the workflow verifies the checksum, release-workflow signature, and provenance attestation. Decompression is limited to 32 MiB and 30 seconds. Only the ten expected regular files can be extracted and copied into the site; additional files and links are rejected, preserving the existing player page. The recorded version, capture identity, and media hashes are checked before copying. Releases created before this archive format retain the source recording until a release with a walkthrough archive is available.

Use the stable [video](https://1-3-7.github.io/disrobe/latest/assets/walkthrough/walkthrough.mp4), [poster](https://1-3-7.github.io/disrobe/latest/assets/walkthrough/poster.png), and [transcript](https://1-3-7.github.io/disrobe/latest/assets/walkthrough/transcript.txt) URLs for entry points that should follow releases. A GitHub attachment URL identifies a fixed upload and does not update when a new release is published.
