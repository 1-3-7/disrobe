# Containers and archives

Before `disrobe` can decompile anything, it often has to get inside a container. The `disrobe-binfmt` layer detects and writes member bytes in-tree for every format below, with auto-detection, recursive chaining through nested layers, and shared zip-slip and decompression-bomb guards.

## At a glance

| Surface | Support |
|---|---|
| Formats | <!-- m:containers_formats -->100<!-- /m --> archive, installer, filesystem, and firmware formats detected, with member bytes written in-tree for all <!-- m:containers_formats -->100<!-- /m --> |
| Carve engine | A recursive carve-everything scan for every known magic, modelling chunked payloads, recursing by depth, and using entropy to separate code from padding |
| Nesting | Container-in-container chaining, governed by `--max-depth` (default 8) |
| Directory input | Batch-processed recursively, bounded by `--batch-max-depth` |
| Guards | Per-entry and aggregate size caps, recursion-depth cap, zip-slip path sanitization, on every format |

## Supported formats

| Category | Formats |
|---|---|
| Archives and installers | ZIP (incl. ZIP64 + AES), tar.gz / tar.bz2 / tar.xz / tar.zst, 7z, RAR4 and RAR5 (stored members from both; RAR5 LZ "normal" method decoded in-tree; RAR 2.9/3.x LZ used by compressed RAR4 is named per-entry, not decoded in-tree), `.cab`, MSI, MSIX / APPX, NSIS (solid and non-solid), Inno Setup (decoded setup-data block stream; per-file split via version-specific `TSetupHeader` parse is the documented limit), InstallShield (stored and zlib members), `.deb`, `.rpm` (metadata), AppImage, Flatpak, Snap |
| Bare compression streams | gzip, bzip2, zstd, lzma, lzip, lz4-frame, zlib, `.Z` (Unix compress) |
| Legacy archives | ar, arj (methods 1-3 decoded; method 4 carved verbatim), arc (rle / squeeze / lzw decoded; methods 5-7 carved verbatim), lzh, lzop, FreeBSD uzip, Xamarin xalz, par2, ELF appended-overlay carve, StuffIt (classic stored forks decoded; compressed forks carved verbatim with a documented note), partclone (decoded) |
| Embedded-linux filesystems | squashfs, cramfs, ext4, romfs, minixfs, jffs2, UBI + UBIFS, yaffs, erofs (chunk and lcluster lz4 / deflate / zstd decoded; microlzma and compact index carved), NTFS, android-sparse, btrfs-send |
| Disk images and partitions | GPT and MBR (partition tables parsed; each partition carved and recursed in-tree), VHD (fixed and dynamic BAT), VHDX (region table + BAT; logical disk materialized from the block-allocation table, then partition-carved and FAT12 / 16 / 32 walked to pull individual stored files), WIM (header resources with XPRESS / LZX / LZMS chunk payloads decompressed in-tree), FAT12 / 16 / 32 (boot sector, FAT chain walk, root and subdirectory traversal) |
| Apple | `.dmg` (UDIF: koly trailer + blkx mish chunks; ADC / zlib / bzip2 / LZFSE / LZMA chunk decoders; then HFS+ catalog walk extracts individual files, all in-tree), `.pkg` (xar TOC + gzip / bzip2 heap, extracted in-tree) |
| Vendor firmware | D-Link (SHRS / encrypted-img AES / alpha / fpkg), EnGenius XOR, Autel ECC table, QNAP PC1, plus CRC-verified Netgear (chk / trx), Xiaomi, Tesla, HP, Moxa, INSTAR, and Airoha carves; OTP-AES Airoha firmware is an information-theoretic wall and is carved verbatim |
| Standalone executables | Bun `--compile` binaries (embedded JS module graph + sourcemaps), Unity AssetBundle (UnityFS) |
| App / runtime | Electron `.asar`, Docker image tarball, OCI image manifest + layers, ISO 9660 + Joliet (extracted in-tree) |

## Commands

Most extraction happens implicitly inside `disrobe auto`, which detects a container, extracts it, and recurses into the contents. Archive-shaped inputs are also available directly:

```sh
disrobe py extract package.whl --out extracted/
disrobe auto installer.msi --out extracted/
disrobe auto firmware-dir/ --out extracted/ --batch-max-depth 6
disrobe extract crash.dmp --out carved/
```

Directory inputs are batch-processed recursively; `--batch-max-depth` limits directory descent. Container nesting inside a detected artifact is governed by `--max-depth` (default 8).

## Coverage and fidelity

### Windows crash dumps

`disrobe extract crash.dmp` (or `disrobe auto crash.dmp`) carves the loaded PE modules out of a Windows minidump. It parses the stream directory, reads the module and memory lists, and for each module rebuilds an in-memory PE image by copying whatever memory the dump actually captured into a buffer at the correct RVAs, rewriting each section's file-offset field to match its virtual address so downstream PE parsers read the result as a well-formed image. Coverage is reported per page: the summary records how many bytes were recovered, which ranges the dump truncated, and which it never captured, with a reason for each gap, so a partially captured module is never presented as complete. The carve is graded by wrapping a real on-disk PE into a minidump and confirming the carved `.text` comes back byte-identical (`minidump_real_pe.rs`); each carved module and a `.disrobe-minidump.json` coverage summary land in the output directory.

### Deno eszip archives

The `disrobe-binfmt` eszip reader (`disrobe_binfmt::containers::eszip`) parses a Deno eszip module-graph archive, versions 2 through 2.3, including one embedded inside a `deno compile` standalone executable, and reconstructs the module graph: each module's specifier, kind, and source bytes, plus redirects and npm specifiers, with per-module source-hash verification that drops any module whose stored hash does not match. It is exercised by a build-then-parse round-trip that also confirms a corrupted source hash is rejected.

### Safety guards

Every extractor shares the quota machinery in `crates/disrobe-binfmt/src/quota.rs`:

- **Per-entry size cap** and **aggregate size cap** defuse decompression bombs.
- **Recursion-depth cap** defuses container-in-container bombs.
- **Zip-slip path sanitization** (`sanitize_entry_path`): every entry path is sanitized so no extraction can escape the output directory, on every format.

Bypasses of any of these are treated as security issues; see the [security policy](../security.md).

## Limits

Where a format's payload is not decoded in-tree, the table above names it per entry rather than implying full extraction:

- Compressed RAR4 (RAR 2.9/3.x LZ) is named per-entry, not decoded.
- Inno Setup splits per file only through a version-specific `TSetupHeader` parse; that is the documented limit.
- arj method 4, arc methods 5-7, StuffIt compressed forks, and erofs microlzma and compact index are carved verbatim rather than decoded.
- OTP-AES Airoha firmware is an information-theoretic wall and is carved verbatim.
- A minidump only contains the memory it captured. Truncated and never-captured ranges are reported with a reason per gap instead of being filled in.
