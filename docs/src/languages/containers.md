# Containers and archives

Before `disrobe` can decompile anything, it often has to get inside a container. The `disrobe-binfmt` layer detects every format below and carries an in-tree member-byte extractor for each, with auto-detection, recursive chaining through nested layers, and shared zip-slip and decompression-bomb guards. A committed input drives 39 of them to member bytes on disk; the rest are unverified rather than shown to fail, because no committed input reaches them.

## At a glance

| Surface | Support |
|---|---|
| Formats declared | <!-- roster-breadth:containers-declared -->101<!-- /roster-breadth --> archive, installer, filesystem, and firmware formats, each carrying an in-tree extractor |
| Formats exercised | <!-- roster-breadth:containers-exercised -->41<!-- /roster-breadth --> of them are driven to member bytes on disk by an input this repository commits, measured by `crates/disrobe-cli/tests/container_breadth.rs` and pinned in `crates/disrobe-cli/tests/golden/container_breadth.txt`. The rest carry an extractor that no committed input reaches, so they are unverified rather than shown to fail and the declared roster is a capability list rather than a measurement |
| Carve engine | A recursive carve-everything scan for every known magic, modeling chunked payloads, recursing by depth, and using entropy to separate code from padding |
| Nesting | Container-in-container chaining, governed by `--max-depth` (default 8) |
| Directory input | Batch-processed recursively, bounded by `--batch-max-depth` |
| Guards | Per-entry and aggregate size caps, recursion-depth cap, zip-slip path sanitization, on every format |

## Supported formats

| Category | Formats |
|---|---|
| Archives and installers | ZIP (incl. ZIP64 + AES), tar.gz / tar.bz2 / tar.xz / tar.zst, 7z, RAR4 and RAR5 (stored members from both; RAR5 LZ "normal" method decoded in-tree; RAR 2.9/3.x LZ, PPMd, mixed LZ and PPMd blocks, and canonical delta and x86 filter programs decoded in-tree, with every decoded member checked against the CRC-32 its header declares), `.cab`, MSI, MSIX / APPX, NSIS (solid and non-solid), Inno Setup 4.0.9 through setup-data profile 7.0.0.3 (stored, zlib, BZip2, LZMA1, and LZMA2 members, including solid groups), InstallShield legacy cabinets (`ISc(` majors 0 and 5: stored members, u16-length chunk-framed raw DEFLATE, and full-flush raw DEFLATE, with obfuscated members decoded before inflate), `.deb`, `.rpm` (metadata), AppImage Type 1 (ISO 9660, Rock Ridge, and zisofs) and Type 2 (SquashFS), Flatpak, Snap |
| Bare compression streams | gzip, bzip2, zstd, lzma, lzip, lz4-frame, zlib, `.Z` (Unix compress) |
| Legacy archives | ar, arj (methods 0-4 decoded, with header and member CRC32 verified; split volumes refused by name), arc (methods 1-9 decoded; independent byte checks cover methods 2 and 5-9; methods 8-9 use grouped dynamic LZW with exact declared-size and CRC checks; methods 10-11 refused), LZH header levels 0-3 (`-lh0-` through `-lh7-`, `-lhx-`, `-lz4-`, `-lz5-`, `-lzs-`, and `-pm0-` decoded; `-lhd-` directories retained; `-lhd-` symbolic links refused; `-pm1-` and `-pm2-` decoded in tree and reaching extraction, each member checked against the CRC-16 its archiver stored; byte, code-page, and UTF-16 paths recovered; missing split volumes refused), lzop, FreeBSD uzip, Xamarin xalz, par2, ELF appended-overlay carve, StuffIt (classic stored, method 2, method 5 LZAH and method 13 forks decoded with record-header and fork CRC validation; StuffIt 5 containers parsed and their Arsenic and stored forks decoded in tree, though extraction still carves a StuffIt 5 archive rather than writing its forks; classic methods 6 and 8 and StuffIt 5 method 14 are not implemented and refuse by name, because no archive using them was found to grade a decoder against; encrypted forks refused), partclone (decoded) |
| Embedded-linux filesystems | squashfs, cramfs, ext4, romfs, minixfs, jffs2, UBI + UBIFS, yaffs, erofs (full and compact indexes with lz4, deflate, zstd, and microlzma decoded), NTFS, android-sparse, btrfs-send |
| Disk images and partitions | GPT and MBR (partition tables parsed; each partition carved and recursed in-tree), VHD (fixed and dynamic BAT), VHDX (region table + BAT; logical disk materialized from the block-allocation table, then partition-carved and FAT12 / 16 / 32 walked to pull individual stored files), WIM (header resources with XPRESS / LZX / LZMS chunk payloads decompressed in-tree), FAT12 / 16 / 32 (boot sector, FAT chain walk, root and subdirectory traversal) |
| Apple | `.dmg` (UDIF: koly trailer + blkx mish chunks; ADC / zlib / bzip2 / LZFSE / LZMA chunk decoders; then HFS+ catalog walk extracts individual files, all in-tree), `.pkg` (xar TOC + gzip / bzip2 heap, extracted in-tree) |
| Vendor firmware | D-Link (SHRS / encrypted-img AES / alpha / fpkg), EnGenius XOR, Autel ECC table, QNAP PC1, plus CRC-verified Netgear (chk / trx), Xiaomi, Tesla, HP, Moxa, INSTAR, and Airoha carves; OTP-AES Airoha firmware is an information-theoretic wall and is carved verbatim |
| Standalone executables | Bun `--compile` binaries (embedded JS module graph + sourcemaps), Unity AssetBundle (UnityFS), .NET single-file bundles (majors 1, 2 and 6; embedded assemblies routed to the CIL decompiler, native entries to the native pass) |
| App / runtime | Electron `.asar`, Docker image tarball, OCI image manifest + layers, ISO 9660 with Joliet fallback, Rock Ridge names, ordered multi-extent files, and zisofs v1 (extracted in-tree) |

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

- RAR 2.9/3.x members carry their transforms as RARVM programs. disrobe identifies a program by exact length and CRC-32 and runs a native transform for the canonical delta, x86 e8, x86 e8/e9, itanium, rgb and audio programs. It does not interpret RARVM bytecode, so a member carrying any other program is refused by name. The corpus grades the delta and x86 e8/e9 transforms against a real archive. The plain x86 e8, itanium, rgb and audio transforms have no real archive in the corpus yet, so their output rests on the CRC-32 check every decoded member passes and on known-answer tests rather than on a graded fixture. The crate publishes this gap as `RAR3_FILTERS_WITHOUT_REAL_ARTIFACT` and `RAR3_FILTER_COVERAGE_NOTE` in `disrobe_binfmt::containers::rar`. Encrypted members, multivolume continuation, and solid state carried from an earlier entry are refused by name.
- Inno Setup follows finite version profiles from the loader through both metadata blocks, file and data records, solid groups, filters, and checksums. Unsupported profiles and encrypted content without a secret refuse by name.
- ARC methods 10-11 are refused.
- StuffIt 5 containers are parsed and their forks decode in tree, but extraction still carves the archive verbatim rather than writing each fork, so `disrobe auto` recovers a StuffIt 5 archive as one blob. Classic StuffIt forks are unaffected and extract per fork.
- OTP-AES Airoha firmware is an information-theoretic wall and is carved verbatim.
- A minidump only contains the memory it captured. Truncated and never-captured ranges are reported with a reason per gap instead of being filled in.
