# Containers and archives

Before **disrobe** can decompile anything, it often has to get inside a container. The `disrobe-binfmt` layer detects <!-- m:containers_formats -->98<!-- /m --> archive, installer, filesystem, and firmware formats and writes member bytes in-tree for all <!-- m:containers_formats -->98<!-- /m -->, with auto-detection, recursive chaining through nested layers, and shared zip-slip and decompression-bomb guards.

A recursive carve-everything engine scans for every known magic, models chunked payloads, recurses by depth, and uses entropy to separate code from padding.

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

## Extraction

Most extraction happens implicitly inside `disrobe auto`, which detects a container, extracts it, and recurses into the contents. Archive-shaped inputs are also available directly:

```sh
disrobe py extract package.whl --out extracted/
disrobe auto installer.msi --out extracted/
disrobe auto firmware-dir/ --out extracted/ --batch-max-depth 6
```

Directory inputs are batch-processed recursively; `--batch-max-depth` limits directory descent. Container nesting inside a detected artifact is governed by `--max-depth` (default 8).

## Safety guards

Every extractor shares the quota machinery in `crates/disrobe-binfmt/src/quota.rs`:

- **Per-entry size cap** and **aggregate size cap** defuse decompression bombs.
- **Recursion-depth cap** defuses container-in-container bombs.
- **Zip-slip path sanitization** (`sanitize_entry_path`): every entry path is sanitized so no extraction can escape the output directory, on every format.

Bypasses of any of these are treated as security issues; see the [security policy](../security.md).
