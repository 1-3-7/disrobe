| section | line | summary |
|---------|-----:|---------|
| clean-room-sources | 14 | format specs studied + licenses for vhd/vhdx/wim/cpio/gpt/mbr |
| container-coverage | 30 | formats-parsed tally and what each new parser enumerates |
| detection-ordering | 43 | magic/tail detection precedence and the xz-vs-tarxz heuristic |
| verification | 52 | how the new parsers are tested non-circularly |

## clean-room-sources

All new container parsers (`cpio.rs`, `vhd.rs`, `vhdx.rs`, `wim.rs`, `partition.rs`) are clean-room
reimplementations from published on-disk format specifications. No reference source was copied.

| format | primary spec studied | license of the reference doc |
|--------|----------------------|------------------------------|
| cpio newc/crc/odc | Linux kernel `Documentation/early-userspace/buffer-format.txt` (SVR4 newc 070701 / crc 070702, 110-byte hex-ascii header); POSIX odc 070707 octal layout | GPL-2.0 (doc text; not copied, only field offsets used) |
| cpio old binary | classic `struct old_cpio_header` (magic 0x71c7, 26-byte PDP-endian header: dev/ino/mode/uid/gid/nlink/rdev, mtime[2], namesize, filesize[2]) | public format knowledge |
| vhd | libyal/libvhdi `Virtual Hard Disk (VHD) image format.asciidoc` (512-byte footer big-endian, cxsparse dynamic header, 4-byte BAT entries, 0xffffffff sentinel) | LGPL-3.0+ (doc; only offsets used) |
| vhdx | libyal/libvhdi `Virtual Hard Disk version 2 (VHDX) image format.asciidoc` (vhdxfile@0, head@64K/128K, regi@192K/256K region table, BAT/Metadata region GUIDs, 64-bit BAT entries, metadata table items) | LGPL-3.0+ (doc; only offsets used) |
| wim | libyal/assorted `Windows Imaging (WIM) file format.asciidoc` + Microsoft WIM spec (208-byte _WIMHEADER_V1_PACKED, 24-byte RESHDR_DISK_SHORT, UTF-16LE XML `<WIM>`/`<IMAGE>` block) | LGPL-3.0+ / MS doc (only offsets used) |
| gpt | UEFI Specification 2.10 ch.5 (EFI PART@LBA1, 92-byte header, 128-byte partition entries, UTF-16LE name) | UEFI Forum spec (public) |
| mbr | classic MBR (partition table @0x1BE, 16-byte entries, 0x55AA@510, 0xEE = GPT protective) | public format knowledge |

Study clones lived only in `C:/Users/.../AppData/Local/Temp/disrobe-refs/` and were deleted after use;
nothing reference-derived entered the tree.

## container-coverage

Before this work: 14 structurally-parsed container formats + 12 sniff-only in `ContainerKind`.
Added 7 new `ContainerKind` variants with real parsers: `Cpio`, `Vhd`, `Vhdx`, `Wim`, `Gpt`, `Mbr`, `Xz`.

- `cpio.rs` — enumerates entries (name/mode/size/data-offset) for newc, crc, odc, and old-binary LE/BE;
  `extract_cpio` writes regular files + dirs to disk under the quota/path-sanitizer.
- `vhd.rs` — footer (cookie/type/CHS geometry/checksum-validated) + dynamic `cxsparse` header + BAT;
  reports allocated block sector list (CHS->LBA total-sector count in `VhdGeometry`).
- `vhdx.rs` — file-id + header (highest sequence number wins) + region table (BAT/Metadata GUIDs) +
  metadata items (block size / logical sector / virtual disk size) + allocated BAT block count
  (chunk-ratio aware, skips sector-bitmap entries).
- `wim.rs` — header + resource table (RESHDR_DISK_SHORT) + UTF-16LE XML image enumeration.
- `partition.rs` — MBR table (with GPT-protective detection) + GPT header + partition entries.
- `Xz` — bare `.xz` (single-stream) distinguished from tar-wrapped `.xz`.

## detection-ordering

`detect_by_magic` precedence: zip/deb/7z/rar/cab/rpm, then xz (heuristic), zstd, gzip, bzip2, pkg,
wim, vhdx, cpio, asar, tar, iso, dmg, then gpt (before mbr — GPT disks carry a protective MBR),
then mbr (least specific). `detect_by_tail` adds zip-EOCD and the VHD `conectix` footer (last 512B).

The xz-vs-tar discrimination (`smells_like_tar_decompressed`) decompresses only the first 262 bytes
of the xz stream via `liblzma` and checks for the `ustar` magic at tar offset 257 — tar-xz -> `TarXz`,
otherwise bare -> `Xz`. Undecompressable xz stubs fall through to `Xz`.

## verification

Non-circular: each parser is tested against a hand-built, spec-accurate byte fixture (real magic,
real field offsets, known field values) and asserts the recovered values — not a re-emit of the
parser's own output. The xz heuristic is tested with genuinely `liblzma`-compressed tar and
non-tar payloads. All 26 pre-existing binfmt formats remain green (only the outdated xz-stub test
was tightened to reflect the new bare-`Xz` classification).
