# Container, archive, and firmware in-tree extraction

- id: `binfmt-extract`
- ecosystem: binfmt
- claim: disrobe extracts member bytes in-tree for every container, archive, and firmware format it detects, with no metadata-only or external-tool-gated formats.
- measured: 98 extracted / 98 detected
- oracle strength: strong
- CI-attested: yes [CI]
- external oracle: per-format in-tree member-byte extraction count (every detected format writes real bytes)
- reproduce: `cargo test -p disrobe-binfmt every_real_format_extracts_in_tree`
- gate source: ContainerKind enum crates/disrobe-binfmt/src/container.rs (98 real variants excluding None); all 98 write member bytes in-tree per ContainerKind::extracted_in_tree_count, asserted in crates/disrobe-binfmt/src/container.rs tests detected_count_is_ninety_eight and every_real_format_extracts_in_tree (0 metadata-summary-only, 0 external-tool-gated); the superset spans archives/installers (ZIP/tar/7z/RAR/cab/MSI/NSIS/deb/rpm/Docker/OCI/ISO), bare single-stream compression (gz/bz2/zst/lzma/lzip/lz4-frame/zlib/.Z), legacy archives (ar/arj/arc/lzh/lzop/uzip/xamarin-xalz/par2/ELF-overlay carve), embedded-linux filesystems (squashfs/cramfs/ext4/romfs/minixfs/jffs2/ubi-ubifs/yaffs/erofs/ntfs/android-sparse/btrfs-send), disk-image/partition containers (GPT/MBR/VHD/VHDX/WIM walked through FAT), and vendor firmware decryptors (D-Link AES/EnGenius XOR/Autel table/QNAP PC1 plus CRC-verified Netgear/Xiaomi/Tesla carves); a recursive carve-everything engine (multi-magic scan, chunk model, depth recursion, entropy gating) drives nested extraction. InnoSetup writes the decoded setup-data block stream (per-file split via the version-specific TSetupHeader parse is the documented limit) and InstallShield writes its stored and zlib members; the arj/arc/stuffit/partclone heavy codecs are carved verbatim with a documented note
