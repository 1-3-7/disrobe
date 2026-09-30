# Input bounds

Every parser treats its input as hostile. Counts, sizes, recursion depth, work and output are capped by named constants, and input that exceeds a cap is refused with a typed error instead of exhausting memory or time. `cargo xtask regen` generates this page from every module-level constant in `crates/*/src` whose name starts with `MAX_` or ends with `_LIMIT`, `_BUDGET` or `_CAP`, and `cargo xtask regen --check` fails when it is stale. The kind column is derived from the constant name.

2175 bounds (count 215, other 1020, output 64, recursion 219, size 478, work 179).

| Crate | Constant | Kind | Type | Value | File |
| --- | --- | --- | --- | --- | --- |
| `disrobe-binfmt` | `SCAN_HIT_CAP` | other | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `STREAM_DECODE_CAP` | other | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `TOTAL_WORK_CHUNK_CAP` | work | `usize` | `1 << 16` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `MAX_MEMBER_COUNT` | count | `usize` | `100_000` | `crates/disrobe-binfmt/src/chain_detector.rs` |
| `disrobe-binfmt` | `MAX_STREAM_BYTES` | size | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/chain_detector.rs` |
| `disrobe-binfmt` | `MAX_OMAP_ENTRIES` | count | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/apfs.rs` |
| `disrobe-binfmt` | `MAX_BASIC_HEADER` | other | `usize` | `2600` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `MAX_EXT_HEADER_BLOCKS` | other | `usize` | `256` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `MAX_EXT_HEADER_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `LZMA_ALONE_DETECT_DICT_LIMIT` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/bare_stream.rs` |
| `disrobe-binfmt` | `MAX_ASSEMBLIES` | other | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_BOOT_MANIFEST_LEN` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_WASM_DATA_SEGMENTS` | other | `u64` | `1024` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_WEBCIL_SECTIONS` | other | `usize` | `96` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_REPLAY_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/btrfs_send.rs` |
| `disrobe-binfmt` | `BACK_SCAN_LIMIT` | other | `usize` | `8 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/bun.rs` |
| `disrobe-binfmt` | `MAX_MODULES` | other | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/bun.rs` |
| `disrobe-binfmt` | `MAX_NAME_BYTES` | size | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cab.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_DOC_LEN` | size | `usize` | `16384` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_FILETABLE_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_LEN` | size | `usize` | `512` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_NAME_LEN` | size | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_SOURCE_FILES` | count | `usize` | `512` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_RECORDS` | count | `usize` | `65536` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_SCAN_ATTEMPTS` | other | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | `usize` | `8192` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STUB_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/cython_stub.rs` |
| `disrobe-binfmt` | `MAX_MAGIC_CANDIDATES` | other | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/deno_compile.rs` |
| `disrobe-binfmt` | `MAX_MEDIA_TYPE` | other | `u8` | `20` | `crates/disrobe-binfmt/src/containers/deno_compile.rs` |
| `disrobe-binfmt` | `MAX_CHUNKS` | other | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `MAX_CHUNK_PREALLOC` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `MAX_IMAGE_BYTES` | size | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `DEPS_JSON_PARSE_CAP` | other | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_EMBEDDED_FILES` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_PATH_LEN` | size | `usize` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_PLAUSIBLE_MAJOR_VERSION` | other | `u32` | `64` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_MAGIC_CANDIDATES` | other | `usize` | `64` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `MAX_NAME_UNITS` | other | `usize` | `2048` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `NESTING_LIMIT` | recursion | `&str` | `"Enigma Virtual Box directory nesting exceeds the supported depth"` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `PE_SECTION_LIMIT` | other | `usize` | `96` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_FULL_INDEX_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_LZMA_DICTIONARY` | other | `u32` | `8 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_PCLUSTER_DECODED` | other | `usize` | `12 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_PCLUSTER_ENCODED` | other | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_CANDIDATE_OFFSETS` | other | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/eszip.rs` |
| `disrobe-binfmt` | `MAX_EXT4_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_EXT4_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_EXTENT_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_DIR_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/fat.rs` |
| `disrobe-binfmt` | `MAX_DIR_RECURSION` | recursion | `u32` | `64` | `crates/disrobe-binfmt/src/containers/fat.rs` |
| `disrobe-binfmt` | `MAX_PART_OUTPUT` | output | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_STATIC_DELTA_PART_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_STATIC_DELTA_SUPERBLOCK_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_FORK_EXTENTS` | other | `usize` | `1 << 16` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_NODES` | count | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_OVERFLOW_RECORDS` | count | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_INNO_FILE_NAME_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_HEADER_STRING` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_OUTPUT` | output | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_TABLE_ENTRIES` | count | `u32` | `1 << 20` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_TOTAL_ENTRIES` | count | `u32` | `4_000_000` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `CHUNK_OUTPUT_LIMIT` | output | `usize` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_FILE_GROUPS` | other | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_NAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_CE_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_DIRECTORIES` | other | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_DIR_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_EXTENTS` | other | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_RECORDS` | count | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_SUSP_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_ZISOFS_BLOCK_POINTERS` | other | `usize` | `131_073` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/jffs2.rs` |
| `disrobe-binfmt` | `MAX_NODES` | count | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/jffs2.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_DIGEST_ITERATIONS` | work | `u32` | `1_000_000` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_KEY_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_PAYLOAD_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_PAYLOAD_OFFSET_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LZH_HEADER_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-binfmt/src/containers/lzh.rs` |
| `disrobe-binfmt` | `MAX_LZH_MEMBERS` | count | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/lzh.rs` |
| `disrobe-binfmt` | `MAX_CARVE_STEPS` | work | `u64` | `1 << 26` | `crates/disrobe-binfmt/src/containers/minidump/carve.rs` |
| `disrobe-binfmt` | `MAX_MEMORY_REGIONS` | other | `u64` | `8_000_000` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_MODULES` | other | `u32` | `262_144` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_BYTES` | size | `u32` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_PDB_PATH_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_SIZE_OF_IMAGE` | size | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_STREAMS` | other | `u32` | `65_536` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_CONTAINER_METADATA_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/mod.rs` |
| `disrobe-binfmt` | `MAX_STREAM_BYTES` | size | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/msi.rs` |
| `disrobe-binfmt` | `APPX_MANIFEST_READ_CAP` | other | `u64` | `1 << 20` | `crates/disrobe-binfmt/src/containers/msix.rs` |
| `disrobe-binfmt` | `LZMA_PROPS_LIMIT` | work | `u8` | `9 * 5 * 5` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_FILE_BYTES` | size | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_HEADER_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_SOLID_BYTES` | size | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILEZ_CONTENT` | other | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_DEPTH` | recursion | `u32` | `64` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_DIR_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_FILES` | count | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_OBJECT_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_TEXT_BYTES` | size | `u64` | `1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `PM1_TREE_WALK_LIMIT` | other | `usize` | `5` | `crates/disrobe-binfmt/src/containers/pmarc.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/rar.rs` |
| `disrobe-binfmt` | `MAX_FILTER_INVOCATIONS` | other | `usize` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_FILTER_PROGRAMS` | other | `usize` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_PROGRAM_LENGTH` | size | `u32` | `0x0001_0000` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_RECORD_LENGTH` | size | `usize` | `0xffff` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_FREQ` | other | `u8` | `124` | `crates/disrobe-binfmt/src/containers/rar_ppmd.rs` |
| `disrobe-binfmt` | `MAX_BLOCKS_PER_MEMBER` | other | `u32` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_FILTER_RECORD` | other | `usize` | `0xffff` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | size | `usize` | `15` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_FILTERS` | other | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_FILTER_BLOCK_SIZE` | size | `u64` | `0x40_0000` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | size | `usize` | `15` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_HEADER_ENTRIES` | count | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_HEADER_STORE` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_TAG_VALUES` | other | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_RAW_IMAGE` | other | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/sparse.rs` |
| `disrobe-binfmt` | `MAX_METADATA_BLOCK` | other | `usize` | `8192` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_PATH_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_WALK_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_CD_ENTRIES` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `MAX_COMMENT` | other | `usize` | `0xFFFF` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `SEARCH_BUDGET` | work | `usize` | `MAX_COMMENT + EOCD_FIXED_LEN + 4` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `MAX_FOLDER_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_RECORDS` | count | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_FOLDER_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_PEBS` | other | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/ubifs.rs` |
| `disrobe-binfmt` | `MAX_FFS_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_FV_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_SECTIONS_PER_FILE` | other | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_BLOCK_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_NODE_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_STRING_SCAN` | other | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_UZIP_PREALLOC` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/uzip.rs` |
| `disrobe-binfmt` | `MAX_UZIP_PREALLOC_U64` | other | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/uzip.rs` |
| `disrobe-binfmt` | `MAX_BAT_ENTRIES` | count | `usize` | `1 << 22` | `crates/disrobe-binfmt/src/containers/vhd.rs` |
| `disrobe-binfmt` | `MAX_DENTRY_COUNT` | count | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/wim_image.rs` |
| `disrobe-binfmt` | `MAX_TREE_DEPTH` | recursion | `u32` | `512` | `crates/disrobe-binfmt/src/containers/wim_image.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_MEMBER_BYTES` | size | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_TOC_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/yaffs.rs` |
| `disrobe-binfmt` | `MAX_SECTION_NAME` | other | `usize` | `512` | `crates/disrobe-binfmt/src/coverage/elf.rs` |
| `disrobe-binfmt` | `MAX_LOAD_COMMANDS` | other | `u64` | `65_536` | `crates/disrobe-binfmt/src/coverage/macho.rs` |
| `disrobe-binfmt` | `MAX_SLICES` | other | `u64` | `4_096` | `crates/disrobe-binfmt/src/coverage/macho.rs` |
| `disrobe-binfmt` | `MAX_COVERAGE_REGIONS` | other | `usize` | `65_536` | `crates/disrobe-binfmt/src/coverage/mod.rs` |
| `disrobe-binfmt` | `MAX_OVERLAP_RECORDS` | count | `usize` | `4_096` | `crates/disrobe-binfmt/src/coverage/mod.rs` |
| `disrobe-binfmt` | `DIRECTORY_LIMIT` | other | `u32` | `16` | `crates/disrobe-binfmt/src/coverage/pe.rs` |
| `disrobe-binfmt` | `MAX_DEBUG_DIRECTORY_ENTRIES` | count | `u64` | `4_096` | `crates/disrobe-binfmt/src/coverage/pe.rs` |
| `disrobe-binfmt` | `MAX_U32_LEB_BYTES` | size | `usize` | `5` | `crates/disrobe-binfmt/src/coverage/wasm.rs` |
| `disrobe-binfmt` | `MAX_DT_STRSZ` | other | `u64` | `0x100_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_ENTRIES` | count | `usize` | `0x10_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_STRING_OUTPUT` | output | `usize` | `0x100_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_NEEDED` | other | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_PROGRAM_HEADERS` | other | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_STRING_LEN` | size | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_CAPTURE_OUTPUT` | output | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/external_wrap.rs` |
| `disrobe-binfmt` | `MAX_DISK_NESTING_DEPTH` | recursion | `u32` | `4` | `crates/disrobe-binfmt/src/extract.rs` |
| `disrobe-binfmt` | `MAX_ITERATED_RECORDS` | work | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RELOCATION_CHAIN_STEPS` | work | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RELOCATION_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RESOURCE_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_TOTAL_ITERATED_BYTES` | work | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_UNIQUE_IMPORTS` | other | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_ENTRY_COMPONENT_BYTES` | size | `usize` | `255` | `crates/disrobe-binfmt/src/quota.rs` |
| `disrobe-binfmt` | `MAX_ENTRY_PATH_BYTES` | size | `usize` | `4096` | `crates/disrobe-binfmt/src/quota.rs` |
| `disrobe-binfmt` | `MAX_NOTES_PER_SEGMENT` | other | `usize` | `1_024` | `crates/disrobe-binfmt/src/rewrite/elf.rs` |
| `disrobe-binfmt` | `MAX_NOTE_SEGMENT_BYTES` | size | `u64` | `1 << 20` | `crates/disrobe-binfmt/src/rewrite/elf.rs` |
| `disrobe-binfmt` | `MAX_EDITS` | other | `usize` | `4_096` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_FAT_SLICES` | other | `u64` | `4_096` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_LOAD_COMMANDS` | other | `u64` | `65_536` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_PLAN_STRUCTURES` | other | `usize` | `65_536` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | `u64` | `262_144` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_DIRECTORY_SLOTS` | other | `u64` | `8_192` | `crates/disrobe-binfmt/src/rewrite/pe.rs` |
| `disrobe-bytes` | `MAX_ENTRY_PREALLOC` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-bytes/src/quota.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURES` | other | `usize` | `4096` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURE_BYTES` | size | `usize` | `4096` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_SCAN_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_NUMBER_FEATURES_PER_INSN` | other | `usize` | `4` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `PE_HEADER_SCAN_CAP` | other | `usize` | `1 << 20` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_IMPORT_ENTRIES` | count | `usize` | `1 << 17` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-capabilities` | `MAX_STUB_SPAN` | other | `u64` | `0x10` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-capabilities` | `MAX_LOWER_STEPS` | work | `usize` | `100_000` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-capabilities` | `MAX_NODE_DEPTH` | recursion | `usize` | `24` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-capabilities` | `MAX_REGEX_PATTERN_LEN` | size | `usize` | `512` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-cfg` | `MAX_FLOW_NODES` | count | `usize` | `(u32::MAX - 1) as usize` | `crates/disrobe-cfg/src/flow.rs` |
| `disrobe-cfg` | `RETURN_TAIL_NODE_CAP` | other | `usize` | `64` | `crates/disrobe-cfg/src/lib.rs` |
| `disrobe-cfg` | `MAX_RECONVERGENCE_CLONES` | other | `usize` | `64` | `crates/disrobe-cfg/src/reconverge.rs` |
| `disrobe-cli` | `RESOURCE_PREVIEW_LIMIT` | other | `usize` | `50` | `crates/disrobe-cli/src/cli/apk.rs` |
| `disrobe-cli` | `MAX_EVIDENCE_SHOWN` | other | `usize` | `6` | `crates/disrobe-cli/src/cli/behavior.rs` |
| `disrobe-cli` | `MAX_NAMESPACE_ATTEMPTS` | other | `usize` | `1024` | `crates/disrobe-cli/src/cli/chain_materialization.rs` |
| `disrobe-cli` | `MAX_SIDECAR_REDACTION_BYTES` | size | `usize` | `64 << 20` | `crates/disrobe-cli/src/cli/chain_v1.rs` |
| `disrobe-cli` | `MAX_REPORTS_GRADED` | other | `usize` | `4096` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_REPORT_SEARCH_DEPTH` | recursion | `usize` | `4` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_COMPONENTS` | other | `usize` | `MAX_CYCLONEDX_PACKAGES + 1` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_COMPONENT_TEXT_BYTES` | size | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_OUTPUT_BYTES` | output | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_PACKAGES` | other | `usize` | `16_384` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_BUNDLE_ASSEMBLIES` | other | `usize` | `512` | `crates/disrobe-cli/src/cli/dotnet.rs` |
| `disrobe-cli` | `MAX_INSTALL_LOG_ENTRIES` | count | `usize` | `500` | `crates/disrobe-cli/src/cli/install/mod.rs` |
| `disrobe-cli` | `MAX_GHIDRA_ARCHIVE_ENTRIES` | count | `usize` | `200_000` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_DOWNLOAD_BYTES` | size | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_ENTRY_UNCOMPRESSED_BYTES` | size | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_TOTAL_UNCOMPRESSED_BYTES` | size | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `NWJS_ZIP_ENTRY_BYTES_CAP` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `NWJS_ZIP_ENTRY_COUNT_CAP` | count | `usize` | `65_535` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `NWJS_ZIP_TOTAL_BYTES_CAP` | size | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_CLASSES` | other | `usize` | `65_536` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_INPUT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_OUTPUT_BYTES` | output | `usize` | `128 * 1024 * 1024` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `DELPHI_LIST_LIMIT` | other | `usize` | `20` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `DEVIRT_FUNCTION_LIMIT` | other | `usize` | `2048` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `DIFF_DEFAULT_LISTING_LIMIT` | other | `usize` | `25` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LOWEST_COVERED_CAP` | other | `usize` | `10` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `MAX_CAPTURE_OUTPUT` | output | `usize` | `4 * 1024 * 1024` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `MAX_NATIVE_SBOM_INPUT_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `SYMBOL_PREVIEW_LIMIT` | other | `usize` | `40` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LITERAL_PREVIEW_LIMIT` | work | `usize` | `64` | `crates/disrobe-cli/src/cli/native_match.rs` |
| `disrobe-cli` | `MAX_DEEP_ANALYZE_LIB_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-cli/src/cli/nuitka.rs` |
| `disrobe-cli` | `MAX_TARGETS` | other | `usize` | `65_536` | `crates/disrobe-cli/src/cli/prowl/harvest.rs` |
| `disrobe-cli` | `MAX_TARGET_INPUT_BYTES` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-cli/src/cli/prowl/harvest.rs` |
| `disrobe-cli` | `MAX_JVM_QUERY_INPUT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_REJECTED_ARTIFACT_DIAGNOSTICS` | other | `usize` | `1_024` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_REJECTED_ARTIFACT_DIAGNOSTIC_BYTES` | size | `usize` | `65_536` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_ARTIFACT_WALK_DEPTH` | recursion | `u32` | `32` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_CITED_ARTIFACTS` | other | `usize` | `4_096` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_REPORT_ANALYSIS_INPUT_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_BEHAVIOR_EVIDENCE` | other | `usize` | `6` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-cli` | `MAX_IOC_ROWS` | other | `usize` | `200` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-cli` | `DEFAULT_LISTING_LIMIT` | other | `usize` | `40` | `crates/disrobe-cli/src/cli/semdiff.rs` |
| `disrobe-cli` | `MAX_SEMDIFF_INPUT_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/semdiff.rs` |
| `disrobe-cli` | `MAX_DOCUMENT_OUTPUT_BYTES` | output | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/structured_document.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_CALLS` | other | `usize` | `32_768` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_CANDIDATE_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_FUNCTIONS` | other | `usize` | `8_192` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_INSTRUCTIONS` | other | `usize` | `262_144` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_RETAINED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_NODES` | count | `usize` | `50_000` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_STEPS` | work | `usize` | `2_000_000` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_VULNMATCH_INPUT_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-core` | `ANTI_ANALYSIS_SCAN_CAP` | other | `usize` | `96 * 1024 * 1024` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `CODE_SCAN_BUDGET` | work | `usize` | `16 * 1024 * 1024` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_EXEMPLARS_PER_KIND` | other | `usize` | `5` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_MACHO_LOAD_CMDS` | other | `usize` | `4096` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_PARSED_SECTIONS` | other | `usize` | `96` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_CACHE_ENTRY_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-core/src/cache.rs` |
| `disrobe-core` | `MAX_CACHE_ENTRY_PREALLOC` | other | `usize` | `8 * 1024 * 1024` | `crates/disrobe-core/src/cache.rs` |
| `disrobe-core` | `DEFAULT_CAP` | other | `u8` | `8` | `crates/disrobe-core/src/chain/spec.rs` |
| `disrobe-core` | `MAX_CAP` | other | `u8` | `16` | `crates/disrobe-core/src/chain/spec.rs` |
| `disrobe-core` | `MAX_AES_INPUT` | other | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/aes_cbc.rs` |
| `disrobe-core` | `MAX_BIGNUM_RADIX_INPUT` | other | `usize` | `1 << 16` | `crates/disrobe-core/src/codec/alphabets.rs` |
| `disrobe-core` | `MAX_RADIX_INPUT` | other | `usize` | `1 << 24` | `crates/disrobe-core/src/codec/alphabets.rs` |
| `disrobe-core` | `MAX_BASE64_INPUT` | other | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/base64.rs` |
| `disrobe-core` | `MAX_CIPHER_INPUT` | other | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/cipher.rs` |
| `disrobe-core` | `JOSE_HEADER_DECODE_CAP` | other | `usize` | `4096` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_SCAN` | other | `usize` | `1 << 20` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_STATIC_PASSPHRASES` | other | `usize` | `32` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_FRAMED_INPUT` | other | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/framed.rs` |
| `disrobe-core` | `MAX_ENTITY_NAME` | other | `usize` | `32` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MAX_PUNYCODE_LABEL_OUTPUT` | output | `usize` | `1024` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MAX_WEB_INPUT` | other | `usize` | `1 << 24` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MS_CAP` | other | `u128` | `5 * MS_PER_D` | `crates/disrobe-core/src/provenance.rs` |
| `disrobe-core` | `MAX_NOTE_LINES` | other | `usize` | `2` | `crates/disrobe-core/src/provenance_map.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOBS` | other | `usize` | `1_000_000` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOB_BYTES` | size | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_COMMITS` | other | `usize` | `100_000` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_BLOB_DECODE` | other | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_CODEC_TOKEN` | other | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_INDICATORS` | other | `usize` | `100_000` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_FIELDS` | other | `usize` | `4096` | `crates/disrobe-core/src/recon/malware_config.rs` |
| `disrobe-core` | `ARCHIVE_MEMBER_PREALLOC_CAP` | other | `u64` | `1 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_DECODED_TOTAL` | other | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_DEPTH` | recursion | `u8` | `4` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_RUNS` | other | `usize` | `4096` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DECODED_TOTAL` | other | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DEPTH` | recursion | `u8` | `3` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_RUN` | other | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CONTAINER_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_DECODED_TOTAL_BYTES` | size | `u64` | `1 << 30` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_FILE_BYTES` | size | `u64` | `64 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_TREE_FILES` | count | `usize` | `200_000` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_WIDE_RUNS` | other | `usize` | `1 << 16` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_ENTRIES` | count | `usize` | `50_000` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_ENTRY_BYTES` | size | `u64` | `64 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_TOTAL_BYTES` | size | `u64` | `1 << 30` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `REGEX_SIZE_LIMIT` | size | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_SERIALIZED_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_SERIALIZED_NODES` | count | `usize` | `1_048_576` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_SERIALIZED_STRING_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_RUNS` | other | `usize` | `4096` | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_RUN_BYTES` | size | `usize` | `64 << 10` | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_DECODE_RECURSE_LEN` | recursion | `usize` | `1 << 16` | `crates/disrobe-core/src/strings.rs` |
| `disrobe-core` | `MAX_PE_SECTIONS` | other | `usize` | `96` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `ZIP_SEARCH_BUDGET` | work | `usize` | `ZIP_MAX_COMMENT + ZIP_EOCD_FIXED_LEN + 4` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `MAX_STRINGS` | other | `usize` | `20` | `crates/disrobe-core/src/yara_gen.rs` |
| `disrobe-core` | `MAX_STRING_LEN` | size | `usize` | `96` | `crates/disrobe-core/src/yara_gen.rs` |
| `disrobe-core` | `HEX_WORK_BUDGET` | work | `u64` | `1 << 20` | `crates/disrobe-core/src/yara_match/atoms.rs` |
| `disrobe-ir` | `MAX_DECODED_ENVELOPE_BYTES` | size | `usize` | `1 << 30` | `crates/disrobe-ir/src/envelope.rs` |
| `disrobe-ir` | `READ_PREALLOC_CAP` | other | `usize` | `1 << 20` | `crates/disrobe-ir/src/io.rs` |
| `disrobe-ir` | `MAX_RECORDS` | count | `usize` | `1 << 16` | `crates/disrobe-ir/src/witness.rs` |
| `disrobe-irsummary` | `MAX_CFG_BLOCKS` | other | `usize` | `200_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_CFG_EDGES` | other | `usize` | `400_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_DFG_SITES` | other | `usize` | `400_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_FIXPOINT_ROUNDS` | work | `usize` | `16` | `crates/disrobe-irsummary/src/optimize.rs` |
| `disrobe-irsummary` | `MAX_BLOCKS` | other | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_BLOCK_INSNS` | other | `usize` | `256` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_INSNS` | other | `usize` | `2048` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_JOINS` | other | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_OUTPUTS` | output | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_STACK_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-lift-x86` | `MAX_X86_BLOCK_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-lift-x86` | `MAX_X86_INSTRUCTIONS` | other | `usize` | `65_536` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-llm-metadata` | `MAX_ANNOTATIONS` | other | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_FILE_BYTES` | size | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_KIND_BYTES` | size | `usize` | `128` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_NOTE_BYTES` | size | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_NOTE_LINES` | other | `usize` | `2` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_SYMBOL_BYTES` | size | `usize` | `1024` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_DECRYPTION_KEY_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PIPELINE_STEPS` | work | `usize` | `1024` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PROVENANCE_CHAIN_ENTRIES` | count | `usize` | `16_384` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PII_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_SCAN_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_DECLARED_TYPE_BYTES` | size | `usize` | `256` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_FUNCTIONS` | other | `usize` | `65_536` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_OBSERVATIONS_PER_VAR` | other | `usize` | `16_384` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_OBSERVATIONS_PER_VAR_U32` | other | `u32` | `16_384` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_VARIABLES_PER_FN` | other | `usize` | `4_096` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-mba` | `BFS_TABLE_BUDGET` | work | `usize` | `1usize << 14` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BITWISE_SYNTH_VARS` | other | `u32` | `4` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_ATOMS` | other | `usize` | `8` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_PRIMES` | other | `usize` | `64` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_SEARCH_STEPS` | work | `usize` | `100_000` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_CFF_BLOCKS` | other | `usize` | `4_096` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `MAX_REGION_NODES` | count | `u32` | `512` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `CHEAP_LOOP_CAP` | other | `u32` | `8` | `crates/disrobe-mba/src/cff/mod.rs` |
| `disrobe-mba` | `MAX_APPLICATIONS` | other | `usize` | `12_000` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_CLASSES` | other | `usize` | `2000` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_INPUT_NODES` | count | `usize` | `48` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_ITERATIONS` | work | `u32` | `10` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_LEAVES` | other | `usize` | `32` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `BANK_CAP` | other | `usize` | `128` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `GEN_BUDGET` | work | `u64` | `60_000` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ATOMS` | other | `usize` | `3` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CANDIDATE_NODES` | count | `usize` | `16` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CONSTS` | other | `usize` | `8` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ROUNDS` | work | `u32` | `4` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_VARS` | other | `u32` | `4` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `VERIFY_BUDGET` | work | `u32` | `32` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_EXHAUSTIVE_EVALS` | other | `u128` | `1 << 24` | `crates/disrobe-mba/src/expr.rs` |
| `disrobe-mba` | `MAX_MBA_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-mba/src/expr.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_DEGREE` | other | `usize` | `1 << 16` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MULTIVAR_EVAL_BUDGET` | work | `u128` | `1 << 22` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MAX_TABLE_ENTRIES` | count | `u64` | `4_096` | `crates/disrobe-mba/src/jumptable/mod.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | other | `u32` | `3` | `crates/disrobe-mba/src/linear_mba.rs` |
| `disrobe-mba` | `MAX_SOLVER_VARS` | other | `u32` | `8` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_COMBOS` | other | `usize` | `60_000` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_SEARCH_VARS` | other | `u32` | `5` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_NODES` | count | `usize` | `16_384` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_VARS` | other | `u32` | `6` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_WORK` | work | `usize` | `1_024` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_RECURSION_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_POLYNOMIAL_PAIR_WORK` | work | `usize` | `8_192 * 8_192` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_PROOF_PAIR_WORK` | work | `usize` | `4_096 * 4_096` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `BIT_BUDGET` | work | `u32` | `22` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_EXHAUSTIBLE` | other | `Width` | `Width::W16` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_OPAQUE_VARS` | other | `u32` | `3` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_ATOM_DEGREE` | other | `u32` | `32` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_ATOMS` | other | `usize` | `24` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MBA_VARS` | other | `u32` | `4` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MONOMIALS` | other | `usize` | `8192` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_ATOMS` | other | `usize` | `8` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIALS` | other | `usize` | `4096` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIAL_DEGREE` | other | `u32` | `128` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_REWRITE_PASSES` | other | `u32` | `64` | `crates/disrobe-mba/src/rewrite.rs` |
| `disrobe-mba` | `MAX_PROVENANCE_BYTES` | size | `usize` | `256` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULES` | other | `usize` | `256` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_CAPTURES` | other | `usize` | `8` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_FILE_BYTES` | size | `usize` | `128 * 1024` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_NAME_BYTES` | size | `usize` | `128` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_BYTES` | size | `usize` | `512` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_NODES` | count | `usize` | `64` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_NODES` | count | `usize` | `4096` | `crates/disrobe-mba/src/rules/engine.rs` |
| `disrobe-mba` | `MAX_CAPTURE_NAME_BYTES` | size | `usize` | `64` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_CONDITIONS_PER_RULE` | other | `usize` | `64` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_PATTERN_NODES` | count | `usize` | `4096` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULES` | other | `usize` | `1024` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULE_NAME_BYTES` | size | `usize` | `128` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULE_TEXT_BYTES` | size | `usize` | `256 * 1024` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_NODES` | count | `usize` | `4096` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | other | `u32` | `3` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_LINEAR_VARS` | other | `u32` | `4` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_VARS` | other | `u32` | `2` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `CERT_NODE_BUDGET` | work | `usize` | `1usize << 20` | `crates/disrobe-mba/src/smt.rs` |
| `disrobe-mba` | `CERT_NODE_BUDGET` | work | `usize` | `1usize << 18` | `crates/disrobe-mba/src/symexec/solver.rs` |
| `disrobe-mba` | `EVAL_NODE_BUDGET` | work | `usize` | `1usize << 18` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_ASSIGNMENTS` | other | `u64` | `1u64 << 12` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_STEPS` | work | `usize` | `1usize << 15` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VARS` | other | `usize` | `6` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VAR_BITS` | other | `u32` | `16` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_WIDTH_BITS` | other | `u16` | `64` | `crates/disrobe-mba/src/symexec/value.rs` |
| `disrobe-mba` | `DEFAULT_NODE_BUDGET` | work | `usize` | `1usize << 20` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `DEFAULT_OP_BUDGET` | work | `usize` | `DEFAULT_NODE_BUDGET * 8` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `MAX_COUNTEREXAMPLE_SLOTS` | count | `usize` | `1024` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `MAX_INPUT_BITS` | other | `usize` | `512` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `POLY_NODE_BUDGET` | work | `usize` | `4096` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mcp` | `MAX_CHAIN_DEPTH` | recursion | `u8` | `64` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_COVERAGE_REGIONS` | other | `usize` | `512` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_IMPORTS` | other | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_IMPORT_BYTES` | size | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_BASE64_CHARS` | other | `usize` | `22 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_DECODED_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_JSON_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_PROVENANCE_LINES` | other | `usize` | `262_144` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAMES_FILE_BYTES` | size | `u64` | `4 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_FIELD_BYTES` | size | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_NOTE_BYTES` | size | `usize` | `8192` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_RECORDS` | count | `usize` | `16_384` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_STRINGS_MIN_LEN` | size | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_WASM_LIFT_SOURCE_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_WORKSPACE_READ_BYTES` | work | `u64` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `DEFAULT_TOKEN_BUDGET` | work | `usize` | `4_096` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_AMBIGUOUS_CANDIDATES` | other | `usize` | `8` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_CALLS` | other | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_CANDIDATE_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_FUNCTIONS` | other | `usize` | `8_192` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_INSTRUCTIONS` | other | `usize` | `262_144` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_RETAINED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_CURSOR_BYTES` | size | `usize` | `256` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_CURSOR_OFFSET` | other | `usize` | `1_000_000` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ENTRY_IDS` | other | `usize` | `64` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_NEIGHBORHOOD_DEPTH` | recursion | `u8` | `32` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_OUTPUT_TEXT_BYTES` | output | `usize` | `160` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_TOKEN_BUDGET` | work | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_XREFS` | other | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MIN_TOKEN_BUDGET` | work | `usize` | `2_048` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-nir` | `MAX_EFFECT_MODELS` | other | `usize` | `65_536` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_EFFECT_ROWS` | other | `usize` | `1_048_576` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_WIRE_EFFECT_LABELS` | other | `usize` | `64` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_EMITTED_BYTES` | output | `usize` | `1_048_576` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_EMIT_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_INDENT_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_REGION_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_CLONE_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_TESTS` | other | `usize` | `64` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_WORK` | work | `usize` | `65_536` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SPLIT_NODES` | count | `usize` | `4096` | `crates/disrobe-nir/src/reducible.rs` |
| `disrobe-nir` | `MAX_SURFACE_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-nir/src/surface.rs` |
| `disrobe-nir` | `MAX_NIR_ELEMENTS` | other | `usize` | `MAX_SOURCE_UNITS` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_RETAINED_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_STRING_BYTES` | size | `usize` | `MAX_SOURCE_BYTES` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_WORK` | work | `usize` | `8 * MAX_NIR_ELEMENTS` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_SOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_SOURCE_UNITS` | other | `usize` | `1_048_576` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir-lift` | `MAX_BIG_DECIMAL_BYTES` | size | `usize` | `1024` | `crates/disrobe-nir-lift/src/beam.rs` |
| `disrobe-nir-lift` | `MAX_LUA_PROTOS` | other | `usize` | `262_144` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_LUA_PROTO_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_REGISTERS` | other | `usize` | `256` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_REPORTED_GAPS` | other | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/arch.rs` |
| `disrobe-nir-lift` | `MAX_FOLD_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-nir-lift` | `MAX_REACHING_ANALYSIS_ELEMENTS` | other | `usize` | `8_388_608` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-nir-lift` | `MAX_IDENTIFIER_BYTES` | size | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_PCODE_INSTRUCTIONS` | other | `usize` | `65_536` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_PCODE_OPERATIONS` | other | `usize` | `1_048_576` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_CALLOTHER_INPUTS` | other | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/ops.rs` |
| `disrobe-nir-lift` | `MAX_CALLOTHER_NAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/ops.rs` |
| `disrobe-nir-lift` | `MAX_SPEC_NAME_BYTES` | size | `usize` | `128` | `crates/disrobe-nir-lift/src/pcode/spec.rs` |
| `disrobe-nir-lift` | `MAX_SPEC_REGISTERS` | other | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/spec.rs` |
| `disrobe-nir-lift` | `MAX_REGISTER_CELLS` | other | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/varnode.rs` |
| `disrobe-nir-lift` | `MAX_VARNODE_BYTES` | size | `u32` | `4096` | `crates/disrobe-nir-lift/src/pcode/varnode.rs` |
| `disrobe-nir-lift` | `MAX_AST_NODES` | count | `usize` | `262_144` | `crates/disrobe-nir-lift/src/python.rs` |
| `disrobe-nir-lift` | `MAX_EMIT_DEPTH` | recursion | `usize` | `512` | `crates/disrobe-nir-lift/src/python.rs` |
| `disrobe-nir-lift` | `MAX_WASM_OPERATORS_PER_FUNCTION` | other | `usize` | `1 << 18` | `crates/disrobe-nir-lift/src/wasm.rs` |
| `disrobe-pass-as3` | `MULTINAME_RENDER_BUDGET` | work | `u32` | `4096` | `crates/disrobe-pass-as3/src/abc.rs` |
| `disrobe-pass-as3` | `MAX_DUP_EXPR_NODES` | count | `usize` | `1024` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_EXPR_DEPTH` | recursion | `usize` | `2048` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_LOOSE_DISPATCH_CONDITIONS` | other | `usize` | `256` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_MERGE_DEFINITIONS` | other | `usize` | `4096` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_NEGATION_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_OR_GUARD_TESTS` | other | `usize` | `64` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_STRUCTURE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_SWITCH_ANALYSIS_FUEL` | work | `usize` | `65_536` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_TERNARY_FOLDS` | other | `usize` | `64` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_ARCHNAME_BYTES` | size | `usize` | `64` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_BYTELOADER_LINE_BYTES` | size | `usize` | `64` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_RUNTIME_SYMBOL_SCAN_BYTES` | size | `usize` | `64 << 20` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_SHEBANG_LINE_BYTES` | size | `usize` | `256` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_DECOMPRESSED_BODY` | other | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_DECOMPRESS_PREALLOC` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_LZMA_MEMLIMIT` | other | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_SPRITE_NESTING` | recursion | `usize` | `256` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_SWF_VERSION` | other | `u8` | `40` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-beam` | `MAX_EXPR_NODES` | count | `usize` | `1024` | `crates/disrobe-pass-beam/src/body_lift/expr.rs` |
| `disrobe-pass-beam` | `MAX_LABEL_VISITS` | other | `u32` | `8` | `crates/disrobe-pass-beam/src/body_lift/mod.rs` |
| `disrobe-pass-beam` | `MAX_WALK_CALLS` | other | `u32` | `20_000` | `crates/disrobe-pass-beam/src/body_lift/mod.rs` |
| `disrobe-pass-beam` | `MAX_ARMS` | other | `usize` | `32` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_CONJUNCTS` | other | `usize` | `24` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TERM_DEPTH` | recursion | `u32` | `16` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TREE_DEPTH` | recursion | `u32` | `24` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_FUN_ARITY` | other | `u32` | `1024` | `crates/disrobe-pass-beam/src/chunks.rs` |
| `disrobe-pass-beam` | `MAX_DISASM_DEPTH` | recursion | `usize` | `500` | `crates/disrobe-pass-beam/src/disasm.rs` |
| `disrobe-pass-beam` | `MAX_SCAN_DEPTH` | recursion | `u32` | `256` | `crates/disrobe-pass-beam/src/elixir.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | recursion | `u32` | `256` | `crates/disrobe-pass-beam/src/elixir_quoted.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | recursion | `u32` | `256` | `crates/disrobe-pass-beam/src/erlang_abstract.rs` |
| `disrobe-pass-beam` | `MAX_ATOM_SCALARS` | other | `usize` | `255` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_DEPRECATED_ATOM_LATIN1_CHARS` | other | `usize` | `255` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_CONTAINER_PREALLOC` | other | `usize` | `1 << 16` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_DEPTH` | recursion | `usize` | `500` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_INFLATE` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_OPCODE` | other | `u32` | `191` | `crates/disrobe-pass-beam/src/opcodes.rs` |
| `disrobe-pass-dotnet` | `EAGER_CCTOR_SCAN_CAP` | other | `u32` | `512` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_DYNAMIC_RELOCATIONS` | other | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_NAME_LEN` | size | `usize` | `256` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_PROFILE_MAJOR` | other | `u16` | `64` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_READY_TO_RUN_SECTIONS` | other | `u16` | `1024` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAMES` | other | `usize` | `65536` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_BUCKETS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_ENTRIES` | count | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_COLLECTION` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_OUTPUT_BYTES` | output | `usize` | `16_777_216` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_BYTES` | size | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_RECORDS` | count | `usize` | `131_072` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_STORAGE_BYTES` | size | `usize` | `16_777_216` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_TYPE_SIGNATURE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_TYPE_SIGNATURE_WORK` | work | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_VALUES` | other | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_BODY_INPUT_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_BODY_OUTPUT_BYTES` | output | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_REFUSAL_BYTES_PER_METHOD` | size | `usize` | `128` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_BODY_INPUT_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_BODY_OUTPUT_BYTES` | output | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_UNIQUE_METHOD_BODIES` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_EXCEPTION_DIRECTORY_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_boundaries.rs` |
| `disrobe-pass-dotnet` | `MAX_RUNTIME_FUNCTIONS` | other | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/method_boundaries.rs` |
| `disrobe-pass-dotnet` | `MAX_BACKEND_CAPTURE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/backends.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_QUALIFIED_NAME_BYTES` | size | `usize` | `MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_SYMBOL_WORK_ITEMS` | work | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_TYPE_NESTING_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_INSTRUCTIONS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/cil.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_EMULATED_INSTRUCTIONS` | other | `usize` | `16_384` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_HEAP` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_HEAP_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_SWITCH_TARGETS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `STEP_LIMIT` | work | `u64` | `4_000_000` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EVALUATION_STACK` | other | `usize` | `64` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_DEPTH` | recursion | `u8` | `32` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_NODES` | count | `u8` | `64` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_HANDLER_BODY_BYTES` | size | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_HANDLER_INSTRUCTIONS` | other | `usize` | `512` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_LOWERED_EFFECTS` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODELS` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODEL_INSTRUCTIONS` | other | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODEL_INSTRUCTIONS_TOTAL` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_LIFT_STACK` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/lift.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_NODES` | count | `usize` | `256` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_VARS` | other | `usize` | `6` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_SAMPLES` | other | `usize` | `16` | `crates/disrobe-pass-dotnet/src/devirt/oracle.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_STACK` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/oracle/model_ref.rs` |
| `disrobe-pass-dotnet` | `MODEL_STEP_LIMIT` | work | `u64` | `4_000_000` | `crates/disrobe-pass-dotnet/src/devirt/oracle/model_ref.rs` |
| `disrobe-pass-dotnet` | `MAX_OPERAND_BYTES` | size | `usize` | `8` | `crates/disrobe-pass-dotnet/src/devirt/profile.rs` |
| `disrobe-pass-dotnet` | `MAX_ABSTRACT_STACK` | other | `usize` | `64` | `crates/disrobe-pass-dotnet/src/devirt/state.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPR_DEPTH` | recursion | `u8` | `32` | `crates/disrobe-pass-dotnet/src/devirt/state.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_BLOCKS` | other | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/structure.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-pass-dotnet/src/devirt/structure.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_RVA_BYTES` | size | `u32` | `512` | `crates/disrobe-pass-dotnet/src/field_rva.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY_FIELD_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CIPHERTEXT_BYTES` | size | `usize` | `1 << 16` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DERIVATIONS` | other | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PBKDF2_ITERATIONS` | work | `u32` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTANTS_BLOB_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTANTS_POOL_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_DECODE_ATTEMPTS` | other | `usize` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTED_RESOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_ENCRYPTED_BLOB_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_METHODS_SCANNED` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_RUN` | other | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `KEY_PATH_STEP_CAP` | work | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `MAX_BLOCKS` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `FIELD_RVA_READ_CAP` | other | `usize` | `1 << 16` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | other | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `STEP_LIMIT` | work | `u32` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/interp.rs` |
| `disrobe-pass-dotnet` | `NATIVE_STEP_CAP` | work | `u64` | `200_000` | `crates/disrobe-pass-dotnet/src/peel/deflatten/predicate.rs` |
| `disrobe-pass-dotnet` | `NATIVE_STUB_READ_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/predicate.rs` |
| `disrobe-pass-dotnet` | `MAX_VISIT` | other | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/rebuild.rs` |
| `disrobe-pass-dotnet` | `MAX_ATTEMPTS_PER_IMAGE` | other | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_NODES` | count | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_VARS` | other | `usize` | `6` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRUCTIONS_PER_IMAGE` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRUCTIONS_PER_METHOD` | other | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_METHODS_PER_IMAGE` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK_VALUES` | other | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/eazvm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_RESOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/ilprotector_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_BLOCKS` | other | `usize` | `512` | `crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRS_PER_BLOCK` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_SECTION_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/maxtocode_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_NAME_CHARS` | other | `usize` | `128` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_REFUSALS` | other | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_DISASM_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_SURFACED_INSNS` | other | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSORS` | other | `usize` | `65_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_CODE` | other | `u32` | `256` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_INSTRUCTIONS` | other | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_CODE` | other | `u32` | `16 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_INSTRUCTIONS` | other | `usize` | `2_048` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_DATA` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_ROWS` | other | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_CODE` | other | `u32` | `4 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_INSTRUCTIONS` | other | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_IMAGE_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MEMBER_REF_ROWS` | other | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_BLOB_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_CODE` | other | `u32` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_PARSE_BYTES` | size | `usize` | `1024 * 1024 + 64 * 1024 + 64` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_ROWS` | other | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_NAME_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_SIGNATURE_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAME_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK` | other | `u16` | `64` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STRING_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_EXCEPTION_CLAUSES` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_INSTRUCTIONS` | other | `usize` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_METHOD_CODE` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_PARSE_BYTES` | size | `usize` | `72 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_TABLE_ROWS` | other | `u64` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TYPE_ROWS` | other | `u32` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_EMBEDDED_RESOURCES` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_RESOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_STRINGS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_ENTRY_METHODS` | other | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_HEAP_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METADATA_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METADATA_STREAMS` | other | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_CODE_BYTES` | size | `u32` | `4096` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_INSTRUCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_ROWS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_TOTAL_BYTES` | size | `usize` | `16 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_PE_SECTIONS` | other | `usize` | `96` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_RELEVANT_METADATA_ROWS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_SELECTED_HEAP_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_STRING_HEAP_ENTRIES` | count | `usize` | `262_144` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_TOTAL_METADATA_ROWS` | other | `u64` | `262_144` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_PARTS` | other | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/smartassembly_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_ROT_SHIFT` | other | `u16` | `64` | `crates/disrobe-pass-dotnet/src/peel/spices_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PROBE_ARGS` | other | `i64` | `64` | `crates/disrobe-pass-dotnet/src/peel/static_decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_STRINGS` | other | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_INPUT_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_OUTPUT_BYTES` | output | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_TOTAL_INPUT_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_TOTAL_OUTPUT_BYTES` | output | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_RUNTIME_FUNCTIONS` | other | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_SECTIONS` | other | `u32` | `1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_USER_STRING_ENTRIES` | count | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_SUPPORTED_R2R_MAJOR_VERSION` | other | `u16` | `27` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_SIGNATURE_NODES` | count | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/signature.rs` |
| `disrobe-pass-dotnet` | `MAX_SIG_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-dotnet/src/signature.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-dotnet/src/structure_emit.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY_LITERAL_ELEMENTS` | work | `usize` | `64` | `crates/disrobe-pass-dotnet/src/structurize.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPR_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-dotnet/src/structurize.rs` |
| `disrobe-pass-dotnet` | `INFERENCE_DEPTH_LIMIT` | recursion | `usize` | `32` | `crates/disrobe-pass-dotnet/src/structurize/operand_kind.rs` |
| `disrobe-pass-dotnet` | `MAX_TABLE_ROWS` | other | `u64` | `1_000_000` | `crates/disrobe-pass-dotnet/src/tables.rs` |
| `disrobe-pass-go` | `FLAT_32_ADDRESS_LIMIT` | other | `u64` | `1 << 32` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_FTAB_CAP` | other | `usize` | `18` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_FUNCNAMETAB_CAP` | other | `usize` | `3` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_PCLNTABLE_CAP` | other | `usize` | `15` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MAX_LISTED_FUNCS` | other | `usize` | `4_096` | `crates/disrobe-pass-go/src/chain_detector.rs` |
| `disrobe-pass-go` | `MAX_CALL_SCAN_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_CALL_SITES` | other | `usize` | `1 << 18` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_DEFER_FUNCS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_RUNTIME_HOOKS` | other | `usize` | `1 << 8` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_PCDATA_ENTRIES` | count | `u32` | `64` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_RUNTIME_CALL_TARGET_NAMES` | other | `usize` | `1 << 12` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_TOTAL_CALL_SCAN_BYTES` | size | `usize` | `64 << 20` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_DECOMPRESSED_LEN` | size | `u64` | `1 << 30` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_FUNCS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_PER_FUNC` | other | `usize` | `1 << 10` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_TOTAL` | other | `usize` | `MAX_DWARF_FUNCS * MAX_DWARF_NAMES_PER_FUNC` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_TYPE_NAMES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_ZDEBUG_INITIAL_CAPACITY` | other | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVES` | other | `usize` | `4096` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVE_TAIL` | other | `usize` | `256` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_DATA_LEN` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_NAME_LEN` | size | `u64` | `4096` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_MAPS` | other | `usize` | `256` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_MAP_ENTRIES` | count | `u64` | `1 << 16` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_TOTAL_EMBED_BYTES` | size | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `LITERAL_NO_INTERPRETER_LIMIT` | work | `&str` | `"garble -literals string encryption is recovered by emulating each \ literal's decrypt thunk, and the thunk interpreter covers x86-64 code only. this build's \ architecture has no interpreter, so its encrypted literals are reported as present but stay \ encrypted` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `LITERAL_RECOVERY_LIMIT` | work | `&str` | `"garble -literals string encryption is not a one-time pad: each literal's key is derived by \ an init-time decrypt thunk from material stored in the binary, so the plaintext is recovered \ statically by emulating that thunk. a scoped x86-64 interpreter runs the thunk the go compiler \ emitted for each literal, reading the encrypted data/key/positions/fullData arrays from rodata \ and the external-key arguments from the call site, including proxy-dispatcher field loads \ through .data. it covers the five obfuscators (simple, swap, shuffle, split, seed), with the \ decrypt as a separate closure or inlined into the caller, and the legacy single-byte \ XOR/ADD/SUB, repeating-key XOR, and standalone data/key blob cases. the interpreter follows the \ seed obfuscator's decFunc closure chain and the proxy dispatcher's indirect calls. the key \` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_LITERAL_SCAN_BYTES` | work | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_PLAIN_STRINGS` | other | `usize` | `MAX_RECOVERED_STRINGS` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_RECOVERED_STRINGS` | other | `usize` | `4096` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_REPEATING_KEY` | other | `usize` | `8` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `STRING_SCAN_BUDGET` | work | `Duration` | `Duration::from_secs(8)` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_BLOB` | other | `usize` | `256` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_BRIDGE_GAP` | other | `usize` | `1` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PERTURBED_BYTES` | size | `usize` | `12` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PLACEHOLDER_RATIO_PCT` | other | `usize` | `12` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_RECOVERIES` | other | `usize` | `1024` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_SCAN_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_STRING_JUNK_BYTES` | size | `usize` | `8` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `WORK_BUDGET` | work | `u64` | `48_000_000` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `GLOBAL_STEP_BUDGET` | work | `u64` | `6_000_000` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_CALLERS_PER_THUNK` | other | `usize` | `4` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_EMU_MEM_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_INLINE_STRING` | other | `usize` | `4096` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_NESTED_CALL_DEPTH` | recursion | `u32` | `96` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_STEPS` | work | `usize` | `200_000` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_THUNK_BYTES` | size | `usize` | `64 << 10` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `THUNK_SCAN_BUDGET` | work | `Duration` | `Duration::from_secs(8)` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_BACKSEARCH_CANDIDATES` | other | `usize` | `4096` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_DEPS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_SETTINGS` | other | `usize` | `1 << 12` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_MODULENAME_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SLICE_LEN` | size | `u64` | `1 << 22` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PCLNTAB_CANDIDATES` | other | `usize` | `16` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SIG_FUNCS` | other | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_FILETAB_ENTRY_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_FUNC_PREALLOC` | other | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_GO_NAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_FUNCS` | other | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_START_LINE` | other | `i32` | `1 << 26` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `DISAMBIG_CANDIDATE_BUDGET` | work | `usize` | `1 << 22` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `ITABLINKS_WALK_CAP` | other | `usize` | `1 << 14` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_FIELDS_PER_STRUCT` | other | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_IMETHODS_PER_INTERFACE` | other | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_METHODS_PER_TYPE` | other | `u16` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_STRUCT_FIELD_TAG_LEN` | size | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_TYPE_NAME_LEN` | size | `usize` | `1024` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `TYPELINKS_WALK_CAP` | other | `usize` | `1 << 14` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-js-deob` | `MAX_SIBLING_MAP_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap.rs` |
| `disrobe-pass-js-deob` | `MAX_MAP_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_NAMES_PER_SOURCE` | other | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RENAMED_BINDINGS` | other | `usize` | `100_000` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_SECTIONS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_SOURCES` | other | `usize` | `1 << 22` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RECURSIVE_DEPTH` | recursion | `usize` | `6` | `crates/disrobe-pass-js-deob/src/esoteric/atob_indirection.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERATOR_CHAIN` | other | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/esoteric/jsfuck.rs` |
| `disrobe-pass-js-deob` | `MAX_PEEL_LAYERS` | other | `usize` | `32` | `crates/disrobe-pass-js-deob/src/esoteric/packer.rs` |
| `disrobe-pass-js-deob` | `LOOP_ITERATION_LIMIT` | work | `u64` | `1_000_000` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_CAPTURE_SCRIPT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_SCRIPT_BYTES` | size | `usize` | `256 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `RECURSION_LIMIT` | recursion | `usize` | `1_024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `STACK_SIZE_LIMIT` | size | `usize` | `16 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_EXACT_MAGNITUDE` | other | `u128` | `1u128 << 53` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_FIXPOINT_ROUNDS` | work | `usize` | `32` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_LOWER_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_DENSE_ARRAY_ELEMENTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/cff_vm/interp.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_DICT_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_INPUT_UNITS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_OUTPUT_UNITS` | output | `usize` | `4 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `LOOP_LIMIT` | other | `u64` | `2_000_000` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `RECURSION_LIMIT` | recursion | `usize` | `1_500` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `STACK_LIMIT` | other | `usize` | `50_000` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `MAX_CALL_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_FOLD_PASSES` | other | `usize` | `8` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_IIFE_BYTES` | size | `usize` | `8 * 1024` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RESULT_CHARS` | other | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RECOVER_PASSES` | other | `usize` | `6` | `crates/disrobe-pass-js-deob/src/jsobfu/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_PRIOR_CONFIDENCE` | other | `u8` | `Confidence::LOW.0` | `crates/disrobe-pass-js-deob/src/mangled_names/corpus_source.rs` |
| `disrobe-pass-js-deob` | `MAX_PASS_CEILING` | other | `u32` | `32` | `crates/disrobe-pass-js-deob/src/obfuscator_io/dispatch.rs` |
| `disrobe-pass-js-deob` | `MAX_EXPRESSION_DEPTH` | recursion | `usize` | `28_000` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERATOR_CHAIN` | other | `usize` | `600` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_SYNTACTIC_NESTING_DEPTH` | recursion | `usize` | `600` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_TEMPLATE_SCAN_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-js-deob/src/string_array/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_ROTATIONS` | other | `u32` | `4096` | `crates/disrobe-pass-js-deob/src/string_array/rotate.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_LOOP_ITERATION_LIMIT` | work | `u64` | `100_000` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_RECURSION_LIMIT` | recursion | `usize` | `256` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_STACK_SIZE_LIMIT` | size | `usize` | `8 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_AGGREGATE_EXPRESSION_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_BATCH_JSON_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_BATCH_OUTPUT_UNITS` | output | `usize` | `1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_CONCURRENT_PROBES` | other | `usize` | `1` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_DECODED_TOTAL_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_DECODED_VALUE_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_ENVIRONMENT_CALLS` | other | `u64` | `10_000_000` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_EXPRESSION_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_GENERATED_SCRIPT_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_PROBE_EXPRESSIONS` | other | `usize` | `65_536` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_SCRIPT_BYTES` | size | `usize` | `256 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_MANGLED_SOURCE_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_MEMBER_CALL_LITERALS` | work | `usize` | `8` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_NEARBY_STRINGS` | other | `usize` | `4` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_SEARCH_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_SUFFIX_ATTEMPTS` | other | `u32` | `512` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | other | `usize` | `16` | `crates/disrobe-pass-js-deob/src/unminify/arithmetic.rs` |
| `disrobe-pass-js-deob` | `MAX_MBA_LOWER_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_PREDICATE_VARS` | other | `usize` | `3` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_DEPENDENCY_SETTER_PAIRS` | other | `usize` | `4_096` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_GENERATED_EDITS` | other | `usize` | `65_536` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_REGISTRATIONS` | other | `usize` | `4_096` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_CANDIDATES` | other | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async.rs` |
| `disrobe-pass-js-deob` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/canon.rs` |
| `disrobe-pass-js-deob` | `MAX_SIMPLIFY_ROUNDS` | work | `usize` | `64` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/emit.rs` |
| `disrobe-pass-js-deob` | `MAX_BLOCKS` | other | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_REGIONS` | other | `usize` | `512` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_REGION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_WALK_DEPTH` | recursion | `usize` | `512` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/order.rs` |
| `disrobe-pass-js-deob` | `MAX_RENDER_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/render.rs` |
| `disrobe-pass-js-deob` | `MAX_TREE_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/structure.rs` |
| `disrobe-pass-js-deob` | `MAX_FIX_POINT_PASSES` | other | `usize` | `8` | `crates/disrobe-pass-js-deob/src/unminify/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_CHAIN` | other | `usize` | `1024` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | other | `usize` | `32` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERANDS` | other | `usize` | `5usize` | `crates/disrobe-pass-js-deob/src/v8/bytecode_opcodes.rs` |
| `disrobe-pass-js-deob` | `MAX_DESERIALIZE_OBJECTS` | other | `usize` | `1usize << 20usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_FRAME_SIZE` | size | `i32` | `1i32 << 24i32` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_RECURSION_DEPTH` | recursion | `usize` | `256usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_BODY` | other | `usize` | `1usize << 20usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_RENDERED_ARGUMENTS` | output | `i64` | `65_534` | `crates/disrobe-pass-js-deob/src/v8/flat_bytecode_lift.rs` |
| `disrobe-pass-js-deob` | `REGISTER_RANGE_SCAN_LIMIT` | other | `i64` | `256` | `crates/disrobe-pass-js-deob/src/v8/flat_bytecode_lift.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_LEN` | size | `u32` | `1u32 << 24u32` | `crates/disrobe-pass-js-deob/src/v8/serialized_code.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_INPUT_FILE_NAME_BYTES` | size | `usize` | `255` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS` | other | `usize` | `255` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_OUTPUT_TREE_BYTES` | output | `u64` | `128 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_OUTPUT_TREE_ENTRIES` | output | `usize` | `262_144` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_SOURCE_BYTES` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_SOURCE_FILES` | count | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_TOTAL_SOURCE_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_ENTRY_BYTES_CAP` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_FILE_COUNT_CAP` | count | `usize` | `256` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_PREALLOC_BYTES_CAP` | size | `u64` | `1024 * 1024` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_INPUT_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_NODES` | count | `usize` | `65_535` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_RENDER_BYTES` | output | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_TEXT_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ATTRIBUTES` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ATTRIBUTES_PER_ELEMENT` | other | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ELEMENT_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_EVENTS` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_OWNED_TEXT_BYTES` | size | `usize` | `16 * 1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_RESOURCE_IDS` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_STRING_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_STRING_COUNT` | count | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_TEXT_BYTES` | size | `usize` | `16 * 1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_BACKEND_CAPTURE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/backends.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | other | `usize` | `128` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_CALL_DEPTH` | recursion | `u32` | `24` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_STACK_DEPTH` | recursion | `usize` | `8_192` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_STRING_LEN` | size | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | `u64` | `6_000_000` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_MAJOR` | other | `u16` | `69` | `crates/disrobe-pass-jvm/src/classfile.rs` |
| `disrobe-pass-jvm` | `MAX_DATAFLOW_VISITS_PER_INSTRUCTION` | other | `usize` | `16` | `crates/disrobe-pass-jvm/src/const_fold.rs` |
| `disrobe-pass-jvm` | `MAX_MASK_SEARCH_PAIRS` | other | `usize` | `4096` | `crates/disrobe-pass-jvm/src/dalvik_blackobf.rs` |
| `disrobe-pass-jvm` | `MAX_DALVIK_BLOCKS` | other | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/dalvik_cfg.rs` |
| `disrobe-pass-jvm` | `MAX_FLOW_WORDS` | other | `usize` | `1 << 22` | `crates/disrobe-pass-jvm/src/dalvik_cfg.rs` |
| `disrobe-pass-jvm` | `MAX_DIAGNOSTICS` | other | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_MARKER_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_MARKER_IDENTIFIERS` | other | `usize` | `16` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_NESTED_CLASS_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | output | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_DESUGAR_SCAN_INSNS` | other | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_BODY_INSNS` | other | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_REFERENCE_BODY_INSNS` | other | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_RESOLVE_ROUNDS` | work | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_dexguard.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_LEN` | size | `usize` | `1 << 20` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_BACKWARD_BRANCHES` | other | `u32` | `500_000` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_BYTES` | size | `usize` | `8 << 20` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_RECURSION_DEPTH` | recursion | `u32` | `12` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `STEP_BUDGET` | work | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `TOTAL_STEP_BUDGET` | work | `u64` | `16 * STEP_BUDGET` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DATA_ELEMENTS` | other | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_DEPTH` | recursion | `u16` | `2` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_HANDLER_BLOCKS` | other | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_MONITOR_BODY_BLOCKS` | other | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | work | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_RECOVERABLE_PAYLOAD_LEN` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dalvik_pack_stub_loader.rs` |
| `disrobe-pass-jvm` | `MAX_HELPER_ARITY` | other | `usize` | `6` | `crates/disrobe-pass-jvm/src/dalvik_r8_inline/detect.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | other | `usize` | `128` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_LEN` | size | `usize` | `1 << 20` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_CANDIDATE_PARAMS` | other | `usize` | `2` | `crates/disrobe-pass-jvm/src/dalvik_strdec_generic.rs` |
| `disrobe-pass-jvm` | `MAX_BUCKET_TESTS` | other | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | work | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_BRANCH_INSNS` | other | `usize` | `2048` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_CODE_BYTES` | size | `usize` | `60_000` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_METHOD_INSNS` | other | `usize` | `8192` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_TRACKED_NARROW_CONSTANT_REGS` | other | `usize` | `128` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_REGION_BLOCKS` | other | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/dalvik_try_regions.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_JOIN_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `MAX_FIXPOINT_ITERS` | work | `usize` | `50_000` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `MAX_SUPERCLASS_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `ARM_CONDITION_BLOCK_CAP` | other | `usize` | `32` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `INT_USE_SCAN_LIMIT` | other | `usize` | `32` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_BOOL_EXPR_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_DUP_EXPR_NODES` | count | `usize` | `1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENTS` | other | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENT_BYTES` | size | `usize` | `262_144` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | output | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `RECORD_ARITY_PROBE_CAP` | other | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `REUSED_LOCAL_SPLIT_WORK_LIMIT` | work | `usize` | `1_000_000` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_BLOCKS` | other | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_CONDITION_CHAIN` | other | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_JOIN_CHAIN` | other | `usize` | `8` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_STRUCTURE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_STRUCTURE_WORK` | work | `usize` | `200_000` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_BLOCKS` | other | `usize` | `8` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_INSTRUCTIONS` | other | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMENSIONS` | other | `u8` | `255` | `crates/disrobe-pass-jvm/src/descriptor.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_ANNOTATION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_ANNOTATION_VALUES` | other | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_DIAGNOSTICS` | other | `usize` | `256` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_NORMALIZATION_ROUNDS` | work | `usize` | `8` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_INNER_CLASS_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-jvm/src/dex2jar.rs` |
| `disrobe-pass-jvm` | `MAX_STORED_FRAME_SLOTS` | other | `usize` | `4 << 20` | `crates/disrobe-pass-jvm/src/frame_infer.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_DECODED_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_EDGES` | other | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_NODES` | count | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_PREALLOC` | other | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_ENTRY_BYTES_CAP` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_ENTRY_COUNT_CAP` | count | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_TOTAL_BYTES_CAP` | size | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMS` | other | `usize` | `255` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_JNI_STRING_LEN` | size | `usize` | `512` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_INT_KEYS` | other | `usize` | `4096` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIBS` | other | `usize` | `128` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIB_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_STUB_BYTES` | size | `usize` | `16` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_HANDLER_COVERAGE` | other | `usize` | `4_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_OUTPUT` | output | `usize` | `1_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_REMAP_WORK` | work | `usize` | `64_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_OAT_DEX_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/oat.rs` |
| `disrobe-pass-jvm` | `MAX_OAT_DEX_LOCATION_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-jvm/src/oat.rs` |
| `disrobe-pass-jvm` | `MAX_HIERARCHY_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-jvm/src/proguard.rs` |
| `disrobe-pass-jvm` | `MAX_METHOD_INSNS` | other | `usize` | `200_000` | `crates/disrobe-pass-jvm/src/protectors/unflatten.rs` |
| `disrobe-pass-jvm` | `MAX_DISPATCH_RESOLVE_STEPS` | work | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/sccp.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_BYTES` | size | `usize` | `65_535` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_DEPTH` | recursion | `u16` | `64` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_ITEMS` | count | `usize` | `1_024` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_NODES` | count | `u32` | `4_096` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | `usize` | `8_192` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `MAX_STRING_LEN` | size | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | `u64` | `4_000_000` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/stub_emulator.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-lua/src/cursor.rs` |
| `disrobe-pass-lua` | `MAX_RESERVE_BYTES` | size | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/cursor.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_WORK` | work | `u64` | `1 << 24` | `crates/disrobe-pass-lua/src/decompile/budget.rs` |
| `disrobe-pass-lua` | `MAX_INLINED_CLOSURE_BYTES` | size | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/decompile/lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/luajit_lift.rs` |
| `disrobe-pass-lua` | `MAX_DIRECT_RENDER_NESTING` | recursion | `usize` | `256` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_RENDERED_STRUCTURE_BYTES` | output | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_VISITS_PER_NODE` | other | `usize` | `2` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_WORK` | work | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_RESERVED_NAME_SCAN` | other | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_NODES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `READ_SEARCH_STATE_BUDGET` | work | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_SCOPE_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/struct_lift/declare.rs` |
| `disrobe-pass-lua` | `MAX_CONDITION_CHAIN` | other | `usize` | `64` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_EXIT_SCAN` | other | `usize` | `4_096` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_BUILD_STEPS` | work | `usize` | `4_096` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_REGION_INSTRUCTIONS` | other | `usize` | `256` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_LOADER_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-pass-lua/src/obfuscator/hercules.rs` |
| `disrobe-pass-lua` | `IB_CONST_COUNT_CAP` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_FUNCTION_COUNT_CAP` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_INSTRUCTION_COUNT_CAP` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_LINEINFO_COUNT_CAP` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `MAX_LOC_CONSTANTS` | other | `usize` | `1usize << 16` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_INSTRUCTIONS` | other | `usize` | `1usize << 20` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_PROTOS` | other | `usize` | `1usize << 16` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_STRING_BYTES` | size | `usize` | `16usize << 20` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `LURAPH_SCAN_LIMIT` | other | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_BOOTSTRAP_TABLE_VALUES` | other | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_LURAPH_EXPR_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `CONSTANT_ARRAY_BUDGET` | work | `ConstantArrayBudget` | `ConstantArrayBudget { max_source_bytes: crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES, max_entries: MAX_CONSTANT_ARRAY_ENTRIES, max_decoded_bytes: MAX_CONSTANT_ARRAY_DECODED_BYTES, }` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_ARRAY_DECODED_BYTES` | size | `usize` | `4 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_ARRAY_ENTRIES` | count | `usize` | `1 << 14` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_NESTED_VMIFY_PASSES` | recursion | `usize` | `4` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `VMIFY_DISPATCH_SCAN_LIMIT` | other | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_BLOCK_STATEMENTS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_LOCALS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_NEST_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_SOURCE_BYTES` | size | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_TOKENS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_EXPRESSION_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_PROOF_STEPS` | work | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_STATE_BINDINGS` | other | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_BOX_STATEMENT_USES` | other | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_BOX_STATE_BINDINGS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_POOL_RESOLVERS` | other | `usize` | `8` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_DISPATCH_DEPTH` | recursion | `u32` | `96` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_FUNCTIONS` | other | `usize` | `1 << 10` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_FUNCTION_BLOCKS` | other | `usize` | `1 << 14` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_LOOP_NESTING` | recursion | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_REACHABILITY_STEPS` | work | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_RECOVERY_DEPTH` | recursion | `usize` | `6` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_REGION_TREE_STEPS` | work | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_SCRATCH_CHAIN_DEPTH` | recursion | `u32` | `12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_STATIC_NUMBER_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_STATIC_NUMBER_FUEL` | work | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | other | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `MAX_FOLD_TOKENS` | other | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `NUMERIC_EXPR_BUDGET` | work | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `MAX_DECOMPRESSED` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_CODE_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_CONSTANT_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_LINE_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_LOCAL_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_PROTO_COUNT` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_UPVALUE_COUNT` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_UPVALUE_NAME_COUNT` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `U32_FIELD_LIMIT` | other | `usize` | `u32::MAX as usize` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `BASE64_PAYLOAD_CHAR_CAP` | other | `usize` | `(LUA_STRING_PAYLOAD_CAP / 3) * 4 + 8` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `BOOTSTRAP_SCAN_LIMIT` | other | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `EMBEDDED_PAYLOAD_SCAN_LIMIT` | other | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `LUA_STRING_PAYLOAD_CAP` | other | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `LUA_TABLE_PAYLOAD_CAP` | other | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `PB_STACK_LIMIT` | other | `usize` | `256` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `PB_STEP_LIMIT` | work | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `VM_CODE_COUNT_CAP` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `VM_CONST_COUNT_CAP` | count | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `DISPATCH_BLOCK_LIMIT` | other | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_GUARD_LIMIT` | other | `usize` | `256` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_PARSE_DEPTH_LIMIT` | recursion | `usize` | `512` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | other | `usize` | `256 * 1024` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `MAX_ASSEMBLED_NODES` | count | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_BUILD_ID_BYTES` | size | `usize` | `128` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_OPCODE_MAP_BYTES` | size | `u64` | `64 << 10` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-mobile` | `MAX_EMBEDDED_DEX_CARVES` | other | `usize` | `16` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_PROTECTOR_CARVE_SCAN` | other | `u64` | `64 << 20` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_RESOLVED_RESOURCES` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_TEXT_ASSET` | other | `u64` | `16 << 20` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_CERTS_PER_SIGNER` | other | `usize` | `256` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_DIGESTS_PER_SIGNER` | other | `usize` | `256` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_PAIRS` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_SIGNERS` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_STRINGS` | other | `u32` | `1 << 22` | `crates/disrobe-pass-mobile/src/arsc.rs` |
| `disrobe-pass-mobile` | `MAX_TYPE_ENTRIES` | count | `u32` | `1 << 20` | `crates/disrobe-pass-mobile/src/arsc.rs` |
| `disrobe-pass-mobile` | `MAX_DEPTH` | recursion | `usize` | `512` | `crates/disrobe-pass-mobile/src/axml.rs` |
| `disrobe-pass-mobile` | `TRAVERSAL_INSN_BUDGET` | work | `usize` | `1 << 22` | `crates/disrobe-pass-mobile/src/flutter/arm64_traversal.rs` |
| `disrobe-pass-mobile` | `MAX_BOOLEAN_RETURN_INSTRUCTIONS` | other | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_SETUP_INSTRUCTIONS` | other | `usize` | `8` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_TRACE_INSTRUCTIONS` | other | `usize` | `256` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_CONSUMED_TEXT_BYTES` | size | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FLOAT_RETURN_SPILL_DISTANCE` | other | `usize` | `3` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FRAME_SLOTS` | other | `usize` | `128` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_MERGE_PREDECESSORS` | other | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_STACK_ARGUMENTS` | other | `usize` | `32` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_CALLS` | other | `usize` | `1 << 14` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_EFFECTS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_DEPTH` | recursion | `usize` | `6` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_NODES` | count | `usize` | `48` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `CLUSTER_TAG_SCAN_LIMIT` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/cluster.rs` |
| `disrobe-pass-mobile` | `MAX_CODE_TABLE_ENTRIES` | count | `usize` | `1 << 22` | `crates/disrobe-pass-mobile/src/flutter/code_table.rs` |
| `disrobe-pass-mobile` | `HARD_CLUSTER_LIMIT` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_OBJECT_LIMIT` | other | `usize` | `2_000_000` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_REFERENCE_LIMIT` | other | `usize` | `16_000_000` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_STRING_CODE_UNIT_LIMIT` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_TOTAL_STRING_BYTE_LIMIT` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_VARIABLE_LENGTH_LIMIT` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_SLOTS` | other | `usize` | `1 << 21` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `FEATURE_STRING_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/flutter/dart_graph_recovery.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_INSNS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/disasm.rs` |
| `disrobe-pass-mobile` | `MEMBER_TABLE_CAP` | other | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/flutter/kernel.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_LITERALS` | work | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_RUN_PROBE` | other | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `POOL_DECODE_BUDGET` | work | `usize` | `1 << 24` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_LIST_ELEMENTS` | other | `usize` | `8` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_CHARS` | work | `usize` | `120` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_DEPTH` | recursion | `usize` | `4` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_NODES` | work | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_DART_IDENTIFIER_BYTES` | size | `usize` | `1 << 14` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_DART_IDENTIFIER_COUNT` | count | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_BOUNDARIES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_STRING_CHARS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/string_pool.rs` |
| `disrobe-pass-mobile` | `MAX_DECIMAL_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/bigint.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_INSTRUCTIONS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_BYTES` | size | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_REG_EXPR_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDERED_CALL_ARGS` | output | `u64` | `256` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDER_BYTES` | output | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_SWITCH_CASES` | other | `u64` | `4096` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_LITERALS` | work | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/literals.rs` |
| `disrobe-pass-mobile` | `MAX_REGEX_DEPTH` | recursion | `usize` | `512` | `crates/disrobe-pass-mobile/src/hermes/regex.rs` |
| `disrobe-pass-mobile` | `MAX_REGEX_INSNS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/regex.rs` |
| `disrobe-pass-mobile` | `MAX_LOOP_EXTENSION_ROUNDS` | work | `usize` | `64` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_LOWERED_LOOPS` | work | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_REGION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_STRUCTURE_BLOCKS` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_STRUCTURE_STATEMENTS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MACHO_FAT_ARCH_COUNT_CAP` | count | `usize` | `4096` | `crates/disrobe-pass-mobile/src/ios.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_COUNT_CAP` | count | `usize` | `65_536` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_PREALLOC_CAP` | other | `usize` | `64 << 20` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_READ_CAP` | other | `usize` | `512 << 20` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_XML` | other | `usize` | `4096` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-mobile` | `MAX_VALUES_ENTRIES` | count | `usize` | `16384` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_INSNS` | other | `usize` | `200_000` | `crates/disrobe-pass-native/src/api_hash.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_DEPTH` | recursion | `usize` | `12` | `crates/disrobe-pass-native/src/authenticode.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `1024` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_FUNCTIONS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_IMAGE_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_REPORT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_X86_INSTRUCTION_BYTES` | size | `usize` | `15` | `crates/disrobe-pass-native/src/code_symbol.rs` |
| `disrobe-pass-native` | `MAX_ITANIUM_ACTION_STEPS` | work | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_ITANIUM_LSDA_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_WINDOWS_SEH_SCOPE_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_AGGREGATE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_IPI_RECORDS` | count | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_MODULES` | other | `usize` | `65_536` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_MODULE_SYMBOLS` | other | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_RESOLVED_STRING_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_SUBSTRING_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_SUBSTRING_REFERENCES` | other | `usize` | `16_384` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_DEPTH` | recursion | `usize` | `512` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `MAX_OBJECTS` | other | `usize` | `200_000` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_BYTES` | output | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `BYTE_SCAN_LIMIT` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_SHORTSTRING_LEN` | size | `usize` | `255` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_STUB_BYTES` | size | `usize` | `256` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_STUB_INSTRUCTIONS` | other | `usize` | `48` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_UNITS` | other | `i32` | `8192` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_ENTRIES` | count | `u32` | `8192` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_NAME_CHARS` | other | `usize` | `512` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCES` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_SCAN_POSITIONS` | other | `usize` | `16_000_000` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRINGS` | other | `usize` | `65_536` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_UNITS` | other | `u32` | `1 << 20` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_METHODS` | other | `u16` | `4096` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELDS_PER_CLASS` | other | `u16` | `4096` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELD_CLASSES` | other | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_INTERFACES` | other | `i32` | `1024` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_ENUM_MEMBERS` | count | `i64` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_FIELD_VISIBILITY` | other | `u8` | `3` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_MANAGED_FIELDS` | other | `i32` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_FIELDS` | other | `i32` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_OPERATORS` | other | `u8` | `64` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_SIZE` | size | `i32` | `1 << 20` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_PATH_TAIL` | other | `usize` | `16` | `crates/disrobe-pass-native/src/delphi/version.rs` |
| `disrobe-pass-native` | `MAX_CLASSES` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_INSTANCE_SIZE` | size | `u32` | `0x0100_0000` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_METHODS_PER_CLASS` | other | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PARENT_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PROPS_PER_CLASS` | work | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_SCAN_POSITIONS` | other | `usize` | `8_000_000` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_TYPE_RECORDS` | count | `usize` | `16384` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/abi.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/bcf_dse.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/branchfold.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_DISPATCH_TREE_STEPS` | work | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_INSNS` | other | `usize` | `200_000` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_DEPTH` | recursion | `u32` | `128` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_STEPS` | work | `u32` | `4096` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_RESOLVE_DEPTH` | recursion | `u32` | `4` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/copyprop.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/deadflags.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_TABLE_ENTRIES` | count | `u64` | `4096` | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_EXPR_NODES` | count | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/mba_lift.rs` |
| `disrobe-pass-native` | `MAX_LIFT_INSNS` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/mba_lift.rs` |
| `disrobe-pass-native` | `MAX_CONSTRAINTS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_FEASIBILITY_EVALS` | other | `u128` | `1 << 24` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_FEASIBILITY_VARS` | other | `u32` | `3` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_PATH_BLOCKS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_JOINS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_LOOPS` | work | `usize` | `1` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_REGISTERS` | output | `usize` | `32` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_STACK_CELLS` | output | `usize` | `32` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_BLOCKS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_INSNS` | other | `usize` | `2048` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLL` | other | `usize` | `8` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLLED_BLOCKS` | other | `usize` | `512` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `VERIFY_ARITY_CAP` | other | `u32` | `12` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DIRECT_CALL_SWEEP_OFFSETS` | other | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_DISCOVERY_FUNCTIONS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_INTERIOR_PROLOGUE_PROVENANCE` | other | `usize` | `MAX_DISCOVERY_FUNCTIONS` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_JUMP_TABLE_ENTRIES` | count | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_NORETURN_DECODED_INSTRUCTIONS` | other | `usize` | `262_144` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_NORETURN_ITERATIONS` | work | `usize` | `64` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_BACKWARD_DISTANCE` | other | `u64` | `1_u64 << 31` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_FORWARD_DISTANCE` | other | `u64` | `(1_u64 << 31) - 1` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_BOUNDARY_PADDING_BYTES` | size | `u64` | `64` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_DECODE_TEXT_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_PAYLOAD_INSTRUCTIONS` | other | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_AARCH64_PLT_ENTRIES` | count | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_EXECUTABLE_RANGES` | other | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_GUARD_CF_FUNCTIONS` | other | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_TLS_CALLBACKS` | other | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_POINTER_SLOTS` | other | `usize` | `1 << 21` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_SEEDS` | other | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_UNWIND_ENTRIES` | count | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_ENTRIES` | count | `usize` | `16 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_ELF_PROGRAM_HEADERS` | other | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_GNU_HASH_BUCKETS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_NEEDED` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_RELOCATIONS` | other | `usize` | `512 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_STRING_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_SYMBOLS` | other | `usize` | `256 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `4096` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_BUFFERS_PER_CANDIDATE` | other | `usize` | `24` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_CANDIDATES` | other | `usize` | `64` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_DECODE_SPAN` | other | `u64` | `64 * 1024` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_PER_RUN` | other | `usize` | `512` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `PER_CANDIDATE_STEP_CAP` | work | `u64` | `200_000` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_ENTROPY_BITS` | other | `f64` | `8.0` | `crates/disrobe-pass-native/src/entropy_viz.rs` |
| `disrobe-pass-native` | `OVERLAY_SCAN_CAP` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/fileid.rs` |
| `disrobe-pass-native` | `LIBRARY_NAME_CAP` | other | `usize` | `1024` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BODY` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_PATTERN_LEN` | size | `u8` | `64` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_TREE_DEPTH` | recursion | `u32` | `256` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/identify.rs` |
| `disrobe-pass-native` | `NATIVE_MATCH_DEFAULT_LIMIT` | other | `usize` | `DEFAULT_LISTING_LIMIT` | `crates/disrobe-pass-native/src/native_match.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_IMPORTS_PER_MODULE` | other | `usize` | `256` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_IMPORT_DESCRIPTORS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_MODULE_NAME_LEN` | size | `usize` | `260` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_THUNK_CANDIDATES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/emulated_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_cca.rs` |
| `disrobe-pass-native` | `OUTPUT_CAP` | output | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_k7_cm.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/kkrunchy_phase2.rs` |
| `disrobe-pass-native` | `MAX_DECODED_SIZE` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_unpack.rs` |
| `disrobe-pass-native` | `MAX_RECOVERED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/loader_generators.rs` |
| `disrobe-pass-native` | `MAX_MEW_LEADING_CHUNKS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/packers/mew_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_POS_BITS` | other | `usize` | `4` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_POS_STATES` | other | `usize` | `1 << MAX_POS_BITS` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_IMAGE_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/mpress_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_IMPORTED_MODULES` | other | `usize` | `96` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_IMPORTS_PER_MODULE` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_MODULE_NAME_BYTES` | size | `usize` | `96` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_DIRECTORIES` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_ENTRIES_PER_DIRECTORY` | count | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_GAP_SEARCH_BYTES` | size | `u32` | `1 << 22` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_LEAVES` | other | `usize` | `16384` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_RECOVERED_IMAGE_BYTES` | size | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCE_DEPTH` | recursion | `u32` | `8` | `crates/disrobe-pass-native/src/packers/pe_unbind.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/pecompact_phase2.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/petite_phase2.rs` |
| `disrobe-pass-native` | `EMULATED_IMAGE_EXPANSION_LIMIT` | other | `u64` | `4096` | `crates/disrobe-pass-native/src/packers/section_recovery.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_BRUTE_FORCE_OFFSETS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSION_ATTEMPTS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_L_INFO_SCAN` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_RESYNC_OFFSETS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_STRUCTURAL_CHECKSUM_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_TAIL_SCAN` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_TOTAL_DECOMPRESSED_OUTPUT` | output | `usize` | `MAX_DECOMPRESSED * 2` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_VERIFY_CANDIDATES` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_VERIFY_EXPANSION` | other | `u64` | `64` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_CARVED_PROTECTED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/vmprotect_carve.rs` |
| `disrobe-pass-native` | `MAX_CARVED_PROTECTED_SECTIONS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/packers/vmprotect_carve.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `131_072` | `crates/disrobe-pass-native/src/packers/yodas_crypter.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/yodas_emulated_unpack.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/yodas_protector_phase2.rs` |
| `disrobe-pass-native` | `ADDRESS_SPACE_CAP` | other | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `DEOBF_SECTION_CAP` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `MAX_TYPE_RECORDS` | count | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/pdb_cxx/catalog.rs` |
| `disrobe-pass-native` | `MAX_FIELDLIST_CHAIN` | other | `usize` | `256` | `crates/disrobe-pass-native/src/pdb_cxx/emit.rs` |
| `disrobe-pass-native` | `MAX_MODULES` | other | `usize` | `65_536` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_PARAMETERS` | other | `usize` | `4_096` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_PROCEDURES` | other | `usize` | `262_144` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_SYMBOLS_PER_MODULE` | other | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_RECURSION_BUDGET` | recursion | `u32` | `24` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_UNWRAP_DEPTH` | recursion | `u32` | `64` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_NAME_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_STUBS` | other | `usize` | `65_536` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SCANNED_NAME_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SYMBOL_NAME_BYTES` | size | `usize` | `4 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `AARCH64_STACK_FP_ALIAS_LIMIT` | other | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `ACYCLIC_JOIN_BLOCK_CAP` | other | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `FORWARD_JOIN_PLAN_CAP` | other | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `LOOP_EXIT_TAIL_ABSORPTION_BUDGET` | work | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_BYTES` | size | `usize` | `1024` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_CALLEES` | other | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_RELOCATIONS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_OUTLINED_EXIT_SLOTS` | other | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_PROGRAM_FUNCTION_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `PURE_TAIL_CLONE_BUDGET` | work | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_LABEL_CAP` | other | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_NODE_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_JOIN_WALK_BUDGET` | work | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SPLIT_BLOCK_CAP` | other | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SUBTREE_CAP` | other | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_FRAME_BYTES` | size | `i64` | `1 << 20` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_INSTRUCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_CASES` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_SLICE_INSTRUCTIONS` | other | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_TABLE_BYTES` | size | `usize` | `MAX_SWITCH_CASES * 8` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `REGISTER_ARGUMENT_LIMIT` | other | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c/aarch64_callsite.rs` |
| `disrobe-pass-native` | `MAX_FIXPOINT_STEPS` | work | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/pseudo_c/aarch64_frame.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_BYTES` | size | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_FUNCTIONS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_AFFINE_SHIFT` | other | `u8` | `126` | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_DIVIDEND_BITS` | other | `u32` | `64` | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_EXPR_NODES` | count | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_FOLDS` | other | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_PROOFS` | other | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_READ_STEPS` | work | `usize` | `16384` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_STATEMENTS` | other | `usize` | `2048` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_VALUES` | other | `usize` | `4` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `PATH_BUDGET` | work | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/pseudo_c/return_channel.rs` |
| `disrobe-pass-native` | `MAX_INLINED_DEFINITIONS` | other | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_LOOP_WEIGHT_DEPTH` | recursion | `u32` | `8` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_RECORDED_DECISIONS` | other | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_COMPRESSED_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_DECOMPRESSED_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_CONTAINER_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_ESCAPED_STRING_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_STRING_BYTES` | size | `usize` | `9 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_WORK_ITEMS` | work | `usize` | `1_048_576` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_PACKAGES` | other | `usize` | `16_384` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_PACKAGE_TEXT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `VERSION_TAIL_CAP` | other | `usize` | `64` | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `ADRP_PAIR_SCAN_LIMIT` | other | `usize` | `16` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WIDE_MOVE_CHAIN_LIMIT` | other | `usize` | `3` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WINDOW_INSTRUCTION_LIMIT` | other | `usize` | `64` | `crates/disrobe-pass-native/src/similarity/opaque.rs` |
| `disrobe-pass-native` | `MAX_GROUP_SPAN` | other | `i64` | `1024` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_SCAN_INSNS` | other | `usize` | `200_000` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_RIP_REFS` | other | `usize` | `200_000` | `crates/disrobe-pass-native/src/stream_disasm.rs` |
| `disrobe-pass-native` | `MAX_MAP_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_MAP_PAGES` | other | `u64` | `MAX_MAP_BYTES / (PAGE_SIZE as u64)` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_WRITE_LOG_ENTRIES` | count | `usize` | `1 << 19` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_PAGES` | other | `usize` | `65_536` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_STEPS` | work | `usize` | `65_536` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_FIXUP_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SECTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SEGMENTS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `STEP_CAP` | work | `u64` | `5_000_000` | `crates/disrobe-pass-native/src/vm_devirt/eval.rs` |
| `disrobe-pass-native` | `MAX_GUARDIAN_BYTECODE_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/guardian.rs` |
| `disrobe-pass-native` | `MAX_BYTECODE_INSNS` | size | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_HANDLERS` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_VM_REGS` | other | `usize` | `256` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_VM_STACK` | other | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_CARVE_BYTES` | size | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_CODE_BYTES` | size | `u64` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_FUNCTIONS` | other | `usize` | `MAX_LISTED_FUNCTIONS` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_EMITTED_NAME_CHARS` | output | `usize` | `120` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_GATE_TOKENS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_RETAINED_SOURCE_BYTES` | size | `u64` | `4 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_OUTPUT` | output | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_STEPS` | work | `usize` | `200_000` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_NIM_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-nativelang/src/demangle.rs` |
| `disrobe-pass-nativelang` | `MAX_INSTRUCTIONS_PER_FUNCTION` | other | `usize` | `8192` | `crates/disrobe-pass-nativelang/src/disasm.rs` |
| `disrobe-pass-nativelang` | `MAX_LISTED_FUNCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-nativelang/src/disasm.rs` |
| `disrobe-pass-nativelang` | `INITIAL_INFLATE_CAP` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_ARRAY_DIMENSIONS` | other | `usize` | `1 << 8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_DEPTH` | recursion | `usize` | `1 << 8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_ITEMS` | count | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_DIE_VISITS` | other | `usize` | `1 << 22` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCTION_PARAMS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_VISITS` | other | `usize` | `16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_STRING_BYTES` | size | `usize` | `1 << 26` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_STRING_LEN` | size | `usize` | `1 << 14` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_TYPE_DEPTH` | recursion | `u8` | `8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_LINE_ROWS` | other | `u64` | `1 << 24` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_TOTAL_DEBUG_BYTES` | size | `u64` | `2 << 30` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_UNCOMPRESSED` | other | `u64` | `1 << 30` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_REPORTED_TYPES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf_types.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_FDES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_FUNCTION_BYTES` | size | `u64` | `256 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_RECOVERED_FUNCTIONS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_TRAVERSAL_TEXT` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_STRING_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_STRING_SCAN_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_TABLE_FUNCTION_STARTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_FUNCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_SYMBOLS` | other | `usize` | `8192` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_CANDIDATES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_NAME_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_NAME_LEN` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SCAN_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SECTIONS` | other | `usize` | `96` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SEGMENTS` | other | `usize` | `64` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SLICE_LEN` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SYMBOLS` | other | `usize` | `16 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_VECTOR_LEN` | size | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nuitka` | `MAX_CONTAINER_LEN` | size | `u64` | `1 << 24` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAF_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAVES` | other | `usize` | `200_000` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LIFT_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_PREPROCESSOR_NESTING` | recursion | `usize` | `256usize` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENTS` | other | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENT_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_DIAMOND_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_FIELD_LEN` | size | `usize` | `256` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_RECORD_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_MODULES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/bytecode_table.rs` |
| `disrobe-pass-nuitka` | `MAX_C_CALL_ARGUMENT_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_DIRECT_STATEMENT_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_FUNCTION_PARAMETERS` | other | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_MODULE_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_FACTORY_TOP_LEVEL_STATEMENTS` | other | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_ASSIGNMENTS` | other | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_SCOPES` | other | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_SCOPE_SEGMENTS` | other | `usize` | `131_072` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MANIFEST_ENTRY_EXTRACT_CAP` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_ONEFILE_MAIN_DECOMPILE_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_COUNT` | count | `u64` | `200_000` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | recursion | `usize` | `200` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | size | `usize` | `200` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_PREVIOUS_CLONE_WEIGHT` | other | `usize` | `128 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_STORED_LAST_WEIGHT` | other | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_TABLE_HEADER_HINTS` | other | `usize` | `64` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_WIDE_SCAN_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_ENTRIES` | count | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_MEMBERS` | count | `usize` | `MAX_CONSTANT_MANIFEST_ENTRIES + 1usize` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_CONST_BYTES` | size | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_CONST_FILES` | count | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_LABEL_BYTES` | size | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_CONST_FILE_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_STREAMS_PER_FILE` | other | `usize` | `1_000_000` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_BOUNDED_READ_PREALLOC_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_DIRECTORY_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_SIBLING_BINARY_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_PYTHON_ABI_MINOR` | other | `u8` | `20` | `crates/disrobe-pass-nuitka/src/detect.rs` |
| `disrobe-pass-nuitka` | `MAX_FROZEN_MODULES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_MARSHAL_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_BINARY_INPUT_BYTES` | size | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_C_SOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_C_SOURCE_LINES` | other | `usize` | `1_000_000` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRIES` | count | `usize` | `100_000` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAMES` | other | `usize` | `50_000` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | size | `usize` | `200` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_MAP_TEXT_BYTES` | size | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_API_CALLS` | other | `usize` | `64` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_ENUMERATION_INSNS` | other | `usize` | `4_000_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_FUNCTIONS` | other | `usize` | `20_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_IMPL_INSNS` | other | `usize` | `20_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_TEXT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_DECOMPRESSED_ABS` | other | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_DECOMPRESSION_RATIO` | other | `u64` | `1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRY_COUNT` | count | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRY_SIZE` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_EXTRACTED_DATA_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_FILENAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `GLOBAL_CANDIDATE_LOG_CAP` | other | `u32` | `16` | `crates/disrobe-pass-nuitka/src/onefile_locator.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_EXPRESSION_BYTES` | size | `usize` | `8_192usize` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_NESTING` | recursion | `usize` | `64usize` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_STATIC_PICKLE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | recursion | `u32` | `128` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_STATEMENTS` | other | `usize` | `4096` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_PREALLOC` | other | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `MAX_UNRECOVERED_RECORDS` | count | `usize` | `4096` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `REASON_ROPE_BUDGET` | work | `&str` | `"the rope exceeds the bounded php 8 rope folding budget"` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CALL_ARGUMENT_CAP` | other | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CALL_RENDER_CAP` | output | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_CLAUSE_CAP` | other | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_TYPE_CAP` | other | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CHILD_CAP` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CLOSURE_USE_CAP` | other | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_FOR_STEP_CAP` | work | `usize` | `16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_ELEMENT_CAP` | other | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_RENDER_CAP` | output | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LITERAL_CAP` | work | `u32` | `4_000_000` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_EXIT_FREE_CAP` | other | `u32` | `SANE_LIFT_DEPTH` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_RELIFT_WORK_CAP` | work | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_NAME_CAP` | other | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_OP_CAP` | other | `u32` | `4_000_000` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_ROPE_WORK_CAP` | work | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_ARM_CAP` | other | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_LABEL_WORK_CAP` | work | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_STATE_WORK_CAP` | work | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_TRY_CATCH_CAP` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_VAR_CAP` | other | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `USE_SCAN_BUDGET` | work | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `MAX_LABEL_ATTRIBUTIONS_PER_ITEM` | other | `usize` | `64` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MAX_LINEARIZE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MAX_LINEARIZE_STEPS` | work | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MIN_LABEL_ATTRIBUTION_BUDGET` | work | `usize` | `4096` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `CONTAINER_INFLATE_OUTPUT_CAP` | output | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-php/src/encoder/container.rs` |
| `disrobe-pass-php` | `ZEND_OPTIMIZER_OBF_KEY_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-php/src/encoder/container.rs` |
| `disrobe-pass-php` | `ZEND_OBFUSCATION_KEY_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-php/src/key_extractor.rs` |
| `disrobe-pass-php` | `EXPR_INFLATE_CAP` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `EXPR_INITIAL_CAP` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_OPAQUE_STATEMENT` | other | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `STR_REPEAT_OUTPUT_CAP` | output | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `STR_REPLACE_OUTPUT_CAP` | output | `usize` | `EXPR_INFLATE_CAP` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_ARGS` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_CLASS_NAMES` | other | `u32` | `1 << 12` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_COPIED_BYTES` | size | `usize` | `1 << 28` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_DEPTH` | recursion | `u32` | `64` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_DYNAMIC_DEFS` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_HASH_ELEMENTS` | other | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_LITERALS` | work | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_OPS` | work | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_OP_ARRAYS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TEMPORARIES` | other | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TRY_CATCH` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TYPE_LIST` | other | `u32` | `1 << 8` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_VALUE_NODES` | count | `usize` | `1 << 22` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_VARS` | other | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `EVAL_CHAIN_INFLATE_OUTPUT_CAP` | output | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `EVAL_PROBE_MIN_BUDGET` | work | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `INFLATE_INITIAL_CAP` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `RESOLVE_DEPTH_CAP` | recursion | `u32` | `32` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `STR_REPLACE_OUTPUT_CAP` | output | `usize` | `EVAL_CHAIN_INFLATE_OUTPUT_CAP` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `PHAR_ALIAS_CAP` | other | `u32` | `1 << 14` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_DECOMPRESS_CAP` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_DECOMPRESS_INITIAL_CAP` | other | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_ENTRY_NAME_CAP` | other | `u32` | `1 << 12` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_MANIFEST_ENTRY_CAP` | other | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_META_CAP` | other | `u32` | `1 << 22` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_PAYLOAD_CAP` | other | `u32` | `1 << 30` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `MAX_RESTRUCTURE_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-php/src/restructure.rs` |
| `disrobe-pass-php` | `MAX_TOKEN_COUNT` | count | `usize` | `1_000_000` | `crates/disrobe-pass-php/src/token.rs` |
| `disrobe-pass-pickle` | `MAX_RENDER_DEPTH` | recursion | `u32` | `2_048` | `crates/disrobe-pass-pickle/src/decompile.rs` |
| `disrobe-pass-pickle` | `LONG_BODY_BUDGET` | work | `usize` | `1 << 18` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `MAX_LONG_BODY` | other | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `MAX_STACKED_STREAMS` | other | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `OPCODE_BUDGET` | work | `usize` | `5_000_000` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `ANCHOR_OPCODE_BUDGET` | work | `usize` | `1 << 16` | `crates/disrobe-pass-pickle/src/ml.rs` |
| `disrobe-pass-pickle` | `MAX_ZIP_COMMENT` | other | `usize` | `0xFFFF` | `crates/disrobe-pass-pickle/src/polyglot.rs` |
| `disrobe-pass-pickle` | `MAX_CYCLE_TARGETS` | other | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/reconstruct.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_BYTES` | recursion | `usize` | `1_048_576` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_DEPTH` | recursion | `usize` | `3` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_SCAN_DEPTH` | recursion | `usize` | `2_048` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_VALUE_DEPTH` | recursion | `u32` | `1_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-pickle` | `NODE_BUDGET` | work | `u64` | `8_000_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-pickle` | `RECURSION_LIMIT` | recursion | `usize` | `2_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-py-decompile` | `MAX_SLOT_INDEX` | other | `u32` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/alt_lift/mpy.rs` |
| `disrobe-pass-py-decompile` | `MAX_PATTERN_NEST_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/ast/builder/branches.rs` |
| `disrobe-pass-py-decompile` | `MAX_IMPORT_LEVEL` | other | `u32` | `32` | `crates/disrobe-pass-py-decompile/src/ast/builder/exprs.rs` |
| `disrobe-pass-py-decompile` | `MAX_LAMBDA_BRANCH_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/ast/builder/function_meta.rs` |
| `disrobe-pass-py-decompile` | `LOOP_HEADER_PREFIX_LIMIT` | other | `usize` | `4` | `crates/disrobe-pass-py-decompile/src/ast/builder/loops.rs` |
| `disrobe-pass-py-decompile` | `CODEOBJ_DEPTH_LIMIT` | recursion | `usize` | `200` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `EXIT_PROBE_STEP_BUDGET` | work | `usize` | `1 << 22` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `MAX_SYNTH_OPERANDS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `STRUCTURE_DEPTH_LIMIT` | recursion | `usize` | `600` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `STRUCTURE_REENTRY_LIMIT` | other | `usize` | `4` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `MAX_EMIT_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/codegen/expr.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_LITERAL_BYTES` | work | `usize` | `1 << 20` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_STRINGS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCAN_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_FRAME_NEST_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/frame_tree/builder.rs` |
| `disrobe-pass-py-decompile` | `MAX_PROBE_CAPTURE` | other | `usize` | `1024 * 1024` | `crates/disrobe-pass-py-decompile/src/recompile.rs` |
| `disrobe-pass-py-decompile` | `MAX_CANDIDATES` | other | `usize` | `48` | `crates/disrobe-pass-py-decompile/src/selfcheck/opcontent.rs` |
| `disrobe-pass-py-decompile` | `MAX_DEPTH` | recursion | `u32` | `96` | `crates/disrobe-pass-py-decompile/src/selfcheck/relower.rs` |
| `disrobe-pass-py-decompile` | `MAX_HOIST_CANDIDATES` | other | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/selfcheck/repair.rs` |
| `disrobe-pass-py-deob` | `MAX_FSTRING_OUTPUT` | output | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/ast_eval/eval.rs` |
| `disrobe-pass-py-deob` | `MAX_REPEAT_ITEMS` | count | `usize` | `8192` | `crates/disrobe-pass-py-deob/src/ast_eval/eval.rs` |
| `disrobe-pass-py-deob` | `MAX_SPLIT` | other | `i128` | `65_536` | `crates/disrobe-pass-py-deob/src/ast_eval/methods.rs` |
| `disrobe-pass-py-deob` | `MAX_OUTPUT` | output | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/ast_eval/pyformat.rs` |
| `disrobe-pass-py-deob` | `MAX_WIDTH` | other | `usize` | `4096` | `crates/disrobe-pass-py-deob/src/ast_eval/pyformat.rs` |
| `disrobe-pass-py-deob` | `MAX_KEY_CANDIDATES` | other | `usize` | `64` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_REPEATING_KEYLEN` | size | `usize` | `40` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_FOLDED_LEN` | size | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_PASSES` | other | `usize` | `16` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-py-deob/src/hyperion_v2v3.rs` |
| `disrobe-pass-py-deob` | `MAX_XOR_KEY_LEN` | size | `usize` | `4 * 1024` | `crates/disrobe-pass-py-deob/src/hyperion_v2v3.rs` |
| `disrobe-pass-py-deob` | `MAX_CHAIN_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_CODEPOINT` | other | `u32` | `0x0010_FFFF` | `crates/disrobe-pass-py-deob/src/obfuscators/de4py_family.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/obfuxtreme.rs` |
| `disrobe-pass-py-deob` | `MAX_LIFT_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/abyss/lift.rs` |
| `disrobe-pass-py-deob` | `MAX_STORE_TARGET_NESTING` | recursion | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/abyss/lift.rs` |
| `disrobe-pass-py-deob` | `MAX_REINSERT_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/reinsert.rs` |
| `disrobe-pass-py-deob` | `MAX_LOADER_BYTECODE` | size | `usize` | `256` | `crates/disrobe-pass-py-deob/src/obfuscators/pyc_zipper.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/pyobfus.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/pypacker.rs` |
| `disrobe-pass-py-deob` | `MAX_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-py-deob/src/peel.rs` |
| `disrobe-pass-py-deob` | `MAX_TOKEN_CHARS` | other | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-py-deob/src/shuffled_base64.rs` |
| `disrobe-pass-py-deob` | `MAX_OUTER_PASSES` | other | `usize` | `8` | `crates/disrobe-pass-py-deob/src/source_cleanup.rs` |
| `disrobe-pass-py-deob` | `MAX_CANONICAL_NAMES` | other | `usize` | `100_000` | `crates/disrobe-pass-py-deob/src/unrename.rs` |
| `disrobe-pass-py-disasm` | `HEAD_SCAN_LIMIT` | other | `usize` | `32 * 1024` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/brython.rs` |
| `disrobe-pass-py-disasm` | `MAX_NESTING` | recursion | `u8` | `48` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_OBJ_NESTING` | recursion | `u8` | `64` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_TABLE_ITEMS` | count | `usize` | `65_536` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_TABLE_PREALLOC` | other | `usize` | `4096` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_VARINT_BYTES` | size | `usize` | `10` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_NATIVE_VERSION` | other | `u8` | `6` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython_native.rs` |
| `disrobe-pass-py-disasm` | `MAX_OBJ_NESTING` | recursion | `u8` | `64` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython_native.rs` |
| `disrobe-pass-py-disasm` | `MAX_ALT_RUNTIME_INPUT_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs` |
| `disrobe-pass-py-disasm` | `MAX_CODE_UNITS` | other | `usize` | `4096` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/pypy.rs` |
| `disrobe-pass-py-disasm` | `MAX_NESTED_CODE_OBJECTS` | recursion | `usize` | `20_000` | `crates/disrobe-pass-py-disasm/src/chain_detector.rs` |
| `disrobe-pass-py-disasm` | `MAX_RENDER_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_REPR_LONG_DIGITS` | other | `usize` | `512` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_SET_SIMULATION` | other | `usize` | `1 << 20` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_EXTENDED_ARG_PREFIXES` | other | `u32` | `3` | `crates/disrobe-pass-py-disasm/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_NAME_LEN` | size | `usize` | `128` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_RECORDS` | count | `usize` | `65_536` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_SECTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `EXECUTION_BUDGET` | work | `usize` | `200_000` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch_recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_BODY_BYTES` | size | `usize` | `256 * 1024` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch_recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_BODY_BYTES` | size | `usize` | `256 * 1024` | `crates/disrobe-pass-pyarmor/src/bcc/recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_NODES` | count | `usize` | `65_536` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_STEPS` | work | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc/stmt_structure.rs` |
| `disrobe-pass-pyarmor` | `MAX_PACKAGE_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-pyarmor/src/bcc/stub.rs` |
| `disrobe-pass-pyarmor` | `MAX_CALL_TARGETS_SCANNED` | other | `usize` | `1024` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_DISASM_LINES` | other | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_FUNCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_RESOLVED_CALLS` | other | `usize` | `256` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_DYNAMIC_CAPTURE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/dynamic_hook.rs` |
| `disrobe-pass-pyarmor` | `MAX_CODE_OBJECT_DEPTH` | recursion | `u32` | `512` | `crates/disrobe-pass-pyarmor/src/inner_cipher.rs` |
| `disrobe-pass-pyarmor` | `MAX_READ` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/key.rs` |
| `disrobe-pass-pyarmor` | `MAX_CAPTURE_FILE_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_JSON_FILE_BYTES` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_RUNTIME_DIR_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_RUNTIME_FILE_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SCAN_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SYMBOLS` | other | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_CONSTANTS` | other | `usize` | `2048` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_SCAN_BYTES` | size | `usize` | `MAX_IMPORT_SCAN_BYTES` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_BCC_SEGMENTS` | other | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/v8v9.rs` |
| `disrobe-pass-pyfreeze` | `MAX_WALK_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-pyfreeze/src/briefcase/layout.rs` |
| `disrobe-pass-pyfreeze` | `MAX_WALK_ENTRIES` | count | `usize` | `200_000` | `crates/disrobe-pass-pyfreeze/src/briefcase/layout.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ENTRY_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ZIP_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_JSON_MANIFEST_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/common/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PREALLOC` | other | `usize` | `1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/common/read_bounded.rs` |
| `disrobe-pass-pyfreeze` | `MAX_COMMENT` | other | `usize` | `0xFFFF` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `SEARCH_BUDGET` | work | `usize` | `MAX_COMMENT + EOCD_FIXED_LEN + 4` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `MAX_TREE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/lib_tree.rs` |
| `disrobe-pass-pyfreeze` | `MAX_TREE_ENTRIES` | count | `usize` | `200_000` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/lib_tree.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FILESYSTEM_BYTECODE_ATTEMPTS` | size | `usize` | `512` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FREEZE_DIR_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FREEZE_INPUT_BYTES` | size | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_LIBRARY_ZIP_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_RECOVERY_FILE_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PEX_ENTRY` | other | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/pex/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PYTHONSCRIPT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/py2exe/pe.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SECTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SLICE` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_NAME_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_RESOURCE_ENTRIES` | count | `usize` | `1_000_000` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_STRUCTURED_VERSION` | other | `u8` | `3` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_DISASM_BYTES` | size | `usize` | `1 << 20` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyfreeze` | `SAMPLE_INSTRUCTION_CAP` | other | `usize` | `32` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyfreeze` | `MAX_MANIFEST_BYTES` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/shiv/mod.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_COMMENT` | other | `usize` | `u16::MAX as usize` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_NATIVE_SURFACE_BYTES` | size | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/chain_detector.rs` |
| `disrobe-pass-pyinstaller` | `MAX_AGGREGATE_INFLATE` | other | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_ABS` | other | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_RATIO` | other | `u64` | `1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INPUT_FILE_BYTES` | size | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_KEY_MODULE_INFLATE` | other | `u64` | `1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DEEP_ANALYZE_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/native_surface.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CANDIDATE_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CANDIDATE_CONSTS` | other | `usize` | `4096` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CODE_WALK_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DECOMPRESS_ATTEMPTS` | other | `usize` | `1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_RECOVERED_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_AGGREGATE_INFLATE` | other | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_ABS` | other | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_RATIO` | other | `u64` | `1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_PYZ_TOC_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-ruby` | `POOL_PREALLOC_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-ruby/src/mruby/irep.rs` |
| `disrobe-pass-ruby` | `MAX_KEYWORD_PARAMS` | other | `usize` | `31` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_LIFT_DEPTH` | recursion | `u32` | `64` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_LIFT_OUTPUT_PREALLOC` | output | `usize` | `1 << 20` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_REGS` | other | `usize` | `4096` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `OCRA_DECOMPRESS_CAP` | other | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-ruby/src/wrappers.rs` |
| `disrobe-pass-ruby` | `MAX_EXPR_LEN` | size | `usize` | `8192` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_NEST_DEPTH` | recursion | `u32` | `64` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_OPERAND_COUNT` | count | `usize` | `MAX_STACK` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_STACK` | other | `usize` | `8192` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `IBF_ARRAY_LEN_CAP` | size | `usize` | `1_048_576` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_OBJECT_LIST_ENTRY_CAP` | other | `u32` | `1_048_576` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_STRING_LEN_CAP` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-scriptlang` | `MAX_SWF_BYTES` | size | `usize` | `1usize << 26` | `crates/disrobe-pass-scriptlang/src/lang/haxe.rs` |
| `disrobe-pass-scriptlang` | `MAX_ADAPTIVE_BYTES` | size | `usize` | `5usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_COLUMNS` | other | `usize` | `64usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_DESCRIPTION_BYTES` | size | `usize` | `1usize << 16` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_MEMBERS` | count | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_PATH_BYTES` | size | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_TOTAL_PATH_BYTES` | size | `usize` | `64usize << 20` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_VIEW_DEPTH` | recursion | `usize` | `8usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_VIEW_ROWS` | other | `i64` | `1i64 << 20` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_RDS_BYTES` | size | `usize` | `1usize << 29` | `crates/disrobe-pass-scriptlang/src/lang/mod.rs` |
| `disrobe-pass-scriptlang` | `MAX_BYTECODE_TEXT_BYTES` | size | `usize` | `1usize << 20` | `crates/disrobe-pass-scriptlang/src/lang/perl_bytecode.rs` |
| `disrobe-pass-scriptlang` | `MAX_OPS` | work | `usize` | `2_000_000usize` | `crates/disrobe-pass-scriptlang/src/lang/perl_bytecode.rs` |
| `disrobe-pass-scriptlang` | `MAX_MULTICONCAT_SEGMENTS` | other | `usize` | `256` | `crates/disrobe-pass-scriptlang/src/lang/perl_decompile.rs` |
| `disrobe-pass-scriptlang` | `COMPLEX_VECTOR_CAP` | other | `usize` | `1024usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_DEPTH` | recursion | `usize` | `256usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_NODES` | count | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_RVALUE_VECTOR_ENTRIES` | count | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_STRING_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `RAW_VECTOR_CAP` | other | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `ENTRY_PREALLOC_CAP` | other | `u64` | `1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_ENTRIES` | count | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_ENTRY_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_METAKIT_NAME_LEN` | size | `usize` | `255usize` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_TOTAL_ENTRY_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_CHUNK_BYTES` | size | `usize` | `1usize << 22` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_INPUT_BYTES` | size | `usize` | `(MAX_INFLATE_BYTES / 3usize) * 4usize + 4usize` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_BYTES` | size | `usize` | `1usize << 26` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_READ_BYTES` | size | `u64` | `(1u64 << 26) + 1u64` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_LAYERS` | other | `usize` | `16usize` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-shell/src/bash/arith.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | other | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_FOR_INDICES` | other | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_PRINTF_BYTES` | size | `usize` | `65536` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_TAG_LEN` | size | `usize` | `1024` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESS_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | work | `usize` | `12` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_INFLATE` | other | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_OUTPUT` | output | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_REPEAT` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_GZIP_OUTPUT` | output | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEELED_OUTPUT` | output | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | work | `usize` | `32` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_LEXER_INPUT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_SUBSTITUTION_DEPTH` | recursion | `usize` | `256usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | count | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_SOURCE_BYTES` | size | `usize` | `MAX_TOKEN_TEXT_BYTES / 3usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_TEXT_BYTES` | size | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_TOKEN_TEXT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_RECOVERED_OUTPUT` | output | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_TABLE_ENTRIES` | count | `usize` | `200_000` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_PATTERN_LEN` | size | `usize` | `256` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_TEXT_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_PATTERN_LEN` | size | `usize` | `64` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_TEXT_LEN` | size | `usize` | `512` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-pass-shell/src/batch/arith.rs` |
| `disrobe-pass-shell` | `MAX_CIPHERTEXT` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/batch/chain.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_ROUNDS` | work | `usize` | `16` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_LINES` | other | `usize` | `50_000` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_OUTPUT` | output | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_OUTPUT` | output | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/batch/expand.rs` |
| `disrobe-pass-shell` | `MAX_FOR_ITERATIONS` | work | `usize` | `4096` | `crates/disrobe-pass-shell/src/batch/forloop.rs` |
| `disrobe-pass-shell` | `MAX_REVERSE_ADDED_BYTES` | size | `usize` | `expand::MAX_EXPANSION_OUTPUT` | `crates/disrobe-pass-shell/src/batch/mod.rs` |
| `disrobe-pass-shell` | `MAX_DECODE_LEN` | size | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/batch/payload.rs` |
| `disrobe-pass-shell` | `MAX_POWERSHELL_LAYER_ROUNDS` | work | `usize` | `16` | `crates/disrobe-pass-shell/src/chain_detector.rs` |
| `disrobe-pass-shell` | `MAX_SCRIPT_SCAN_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/detect.rs` |
| `disrobe-pass-shell` | `MAX_ACTION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DICT_ENTRIES` | count | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DOCUMENT_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FILTER_CHAIN` | other | `usize` | `8` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDINGS` | other | `usize` | `8192` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDING_TEXT` | other | `usize` | `1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_LZW_CODES` | other | `usize` | `4096` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_TREE_NODES` | count | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECT_DEPTH` | recursion | `usize` | `96` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJSTM_OBJECTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_PREDICTOR_COLUMNS` | other | `usize` | `250_000` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_RESOLVE_STEPS` | work | `usize` | `256` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STREAM_OUTPUT` | output | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CONCAT` | other | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_OUTPUT` | output | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_WALK_NODES` | count | `usize` | `1 << 18` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_CHAIN` | other | `usize` | `1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_ENTRIES` | count | `usize` | `1 << 21` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_FIELD_WIDTH` | other | `usize` | `8` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `STATIC_EVAL_DEPTH_CAP` | recursion | `usize` | `2` | `crates/disrobe-pass-shell/src/policy.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/chameleon.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_obfuscation.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | other | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_obfuscation.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_stealth.rs` |
| `disrobe-pass-shell` | `MAX_LEXER_INPUT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | count | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_SOURCE_BYTES` | size | `usize` | `MAX_TOKEN_TEXT_BYTES / 3usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_TEXT_BYTES` | size | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_TOKEN_TEXT_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/powerhell.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/psobf.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | other | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/psobf.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_RESERVE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_ENTRY_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_ENTRY_RESERVE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_MODULE_REFS` | other | `usize` | `512` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_MODULE_STREAM_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `PROJECT_INFORMATION_RECORD_LIMIT` | other | `usize` | `32` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_CALL_ARGS` | other | `usize` | `256` | `crates/disrobe-pass-shell/src/vba/pcode_lift.rs` |
| `disrobe-pass-shell` | `MAX_CFB_ENTRIES` | count | `usize` | `8192` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_RESERVE` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_FUNC_ARG_CHAIN` | other | `usize` | `4096` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_OVBA_DECOMPRESSED_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_TYPE_DESCRIPTOR_DEPTH` | recursion | `usize` | `8` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_VALUES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_EXTERN_NAMES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORDS` | count | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORD_BODY` | other | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RGCE` | other | `usize` | `512 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_SHEETS` | other | `usize` | `4096` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_STACK_DEPTH` | recursion | `usize` | `4096` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CHARS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_TOKENS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_WORKBOOK_BYTES` | work | `u64` | `128 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_XTI` | other | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRIES` | count | `usize` | `8192` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRY_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-sourcedefender` | `MAX_ARMORED_INPUT_BYTES` | size | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_ARMORED_OUTPUT_BYTES` | output | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_HEX_INPUT_BYTES` | size | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_SOURCEDEFENDER_INFLATE` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_BINARY_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_CONTAINER_ITEMS` | count | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_ENVELOPE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_STRING_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_ARMORED_CIPHERTEXT_CHARS` | other | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_FRAME_LINES` | other | `usize` | `32_768` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_FRAME_TEXT_BYTES` | size | `usize` | `MAX_PYE_ARMORED_CIPHERTEXT_CHARS + 64 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_GCM_AAD_BYTES` | size | `u64` | `(1u64 << 61) - 1` | `crates/disrobe-pass-sourcedefender/src/gcm_tag.rs` |
| `disrobe-pass-sourcedefender` | `MAX_GCM_CIPHERTEXT_BYTES` | size | `u64` | `(1u64 << 36) - 32` | `crates/disrobe-pass-sourcedefender/src/gcm_tag.rs` |
| `disrobe-pass-sourcedefender` | `MAX_INLINED_BLOCKS` | other | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/inlined.rs` |
| `disrobe-pass-sourcedefender` | `MAX_INLINED_SOURCE_BYTES` | size | `usize` | `MAX_ARMORED_INPUT_BYTES` | `crates/disrobe-pass-sourcedefender/src/inlined.rs` |
| `disrobe-pass-sourcedefender` | `MAX_FILENAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/kdf.rs` |
| `disrobe-pass-sourcedefender` | `MAX_CONTAINER_INPUT_BYTES` | size | `usize` | `MAX_HEX_INPUT_BYTES + 64 * 1024` | `crates/disrobe-pass-sourcedefender/src/layered.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MODERN_BODY_LINES` | other | `usize` | `32_768` | `crates/disrobe-pass-sourcedefender/src/layered.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MODERN_GCM_BODY_BYTES` | size | `usize` | `MAX_HEX_INPUT_BYTES / 2` | `crates/disrobe-pass-sourcedefender/src/modern_gcm.rs` |
| `disrobe-pass-sourcedefender` | `MAX_CODE_OBJECT_SUMMARIES` | other | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MARSHAL_PAYLOAD_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MARSHAL_TRAVERSAL_OBJECTS` | other | `usize` | `131_072` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_NESTED_CODE_DEPTH` | recursion | `usize` | `32` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAIN_CHILDREN` | other | `usize` | `256` | `crates/disrobe-pass-swift-objc/src/chain_detector.rs` |
| `disrobe-pass-swift-objc` | `CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT` | other | `u32` | `0x1005` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_BLOB_LEN` | size | `u32` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_IDENTIFIER_LEN` | size | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOT_COUNT` | count | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_VERIFIED_PAGES` | other | `u32` | `65_536` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_DEPTH` | recursion | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_NODES` | count | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPEAT_COUNT` | count | `u32` | `2048` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOL_LEN` | size | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_IMAGES` | other | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_IMAGE_OUTPUT_BYTES` | output | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_LOCAL_SYMBOL_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_MAPPINGS` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_RECORDED_AUTH_POINTERS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOTAL_OUTPUT_BYTES` | output | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_INDIRECT_SYMBOLS` | other | `usize` | `8_000_000` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINKEDIT_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINKEDIT_SYMBOLS` | other | `usize` | `4_000_000` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_PAGE_EXTRAS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLIDE_PAGES` | other | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_V1_ENTRY_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_FAMILY_BYTES` | size | `u64` | `12 * 1024 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache/subcache.rs` |
| `disrobe-pass-swift-objc` | `MAX_SUB_CACHES` | other | `usize` | `128` | `crates/disrobe-pass-swift-objc/src/dyld_cache/subcache.rs` |
| `disrobe-pass-swift-objc` | `MAX_ENTRY_BYTES` | size | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `MAX_PREALLOC` | other | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `MAX_ZIP_ENTRY_COUNT` | count | `usize` | `65_536` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `FAT_ARCH_COUNT_CAP` | count | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_DYLIBS` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NAME` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NODES` | count | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_STARTS` | other | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_INDIRECT_SYMBOLS` | other | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_RPATHS` | other | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOLS` | other | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOL_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_BYTES` | size | `u64` | `256 * 1024` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_INSTRUCTIONS_PER_FUNCTION` | other | `usize` | `8192` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINES_PER_FUNCTION` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LISTED_FUNCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_NIR_SYMBOLS` | other | `usize` | `8192` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_TYPES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_SELECTOR_HINT_WORK` | work | `u64` | `4_000_000` | `crates/disrobe-pass-swift-objc/src/objc.rs` |
| `disrobe-pass-swift-objc` | `MAX_BIND_OPS` | work | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CALL_SITES` | other | `usize` | `1 << 14` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_DEPTH` | recursion | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_STEPS` | work | `usize` | `1 << 13` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_IMPORTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_PAGES` | other | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_SEGMENTS` | other | `usize` | `1 << 12` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_MOVE_HOPS` | work | `usize` | `8` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOTS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_STUB_ENTRIES` | count | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOTAL_BINDS` | other | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CATEGORIES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CLASSES` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_LIST_COUNT` | count | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOLS` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REFS` | other | `usize` | `1 << 12` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_EMBEDDED_IMAGES` | other | `usize` | `256` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_INSTALL_NAMES` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_ZIP_ENTRY` | other | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_DESCRIPTORS` | other | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_FIELDS_PER_TYPE` | other | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | other | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | other | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REQUIREMENTS` | other | `usize` | `1 << 14` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_TYPE_RECORDS` | count | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_ARRAY_LEN` | size | `u64` | `1 << 26` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_VBR_PIECES` | other | `u32` | `16` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOOLCHAIN_HINTS` | other | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/toolchain.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINKS` | other | `usize` | `2_048` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINKS_JSON_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINK_STRING_BYTES` | size | `usize` | `4_096` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_NAME_PROPAGATION_WORK` | work | `usize` | `MAX_BOUNDARY_NAME_SEEDS * MAX_BOUNDARY_LINKS * 4` | `crates/disrobe-pass-wasm-deob/src/boundary_name_propagation.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_NAME_SEEDS` | other | `usize` | `256` | `crates/disrobe-pass-wasm-deob/src/boundary_name_propagation.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BODY_OPS` | work | `usize` | `2_000_000` | `crates/disrobe-pass-wasm-deob/src/fingerprint.rs` |
| `disrobe-pass-wasm-deob` | `MAX_ORIGIN_DEPTH` | recursion | `u32` | `1024` | `crates/disrobe-pass-wasm-deob/src/lib.rs` |
| `disrobe-pass-wasm-deob` | `MAX_RENDER_INDENT` | output | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/lib.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_EXPORT_NAME_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_MODULE_EXPORTS` | other | `usize` | `65_536` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_MODULE_FUNCTIONS` | other | `usize` | `4096` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `DATA_ESCAPE_PREALLOC_CAP` | other | `usize` | `1 << 20` | `crates/disrobe-pass-wasm-deob/src/lift_module_faithful.rs` |
| `disrobe-pass-wasm-deob` | `MAX_SYNTHETIC_STRUCT_FIELDS` | other | `u32` | `4096` | `crates/disrobe-pass-wasm-deob/src/lift_wat.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TREE_NODES` | count | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/obfuscators/mba.rs` |
| `disrobe-pass-wasm-deob` | `MAX_ITERATIONS` | work | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/obfuscators/tigress/unflatten.rs` |
| `disrobe-pass-wasm-deob` | `FUEL_BUDGET` | work | `u64` | `100_000_000` | `crates/disrobe-pass-wasm-deob/src/obfuscators/wasmixer/sandbox_unwrap.rs` |
| `disrobe-pass-wasm-deob` | `TABLE_ELEMENT_LIMIT` | other | `usize` | `1 << 16` | `crates/disrobe-pass-wasm-deob/src/obfuscators/wasmixer/sandbox_unwrap.rs` |
| `disrobe-pass-wasm-deob` | `MAX_EXPR_NODES` | count | `usize` | `96` | `crates/disrobe-pass-wasm-deob/src/recover.rs` |
| `disrobe-pass-wasm-deob` | `MAX_FOLD_INSTRUCTIONS` | other | `usize` | `1 << 21` | `crates/disrobe-pass-wasm-deob/src/recover.rs` |
| `disrobe-pass-wasm-deob` | `NESTED_SEQ_LIMIT` | recursion | `usize` | `4096` | `crates/disrobe-pass-wasm-deob/src/recover/cff.rs` |
| `disrobe-pass-wasm-deob` | `MAX_GUARD_LEN` | size | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/recover/opaque.rs` |
| `disrobe-pass-wasm-deob` | `MAX_CALL_DEPTH` | recursion | `u32` | `8` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_MODULE_STEPS` | work | `u64` | `50_000_000` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_STEPS` | work | `u64` | `2_000_000` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_VALUE_STACK` | other | `usize` | `4_096` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MULTI_EXIT_LIMIT` | other | `usize` | `16` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `NODE_LIMIT` | other | `usize` | `512` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `STATE_EXPRESSION_LIMIT` | other | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `TRANSITION_INSTRUCTION_LIMIT` | other | `usize` | `512` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_RESOURCES` | other | `usize` | `MAX_BOUNDARY_LINKS` | `crates/disrobe-pass-wasm-deob/src/signature.rs` |
| `disrobe-pass-wasm-deob` | `MAX_FUNCTION_LOCALS` | other | `usize` | `100_000` | `crates/disrobe-pass-wasm-deob/src/signature.rs` |
| `disrobe-pass-webview` | `COMPRESSED_SAMPLE_CAP` | other | `usize` | `4096` | `crates/disrobe-pass-webview/src/decompress.rs` |
| `disrobe-pass-webview` | `MAX_EVIDENCE_MARKERS` | other | `usize` | `8` | `crates/disrobe-pass-webview/src/detect.rs` |
| `disrobe-pass-webview` | `MAX_ENTRY_PATH_BYTES` | size | `usize` | `4096` | `crates/disrobe-pass-webview/src/electron.rs` |
| `disrobe-pass-webview` | `MAX_EXTENSION_LEN` | size | `usize` | `16` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_HASH_HAMMING` | other | `usize` | `1` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_PATH_LEN` | size | `usize` | `4096` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_RECORD_BLOB` | other | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_SCAN_RECORDS` | count | `usize` | `2_000_000` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_UNREADABLE_GAP` | other | `usize` | `2` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_FAT_SLICES` | other | `usize` | `64` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_OVERLAP_WALK` | other | `usize` | `64` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_SPANS` | other | `usize` | `4096` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILES_SCANNED` | count | `usize` | `16_384` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILE_BYTES` | size | `u64` | `1024 * 1024` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_PACKED_PAIRS` | other | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_RECOMPILE_PYC` | other | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_FILES` | count | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_TOML_BYTES` | size | `u64` | `1024 * 1024` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_NATIVE_MATCH_INPUT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-playground/src/native_match.rs` |
| `disrobe-playground` | `MAX_SOURCE_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-playground/src/wasm.rs` |
| `disrobe-plugin-host` | `DEFAULT_FUEL_BUDGET` | work | `u64` | `50_000_000` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_FUEL_BUDGET` | work | `u64` | `1_000_000_000` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_MEMORY_CAP_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_WALL_DEADLINE` | other | `Duration` | `Duration::from_secs(30)` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_WASM_MODULE_BYTES` | size | `usize` | `DEFAULT_MEMORY_CAP_BYTES` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_SIGNATURE_BYTES` | size | `usize` | `16 * 1024` | `crates/disrobe-plugin-loader/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_SIGNED_COMPONENT_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-plugin-loader/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_CAPABILITIES` | other | `usize` | `128` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_CAPABILITY_BYTES` | size | `usize` | `256` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_NAME_BYTES` | size | `usize` | `128` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_TOML_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_VERSION_BYTES` | size | `usize` | `64` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-prowl` | `MAX_CONFIG_BYTES` | size | `u64` | `1 << 20` | `crates/disrobe-prowl/src/keys.rs` |
| `disrobe-py-marshal` | `BYTE_BUDGET` | work | `u64` | `1024 * 1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `BYTE_BUDGET` | work | `u64` | `512 * 1024 * 1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_COLLECTION_ITEMS` | count | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_DICT_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_INTERNED_STRINGS` | other | `usize` | `1 << 13` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_INTERNED_STRINGS` | other | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_LEN` | size | `u32` | `1 << 28` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_LONG_DIGITS` | other | `u32` | `1 << 24` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_OBJECT_PREALLOC` | other | `usize` | `1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_REFS` | other | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_TRACE_ENTRIES` | count | `usize` | `1 << 12` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_TRACE_ENTRIES` | count | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `NODE_BUDGET` | work | `u64` | `8_000_000` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-pyarmor-cextract` | `MAX_CAPTURED_CODE_OBJECTS` | other | `usize` | `65_536` | `crates/disrobe-pyarmor-cextract/src/capture.rs` |
| `disrobe-pyarmor-cextract` | `MAX_CAPTURED_PYC_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pyarmor-cextract/src/capture.rs` |
| `disrobe-pyarmor-cextract` | `MAX_PROLOGUE_SCAN` | other | `usize` | `32` | `crates/disrobe-pyarmor-cextract/src/hotpatch/x86_disasm.rs` |
| `disrobe-pyarmor-cextract` | `MAX_MARSHAL_BODY_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pyarmor-cextract/src/marshal_writer.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_CAPTURED` | other | `usize` | `262_144` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_DRAIN_OUTPUTS` | output | `usize` | `65_536` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_DRAIN_OUTPUT_BYTES` | output | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_MARSHALLED_CODE_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-python` | `MAX_CONTAINER_INPUT_BYTES` | size | `usize` | `256 * 1024 * 1024` | `crates/disrobe-python/src/container.rs` |
| `disrobe-python` | `MAX_PY_JSON_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-python/src/convert.rs` |
| `disrobe-python` | `MAX_PY_JSON_ITEMS` | count | `usize` | `1_000_000` | `crates/disrobe-python/src/convert.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_EDGES` | other | `usize` | `65_536` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_NODES` | count | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_IMPLEMENTOR_MATCHES` | other | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MALFORMED_DESCRIPTOR_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MALFORMED_DESCRIPTOR_DIAGNOSTICS` | other | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MISSING_DEFINITION_DIAGNOSTICS` | other | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_BYTES` | size | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_DEPTH` | recursion | `usize` | `256` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_ELEMENTS` | other | `usize` | `65_536` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_QUERY_ARGUMENT_BYTES` | size | `usize` | `4 * 1024` | `crates/disrobe-query/src/parse.rs` |
| `disrobe-query` | `MAX_QUERY_BYTES` | size | `usize` | `8 * 1024` | `crates/disrobe-query/src/parse.rs` |
| `disrobe-semdiff` | `MAX_LINEAGE_VARIANTS` | other | `usize` | `32` | `crates/disrobe-semdiff/src/lineage.rs` |
| `disrobe-semdiff` | `MAX_FUNCTIONS_PER_MODULE` | other | `usize` | `50_000` | `crates/disrobe-semdiff/src/structural.rs` |
| `disrobe-semdiff` | `MAX_PROPAGATION_ROUNDS` | work | `u32` | `8` | `crates/disrobe-semdiff/src/structural.rs` |
| `disrobe-semdiff` | `MAX_ADDRESS_PEEL_STEPS` | work | `u32` | `32` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_BLOCKS` | other | `usize` | `128` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_DEPTH` | recursion | `u32` | `128` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_INSTRUCTIONS` | other | `usize` | `4096` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_MEMORY_CELLS` | other | `usize` | `256` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_NODES` | count | `usize` | `4096` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_OUTPUTS` | output | `usize` | `64` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-similarity` | `REFINEMENT_ROUND_CAP` | work | `usize` | `16` | `crates/disrobe-similarity/src/fingerprint.rs` |
| `disrobe-similarity` | `PROPAGATION_ROUND_CAP` | work | `usize` | `64` | `crates/disrobe-similarity/src/matcher/propagation.rs` |
| `disrobe-similarity` | `DEFAULT_LISTING_LIMIT` | other | `usize` | `25` | `crates/disrobe-similarity/src/presentation.rs` |
| `disrobe-sleigh` | `MAX_DECODE_CONSTRUCTOR_ATTEMPTS` | other | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_EVALUATION_DEPTH` | recursion | `usize` | `128` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_FIXED_BITS_MEMO_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_PATTERN_CLAUSES` | other | `usize` | `4_096` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_CLAUSES` | other | `usize` | `4_194_304` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CONSTRUCTORS` | other | `usize` | `4_096` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `UNSUPPORTED_ENCODING_CAPTURE_LIMIT` | other | `usize` | `24` | `crates/disrobe-sleigh/src/lifter/riscv.rs` |
| `disrobe-sleigh` | `MAX_CONDITION_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-sleigh/src/preprocessor.rs` |
| `disrobe-sleigh` | `MAX_ITEM_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_PATTERN_NESTING` | recursion | `usize` | `64` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_SOURCE_BYTES` | size | `usize` | `4 * 1024 * 1024` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_TOKEN_COUNT` | count | `usize` | `500_000` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-taint` | `CALL_EDGE_TARGET_CAP` | other | `usize` | `4_096` | `crates/disrobe-taint/src/callgraph.rs` |
| `disrobe-taint` | `MAX_INTERNED` | other | `u16` | `63` | `crates/disrobe-taint/src/config.rs` |
| `disrobe-taint` | `MAX_OUT_ARGUMENTS_PER_SOURCE` | other | `usize` | `32` | `crates/disrobe-taint/src/config.rs` |
| `disrobe-taint` | `MAX_PATH_STEPS` | work | `usize` | `128` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-taint` | `MAX_RECORDED_UNRESOLVED_CALLS` | other | `usize` | `4096` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-testkit` | `MAX_OPTIONAL_LIST_BYTES` | size | `u64` | `256 * 1024` | `crates/disrobe-testkit/src/prerequisite.rs` |
| `disrobe-testkit` | `MAX_RECORD_NAME` | other | `usize` | `160` | `crates/disrobe-testkit/src/prerequisite.rs` |
| `disrobe-testkit` | `MAX_CORPUS_ENTRY_BYTES` | size | `usize` | `MAX_WIRE_CASE_BYTES / 4` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-testkit` | `MAX_ENTRY_NAME_BYTES` | size | `usize` | `4096` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-testkit` | `MAX_WIRE_CASE_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-tool-process` | `MAX_GROUP_MEMBERS` | count | `usize` | `1024` | `crates/disrobe-tool-process/src/unix.rs` |
| `disrobe-tool-process` | `MAX_COMMAND_LINE_UNITS` | other | `usize` | `32_767` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_BLOCK_UNITS` | other | `usize` | `1_048_576` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_INPUT_ENTRIES` | count | `usize` | `1_048_576` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_STRING_UNITS` | other | `usize` | `32_767` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_NORMAL_PROGRAM_PATH_UNITS` | other | `usize` | `259` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_RETAINED_ENVIRONMENT_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-typerec` | `MAX_COPY_DEPTH` | recursion | `u8` | `8` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MAX_THUNK_INSNS` | other | `usize` | `8` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MIN_SOLVE_BUDGET` | work | `usize` | `4096` | `crates/disrobe-typerec/src/constraint.rs` |
| `disrobe-typerec` | `MAX_DECODE_INSNS` | other | `usize` | `1 << 16` | `crates/disrobe-typerec/src/decode.rs` |
| `disrobe-typerec` | `MAX_DIE_VISITS` | other | `usize` | `1 << 20` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_FIELDS` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_PARAMS` | other | `usize` | `64` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_TYPE_DEPTH` | recursion | `u8` | `16` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_UNITS` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_VARS_PER_FUNCTION` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_EXPRESSION_OPERATIONS` | other | `usize` | `64` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_LOCATION_LIST_ENTRIES` | count | `usize` | `512` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_PROLOGUE_INSTRUCTIONS` | other | `usize` | `32` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_DESCRIPTORS` | other | `usize` | `1 << 14` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_ENTRIES` | count | `usize` | `1 << 21` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_THUNKS` | other | `u64` | `1 << 20` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_HEAP_BLOCKS` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_ROUNDS` | work | `usize` | `1 << 3` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_SLOTS` | other | `usize` | `1 << 6` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_REGION_CELLS` | other | `usize` | `1 << 8` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_STACK_SLOTS` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SITES` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SYMBOLS` | other | `usize` | `1 << 20` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_RELOC_TARGETS` | other | `usize` | `1 << 16` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_SECTIONS` | other | `usize` | `1 << 12` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_THUNK_SCAN` | other | `usize` | `1 << 24` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-validator` | `MAX_CORPUS_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-validator` | `MAX_CORPUS_ENTRIES` | count | `usize` | `65_536` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-validator` | `MAX_HASH_DEPTH` | recursion | `usize` | `64` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_HASH_FILES` | count | `usize` | `65_536` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_HASH_FILE_BYTES` | size | `u64` | `64 * 1024 * 1024` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_SAMPLE_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-vulnmatch` | `MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE` | other | `usize` | `16` | `crates/disrobe-vulnmatch/src/adapters.rs` |
| `disrobe-vulnmatch` | `MAX_CONSTRAINT_BYTES` | size | `usize` | `8 * 1024` | `crates/disrobe-vulnmatch/src/constraint.rs` |
| `disrobe-vulnmatch` | `MAX_CONSTRAINT_NODES` | count | `usize` | `256` | `crates/disrobe-vulnmatch/src/constraint.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_INPUTS` | other | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_OUTPUT_BYTES` | output | `usize` | `32 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_RESULTS` | other | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_TEXT_BYTES` | size | `usize` | `8 * 1024` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_WORK` | work | `usize` | `1_048_576` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_AFFECTED` | other | `usize` | `4_096` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EVALUATION_WORK` | work | `usize` | `2_000_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EVENTS` | other | `usize` | `512` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EXPLICIT_VERSIONS` | other | `usize` | `8_192` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_FIELD_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_FINDINGS` | other | `usize` | `10_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_ISSUES` | other | `usize` | `10_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_LINE_BYTES` | size | `usize` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_OSV_BYTES` | size | `u64` | `16 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_OS_RELEASE_BYTES` | size | `u64` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGES` | other | `usize` | `100_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_FIELD_BYTES` | size | `usize` | `4 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_RANGES` | other | `usize` | `128` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_STANZA_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_STATUS_BYTES` | size | `u64` | `256 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_URL_INPUT_BYTES` | size | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/package_url.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_URL_OUTPUT_BYTES` | output | `usize` | `56 * 1024` | `crates/disrobe-vulnmatch/src/package_url.rs` |
| `disrobe-vulnmatch` | `MAX_VERSION_BYTES` | size | `usize` | `4 * 1024` | `crates/disrobe-vulnmatch/src/version.rs` |
| `disrobe-vulnmatch` | `MAX_VERSION_PARTS` | other | `usize` | `256` | `crates/disrobe-vulnmatch/src/version.rs` |
| `disrobe-wasm` | `MAX_ENTROPY_BLOCKS` | other | `usize` | `4096` | `crates/disrobe-wasm/src/entry.rs` |
| `disrobe-wasm` | `MAX_DECODED_BYTES` | size | `u64` | `128 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_ENTRY_BYTES` | size | `u64` | `32 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_MANIFEST_BYTES` | size | `u64` | `2 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_INSTRUCTIONS` | other | `usize` | `65_536` | `crates/disrobe-wasm/src/entry/dotnet.rs` |
| `disrobe-wasm` | `MAX_METHOD_INSTRUCTIONS` | other | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/dotnet.rs` |
| `disrobe-wasm` | `MAX_IMAGE_NAMES` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_INPUT` | other | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_RECORDS` | count | `usize` | `131_072` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_SYMBOLS` | other | `u64` | `65_536` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_TYPES` | other | `u64` | `16_384` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_CONSTANT_POOL_SLOTS` | other | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_FIELDS` | other | `usize` | `4096` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_INSTRUCTIONS` | other | `usize` | `65_536` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHODS` | other | `usize` | `1024` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHOD_EDGES` | other | `usize` | `2048` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHOD_INSTRUCTIONS` | other | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_ENTRIES` | count | `usize` | `4096` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_MEMBER_BYTES` | size | `usize` | `32 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_NAME_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_METADATA_BYTES` | size | `usize` | `8 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_RUNTIME_BYTES` | size | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_WRAPPER_BYTES` | size | `usize` | `1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_GUEST_ALLOC` | other | `usize` | `1 << 30` | `crates/disrobe-wasm/src/lib.rs` |
| `disrobe-wasm` | `MAX_INPUT_BYTES` | size | `usize` | `64 * 1024 * 1024` | `crates/disrobe-wasm/src/lib.rs` |
| `disrobe-wasm` | `MAX_RESULT_PAYLOAD` | other | `usize` | `64 * 1024 * 1024` | `crates/disrobe-wasm/src/lib.rs` |
