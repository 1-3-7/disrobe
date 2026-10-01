# Input bounds

Every parser treats its input as hostile. Counts, sizes, recursion depth, work and output are capped by named constants. `cargo xtask regen` generates this page from every module-level constant in `crates/*/src` whose name starts with `MAX_` or ends with `_LIMIT`, `_BUDGET` or `_CAP`, and `cargo xtask regen --check` fails when it is stale. The kind column is derived from the constant name.

The exceeded column states what happens when input goes past the bound. It comes from a syntax-tree scan of the defining crate's non-test sources: each read of the constant is traced through comparisons, local bindings, struct fields, same-crate function parameters, function results and derived constants to the branch taken when the bound is exceeded. The column reports the strongest outcome over all reads, in this order:

- **error**: a typed error is returned. The column names the error variant and its `DR-` diagnostic code when the variant carries one; `untyped` marks a string error.
- **recorded**: the input is truncated or refused and a flag or refusal record says so.
- **panic**: an assertion or panic fires.
- **delegated**: the bound is passed to a function the scan could not follow.
- **silent**: a loop stops, a value is clamped or work is skipped with no error and no record.
- **unclassified**: the scan found a read but could not attribute an outcome to it.
- **allocation**: the bound only sizes a buffer or a capacity reservation.
- **unused**: the defining crate never reads the constant.

The scan does not resolve types or trait dispatch, so an outcome names the construct it found rather than proving the behaviour.

2181 bounds (count 215, other 1024, output 64, recursion 219, size 479, work 180).

Exceeded: error 884, recorded 185, panic 0, delegated 49, silent 1005, unclassified 17, allocation 33, unused 8.

| Crate | Constant | Kind | Exceeded | Type | Value | File |
| --- | --- | --- | --- | --- | --- | --- |
| `disrobe-binfmt` | `SCAN_HIT_CAP` | other | silent: `while` condition in `scan_magics` | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `STREAM_DECODE_CAP` | other | silent: `.take()` in `decode_validate`; `return` in `bzip2_exact_extent`; `return` in `gzip_exact_extent`; 1 more | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `TOTAL_WORK_CHUNK_CAP` | work | recorded: flag `exhausted` | `usize` | `1 << 16` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `MAX_MEMBER_COUNT` | count | error: `CoreError::PassFailure` (DR-CORE-0003); untyped `format!` | `usize` | `100_000` | `crates/disrobe-binfmt/src/chain_detector.rs` |
| `disrobe-binfmt` | `MAX_STREAM_BYTES` | size | error: `CoreError::PassFailure` (DR-CORE-0003); untyped `format!` | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/chain_detector.rs` |
| `disrobe-binfmt` | `MAX_OMAP_ENTRIES` | count | silent: `break` in `omap_leaf_mappings`; `for` range in `walk_fs_tree_leaf` | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/apfs.rs` |
| `disrobe-binfmt` | `MAX_BASIC_HEADER` | other | error: `Error::Arj` (DR-BINFMT-0054) | `usize` | `2600` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `MAX_EXT_HEADER_BLOCKS` | other | error: `Error::Arj` (DR-BINFMT-0054) | `usize` | `256` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `MAX_EXT_HEADER_BYTES` | size | error: `Error::Arj` (DR-BINFMT-0054) | `usize` | `8 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/arj.rs` |
| `disrobe-binfmt` | `LZMA_ALONE_DETECT_DICT_LIMIT` | other | unclassified: stored in `memlimit` with no read found | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/bare_stream.rs` |
| `disrobe-binfmt` | `MAX_ASSEMBLIES` | other | error: `blazor_err()` | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_BOOT_MANIFEST_LEN` | size | error: `Error::QuotaExceeded` (DR-BINFMT-0009); `blazor_err()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_WASM_DATA_SEGMENTS` | other | error: `blazor_err()` | `u64` | `1024` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_WEBCIL_SECTIONS` | other | error: `blazor_err()` | `usize` | `96` | `crates/disrobe-binfmt/src/containers/blazor_webcil.rs` |
| `disrobe-binfmt` | `MAX_REPLAY_FILES` | count | recorded: `notes` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/btrfs_send.rs` |
| `disrobe-binfmt` | `BACK_SCAN_LIMIT` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `8 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/bun.rs` |
| `disrobe-binfmt` | `MAX_MODULES` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/bun.rs` |
| `disrobe-binfmt` | `MAX_NAME_BYTES` | size | error: `Error::Cab` (DR-BINFMT-0018) | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cab.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_DEPTH` | recursion | silent: `break` in `walk_cramfs` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_FILES` | count | silent: `break` in `walk_cramfs` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_DOC_LEN` | size | silent: `.min()` clamp in `read_c_string`; `.take()` in `find_doc_starting_with` | `usize` | `16384` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_FILETABLE_ENTRIES` | count | silent: `for` range in `recover_source_files` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_LEN` | size | silent: `return` in `module_name_from_init`; no action in `locate_module_init` | `usize` | `512` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_NAME_LEN` | size | silent: `.min()` clamp in `read_c_string`; `return` in `is_valid_identifier`; skipped in `scan_source_strings` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_SOURCE_FILES` | count | silent: skipped in `push_unique` | `usize` | `512` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_RECORDS` | count | silent: `return` in `recover_structural` | `usize` | `65536` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_SCAN_ATTEMPTS` | other | silent: `return` in `recover_structural` | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | silent: `while` condition in `walk_method_table` | `usize` | `8192` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STUB_BYTES` | size | silent: `return` in `render_cython_stub` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/cython_stub.rs` |
| `disrobe-binfmt` | `MAX_MAGIC_CANDIDATES` | other | silent: `.take()` in `magic_offsets` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/deno_compile.rs` |
| `disrobe-binfmt` | `MAX_MEDIA_TYPE` | other | error: `malformed()` | `u8` | `20` | `crates/disrobe-binfmt/src/containers/deno_compile.rs` |
| `disrobe-binfmt` | `MAX_CHUNKS` | other | silent: `return` in `parse_mish_chunks` | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `MAX_CHUNK_PREALLOC` | other | allocation: `with_capacity` in `adc_decompress`; `with_capacity` in `new`; `with_capacity` in `read_limited_chunk` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `MAX_IMAGE_BYTES` | size | error: `Error::Decompression` (DR-BINFMT-0007); `dmg_chunk_cap_error()`; untyped `format!` | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `DEPS_JSON_PARSE_CAP` | other | error: `Error::QuotaExceeded` (DR-BINFMT-0009) | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_EMBEDDED_FILES` | count | error: `bundle_err()` | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_PATH_LEN` | size | error: untyped `format!` | `usize` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_PLAUSIBLE_MAJOR_VERSION` | other | silent: `return` in `header_is_plausible` | `u32` | `64` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `MAX_MAGIC_CANDIDATES` | other | error: `unsupported()` | `usize` | `64` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `MAX_NAME_UNITS` | other | error: `unsupported()` | `usize` | `2048` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `NESTING_LIMIT` | recursion | error: `Error::UnsupportedContainer` (DR-BINFMT-0012) | `&str` | `"Enigma Virtual Box directory nesting exceeds the supported depth"` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `PE_SECTION_LIMIT` | other | silent: `return` in `pe_has_enigma_sections` | `usize` | `96` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | error: `Error::Erofs` (DR-BINFMT-0048) | `usize` | `256` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | error: `Error::Erofs` (DR-BINFMT-0048) | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_FULL_INDEX_ENTRIES` | count | error: `Error::Erofs` (DR-BINFMT-0048) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_LZMA_DICTIONARY` | other | error: `Error::Erofs` (DR-BINFMT-0048) | `u32` | `8 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_PCLUSTER_DECODED` | other | error: `Error::Erofs` (DR-BINFMT-0048) | `usize` | `12 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_PCLUSTER_ENCODED` | other | error: `Error::Erofs` (DR-BINFMT-0048) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/erofs.rs` |
| `disrobe-binfmt` | `MAX_CANDIDATE_OFFSETS` | other | silent: `.truncate()` in `candidate_offsets`; `break` in `scan_magic_offsets` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/eszip.rs` |
| `disrobe-binfmt` | `MAX_EXT4_DEPTH` | recursion | recorded: `refusals` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_EXT4_FILES` | count | recorded: `refusals` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_EXTENT_DEPTH` | recursion | error: `Error::Ext4` (DR-BINFMT-0040) | `usize` | `8` | `crates/disrobe-binfmt/src/containers/ext4.rs` |
| `disrobe-binfmt` | `MAX_DIR_ENTRIES` | count | unclassified: stored in `entries_budget` with no read found | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/fat.rs` |
| `disrobe-binfmt` | `MAX_DIR_RECURSION` | recursion | silent: `return` in `walk_dir` | `u32` | `64` | `crates/disrobe-binfmt/src/containers/fat.rs` |
| `disrobe-binfmt` | `MAX_PART_OUTPUT` | output | silent: `.take()` in `decompress_xz` | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_STATIC_DELTA_PART_BYTES` | size | delegated: `ostree::read_file_bounded()?` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_STATIC_DELTA_SUPERBLOCK_BYTES` | size | delegated: `ostree::read_file_bounded()?` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | silent: `return` in `walk_leaf_records` | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_FORK_EXTENTS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 16` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_NODES` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `5_000_000` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_OVERFLOW_RECORDS` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_INNO_FILE_NAME_BYTES` | size | error: `inno_err()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_HEADER_STRING` | other | silent: `return` in `read_inno_string`; `return` in `skip_inno_string` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_OUTPUT` | output | error: `Error::Decompression` (DR-BINFMT-0007); `dmg_chunk_cap_error()`; `inno_err()`; 2 more | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_TABLE_ENTRIES` | count | error: `inno_err()`; untyped `format!` | `u32` | `1 << 20` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_INNO_TOTAL_ENTRIES` | count | error: `inno_err()` | `u32` | `4_000_000` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `CHUNK_OUTPUT_LIMIT` | output | allocation: `with_capacity` in `decode_framed_deflate`; `with_capacity` in `decode_full_flush_deflate`; buffer length in `decode_framed_deflate`; 1 more | `usize` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_FILE_GROUPS` | other | silent: `while` condition in `read_file_groups` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_NAME_BYTES` | size | delegated: `CStrOptions::terminated()?` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | error: `Error::InstallShield` (DR-BINFMT-0037) | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_CE_DEPTH` | recursion | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `8` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_DIRECTORIES` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_DIR_DEPTH` | recursion | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `64` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_EXTENTS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_RECORDS` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_SUSP_BYTES` | size | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_ZISOFS_BLOCK_POINTERS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `131_073` | `crates/disrobe-binfmt/src/containers/iso.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | silent: `continue` in `walk_jffs2` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/jffs2.rs` |
| `disrobe-binfmt` | `MAX_NODES` | count | recorded: `notes` | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/jffs2.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_DIGEST_ITERATIONS` | work | error: `Error::Luks1KdfCost` (DR-BINFMT-0077); `Error::Luks1Malformed` (DR-BINFMT-0076) | `u32` | `1_000_000` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_KEY_BYTES` | size | error: `Error::Luks1Malformed` (DR-BINFMT-0076) | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_PAYLOAD_BYTES` | size | error: `Error::Luks1PayloadTooLarge` (DR-BINFMT-0083) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LUKS1_PAYLOAD_OFFSET_BYTES` | size | error: `Error::Luks1PayloadOffsetTooLarge` (DR-BINFMT-0084) | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/luks1.rs` |
| `disrobe-binfmt` | `MAX_LZH_HEADER_BYTES` | size | error: `Error::Lzh` (DR-BINFMT-0056) | `usize` | `1024 * 1024` | `crates/disrobe-binfmt/src/containers/lzh.rs` |
| `disrobe-binfmt` | `MAX_LZH_MEMBERS` | count | error: `Error::Lzh` (DR-BINFMT-0056); `Error::QuotaExceeded` (DR-BINFMT-0009); `inno_err()` | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/lzh.rs` |
| `disrobe-binfmt` | `MAX_CARVE_STEPS` | work | error: `Error::Minidump` (DR-BINFMT-0068); untyped `format!` | `u64` | `1 << 26` | `crates/disrobe-binfmt/src/containers/minidump/carve.rs` |
| `disrobe-binfmt` | `MAX_MEMORY_REGIONS` | other | error: `Error::Minidump` (DR-BINFMT-0068); untyped `format!` | `u64` | `8_000_000` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_MODULES` | other | error: `Error::Minidump` (DR-BINFMT-0068); untyped `format!` | `u32` | `262_144` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_BYTES` | size | silent: `return` in `read_minidump_string` | `u32` | `64 * 1024` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_PDB_PATH_BYTES` | size | error: `CoffLayoutError::BigObjVersion`; `CoreError::PassFailure` (DR-CORE-0003); `Error::Arc` (DR-BINFMT-0055); 52 more | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_SIZE_OF_IMAGE` | size | error: `Error::Minidump` (DR-BINFMT-0068); untyped `format!` | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_STREAMS` | other | error: `Error::Minidump` (DR-BINFMT-0068); untyped `format!` | `u32` | `65_536` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | silent: `break` in `walk_minixfs` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | silent: `break` in `walk_minixfs` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_CONTAINER_METADATA_BYTES` | size | delegated: `super::admit_metadata_bytes()?` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/mod.rs` |
| `disrobe-binfmt` | `MAX_STREAM_BYTES` | size | silent: `.take()` in `read_msi_extractable` | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/msi.rs` |
| `disrobe-binfmt` | `APPX_MANIFEST_READ_CAP` | other | error: `Error::ZipEntry` (DR-BINFMT-0004) | `u64` | `1 << 20` | `crates/disrobe-binfmt/src/containers/msix.rs` |
| `disrobe-binfmt` | `LZMA_PROPS_LIMIT` | work | error: `nsis_err()` | `u8` | `9 * 5 * 5` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | error: `nsis_err()` | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_FILE_BYTES` | size | error: `Error::Nsis` (DR-BINFMT-0033); `Error::other()`; `nsis_err()`; 1 more | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_HEADER_BYTES` | size | error: `nsis_err()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_SOLID_BYTES` | size | error: `Error::Nsis` (DR-BINFMT-0033); `Error::other()`; `nsis_err()`; 1 more | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/nsis.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | recursion | silent: `break` in `walk_ntfs` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | silent: `break` in `walk_ntfs` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILEZ_CONTENT` | other | silent: `.take()` in `inflate_raw_deflate` | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_DEPTH` | recursion | error: `Error::Flatpak` (DR-BINFMT-0042); untyped `format!` | `u32` | `64` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_DIR_ENTRIES` | count | silent: `.take()` in `collect_refs_recursive`; `.take()` in `count_objects`; `.take()` in `reconstruct_delta_dirs` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_FILES` | count | error: `Error::Flatpak` (DR-BINFMT-0042); untyped `format!` | `usize` | `200_000` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_OBJECT_BYTES` | size | error: `Error::Flatpak` (DR-BINFMT-0042); untyped `format!` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_TEXT_BYTES` | size | error: `Error::Flatpak` (DR-BINFMT-0042); untyped `format!` | `u64` | `1024 * 1024` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `PM1_TREE_WALK_LIMIT` | other | silent: `for` range in `read_byte_decode_index` | `usize` | `5` | `crates/disrobe-binfmt/src/containers/pmarc.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/rar.rs` |
| `disrobe-binfmt` | `MAX_FILTER_INVOCATIONS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_FILTER_PROGRAMS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_PROGRAM_LENGTH` | size | error: `Error::Decompression` (DR-BINFMT-0007) | `u32` | `0x0001_0000` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_RECORD_LENGTH` | size | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `0xffff` | `crates/disrobe-binfmt/src/containers/rar_filters.rs` |
| `disrobe-binfmt` | `MAX_FREQ` | other | delegated: passed to `.copy_from_slice` | `u8` | `124` | `crates/disrobe-binfmt/src/containers/rar_ppmd.rs` |
| `disrobe-binfmt` | `MAX_BLOCKS_PER_MEMBER` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `u32` | `8_192` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_FILTER_RECORD` | other | allocation: `with_capacity` in `read_filter_record_lz`; `with_capacity` in `read_filter_record_ppm` | `usize` | `0xffff` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | size | silent: `for` range in `make_decode_table`; `while` condition in `decode_number` | `usize` | `15` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_FILTERS` | other | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_FILTER_BLOCK_SIZE` | size | error: `.to_owned()`; `Error::Ar` (DR-BINFMT-0053); `Error::Arc` (DR-BINFMT-0055); 53 more | `u64` | `0x40_0000` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | size | silent: `for` range in `make_decode_table`; `while` condition in `decode_number` | `usize` | `15` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_DEPTH` | recursion | silent: `continue` in `walk_romfs` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_FILES` | count | silent: `return` in `walk_romfs` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_HEADER_ENTRIES` | count | error: `Error::Rpm` (DR-BINFMT-0017) | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_HEADER_STORE` | other | error: `Error::Rpm` (DR-BINFMT-0017) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_TAG_VALUES` | other | error: `Error::Rpm` (DR-BINFMT-0017) | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/rpm.rs` |
| `disrobe-binfmt` | `MAX_RAW_IMAGE` | other | error: `Error::Sparse` (DR-BINFMT-0046) | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/sparse.rs` |
| `disrobe-binfmt` | `MAX_METADATA_BLOCK` | other | silent: `return` in `read_metadata_block_at`; `while` condition in `read_metadata_at` | `usize` | `8192` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_PATH_DEPTH` | recursion | silent: `break` in `walk_squashfs` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_WALK_FILES` | count | silent: `break` in `walk_squashfs` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_CD_ENTRIES` | count | error: `.to_owned()`; `Error::Zip` (DR-BINFMT-0003); untyped `format!` | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `MAX_COMMENT` | other | error: `.to_owned()`; `Error::Zip` (DR-BINFMT-0003); untyped `format!` | `usize` | `0xFFFF` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `SEARCH_BUDGET` | work | error: `.to_owned()`; `Error::Zip` (DR-BINFMT-0003); untyped `format!` | `usize` | `MAX_COMMENT + EOCD_FIXED_LEN + 4` | `crates/disrobe-binfmt/src/containers/squirrel.rs` |
| `disrobe-binfmt` | `MAX_FOLDER_DEPTH` | recursion | error: `stuffit_error()` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | error: `stuffit_error()` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_RECORDS` | count | error: `stuffit_error()` | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/stuffit.rs` |
| `disrobe-binfmt` | `MAX_ENTRIES` | count | error: `sit5_error()` | `usize` | `65_535` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_FOLDER_DEPTH` | recursion | error: `sit5_error()` | `usize` | `256` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_PATH_BYTES` | size | error: `sit5_error()` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/stuffit5.rs` |
| `disrobe-binfmt` | `MAX_PEBS` | other | error: `Error::Ubifs` (DR-BINFMT-0052) | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/ubifs.rs` |
| `disrobe-binfmt` | `MAX_FFS_FILES` | count | recorded: `notes`; flag `truncated` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_FV_DEPTH` | recursion | error: `Error::UefiFirmwareVolume` (DR-BINFMT-0070); untyped `format!` | `usize` | `16` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_SECTIONS_PER_FILE` | other | error: `Error::UefiFirmwareVolume` (DR-BINFMT-0070); untyped `format!` | `usize` | `100_000` | `crates/disrobe-binfmt/src/containers/uefi_fv.rs` |
| `disrobe-binfmt` | `MAX_BLOCK_COUNT` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_NODE_COUNT` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 20` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_STRING_SCAN` | other | delegated: `.peek_bytes()?` | `usize` | `4096` | `crates/disrobe-binfmt/src/containers/unityfs.rs` |
| `disrobe-binfmt` | `MAX_UZIP_PREALLOC` | other | allocation: `with_capacity` in `read_block_to_exact` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/uzip.rs` |
| `disrobe-binfmt` | `MAX_UZIP_PREALLOC_U64` | other | allocation: `with_capacity` in `parse_uzip` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/uzip.rs` |
| `disrobe-binfmt` | `MAX_BAT_ENTRIES` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1 << 22` | `crates/disrobe-binfmt/src/containers/vhd.rs` |
| `disrobe-binfmt` | `MAX_DENTRY_COUNT` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/containers/wim_image.rs` |
| `disrobe-binfmt` | `MAX_TREE_DEPTH` | recursion | error: `Error::Decompression` (DR-BINFMT-0007) | `u32` | `512` | `crates/disrobe-binfmt/src/containers/wim_image.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | error: `Error::Decompression` (DR-BINFMT-0007) | `usize` | `2_000_000` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_MEMBER_BYTES` | size | delegated: passed to `.copy_from_slice` | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_TOC_BYTES` | size | error: `Error::Decompression` (DR-BINFMT-0007) | `u64` | `256 * 1024 * 1024` | `crates/disrobe-binfmt/src/containers/xar.rs` |
| `disrobe-binfmt` | `MAX_FILES` | count | recorded: `notes` | `usize` | `500_000` | `crates/disrobe-binfmt/src/containers/yaffs.rs` |
| `disrobe-binfmt` | `MAX_SECTION_NAME` | other | silent: `return` in `section_name` | `usize` | `512` | `crates/disrobe-binfmt/src/coverage/elf.rs` |
| `disrobe-binfmt` | `MAX_LOAD_COMMANDS` | other | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `u64` | `65_536` | `crates/disrobe-binfmt/src/coverage/macho.rs` |
| `disrobe-binfmt` | `MAX_SLICES` | other | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `u64` | `4_096` | `crates/disrobe-binfmt/src/coverage/macho.rs` |
| `disrobe-binfmt` | `MAX_COVERAGE_REGIONS` | other | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `usize` | `65_536` | `crates/disrobe-binfmt/src/coverage/mod.rs` |
| `disrobe-binfmt` | `MAX_OVERLAP_RECORDS` | count | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `usize` | `4_096` | `crates/disrobe-binfmt/src/coverage/mod.rs` |
| `disrobe-binfmt` | `DIRECTORY_LIMIT` | other | error: untyped error | `u32` | `16` | `crates/disrobe-binfmt/src/coverage/pe.rs` |
| `disrobe-binfmt` | `MAX_DEBUG_DIRECTORY_ENTRIES` | count | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `u64` | `4_096` | `crates/disrobe-binfmt/src/coverage/pe.rs` |
| `disrobe-binfmt` | `MAX_U32_LEB_BYTES` | size | error: `Error::Coverage` (DR-BINFMT-0072); untyped `format!` | `usize` | `5` | `crates/disrobe-binfmt/src/coverage/wasm.rs` |
| `disrobe-binfmt` | `MAX_DT_STRSZ` | other | silent: `return` in `parse_elf_dynamic` | `u64` | `0x100_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_ENTRIES` | count | silent: `return` in `parse_elf_dynamic` | `usize` | `0x10_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_STRING_OUTPUT` | output | silent: `return` in `resolve_bounded_string` | `usize` | `0x100_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_NEEDED` | other | silent: `return` in `push_needed_offset` | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_PROGRAM_HEADERS` | other | silent: `return` in `parse_elf_dynamic` | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_STRING_LEN` | size | silent: `.min()` clamp in `read_cstr` | `usize` | `0x1_0000` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_CAPTURE_OUTPUT` | output | error: `Error::Io` (DR-BINFMT-0001) | `usize` | `4 * 1024 * 1024` | `crates/disrobe-binfmt/src/external_wrap.rs` |
| `disrobe-binfmt` | `MAX_DISK_NESTING_DEPTH` | recursion | silent: `return` in `recurse_into_filesystem` | `u32` | `4` | `crates/disrobe-binfmt/src/extract.rs` |
| `disrobe-binfmt` | `MAX_ITERATED_RECORDS` | work | error: `ne_error()` | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RELOCATION_CHAIN_STEPS` | work | error: `ne_error()` | `usize` | `1_000_000` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RELOCATION_RECORDS` | count | error: `ne_error()` | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_RESOURCE_RECORDS` | count | error: `ne_error()` | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_TOTAL_ITERATED_BYTES` | work | error: `ne_error()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_UNIQUE_IMPORTS` | other | error: `ne_error()` | `usize` | `65_536` | `crates/disrobe-binfmt/src/ne.rs` |
| `disrobe-binfmt` | `MAX_ENTRY_COMPONENT_BYTES` | size | recorded: `note()` | `usize` | `255` | `crates/disrobe-binfmt/src/quota.rs` |
| `disrobe-binfmt` | `MAX_ENTRY_PATH_BYTES` | size | error: `Error::Rpm` (DR-BINFMT-0017); `Error::Tar` (DR-BINFMT-0005); `malformed()` | `usize` | `4096` | `crates/disrobe-binfmt/src/quota.rs` |
| `disrobe-binfmt` | `MAX_NOTES_PER_SEGMENT` | other | silent: `for` range in `find_build_ids` | `usize` | `1_024` | `crates/disrobe-binfmt/src/rewrite/elf.rs` |
| `disrobe-binfmt` | `MAX_NOTE_SEGMENT_BYTES` | size | error: `rewrite_error()` | `u64` | `1 << 20` | `crates/disrobe-binfmt/src/rewrite/elf.rs` |
| `disrobe-binfmt` | `MAX_EDITS` | other | error: `Error::Rewrite` (DR-BINFMT-0074); untyped `format!` | `usize` | `4_096` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_FAT_SLICES` | other | error: `Error::CoverageUnsupported` (DR-BINFMT-0073); `Error::RewriteUnsupported` (DR-BINFMT-0075); untyped `format!` | `u64` | `4_096` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_LOAD_COMMANDS` | other | error: `Error::CoverageUnsupported` (DR-BINFMT-0073); `Error::RewriteUnsupported` (DR-BINFMT-0075); untyped `format!` | `u64` | `65_536` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_PLAN_STRUCTURES` | other | error: `Error::Rewrite` (DR-BINFMT-0074); untyped `format!` | `usize` | `65_536` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | count | error: `Error::CoverageUnsupported` (DR-BINFMT-0073); `Error::RewriteUnsupported` (DR-BINFMT-0075); untyped `format!` | `u64` | `262_144` | `crates/disrobe-binfmt/src/rewrite/mod.rs` |
| `disrobe-binfmt` | `MAX_DIRECTORY_SLOTS` | other | silent: `.min()` clamp in `plan` | `u64` | `8_192` | `crates/disrobe-binfmt/src/rewrite/pe.rs` |
| `disrobe-bytes` | `MAX_ENTRY_PREALLOC` | other | allocation: `with_capacity` in `new`; `with_capacity` in `read_to_limit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-bytes/src/quota.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURES` | other | silent: `.take()` in `push_file_strings_with_limits` | `usize` | `4096` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURE_BYTES` | size | silent: `continue` in `push_file_strings_with_limits` | `usize` | `4096` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_SCAN_BYTES` | size | silent: `.min()` clamp in `push_file_strings_with_limits` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_NUMBER_FEATURES_PER_INSN` | other | silent: skipped in `instruction_features` | `usize` | `4` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `PE_HEADER_SCAN_CAP` | other | silent: `.min()` clamp in `embedded_pe_offset` | `usize` | `1 << 20` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_IMPORT_ENTRIES` | count | silent: `break` in `from_elf`; `break` in `from_pe` | `usize` | `1 << 17` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-capabilities` | `MAX_STUB_SPAN` | other | silent: `.min()` clamp in `name_at_thunk` | `u64` | `0x10` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-capabilities` | `MAX_LOWER_STEPS` | work | error: `LoadError::TooComplex` | `usize` | `100_000` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-capabilities` | `MAX_NODE_DEPTH` | recursion | error: `LoadError::TooDeep` | `usize` | `24` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-capabilities` | `MAX_REGEX_PATTERN_LEN` | size | error: `LoadError::RegexTooLong` | `usize` | `512` | `crates/disrobe-capabilities/src/yaml_rules/load.rs` |
| `disrobe-cfg` | `MAX_FLOW_NODES` | count | error: `CfgError::TooManyNodes`; `FlowError::NodeCountExceedsCapacity` | `usize` | `(u32::MAX - 1) as usize` | `crates/disrobe-cfg/src/flow.rs` |
| `disrobe-cfg` | `RETURN_TAIL_NODE_CAP` | other | silent: `return` in `private_return_tail` | `usize` | `64` | `crates/disrobe-cfg/src/lib.rs` |
| `disrobe-cfg` | `MAX_RECONVERGENCE_CLONES` | other | silent: `.min()` clamp in `tight_for_reconvergence` | `usize` | `64` | `crates/disrobe-cfg/src/reconverge.rs` |
| `disrobe-cli` | `RESOURCE_PREVIEW_LIMIT` | other | silent: `.min()` clamp in `render_resources` | `usize` | `50` | `crates/disrobe-cli/src/cli/apk.rs` |
| `disrobe-cli` | `MAX_EVIDENCE_SHOWN` | other | silent: `.take()` in `push_anti_analysis_evidence_lines`; `.take()` in `render_text`; no action in `push_anti_analysis_evidence_lines`; 1 more | `usize` | `6` | `crates/disrobe-cli/src/cli/behavior.rs` |
| `disrobe-cli` | `MAX_NAMESPACE_ATTEMPTS` | other | error: untyped `miette!` | `usize` | `1024` | `crates/disrobe-cli/src/cli/chain_materialization.rs` |
| `disrobe-cli` | `MAX_SIDECAR_REDACTION_BYTES` | size | silent: `return` in `sidecar_shape` | `usize` | `64 << 20` | `crates/disrobe-cli/src/cli/chain_v1.rs` |
| `disrobe-cli` | `MAX_REPORTS_GRADED` | other | silent: `break` in `find_reports` | `usize` | `4096` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_REPORT_SEARCH_DEPTH` | recursion | silent: `for` range in `find_reports` | `usize` | `4` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_COMPONENTS` | other | error: `CycloneDxError::TooManyComponents` | `usize` | `MAX_CYCLONEDX_PACKAGES + 1` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_COMPONENT_TEXT_BYTES` | size | error: `CycloneDxError::ComponentTextTooLong` | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_OUTPUT_BYTES` | output | error: `CycloneDxError::OutputTooLong`; `Error::other()` | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_CYCLONEDX_PACKAGES` | other | error: `CycloneDxError::TooManyComponents`; `CycloneDxError::TooManyPackages` | `usize` | `16_384` | `crates/disrobe-cli/src/cli/cyclonedx.rs` |
| `disrobe-cli` | `MAX_BUNDLE_ASSEMBLIES` | other | error: untyped `miette!` | `usize` | `512` | `crates/disrobe-cli/src/cli/dotnet.rs` |
| `disrobe-cli` | `MAX_INSTALL_LOG_ENTRIES` | count | silent: no action in `trim_install_log`; slice in `trim_install_log` | `usize` | `500` | `crates/disrobe-cli/src/cli/install/mod.rs` |
| `disrobe-cli` | `MAX_GHIDRA_ARCHIVE_ENTRIES` | count | error: untyped `miette!` | `usize` | `200_000` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_DOWNLOAD_BYTES` | size | error: untyped `miette!` | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_ENTRY_UNCOMPRESSED_BYTES` | size | error: untyped `miette!` | `u64` | `2 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `MAX_GHIDRA_TOTAL_UNCOMPRESSED_BYTES` | size | error: untyped `miette!` | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/install_deps.rs` |
| `disrobe-cli` | `NWJS_ZIP_ENTRY_BYTES_CAP` | size | error: untyped `miette!` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `NWJS_ZIP_ENTRY_COUNT_CAP` | count | error: untyped `miette!` | `usize` | `65_535` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `NWJS_ZIP_TOTAL_BYTES_CAP` | size | error: untyped `miette!` | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-cli/src/cli/js.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_CLASSES` | other | recorded: flag `omitted` | `usize` | `65_536` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_INPUT_BYTES` | size | error: untyped `miette!` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `MAX_IN_HOUSE_DEX_OUTPUT_BYTES` | output | error: untyped `miette!` | `usize` | `128 * 1024 * 1024` | `crates/disrobe-cli/src/cli/jvm.rs` |
| `disrobe-cli` | `DELPHI_LIST_LIMIT` | other | silent: `.take()` in `render_delphi_classes`; `.take()` in `render_delphi_forms`; `.take()` in `render_delphi_types`; 3 more | `usize` | `20` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `DEVIRT_FUNCTION_LIMIT` | other | unclassified: compound assignment in `decompile_native_pcode`; value in `decompile_native_pcode` | `usize` | `2048` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `DIFF_DEFAULT_LISTING_LIMIT` | other | error: untyped `miette!` | `usize` | `25` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LOWEST_COVERED_CAP` | other | silent: `.truncate()` in `lowest_covered` | `usize` | `10` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `MAX_CAPTURE_OUTPUT` | output | delegated: `subprocess::run_captured()?` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `MAX_NATIVE_SBOM_INPUT_BYTES` | size | error: untyped `miette!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `SYMBOL_PREVIEW_LIMIT` | other | silent: `.min()` clamp in `render_cxx_class_rows`; `.min()` clamp in `render_import_rows`; `.min()` clamp in `render_symbol_rows` | `usize` | `40` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LITERAL_PREVIEW_LIMIT` | work | silent: `.take()` in `preview`; `return` in `preview` | `usize` | `64` | `crates/disrobe-cli/src/cli/native_match.rs` |
| `disrobe-cli` | `MAX_DEEP_ANALYZE_LIB_BYTES` | size | error: untyped `miette!` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-cli/src/cli/nuitka.rs` |
| `disrobe-cli` | `MAX_TARGETS` | other | error: untyped `miette!` | `usize` | `65_536` | `crates/disrobe-cli/src/cli/prowl/harvest.rs` |
| `disrobe-cli` | `MAX_TARGET_INPUT_BYTES` | size | error: untyped `miette!` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-cli/src/cli/prowl/harvest.rs` |
| `disrobe-cli` | `MAX_JVM_QUERY_INPUT_BYTES` | size | error: untyped `miette!` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_REJECTED_ARTIFACT_DIAGNOSTICS` | other | recorded: `JvmHierarchyDiagnostic::RejectedArtifactDiagnosticLimit`; flag `rejected_artifacts_truncated` | `usize` | `1_024` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_REJECTED_ARTIFACT_DIAGNOSTIC_BYTES` | size | recorded: `JvmHierarchyDiagnostic::RejectedArtifactDiagnosticLimit`; flag `rejected_artifacts_truncated` | `usize` | `65_536` | `crates/disrobe-cli/src/cli/query.rs` |
| `disrobe-cli` | `MAX_ARTIFACT_WALK_DEPTH` | recursion | recorded: flag `truncated` | `u32` | `32` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_CITED_ARTIFACTS` | other | recorded: flag `truncated` | `usize` | `4_096` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_REPORT_ANALYSIS_INPUT_BYTES` | size | error: untyped `format!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/report.rs` |
| `disrobe-cli` | `MAX_BEHAVIOR_EVIDENCE` | other | silent: `.take()` in `render_behavior_row`; no action in `render_behavior_row` | `usize` | `6` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-cli` | `MAX_IOC_ROWS` | other | silent: `.take()` in `render_indicators`; no action in `render_indicators` | `usize` | `200` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-cli` | `DEFAULT_LISTING_LIMIT` | other | error: untyped `miette!` | `usize` | `40` | `crates/disrobe-cli/src/cli/semdiff.rs` |
| `disrobe-cli` | `MAX_SEMDIFF_INPUT_BYTES` | size | error: untyped `miette!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/semdiff.rs` |
| `disrobe-cli` | `MAX_DOCUMENT_OUTPUT_BYTES` | output | error: `Error::other()`; `StructuredDocumentError::OutputTooLong` | `usize` | `24 * 1024 * 1024` | `crates/disrobe-cli/src/cli/structured_document.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_CALLS` | other | unclassified: stored in `calls` with no read found | `usize` | `32_768` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_CANDIDATE_RECORDS` | count | unclassified: stored in `candidate_records` with no read found | `usize` | `65_536` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_FUNCTIONS` | other | error: `CycloneDxError::AllocationFailed`; `CycloneDxError::ArithmeticOverflow`; `OpenVexError::NoFindings`; 1 more | `usize` | `8_192` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_INSTRUCTIONS` | other | error: `OpenVexError::NoFindings`; untyped `miette!` | `usize` | `262_144` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_NAVIGATION_RETAINED_BYTES` | size | unclassified: stored in `retained_bytes` with no read found | `usize` | `64 * 1024 * 1024` | `crates/disrobe-cli/src/cli/taint.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_DEPTH` | recursion | error: `OpenVexError::NoFindings`; untyped `miette!` | `usize` | `128` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_NODES` | count | error: `OpenVexError::NoFindings`; untyped `miette!` | `usize` | `50_000` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_ANALYSIS_STEPS` | work | error: `OpenVexError::NoFindings`; untyped `miette!` | `usize` | `2_000_000` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-cli` | `MAX_VULNMATCH_INPUT_BYTES` | size | error: untyped `miette!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-cli/src/cli/vulnmatch.rs` |
| `disrobe-core` | `ANTI_ANALYSIS_SCAN_CAP` | other | silent: slice in `scan_with_chain` | `usize` | `96 * 1024 * 1024` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `CODE_SCAN_BUDGET` | work | recorded: flag `budget` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_EXEMPLARS_PER_KIND` | other | silent: `.take()` in `cap_evidence`; no action in `cap_evidence` | `usize` | `5` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_MACHO_LOAD_CMDS` | other | silent: `.min()` clamp in `macho_code_layout` | `usize` | `4096` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_PARSED_SECTIONS` | other | silent: `.min()` clamp in `elf_code_layout`; `.min()` clamp in `macho_segment_sections`; `.min()` clamp in `pe_code_layout` | `usize` | `96` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_CACHE_ENTRY_BYTES` | size | silent: `.take()` in `read_entry_file`; `return` in `read_entry_file` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-core/src/cache.rs` |
| `disrobe-core` | `MAX_CACHE_ENTRY_PREALLOC` | other | allocation: `with_capacity` in `read_entry_file` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-core/src/cache.rs` |
| `disrobe-core` | `DEFAULT_CAP` | other | unclassified: stored in `cap` with no read found | `u8` | `8` | `crates/disrobe-core/src/chain/spec.rs` |
| `disrobe-core` | `MAX_CAP` | other | error: `ChainSpecError::CapOutOfRange` (DR-CORE-0105) | `u8` | `16` | `crates/disrobe-core/src/chain/spec.rs` |
| `disrobe-core` | `MAX_AES_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/aes_cbc.rs` |
| `disrobe-core` | `MAX_BIGNUM_RADIX_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 16` | `crates/disrobe-core/src/codec/alphabets.rs` |
| `disrobe-core` | `MAX_RADIX_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 24` | `crates/disrobe-core/src/codec/alphabets.rs` |
| `disrobe-core` | `MAX_BASE64_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/base64.rs` |
| `disrobe-core` | `MAX_CIPHER_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/cipher.rs` |
| `disrobe-core` | `JOSE_HEADER_DECODE_CAP` | other | silent: `return` in `decode_base64url`; `return` in `decode_jose_header` | `usize` | `4096` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_SCAN` | other | silent: slice in `classify` | `usize` | `1 << 20` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_STATIC_PASSPHRASES` | other | silent: `break` in `static_passphrase_candidates`; `while` condition in `push_label_passphrases` | `usize` | `32` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_FRAMED_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 26` | `crates/disrobe-core/src/codec/framed.rs` |
| `disrobe-core` | `MAX_ENTITY_NAME` | other | silent: fallback value in `html_entity_decode_with_scan` | `usize` | `32` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MAX_PUNYCODE_LABEL_OUTPUT` | output | error: `DecodeError::TooLarge` | `usize` | `1024` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MAX_WEB_INPUT` | other | error: `DecodeError::TooLarge` | `usize` | `1 << 24` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MS_CAP` | other | silent: `return` in `pretty_duration` | `u128` | `5 * MS_PER_D` | `crates/disrobe-core/src/provenance.rs` |
| `disrobe-core` | `MAX_NOTE_LINES` | other | error: `ProvenanceMapError::NoteTooManyLines` (DR-CORE-PMAP-0001) | `usize` | `2` | `crates/disrobe-core/src/provenance_map.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOBS` | other | silent: `break` in `report_git` | `usize` | `1_000_000` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOB_BYTES` | size | silent: `continue` in `report_git` | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_COMMITS` | other | silent: `break` in `report_git` | `usize` | `100_000` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_BLOB_DECODE` | other | silent: `continue` in `decode_and_recurse`; `continue` in `decode_codecs_and_recurse` | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_CODEC_TOKEN` | other | silent: `continue` in `decode_codecs_and_recurse` | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_INDICATORS` | other | silent: `break` in `extract_with_work`; `break` in `scan_text_layer`; `return` in `collect_domains`; 7 more | `usize` | `100_000` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_FIELDS` | other | recorded: flag `budget` | `usize` | `4096` | `crates/disrobe-core/src/recon/malware_config.rs` |
| `disrobe-core` | `ARCHIVE_MEMBER_PREALLOC_CAP` | other | allocation: `with_capacity` in `read_archive_member` | `u64` | `1 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_DECODED_TOTAL` | other | silent: `break` in `base64_decode_findings`; `continue` in `base64_decode_findings` | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_DEPTH` | recursion | silent: `return` in `base64_decode_findings` | `u8` | `4` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_RUNS` | other | silent: `break` in `base64_decode_findings` | `usize` | `4096` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DECODED_TOTAL` | other | silent: `break` in `codec_cascade_findings`; `return` in `codec_peel_token` | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DEPTH` | recursion | silent: `return` in `codec_cascade_findings` | `u8` | `3` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_RUN` | other | silent: `return` in `codec_output_advances`; `return` in `codec_peel_token` | `usize` | `1 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CONTAINER_DEPTH` | recursion | silent: skipped in `scan_blob` | `usize` | `8` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_DECODED_TOTAL_BYTES` | size | delegated: passed to `.set` | `u64` | `1 << 30` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_FILE_BYTES` | size | silent: `.take()` in `read_scan_file`; `return` in `read_scan_file` | `u64` | `64 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_TREE_FILES` | count | silent: `break` in `walk_with_limit` | `usize` | `200_000` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_WIDE_RUNS` | other | silent: `break` in `merge_runs`; `return` in `push_narrow_run`; `return` in `push_wide_run`; 2 more | `usize` | `1 << 16` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_ENTRIES` | count | silent: `.min()` clamp in `scan_zip_bytes`; `break` in `scan_tar_bytes` | `usize` | `50_000` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_ENTRY_BYTES` | size | delegated: passed to `.set` | `u64` | `64 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_TOTAL_BYTES` | size | delegated: passed to `.set` | `u64` | `1 << 30` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `REGEX_SIZE_LIMIT` | size | delegated: `.dfa_size_limit()?`; `.size_limit()?` | `usize` | `16 << 20` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_SERIALIZED_DEPTH` | recursion | error: `RedactionError::DepthLimit` | `usize` | `64` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_SERIALIZED_NODES` | count | error: `RedactionError::NodeLimit` | `usize` | `1_048_576` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_SERIALIZED_STRING_BYTES` | size | error: `RedactionError::StringBytesLimit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-core/src/recon/redact.rs` |
| `disrobe-core` | `MAX_RUNS` | other | silent: `break` in `merge_runs`; `return` in `push_narrow_run`; `return` in `push_wide_run`; 2 more | `usize` | `4096` | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_RUN_BYTES` | size | silent: `continue` in `unit_runs_wide`; no action in `collect_narrow_runs`; slice in `text_runs` | `usize` | `64 << 10` | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_DECODE_RECURSE_LEN` | recursion | silent: `continue` in `recover_base64`; `continue` in `recover_codec` | `usize` | `1 << 16` | `crates/disrobe-core/src/strings.rs` |
| `disrobe-core` | `MAX_PE_SECTIONS` | other | silent: `return` in `pe_header_is_valid` | `usize` | `96` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `ZIP_SEARCH_BUDGET` | work | silent: `while` condition in `find_eocd` | `usize` | `ZIP_MAX_COMMENT + ZIP_EOCD_FIXED_LEN + 4` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `MAX_STRINGS` | other | silent: `break` in `select_strings` | `usize` | `20` | `crates/disrobe-core/src/yara_gen.rs` |
| `disrobe-core` | `MAX_STRING_LEN` | size | delegated: passed to `.sort_by` | `usize` | `96` | `crates/disrobe-core/src/yara_gen.rs` |
| `disrobe-core` | `HEX_WORK_BUDGET` | work | silent: `return` in `hex_matches_at` | `u64` | `1 << 20` | `crates/disrobe-core/src/yara_match/atoms.rs` |
| `disrobe-ir` | `MAX_DECODED_ENVELOPE_BYTES` | size | error: `EnvelopeError::EnvelopeTooLarge` | `usize` | `1 << 30` | `crates/disrobe-ir/src/envelope.rs` |
| `disrobe-ir` | `READ_PREALLOC_CAP` | other | allocation: `with_capacity` in `read_from_path` | `usize` | `1 << 20` | `crates/disrobe-ir/src/io.rs` |
| `disrobe-ir` | `MAX_RECORDS` | count | error: `WitnessError::RecordLimit` | `usize` | `1 << 16` | `crates/disrobe-ir/src/witness.rs` |
| `disrobe-irsummary` | `MAX_CFG_BLOCKS` | other | recorded: flag `truncated` | `usize` | `200_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_CFG_EDGES` | other | recorded: flag `truncated` | `usize` | `400_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_DFG_SITES` | other | recorded: flag `truncated` | `usize` | `400_000` | `crates/disrobe-irsummary/src/llm.rs` |
| `disrobe-irsummary` | `MAX_FIXPOINT_ROUNDS` | work | silent: `for` range in `optimize_graph` | `usize` | `16` | `crates/disrobe-irsummary/src/optimize.rs` |
| `disrobe-irsummary` | `MAX_BLOCKS` | other | silent: `return` in `build_region`; `return` in `collect_leaders` | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_BLOCK_INSNS` | other | silent: `return` in `build_block`; `return` in `collect_leaders` | `usize` | `256` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_INSNS` | other | silent: `return` in `summarize_function` | `usize` | `2048` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_JOINS` | other | silent: `return` in `summarize_region` | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_OUTPUTS` | output | silent: `return` in `finalize` | `usize` | `64` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_STACK_DEPTH` | recursion | silent: `return` in `push` | `usize` | `256` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-lift-x86` | `MAX_X86_BLOCK_BYTES` | size | silent: `.min()` clamp in `decode_block`; `.min()` clamp in `invalid_bitness_block`; fallback value in `with_limits` | `usize` | `1024 * 1024` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-lift-x86` | `MAX_X86_INSTRUCTIONS` | other | silent: `while` condition in `decode_block`; fallback value in `with_limits` | `usize` | `65_536` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-llm-metadata` | `MAX_ANNOTATIONS` | other | error: `AnnotationError::TooManyAnnotations` | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_FILE_BYTES` | size | error: `AnnotationError::FieldTooLong` | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_KIND_BYTES` | size | error: `AnnotationError::FieldTooLong` | `usize` | `128` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_NOTE_BYTES` | size | error: `AnnotationError::FieldTooLong` | `usize` | `4096` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_NOTE_LINES` | other | error: `AnnotationError::NoteTooLong` | `usize` | `2` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_SYMBOL_BYTES` | size | error: `AnnotationError::FieldTooLong` | `usize` | `1024` | `crates/disrobe-llm-metadata/src/annotation.rs` |
| `disrobe-llm-metadata` | `MAX_DECRYPTION_KEY_ENTRIES` | count | error: `LlmMetadataError::Serialization` | `usize` | `4096` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PIPELINE_STEPS` | work | error: `LlmMetadataError::Serialization` | `usize` | `1024` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PROVENANCE_CHAIN_ENTRIES` | count | error: `LlmMetadataError::Serialization` | `usize` | `16_384` | `crates/disrobe-llm-metadata/src/bundle.rs` |
| `disrobe-llm-metadata` | `MAX_PII_ENTRIES` | count | silent: `.min()` clamp in `scan` | `usize` | `4096` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_SCAN_BYTES` | size | silent: `.min()` clamp in `scan` | `usize` | `1024 * 1024` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_DECLARED_TYPE_BYTES` | size | silent: `return` in `parse_declared_type` | `usize` | `256` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_FUNCTIONS` | other | silent: skipped in `add_function` | `usize` | `65_536` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_OBSERVATIONS_PER_VAR` | other | unused: no use in the crate | `usize` | `16_384` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_OBSERVATIONS_PER_VAR_U32` | other | silent: skipped in `observe` | `u32` | `16_384` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_VARIABLES_PER_FN` | other | silent: skipped in `add_local`; skipped in `add_parameter` | `usize` | `4_096` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-mba` | `BFS_TABLE_BUDGET` | work | silent: `return` in `minimal_bitwise_for_table` | `usize` | `1usize << 14` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BITWISE_SYNTH_VARS` | other | silent: `return` in `synthesize_bitwise_masked`; no action in `simplify_l0_l5` | `u32` | `4` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_ATOMS` | other | silent: `return` in `boolean_minimization_candidate`; `return` in `collect_boolean_atoms`; `return` in `collect_predicate_atoms`; 2 more | `usize` | `8` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_PRIMES` | other | silent: `return` in `minimize_sop` | `usize` | `64` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_SEARCH_STEPS` | work | recorded: flag `exhausted` | `usize` | `100_000` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_CFF_BLOCKS` | other | silent: `return` in `devirtualize_cheap`; `return` in `devirtualize_table_dispatch`; `return` in `devirtualize_traced` | `usize` | `4_096` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `MAX_REGION_NODES` | count | silent: `return` in `run` | `u32` | `512` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `CHEAP_LOOP_CAP` | other | silent: `for` range in `cheap_initial`; `for` range in `cheap_resolve_block`; `return` in `cheap_initial`; 1 more | `u32` | `8` | `crates/disrobe-mba/src/cff/mod.rs` |
| `disrobe-mba` | `MAX_APPLICATIONS` | other | recorded: `StopReason::ApplicationLimit` | `usize` | `12_000` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_CLASSES` | other | recorded: `Refusal::ClassBudgetExhausted`; `StopReason::ClassLimit` | `usize` | `2000` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_INPUT_NODES` | count | recorded: `Refusal::NodesAboveCap`; `Saturation::Refused` | `usize` | `48` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_ITERATIONS` | work | recorded: `StopReason::IterationLimit` | `u32` | `10` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `MAX_LEAVES` | other | error: `BuildStop::LeafBudget` | `usize` | `32` | `crates/disrobe-mba/src/egraph.rs` |
| `disrobe-mba` | `BANK_CAP` | other | silent: skipped in `offer` | `usize` | `128` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `GEN_BUDGET` | work | silent: `return` in `expand_layer`; `return` in `grow`; `return` in `offer` | `u64` | `60_000` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ATOMS` | other | silent: `return` in `push_atom` | `usize` | `3` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CANDIDATE_NODES` | count | silent: `.min()` clamp in `synthesize` | `usize` | `16` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CONSTS` | other | silent: `.truncate()` in `build_consts` | `usize` | `8` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ROUNDS` | work | silent: `for` range in `grow` | `u32` | `4` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_VARS` | other | silent: `return` in `synthesize` | `u32` | `4` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `VERIFY_BUDGET` | work | silent: no action in `offer` | `u32` | `32` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_EXHAUSTIVE_EVALS` | other | recorded: `OpaqueVerdict::OutOfBudget`; flag `exhaustive` | `u128` | `1 << 24` | `crates/disrobe-mba/src/expr.rs` |
| `disrobe-mba` | `MAX_MBA_DEPTH` | recursion | recorded: `MixedRefusal::DepthLimit`; `MixedSimplification::Refused`; `OpaqueVerdict::OutOfBudget`; 2 more | `usize` | `256` | `crates/disrobe-mba/src/expr.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_DEGREE` | other | silent: `return` in `composition_is_identity`; `return` in `polynomial_is_zero_function` | `usize` | `1 << 16` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MULTIVAR_EVAL_BUDGET` | work | silent: `return` in `multivar_induces_zero` | `u128` | `1 << 22` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MAX_TABLE_ENTRIES` | count | silent: `.min()` clamp in `solver_resolve`; `return` in `solver_resolve`; `return` in `try_resolve_vsa` | `u64` | `4_096` | `crates/disrobe-mba/src/jumptable/mod.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | other | silent: `return` in `synthesize_linear_basis` | `u32` | `3` | `crates/disrobe-mba/src/linear_mba.rs` |
| `disrobe-mba` | `MAX_SOLVER_VARS` | other | silent: `return` in `solve_linear_mba`; `return` in `verify_equivalent`; no action in `simplify_l0_l5` | `u32` | `8` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_COMBOS` | other | silent: `return` in `subset_combinations` | `usize` | `60_000` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_SEARCH_VARS` | other | silent: skipped in `solve_linear_mba` | `u32` | `5` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_NODES` | count | recorded: `MixedRefusal::NodeLimit`; `MixedSimplification::Refused` | `usize` | `16_384` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_VARS` | other | error: `MixedRefusal::VariableLimit` | `u32` | `6` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_MBA_WORK` | work | error: `MixedRefusal::WorkLimit` | `usize` | `1_024` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_MIXED_RECURSION_DEPTH` | recursion | error: `MixedRefusal::DepthLimit` | `usize` | `256` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_POLYNOMIAL_PAIR_WORK` | work | error: `MixedRefusal::WorkLimit` | `usize` | `8_192 * 8_192` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `MAX_PROOF_PAIR_WORK` | work | error: `MixedRefusal::WorkLimit` | `usize` | `4_096 * 4_096` | `crates/disrobe-mba/src/mixed_mba.rs` |
| `disrobe-mba` | `BIT_BUDGET` | work | recorded: `OpaqueVerdict::OutOfBudget` | `u32` | `22` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_EXHAUSTIBLE` | other | recorded: `OpaqueVerdict::OutOfBudget` | `Width` | `Width::W16` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_OPAQUE_VARS` | other | recorded: `OpaqueVerdict::OutOfBudget` | `u32` | `3` | `crates/disrobe-mba/src/opaque.rs` |
| `disrobe-mba` | `MAX_ATOM_DEGREE` | other | silent: `return` in `to_falling_factorial`; `return` in `to_power_basis` | `u32` | `32` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_ATOMS` | other | silent: `return` in `intern_atom` | `usize` | `24` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MBA_VARS` | other | silent: `return` in `polynomial_solver_work`; `return` in `solve_polynomial_mba`; no action in `simplify_l0_l5` | `u32` | `4` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MONOMIALS` | other | silent: `return` in `multiply_poly`; `return` in `substitute_axis` | `usize` | `8192` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_ATOMS` | other | silent: `return` in `congruent_to_constant`; `return` in `induces_zero_over_free_atoms` | `usize` | `8` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIALS` | other | silent: `return` in `multiply` | `usize` | `4096` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIAL_DEGREE` | other | silent: `return` in `multiply_monomials` | `u32` | `128` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_REWRITE_PASSES` | other | silent: `for` range in `canonicalize` | `u32` | `64` | `crates/disrobe-mba/src/rewrite.rs` |
| `disrobe-mba` | `MAX_PROVENANCE_BYTES` | size | error: `EgraphRuleError::ProvenanceTooLong` | `usize` | `256` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULES` | other | error: `EgraphRuleError::TooManyRules` | `usize` | `256` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_CAPTURES` | other | error: `EgraphRuleError::TooManyCaptures` | `usize` | `8` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_FILE_BYTES` | size | error: `EgraphRuleError::TooLarge` | `usize` | `128 * 1024` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_RULE_NAME_BYTES` | size | error: `EgraphRuleError::RuleNameTooLong` | `usize` | `128` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_BYTES` | size | error: `TermError::TooLong` | `usize` | `512` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_DEPTH` | recursion | error: `TermError::TooDeep` | `usize` | `16` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TERM_NODES` | count | error: `TermError::TooManyNodes` | `usize` | `64` | `crates/disrobe-mba/src/rules/egraph_rules.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_NODES` | count | error: `ApplyError::DepthExceeded` | `usize` | `4096` | `crates/disrobe-mba/src/rules/engine.rs` |
| `disrobe-mba` | `MAX_CAPTURE_NAME_BYTES` | size | error: `LoadError::CaptureNameTooLong` | `usize` | `64` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_CONDITIONS_PER_RULE` | other | error: `LoadError::TooManyConditions` | `usize` | `64` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_PATTERN_NODES` | count | error: `LoadError::PatternTooLarge` | `usize` | `4096` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULES` | other | error: `LoadError::TooManyRules` | `usize` | `1024` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULE_NAME_BYTES` | size | error: `LoadError::RuleNameTooLong` | `usize` | `128` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_RULE_TEXT_BYTES` | size | error: `LoadError::TooLarge` | `usize` | `256 * 1024` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_NODES` | count | error: `LoadError::TemplateTooLarge` | `usize` | `4096` | `crates/disrobe-mba/src/rules/loader.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | other | silent: no action in `simplify_l0_l5` | `u32` | `3` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_LINEAR_VARS` | other | silent: skipped in `simplify_l0_l5` | `u32` | `4` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_VARS` | other | silent: skipped in `simplify_l0_l5` | `u32` | `2` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `CERT_NODE_BUDGET` | work | error: `EncodeExhausted` | `usize` | `1usize << 20` | `crates/disrobe-mba/src/smt.rs` |
| `disrobe-mba` | `CERT_NODE_BUDGET` | work | error: `EncodeExhausted` | `usize` | `1usize << 18` | `crates/disrobe-mba/src/symexec/solver.rs` |
| `disrobe-mba` | `EVAL_NODE_BUDGET` | work | silent: `return` in `eval_term` | `usize` | `1usize << 18` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_ASSIGNMENTS` | other | silent: `return` in `enumeration_domain` | `u64` | `1u64 << 12` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_STEPS` | work | silent: `.min()` clamp in `enumerate_conjunction` | `usize` | `1usize << 15` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VARS` | other | silent: `return` in `enumeration_domain` | `usize` | `6` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VAR_BITS` | other | silent: `return` in `enumeration_domain` | `u32` | `16` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_WIDTH_BITS` | other | error: `ApplyError::CaptureKindMismatch`; `ApplyError::MissingCapture`; `BuildStop::ClassBudget`; 29 more | `u16` | `64` | `crates/disrobe-mba/src/symexec/value.rs` |
| `disrobe-mba` | `DEFAULT_NODE_BUDGET` | work | error: `EncodeExhausted`; `MixedRefusal::VariableLimit` | `usize` | `1usize << 20` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `DEFAULT_OP_BUDGET` | work | recorded: flag `exhausted`; flag `truncated` | `usize` | `DEFAULT_NODE_BUDGET * 8` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `MAX_COUNTEREXAMPLE_SLOTS` | count | silent: `return` in `expand_counterexample` | `usize` | `1024` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `MAX_INPUT_BITS` | other | recorded: `OpaqueVerdict::OutOfBudget` | `usize` | `512` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mba` | `POLY_NODE_BUDGET` | work | recorded: `AbstainReason::SolverBudget`; `CffAbstain::Budget`; `JumpTableAbstain::SolverBudget` | `usize` | `4096` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mcp` | `MAX_CHAIN_DEPTH` | recursion | error: untyped `format!` | `u8` | `64` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_COVERAGE_REGIONS` | other | recorded: flag `regions_truncated` | `usize` | `512` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_IMPORTS` | other | error: untyped `format!` | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_IMPORT_BYTES` | size | error: untyped `format!` | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_BASE64_CHARS` | other | error: untyped `format!` | `usize` | `22 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_DECODED_BYTES` | size | error: untyped `format!` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_INLINE_JSON_BYTES` | size | error: untyped `format!` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_PROVENANCE_LINES` | other | error: untyped `format!` | `usize` | `262_144` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAMES_FILE_BYTES` | size | error: untyped `format!` | `u64` | `4 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_FIELD_BYTES` | size | error: untyped `format!` | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_NOTE_BYTES` | size | error: untyped `format!` | `usize` | `8192` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_RENAME_RECORDS` | count | error: untyped `format!` | `usize` | `16_384` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_STRINGS_MIN_LEN` | size | error: untyped `format!` | `usize` | `4096` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_WASM_LIFT_SOURCE_BYTES` | size | unclassified: stored in `wasm_lift()` with no read found | `usize` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `MAX_WORKSPACE_READ_BYTES` | work | error: untyped `format!` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-mcp/src/lib.rs` |
| `disrobe-mcp` | `DEFAULT_TOKEN_BUDGET` | work | error: `row_too_large()`; untyped `format!` | `usize` | `4_096` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_AMBIGUOUS_CANDIDATES` | other | silent: `.take()` in `call_outcome_out` | `usize` | `8` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_CALLS` | other | error: `cursor_error()` | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_CANDIDATE_RECORDS` | count | unclassified: stored in `candidate_records` with no read found | `usize` | `65_536` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_FUNCTIONS` | other | unclassified: pattern binding in `call_graph`; pattern binding in `neighborhood`; stored in `max_nodes` with no read found; 2 more | `usize` | `8_192` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_INSTRUCTIONS` | other | unclassified: stored in `instructions` with no read found | `usize` | `262_144` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ANALYSIS_RETAINED_BYTES` | size | delegated: `.bounded_navigation_xrefs_to_function()?` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_CURSOR_BYTES` | size | error: untyped `format!` | `usize` | `256` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_CURSOR_OFFSET` | other | error: `cursor_error()` | `usize` | `1_000_000` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_ENTRY_IDS` | other | error: untyped `format!` | `usize` | `64` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_NEIGHBORHOOD_DEPTH` | recursion | error: untyped `format!` | `u8` | `32` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_OUTPUT_TEXT_BYTES` | output | recorded: flag `truncated` | `usize` | `160` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_TOKEN_BUDGET` | work | error: untyped `format!` | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MAX_XREFS` | other | delegated: `.bounded_navigation_xrefs_to_function()?` | `usize` | `32_768` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-mcp` | `MIN_TOKEN_BUDGET` | work | error: untyped `format!` | `usize` | `2_048` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-nir` | `MAX_EFFECT_MODELS` | other | error: `EffectContextError::ModelLimit` | `usize` | `65_536` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_EFFECT_ROWS` | other | error: `EffectTableError::RowLimit`; `NirProvenanceError::ByteLimit` | `usize` | `1_048_576` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_WIRE_EFFECT_LABELS` | other | error: `EffectTableError::EffectLabelLimit` | `usize` | `64` | `crates/disrobe-nir/src/effects.rs` |
| `disrobe-nir` | `MAX_EMITTED_BYTES` | output | error: `EmitError::DepthExceeded`; `EmitError::OutputLimitExceeded` | `usize` | `1_048_576` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_EMIT_DEPTH` | recursion | error: `EmitError::DepthExceeded` | `usize` | `128` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_INDENT_DEPTH` | recursion | silent: `.min()` clamp in `write_indent` | `usize` | `32` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_REGION_DEPTH` | recursion | recorded: `StructureFailure::RegionDepthExceeded` | `usize` | `128` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_CLONE_BYTES` | size | silent: `?` on a checked operation in `charge_condition_clone` | `usize` | `1024 * 1024` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_TESTS` | other | silent: `return` in `resolve_condition_edge`; `return` in `short_circuit_candidate` | `usize` | `64` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_WORK` | work | error: `NirProvenanceError::WorkLimit` | `usize` | `65_536` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SPLIT_NODES` | count | error: `SplitRefusal::GraphTooLarge` | `usize` | `4096` | `crates/disrobe-nir/src/reducible.rs` |
| `disrobe-nir` | `MAX_SURFACE_DEPTH` | recursion | recorded: flag `complete` | `usize` | `128` | `crates/disrobe-nir/src/surface.rs` |
| `disrobe-nir` | `MAX_NIR_ELEMENTS` | other | error: `NirProvenanceError::ElementLimit`; `NirProvenanceError::WorkLimit` | `usize` | `MAX_SOURCE_UNITS` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_RETAINED_BYTES` | size | error: `NirProvenanceError::RetainedByteLimit` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_STRING_BYTES` | size | error: `NirProvenanceError::StringByteLimit` | `usize` | `MAX_SOURCE_BYTES` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_NIR_WORK` | work | error: `NirProvenanceError::WorkLimit` | `usize` | `8 * MAX_NIR_ELEMENTS` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_SOURCE_BYTES` | size | error: `EffectTableError::RowLimit`; `NirProvenanceError::ByteLimit`; `NirProvenanceError::StringByteLimit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir` | `MAX_SOURCE_UNITS` | other | error: `NirProvenanceError::ElementLimit`; `NirProvenanceError::UnitLimit`; `NirProvenanceError::WorkLimit` | `usize` | `1_048_576` | `crates/disrobe-nir/src/types.rs` |
| `disrobe-nir-lift` | `MAX_BIG_DECIMAL_BYTES` | size | silent: `return` in `big_to_decimal` | `usize` | `1024` | `crates/disrobe-nir-lift/src/beam.rs` |
| `disrobe-nir-lift` | `MAX_LUA_PROTOS` | other | error: `LiftError::AstSizeExceeded` | `usize` | `262_144` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_LUA_PROTO_DEPTH` | recursion | error: `LiftError::DepthExceeded` | `usize` | `256` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_REGISTERS` | other | allocation: buffer length in `new` | `usize` | `256` | `crates/disrobe-nir-lift/src/lua.rs` |
| `disrobe-nir-lift` | `MAX_REPORTED_GAPS` | other | silent: `.take()` in `block_gaps` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/arch.rs` |
| `disrobe-nir-lift` | `MAX_FOLD_DEPTH` | recursion | silent: `return` in `resolve` | `usize` | `64` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-nir-lift` | `MAX_REACHING_ANALYSIS_ELEMENTS` | other | silent: `return` in `compute_entries`; `return` in `eliminate_dead_values` | `usize` | `8_388_608` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-nir-lift` | `MAX_IDENTIFIER_BYTES` | size | error: `LiftError::InvalidPcode` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_PCODE_INSTRUCTIONS` | other | error: `LiftError::PcodeInstructionLimit` | `usize` | `65_536` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_PCODE_OPERATIONS` | other | error: `LiftError::PcodeOperationLimit` | `usize` | `1_048_576` | `crates/disrobe-nir-lift/src/pcode/mod.rs` |
| `disrobe-nir-lift` | `MAX_CALLOTHER_INPUTS` | other | error: `invalid()` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/ops.rs` |
| `disrobe-nir-lift` | `MAX_CALLOTHER_NAME_BYTES` | size | error: `invalid()` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/ops.rs` |
| `disrobe-nir-lift` | `MAX_SPEC_NAME_BYTES` | size | error: `invalid()` | `usize` | `128` | `crates/disrobe-nir-lift/src/pcode/spec.rs` |
| `disrobe-nir-lift` | `MAX_SPEC_REGISTERS` | other | error: `invalid()` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/spec.rs` |
| `disrobe-nir-lift` | `MAX_REGISTER_CELLS` | other | error: `invalid()` | `usize` | `4096` | `crates/disrobe-nir-lift/src/pcode/varnode.rs` |
| `disrobe-nir-lift` | `MAX_VARNODE_BYTES` | size | error: `invalid()` | `u32` | `4096` | `crates/disrobe-nir-lift/src/pcode/varnode.rs` |
| `disrobe-nir-lift` | `MAX_AST_NODES` | count | error: `LiftError::AstSizeExceeded` | `usize` | `262_144` | `crates/disrobe-nir-lift/src/python.rs` |
| `disrobe-nir-lift` | `MAX_EMIT_DEPTH` | recursion | error: `LiftError::DepthExceeded` | `usize` | `512` | `crates/disrobe-nir-lift/src/python.rs` |
| `disrobe-nir-lift` | `MAX_WASM_OPERATORS_PER_FUNCTION` | other | error: `LiftError::Source` | `usize` | `1 << 18` | `crates/disrobe-nir-lift/src/wasm.rs` |
| `disrobe-pass-as3` | `MULTINAME_RENDER_BUDGET` | work | silent: `return` in `render_multiname_bounded` | `u32` | `4096` | `crates/disrobe-pass-as3/src/abc.rs` |
| `disrobe-pass-as3` | `MAX_DUP_EXPR_NODES` | count | silent: `return` in `scope_node_count_capped`; `return` in `walk`; fallback value in `dup_clone` | `usize` | `1024` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_EXPR_DEPTH` | recursion | error: `Error::ExprDepthExceeded` (DR-AS3-0021) | `usize` | `2048` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_LOOSE_DISPATCH_CONDITIONS` | other | error: `SWITCH_ANALYSIS_BUDGET_MARKER` | `usize` | `256` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_MERGE_DEFINITIONS` | other | silent: `continue` in `merge_tracked_values` | `usize` | `4096` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_NEGATION_DEPTH` | recursion | silent: `return` in `negate_without_introducing_not` | `usize` | `32` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_OR_GUARD_TESTS` | other | silent: `return` in `or_guard_shared_target` | `usize` | `64` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_STRUCTURE_DEPTH` | recursion | error: `SWITCH_ANALYSIS_BUDGET_MARKER` | `usize` | `256` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_SWITCH_ANALYSIS_FUEL` | work | recorded: flag `exhausted` | `usize` | `65_536` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_TERNARY_FOLDS` | other | silent: `for` range in `resolve_ternary` | `usize` | `64` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_ARCHNAME_BYTES` | size | silent: slice in `is_byteloader_stream` | `usize` | `64` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_BYTELOADER_LINE_BYTES` | size | silent: slice in `skip_line` | `usize` | `64` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_RUNTIME_SYMBOL_SCAN_BYTES` | size | silent: slice in `detect_with_symbol_scan_limit` | `usize` | `64 << 20` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_SHEBANG_LINE_BYTES` | size | silent: slice in `skip_line` | `usize` | `256` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_DECOMPRESSED_BODY` | other | error: `Error::SwfDecompress` (DR-AS3-0005); `Error::SwfTruncated` (DR-AS3-0003) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_DECOMPRESS_PREALLOC` | other | delegated: passed to `.kv` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_LZMA_MEMLIMIT` | other | delegated: `Stream::new_lzma_decoder()?` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_SPRITE_NESTING` | recursion | delegated: passed to `Self::accumulate_counts` | `usize` | `256` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-as3` | `MAX_SWF_VERSION` | other | error: `Error::SwfUnsupportedVersion` (DR-AS3-0004) | `u8` | `40` | `crates/disrobe-pass-as3/src/swf.rs` |
| `disrobe-pass-beam` | `MAX_EXPR_NODES` | count | recorded: flag `degraded` | `usize` | `1024` | `crates/disrobe-pass-beam/src/body_lift/expr.rs` |
| `disrobe-pass-beam` | `MAX_LABEL_VISITS` | other | silent: `return` in `enter_label` | `u32` | `8` | `crates/disrobe-pass-beam/src/body_lift/mod.rs` |
| `disrobe-pass-beam` | `MAX_WALK_CALLS` | other | recorded: flag `degraded` | `u32` | `20_000` | `crates/disrobe-pass-beam/src/body_lift/mod.rs` |
| `disrobe-pass-beam` | `MAX_ARMS` | other | silent: `return` in `collect`; `return` in `descend`; `return` in `split_receive_arms` | `usize` | `32` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_CONJUNCTS` | other | silent: `return` in `split_receive_arms` | `usize` | `24` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TERM_DEPTH` | recursion | silent: `return` in `cannot_raise`; `return` in `is_guard_safe`; `return` in `is_literal`; 1 more | `u32` | `16` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TREE_DEPTH` | recursion | silent: `return` in `collect` | `u32` | `24` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_FUN_ARITY` | other | error: `CoreError::PassFailure` (DR-CORE-0003); `Error::BadAtomIndex` (DR-BEAM-0009); `Error::EzUnsafePath` (DR-BEAM-0022); 3 more | `u32` | `1024` | `crates/disrobe-pass-beam/src/chunks.rs` |
| `disrobe-pass-beam` | `MAX_DISASM_DEPTH` | recursion | error: `Error::DepthExceeded` (DR-BEAM-0023) | `usize` | `500` | `crates/disrobe-pass-beam/src/disasm.rs` |
| `disrobe-pass-beam` | `MAX_SCAN_DEPTH` | recursion | silent: `return` in `enforced_keys_in`; `return` in `find_enforced_keys`; `return` in `find_struct_list`; 1 more | `u32` | `256` | `crates/disrobe-pass-beam/src/elixir.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | recursion | silent: fallback value in `enter` | `u32` | `256` | `crates/disrobe-pass-beam/src/elixir_quoted.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | recursion | silent: fallback value in `enter` | `u32` | `256` | `crates/disrobe-pass-beam/src/erlang_abstract.rs` |
| `disrobe-pass-beam` | `MAX_ATOM_SCALARS` | other | error: `Error::AtomTooLong` (DR-BEAM-0025) | `usize` | `255` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_DEPRECATED_ATOM_LATIN1_CHARS` | other | error: `Error::AtomTooLong` (DR-BEAM-0025) | `usize` | `255` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_CONTAINER_PREALLOC` | other | allocation: `with_capacity` in `decode_term_after_first` | `usize` | `1 << 16` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_DEPTH` | recursion | error: `Error::DepthExceeded` (DR-BEAM-0023) | `usize` | `500` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_ETF_INFLATE` | other | error: `Error::Zlib` (DR-BEAM-0016) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-beam/src/etf.rs` |
| `disrobe-pass-beam` | `MAX_OPCODE` | other | error: `Error::UnknownOpcode` (DR-BEAM-0012) | `u32` | `191` | `crates/disrobe-pass-beam/src/opcodes.rs` |
| `disrobe-pass-dotnet` | `EAGER_CCTOR_SCAN_CAP` | other | silent: `while` condition in `detect` | `u32` | `512` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_DYNAMIC_RELOCATIONS` | other | error: `Error::AotContainerRead` (DR-DOTNET-0033) | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_NAME_LEN` | size | silent: `return` in `read_metadata_name` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_PROFILE_MAJOR` | other | silent: `continue` in `declared_profile` | `u16` | `64` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_READY_TO_RUN_SECTIONS` | other | silent: `return` in `read_ready_to_run_header` | `u16` | `1024` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAMES` | other | silent: `break` in `recover_names_at_threshold`; `while` condition in `recover_names_at_threshold` | `usize` | `65536` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_BUCKETS` | other | error: `invalid()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_BYTES` | size | error: `invalid()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_INVOKE_MAP_ENTRIES` | count | error: `invalid()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/invoke_map.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_COLLECTION` | other | error: `invalid_metadata()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_OUTPUT_BYTES` | output | error: `invalid_metadata()` | `usize` | `16_777_216` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_RECORDS` | count | error: `invalid_metadata()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_BYTES` | size | error: `invalid_metadata()` | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_RECORDS` | count | error: `invalid_metadata()` | `usize` | `131_072` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_STRING_STORAGE_BYTES` | size | error: `invalid_metadata()` | `usize` | `16_777_216` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_TYPE_SIGNATURE_DEPTH` | recursion | error: `invalid_metadata()` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_TYPE_SIGNATURE_WORK` | work | error: `invalid_metadata()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_VALUES` | other | error: `invalid_metadata()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/metadata_records.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_BODY_INPUT_BYTES` | size | error: `refused()` | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_BODY_OUTPUT_BYTES` | output | recorded: `refused()` | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_REFUSAL_BYTES_PER_METHOD` | size | error: `invalid()`; untyped error | `usize` | `128` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_BODY_INPUT_BYTES` | size | error: `refused()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_BODY_OUTPUT_BYTES` | output | error: `invalid()`; untyped error | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_UNIQUE_METHOD_BODIES` | other | error: `refused()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/aot/method_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_EXCEPTION_DIRECTORY_BYTES` | size | error: `invalid()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/aot/method_boundaries.rs` |
| `disrobe-pass-dotnet` | `MAX_RUNTIME_FUNCTIONS` | other | error: `invalid()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/aot/method_boundaries.rs` |
| `disrobe-pass-dotnet` | `MAX_BACKEND_CAPTURE` | other | delegated: `subprocess::run_captured()?` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/backends.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_QUALIFIED_NAME_BYTES` | size | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_SYMBOL_ARTIFACT_BYTES` | size | error: `.to_owned()`; `.to_string()`; `AotSignatureAbstention::ArgumentPositionsExceeded`; 36 more | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_SYMBOL_WORK_ITEMS` | work | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_NATIVE_AOT_TYPE_NESTING_DEPTH` | recursion | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `256` | `crates/disrobe-pass-dotnet/src/chain_detector.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_INSTRUCTIONS` | other | error: `Error::CilInstructionCountExceeded` (DR-DOTNET-0030) | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/cil.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY` | other | error: `EmulationError::OutOfBounds` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_EMULATED_INSTRUCTIONS` | other | error: `EmulationError::OutOfBounds` | `usize` | `16_384` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_HEAP` | other | error: `EmulationError::OutOfBounds` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_HEAP_BYTES` | size | error: `EmulationError::OutOfBounds` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_SWITCH_TARGETS` | other | error: `EmulationError::OutOfBounds` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `STEP_LIMIT` | work | error: `EmulationError::StepLimitExceeded` | `u64` | `4_000_000` | `crates/disrobe-pass-dotnet/src/cil_emulator.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EVALUATION_STACK` | other | error: `Reject::new()` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_DEPTH` | recursion | silent: `return` in `append_output_expression`; `return` in `binary`; `return` in `expression_contains_stack_input` | `u8` | `32` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_NODES` | count | silent: `return` in `binary` | `u8` | `64` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_HANDLER_BODY_BYTES` | size | error: `Reject::new()` | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_HANDLER_INSTRUCTIONS` | other | silent: `return` in `summarize_cil_handler` | `usize` | `512` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_LOWERED_EFFECTS` | other | error: `Reject::new()` | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODELS` | other | error: `ExtractError::ProgramTooLarge` | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODEL_INSTRUCTIONS` | other | error: `ExtractError::ProgramTooLarge` | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_MODEL_INSTRUCTIONS_TOTAL` | other | error: `ExtractError::ProgramTooLarge` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/devirt/extract.rs` |
| `disrobe-pass-dotnet` | `MAX_LIFT_STACK` | other | error: `Reject::new()` | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/lift.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_NODES` | count | silent: `.min()` clamp in `simplify_expression`; `return` in `count` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_VARS` | other | silent: `return` in `intern_leaf`; `return` in `simplify_expression` | `usize` | `6` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_SAMPLES` | other | silent: `return` in `append_input_case`; `return` in `append_input_values` | `usize` | `16` | `crates/disrobe-pass-dotnet/src/devirt/oracle.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_STACK` | other | error: untyped error | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/devirt/oracle/model_ref.rs` |
| `disrobe-pass-dotnet` | `MODEL_STEP_LIMIT` | work | recorded: `ModelRun::StepLimit` | `u64` | `4_000_000` | `crates/disrobe-pass-dotnet/src/devirt/oracle/model_ref.rs` |
| `disrobe-pass-dotnet` | `MAX_OPERAND_BYTES` | size | error: `Reject::new()` | `usize` | `8` | `crates/disrobe-pass-dotnet/src/devirt/profile.rs` |
| `disrobe-pass-dotnet` | `MAX_ABSTRACT_STACK` | other | error: `Reject::new()` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/devirt/state.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPR_DEPTH` | recursion | error: `Reject::new()` | `u8` | `32` | `crates/disrobe-pass-dotnet/src/devirt/state.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_BLOCKS` | other | error: `StructureError::new()` | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/devirt/structure.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_DEPTH` | recursion | error: `StructureError::new()` | `usize` | `128` | `crates/disrobe-pass-dotnet/src/devirt/structure.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_RVA_BYTES` | size | silent: `continue` in `build` | `u32` | `512` | `crates/disrobe-pass-dotnet/src/field_rva.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY_FIELD_BYTES` | size | silent: `continue` in `array_field_data` | `usize` | `1 << 20` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | other | silent: `break` in `recover_bitmono_strings` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CIPHERTEXT_BYTES` | size | silent: `return` in `decrypt_site` | `usize` | `1 << 16` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | other | silent: `continue` in `method_bodies` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DERIVATIONS` | other | silent: `return` in `decrypt_site` | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PBKDF2_ITERATIONS` | work | silent: `continue` in `locate_decryptor` | `u32` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTANTS_BLOB_BYTES` | size | recorded: flag `size` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTANTS_POOL_BYTES` | size | silent: `continue` in `recover_pool` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_DECODE_ATTEMPTS` | other | silent: `return` in `recover_strings` | `usize` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | other | silent: `break` in `collect_ldc_i4_immediates`; `break` in `recover_pool` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTED_RESOURCE_BYTES` | size | error: `Error::Truncated` (DR-DOTNET-0005) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_ENCRYPTED_BLOB_BYTES` | size | error: `Error::Truncated` (DR-DOTNET-0005) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | other | silent: `break` in `collect_ldc_i4_immediates`; `break` in `peel_confuserex_resources` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_METHODS_SCANNED` | other | silent: `break` in `recover_seeds_by_emulation` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_RUN` | other | silent: `return` in `seed_run` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `KEY_PATH_STEP_CAP` | work | silent: `return` in `reaches_dispatcher_switch` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `MAX_BLOCKS` | other | silent: `return` in `build` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `FIELD_RVA_READ_CAP` | other | silent: `.min()` clamp in `build_field_env` | `usize` | `1 << 16` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | other | silent: `return` in `scan_call_sites` | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `STEP_LIMIT` | work | error: `ResolveError::StepLimit` | `u32` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/interp.rs` |
| `disrobe-pass-dotnet` | `NATIVE_STEP_CAP` | work | delegated: `.run()?` | `u64` | `200_000` | `crates/disrobe-pass-dotnet/src/peel/deflatten/predicate.rs` |
| `disrobe-pass-dotnet` | `NATIVE_STUB_READ_CAP` | other | silent: `.min()` clamp in `classify` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/deflatten/predicate.rs` |
| `disrobe-pass-dotnet` | `MAX_VISIT` | other | silent: `break` in `deflatten_with_oracle` | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/deflatten/rebuild.rs` |
| `disrobe-pass-dotnet` | `MAX_ATTEMPTS_PER_IMAGE` | other | recorded: `RewriteOutcome::Refused` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_DEPTH` | recursion | recorded: `RewriteOutcome::Refused` | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_NODES` | count | recorded: `RewriteOutcome::Refused` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPRESSION_VARS` | other | recorded: `RewriteOutcome::Refused` | `usize` | `6` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRUCTIONS_PER_IMAGE` | other | recorded: `RewriteOutcome::Refused` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRUCTIONS_PER_METHOD` | other | recorded: `RewriteOutcome::Refused` | `usize` | `4_096` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_METHODS_PER_IMAGE` | other | recorded: `RewriteOutcome::Refused` | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK_VALUES` | other | silent: `return` in `lower_postfix`; `return` in `verify_straight_line` | `usize` | `1_024` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRS` | other | error: `DecodeError::Truncated` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/eazvm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_RESOURCE_BYTES` | size | silent: `return` in `locate_embedded_resource` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/ilprotector_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_BLOCKS` | other | error: `DisasmError::TooManyBlocks` | `usize` | `512` | `crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRS_PER_BLOCK` | other | silent: `for` range in `decode_block` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_SECTION_BYTES` | size | silent: `.min()` clamp in `locate_encrypted_section` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/maxtocode_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_NAME_CHARS` | other | silent: `.take()` in `bounded_eazvm_analysis_name` | `usize` | `128` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_REFUSALS` | other | silent: skipped in `apply_eazvm_tier` | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_DISASM_BYTES` | size | silent: `.min()` clamp in `surface_native_stub` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_SURFACED_INSNS` | other | silent: `.take()` in `surface_native_stub` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSORS` | other | silent: `return` in `prove_constructor` | `usize` | `65_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_CODE` | other | silent: `return` in `prove_accessor` | `u32` | `256` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_INSTRUCTIONS` | other | silent: `return` in `prove_accessor` | `usize` | `32` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_CODE` | other | silent: `return` in `prove_constructor` | `u32` | `16 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_INSTRUCTIONS` | other | silent: `return` in `prove_constructor` | `usize` | `2_048` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_DATA` | other | silent: `return` in `prove_constructor` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_ROWS` | other | error: `ScanFailure::TableLimit` | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_CODE` | other | silent: `return` in `prove_getter` | `u32` | `4 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_INSTRUCTIONS` | other | silent: `return` in `prove_getter` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_IMAGE_BYTES` | size | error: `ScanFailure::ImageLimit` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MEMBER_REF_ROWS` | other | error: `ScanFailure::TableLimit` | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_BLOB_BYTES` | size | error: `ScanFailure::ImageLimit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METADATA_BYTES` | size | error: `ScanFailure::ImageLimit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_CODE` | other | error: `ScanFailure::MethodBodies` | `u32` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_PARSE_BYTES` | size | silent: `.min()` clamp in `read_bodies` | `usize` | `1024 * 1024 + 64 * 1024 + 64` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_ROWS` | other | error: `ScanFailure::TableLimit` | `u32` | `131_072` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_NAME_BYTES` | size | error: `ScanFailure::TableLimit` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_MODEL_SIGNATURE_BYTES` | size | error: `ScanFailure::TableLimit` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_BYTES` | size | silent: `return` in `prove_accessors` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAME_BYTES` | size | silent: `?` on a checked operation in `prove_accessors` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK` | other | silent: `return` in `prove_accessor`; `return` in `prove_constructor`; `return` in `prove_getter` | `u16` | `64` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STRING_BYTES` | size | silent: `return` in `prove_accessors` | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_EXCEPTION_CLAUSES` | other | error: `ScanFailure::MethodBodies` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_INSTRUCTIONS` | other | error: `ScanFailure::MethodBodies` | `usize` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_METHOD_CODE` | other | error: `ScanFailure::MethodBodies` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_PARSE_BYTES` | size | error: `ScanFailure::MethodBodies` | `usize` | `72 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TOTAL_TABLE_ROWS` | other | error: `ScanFailure::TableLimit` | `u64` | `1_000_000` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_TYPE_ROWS` | other | error: `ScanFailure::TableLimit` | `u32` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_EMBEDDED_RESOURCES` | other | error: `.to_string()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_RESOURCE_BYTES` | size | error: `.to_string()`; `refused()`; untyped `format!`; 1 more | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_STRINGS` | other | silent: `break` in `read_unicode_records_varint`; `return` in `read_unicode_records_int32_strict`; `return` in `read_unicode_records_varint_strict` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_ENTRY_METHODS` | other | error: `.to_string()` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_HEAP_BYTES` | size | error: `.to_string()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METADATA_BYTES` | size | error: `.to_string()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METADATA_STREAMS` | other | error: `.to_string()` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_CODE_BYTES` | size | error: untyped `format!` | `u32` | `4096` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_INSTRUCTIONS` | other | error: untyped `format!` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_ROWS` | other | error: `.to_string()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_METHOD_TOTAL_BYTES` | size | error: untyped `format!` | `usize` | `16 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_PE_SECTIONS` | other | error: `.to_string()` | `usize` | `96` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_RELEVANT_METADATA_ROWS` | other | error: `.to_string()` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_SELECTED_HEAP_BYTES` | size | error: `.to_string()` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_STRING_HEAP_ENTRIES` | count | error: `.to_string()` | `usize` | `262_144` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_REACTOR_TOTAL_METADATA_ROWS` | other | error: `.to_string()` | `u64` | `262_144` | `crates/disrobe-pass-dotnet/src/peel/protector_resources/reactor.rs` |
| `disrobe-pass-dotnet` | `MAX_PARTS` | other | error: untyped `format!` | `usize` | `65_536` | `crates/disrobe-pass-dotnet/src/peel/smartassembly_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_ROT_SHIFT` | other | silent: no action in `recover_spices` | `u16` | `64` | `crates/disrobe-pass-dotnet/src/peel/spices_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PROBE_ARGS` | other | silent: `for` range in `probe_decoder` | `i64` | `64` | `crates/disrobe-pass-dotnet/src/peel/static_decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | other | silent: `continue` in `collect_from_type` | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_STRINGS` | other | silent: `return` in `recover_emulated_strings` | `usize` | `8192` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_INPUT_BYTES` | size | recorded: `R2rMethodBodyRefusal::InputBudgetExhausted` | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_OUTPUT_BYTES` | output | recorded: `R2rMethodBodyRefusal::OutputBudgetExhausted` | `usize` | `1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_TOTAL_INPUT_BYTES` | size | recorded: `R2rMethodBodyRefusal::InputBudgetExhausted` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_METHOD_BODY_TOTAL_OUTPUT_BYTES` | output | recorded: `R2rMethodBodyRefusal::OutputBudgetExhausted` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_RUNTIME_FUNCTIONS` | other | error: `Error::InvalidR2rRuntimeFunctions` (DR-DOTNET-0042); `invalid_method_def()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_SECTIONS` | other | error: `Error::TooManyR2rSections` (DR-DOTNET-0040); `invalid_method_def()` | `u32` | `1024` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_R2R_USER_STRING_ENTRIES` | count | error: `invalid_method_def()` | `usize` | `1_048_576` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_SUPPORTED_R2R_MAJOR_VERSION` | other | error: `Error::TooManyR2rSections` (DR-DOTNET-0040); `Error::UnsupportedR2rVersion` (DR-DOTNET-0016) | `u16` | `27` | `crates/disrobe-pass-dotnet/src/r2r.rs` |
| `disrobe-pass-dotnet` | `MAX_SIGNATURE_NODES` | count | error: `Error::SignatureTooManyNodes` (DR-DOTNET-0028) | `usize` | `4096` | `crates/disrobe-pass-dotnet/src/signature.rs` |
| `disrobe-pass-dotnet` | `MAX_SIG_DEPTH` | recursion | error: `Error::SignatureTooDeep` (DR-DOTNET-0026) | `usize` | `256` | `crates/disrobe-pass-dotnet/src/signature.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_DEPTH` | recursion | silent: `return` in `emit_region` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/structure_emit.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY_LITERAL_ELEMENTS` | work | error: `value` | `usize` | `64` | `crates/disrobe-pass-dotnet/src/structurize.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPR_DEPTH` | recursion | silent: `return` in `expression_depth`; fallback value in `bounded_expression` | `usize` | `256` | `crates/disrobe-pass-dotnet/src/structurize.rs` |
| `disrobe-pass-dotnet` | `INFERENCE_DEPTH_LIMIT` | recursion | silent: `return` in `infer_bounded`; `return` in `may_convert` | `usize` | `32` | `crates/disrobe-pass-dotnet/src/structurize/operand_kind.rs` |
| `disrobe-pass-dotnet` | `MAX_TABLE_ROWS` | other | error: `Error::TableRowCountTooLarge` (DR-DOTNET-0029) | `u64` | `1_000_000` | `crates/disrobe-pass-dotnet/src/tables.rs` |
| `disrobe-pass-go` | `FLAT_32_ADDRESS_LIMIT` | other | unused: no use in the crate | `u64` | `1 << 32` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_FTAB_CAP` | other | unused: no use in the crate | `usize` | `18` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_FUNCNAMETAB_CAP` | other | unused: no use in the crate | `usize` | `3` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MD_WORD_PCLNTABLE_CAP` | other | unused: no use in the crate | `usize` | `15` | `crates/disrobe-pass-go/src/binary.rs` |
| `disrobe-pass-go` | `MAX_LISTED_FUNCS` | other | silent: `.take()` in `push_defer_section`; `.take()` in `render_symbol_report`; no action in `push_defer_section`; 1 more | `usize` | `4_096` | `crates/disrobe-pass-go/src/chain_detector.rs` |
| `disrobe-pass-go` | `MAX_CALL_SCAN_BYTES` | size | recorded: flag `truncated` | `usize` | `1 << 20` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_CALL_SITES` | other | recorded: flag `truncated` | `usize` | `1 << 18` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_DEFER_FUNCS` | other | recorded: flag `truncated` | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_LISTED_RUNTIME_HOOKS` | other | recorded: flag `truncated` | `usize` | `1 << 8` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_PCDATA_ENTRIES` | count | silent: `return` in `read_func_defer_view` | `u32` | `64` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_RUNTIME_CALL_TARGET_NAMES` | other | recorded: flag `truncated` | `usize` | `1 << 12` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_TOTAL_CALL_SCAN_BYTES` | size | recorded: flag `truncated` | `usize` | `64 << 20` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_DECOMPRESSED_LEN` | size | silent: `.take()` in `inflate_raw`; `return` in `decompress_zdebug`; fallback value in `inflate_raw` | `u64` | `1 << 30` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_FUNCS` | other | silent: `break` in `collect_unit`; `break` in `walk_dwarf`; skipped in `push_function` | `usize` | `1 << 18` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_PER_FUNC` | other | silent: `break` in `collect_unit`; skipped in `collect_unit` | `usize` | `1 << 10` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_TOTAL` | other | silent: `break` in `collect_unit` | `usize` | `MAX_DWARF_FUNCS * MAX_DWARF_NAMES_PER_FUNC` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_TYPE_NAMES` | other | silent: `break` in `walk_dwarf`; skipped in `collect_unit` | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_ZDEBUG_INITIAL_CAPACITY` | other | allocation: `with_capacity` in `decompress_zdebug` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVES` | other | silent: `break` in `collect_directives` | `usize` | `4096` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVE_TAIL` | other | silent: `.min()` clamp in `collect_directives` | `usize` | `256` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_DATA_LEN` | size | silent: `return` in `parse_record` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_NAME_LEN` | size | silent: `return` in `is_clean_embed_path`; `return` in `parse_record` | `u64` | `4096` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_MAPS` | other | recorded: flag `maps_capped` | `usize` | `256` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_MAP_ENTRIES` | count | silent: `return` in `read_map` | `u64` | `1 << 16` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_TOTAL_EMBED_BYTES` | size | silent: `.min()` clamp in `read_member_bytes` | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `LITERAL_NO_INTERPRETER_LIMIT` | work | unclassified: stored in `literal_recovery_limit` with no read found | `&str` | `"garble -literals string encryption is recovered by emulating each \ literal's decrypt thunk, and the thunk interpreter covers x86-64 code only. this build's \ architecture has no interpreter, so its encrypted literals are reported as present but stay \ encrypted` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `LITERAL_RECOVERY_LIMIT` | work | unclassified: stored in `literal_recovery_limit` with no read found | `&str` | `"garble -literals string encryption is not a one-time pad: each literal's key is derived by \ an init-time decrypt thunk from material stored in the binary, so the plaintext is recovered \ statically by emulating that thunk. a scoped x86-64 interpreter runs the thunk the go compiler \ emitted for each literal, reading the encrypted data/key/positions/fullData arrays from rodata \ and the external-key arguments from the call site, including proxy-dispatcher field loads \ through .data. it covers the five obfuscators (simple, swap, shuffle, split, seed), with the \ decrypt as a separate closure or inlined into the caller, and the legacy single-byte \ XOR/ADD/SUB, repeating-key XOR, and standalone data/key blob cases. the interpreter follows the \ seed obfuscator's decFunc closure chain and the proxy dispatcher's indirect calls. the key \` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_LITERAL_SCAN_BYTES` | work | silent: skipped in `recover_strings`; slice in `recover_strings` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_PLAIN_STRINGS` | other | silent: `return` in `scan_ascii_strings`; skipped in `scan_ascii_strings` | `usize` | `MAX_RECOVERED_STRINGS` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_RECOVERED_STRINGS` | other | silent: `.take()` in `recover_strings`; `.truncate()` in `recover_strings`; `return` in `scan_ascii_strings`; 2 more | `usize` | `4096` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_REPEATING_KEY` | other | silent: `for` range in `scan_repeating_xor` | `usize` | `8` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `STRING_SCAN_BUDGET` | work | silent: `break` in `recover_strings` | `Duration` | `Duration::from_secs(8)` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_BLOB` | other | silent: `.min()` clamp in `grow_clean_pair` | `usize` | `256` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_BRIDGE_GAP` | other | silent: `break` in `extract_string_window` | `usize` | `1` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PERTURBED_BYTES` | size | silent: `return` in `grow_clean_pair` | `usize` | `12` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PLACEHOLDER_RATIO_PCT` | other | silent: `return` in `plausible_plaintext` | `usize` | `12` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_RECOVERIES` | other | silent: `return` in `recover_simple_literals` | `usize` | `1024` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_SCAN_BYTES` | size | silent: `return` in `recover_simple_literals` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_STRING_JUNK_BYTES` | size | silent: `break` in `grow_clean_pair` | `usize` | `8` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `WORK_BUDGET` | work | silent: `return` in `recover_simple_literals` | `u64` | `48_000_000` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `GLOBAL_STEP_BUDGET` | work | silent: `break` in `run_block`; `return` in `call_into_text` | `u64` | `6_000_000` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_CALLERS_PER_THUNK` | other | silent: skipped in `build_caller_index` | `usize` | `4` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_EMU_MEM_BYTES` | size | silent: `continue` in `write_mem`; `for` range in `zero_fill` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_INLINE_STRING` | other | silent: `return` in `span_is_printable`; no action in `snapshot_consumer_args` | `usize` | `4096` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_NESTED_CALL_DEPTH` | recursion | silent: `return` in `call_into_text` | `u32` | `96` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_STEPS` | work | silent: `while` condition in `run_block` | `usize` | `200_000` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_THUNK_BYTES` | size | silent: `.min()` clamp in `slice_for` | `usize` | `64 << 10` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `THUNK_SCAN_BUDGET` | work | silent: `break` in `recover_thunk_literals` | `Duration` | `Duration::from_secs(8)` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_BACKSEARCH_CANDIDATES` | other | silent: `return` in `via_pclntab_backsearch` | `usize` | `4096` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_DEPS` | other | silent: skipped in `build_info_from_parts` | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_SETTINGS` | other | silent: skipped in `build_info_from_parts` | `usize` | `1 << 12` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_MODULENAME_LEN` | size | delegated: `.or()?`; passed to `.kv` | `usize` | `4096` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SLICE_LEN` | size | silent: `return` in `validated_slice` | `u64` | `1 << 22` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PCLNTAB_CANDIDATES` | other | silent: `while` condition in `collect_needles_in_section` | `usize` | `16` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SIG_FUNCS` | other | silent: `return` in `validate_header_structure` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_FILETAB_ENTRY_LEN` | size | silent: `return` in `is_source_file`; fallback value in `read_filetab_name`; skipped in `collect_filetab_blob` | `usize` | `4096` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_FUNC_PREALLOC` | other | allocation: `.reserve()` in `func_table_go116`; `.reserve()` in `func_table_go118_plus`; `.reserve()` in `func_table_go12` | `usize` | `1 << 16` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_GO_NAME_BYTES` | size | recorded: `record_package()` | `usize` | `4096` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_FUNCS` | other | silent: `return` in `bounded_func_count` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_START_LINE` | other | delegated: passed to `.kv` | `i32` | `1 << 26` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `DISAMBIG_CANDIDATE_BUDGET` | work | silent: `break` in `disambiguate_shape_args` | `usize` | `1 << 22` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `ITABLINKS_WALK_CAP` | other | recorded: flag `truncated` | `usize` | `1 << 14` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_FIELDS_PER_STRUCT` | other | silent: `return` in `read_struct_fields` | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_IMETHODS_PER_INTERFACE` | other | silent: `return` in `read_interface_methods` | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_METHODS_PER_TYPE` | other | silent: `return` in `read_type_methods` | `u16` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_STRUCT_FIELD_TAG_LEN` | size | silent: `return` in `decode_name_component` | `u64` | `1 << 12` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_TYPE_NAME_LEN` | size | recorded: flag `duplicate_names_dropped` | `usize` | `1024` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `TYPELINKS_WALK_CAP` | other | recorded: flag `truncated` | `usize` | `1 << 14` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-js-deob` | `MAX_SIBLING_MAP_BYTES` | size | error: `SiblingMapRefusal::TooLarge` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap.rs` |
| `disrobe-pass-js-deob` | `MAX_MAP_BYTES` | size | error: `Error::SyntaxLimit` (DR-JSDEOB-0005) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_NAMES_PER_SOURCE` | other | silent: skipped in `collect_coverage_by_source` | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RENAMED_BINDINGS` | other | silent: `return` in `renamed_bindings` | `usize` | `100_000` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_SECTIONS` | other | error: `Error::SyntaxLimit` (DR-JSDEOB-0005) | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_SOURCES` | other | error: `CoreError::PassFailure` (DR-CORE-0003); `Error::OxcParse` (DR-JSDEOB-0003); `Error::SyntaxLimit` (DR-JSDEOB-0005); 20 more | `usize` | `1 << 22` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RECURSIVE_DEPTH` | recursion | silent: `return` in `recursive_descend` | `usize` | `6` | `crates/disrobe-pass-js-deob/src/esoteric/atob_indirection.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERATOR_CHAIN` | other | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/esoteric/jsfuck.rs` |
| `disrobe-pass-js-deob` | `MAX_PEEL_LAYERS` | other | silent: `while` condition in `unpack` | `usize` | `32` | `crates/disrobe-pass-js-deob/src/esoteric/packer.rs` |
| `disrobe-pass-js-deob` | `LOOP_ITERATION_LIMIT` | work | delegated: passed to `.set_loop_iteration_limit` | `u64` | `1_000_000` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_CAPTURE_SCRIPT_BYTES` | size | silent: `return` in `eval_to_source` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_SCRIPT_BYTES` | size | error: `ProbeRefusal::InputTooLarge` | `usize` | `256 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `RECURSION_LIMIT` | recursion | delegated: passed to `.set_recursion_limit` | `usize` | `1_024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `STACK_SIZE_LIMIT` | size | delegated: passed to `.set_stack_size_limit` | `usize` | `16 * 1024` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_EXACT_MAGNITUDE` | other | silent: `return` in `arith_combine`; `return` in `int_pattern`; `return` in `lower_arith` | `u128` | `1u128 << 53` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_FIXPOINT_ROUNDS` | work | silent: `for` range in `fold_algebraic_opaque` | `usize` | `32` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_LOWER_DEPTH` | recursion | silent: `return` in `lower_arith`; `return` in `lower_bits`; `return` in `lower_predicate`; 1 more | `usize` | `128` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_DENSE_ARRAY_ELEMENTS` | other | silent: `return` in `assign_to` | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/cff_vm/interp.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_DICT_ENTRIES` | count | silent: `return` in `lzstring_decompress_values` | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_INPUT_UNITS` | other | silent: `return` in `lzstring_decompress_base64`; `return` in `lzstring_decompress_uri`; `return` in `lzstring_decompress_utf16_raw`; 3 more | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_OUTPUT_UNITS` | output | silent: `return` in `lzstring_decompress_values` | `usize` | `4 << 20` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `LOOP_LIMIT` | other | delegated: passed to `.set_loop_iteration_limit` | `u64` | `2_000_000` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `RECURSION_LIMIT` | recursion | delegated: passed to `.set_recursion_limit` | `usize` | `1_500` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `STACK_LIMIT` | other | delegated: passed to `.set_stack_size_limit` | `usize` | `50_000` | `crates/disrobe-pass-js-deob/src/jscrambler/strict_dispatch_tests.rs` |
| `disrobe-pass-js-deob` | `MAX_CALL_BYTES` | size | silent: `return` in `try_fold_at` | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_FOLD_PASSES` | other | silent: `for` range in `fold_char_constructors` | `usize` | `8` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_IIFE_BYTES` | size | silent: `return` in `try_fold_iife` | `usize` | `8 * 1024` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RESULT_CHARS` | other | silent: `return` in `is_safe_literal_body` | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RECOVER_PASSES` | other | silent: `for` range in `try_recover` | `usize` | `6` | `crates/disrobe-pass-js-deob/src/jsobfu/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_PRIOR_CONFIDENCE` | other | error: `Error::AuthorizationRequired` (DR-JSDEOB-0010); `Error::NoFamilyMatched` (DR-JSDEOB-0001) | `u8` | `Confidence::LOW.0` | `crates/disrobe-pass-js-deob/src/mangled_names/corpus_source.rs` |
| `disrobe-pass-js-deob` | `MAX_PASS_CEILING` | other | recorded: flag `hit_pass_ceiling` | `u32` | `32` | `crates/disrobe-pass-js-deob/src/obfuscator_io/dispatch.rs` |
| `disrobe-pass-js-deob` | `MAX_EXPRESSION_DEPTH` | recursion | error: `ProbeRefusal::UnsafeNesting` | `usize` | `28_000` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERATOR_CHAIN` | other | error: `Error::SyntaxLimit` (DR-JSDEOB-0005); `ProbeRefusal::UnsafeNesting` | `usize` | `600` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_SYNTACTIC_NESTING_DEPTH` | recursion | error: `Error::SyntaxLimit` (DR-JSDEOB-0005); `ProbeRefusal::UnsafeNesting` | `usize` | `600` | `crates/disrobe-pass-js-deob/src/sandbox_guard.rs` |
| `disrobe-pass-js-deob` | `MAX_TEMPLATE_SCAN_DEPTH` | recursion | error: `ProbeRefusal::UnsafeNesting` | `usize` | `256` | `crates/disrobe-pass-js-deob/src/string_array/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_ROTATIONS` | other | silent: `for` range in `simulate` | `u32` | `4096` | `crates/disrobe-pass-js-deob/src/string_array/rotate.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_LOOP_ITERATION_LIMIT` | work | delegated: passed to `.set_loop_iteration_limit` | `u64` | `100_000` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_RECURSION_LIMIT` | recursion | delegated: passed to `.set_recursion_limit` | `usize` | `256` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `DEFAULT_STACK_SIZE_LIMIT` | size | delegated: passed to `.set_stack_size_limit` | `usize` | `8 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_AGGREGATE_EXPRESSION_BYTES` | size | error: `ProbeRefusal::InputTooLarge` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_BATCH_JSON_BYTES` | size | error: `ProbeRefusal::BoundExceeded` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_BATCH_OUTPUT_UNITS` | output | silent: `while` condition in `usize_decimal_len` | `usize` | `1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_CONCURRENT_PROBES` | other | silent: `while` condition in `acquire_probe_permit_from` | `usize` | `1` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_DECODED_TOTAL_BYTES` | size | error: `ProbeRefusal::BoundExceeded` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_DECODED_VALUE_BYTES` | size | error: `ProbeRefusal::BoundExceeded` | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_ENVIRONMENT_CALLS` | other | error: `ProbeRefusal::BoundExceeded` | `u64` | `10_000_000` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_EXPRESSION_BYTES` | size | error: `ProbeRefusal::InputTooLarge` | `usize` | `64 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_GENERATED_SCRIPT_BYTES` | size | error: `ProbeRefusal::InputTooLarge` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_PROBE_EXPRESSIONS` | other | error: `ProbeRefusal::BoundExceeded` | `usize` | `65_536` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_SCRIPT_BYTES` | size | error: `ProbeRefusal::InputTooLarge` | `usize` | `256 * 1024` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_MANGLED_SOURCE_BYTES` | size | error: `Error::SyntaxLimit` (DR-JSDEOB-0005) | `usize` | `1 << 20` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_MEMBER_CALL_LITERALS` | work | silent: `.take()` in `restore_terser_mangled_bounded`; skipped in `restore_terser_mangled_bounded` | `usize` | `8` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_NEARBY_STRINGS` | other | silent: `.take()` in `static_member_call_literals_on_reference`; `return` in `collect_string_literals` | `usize` | `4` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_SEARCH_DEPTH` | recursion | silent: `return` in `collect_string_literals` | `usize` | `8` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_SUFFIX_ATTEMPTS` | other | silent: `for` range in `allocate` | `u32` | `512` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | other | silent: `for` range in `fold_binary` | `usize` | `16` | `crates/disrobe-pass-js-deob/src/unminify/arithmetic.rs` |
| `disrobe-pass-js-deob` | `MAX_MBA_LOWER_DEPTH` | recursion | silent: `return` in `lower_expression_at`; `return` in `render_expression_at` | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_PREDICATE_VARS` | other | silent: `return` in `classify_predicate` | `usize` | `3` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_DEPENDENCY_SETTER_PAIRS` | other | silent: `return` in `recover`; `return` in `registration` | `usize` | `4_096` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_GENERATED_EDITS` | other | recorded: `RegistrationEditResult::Exhausted` | `usize` | `65_536` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_REGISTRATIONS` | other | silent: `return` in `recover` | `usize` | `4_096` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_CANDIDATES` | other | recorded: `Refusal::TooLarge` | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async.rs` |
| `disrobe-pass-js-deob` | `MAX_DEPTH` | recursion | error: `UnsupportedShape` | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/canon.rs` |
| `disrobe-pass-js-deob` | `MAX_SIMPLIFY_ROUNDS` | work | silent: `for` range in `simplify` | `usize` | `64` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/emit.rs` |
| `disrobe-pass-js-deob` | `MAX_BLOCKS` | other | error: `Refusal::TooLarge` | `usize` | `4096` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_REGIONS` | other | error: `Refusal::RegionShape` | `usize` | `512` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_REGION_DEPTH` | recursion | error: `Refusal::TooDeep` | `usize` | `64` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/machine.rs` |
| `disrobe-pass-js-deob` | `MAX_WALK_DEPTH` | recursion | error: `Refusal::TooDeep` | `usize` | `512` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/order.rs` |
| `disrobe-pass-js-deob` | `MAX_RENDER_DEPTH` | recursion | error: `Refusal::TooDeep` | `usize` | `256` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/render.rs` |
| `disrobe-pass-js-deob` | `MAX_TREE_DEPTH` | recursion | error: `Refusal::TooDeep` | `usize` | `128` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/structure.rs` |
| `disrobe-pass-js-deob` | `MAX_FIX_POINT_PASSES` | other | silent: `for` range in `unminify` | `usize` | `8` | `crates/disrobe-pass-js-deob/src/unminify/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_CHAIN` | other | silent: `break` in `collect_chain` | `usize` | `1024` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | other | silent: `for` range in `fold_string_concat` | `usize` | `32` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERANDS` | other | silent: `while` condition in `new` | `usize` | `5usize` | `crates/disrobe-pass-js-deob/src/v8/bytecode_opcodes.rs` |
| `disrobe-pass-js-deob` | `MAX_DESERIALIZE_OBJECTS` | other | error: `Error::OxcParse` (DR-JSDEOB-0003) | `usize` | `1usize << 20usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_FRAME_SIZE` | size | silent: `return` in `recover_bytecode_array_with_layout` | `i32` | `1i32 << 24i32` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_RECURSION_DEPTH` | recursion | error: `Error::OxcParse` (DR-JSDEOB-0003) | `usize` | `256usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_BODY` | other | silent: `return` in `decode_string_from_run` | `usize` | `1usize << 20usize` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_RENDERED_ARGUMENTS` | output | delegated: passed to `push_format` | `i64` | `65_534` | `crates/disrobe-pass-js-deob/src/v8/flat_bytecode_lift.rs` |
| `disrobe-pass-js-deob` | `REGISTER_RANGE_SCAN_LIMIT` | other | silent: no action in `prepare_accumulator` | `i64` | `256` | `crates/disrobe-pass-js-deob/src/v8/flat_bytecode_lift.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_LEN` | size | silent: `continue` in `extract_framed_strings` | `u32` | `1u32 << 24u32` | `crates/disrobe-pass-js-deob/src/v8/serialized_code.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_INPUT_FILE_NAME_BYTES` | size | error: `JadxRefusal::InvalidInputFileName` | `usize` | `255` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_INPUT_FILE_NAME_UTF16_UNITS` | other | error: `JadxRefusal::InvalidInputFileName` | `usize` | `255` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_OUTPUT_TREE_BYTES` | output | error: `JadxRefusal::OutputLimit` | `u64` | `128 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_OUTPUT_TREE_ENTRIES` | output | error: `JadxRefusal::OutputLimit` | `usize` | `262_144` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_SOURCE_BYTES` | size | error: `JadxRefusal::OutputLimit` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_SOURCE_FILES` | count | error: `JadxRefusal::OutputLimit` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `MAX_JADX_TOTAL_SOURCE_BYTES` | size | error: `JadxRefusal::OutputLimit` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/android_backend.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_ENTRY_BYTES_CAP` | size | error: `Error::Zip` (DR-JVM-0011) | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_FILE_COUNT_CAP` | count | error: `Error::Zip` (DR-JVM-0011) | `usize` | `256` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `V1_SIGNATURE_PREALLOC_BYTES_CAP` | size | allocation: `with_capacity` in `read_v1_signature_file` | `u64` | `1024 * 1024` | `crates/disrobe-pass-jvm/src/apk_sig.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_DEPTH` | recursion | error: `AnnotationError()` | `usize` | `64` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_INPUT_BYTES` | size | error: `.to_string()`; `AnnotationError()`; `Error::Dex2JarLimit` (DR-JVM-0094); 11 more | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_NODES` | count | error: `AnnotationError()`; `SignatureSyntaxError`; untyped error | `usize` | `65_535` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_RENDER_BYTES` | output | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_ANNOTATION_TEXT_BYTES` | size | error: `AnnotationError()` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/attributes.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ATTRIBUTES` | other | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ATTRIBUTES_PER_ELEMENT` | other | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_ELEMENT_DEPTH` | recursion | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `128` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_EVENTS` | other | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_OWNED_TEXT_BYTES` | size | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `16 * 1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_RESOURCE_IDS` | other | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_STRING_BYTES` | size | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_STRING_COUNT` | count | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_AXML_TEXT_BYTES` | size | error: `Error::BadAxml` (DR-JVM-0013) | `usize` | `16 * 1_048_576` | `crates/disrobe-pass-jvm/src/axml.rs` |
| `disrobe-pass-jvm` | `MAX_BACKEND_CAPTURE` | other | delegated: `subprocess::run_captured()?` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/backends.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | other | silent: `for` range in `next_bounded_int` | `usize` | `128` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_CALL_DEPTH` | recursion | error: `EvalError::CallDepthExceeded` | `u32` | `24` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | error: `EvalError::HeapExhausted` | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_STACK_DEPTH` | recursion | error: `EvalError::StackOverflow` | `usize` | `8_192` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_STRING_LEN` | size | error: `EvalError::BadShape` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | error: `EvalError::StepLimitExceeded` | `u64` | `6_000_000` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_MAJOR` | other | error: `Error::UnknownConstantTag` (DR-JVM-0005); `Error::UnsupportedClassVersion` (DR-JVM-0004) | `u16` | `69` | `crates/disrobe-pass-jvm/src/classfile.rs` |
| `disrobe-pass-jvm` | `MAX_DATAFLOW_VISITS_PER_INSTRUCTION` | other | silent: `return` in `local_constants_at_block_entries` | `usize` | `16` | `crates/disrobe-pass-jvm/src/const_fold.rs` |
| `disrobe-pass-jvm` | `MAX_MASK_SEARCH_PAIRS` | other | silent: `return` in `recover_dispatch_mask` | `usize` | `4096` | `crates/disrobe-pass-jvm/src/dalvik_blackobf.rs` |
| `disrobe-pass-jvm` | `MAX_DALVIK_BLOCKS` | other | error: `StructureError::TooManyBlocks` | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/dalvik_cfg.rs` |
| `disrobe-pass-jvm` | `MAX_FLOW_WORDS` | other | silent: `return` in `analyze` | `usize` | `1 << 22` | `crates/disrobe-pass-jvm/src/dalvik_cfg.rs` |
| `disrobe-pass-jvm` | `MAX_DIAGNOSTICS` | other | silent: no action in `analyze` | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_MARKER_BYTES` | size | silent: `return` in `parse_marker` | `usize` | `4096` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_MARKER_IDENTIFIERS` | other | recorded: flag `marker_conflicts` | `usize` | `16` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_NESTED_CLASS_DEPTH` | recursion | silent: `for` range in `lexically_encloses`; `for` range in `translated_owner_path`; no action in `compose_rendered_class` | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | output | silent: `return` in `render_region` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_DESUGAR_SCAN_INSNS` | other | silent: `return` in `exclusively_constructed`; `return` in `helper_references`; `return` in `scan_references` | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_BODY_INSNS` | other | silent: `return` in `inlinable_helper_body` | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_REFERENCE_BODY_INSNS` | other | silent: `return` in `match_reference_body` | `usize` | `64` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_RESOLVE_ROUNDS` | work | silent: `break` in `unflatten_with_graph` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_dexguard.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_LEN` | size | error: `SkipReason::OutputTooLarge`; `SkipReason::Unsound` | `usize` | `1 << 20` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_BACKWARD_BRANCHES` | other | error: `SkipReason::BudgetExhausted` | `u32` | `500_000` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_BYTES` | size | error: `SkipReason::OutputTooLarge` | `usize` | `8 << 20` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | error: `SkipReason::OutputTooLarge` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_RECURSION_DEPTH` | recursion | error: `SkipReason::BudgetExhausted` | `u32` | `12` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `STEP_BUDGET` | work | error: `SkipReason::BudgetExhausted` | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `TOTAL_STEP_BUDGET` | work | error: `SkipReason::BudgetExhausted` | `u64` | `16 * STEP_BUDGET` | `crates/disrobe-pass-jvm/src/dalvik_interp.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DATA_ELEMENTS` | other | silent: `return` in `array_data_elements` | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_DEPTH` | recursion | silent: `return` in `inline_helper_body` | `u16` | `2` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_HANDLER_BLOCKS` | other | silent: `break` in `monitor_handler` | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_MONITOR_BODY_BLOCKS` | other | silent: `continue` in `releases_before_leaving`; `return` in `monitor_region` | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | work | silent: `for` range in `past_trampolines` | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_RECOVERABLE_PAYLOAD_LEN` | size | recorded: `note`; `record_construction()`; `record_reference_store()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dalvik_pack_stub_loader.rs` |
| `disrobe-pass-jvm` | `MAX_HELPER_ARITY` | other | recorded: flag `applied` | `usize` | `6` | `crates/disrobe-pass-jvm/src/dalvik_r8_inline/detect.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | other | silent: `for` range in `next_bounded_int` | `usize` | `128` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_LEN` | size | error: `EvalError::BadShape` | `usize` | `1 << 20` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | error: `EvalError::HeapExhausted` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | error: `EvalError::StepLimitExceeded` | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_CANDIDATE_PARAMS` | other | silent: `return` in `signature_weight` | `usize` | `2` | `crates/disrobe-pass-jvm/src/dalvik_strdec_generic.rs` |
| `disrobe-pass-jvm` | `MAX_BUCKET_TESTS` | other | silent: `for` range in `bucket_chain` | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | work | silent: `for` range in `absorb_trampolines`; `for` range in `skip_trampolines` | `usize` | `4` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_BRANCH_INSNS` | other | recorded: `record_bail_kind()` | `usize` | `2048` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_CODE_BYTES` | size | recorded: `record_bail_kind()` | `usize` | `60_000` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_METHOD_INSNS` | other | recorded: `record_bail_kind()` | `usize` | `8192` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_TRACKED_NARROW_CONSTANT_REGS` | other | silent: `return` in `must_narrow_constant_states` | `usize` | `128` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_REGION_BLOCKS` | other | silent: `for` range in `nearest_common_dominator`; `return` in `merge_ranges` | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/dalvik_try_regions.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_JOIN_DEPTH` | recursion | silent: `return` in `join_ref` | `usize` | `16` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `MAX_FIXPOINT_ITERS` | work | delegated: passed to `debug::dbg_kv` | `usize` | `50_000` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `MAX_SUPERCLASS_DEPTH` | recursion | silent: `while` condition in `root_first_chain` | `usize` | `256` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `ARM_CONDITION_BLOCK_CAP` | other | silent: `return` in `arm_tree_value`; `return` in `arm_value`; `return` in `ternary_join_entry` | `usize` | `32` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `INT_USE_SCAN_LIMIT` | other | silent: `.take()` in `loaded_int_has_int_use` | `usize` | `32` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_BOOL_EXPR_BYTES` | size | silent: `return` in `eval_bool_node_memo` | `usize` | `64 * 1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_DUP_EXPR_NODES` | count | error: `Error::ArscTruncated` (DR-JVM-0032); `Error::BadBytecode` (DR-JVM-0025); `Error::BadKotlinMetadata` (DR-JVM-0020); 9 more | `usize` | `1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENTS` | other | silent: `return` in `replacement_nodes` | `usize` | `4_096` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENT_BYTES` | size | silent: `return` in `replacement_nodes` | `usize` | `262_144` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | output | silent: `return` in `append_inner_output`; `return` in `append_java_replacement`; `return` in `emit_nested_class_stubs`; 2 more | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `RECORD_ARITY_PROBE_CAP` | other | silent: `while` condition in `infer_record_arity` | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `REUSED_LOCAL_SPLIT_WORK_LIMIT` | work | silent: `return` in `claim_reused_local_split_work` | `usize` | `1_000_000` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_BLOCKS` | other | error: `StructureError::TooManyBlocks` | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_CONDITION_CHAIN` | other | silent: `return` in `short_circuit_merge`; `return` in `structure_condition_chain`; `while` condition in `loop_condition_chain` | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_JOIN_CHAIN` | other | silent: `break` in `continuation_joins`; `for` range in `goto_chain_end`; `for` range in `handler_join_after`; 1 more | `usize` | `8` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_STRUCTURE_DEPTH` | recursion | recorded: flag `had_irreducible` | `usize` | `256` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_STRUCTURE_WORK` | work | recorded: flag `had_irreducible` | `usize` | `200_000` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_BLOCKS` | other | silent: `return` in `duplicable_tail` | `usize` | `8` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_INSTRUCTIONS` | other | silent: `return` in `duplicable_tail` | `usize` | `64` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMENSIONS` | other | silent: `return` in `parse_one`; `return` in `type_descriptor_end` | `u8` | `255` | `crates/disrobe-pass-jvm/src/descriptor.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_ANNOTATION_DEPTH` | recursion | error: `SignatureSyntaxError`; `system_metadata_error()` | `usize` | `64` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_ANNOTATION_VALUES` | other | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `1_048_576` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_BYTES` | size | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_DIAGNOSTICS` | other | recorded: flag `suppressed_diagnostics` | `usize` | `256` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_NORMALIZATION_ROUNDS` | work | silent: `for` range in `normalize_system_metadata` | `usize` | `8` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_INNER_CLASS_DEPTH` | recursion | error: untyped error | `usize` | `64` | `crates/disrobe-pass-jvm/src/dex2jar.rs` |
| `disrobe-pass-jvm` | `MAX_STORED_FRAME_SLOTS` | other | recorded: `FrameInferOutcome::BudgetExceeded`; `note` | `usize` | `4 << 20` | `crates/disrobe-pass-jvm/src/frame_infer.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_DECODED_BYTES` | size | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_EDGES` | other | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_DEX_HIERARCHY_NODES` | count | error: `Error::BadBytecode` (DR-JVM-0025) | `usize` | `16_384` | `crates/disrobe-pass-jvm/src/hierarchy.rs` |
| `disrobe-pass-jvm` | `MAX_PREALLOC` | other | allocation: `with_capacity` in `read_zip_file` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_ENTRY_BYTES_CAP` | size | error: `Error::Zip` (DR-JVM-0011) | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_ENTRY_COUNT_CAP` | count | error: `Error::Zip` (DR-JVM-0011) | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `ZIP_TOTAL_BYTES_CAP` | size | error: `Error::Zip` (DR-JVM-0011) | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jar.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMS` | other | silent: `return` in `consume_field_type` | `usize` | `255` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_JNI_STRING_LEN` | size | silent: `return` in `is_jni_method_name`; `return` in `read_c_string` | `usize` | `512` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_INT_KEYS` | other | silent: `break` in `extract_static_int_keys` | `usize` | `4096` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIBS` | other | silent: `.take()` in `extract_static_int_keys` | `usize` | `128` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIB_BYTES` | size | silent: `continue` in `extract_static_int_keys` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_STUB_BYTES` | size | silent: `.min()` clamp in `bytes_at_address` | `usize` | `16` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_HANDLER_COVERAGE` | other | error: `TOO_LARGE` | `usize` | `4_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_DEPTH` | recursion | error: `TOO_DEEP` | `usize` | `64` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_OUTPUT` | output | error: `TOO_LARGE` | `usize` | `1_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_REMAP_WORK` | work | error: `TOO_LARGE` | `usize` | `64_000_000` | `crates/disrobe-pass-jvm/src/jsr_inline.rs` |
| `disrobe-pass-jvm` | `MAX_OAT_DEX_BYTES` | size | error: `out_of_range()` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-jvm/src/oat.rs` |
| `disrobe-pass-jvm` | `MAX_OAT_DEX_LOCATION_LEN` | size | error: `out_of_range()` | `usize` | `4096` | `crates/disrobe-pass-jvm/src/oat.rs` |
| `disrobe-pass-jvm` | `MAX_HIERARCHY_DEPTH` | recursion | silent: `return` in `resolve_field_with_inheritance`; `return` in `resolve_method_with_inheritance` | `usize` | `256` | `crates/disrobe-pass-jvm/src/proguard.rs` |
| `disrobe-pass-jvm` | `MAX_METHOD_INSNS` | other | silent: `return` in `unflatten_method` | `usize` | `200_000` | `crates/disrobe-pass-jvm/src/protectors/unflatten.rs` |
| `disrobe-pass-jvm` | `MAX_DISPATCH_RESOLVE_STEPS` | work | silent: `break` in `simplify_flattened_cfg` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/sccp.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_BYTES` | size | error: `.to_string()` | `usize` | `65_535` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_DEPTH` | recursion | error: `.error()` | `u16` | `64` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_ITEMS` | count | error: `.error()`; `.to_string()` | `usize` | `1_024` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_SIGNATURE_NODES` | count | error: `.error()` | `u32` | `4_096` | `crates/disrobe-pass-jvm/src/signature.rs` |
| `disrobe-pass-jvm` | `MAX_HEAP_OBJECTS` | other | error: `RecoveryError::HeapExhausted` | `usize` | `8_192` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `MAX_STRING_LEN` | size | error: `RecoveryError::BadShape` | `usize` | `65_536` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | error: `RecoveryError::StepLimitExceeded` | `u64` | `4_000_000` | `crates/disrobe-pass-jvm/src/string_recovery.rs` |
| `disrobe-pass-jvm` | `STEP_LIMIT` | work | error: `EmulationError::StepLimitExceeded` | `u64` | `2_000_000` | `crates/disrobe-pass-jvm/src/stub_emulator.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | error: `Error::ProtoNestingTooDeep` (DR-LUA-0025) | `usize` | `256` | `crates/disrobe-pass-lua/src/cursor.rs` |
| `disrobe-pass-lua` | `MAX_RESERVE_BYTES` | size | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/cursor.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_WORK` | work | error: `CoreError::PassFailure` (DR-CORE-0003); `Error::DecompileUnsupported` (DR-LUA-0020); `Error::PrometheusVmifyRefused` (DR-LUA-0029); 3 more | `u64` | `1 << 24` | `crates/disrobe-pass-lua/src/decompile/budget.rs` |
| `disrobe-pass-lua` | `MAX_INLINED_CLOSURE_BYTES` | size | recorded: `warnings`; flag `fully_structured` | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/decompile/lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | recorded: flag `fully_structured` | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | recorded: `warnings`; flag `fully_structured` | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/luajit_lift.rs` |
| `disrobe-pass-lua` | `MAX_DIRECT_RENDER_NESTING` | recursion | recorded: flag `refused` | `usize` | `256` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_LIFT_DEPTH` | recursion | recorded: `warnings`; flag `fully_structured` | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_RENDERED_STRUCTURE_BYTES` | output | recorded: flag `refused` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-lua/src/decompile/luau_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_VISITS_PER_NODE` | other | silent: `.min()` clamp in `for_nodes` | `usize` | `2` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_WORK` | work | silent: `.min()` clamp in `for_nodes` | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_RESERVED_NAME_SCAN` | other | silent: `return` in `names_referenced_by` | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_DEPTH` | recursion | silent: `return` in `lift_structured_captured` | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_NODES` | count | silent: `return` in `lift_structured_captured` | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `READ_SEARCH_STATE_BUDGET` | work | silent: `return` in `read_after_control_flow` | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_SCOPE_DEPTH` | recursion | silent: `return` in `block_captures_in_closure`; `return` in `block_mentions`; `return` in `declare_in_block`; 3 more | `usize` | `200` | `crates/disrobe-pass-lua/src/decompile/struct_lift/declare.rs` |
| `disrobe-pass-lua` | `MAX_CONDITION_CHAIN` | other | silent: `while` condition in `recover_short_circuit_chains` | `usize` | `64` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_EXIT_SCAN` | other | silent: `.take()` in `retarget_exits_through_skip_jumps` | `usize` | `4_096` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_BUILD_STEPS` | work | silent: `return` in `build` | `usize` | `4_096` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_REGION_INSTRUCTIONS` | other | silent: `return` in `build`; `while` condition in `region_bounds` | `usize` | `256` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_LOADER_DEPTH` | recursion | silent: `for` range in `peel` | `usize` | `16` | `crates/disrobe-pass-lua/src/obfuscator/hercules.rs` |
| `disrobe-pass-lua` | `IB_CONST_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_FUNCTION_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_INSTRUCTION_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `IB_LINEINFO_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/ironbrew2_real.rs` |
| `disrobe-pass-lua` | `MAX_LOC_CONSTANTS` | other | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1usize << 16` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_INSTRUCTIONS` | other | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1usize << 20` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_PROTOS` | other | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1usize << 16` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_LOC_STRING_BYTES` | size | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `16usize << 20` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | error: `Error::ProtoNestingTooDeep` (DR-LUA-0025) | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/luaobfuscator_com.rs` |
| `disrobe-pass-lua` | `LURAPH_SCAN_LIMIT` | other | silent: `.min()` clamp in `find_lua_assignment_value` | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_BOOTSTRAP_TABLE_VALUES` | other | silent: `return` in `parse_numeric_table_len` | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_LURAPH_EXPR_LEN` | size | silent: `return` in `rewrite_hex_literals` | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `CONSTANT_ARRAY_BUDGET` | work | error: `Error::LiftBudgetExceeded` (DR-LUA-0031); `Error::LimitExceeded` (DR-LUA-0027); `Error::other()`; 1 more | `ConstantArrayBudget` | `ConstantArrayBudget { max_source_bytes: crate::obfuscator::prometheus_vm_ast::MAX_SOURCE_BYTES, max_entries: MAX_CONSTANT_ARRAY_ENTRIES, max_decoded_bytes: MAX_CONSTANT_ARRAY_DECODED_BYTES, }` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_ARRAY_DECODED_BYTES` | size | error: `Error::LimitExceeded` (DR-LUA-0027); `limit_exceeded()` | `usize` | `4 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_ARRAY_ENTRIES` | count | error: `Error::LiftBudgetExceeded` (DR-LUA-0031); `Error::LimitExceeded` (DR-LUA-0027); `Error::other()` | `usize` | `1 << 14` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_NESTED_VMIFY_PASSES` | recursion | silent: `while` condition in `apply_vmify_devirt` | `usize` | `4` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `VMIFY_DISPATCH_SCAN_LIMIT` | other | silent: `return` in `matches_vmify_container_shape` | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_BLOCK_STATEMENTS` | other | error: `Error::DecompileUnsupported` (DR-LUA-0020) | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_LOCALS` | other | error: `Error::DecompileUnsupported` (DR-LUA-0020) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_NEST_DEPTH` | recursion | error: `Error::DecompileUnsupported` (DR-LUA-0020) | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_SOURCE_BYTES` | size | error: `Error::DecompileUnsupported` (DR-LUA-0020); `Error::LimitExceeded` (DR-LUA-0027); `limit_exceeded()`; 1 more | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_TOKENS` | other | error: `Error::DecompileUnsupported` (DR-LUA-0020) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_ast.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_EXPRESSION_DEPTH` | recursion | silent: `return` in `anti_tamper_value` | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_PROOF_STEPS` | work | error: `refuse()` | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_STATE_BINDINGS` | other | error: `refuse()` | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_BOX_STATEMENT_USES` | other | error: `refuse()` | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_BOX_STATE_BINDINGS` | other | error: `refuse()` | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_CONSTANT_POOL_RESOLVERS` | other | error: `refuse()` | `usize` | `8` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_DISPATCH_DEPTH` | recursion | error: `refuse()` | `u32` | `96` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_FUNCTIONS` | other | error: `refuse()` | `usize` | `1 << 10` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_FUNCTION_BLOCKS` | other | error: `refuse()` | `usize` | `1 << 14` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_LOOP_NESTING` | recursion | silent: `return` in `render_loop` | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_REACHABILITY_STEPS` | work | error: `refuse()` | `usize` | `1 << 18` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_RECOVERY_DEPTH` | recursion | error: `refuse()` | `usize` | `6` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_REGION_TREE_STEPS` | work | silent: `?` on a checked operation in `collect_region_nodes`; `?` on a checked operation in `loop_exit_tails`; `?` on a checked operation in `region_contains_node`; 1 more | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_SCRATCH_CHAIN_DEPTH` | recursion | silent: `return` in `resolve_and_expr`; `return` in `resolve_number_via_last_write` | `u32` | `12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_STATIC_NUMBER_DEPTH` | recursion | silent: `return` in `evaluate_at_depth` | `usize` | `32` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_STATIC_NUMBER_FUEL` | work | delegated: passed to `.set` | `usize` | `1 << 12` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | other | silent: `return` in `analyze_dispatch` | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `MAX_FOLD_TOKENS` | other | silent: `return` in `fold_one_expression`; `return` in `try_fold_span` | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `NUMERIC_EXPR_BUDGET` | work | error: `Error::DecompileUnsupported` (DR-LUA-0020) | `usize` | `1 << 24` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `MAX_DECOMPRESSED` | other | error: `Error::Io` (DR-LUA-0001); `Error::LiftBudgetExceeded` (DR-LUA-0031); `Error::LimitExceeded` (DR-LUA-0027); 1 more | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | error: `Error::ProtoNestingTooDeep` (DR-LUA-0025) | `usize` | `200` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_CODE_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_CONSTANT_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_LINE_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_LOCAL_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_PROTO_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_UPVALUE_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `MAX_SLUA_UPVALUE_NAME_COUNT` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `U32_FIELD_LIMIT` | other | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `u32::MAX as usize` | `crates/disrobe-pass-lua/src/obfuscator/slua.rs` |
| `disrobe-pass-lua` | `BASE64_PAYLOAD_CHAR_CAP` | other | silent: `return` in `decode_base64_payload_run` | `usize` | `(LUA_STRING_PAYLOAD_CAP / 3) * 4 + 8` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `BOOTSTRAP_SCAN_LIMIT` | other | silent: `.min()` clamp in `find_lua_assignment_value`; `while` condition in `extract_named_lua_byte_buffer` | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `EMBEDDED_PAYLOAD_SCAN_LIMIT` | other | silent: `.min()` clamp in `extract_lua_string_payload` | `usize` | `8 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `LUA_STRING_PAYLOAD_CAP` | other | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `LUA_TABLE_PAYLOAD_CAP` | other | silent: `return` in `decode_lua_byte_table` | `usize` | `16 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `PB_STACK_LIMIT` | other | error: `Error::BootstrapEmulationFailed` (DR-LUA-0026) | `usize` | `256` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `PB_STEP_LIMIT` | work | error: `Error::BootstrapEmulationFailed` (DR-LUA-0026) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `VM_CODE_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `VM_CONST_COUNT_CAP` | count | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `1 << 20` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `DISPATCH_BLOCK_LIMIT` | other | silent: `break` in `lift_dispatch` | `usize` | `4096` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_GUARD_LIMIT` | other | silent: `break` in `collect_threshold_cuts` | `usize` | `256` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_PARSE_DEPTH_LIMIT` | recursion | silent: `return` in `parse_dispatch_node` | `usize` | `512` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | other | silent: `.min()` clamp in `lift_dispatch` | `usize` | `256 * 1024` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `INT_VARINT_LIMIT` | other | error: `Error::VarintOverflow` (DR-LUA-0032) | `u64` | `i32::MAX as u64` | `crates/disrobe-pass-lua/src/reader/lua55.rs` |
| `disrobe-pass-lua` | `MAX_MATERIALIZED_STRING_BYTES` | size | error: `Error::LimitExceeded` (DR-LUA-0027) | `usize` | `64 << 20` | `crates/disrobe-pass-lua/src/reader/lua55.rs` |
| `disrobe-pass-lua` | `MAX_ASSEMBLED_NODES` | count | error: `Error::LuauOpcodeMap` (DR-LUA-0030) | `usize` | `1 << 16` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_BUILD_ID_BYTES` | size | error: `Error::LuauOpcodeMap` (DR-LUA-0030) | `usize` | `128` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_OPCODE_MAP_BYTES` | size | error: `Error::LuauOpcodeMap` (DR-LUA-0030) | `u64` | `64 << 10` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-lua` | `MAX_PROTO_DEPTH` | recursion | error: `Error::LuauOpcodeMap` (DR-LUA-0030) | `usize` | `200` | `crates/disrobe-pass-lua/src/reader/luau.rs` |
| `disrobe-pass-mobile` | `MAX_EMBEDDED_DEX_CARVES` | other | silent: `while` condition in `collect_plain_dex_carves`; `while` condition in `collect_xor_dex_carves` | `usize` | `16` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_PROTECTOR_CARVE_SCAN` | other | silent: skipped in `analyze`; skipped in `extract_android_dex_children` | `u64` | `64 << 20` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_RESOLVED_RESOURCES` | other | silent: `break` in `summarise_arsc` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_TEXT_ASSET` | other | silent: skipped in `analyze` | `u64` | `16 << 20` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_CERTS_PER_SIGNER` | other | silent: `break` in `parse_signer` | `usize` | `256` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_DIGESTS_PER_SIGNER` | other | silent: `break` in `parse_signer` | `usize` | `256` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_PAIRS` | other | silent: `break` in `parse_id_value_pairs` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_SIGNERS` | other | silent: `break` in `parse_scheme` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_STRINGS` | other | error: `Error::ArscTruncated` (DR-MOB-0029) | `u32` | `1 << 22` | `crates/disrobe-pass-mobile/src/arsc.rs` |
| `disrobe-pass-mobile` | `MAX_TYPE_ENTRIES` | count | error: `Error::ArscTruncated` (DR-MOB-0029) | `u32` | `1 << 20` | `crates/disrobe-pass-mobile/src/arsc.rs` |
| `disrobe-pass-mobile` | `MAX_DEPTH` | recursion | error: `Error::AxmlTruncated` (DR-MOB-0026) | `usize` | `512` | `crates/disrobe-pass-mobile/src/axml.rs` |
| `disrobe-pass-mobile` | `TRAVERSAL_INSN_BUDGET` | work | silent: `break` in `traverse` | `usize` | `1 << 22` | `crates/disrobe-pass-mobile/src/flutter/arm64_traversal.rs` |
| `disrobe-pass-mobile` | `MAX_BOOLEAN_RETURN_INSTRUCTIONS` | other | silent: `return` in `recover_boolean_return` | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_SETUP_INSTRUCTIONS` | other | silent: `?` on a checked operation in `skip` | `usize` | `8` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_TRACE_INSTRUCTIONS` | other | silent: `?` on a checked operation in `skip` | `usize` | `256` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_CONSUMED_TEXT_BYTES` | size | silent: skipped in `consumed_text` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FLOAT_RETURN_SPILL_DISTANCE` | other | silent: `?` on a checked operation in `skip` | `usize` | `3` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FRAME_SLOTS` | other | silent: `return` in `record_frame` | `usize` | `128` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_MERGE_PREDECESSORS` | other | silent: `return` in `entry_state` | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_STACK_ARGUMENTS` | other | silent: `return` in `record_stack`; `return` in `stack_arguments` | `usize` | `32` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_CALLS` | other | silent: `break` in `track_call_sites` | `usize` | `1 << 14` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_EFFECTS` | other | silent: `return` in `define`; skipped in `bookkeeping`; skipped in `step` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_DEPTH` | recursion | silent: `return` in `render_value` | `usize` | `6` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_NODES` | count | silent: `?` on a checked operation in `node_budget` | `usize` | `48` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `CLUSTER_TAG_SCAN_LIMIT` | other | silent: `.min()` clamp in `scan_cid_tags` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/cluster.rs` |
| `disrobe-pass-mobile` | `MAX_CODE_TABLE_ENTRIES` | count | error: `Error::DartCodeTableUnavailable` (DR-MOB-0048) | `usize` | `1 << 22` | `crates/disrobe-pass-mobile/src/flutter/code_table.rs` |
| `disrobe-pass-mobile` | `HARD_CLUSTER_LIMIT` | other | error: `DartPoolUnresolvedReason::ClusterBodyUnmodelled`; `DartPoolUnresolvedReason::DeclaredNameMissing`; `DartPoolUnresolvedReason::ImmediateMissing`; 18 more | `usize` | `4096` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_OBJECT_LIMIT` | other | error: `DartPoolUnresolvedReason::ObjectOutOfRange`; `DartPoolUnresolvedReason::TypeArgumentsMalformed`; `DartPoolUnresolvedReason::TypeFlagsMissing`; 2 more | `usize` | `2_000_000` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_REFERENCE_LIMIT` | other | error: `DartPoolUnresolvedReason::Cyclic`; `DartPoolUnresolvedReason::DeclaredNameMissing`; `DartPoolUnresolvedReason::ObjectOutOfRange`; 7 more | `usize` | `16_000_000` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_STRING_CODE_UNIT_LIMIT` | other | error: `Error::DartGraphConfiguredLimitExceeded` (DR-MOB-0044); `Error::DartGraphLimitExceeded` (DR-MOB-0035) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_TOTAL_STRING_BYTE_LIMIT` | size | error: `Error::DartGraphConfiguredLimitExceeded` (DR-MOB-0044); `Error::DartGraphLimitExceeded` (DR-MOB-0035) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `HARD_VARIABLE_LENGTH_LIMIT` | size | error: `Error::DartGraphConfiguredLimitExceeded` (DR-MOB-0044); `Error::DartGraphInvalidClusterValue` (DR-MOB-0037); `Error::DartGraphLimitExceeded` (DR-MOB-0035) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_SLOTS` | other | silent: skipped in `fill_object_pools` | `usize` | `1 << 21` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `FEATURE_STRING_CAP` | other | error: `Error::DartGraphInvalidHeader` (DR-MOB-0047) | `usize` | `4096` | `crates/disrobe-pass-mobile/src/flutter/dart_graph_recovery.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_INSNS` | other | silent: `while` condition in `disassemble_function`; `while` condition in `disassemble_range` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/disasm.rs` |
| `disrobe-pass-mobile` | `MEMBER_TABLE_CAP` | other | silent: `return` in `member_table_from_count`; `return` in `parse` | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/flutter/kernel.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_LITERALS` | work | silent: `break` in `resolve_pool_literals`; `while` condition in `resolve_pool_literals` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_RUN_PROBE` | other | silent: `while` condition in `pool_run_length` | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `POOL_DECODE_BUDGET` | work | silent: `.min()` clamp in `recover_object_pool_references` | `usize` | `1 << 24` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_LIST_ELEMENTS` | other | error: `DartPoolUnresolvedReason::TypeArgumentsMalformed` | `usize` | `8` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_CHARS` | work | error: `DartPoolUnresolvedReason::TextTooLong` | `usize` | `120` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_DEPTH` | recursion | error: `DartPoolUnresolvedReason::DepthExceeded` | `usize` | `4` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_LITERAL_NODES` | work | error: `DartPoolUnresolvedReason::NodeBudgetExhausted` | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/pool_table.rs` |
| `disrobe-pass-mobile` | `MAX_DART_IDENTIFIER_BYTES` | size | recorded: flag `current_overlong` | `usize` | `1 << 14` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_DART_IDENTIFIER_COUNT` | count | silent: `break` in `extract_dart_identifiers`; skipped in `flush_identifier` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_BOUNDARIES` | other | silent: `while` condition in `scan_function_boundaries` | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_STRING_CHARS` | other | silent: `continue` in `scan_one_byte_strings` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/flutter/string_pool.rs` |
| `disrobe-pass-mobile` | `MAX_ALLOCATOR_WORDS` | other | silent: `for` range in `allocate_object_helper_inputs` | `usize` | `64` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_REGISTER_SAVES` | other | silent: `return` in `stub_frame_entry` | `usize` | `32` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_STUB_ARGUMENT_STEPS` | work | silent: `for` range in `runtime_call_stub` | `usize` | `16` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_TAG_WORDS` | other | silent: `return` in `allocation_stub_for_class` | `usize` | `4` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_DECIMAL_BYTES` | size | silent: fallback value in `bigint_literal` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/bigint.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_INSTRUCTIONS` | other | silent: `while` condition in `decode_instructions` | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_BYTES` | size | silent: no action in `closure_expr` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_DEPTH` | recursion | silent: `return` in `inlined_closure_bodies` | `usize` | `8` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_REG_EXPR_BYTES` | size | silent: no action in `set_reg` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDERED_CALL_ARGS` | output | silent: `.min()` clamp in `unrecovered_arg_list`; `return` in `call_window_registers` | `u64` | `256` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDER_BYTES` | output | silent: `break` in `render_block_stmts`; `break` in `render_structured` | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_SWITCH_CASES` | other | silent: `return` in `switch_table_entries` | `u64` | `4096` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_LITERALS` | work | silent: `return` in `decode_literals`; `while` condition in `decode_literals` | `usize` | `1 << 20` | `crates/disrobe-pass-mobile/src/hermes/literals.rs` |
| `disrobe-pass-mobile` | `MAX_REGEX_DEPTH` | recursion | recorded: flag `fully_modeled` | `usize` | `512` | `crates/disrobe-pass-mobile/src/hermes/regex.rs` |
| `disrobe-pass-mobile` | `MAX_REGEX_INSNS` | other | silent: `while` condition in `decode_body`; `while` condition in `render_range_inner` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/regex.rs` |
| `disrobe-pass-mobile` | `MAX_LOOP_EXTENSION_ROUNDS` | work | silent: `for` range in `extend_loop_body` | `usize` | `64` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_LOWERED_LOOPS` | work | error: `StructureDecline::BlockBudgetExceeded` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_REGION_DEPTH` | recursion | error: `StructureDecline::DepthExceeded` | `usize` | `64` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_STRUCTURE_BLOCKS` | other | error: `StructureDecline::BlockBudgetExceeded` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_STRUCTURE_STATEMENTS` | other | error: `StructureDecline::StatementBudgetExceeded` | `usize` | `1 << 16` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MACHO_FAT_ARCH_COUNT_CAP` | count | error: `Error::MachOFatTooManyArches` (DR-MOB-0031) | `usize` | `4096` | `crates/disrobe-pass-mobile/src/ios.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_COUNT_CAP` | count | error: `Error::Zip` (DR-MOB-0002) | `usize` | `65_536` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_PREALLOC_CAP` | other | unused: no use in the crate | `usize` | `64 << 20` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `ZIP_ENTRY_READ_CAP` | other | error: `Error::Zip` (DR-MOB-0002) | `usize` | `512 << 20` | `crates/disrobe-pass-mobile/src/lib.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_XML` | other | silent: `break` in `decode_archive` | `usize` | `4096` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-mobile` | `MAX_VALUES_ENTRIES` | count | silent: `break` in `reconstruct_values` | `usize` | `16384` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_INSNS` | other | silent: `break` in `harvested_hash_constants` | `usize` | `200_000` | `crates/disrobe-pass-native/src/api_hash.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_DEPTH` | recursion | silent: `while` condition in `build_chain` | `usize` | `12` | `crates/disrobe-pass-native/src/authenticode.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | silent: `return` in `build_cfg`; `return` in `collect_leaders` | `usize` | `256` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `return` in `build_block`; `return` in `collect_leaders` | `usize` | `1024` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_FUNCTIONS` | other | silent: `return` in `native_pseudo_report` | `usize` | `256` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_IMAGE_BYTES` | size | silent: `return` in `native_pseudo_report` | `usize` | `1024 * 1024` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_REPORT_BYTES` | size | silent: no action in `build_image_children` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_X86_INSTRUCTION_BYTES` | size | silent: slice in `is_import_thunk` | `usize` | `15` | `crates/disrobe-pass-native/src/code_symbol.rs` |
| `disrobe-pass-native` | `MAX_ITANIUM_ACTION_STEPS` | work | error: untyped error | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_ITANIUM_LSDA_ENTRIES` | count | error: `Error::Dwarf` (DR-NATIVE-0006); untyped `format!` | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_WINDOWS_SEH_SCOPE_ENTRIES` | count | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `65_536` | `crates/disrobe-pass-native/src/cxx_recovery.rs` |
| `disrobe-pass-native` | `MAX_AGGREGATE_BYTES` | size | error: `PdbProvenanceError::AggregateLimit` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_IPI_RECORDS` | count | error: `PdbProvenanceError::IpiRecordLimit` | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_MODULES` | other | error: `PdbProvenanceError::ModuleLimit` | `usize` | `65_536` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_MODULE_SYMBOLS` | other | error: `PdbProvenanceError::ModuleSymbolLimit` | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_RESOLVED_STRING_BYTES` | size | error: `PdbProvenanceError::ResolvedStringLimit` | `usize` | `1024 * 1024` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_SUBSTRING_DEPTH` | recursion | error: `PdbProvenanceError::SubstringDepth` | `usize` | `64` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_SUBSTRING_REFERENCES` | other | error: `PdbProvenanceError::SubstringReferenceLimit`; `PdbProvenanceError::SubstringTraversalLimit` | `usize` | `16_384` | `crates/disrobe-pass-native/src/debug_info/pdb_provenance.rs` |
| `disrobe-pass-native` | `MAX_DEPTH` | recursion | silent: `return` in `process_value`; `return` in `read_object`; `return` in `read_prop_list` | `usize` | `512` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `MAX_OBJECTS` | other | silent: `return` in `read_object` | `usize` | `200_000` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_BYTES` | output | recorded: flag `capped` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `BYTE_SCAN_LIMIT` | size | silent: slice in `identify`; slice in `scan_window` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_SHORTSTRING_LEN` | size | silent: `return` in `is_plausible_symbol_of_length`; `return` in `read_shortstring` | `usize` | `255` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_STUB_BYTES` | size | silent: slice in `entry_stub_addresses` | `usize` | `256` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_STUB_INSTRUCTIONS` | other | silent: `while` condition in `entry_stub_addresses` | `usize` | `48` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_UNITS` | other | silent: `return` in `parse_at` | `i32` | `8192` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_ENTRIES` | count | silent: `.min()` clamp in `entry_count` | `u32` | `8192` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_NAME_CHARS` | other | silent: `.min()` clamp in `read_res_name` | `usize` | `512` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCES` | other | silent: `return` in `walk_langs`; `return` in `walk_names`; `return` in `walk_types` | `usize` | `8192` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_SCAN_POSITIONS` | other | silent: `break` in `scan` | `usize` | `16_000_000` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRINGS` | other | silent: `break` in `scan` | `usize` | `65_536` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_UNITS` | other | silent: `return` in `read_candidate` | `u32` | `1 << 20` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_METHODS` | other | silent: `return` in `parse_dynamic_table` | `u16` | `4096` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELDS_PER_CLASS` | other | silent: `return` in `parse_field_table` | `u16` | `4096` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELD_CLASSES` | other | silent: `return` in `field_class_candidates` | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_INTERFACES` | other | silent: `return` in `parse_interface_table` | `i32` | `1024` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_ENUM_MEMBERS` | count | silent: `return` in `fill_enumeration` | `i64` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_FIELD_VISIBILITY` | other | silent: `return` in `parse_record_fields` | `u8` | `3` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_MANAGED_FIELDS` | other | silent: `return` in `fill_record` | `i32` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_FIELDS` | other | silent: `return` in `parse_record_fields` | `i32` | `4096` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_OPERATORS` | other | unclassified: stored in `record_fields` with no read found | `u8` | `64` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_SIZE` | size | silent: `return` in `fill_record` | `i32` | `1 << 20` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_PATH_TAIL` | other | silent: slice in `scan_toolchain_paths` | `usize` | `16` | `crates/disrobe-pass-native/src/delphi/version.rs` |
| `disrobe-pass-native` | `MAX_CLASSES` | other | recorded: flag `scan_truncated` | `usize` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_INSTANCE_SIZE` | size | silent: `return` in `validate_class` | `u32` | `0x0100_0000` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_METHODS_PER_CLASS` | other | silent: `.min()` clamp in `parse_method_table` | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PARENT_DEPTH` | recursion | silent: `break` in `accumulate` | `usize` | `64` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PROPS_PER_CLASS` | work | silent: `.min()` clamp in `parse_typeinfo` | `u16` | `8192` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_SCAN_POSITIONS` | other | recorded: flag `scan_truncated` | `usize` | `8_000_000` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_TYPE_RECORDS` | count | silent: `.take()` in `describe_types` | `usize` | `16384` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/abi.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/bcf_dse.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/branchfold.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | silent: `return` in `carve_blocks` | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_DISPATCH_TREE_STEPS` | work | silent: `break` in `compare_chain_blocks`; `return` in `model_compare_tree`; `while` condition in `enqueue_jump_table_targets`; 1 more | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_INSNS` | other | silent: `return` in `build_program`; `return` in `recursive_decode` | `usize` | `200_000` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_DEPTH` | recursion | silent: `return` in `walk` | `u32` | `128` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_STEPS` | work | silent: `return` in `walk` | `u32` | `4096` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_RESOLVE_DEPTH` | recursion | silent: `return` in `resolve_loc` | `u32` | `4` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/copyprop.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/deadflags.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_TABLE_ENTRIES` | count | silent: `.min()` clamp in `read_pic_table`; `.min()` clamp in `read_table`; `while` condition in `read_pic_table`; 1 more | `u64` | `4096` | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_EXPR_NODES` | count | recorded: flag `capped` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/mba_lift.rs` |
| `disrobe-pass-native` | `MAX_LIFT_INSNS` | other | silent: `return` in `lift_arith_value`; `return` in `lift_operand_pair` | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/mba_lift.rs` |
| `disrobe-pass-native` | `MAX_CONSTRAINTS` | other | recorded: `WallReason::ConstraintBudgetExceeded` | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `8192` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_FEASIBILITY_EVALS` | other | recorded: `WallReason::NonExhaustibleDomain` | `u128` | `1 << 24` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_FEASIBILITY_VARS` | other | recorded: `WallReason::VariableBudgetExceeded` | `u32` | `3` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_PATH_BLOCKS` | other | silent: `return` in `walk` | `usize` | `256` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | other | silent: `return` in `build_block`; `return` in `collect_leaders` | `usize` | `256` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `4096` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_JOINS` | other | silent: `return` in `summarize_region` | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_LOOPS` | work | silent: `for` range in `unroll_natural_loops` | `usize` | `1` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_REGISTERS` | output | silent: `return` in `finalize_summary` | `usize` | `32` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_STACK_CELLS` | output | silent: `return` in `finalize_summary` | `usize` | `32` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_BLOCKS` | other | silent: `return` in `build_region`; `return` in `collect_leaders` | `usize` | `64` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_INSNS` | other | silent: `return` in `build_region` | `usize` | `2048` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLL` | other | silent: `break` in `rs_emit_range`; `continue` in `forward_join_lowering_candidates`; `continue` in `prove_one`; 34 more | `usize` | `8` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLLED_BLOCKS` | other | silent: `return` in `unroll_one` | `usize` | `512` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `VERIFY_ARITY_CAP` | other | silent: `return` in `densify` | `u32` | `12` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DIRECT_CALL_SWEEP_OFFSETS` | other | silent: `.min()` clamp in `add_linear_call_evidence`; `.min()` clamp in `sweep_direct_call_target_evidence`; `break` in `add_linear_call_evidence`; 1 more | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_DISCOVERY_FUNCTIONS` | other | delegated: passed to `unwind::visit_frame_ranges` | `usize` | `1 << 18` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_INTERIOR_PROLOGUE_PROVENANCE` | other | silent: skipped in `traverse_function` | `usize` | `MAX_DISCOVERY_FUNCTIONS` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_JUMP_TABLE_ENTRIES` | count | silent: `while` condition in `resolve_jump_table` | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_NORETURN_DECODED_INSTRUCTIONS` | other | recorded: `NoreturnCandidates::Exhausted`; `NoreturnFunctionOutcome::Exhausted` | `usize` | `262_144` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_NORETURN_ITERATIONS` | work | silent: `for` range in `noreturn_closure` | `usize` | `64` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_BACKWARD_DISTANCE` | other | silent: `return` in `direct_call_target` | `u64` | `1_u64 << 31` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_FORWARD_DISTANCE` | other | silent: `return` in `direct_call_target` | `u64` | `(1_u64 << 31) - 1` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_BOUNDARY_PADDING_BYTES` | size | silent: `return` in `is_alignment_boundary` | `u64` | `64` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_DECODE_TEXT_BYTES` | size | error: `.to_owned()`; `AuthenticodeVerdict::MalformedSignature`; `CompactUnwindError::Address`; 21 more | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_PAYLOAD_INSTRUCTIONS` | other | error: `.to_owned()`; `AuthenticodeVerdict::MalformedSignature`; `CompactUnwindError::Address`; 21 more | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_AARCH64_PLT_ENTRIES` | count | silent: `for` range in `collect_elf_plt_entries` | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_EXECUTABLE_RANGES` | other | silent: `break` in `new`; `return` in `new_pe64` | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_GUARD_CF_FUNCTIONS` | other | silent: `.min()` clamp in `decode_pe_arm64_guard_cf_functions` | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_TLS_CALLBACKS` | other | silent: `for` range in `decode_pe_arm64_tls_callbacks` | `usize` | `1 << 12` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_POINTER_SLOTS` | other | silent: `break` in `collect_data_pointers`; `return` in `collect_initializer_tables` | `usize` | `1 << 21` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_SEEDS` | other | silent: `break` in `aarch64_boundary_prologue_seeds`; `break` in `aarch64_gap_boundary_prologue_seeds`; `return` in `aarch64_boundary_prologue_seeds`; 3 more | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_UNWIND_ENTRIES` | count | error: `CompactUnwindError::Index`; `CompactUnwindError::Limit` | `usize` | `1 << 17` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_ENTRIES` | count | silent: `while` condition in `read_dynamic_entries` | `usize` | `16 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_ELF_PROGRAM_HEADERS` | other | silent: `return` in `is_well_formed_elf_executable`; `return` in `validate_section_table` | `usize` | `1_000_000` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_GNU_HASH_BUCKETS` | other | silent: `return` in `gnu_hash_symbol_count` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_NEEDED` | other | silent: `.min()` clamp in `read_pointer_array`; `continue` in `analyze` | `usize` | `4096` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_RELOCATIONS` | other | silent: `return` in `read_rel`; `return` in `read_rela` | `usize` | `512 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_STRING_BYTES` | size | silent: `.min()` clamp in `read_interpreter`; `.min()` clamp in `resolve_dynstr` | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_SYMBOLS` | other | silent: `.min()` clamp in `bounded_symbol_scan`; `.min()` clamp in `read_dynamic_symbols`; `return` in `gnu_hash_symbol_count`; 2 more | `usize` | `256 * 1024` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `4096` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_BUFFERS_PER_CANDIDATE` | other | silent: `.take()` in `emulate_string_decoders_inner` | `usize` | `24` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_CANDIDATES` | other | silent: `.take()` in `emulate_string_decoders_inner` | `usize` | `64` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_DECODE_SPAN` | other | silent: `.min()` clamp in `emulate_string_decoders_inner` | `u64` | `64 * 1024` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_PER_RUN` | other | silent: `break` in `merge_harvests`; `return` in `harvest_ascii`; `return` in `harvest_utf16`; 3 more | `usize` | `512` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_LEN` | size | silent: `return` in `insert_static_run`; `return` in `push_candidate`; `return` in `push_wide_candidate` | `usize` | `4096` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `PER_CANDIDATE_STEP_CAP` | work | silent: `break` in `run` | `u64` | `200_000` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_ENTROPY_BITS` | other | silent: `.clamp()` clamp in `normalized_entropy` | `f64` | `8.0` | `crates/disrobe-pass-native/src/entropy_viz.rs` |
| `disrobe-pass-native` | `OVERLAY_SCAN_CAP` | other | recorded: `.record()` | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/fileid.rs` |
| `disrobe-pass-native` | `LIBRARY_NAME_CAP` | other | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `1024` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BODY` | other | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_PATTERN_LEN` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `u8` | `64` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `MAX_TREE_DEPTH` | recursion | error: `Error::SignatureDb` (DR-NATIVE-0019) | `u32` | `256` | `crates/disrobe-pass-native/src/flirt.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | other | silent: slice in `bytes_find` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/identify.rs` |
| `disrobe-pass-native` | `NATIVE_MATCH_DEFAULT_LIMIT` | other | unused: no use in the crate | `usize` | `DEFAULT_LISTING_LIMIT` | `crates/disrobe-pass-native/src/native_match.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_IMPORTS_PER_MODULE` | other | recorded: flag `overflowed` | `usize` | `256` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_IMPORT_DESCRIPTORS` | other | silent: `break` in `find_aspack_runtime_import_directory`; `return` in `find_aspack_runtime_import_directory`; `return` in `reconstruct_aspack_import_descriptors` | `usize` | `64` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_MODULE_NAME_LEN` | size | silent: `continue` in `collect_aspack_import_layouts`; `for` range in `read_guest_cstr`; `return` in `reconstruct_aspack_import_descriptors` | `usize` | `260` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_THUNK_CANDIDATES` | other | silent: `return` in `find_unique_thunk_tables` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/emulated_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_cca.rs` |
| `disrobe-pass-native` | `OUTPUT_CAP` | output | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_k7_cm.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/kkrunchy_phase2.rs` |
| `disrobe-pass-native` | `MAX_DECODED_SIZE` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/kkrunchy_unpack.rs` |
| `disrobe-pass-native` | `MAX_RECOVERED_BYTES` | size | error: `donut_module_error()`; `loader_error()` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/loader_generators.rs` |
| `disrobe-pass-native` | `MAX_MEW_LEADING_CHUNKS` | other | unclassified: stored in `max_entries` with no read found | `usize` | `64` | `crates/disrobe-pass-native/src/packers/mew_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_POS_BITS` | other | silent: fallback value in `decode_bit` | `usize` | `4` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_POS_STATES` | other | silent: fallback value in `decode_bit` | `usize` | `1 << MAX_POS_BITS` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_IMAGE_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/mpress_unpack.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_IMPORTED_MODULES` | other | silent: `break` in `locate_import_record`; `while` condition in `locate_import_descriptors` | `usize` | `96` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_IMPORTS_PER_MODULE` | other | silent: `break` in `locate_import_record` | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_MODULE_NAME_BYTES` | size | silent: slice in `module_name_is_plausible` | `usize` | `96` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_DEPTH` | recursion | error: `Error::LoaderRecovery` (DR-NATIVE-0026); untyped `format!` | `usize` | `8` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_DIRECTORIES` | other | error: `Error::LoaderRecovery` (DR-NATIVE-0026); untyped `format!` | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_ENTRIES_PER_DIRECTORY` | count | error: `Error::LoaderRecovery` (DR-NATIVE-0026); untyped `format!` | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_GAP_SEARCH_BYTES` | size | silent: `return` in `forced_leaf_placements` | `u32` | `1 << 22` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_LEAVES` | other | error: `Error::LoaderRecovery` (DR-NATIVE-0026); untyped `format!` | `usize` | `16384` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_RECOVERED_IMAGE_BYTES` | size | error: `Error::LoaderRecovery` (DR-NATIVE-0026); untyped `format!` | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCE_DEPTH` | recursion | silent: `return` in `walk_resource_dir` | `u32` | `8` | `crates/disrobe-pass-native/src/packers/pe_unbind.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/pecompact_phase2.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `16_384` | `crates/disrobe-pass-native/src/packers/petite_phase2.rs` |
| `disrobe-pass-native` | `EMULATED_IMAGE_EXPANSION_LIMIT` | other | recorded: flag `int3_gauntlet_cleared` | `u64` | `4096` | `crates/disrobe-pass-native/src/packers/section_recovery.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | silent: `return` in `decode_elf_extents_with_budget`; `return` in `walk_block_chain` | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_BRUTE_FORCE_OFFSETS` | other | silent: `.min()` clamp in `decode_image_with_budget`; `.min()` clamp in `decode_multiblock_with_budget`; `.min()` clamp in `locate_structural` | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSED` | other | error: `.clone()`; `.to_owned()`; `AddressError::RvaNotMapped`; 69 more | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_DECOMPRESSION_ATTEMPTS` | other | error: `.clone()`; `.to_owned()`; `AddressError::RvaNotMapped`; 69 more | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_L_INFO_SCAN` | other | silent: `.min()` clamp in `elf_first_block_offset` | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_RESYNC_OFFSETS` | other | silent: `while` condition in `decode_elf_extents_with_budget` | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_STRUCTURAL_CHECKSUM_BYTES` | size | silent: `return` in `reserve` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_TAIL_SCAN` | other | error: `Error::UpxDecode` (DR-NATIVE-0022) | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_TOTAL_DECOMPRESSED_OUTPUT` | output | error: `.clone()`; `.to_owned()`; `AddressError::RvaNotMapped`; 69 more | `usize` | `MAX_DECOMPRESSED * 2` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_VERIFY_CANDIDATES` | other | silent: `break` in `locate_structural` | `usize` | `4096` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_VERIFY_EXPANSION` | other | error: `Error::UpxDecode` (DR-NATIVE-0022) | `u64` | `64` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_CARVED_PROTECTED_BYTES` | size | recorded: flag `blob_truncated` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-native/src/packers/vmprotect_carve.rs` |
| `disrobe-pass-native` | `MAX_CARVED_PROTECTED_SECTIONS` | other | silent: `.take()` in `carve_themida`; `.take()` in `carve_vmprotect` | `usize` | `64` | `crates/disrobe-pass-native/src/packers/vmprotect_carve.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `131_072` | `crates/disrobe-pass-native/src/packers/yodas_crypter.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/yodas_emulated_unpack.rs` |
| `disrobe-pass-native` | `EMU_LAZY_PAGE_BUDGET` | work | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u32` | `65_536` | `crates/disrobe-pass-native/src/packers/yodas_protector_phase2.rs` |
| `disrobe-pass-native` | `ADDRESS_SPACE_CAP` | other | silent: `return` in `flatten_address_space` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `DEOBF_SECTION_CAP` | other | silent: `.min()` clamp in `executable_sections` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `MAX_TYPE_RECORDS` | count | error: `Error::Pdb` (DR-NATIVE-0007) | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/pdb_cxx/catalog.rs` |
| `disrobe-pass-native` | `MAX_FIELDLIST_CHAIN` | other | silent: `for` range in `collect_fieldlist` | `usize` | `256` | `crates/disrobe-pass-native/src/pdb_cxx/emit.rs` |
| `disrobe-pass-native` | `MAX_MODULES` | other | silent: `continue` in `recover_module_procedures` | `usize` | `65_536` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_PARAMETERS` | other | error: `FunctionRejectReason::Malformed` | `usize` | `4_096` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_PROCEDURES` | other | silent: `continue` in `recover_module_procedures` | `usize` | `262_144` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_SYMBOLS_PER_MODULE` | other | recorded: flag `modules_truncated_at_symbol_bound` | `usize` | `4_000_000` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_RECURSION_BUDGET` | recursion | silent: `return` in `resolve_spelling_bounded` | `u32` | `24` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_UNWRAP_DEPTH` | recursion | silent: `for` range in `resolve_spelling_bounded` | `u32` | `64` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_NAME_BYTES` | size | silent: `return` in `resolve_macho_stub_imports` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_STUBS` | other | silent: `return` in `resolve_macho_stub_imports` | `usize` | `65_536` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SCANNED_NAME_BYTES` | size | silent: `return` in `resolve_macho_stub_imports`; slice in `resolve_macho_stub_imports` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SYMBOL_NAME_BYTES` | size | silent: slice in `resolve_macho_stub_imports` | `usize` | `4 * 1024` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `AARCH64_STACK_FP_ALIAS_LIMIT` | other | error: `Error::LlvmIr` (DR-NATIVE-0018) | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `ACYCLIC_JOIN_BLOCK_CAP` | other | silent: `return` in `acyclic_join_lowering_plan`; `return` in `join_plan_preserves_blocks` | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `FORWARD_JOIN_PLAN_CAP` | other | silent: `return` in `forward_join_lowering_candidates` | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `LOOP_EXIT_TAIL_ABSORPTION_BUDGET` | work | silent: `for` range in `absorb_private_exit_tails` | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_BYTES` | size | silent: `return` in `local_noreturn_leaf_is_proven`; `return` in `outlined_noreturn_exit` | `usize` | `1024` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_CALLEES` | other | silent: `continue` in `object_transfer_facts`; skipped in `object_transfer_facts` | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_RELOCATIONS` | other | silent: `.take()` in `read`; `return` in `read` | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_OUTLINED_EXIT_SLOTS` | other | silent: `return` in `outlined_noreturn_exit` | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_PROGRAM_FUNCTION_BYTES` | size | delegated: passed to `debug::dbg_line` | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `PURE_TAIL_CLONE_BUDGET` | work | silent: `for` range in `emit_cloned_pure_tail` | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_LABEL_CAP` | other | silent: `return` in `rs_forward_exit_labels`; `return` in `rs_resume_paths` | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_NODE_CAP` | other | silent: `return` in `rs_forward_exit_labels`; `return` in `rs_resume_paths` | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_JOIN_WALK_BUDGET` | work | silent: `return` in `joins_every_non_tail_path` | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SPLIT_BLOCK_CAP` | other | silent: `return` in `closed_loop_body`; `return` in `render_cfg_blocks_via_cns`; `return` in `split_tail_regions` | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SUBTREE_CAP` | other | silent: `return` in `private_tail_subtree` | `usize` | `32` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_FRAME_BYTES` | size | error: `reject_at()` | `i64` | `1 << 20` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_INSTRUCTIONS` | other | error: `reject()` | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_CASES` | other | silent: `return` in `readable_switch_table`; `return` in `recover_aarch64_switch` | `usize` | `4096` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_SLICE_INSTRUCTIONS` | other | silent: `for` range in `matching_switch_guard`; `for` range in `single_block_definition`; `for` range in `single_block_pc_relative_definition`; 1 more | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_TABLE_BYTES` | size | silent: `return` in `readable_switch_table` | `usize` | `MAX_SWITCH_CASES * 8` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `REGISTER_ARGUMENT_LIMIT` | other | silent: `for` range in `prove_arguments` | `usize` | `8` | `crates/disrobe-pass-native/src/pseudo_c/aarch64_callsite.rs` |
| `disrobe-pass-native` | `MAX_FIXPOINT_STEPS` | work | error: `reject()` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/pseudo_c/aarch64_frame.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_BYTES` | size | silent: `return` in `clobbers` | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_FUNCTIONS` | other | silent: `return` in `clobbers` | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_AFFINE_SHIFT` | other | silent: fallback value in `remainder_register` | `u8` | `126` | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_DIVIDEND_BITS` | other | silent: `return` in `disjoint_or`; `return` in `divisor_reproduces_witness`; `return` in `quotient_ceiling`; 2 more | `u32` | `64` | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | other | silent: `return` in `specialize` | `usize` | `256` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_EXPR_NODES` | count | silent: `return` in `push_value` | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_FOLDS` | other | silent: `for` range in `specialize` | `usize` | `16` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_PROOFS` | other | silent: `?` on a checked operation in `prove_one` | `usize` | `64` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_READ_STEPS` | work | error: `Error::LlvmIr` (DR-NATIVE-0018) | `usize` | `16384` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_STATEMENTS` | other | silent: `return` in `specialize` | `usize` | `2048` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_VALUES` | other | silent: `return` in `definitions` | `usize` | `4` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `PATH_BUDGET` | work | error: untyped error | `usize` | `1 << 16` | `crates/disrobe-pass-native/src/pseudo_c/return_channel.rs` |
| `disrobe-pass-native` | `MAX_INLINED_DEFINITIONS` | other | silent: `for` range in `inline_single_use_definitions` | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_LOOP_WEIGHT_DEPTH` | recursion | delegated: passed to `debug::dbg_line` | `u32` | `8` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_RECORDED_DECISIONS` | other | silent: `return` in `record` | `usize` | `128` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_COMPRESSED_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_DECOMPRESSED_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_CONTAINER_ENTRIES` | count | error: untyped `format!` | `usize` | `65_536` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_DEPTH` | recursion | error: untyped `format!` | `usize` | `32` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_ESCAPED_STRING_BYTES` | size | error: `Error::SignatureDb` (DR-NATIVE-0019) | `usize` | `64 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_STRING_BYTES` | size | error: untyped `format!` | `usize` | `9 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_JSON_WORK_ITEMS` | work | error: untyped `format!` | `usize` | `1_048_576` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_PACKAGES` | other | error: untyped `format!` | `usize` | `16_384` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `MAX_AUDITABLE_PACKAGE_TEXT_BYTES` | size | error: untyped `format!` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-native/src/rust_recovery.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | other | silent: slice in `analyze`; slice in `dotnet_bundle_finding`; slice in `pkr_ce1a_finding`; 1 more | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `VERSION_TAIL_CAP` | other | silent: slice in `dotted_after`; slice in `literal_tail` | `usize` | `64` | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `ADRP_PAIR_SCAN_LIMIT` | other | silent: `for` range in `paired_low_bits` | `usize` | `16` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WIDE_MOVE_CHAIN_LIMIT` | other | silent: `while` condition in `fold_wide_move` | `usize` | `3` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WINDOW_INSTRUCTION_LIMIT` | other | silent: `while` condition in `window_start` | `usize` | `64` | `crates/disrobe-pass-native/src/similarity/opaque.rs` |
| `disrobe-pass-native` | `MAX_GROUP_SPAN` | other | silent: no action in `reassemble_group` | `i64` | `1024` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_SCAN_INSNS` | other | silent: `break` in `harvest_stack_stores` | `usize` | `200_000` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_RIP_REFS` | other | silent: `break` in `scan_rip_relative_refs` | `usize` | `200_000` | `crates/disrobe-pass-native/src/stream_disasm.rs` |
| `disrobe-pass-native` | `MAX_MAP_BYTES` | size | error: `Error::GoblinParse` (DR-NATIVE-0005); `Error::SignatureDb` (DR-NATIVE-0019); untyped `format!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_MAP_PAGES` | other | error: `Error::GoblinParse` (DR-NATIVE-0005) | `u64` | `MAX_MAP_BYTES / (PAGE_SIZE as u64)` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_WRITE_LOG_ENTRIES` | count | recorded: flag `write_log_truncated` | `usize` | `1 << 19` | `crates/disrobe-pass-native/src/stub_emu/mem.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_PAGES` | other | silent: `?` on a checked operation in `apply_chains` | `usize` | `65_536` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_STEPS` | work | silent: `?` on a checked operation in `apply_chains` | `usize` | `65_536` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_FIXUP_BYTES` | size | silent: `return` in `apply` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SECTIONS` | other | silent: `return` in `loaded_section_ranges`; `return` in `validate_loaded_sections` | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SEGMENTS` | other | silent: `return` in `apply_chains`; `return` in `apply` | `usize` | `256` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `STEP_CAP` | work | error: `EvalError::StepCapExceeded` | `u64` | `5_000_000` | `crates/disrobe-pass-native/src/vm_devirt/eval.rs` |
| `disrobe-pass-native` | `MAX_GUARDIAN_BYTECODE_BYTES` | size | silent: `.min()` clamp in `devirtualize_guardian_rs` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/guardian.rs` |
| `disrobe-pass-native` | `MAX_BYTECODE_INSNS` | size | error: `LiftError::TooLarge` | `usize` | `1 << 20` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_HANDLERS` | other | silent: `return` in `read_pointer_table`; `return` in `recover_via_codescan`; `return` in `recover_via_exports`; 1 more | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_VM_REGS` | other | error: `EvalError::RegisterOutOfRange`; `EvalError::TooManyArgs` | `usize` | `256` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-native` | `MAX_VM_STACK` | other | error: `EvalError::StackOverflow` | `usize` | `4096` | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_CARVE_BYTES` | size | recorded: `BodySkip::CodeBudgetExhausted`; `skipped` | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_CODE_BYTES` | size | recorded: `skipped` | `u64` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_BODY_FUNCTIONS` | other | recorded: `BodySkip::FunctionBudgetExhausted` | `usize` | `MAX_LISTED_FUNCTIONS` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_EMITTED_NAME_CHARS` | output | silent: `.take()` in `emitted_identifier` | `usize` | `120` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_GATE_TOKENS` | other | recorded: flag `truncated` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_RETAINED_SOURCE_BYTES` | size | recorded: `BodyStatus::RecoveredElided` | `u64` | `4 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_DEPTH` | recursion | silent: fallback value in `enter` | `usize` | `256` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_OUTPUT` | output | recorded: flag `output_exhausted` | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_STEPS` | work | error: `DDemangleError::StepBudget` | `usize` | `200_000` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_NIM_DEPTH` | recursion | silent: `return` in `read_nim_type` | `usize` | `256` | `crates/disrobe-pass-nativelang/src/demangle.rs` |
| `disrobe-pass-nativelang` | `MAX_INSTRUCTIONS_PER_FUNCTION` | other | recorded: flag `truncated` | `usize` | `8192` | `crates/disrobe-pass-nativelang/src/disasm.rs` |
| `disrobe-pass-nativelang` | `MAX_LISTED_FUNCTIONS` | other | recorded: `BodySkip::FunctionBudgetExhausted` | `usize` | `4096` | `crates/disrobe-pass-nativelang/src/disasm.rs` |
| `disrobe-pass-nativelang` | `INITIAL_INFLATE_CAP` | other | allocation: `with_capacity` in `inflate_up_to` | `usize` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_ARRAY_DIMENSIONS` | other | silent: `while` condition in `array_dimensions` | `usize` | `1 << 8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATES` | other | silent: `break` in `walk_dwarf`; skipped in `collect_aggregates`; skipped in `push_aggregate` | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_DEPTH` | recursion | silent: skipped in `collect_aggregates` | `usize` | `1 << 8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_ITEMS` | count | silent: `return` in `collect_aggregates`; `return` in `take_aggregate_item` | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_DIE_VISITS` | other | silent: `break` in `walk_dwarf`; `return` in `collect_aggregates`; `return` in `visit_die` | `usize` | `1 << 22` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCS` | other | silent: `break` in `walk_dwarf`; `return` in `collect_unit`; skipped in `push_function` | `usize` | `1 << 18` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCTION_PARAMS` | other | silent: `return` in `collect_unit`; `return` in `take_function_param` | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_DEPTH` | recursion | silent: `continue` in `resolve_attr_queue`; skipped in `resolve_attr_queue` | `usize` | `8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_VISITS` | other | silent: `return` in `enqueue_references`; `while` condition in `resolve_attr_queue` | `usize` | `16` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_STRING_BYTES` | size | recorded: flag `string_limit_hit` | `usize` | `1 << 26` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_STRING_LEN` | size | recorded: flag `string_limit_hit` | `usize` | `1 << 14` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_TYPE_DEPTH` | recursion | silent: `return` in `resolve_type_name` | `u8` | `8` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_LINE_ROWS` | other | silent: `break` in `assign_line_ranges`; `break` in `fill_line_ranges` | `u64` | `1 << 24` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_TOTAL_DEBUG_BYTES` | size | error: untyped `format!` | `u64` | `2 << 30` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_UNCOMPRESSED` | other | error: untyped `format!` | `u64` | `1 << 30` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_REPORTED_TYPES` | other | silent: `.take()` in `recover_types` | `usize` | `1 << 16` | `crates/disrobe-pass-nativelang/src/dwarf_types.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_BYTES` | size | silent: `return` in `recover_eh_frame_functions` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_FDES` | other | silent: `while` condition in `recover_eh_frame_functions` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_FUNCTION_BYTES` | size | recorded: `skipped` | `u64` | `256 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_RECOVERED_FUNCTIONS` | other | silent: `break` in `recover_functions` | `usize` | `1 << 18` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_TRAVERSAL_TEXT` | other | silent: `return` in `run_traversal` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_STRING_COUNT` | count | silent: `return` in `push_capped` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_STRING_SCAN_BYTES` | size | recorded: flag `truncated` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_TABLE_FUNCTION_STARTS` | other | silent: `.take()` in `parse`; `.take()` in `pe_unwind_table_starts`; `break` in `macho_function_starts` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_FUNCTIONS` | other | silent: `.take()` in `lift_native_nir` | `usize` | `4096` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_SYMBOLS` | other | silent: `.take()` in `lift_native_nir` | `usize` | `8192` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_CANDIDATES` | other | recorded: flag `truncated` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_NAME_BYTES` | size | recorded: flag `truncated` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_NAME_LEN` | size | silent: `return` in `accept_d_rtti_name`; `return` in `demangle_d_struct_type`; `return` in `mapped_d_slice` | `usize` | `64 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SCAN_BYTES` | size | recorded: flag `truncated` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SECTIONS` | other | recorded: `TraversalRun::Incomplete`; `skipped`; flag `sections_truncated` | `usize` | `96` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SEGMENTS` | other | silent: `return` in `accept_d_rtti_name` | `usize` | `64` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SLICE_LEN` | size | silent: `return` in `mapped_d_slice` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SYMBOLS` | other | recorded: flag `any`; flag `truncated` | `usize` | `16 * 1024` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_VECTOR_LEN` | size | silent: `return` in `d_class_info_at`; `return` in `d_class_info_name_at` | `usize` | `1 << 20` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nuitka` | `MAX_CONTAINER_LEN` | size | silent: `return` in `walk_sequence`; `return` in `walk_value` | `u64` | `1 << 24` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | recursion | silent: `return` in `walk_value` | `usize` | `64` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAF_BYTES` | size | silent: `.min()` clamp in `scan_constants_blob`; `?` on a checked operation in `read_zero_terminated_bytes`; `break` in `scan_constants_blob`; 1 more | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAVES` | other | silent: `return` in `push_int`; `return` in `push_str` | `usize` | `200_000` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LIFT_DEPTH` | recursion | silent: `return` in `eval_atom`; `return` in `eval_value`; `return` in `lift_block` | `usize` | `256` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_PREPROCESSOR_NESTING` | recursion | silent: `return` in `parse_primary` | `usize` | `256usize` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENTS` | other | silent: `return` in `split_top_args` | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENT_BYTES` | size | silent: `return` in `split_top_args` | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_DIAMOND_DEPTH` | recursion | silent: `return` in `arm_value` | `usize` | `64` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_FIELD_LEN` | size | silent: `continue` in `decode_record` | `usize` | `256` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_RECORD_LEN` | size | silent: `.min()` clamp in `scan_build_info` | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_MODULES` | other | error: `Error::ConstTooManyStreams` (DR-NUITKA-0016) | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/bytecode_table.rs` |
| `disrobe-pass-nuitka` | `MAX_C_CALL_ARGUMENT_BYTES` | size | silent: `return` in `split_top_level_args_with_mask` | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_DIRECT_STATEMENT_BYTES` | size | silent: `return` in `direct_statement_suffix` | `usize` | `1_048_576` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_FUNCTION_PARAMETERS` | other | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_MODULE_RECORDS` | count | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_FACTORY_TOP_LEVEL_STATEMENTS` | other | silent: `return` in `factory_top_level_statements` | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_ASSIGNMENTS` | other | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_SCOPES` | other | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_TEMPORARY_CONST_SCOPE_SEGMENTS` | other | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `131_072` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MANIFEST_ENTRY_EXTRACT_CAP` | other | silent: fallback value in `render_manifest_light` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_ONEFILE_MAIN_DECOMPILE_BYTES` | size | silent: skipped in `extract_children` | `usize` | `1024 * 1024` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_BYTES` | size | silent: `return` in `plausible_table_header`; `return` in `try_chunk_with_layout` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_COUNT` | count | silent: `return` in `big_int`; `return` in `plausible_table_header`; `return` in `sequence`; 2 more | `u64` | `200_000` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | recursion | silent: `return` in `value` | `usize` | `200` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | size | silent: `return` in `plausible_table_header`; `return` in `try_chunk_with_layout`; slice in `plausible_table_header`; 1 more | `usize` | `200` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_PREVIOUS_CLONE_WEIGHT` | other | silent: `return` in `value_body` | `usize` | `128 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_STORED_LAST_WEIGHT` | other | silent: fallback value in `value` | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_TABLE_HEADER_HINTS` | other | silent: `while` condition in `table_header_hints` | `usize` | `64` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_BYTES` | size | silent: `return` in `bounded_len` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_WIDE_SCAN_BYTES` | size | recorded: `ConstantsUnparsedReason::WideScanSkipped` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_BYTES` | size | error: `Error::ArtifactTooLarge` (DR-NUITKA-0026); `Error::InputTooLarge` (DR-NUITKA-0032) | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_ENTRIES` | count | error: `Error::ConstManifestTooManyEntries` (DR-NUITKA-0030); untyped `format!` | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_MANIFEST_MEMBERS` | count | error: `Error::ConstManifestTooManyEntries` (DR-NUITKA-0030); untyped `format!` | `usize` | `MAX_CONSTANT_MANIFEST_ENTRIES + 1usize` | `crates/disrobe-pass-nuitka/src/const_manifest.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_CONST_BYTES` | size | error: `Error::ArtifactTooLarge` (DR-NUITKA-0026); `Error::BuildConstantsTooLarge` (DR-NUITKA-0029); `Error::InputTooLarge` (DR-NUITKA-0032) | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_CONST_FILES` | count | error: `Error::TooManyConstFiles` (DR-NUITKA-0028); `Error::TooManyConstantInputs` (DR-NUITKA-0033) | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_CONSTANT_LABEL_BYTES` | size | error: `Error::InputTooLarge` (DR-NUITKA-0032) | `usize` | `4_096` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_CONST_FILE_BYTES` | size | error: `Error::ArtifactTooLarge` (DR-NUITKA-0026); `Error::InputTooLarge` (DR-NUITKA-0032) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_STREAMS_PER_FILE` | other | error: `Error::ConstTooManyStreams` (DR-NUITKA-0016) | `usize` | `1_000_000` | `crates/disrobe-pass-nuitka/src/constants.rs` |
| `disrobe-pass-nuitka` | `MAX_BOUNDED_READ_PREALLOC_BYTES` | size | allocation: `with_capacity` in `read_file_bounded` | `usize` | `1024 * 1024` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_BUILD_DIRECTORY_ENTRIES` | count | error: `Error::TooManyDirectoryEntries` (DR-NUITKA-0031) | `usize` | `65_536` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_SIBLING_BINARY_BYTES` | size | silent: `.take()` in `read_file_bounded`; `return` in `read_file_bounded` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_PYTHON_ABI_MINOR` | other | silent: `for` range in `find_python_runtime_name`; `for` range in `find_python_version_marker` | `u8` | `20` | `crates/disrobe-pass-nuitka/src/detect.rs` |
| `disrobe-pass-nuitka` | `MAX_FROZEN_MODULES` | other | silent: `while` condition in `recover_frozen_bytecode` | `usize` | `1 << 16` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_MARSHAL_BYTES` | size | silent: slice in `load_code` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_BINARY_INPUT_BYTES` | size | error: `Error::ArtifactTooLarge` (DR-NUITKA-0026); `Error::InputTooLarge` (DR-NUITKA-0032) | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_C_SOURCE_BYTES` | size | error: `Error::CSourceTooLarge` (DR-NUITKA-0023) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_C_SOURCE_LINES` | other | error: `Error::CSourceComplexityExceeded` (DR-NUITKA-0027) | `usize` | `1_000_000` | `crates/disrobe-pass-nuitka/src/limits.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRIES` | count | silent: `break` in `map_names` | `usize` | `100_000` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAMES` | other | silent: `.take()` in `map_names` | `usize` | `50_000` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | size | silent: `continue` in `map_names`; `return` in `map_names`; slice in `read_c_string` | `usize` | `200` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_MAP_TEXT_BYTES` | size | silent: `for` range in `map_names` | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_API_CALLS` | other | silent: `break` in `collect_api_calls` | `usize` | `64` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_ENUMERATION_INSNS` | other | recorded: flag `exhausted` | `usize` | `4_000_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_FUNCTIONS` | other | silent: `.min()` clamp in `parse_pdata`; `break` in `locate_impls`; skipped in `collect_ctor_sites` | `usize` | `20_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_IMPL_INSNS` | other | silent: `while` condition in `decode_function` | `usize` | `20_000` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_TEXT_BYTES` | size | silent: `.min()` clamp in `parse_pe` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_DECOMPRESSED_ABS` | other | error: `Error::Zstd` (DR-NUITKA-0005); untyped `format!` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_DECOMPRESSION_RATIO` | other | error: `Error::Zstd` (DR-NUITKA-0005); untyped `format!` | `u64` | `1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRY_COUNT` | count | error: `Error::EntryTruncated` (DR-NUITKA-0006) | `usize` | `1 << 20` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRY_SIZE` | size | error: `Error::EntryTruncated` (DR-NUITKA-0006) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_EXTRACTED_DATA_BYTES` | size | error: `Error::InputTooLarge` (DR-NUITKA-0032) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `MAX_FILENAME_BYTES` | size | error: `Error::EntryTruncated` (DR-NUITKA-0006) | `usize` | `4096` | `crates/disrobe-pass-nuitka/src/onefile.rs` |
| `disrobe-pass-nuitka` | `GLOBAL_CANDIDATE_LOG_CAP` | other | silent: skipped in `locate_onefile_payload` | `u32` | `16` | `crates/disrobe-pass-nuitka/src/onefile_locator.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_EXPRESSION_BYTES` | size | silent: `return` in `is_safe_annotation_expression` | `usize` | `8_192usize` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_NESTING` | recursion | silent: `return` in `enter_nesting` | `usize` | `64usize` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_STATIC_PICKLE_DEPTH` | recursion | silent: `return` in `contains_nonfinite_float`; `return` in `is_static_pickle_hashable`; `return` in `is_static_pickle_value`; 1 more | `usize` | `256` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | recursion | silent: `return` in `parse_destructure_targets` | `u32` | `128` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_STATEMENTS` | other | silent: `return` in `parse_block_body`; `return` in `parse_destructure_targets`; `return` in `parse_program` | `usize` | `4096` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_PREALLOC` | other | allocation: `with_capacity` in `fold_rope`; `with_capacity` in `parse_literals`; `with_capacity` in `parse_one`; 5 more | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `MAX_UNRECOVERED_RECORDS` | count | silent: `break` in `emit_body`; skipped in `limit`; skipped in `record_opaque_literals`; 2 more | `usize` | `4096` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `REASON_ROPE_BUDGET` | work | error: `Error::ContainerBadFraming` (DR-PHP-0100); `Error::OpcacheLayout` (DR-PHP-0125) | `&str` | `"the rope exceeds the bounded php 8 rope folding budget"` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CALL_ARGUMENT_CAP` | other | recorded: `.refuse()` | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CALL_RENDER_CAP` | output | recorded: `.refuse()` | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_CLAUSE_CAP` | other | silent: `return` in `catch_region_end`; `return` in `lift_catch_arms` | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_TYPE_CAP` | other | silent: `return` in `catch_clause` | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CHILD_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CLOSURE_USE_CAP` | other | silent: `return` in `fold_closure` | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_FOR_STEP_CAP` | work | silent: `return` in `for_step_start` | `usize` | `16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_ELEMENT_CAP` | other | silent: `return` in `list_entries` | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_RENDER_CAP` | output | silent: `return` in `fold_list_assign`; `return` in `list_entries`; `return` in `push_list_text` | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LITERAL_CAP` | work | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `4_000_000` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_EXIT_FREE_CAP` | other | silent: `return` in `exit_frees_match` | `u32` | `SANE_LIFT_DEPTH` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_RELIFT_WORK_CAP` | work | silent: `?` on a checked operation in `loop_relift_charge` | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_NAME_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_OP_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `4_000_000` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_ROPE_WORK_CAP` | work | recorded: `.refuse()` | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_ARM_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_LABEL_WORK_CAP` | work | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_STATE_WORK_CAP` | work | silent: `return` in `structure_linear_match`; `return` in `structure_switch_dispatch` | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_TRY_CATCH_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_VAR_CAP` | other | error: `Error::OpArrayFieldOversize` (DR-PHP-0093) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `USE_SCAN_BUDGET` | work | silent: `break` in `read_after_jump`; `return` in `free_unconsumed` | `usize` | `256` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `MAX_LABEL_ATTRIBUTIONS_PER_ITEM` | other | error: `Error::Deflatten` (DR-PHP-0110) | `usize` | `64` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MAX_LINEARIZE_DEPTH` | recursion | silent: `return` in `try_emit_braced` | `usize` | `256` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MAX_LINEARIZE_STEPS` | work | error: `Error::Deflatten` (DR-PHP-0110) | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `MIN_LABEL_ATTRIBUTION_BUDGET` | work | error: `Error::Deflatten` (DR-PHP-0110) | `usize` | `4096` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `CONTAINER_INFLATE_OUTPUT_CAP` | output | error: `Error::ContainerInflateBomb` (DR-PHP-0102) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-php/src/encoder/container.rs` |
| `disrobe-pass-php` | `ZEND_OPTIMIZER_OBF_KEY_CAP` | other | silent: `return` in `read_zend_optimizer_key` | `usize` | `4096` | `crates/disrobe-pass-php/src/encoder/container.rs` |
| `disrobe-pass-php` | `ZEND_OBFUSCATION_KEY_CAP` | other | silent: `return` in `recover_zend_optimizer_obfuscation_key` | `usize` | `4096` | `crates/disrobe-pass-php/src/key_extractor.rs` |
| `disrobe-pass-php` | `EXPR_INFLATE_CAP` | other | error: `Error::StrReplaceExpansion` (DR-PHP-0036) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `EXPR_INITIAL_CAP` | other | allocation: `with_capacity` in `inflate_bounded` | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_OPAQUE_STATEMENT` | other | silent: skipped in `parse_statements` | `usize` | `1 << 20` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | recursion | silent: `return` in `parse_expr`; `return` in `parse_var_ref` | `usize` | `256` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `STR_REPEAT_OUTPUT_CAP` | output | silent: `return` in `str_repeat` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `STR_REPLACE_OUTPUT_CAP` | output | error: `Error::StrReplaceExpansion` (DR-PHP-0036) | `usize` | `EXPR_INFLATE_CAP` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_ARGS` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_CLASS_NAMES` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 12` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_COPIED_BYTES` | size | error: `Error::OpcacheOversize` (DR-PHP-0124) | `usize` | `1 << 28` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_DEPTH` | recursion | error: `Error::OpcacheNestTooDeep` (DR-PHP-0126) | `u32` | `64` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_DYNAMIC_DEFS` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_HASH_ELEMENTS` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_LITERALS` | work | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_OPS` | work | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_OP_ARRAYS` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `usize` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TEMPORARIES` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TRY_CATCH` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_TYPE_LIST` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 8` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_VALUE_NODES` | count | error: `Error::OpcacheOversize` (DR-PHP-0124) | `usize` | `1 << 22` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `MAX_VARS` | other | error: `Error::OpcacheOversize` (DR-PHP-0124) | `u32` | `1 << 16` | `crates/disrobe-pass-php/src/opcache.rs` |
| `disrobe-pass-php` | `EVAL_CHAIN_INFLATE_OUTPUT_CAP` | output | error: `Error::GzInflateBomb` (DR-PHP-0035); `Error::StrReplaceExpansion` (DR-PHP-0036) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `EVAL_PROBE_MIN_BUDGET` | work | silent: `?` on a checked operation in `next_eval_call_arg` | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `INFLATE_INITIAL_CAP` | other | allocation: `with_capacity` in `inflate_bounded` | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `RESOLVE_DEPTH_CAP` | recursion | silent: `return` in `classify_inner_at_depth`; `return` in `resolve_arg` | `u32` | `32` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `STR_REPLACE_OUTPUT_CAP` | output | error: `Error::StrReplaceExpansion` (DR-PHP-0036) | `usize` | `EVAL_CHAIN_INFLATE_OUTPUT_CAP` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `PHAR_ALIAS_CAP` | other | error: `Error::PharAliasOversize` (DR-PHP-0024) | `u32` | `1 << 14` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_DECOMPRESS_CAP` | other | error: `Error::PharArchiveQuotaExceeded` (DR-PHP-0037); `Error::PharDeclaredSizeImplausible` (DR-PHP-0029) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_DECOMPRESS_INITIAL_CAP` | other | allocation: `with_capacity` in `try_bounded` | `usize` | `64 * 1024` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_ENTRY_NAME_CAP` | other | error: `Error::PharManifestTruncated` (DR-PHP-0022) | `u32` | `1 << 12` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_MANIFEST_ENTRY_CAP` | other | error: `Error::PharManifestTooLarge` (DR-PHP-0023) | `u32` | `1 << 20` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_META_CAP` | other | error: `Error::PharManifestTruncated` (DR-PHP-0022) | `u32` | `1 << 22` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `PHAR_PAYLOAD_CAP` | other | error: `Error::PharEntryPayloadTruncated` (DR-PHP-0025) | `u32` | `1 << 30` | `crates/disrobe-pass-php/src/phar.rs` |
| `disrobe-pass-php` | `MAX_RESTRUCTURE_DEPTH` | recursion | silent: `return` in `emit_units`; `return` in `structure_region`; fallback value in `emit_unit` | `usize` | `256` | `crates/disrobe-pass-php/src/restructure.rs` |
| `disrobe-pass-php` | `MAX_TOKEN_COUNT` | count | error: `Error::TokenCountExceeded` (DR-PHP-0012) | `usize` | `1_000_000` | `crates/disrobe-pass-php/src/token.rs` |
| `disrobe-pass-pickle` | `MAX_RENDER_DEPTH` | recursion | silent: `return` in `inline_unused_refs`; `return` in `render` | `u32` | `2_048` | `crates/disrobe-pass-pickle/src/decompile.rs` |
| `disrobe-pass-pickle` | `LONG_BODY_BUDGET` | work | error: `Error::LongBudget` (DR-PICKLE-0024) | `usize` | `1 << 18` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `MAX_LONG_BODY` | other | error: `Error::LongTooLong` (DR-PICKLE-0023) | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `MAX_STACKED_STREAMS` | other | silent: `break` in `disassemble_streams`; no action in `analyze_streams`; no action in `run` | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `OPCODE_BUDGET` | work | error: `Error::OpcodeBudget` (DR-PICKLE-0012) | `usize` | `5_000_000` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `ANCHOR_OPCODE_BUDGET` | work | silent: `.min()` clamp in `scan_for_embedded_with_work` | `usize` | `1 << 16` | `crates/disrobe-pass-pickle/src/ml.rs` |
| `disrobe-pass-pickle` | `MAX_ZIP_COMMENT` | other | recorded: `notes` | `usize` | `0xFFFF` | `crates/disrobe-pass-pickle/src/polyglot.rs` |
| `disrobe-pass-pickle` | `MAX_CYCLE_TARGETS` | other | recorded: flag `reexecutable` | `usize` | `4_096` | `crates/disrobe-pass-pickle/src/reconstruct.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_BYTES` | recursion | silent: `return` in `analyze_nested_pickle` | `usize` | `1_048_576` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_DEPTH` | recursion | silent: `return` in `analyze_nested_pickle` | `usize` | `3` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_SCAN_DEPTH` | recursion | silent: `return` in `scan_nested_pickles`; `return` in `scan_value` | `usize` | `2_048` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_VALUE_DEPTH` | recursion | error: `Error::ValueDepth` (DR-PICKLE-0018) | `u32` | `1_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-pickle` | `NODE_BUDGET` | work | error: `Error::NodeBudget` (DR-PICKLE-0017) | `u64` | `8_000_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-pickle` | `RECURSION_LIMIT` | recursion | error: `Error::RecursionLimit` (DR-PICKLE-0011) | `usize` | `2_000` | `crates/disrobe-pass-pickle/src/vm.rs` |
| `disrobe-pass-py-decompile` | `MAX_SLOT_INDEX` | other | error: `DecompileError::Emit` | `u32` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/alt_lift/mpy.rs` |
| `disrobe-pass-py-decompile` | `MAX_PATTERN_NEST_DEPTH` | recursion | silent: `return` in `classify_mapping_pattern`; `return` in `classify_sequence_pattern` | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/ast/builder/branches.rs` |
| `disrobe-pass-py-decompile` | `MAX_IMPORT_LEVEL` | other | silent: `continue` in `build_linear_stmts_sim_seed`; fallback value in `bounded_import_level` | `u32` | `32` | `crates/disrobe-pass-py-decompile/src/ast/builder/exprs.rs` |
| `disrobe-pass-py-decompile` | `MAX_LAMBDA_BRANCH_DEPTH` | recursion | silent: `return` in `returned_expr` | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/ast/builder/function_meta.rs` |
| `disrobe-pass-py-decompile` | `LOOP_HEADER_PREFIX_LIMIT` | other | error: `DecompileError::AstDesync`; `DecompileError::BlockOutOfRange`; `DecompileError::MalformedExceptionTable` | `usize` | `4` | `crates/disrobe-pass-py-decompile/src/ast/builder/loops.rs` |
| `disrobe-pass-py-decompile` | `CODEOBJ_DEPTH_LIMIT` | recursion | error: `DecompileError::StructuringDepthExceeded` | `usize` | `200` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `EXIT_PROBE_STEP_BUDGET` | work | error: `DecompileError::StructuringBudgetExceeded`; `exit_probe_budget_error()` | `usize` | `1 << 22` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `MAX_SYNTH_OPERANDS` | other | silent: `.min()` clamp in `pop_n`; `for` range in `build_linear_stmts_sim_seed` | `usize` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `STRUCTURE_DEPTH_LIMIT` | recursion | error: `DecompileError::StructuringDepthExceeded` | `usize` | `600` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `STRUCTURE_REENTRY_LIMIT` | other | silent: `return` in `enter_active_region` | `usize` | `4` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `MAX_EMIT_DEPTH` | recursion | delegated: passed to `drop` | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/codegen/expr.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_LITERAL_BYTES` | work | silent: `.min()` clamp in `collect_byte_tokens` | `usize` | `1 << 20` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_STRINGS` | other | silent: `return` in `collect_code`; `return` in `collect_object` | `usize` | `1 << 16` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCAN_DEPTH` | recursion | silent: `return` in `collect_code`; `return` in `collect_object` | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_FRAME_NEST_DEPTH` | recursion | silent: no action in `attach_into` | `usize` | `256` | `crates/disrobe-pass-py-decompile/src/frame_tree/builder.rs` |
| `disrobe-pass-py-decompile` | `MAX_PROBE_CAPTURE` | other | delegated: `subprocess::run_captured()?` | `usize` | `1024 * 1024` | `crates/disrobe-pass-py-decompile/src/recompile.rs` |
| `disrobe-pass-py-decompile` | `MAX_CANDIDATES` | other | silent: `.take()` in `accept_reordering_core` | `usize` | `48` | `crates/disrobe-pass-py-decompile/src/selfcheck/opcontent.rs` |
| `disrobe-pass-py-decompile` | `MAX_DEPTH` | recursion | silent: `return` in `lower_seq`; `return` in `lower_try` | `u32` | `96` | `crates/disrobe-pass-py-decompile/src/selfcheck/relower.rs` |
| `disrobe-pass-py-decompile` | `MAX_HOIST_CANDIDATES` | other | silent: `.take()` in `repair_else_tail` | `usize` | `64` | `crates/disrobe-pass-py-decompile/src/selfcheck/repair.rs` |
| `disrobe-pass-py-deob` | `MAX_FSTRING_OUTPUT` | output | error: `EvalError::Overflow` | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/ast_eval/eval.rs` |
| `disrobe-pass-py-deob` | `MAX_REPEAT_ITEMS` | count | error: `EvalError::Overflow` | `usize` | `8192` | `crates/disrobe-pass-py-deob/src/ast_eval/eval.rs` |
| `disrobe-pass-py-deob` | `MAX_SPLIT` | other | error: `EvalError::IndexOutOfRange`; `EvalError::Overflow`; `EvalError::TypeMismatch`; 1 more | `i128` | `65_536` | `crates/disrobe-pass-py-deob/src/ast_eval/methods.rs` |
| `disrobe-pass-py-deob` | `MAX_OUTPUT` | output | error: `EvalError::Overflow` | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/ast_eval/pyformat.rs` |
| `disrobe-pass-py-deob` | `MAX_WIDTH` | other | error: `EvalError::Overflow` | `usize` | `4096` | `crates/disrobe-pass-py-deob/src/ast_eval/pyformat.rs` |
| `disrobe-pass-py-deob` | `MAX_KEY_CANDIDATES` | other | silent: `.truncate()` in `dedup_and_rank` | `usize` | `64` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_REPEATING_KEYLEN` | size | silent: `for` range in `best_keylengths` | `usize` | `40` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_FOLDED_LEN` | size | silent: `return` in `fold_binop` | `usize` | `1 << 20` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_PASSES` | other | silent: `for` range in `fold` | `usize` | `16` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | silent: `return` in `collect_code_objects` | `usize` | `32` | `crates/disrobe-pass-py-deob/src/hyperion_v2v3.rs` |
| `disrobe-pass-py-deob` | `MAX_XOR_KEY_LEN` | size | error: `Error::XorKey` (DR-PYDEOB-0011) | `usize` | `4 * 1024` | `crates/disrobe-pass-py-deob/src/hyperion_v2v3.rs` |
| `disrobe-pass-py-deob` | `MAX_CHAIN_DEPTH` | recursion | silent: `for` range in `peel_to_marshal_blob` | `usize` | `16` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | silent: `return` in `collect_nested_blobs`; no action in `decompile_code` | `usize` | `64` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_CODEPOINT` | other | silent: `return` in `apply_shift`; `return` in `stage1_codepoints` | `u32` | `0x0010_FFFF` | `crates/disrobe-pass-py-deob/src/obfuscators/de4py_family.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | silent: `return` in `walk` | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/obfuxtreme.rs` |
| `disrobe-pass-py-deob` | `MAX_LIFT_DEPTH` | recursion | error: `LiftError` | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/abyss/lift.rs` |
| `disrobe-pass-py-deob` | `MAX_STORE_TARGET_NESTING` | recursion | error: `LiftError` | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/abyss/lift.rs` |
| `disrobe-pass-py-deob` | `MAX_REINSERT_DEPTH` | recursion | error: `Error::Marshal` (DR-PYDEOB-0010) | `usize` | `64` | `crates/disrobe-pass-py-deob/src/obfuscators/patchwork/reinsert.rs` |
| `disrobe-pass-py-deob` | `MAX_LOADER_BYTECODE` | size | silent: `return` in `looks_like_loader` | `usize` | `256` | `crates/disrobe-pass-py-deob/src/obfuscators/pyc_zipper.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | silent: `return` in `collect_code_objects` | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/pyobfus.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | recursion | silent: `return` in `collect_code_objects` | `usize` | `32` | `crates/disrobe-pass-py-deob/src/obfuscators/pypacker.rs` |
| `disrobe-pass-py-deob` | `MAX_DEPTH` | recursion | error: `Error::DepthLimit` (DR-PYDEOB-0003) | `usize` | `32` | `crates/disrobe-pass-py-deob/src/peel.rs` |
| `disrobe-pass-py-deob` | `MAX_TOKEN_CHARS` | other | silent: `return` in `recover` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-py-deob/src/shuffled_base64.rs` |
| `disrobe-pass-py-deob` | `MAX_OUTER_PASSES` | other | silent: `for` range in `cleanup_source` | `usize` | `8` | `crates/disrobe-pass-py-deob/src/source_cleanup.rs` |
| `disrobe-pass-py-deob` | `MAX_CANONICAL_NAMES` | other | silent: `continue` in `canonicalize_homoglyph_names` | `usize` | `100_000` | `crates/disrobe-pass-py-deob/src/unrename.rs` |
| `disrobe-pass-py-disasm` | `HEAD_SCAN_LIMIT` | other | error: `AltRuntimeError::NotDetected` (DR-PYALT-0004) | `usize` | `32 * 1024` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/brython.rs` |
| `disrobe-pass-py-disasm` | `MAX_NESTING` | recursion | error: `AltRuntimeError::BadEncoding` (DR-PYALT-0006) | `u8` | `48` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_OBJ_NESTING` | recursion | error: `AltRuntimeError::BadEncoding` (DR-PYALT-0006) | `u8` | `64` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_TABLE_ITEMS` | count | error: `AltRuntimeError::BadEncoding` (DR-PYALT-0006) | `usize` | `65_536` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_TABLE_PREALLOC` | other | allocation: `with_capacity` in `decode_arg_names`; `with_capacity` in `parse_bytecode`; `with_capacity` in `parse`; 1 more | `usize` | `4096` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_VARINT_BYTES` | size | error: `AltRuntimeError::BadEncoding` (DR-PYALT-0006) | `usize` | `10` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython.rs` |
| `disrobe-pass-py-disasm` | `MAX_NATIVE_VERSION` | other | error: `AltRuntimeError::NotDetected` (DR-PYALT-0004); `AltRuntimeError::UnsupportedVersion` (DR-PYALT-0003) | `u8` | `6` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython_native.rs` |
| `disrobe-pass-py-disasm` | `MAX_OBJ_NESTING` | recursion | error: `AltRuntimeError::BadEncoding` (DR-PYALT-0006) | `u8` | `64` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/micropython_native.rs` |
| `disrobe-pass-py-disasm` | `MAX_ALT_RUNTIME_INPUT_BYTES` | size | error: `AltRuntimeError::InputTooLarge` (DR-PYALT-0007) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/mod.rs` |
| `disrobe-pass-py-disasm` | `MAX_CODE_UNITS` | other | silent: `break` in `disassemble_code_tree` | `usize` | `4096` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/pypy.rs` |
| `disrobe-pass-py-disasm` | `MAX_NESTED_CODE_OBJECTS` | recursion | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `20_000` | `crates/disrobe-pass-py-disasm/src/chain_detector.rs` |
| `disrobe-pass-py-disasm` | `MAX_RENDER_DEPTH` | recursion | silent: `return` in `repr_object` | `usize` | `64` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_REPR_LONG_DIGITS` | other | silent: `return` in `repr_bigint` | `usize` | `512` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_SET_SIMULATION` | other | silent: `return` in `cpython_set_order` | `usize` | `1 << 20` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_EXTENDED_ARG_PREFIXES` | other | recorded: flag `argrepr` | `u32` | `3` | `crates/disrobe-pass-py-disasm/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_NAME_LEN` | size | silent: `return` in `resolve_name` | `usize` | `128` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_RECORDS` | count | silent: `while` condition in `parse_records` | `usize` | `65_536` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_SECTIONS` | other | silent: `.min()` clamp in `enumerate_elf_sections` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `EXECUTION_BUDGET` | work | silent: `return` in `run` | `usize` | `200_000` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch_recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_BODY_BYTES` | size | recorded: `notes` | `usize` | `256 * 1024` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch_recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_BODY_BYTES` | size | recorded: `notes` | `usize` | `256 * 1024` | `crates/disrobe-pass-pyarmor/src/bcc/recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_DEPTH` | recursion | silent: no action in `build_node`; no action in `walk_artifacts` | `usize` | `64` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_NODES` | count | silent: `break` in `build_node`; `break` in `walk_artifacts` | `usize` | `65_536` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_STEPS` | work | silent: `return` in `recover_idealized` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc/stmt_structure.rs` |
| `disrobe-pass-pyarmor` | `MAX_PACKAGE_DEPTH` | recursion | silent: `break` in `derive_module_path` | `usize` | `64` | `crates/disrobe-pass-pyarmor/src/bcc/stub.rs` |
| `disrobe-pass-pyarmor` | `MAX_CALL_TARGETS_SCANNED` | other | silent: `.take()` in `resolve_sibling_calls` | `usize` | `1024` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_DISASM_LINES` | other | silent: `break` in `render_unmodeled` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_FUNCTIONS` | other | silent: `while` condition in `discover_functions` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_RESOLVED_CALLS` | other | silent: `break` in `resolve_sibling_calls` | `usize` | `256` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_DYNAMIC_CAPTURE` | other | error: `Error::DynamicHookTimedOut` (DR-PYARM-0018); `Error::KeyExtraction` (DR-PYARM-0009) | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/dynamic_hook.rs` |
| `disrobe-pass-pyarmor` | `MAX_CODE_OBJECT_DEPTH` | recursion | recorded: flag `depth_limit_truncations` | `u32` | `512` | `crates/disrobe-pass-pyarmor/src/inner_cipher.rs` |
| `disrobe-pass-pyarmor` | `MAX_READ` | other | silent: `.min()` clamp in `extract_runtime_key` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/key.rs` |
| `disrobe-pass-pyarmor` | `MAX_CAPTURE_FILE_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_JSON_FILE_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_RUNTIME_DIR_ENTRIES` | count | error: `ErrorKind::InvalidData` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_RUNTIME_FILE_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/lib.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SCAN_BYTES` | size | silent: slice in `scan_import_symbols`; slice in `scan_printable_strings` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SYMBOLS` | other | silent: `return` in `scan_import_symbols` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_BYTES` | size | silent: `.min()` clamp in `push_printable_string` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_CONSTANTS` | other | silent: `return` in `scan_printable_strings` | `usize` | `2048` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_SCAN_BYTES` | size | silent: slice in `scan_printable_strings` | `usize` | `MAX_IMPORT_SCAN_BYTES` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_BCC_SEGMENTS` | other | silent: `while` condition in `peel_bcc` | `usize` | `4096` | `crates/disrobe-pass-pyarmor/src/v8v9.rs` |
| `disrobe-pass-pyfreeze` | `MAX_WALK_DEPTH` | recursion | error: `Error::BriefcaseWalkBounded` (DR-PYFRZ-0024) | `usize` | `64` | `crates/disrobe-pass-pyfreeze/src/briefcase/layout.rs` |
| `disrobe-pass-pyfreeze` | `MAX_WALK_ENTRIES` | count | error: `Error::BriefcaseWalkBounded` (DR-PYFRZ-0024) | `usize` | `200_000` | `crates/disrobe-pass-pyfreeze/src/briefcase/layout.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ENTRY_BYTES` | size | silent: `continue` in `carve_zip_members` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ZIP_ENTRIES` | count | silent: `.min()` clamp in `carve_zip_members` | `usize` | `65_536` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_JSON_MANIFEST_BYTES` | size | error: `Error::JsonManifestTooLarge` (DR-PYFRZ-0027) | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/common/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PREALLOC` | other | allocation: `with_capacity` in `read_to_vec_bounded`; `with_capacity` in `read_to_vec_limited` | `usize` | `1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/common/read_bounded.rs` |
| `disrobe-pass-pyfreeze` | `MAX_COMMENT` | other | silent: `for` range in `locate` | `usize` | `0xFFFF` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `SEARCH_BUDGET` | work | silent: `for` range in `locate` | `usize` | `MAX_COMMENT + EOCD_FIXED_LEN + 4` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `MAX_TREE_DEPTH` | recursion | error: `Error::QuotaExceeded` (DR-PYFRZ-0018) | `usize` | `32` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/lib_tree.rs` |
| `disrobe-pass-pyfreeze` | `MAX_TREE_ENTRIES` | count | error: `Error::QuotaExceeded` (DR-PYFRZ-0018) | `usize` | `200_000` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/lib_tree.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FILESYSTEM_BYTECODE_ATTEMPTS` | size | recorded: flag `filesystem_bytecode_capped` | `usize` | `512` | `crates/disrobe-pass-pyfreeze/src/cxfreeze/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FREEZE_DIR_ENTRIES` | count | silent: `.take()` in `find_python_runtime`; `break` in `sibling_native_extensions` | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FREEZE_INPUT_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_LIBRARY_ZIP_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_RECOVERY_FILE_BYTES` | size | error: `ErrorKind::InvalidData` | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PEX_ENTRY` | other | delegated: `read_bounded::read_to_vec_limited()?` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/pex/mod.rs` |
| `disrobe-pass-pyfreeze` | `MAX_PYTHONSCRIPT_BYTES` | size | error: `Error::PeParse` (DR-PYFRZ-0013) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/py2exe/pe.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SECTIONS` | other | silent: `return` in `parse_blob_index` | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SLICE` | other | silent: `.min()` clamp in `extract_resources_blob` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_NAME_LEN` | size | silent: `while` condition in `scan_name_start` | `usize` | `4096` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_RESOURCE_ENTRIES` | count | silent: `break` in `heuristic_walk`; `return` in `extract_modules_structured`; `return` in `parse_structured_region` | `usize` | `1_000_000` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_STRUCTURED_VERSION` | other | silent: `for` range in `extract_resources_blob`; no action in `find_packed_magic` | `u8` | `3` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_DISASM_BYTES` | size | silent: slice in `surface_native` | `usize` | `1 << 20` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyfreeze` | `SAMPLE_INSTRUCTION_CAP` | other | silent: `.take()` in `surface_native` | `usize` | `32` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyfreeze` | `MAX_MANIFEST_BYTES` | size | delegated: `read_bounded::read_to_vec_limited()?` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyfreeze/src/shiv/mod.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_COMMENT` | other | silent: `return` in `find_eocd` | `usize` | `u16::MAX as usize` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_ENTRIES` | count | silent: `while` condition in `walk_central_directory` | `usize` | `1 << 20` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_NATIVE_SURFACE_BYTES` | size | silent: skipped in `extract_children` | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/chain_detector.rs` |
| `disrobe-pass-pyinstaller` | `MAX_AGGREGATE_INFLATE` | other | error: `ErrorKind::InvalidData` | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_ABS` | other | error: `ErrorKind::InvalidData` | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_RATIO` | other | error: `ErrorKind::InvalidData` | `u64` | `1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INPUT_FILE_BYTES` | size | error: `Error::InputFileTooLarge` (DR-PYINST-0013) | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_KEY_MODULE_INFLATE` | other | error: `ErrorKind::InvalidData` | `u64` | `1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/extract.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DEEP_ANALYZE_BYTES` | size | silent: skipped in `surface_native_entry` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/native_surface.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CANDIDATE_BYTES` | size | recorded: flag `exhausted` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CANDIDATE_CONSTS` | other | recorded: flag `exhausted` | `usize` | `4096` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CODE_WALK_DEPTH` | recursion | silent: `return` in `collect_byte_consts` | `usize` | `64` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DECOMPRESS_ATTEMPTS` | other | silent: `break` in `unzip_pyc_with_limits`; `return` in `take` | `usize` | `1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_RECOVERED_BYTES` | size | silent: `.take()` in `read_capped`; `return` in `read_capped` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_AGGREGATE_INFLATE` | other | error: `ErrorKind::InvalidData` | `u64` | `8 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_ABS` | other | error: `ErrorKind::InvalidData` | `u64` | `4 * 1024 * 1024 * 1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_INFLATE_RATIO` | other | error: `ErrorKind::InvalidData` | `u64` | `1024` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-pyinstaller` | `MAX_PYZ_TOC_ENTRIES` | count | error: `Error::TocWalk` (DR-PYINST-0004) | `usize` | `1 << 20` | `crates/disrobe-pass-pyinstaller/src/pyz.rs` |
| `disrobe-pass-ruby` | `POOL_PREALLOC_CAP` | other | allocation: `with_capacity` in `read_record` | `usize` | `4096` | `crates/disrobe-pass-ruby/src/mruby/irep.rs` |
| `disrobe-pass-ruby` | `MAX_KEYWORD_PARAMS` | other | allocation: `with_capacity` in `keyword_prologue` | `usize` | `31` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_LIFT_DEPTH` | recursion | recorded: flag `coverage_complete` | `u32` | `64` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_LIFT_OUTPUT_PREALLOC` | output | allocation: `with_capacity` in `lift_tree` | `usize` | `1 << 20` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_REGS` | other | silent: skipped in `set_pending`; skipped in `set` | `usize` | `4096` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `OCRA_DECOMPRESS_CAP` | other | error: `Error::other()`; `RubyError::OcraLzmaDecode` (DR-RUBY-0064) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-ruby/src/wrappers.rs` |
| `disrobe-pass-ruby` | `MAX_EXPR_LEN` | size | silent: fallback value in `push` | `usize` | `8192` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_NEST_DEPTH` | recursion | silent: `return` in `emit_send`; `return` in `massign_targets`; `return` in `render_iseq_statements`; 1 more | `u32` | `64` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_OPERAND_COUNT` | count | recorded: flag `assigns`; flag `escaped` | `usize` | `MAX_STACK` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_STACK` | other | recorded: flag `assigns`; flag `escaped` | `usize` | `8192` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `IBF_ARRAY_LEN_CAP` | size | silent: `.min()` clamp in `decode_object`; `for` range in `parse_ci_entries` | `usize` | `1_048_576` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_OBJECT_LIST_ENTRY_CAP` | other | silent: `.min()` clamp in `parse_image` | `u32` | `1_048_576` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_STRING_LEN_CAP` | size | silent: `break` in `decode_iseq_body`; skipped in `decode_object` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-scriptlang` | `MAX_SWF_BYTES` | size | silent: `return` in `inflate_cws` | `usize` | `1usize << 26` | `crates/disrobe-pass-scriptlang/src/lang/haxe.rs` |
| `disrobe-pass-scriptlang` | `MAX_ADAPTIVE_BYTES` | size | error: `Error::StarkitMetakit` (DR-SCRIPT-0404) | `usize` | `5usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_COLUMNS` | other | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `64usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_DESCRIPTION_BYTES` | size | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `1usize << 16` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_MEMBERS` | count | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_PATH_BYTES` | size | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_TOTAL_PATH_BYTES` | size | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `64usize << 20` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_VIEW_DEPTH` | recursion | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `usize` | `8usize` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_VIEW_ROWS` | other | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); untyped `format!` | `i64` | `1i64 << 20` | `crates/disrobe-pass-scriptlang/src/lang/metakit.rs` |
| `disrobe-pass-scriptlang` | `MAX_RDS_BYTES` | size | silent: `.take()` in `read_bounded`; `return` in `maybe_gunzip_rds_with_limit`; `return` in `read_bounded` | `usize` | `1usize << 29` | `crates/disrobe-pass-scriptlang/src/lang/mod.rs` |
| `disrobe-pass-scriptlang` | `MAX_BYTECODE_TEXT_BYTES` | size | error: `Error::PerlBytecodeTruncated` (DR-SCRIPT-0211); `Error::PerlBytecodeValueTooLarge` (DR-SCRIPT-0214) | `usize` | `1usize << 20` | `crates/disrobe-pass-scriptlang/src/lang/perl_bytecode.rs` |
| `disrobe-pass-scriptlang` | `MAX_OPS` | work | silent: `while` condition in `read_bytecode` | `usize` | `2_000_000usize` | `crates/disrobe-pass-scriptlang/src/lang/perl_bytecode.rs` |
| `disrobe-pass-scriptlang` | `MAX_MULTICONCAT_SEGMENTS` | other | silent: `.take()` in `parse_multiconcat` | `usize` | `256` | `crates/disrobe-pass-scriptlang/src/lang/perl_decompile.rs` |
| `disrobe-pass-scriptlang` | `COMPLEX_VECTOR_CAP` | other | silent: `.min()` clamp in `walk_item_body` | `usize` | `1024usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_DEPTH` | recursion | error: `Error::RdsDepthExceeded` (DR-SCRIPT-0303) | `usize` | `256usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_NODES` | count | error: `Error::RdsNodeLimitExceeded` (DR-SCRIPT-0306) | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_RVALUE_VECTOR_ENTRIES` | count | error: `Error::RdsValueTooLarge` (DR-SCRIPT-0307) | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_STRING_BYTES` | size | error: `Error::RdsValueTooLarge` (DR-SCRIPT-0307) | `usize` | `64 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `RAW_VECTOR_CAP` | other | recorded: flag `truncated` | `usize` | `4096usize` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `ENTRY_PREALLOC_CAP` | other | allocation: `with_capacity` in `member_bytes`; `with_capacity` in `read_zip_entry_to_limit` | `u64` | `1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_ENTRIES` | count | silent: `for` range in `extract_zip_with_limits`; `while` condition in `scan_metakit_files` | `usize` | `65_536usize` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_ENTRY_BYTES` | size | error: `Error::StarkitMetakit` (DR-SCRIPT-0404); `Error::StarkitZip` (DR-SCRIPT-0401) | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_METAKIT_NAME_LEN` | size | silent: `return` in `read_metakit_token`; skipped in `scan_metakit_files` | `usize` | `255usize` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_TOTAL_ENTRY_BYTES` | size | error: `Error::StarkitZip` (DR-SCRIPT-0401) | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_CHUNK_BYTES` | size | silent: `for` range in `base64_decode` | `usize` | `1usize << 22` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_INPUT_BYTES` | size | silent: `return` in `base64_decode`; skipped in `base64_blobs` | `usize` | `(MAX_INFLATE_BYTES / 3usize) * 4usize + 4usize` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_BYTES` | size | silent: `break` in `rebuild_replace`; `return` in `base64_decode`; `return` in `read_inflate_text`; 1 more | `usize` | `1usize << 26` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_READ_BYTES` | size | silent: `.take()` in `read_inflate_text` | `u64` | `(1u64 << 26) + 1u64` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_LAYERS` | other | silent: `while` condition in `recover` | `usize` | `16usize` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | recursion | silent: `return` in `parse_expression`; `return` in `parse_unary` | `usize` | `256` | `crates/disrobe-pass-shell/src/bash/arith.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | other | silent: `return` in `parse_array_assignment` | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_FOR_INDICES` | other | silent: `return` in `parse_for_lookup_loop` | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_PRINTF_BYTES` | size | silent: `return` in `try_string_split_indirection` | `usize` | `65536` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_TAG_LEN` | size | silent: `return` in `parse_md5_cut_chunk` | `usize` | `1024` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | silent: `return` in `try_compress_payload` | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESS_BYTES` | size | silent: `return` in `try_compress_payload` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | work | silent: `for` range in `reverse_bashfuscator`; no action in `reverse_bashfuscator` | `usize` | `12` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DEPTH` | recursion | silent: `return` in `eval_wrapped_command`; no action in `wall` | `usize` | `64` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_INFLATE` | other | recorded: `.note()` | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_OUTPUT` | output | silent: `break` in `decode_pipeline`; `break` in `evaluate` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_REPEAT` | other | silent: no action in `expand_tr_set` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_GZIP_OUTPUT` | output | silent: `.take()` in `peel_non_eval_layers`; `.truncate()` in `peel_non_eval_layers`; fallback value in `peel_non_eval_layers` | `u64` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEELED_OUTPUT` | output | silent: `break` in `peel_indirection_with_policy` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | work | silent: `break` in `peel_indirection_with_policy` | `usize` | `32` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_LEXER_INPUT_BYTES` | size | recorded: `BashTokenKind::Truncated`; flag `truncation` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_SUBSTITUTION_DEPTH` | recursion | recorded: flag `nesting_truncated` | `usize` | `256usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | count | silent: `while` condition in `tokenize_bash` | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_SOURCE_BYTES` | size | recorded: flag `source_limit_exceeded` | `usize` | `MAX_TOKEN_TEXT_BYTES / 3usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_TEXT_BYTES` | size | recorded: flag `source_limit_exceeded` | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_TOKEN_TEXT_BYTES` | size | recorded: flag `budget` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_RECOVERED_OUTPUT` | output | silent: `break` in `reverse_node_bash_obfuscate` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_TABLE_ENTRIES` | count | silent: `while` condition in `parse_chunk_table` | `usize` | `200_000` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_PATTERN_LEN` | size | silent: `return` in `substitute`; `return` in `trim_prefix`; `return` in `trim_suffix` | `usize` | `256` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_TEXT_LEN` | size | silent: `return` in `substitute`; `return` in `trim_prefix`; `return` in `trim_suffix` | `usize` | `4096` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_PATTERN_LEN` | size | silent: `return` in `substitute` | `usize` | `64` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_TEXT_LEN` | size | silent: `return` in `substitute` | `usize` | `512` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | recursion | silent: `return` in `parse_expr`; `return` in `parse_unary` | `usize` | `256` | `crates/disrobe-pass-shell/src/batch/arith.rs` |
| `disrobe-pass-shell` | `MAX_CIPHERTEXT` | other | silent: `continue` in `recover_stages` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/batch/chain.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_ROUNDS` | work | silent: `for` range in `expand_repeated` | `usize` | `16` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_LINES` | other | silent: `break` in `deobfuscate_batch` | `usize` | `50_000` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_OUTPUT` | output | silent: `break` in `deobfuscate_batch` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_OUTPUT` | output | silent: `break` in `expand_sigil`; `return` in `reserve_expansion_bytes` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/batch/expand.rs` |
| `disrobe-pass-shell` | `MAX_FOR_ITERATIONS` | work | silent: `return` in `numeric_sequence` | `usize` | `4096` | `crates/disrobe-pass-shell/src/batch/forloop.rs` |
| `disrobe-pass-shell` | `MAX_REVERSE_ADDED_BYTES` | size | silent: `return` in `reserve_expansion_bytes` | `usize` | `expand::MAX_EXPANSION_OUTPUT` | `crates/disrobe-pass-shell/src/batch/mod.rs` |
| `disrobe-pass-shell` | `MAX_DECODE_LEN` | size | silent: `continue` in `extract_base64_blobs`; `return` in `decode_base64_flexible` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/batch/payload.rs` |
| `disrobe-pass-shell` | `MAX_POWERSHELL_LAYER_ROUNDS` | work | silent: `for` range in `reverse_powershell_layers` | `usize` | `16` | `crates/disrobe-pass-shell/src/chain_detector.rs` |
| `disrobe-pass-shell` | `MAX_SCRIPT_SCAN_BYTES` | size | silent: slice in `detect` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/detect.rs` |
| `disrobe-pass-shell` | `MAX_ACTION_DEPTH` | recursion | silent: `return` in `handle_action` | `usize` | `64` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | other | silent: `break` in `parse_array` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DICT_ENTRIES` | count | silent: `break` in `parse_dictionary_or_stream` | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DOCUMENT_BYTES` | size | silent: slice in `analyze` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FILTER_CHAIN` | other | silent: `break` in `decode_stream` | `usize` | `8` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDINGS` | other | silent: `break` in `collect_name_tree`; `break` in `scan_hex_obfuscated_names`; `return` in `add_embedded`; 2 more | `usize` | `8192` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDING_TEXT` | other | silent: `.truncate()` in `extract_javascript`; `while` condition in `cutoff`; no action in `cutoff` | `usize` | `1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_LZW_CODES` | other | silent: skipped in `lzw_decode` | `usize` | `4096` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_BYTES` | size | silent: `break` in `parse_name`; `break` in `scan_hex_obfuscated_names` | `usize` | `4096` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_TREE_NODES` | count | silent: `break` in `collect_name_tree` | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECTS` | other | silent: `break` in `brute_force`; `return` in `insert_object` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECT_DEPTH` | recursion | silent: `return` in `parse_object` | `usize` | `96` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJSTM_OBJECTS` | other | silent: `.min()` clamp in `expand_object_streams` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_PREDICTOR_COLUMNS` | other | silent: `.clamp()` clamp in `apply_predictor` | `usize` | `250_000` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_RESOLVE_STEPS` | work | silent: `return` in `resolve` | `usize` | `256` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STREAM_OUTPUT` | output | recorded: flag `capped` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_BYTES` | size | silent: `break` in `parse_hex_string`; `break` in `parse_literal_string` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CONCAT` | other | silent: `break` in `extract_javascript` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_OUTPUT` | output | recorded: flag `capped` | `usize` | `512 * 1024 * 1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_WALK_NODES` | count | silent: `break` in `global_sweep`; `break` in `walk_acroform`; `break` in `walk_pages`; 3 more | `usize` | `1 << 18` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_CHAIN` | other | silent: `break` in `parse_xref_chain` | `usize` | `1024` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_ENTRIES` | count | silent: `.min()` clamp in `parse_xref_stream`; `for` range in `parse_xref_table` | `usize` | `1 << 21` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_FIELD_WIDTH` | other | silent: `return` in `parse_xref_stream` | `usize` | `8` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `STATIC_EVAL_DEPTH_CAP` | recursion | silent: `break` in `peel_indirection_with_policy`; `continue` in `unwrap`; `return` in `eval_wrapped_command`; 2 more | `usize` | `2` | `crates/disrobe-pass-shell/src/policy.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | silent: `return` in `decode_frombase64_payload` | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/chameleon.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | error: `Error::InputTooLarge` (DR-NUITKA-0032) | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_obfuscation.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | other | silent: `.take()` in `reverse_compress`; `.truncate()` in `reverse_compress`; fallback value in `reverse_compress` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_obfuscation.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | silent: `return` in `reverse_then_b64_decode` | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/invoke_stealth.rs` |
| `disrobe-pass-shell` | `MAX_LEXER_INPUT_BYTES` | size | recorded: `.note()`; `BashTokenKind::Truncated`; `TokenKind::Truncated`; 31 more | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | count | silent: `while` condition in `tokenize` | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_SOURCE_BYTES` | size | recorded: flag `source_limit_exceeded` | `usize` | `MAX_TOKEN_TEXT_BYTES / 3usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_TEXT_BYTES` | size | recorded: flag `source_limit_exceeded` | `usize` | `65_536usize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_TOKEN_TEXT_BYTES` | size | recorded: flag `budget` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | error: `Error::InputTooLarge` (DR-NUITKA-0032) | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/powerhell.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | other | error: `Error::InputTooLarge` (DR-NUITKA-0032) | `usize` | `2 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/psobf.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | other | silent: `.take()` in `reverse_psobf`; `.truncate()` in `reverse_psobf`; fallback value in `reverse_psobf` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-pass-shell/src/powershell/psobf.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_BYTES` | size | error: `Error::VbaPcode` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_RESERVE` | other | allocation: `with_capacity` in `read_stream` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_ENTRY_BYTES` | size | error: `Error::VbaPcode` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_ENTRY_RESERVE` | other | allocation: `with_capacity` in `read_zip_entry_bounded` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_MODULE_REFS` | other | error: `Error::VbaPcode` | `usize` | `512` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_MODULE_STREAM_BYTES` | size | error: `Error::VbaPcode` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `PROJECT_INFORMATION_RECORD_LIMIT` | other | silent: `for` range in `project_codepage` | `usize` | `32` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_CALL_ARGS` | other | silent: `.min()` clamp in `pop_n` | `usize` | `256` | `crates/disrobe-pass-shell/src/vba/pcode_lift.rs` |
| `disrobe-pass-shell` | `MAX_CFB_ENTRIES` | count | silent: `.take()` in `locate_vba_storages` | `usize` | `8192` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_BYTES` | size | error: `Error::VbaPcode` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_CFB_STREAM_RESERVE` | other | allocation: `with_capacity` in `read_stream` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_FUNC_ARG_CHAIN` | other | silent: `while` condition in `disasm_func` | `usize` | `4096` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_OVBA_DECOMPRESSED_BYTES` | size | error: `Error::VbaPcode` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_TYPE_DESCRIPTOR_DEPTH` | recursion | silent: `return` in `named_type_from_descriptor` | `usize` | `8` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_VALUES` | other | silent: `return` in `read_array_constant` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_EXTERN_NAMES` | other | silent: `continue` in `build` | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORDS` | count | silent: `while` condition in `iter_biff12`; `while` condition in `iter_biff8` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORD_BODY` | other | silent: `.min()` clamp in `iter_biff12`; `.min()` clamp in `iter_biff8`; fallback value in `iter_biff8` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RGCE` | other | silent: `return` in `parse_fmla_biff12`; `return` in `parse_formula_biff8`; `return` in `parse_lbl`; 1 more | `usize` | `512 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_SHEETS` | other | silent: `break` in `enumerate_sheets` | `usize` | `4096` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_STACK_DEPTH` | recursion | recorded: flag `aborted` | `usize` | `4096` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CHARS` | other | silent: `.min()` clamp in `decode_chars`; `return` in `read_utf16_units` | `usize` | `1 << 20` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_TOKENS` | other | recorded: flag `aborted` | `usize` | `1 << 18` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_WORKBOOK_BYTES` | work | silent: `.take()` in `read_cfb_stream`; `return` in `read_cfb_stream` | `u64` | `128 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_XTI` | other | silent: `.min()` clamp in `parse_externsheet` | `usize` | `1 << 16` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRIES` | count | silent: `return` in `open_biff12` | `usize` | `8192` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRY_BYTES` | size | silent: `.take()` in `read_zip_entry`; `return` in `read_zip_entry` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-sourcedefender` | `MAX_ARMORED_INPUT_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_ARMORED_OUTPUT_BYTES` | output | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_HEX_INPUT_BYTES` | size | error: `CoreError::PassFailure` (DR-CORE-0003); `Error::InputLimit` (DR-SDEF-0011); `Error::Msgpack` (DR-SDEF-0008); 1 more | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_SOURCEDEFENDER_INFLATE` | other | error: `Error::Base85` (DR-SDEF-0004) | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/codec.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_BINARY_BYTES` | size | error: `Error::Msgpack` (DR-SDEF-0008) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_CONTAINER_ITEMS` | count | error: `Error::Msgpack` (DR-SDEF-0008) | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_DEPTH` | recursion | error: `Error::Msgpack` (DR-SDEF-0008) | `usize` | `64` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_ENVELOPE_BYTES` | size | error: `Error::Msgpack` (DR-SDEF-0008) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MSGPACK_STRING_BYTES` | size | error: `Error::Msgpack` (DR-SDEF-0008) | `usize` | `32 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_ARMORED_CIPHERTEXT_CHARS` | other | error: `Error::Base85` (DR-SDEF-0004); `Error::InputLimit` (DR-SDEF-0011) | `usize` | `96 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_FRAME_LINES` | other | error: `Error::Base85` (DR-SDEF-0004) | `usize` | `32_768` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_PYE_FRAME_TEXT_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `MAX_PYE_ARMORED_CIPHERTEXT_CHARS + 64 * 1024` | `crates/disrobe-pass-sourcedefender/src/envelope.rs` |
| `disrobe-pass-sourcedefender` | `MAX_GCM_AAD_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `u64` | `(1u64 << 61) - 1` | `crates/disrobe-pass-sourcedefender/src/gcm_tag.rs` |
| `disrobe-pass-sourcedefender` | `MAX_GCM_CIPHERTEXT_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `u64` | `(1u64 << 36) - 32` | `crates/disrobe-pass-sourcedefender/src/gcm_tag.rs` |
| `disrobe-pass-sourcedefender` | `MAX_INLINED_BLOCKS` | other | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/inlined.rs` |
| `disrobe-pass-sourcedefender` | `MAX_INLINED_SOURCE_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `MAX_ARMORED_INPUT_BYTES` | `crates/disrobe-pass-sourcedefender/src/inlined.rs` |
| `disrobe-pass-sourcedefender` | `MAX_FILENAME_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/kdf.rs` |
| `disrobe-pass-sourcedefender` | `MAX_CONTAINER_INPUT_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `MAX_HEX_INPUT_BYTES + 64 * 1024` | `crates/disrobe-pass-sourcedefender/src/layered.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MODERN_BODY_LINES` | other | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `32_768` | `crates/disrobe-pass-sourcedefender/src/layered.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MODERN_GCM_BODY_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `MAX_HEX_INPUT_BYTES / 2` | `crates/disrobe-pass-sourcedefender/src/modern_gcm.rs` |
| `disrobe-pass-sourcedefender` | `MAX_CODE_OBJECT_SUMMARIES` | other | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `4096` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MARSHAL_PAYLOAD_BYTES` | size | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_MARSHAL_TRAVERSAL_OBJECTS` | other | error: `Error::InputLimit` (DR-SDEF-0011) | `usize` | `131_072` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-sourcedefender` | `MAX_NESTED_CODE_DEPTH` | recursion | error: `Error::NestingLimit` (DR-SDEF-0012) | `usize` | `32` | `crates/disrobe-pass-sourcedefender/src/source_recover.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAIN_CHILDREN` | other | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `256` | `crates/disrobe-pass-swift-objc/src/chain_detector.rs` |
| `disrobe-pass-swift-objc` | `CSSLOT_ALTERNATE_CODEDIRECTORY_LIMIT` | other | error: `Error::Demangle` (DR-IOS-0011) | `u32` | `0x1005` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_BLOB_LEN` | size | silent: `break` in `parse` | `u32` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_IDENTIFIER_LEN` | size | silent: `?` on a checked operation in `read_cstr_bounded` | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOT_COUNT` | count | silent: `.min()` clamp in `parse` | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_VERIFIED_PAGES` | other | silent: `.min()` clamp in `verify_page_hashes` | `u32` | `65_536` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_DEPTH` | recursion | recorded: flag `depth_limit_hits` | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_NODES` | count | silent: `?` on a checked operation in `spend` | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPEAT_COUNT` | count | silent: `return` in `demangle_repeated_standard_substitution`; `return` in `demangle_substitution_chain`; `return` in `demangle_substitution` | `u32` | `2048` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOL_LEN` | size | error: `Error::Demangle` (DR-IOS-0011) | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_IMAGES` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_IMAGE_OUTPUT_BYTES` | output | error: `Error::BadDyldCache` (DR-IOS-0016) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_LOCAL_SYMBOL_ENTRIES` | count | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_MAPPINGS` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_RECORDED_AUTH_POINTERS` | other | silent: skipped in `unapply_segment_slide` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOTAL_OUTPUT_BYTES` | output | error: `Error::BadDyldCache` (DR-IOS-0016) | `u64` | `1024 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_INDIRECT_SYMBOLS` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `8_000_000` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINKEDIT_BYTES` | size | error: `Error::BadDyldCache` (DR-IOS-0016) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINKEDIT_SYMBOLS` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `4_000_000` | `crates/disrobe-pass-swift-objc/src/dyld_cache/linkedit.rs` |
| `disrobe-pass-swift-objc` | `MAX_PAGE_EXTRAS` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLIDE_PAGES` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_V1_ENTRY_BYTES` | size | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/dyld_cache/slide.rs` |
| `disrobe-pass-swift-objc` | `MAX_FAMILY_BYTES` | size | error: `Error::BadDyldCache` (DR-IOS-0016) | `u64` | `12 * 1024 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/dyld_cache/subcache.rs` |
| `disrobe-pass-swift-objc` | `MAX_SUB_CACHES` | other | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `128` | `crates/disrobe-pass-swift-objc/src/dyld_cache/subcache.rs` |
| `disrobe-pass-swift-objc` | `MAX_ENTRY_BYTES` | size | error: `Error::Ipa` (DR-IOS-0002) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `MAX_PREALLOC` | other | allocation: `with_capacity` in `read_zip_entry_limited` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `MAX_ZIP_ENTRY_COUNT` | count | error: `Error::Ipa` (DR-IOS-0002) | `usize` | `65_536` | `crates/disrobe-pass-swift-objc/src/ipa.rs` |
| `disrobe-pass-swift-objc` | `FAT_ARCH_COUNT_CAP` | count | error: `Error::BadFatHeader` (DR-IOS-0006) | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_DYLIBS` | other | silent: skipped in `parse_slice` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_DEPTH` | recursion | silent: `return` in `walk_export_node` | `usize` | `128` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NAME` | other | silent: `?` on a checked operation in `cstr_in`; `continue` in `walk_export_node` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NODES` | count | silent: `return` in `walk_export_node` | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_STARTS` | other | silent: `while` condition in `function_starts` | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_INDIRECT_SYMBOLS` | other | silent: `.min()` clamp in `import_thunks` | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_RPATHS` | other | silent: skipped in `parse_slice` | `usize` | `1024` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOLS` | other | silent: `.min()` clamp in `function_symbols`; `.min()` clamp in `symbol_names` | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOL_LEN` | size | silent: `?` on a checked operation in `read_cstr_bounded` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_BYTES` | size | silent: `.min()` clamp in `end_boundary`; `return` in `carve` | `u64` | `256 * 1024` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_INSTRUCTIONS_PER_FUNCTION` | other | recorded: flag `truncated` | `usize` | `8192` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINES_PER_FUNCTION` | other | silent: `.take()` in `lines_for` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LISTED_FUNCTIONS` | other | silent: `.take()` in `lift_native_nir`; `break` in `build_function_bodies` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_NIR_SYMBOLS` | other | silent: `.take()` in `lift_native_nir` | `usize` | `8192` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_TYPES` | other | silent: `.take()` in `recover_native_bodies` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_SELECTOR_HINT_WORK` | work | silent: `continue` in `index_selectors` | `u64` | `4_000_000` | `crates/disrobe-pass-swift-objc/src/objc.rs` |
| `disrobe-pass-swift-objc` | `MAX_BIND_OPS` | work | silent: `while` condition in `interpret_bind` | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CALL_SITES` | other | silent: `break` in `annotate_instructions` | `usize` | `1 << 14` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_DEPTH` | recursion | silent: `return` in `reaching_def_from`; `return` in `reaching_slot` | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_STEPS` | work | silent: `return` in `build` | `usize` | `1 << 13` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_IMPORTS` | other | silent: `.min()` clamp in `parse_chained_imports` | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_PAGES` | other | silent: `.min()` clamp in `walk_chained_pages`; `for` range in `walk_chained_pages` | `usize` | `1 << 22` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_SEGMENTS` | other | silent: `.min()` clamp in `chained_segment_infos` | `usize` | `1 << 12` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | silent: `?` on a checked operation in `chained_symbol_at`; `?` on a checked operation in `cstr_at_offset` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_MOVE_HOPS` | work | silent: `for` range in `trace_pointer_slot` | `usize` | `8` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOTS` | other | silent: `.min()` clamp in `build_classref_map`; `.min()` clamp in `build_selref_map`; `.min()` clamp in `interpret_bind` | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_STUB_ENTRIES` | count | silent: `while` condition in `build_arm64_stub_map`; `while` condition in `build_x86_stub_map` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOTAL_BINDS` | other | silent: `break` in `interpret_bind`; `for` range in `walk_chain`; `while` condition in `interpret_bind` | `usize` | `1 << 20` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CATEGORIES` | other | silent: `.take()` in `recover_categories` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CLASSES` | other | silent: `.take()` in `recover_interfaces` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | silent: `?` on a checked operation in `cstr_at_offset` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_LIST_COUNT` | count | silent: `return` in `read_entsize_list_header` | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOLS` | other | silent: `.take()` in `recover_protocols` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REFS` | other | silent: `return` in `parse_protocol_refs` | `usize` | `1 << 12` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_EMBEDDED_IMAGES` | other | error: `CoreError::PassFailure` (DR-CORE-0003) | `usize` | `256` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_INSTALL_NAMES` | other | silent: `.take()` in `dyld_cache_report` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_ZIP_ENTRY` | other | delegated: `ipa::read_zip_entry_limited()?` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | other | silent: `?` on a checked operation in `cstr_at_offset`; `?` on a checked operation in `mangled_name_at_offset` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_DESCRIPTORS` | other | silent: `while` condition in `parse_field_descriptors` | `usize` | `1 << 18` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_FIELDS_PER_TYPE` | other | silent: `.min()` clamp in `read_field_list`; `break` in `parse_field_descriptors` | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | size | silent: `?` on a checked operation in `cstr_at_offset` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | other | silent: `break` in `synthesize_nominal_mangling` | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | size | silent: `?` on a checked operation in `cstr_at_offset` | `usize` | `4096` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | other | silent: `break` in `walk_parent_names` | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REQUIREMENTS` | other | silent: `.min()` clamp in `read_protocol_requirements` | `usize` | `1 << 14` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_TYPE_RECORDS` | count | error: `Error::BadDyldCache` (DR-IOS-0016) | `usize` | `1 << 16` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_ARRAY_LEN` | size | error: `Error::BadBitstream` (DR-IOS-0014) | `u64` | `1 << 26` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_DEPTH` | recursion | error: `Error::BadBitstream` (DR-IOS-0014) | `usize` | `64` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_VBR_PIECES` | other | error: `Error::BadBitstream` (DR-IOS-0014) | `u32` | `16` | `crates/disrobe-pass-swift-objc/src/swiftmodule.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOOLCHAIN_HINTS` | other | silent: `.take()` in `report` | `usize` | `16` | `crates/disrobe-pass-swift-objc/src/toolchain.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINKS` | other | error: `BoundaryLinksError::TooManyLinks`; `BoundaryNamePropagationError::WorkLimitExceeded`; `Error::Parse` (DR-WASMDEOB-0001) | `usize` | `2_048` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINKS_JSON_BYTES` | size | error: `BoundaryLinksError::InputTooLarge` | `usize` | `1_048_576` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_LINK_STRING_BYTES` | size | error: `BoundaryLinksError::InvalidLanguage`; `BoundaryLinksError::StringTooLong`; `BoundaryNamePropagationError::NameTooLong` | `usize` | `4_096` | `crates/disrobe-pass-wasm-deob/src/boundary_links.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_NAME_PROPAGATION_WORK` | work | error: `BoundaryNamePropagationError::WorkLimitExceeded` | `usize` | `MAX_BOUNDARY_NAME_SEEDS * MAX_BOUNDARY_LINKS * 4` | `crates/disrobe-pass-wasm-deob/src/boundary_name_propagation.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_NAME_SEEDS` | other | error: `BoundaryNamePropagationError::TooManyNames`; `BoundaryNamePropagationError::WorkLimitExceeded` | `usize` | `256` | `crates/disrobe-pass-wasm-deob/src/boundary_name_propagation.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BODY_OPS` | work | silent: `break` in `fingerprint_body` | `usize` | `2_000_000` | `crates/disrobe-pass-wasm-deob/src/fingerprint.rs` |
| `disrobe-pass-wasm-deob` | `MAX_ORIGIN_DEPTH` | recursion | error: `TypeRecoveryRefusal::AddressDepth` | `u32` | `1024` | `crates/disrobe-pass-wasm-deob/src/lib.rs` |
| `disrobe-pass-wasm-deob` | `MAX_RENDER_INDENT` | output | silent: `.min()` clamp in `pad`; `.min()` clamp in `render_operators` | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/lib.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_EXPORT_NAME_BYTES` | size | error: `AtomicMemoryRefusal::ExportNameBytes` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_MODULE_EXPORTS` | other | error: `AtomicMemoryRefusal::ExportCount` | `usize` | `65_536` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TYPESCRIPT_MODULE_FUNCTIONS` | other | error: `AtomicMemoryRefusal::FunctionCount` | `usize` | `4096` | `crates/disrobe-pass-wasm-deob/src/lift.rs` |
| `disrobe-pass-wasm-deob` | `DATA_ESCAPE_PREALLOC_CAP` | other | allocation: `with_capacity` in `encode_data_bytes` | `usize` | `1 << 20` | `crates/disrobe-pass-wasm-deob/src/lift_module_faithful.rs` |
| `disrobe-pass-wasm-deob` | `MAX_SYNTHETIC_STRUCT_FIELDS` | other | silent: `.clamp()` clamp in `record_struct_field_count`; `.min()` clamp in `record_struct_new_field_types`; `return` in `record_struct_field_index` | `u32` | `4096` | `crates/disrobe-pass-wasm-deob/src/lift_wat.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TREE_NODES` | count | silent: `return` in `lower_inner` | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/obfuscators/mba.rs` |
| `disrobe-pass-wasm-deob` | `MAX_ITERATIONS` | work | silent: `break` in `unflatten`; `for` range in `unflatten_to_fixed_point` | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/obfuscators/tigress/unflatten.rs` |
| `disrobe-pass-wasm-deob` | `FUEL_BUDGET` | work | delegated: `.set_fuel()?` | `u64` | `100_000_000` | `crates/disrobe-pass-wasm-deob/src/obfuscators/wasmixer/sandbox_unwrap.rs` |
| `disrobe-pass-wasm-deob` | `TABLE_ELEMENT_LIMIT` | other | delegated: `.call()?`; `.get_memory()?`; `.instantiate()?`; 1 more | `usize` | `1 << 16` | `crates/disrobe-pass-wasm-deob/src/obfuscators/wasmixer/sandbox_unwrap.rs` |
| `disrobe-pass-wasm-deob` | `MAX_EXPR_NODES` | count | silent: `return` in `parse_value` | `usize` | `96` | `crates/disrobe-pass-wasm-deob/src/recover.rs` |
| `disrobe-pass-wasm-deob` | `MAX_FOLD_INSTRUCTIONS` | other | recorded: flag `intra_function_folding_skipped` | `usize` | `1 << 21` | `crates/disrobe-pass-wasm-deob/src/recover.rs` |
| `disrobe-pass-wasm-deob` | `NESTED_SEQ_LIMIT` | recursion | recorded: flag `truncated` | `usize` | `4096` | `crates/disrobe-pass-wasm-deob/src/recover/cff.rs` |
| `disrobe-pass-wasm-deob` | `MAX_GUARD_LEN` | size | silent: `return` in `match_diamond` | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/recover/opaque.rs` |
| `disrobe-pass-wasm-deob` | `MAX_CALL_DEPTH` | recursion | silent: `return` in `invoke` | `u32` | `8` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_MODULE_STEPS` | work | recorded: flag `guard_folding_budget_exhausted` | `u64` | `50_000_000` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_STEPS` | work | silent: `return` in `eval_guard`; `return` in `run_seq` | `u64` | `2_000_000` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_VALUE_STACK` | other | silent: `return` in `run_seq` | `usize` | `4_096` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MULTI_EXIT_LIMIT` | other | unclassified: match pattern in `render` | `usize` | `16` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `NODE_LIMIT` | other | silent: `.take()` in `collect_branch_transitions`; `return` in `accesses_cell_outside_root`; `return` in `accesses_cell`; 8 more | `usize` | `512` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `STATE_EXPRESSION_LIMIT` | other | silent: `?` on a checked operation in `expression_suffix`; `?` on a checked operation in `state_write_expression`; `return` in `eval_value`; 5 more | `usize` | `64` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `TRANSITION_INSTRUCTION_LIMIT` | other | silent: `return` in `classify_select_conditional`; `return` in `condition_has_isolated_value_stack`; `return` in `structured_work_is_bounded` | `usize` | `512` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BOUNDARY_RESOURCES` | other | error: `Error::Parse` (DR-WASMDEOB-0001) | `usize` | `MAX_BOUNDARY_LINKS` | `crates/disrobe-pass-wasm-deob/src/signature.rs` |
| `disrobe-pass-wasm-deob` | `MAX_FUNCTION_LOCALS` | other | delegated: passed to `iter::repeat_n` | `usize` | `100_000` | `crates/disrobe-pass-wasm-deob/src/signature.rs` |
| `disrobe-pass-webview` | `COMPRESSED_SAMPLE_CAP` | other | silent: `.min()` clamp in `looks_compressed` | `usize` | `4096` | `crates/disrobe-pass-webview/src/decompress.rs` |
| `disrobe-pass-webview` | `MAX_EVIDENCE_MARKERS` | other | silent: `.truncate()` in `classify_all`; `.truncate()` in `marker_evidence` | `usize` | `8` | `crates/disrobe-pass-webview/src/detect.rs` |
| `disrobe-pass-webview` | `MAX_ENTRY_PATH_BYTES` | size | silent: `return` in `bounded_join`; `while` condition in `bounded_join`; slice in `bounded_join` | `usize` | `4096` | `crates/disrobe-pass-webview/src/electron.rs` |
| `disrobe-pass-webview` | `MAX_EXTENSION_LEN` | size | silent: `continue` in `scan`; no action in `best_window` | `usize` | `16` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_HASH_HAMMING` | other | silent: fallback value in `hash_window` | `usize` | `1` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_PATH_LEN` | size | silent: `return` in `validate` | `usize` | `4096` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_RECORD_BLOB` | other | unclassified: pattern binding in `validate` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_SCAN_RECORDS` | count | silent: `return` in `collect_runs`; skipped in `collect_runs` | `usize` | `2_000_000` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_UNREADABLE_GAP` | other | silent: `break` in `collect_runs` | `usize` | `2` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_FAT_SLICES` | other | silent: `.take()` in `build_slices` | `usize` | `64` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_OVERLAP_WALK` | other | silent: slice in `containing` | `usize` | `64` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_SPANS` | other | silent: `break` in `build` | `usize` | `4096` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILES_SCANNED` | count | silent: `break` in `scan_circularity` | `usize` | `16_384` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILE_BYTES` | size | silent: `.take()` in `read_text_bounded`; `return` in `read_text_bounded` | `u64` | `1024 * 1024` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_PACKED_PAIRS` | other | silent: `break` in `discover_packed_pairs` | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_RECOMPILE_PYC` | other | silent: `break` in `discover_recompile_pyc` | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_FILES` | count | silent: `break` in `build` | `usize` | `4096` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_TOML_BYTES` | size | silent: `.take()` in `read_text_bounded`; `return` in `read_text_bounded` | `u64` | `1024 * 1024` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_NATIVE_MATCH_INPUT_BYTES` | size | error: `NativeMatchUploadError::InputTooLarge` (DR-PLAYGROUND-0100) | `usize` | `64 * 1024 * 1024` | `crates/disrobe-playground/src/native_match.rs` |
| `disrobe-playground` | `MAX_SOURCE_BYTES` | size | delegated: `lift_module_source_with_limit()?` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-playground/src/wasm.rs` |
| `disrobe-plugin-host` | `DEFAULT_FUEL_BUDGET` | work | delegated: `.set_fuel()?` | `u64` | `50_000_000` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_FUEL_BUDGET` | work | delegated: `.set_fuel()?` | `u64` | `1_000_000_000` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_MEMORY_CAP_BYTES` | size | error: `SandboxError::Memory` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_WALL_DEADLINE` | other | error: `SandboxError::Timeout` | `Duration` | `Duration::from_secs(30)` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-host` | `MAX_WASM_MODULE_BYTES` | size | error: `SandboxError::ModuleTooLarge` | `usize` | `DEFAULT_MEMORY_CAP_BYTES` | `crates/disrobe-plugin-host/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_SIGNATURE_BYTES` | size | error: `LoaderError::SignatureTooLarge` | `usize` | `16 * 1024` | `crates/disrobe-plugin-loader/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_SIGNED_COMPONENT_BYTES` | size | error: `LoaderError::ComponentTooLarge` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-plugin-loader/src/lib.rs` |
| `disrobe-plugin-loader` | `MAX_CAPABILITIES` | other | error: `ManifestError::TooManyCapabilities` | `usize` | `128` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_CAPABILITY_BYTES` | size | error: `ManifestError::CapabilityTooLarge` | `usize` | `256` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_NAME_BYTES` | size | error: `ManifestError::NameTooLarge` | `usize` | `128` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_TOML_BYTES` | size | error: `ManifestError::ManifestTooLarge` | `usize` | `64 * 1024` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-plugin-loader` | `MAX_MANIFEST_VERSION_BYTES` | size | error: `ManifestError::VersionTooLarge` | `usize` | `64` | `crates/disrobe-plugin-loader/src/manifest.rs` |
| `disrobe-prowl` | `MAX_CONFIG_BYTES` | size | error: `KeyError::ConfigTooLarge` | `u64` | `1 << 20` | `crates/disrobe-prowl/src/keys.rs` |
| `disrobe-py-marshal` | `BYTE_BUDGET` | work | error: `Error::ByteBudget` (DR-MARSHAL-0018) | `u64` | `1024 * 1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `BYTE_BUDGET` | work | error: `Error::ByteBudget` (DR-MARSHAL-0018) | `u64` | `512 * 1024 * 1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_COLLECTION_ITEMS` | count | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_DEPTH` | recursion | error: `Error::DepthLimit` (DR-MARSHAL-0009) | `usize` | `256` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_DICT_ENTRIES` | count | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_INTERNED_STRINGS` | other | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `usize` | `1 << 13` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_INTERNED_STRINGS` | other | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_LEN` | size | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `u32` | `1 << 28` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_LONG_DIGITS` | other | error: `Error::LongDigitOverflow` (DR-MARSHAL-0010) | `u32` | `1 << 24` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_OBJECT_PREALLOC` | other | allocation: `with_capacity` in `read_n_objects` | `usize` | `1024` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_REFS` | other | error: `Error::LengthOverflow` (DR-MARSHAL-0011) | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_TRACE_ENTRIES` | count | recorded: flag `entries_omitted` | `usize` | `1 << 12` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `MAX_TRACE_ENTRIES` | count | recorded: flag `entries_omitted` | `usize` | `1 << 20` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-py-marshal` | `NODE_BUDGET` | work | error: `Error::NodeBudget` (DR-MARSHAL-0014) | `u64` | `8_000_000` | `crates/disrobe-py-marshal/src/reader.rs` |
| `disrobe-pyarmor-cextract` | `MAX_CAPTURED_CODE_OBJECTS` | other | error: `CextractError::CaptureLimit` | `usize` | `65_536` | `crates/disrobe-pyarmor-cextract/src/capture.rs` |
| `disrobe-pyarmor-cextract` | `MAX_CAPTURED_PYC_BYTES` | size | error: `CextractError::CaptureLimit` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pyarmor-cextract/src/capture.rs` |
| `disrobe-pyarmor-cextract` | `MAX_PROLOGUE_SCAN` | other | error: `CextractError::HotpatchFailed` | `usize` | `32` | `crates/disrobe-pyarmor-cextract/src/hotpatch/x86_disasm.rs` |
| `disrobe-pyarmor-cextract` | `MAX_MARSHAL_BODY_BYTES` | size | error: `CextractError::PycTooLarge` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pyarmor-cextract/src/marshal_writer.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_CAPTURED` | other | silent: skipped in `_trace_callback` | `usize` | `262_144` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_DRAIN_OUTPUTS` | output | error: untyped `format!` | `usize` | `65_536` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_DRAIN_OUTPUT_BYTES` | output | error: `DrainLimitError::OutputBytes` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_MARSHALLED_CODE_BYTES` | size | error: `DrainLimitError::MarshalledCodeObject` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-python` | `MAX_CONTAINER_INPUT_BYTES` | size | error: untyped `format!` | `usize` | `256 * 1024 * 1024` | `crates/disrobe-python/src/container.rs` |
| `disrobe-python` | `MAX_PY_JSON_DEPTH` | recursion | error: untyped `format!` | `usize` | `256` | `crates/disrobe-python/src/convert.rs` |
| `disrobe-python` | `MAX_PY_JSON_ITEMS` | count | error: untyped `format!` | `usize` | `1_000_000` | `crates/disrobe-python/src/convert.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_DESCRIPTOR_BYTES` | size | recorded: `JvmHierarchyDiagnostic::DescriptorBytesLimit`; `JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit`; `JvmHierarchyDiagnostic::TargetDescriptorBytesLimit`; 2 more | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_EDGES` | other | recorded: `JvmHierarchyDiagnostic::EdgeLimit`; `diagnostics` | `usize` | `65_536` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_HIERARCHY_NODES` | count | recorded: `JvmHierarchyDiagnostic::NodeLimit`; `diagnostics` | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_IMPLEMENTOR_MATCHES` | other | recorded: `JvmHierarchyDiagnostic::MatchLimit`; `diagnostics` | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MALFORMED_DESCRIPTOR_BYTES` | size | recorded: `JvmHierarchyDiagnostic::MalformedDescriptorDiagnosticLimit`; flag `truncated` | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MALFORMED_DESCRIPTOR_DIAGNOSTICS` | other | recorded: `JvmHierarchyDiagnostic::MalformedDescriptorDiagnosticLimit`; flag `truncated` | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_MISSING_DEFINITION_DIAGNOSTICS` | other | recorded: `JvmHierarchyDiagnostic::MissingDefinitionDiagnosticLimit`; flag `missing_diagnostics_truncated` | `usize` | `16_384` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_BYTES` | size | recorded: `JvmHierarchyDiagnostic::ProofBytesLimit`; `diagnostics` | `usize` | `1_048_576` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_DEPTH` | recursion | recorded: `JvmHierarchyDiagnostic::ProofDepthLimit`; `diagnostics` | `usize` | `256` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_JVM_PROOF_ELEMENTS` | other | recorded: `JvmHierarchyDiagnostic::ProofElementsLimit`; `diagnostics` | `usize` | `65_536` | `crates/disrobe-query/src/jvm.rs` |
| `disrobe-query` | `MAX_QUERY_ARGUMENT_BYTES` | size | error: `ParseError::ArgumentTooLong` | `usize` | `4 * 1024` | `crates/disrobe-query/src/parse.rs` |
| `disrobe-query` | `MAX_QUERY_BYTES` | size | error: `ParseError::TooLong` | `usize` | `8 * 1024` | `crates/disrobe-query/src/parse.rs` |
| `disrobe-semdiff` | `MAX_LINEAGE_VARIANTS` | other | silent: slice in `variant_lineage` | `usize` | `32` | `crates/disrobe-semdiff/src/lineage.rs` |
| `disrobe-semdiff` | `MAX_FUNCTIONS_PER_MODULE` | other | recorded: `Indeterminate::FunctionCountCapExceeded`; `refused_report()` | `usize` | `50_000` | `crates/disrobe-semdiff/src/structural.rs` |
| `disrobe-semdiff` | `MAX_PROPAGATION_ROUNDS` | work | recorded: flag `exhausted_by_cap` | `u32` | `8` | `crates/disrobe-semdiff/src/structural.rs` |
| `disrobe-semdiff` | `MAX_ADDRESS_PEEL_STEPS` | work | silent: `while` condition in `address_form` | `u32` | `32` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_BLOCKS` | other | error: `SummaryDecline::BlockCountExceeded` | `usize` | `128` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_DEPTH` | recursion | recorded: `SummaryDecline::DepthBudgetExhausted` | `u32` | `128` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_INSTRUCTIONS` | other | error: `SummaryDecline::InstructionCountExceeded` | `usize` | `4096` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_MEMORY_CELLS` | other | recorded: `SummaryDecline::MemoryCellBudgetExhausted` | `usize` | `256` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_NODES` | count | recorded: `SummaryDecline::NodeBudgetExhausted` | `usize` | `4096` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-semdiff` | `MAX_SUMMARY_OUTPUTS` | output | recorded: `SummaryDecline::OutputBudgetExhausted` | `usize` | `64` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-similarity` | `REFINEMENT_ROUND_CAP` | work | silent: `for` range in `refine` | `usize` | `16` | `crates/disrobe-similarity/src/fingerprint.rs` |
| `disrobe-similarity` | `PROPAGATION_ROUND_CAP` | work | silent: `for` range in `propagate` | `usize` | `64` | `crates/disrobe-similarity/src/matcher/propagation.rs` |
| `disrobe-similarity` | `DEFAULT_LISTING_LIMIT` | other | unused: no use in the crate | `usize` | `25` | `crates/disrobe-similarity/src/presentation.rs` |
| `disrobe-sleigh` | `MAX_DECODE_CONSTRUCTOR_ATTEMPTS` | other | recorded: `DecodeOutcome::ResourceLimit`; flag `exceeded` | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_EVALUATION_DEPTH` | recursion | error: `SleighError::Parse` | `usize` | `128` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_FIXED_BITS_MEMO_ENTRIES` | count | silent: skipped in `table_bits` | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_PATTERN_CLAUSES` | other | recorded: flag `unavailable` | `usize` | `4_096` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_CLAUSES` | other | silent: `return` in `remember_table_clauses` | `usize` | `4_194_304` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_ENTRIES` | count | silent: `return` in `remember_table_clauses` | `usize` | `65_536` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CONSTRUCTORS` | other | error: `SleighError::Parse` | `usize` | `4_096` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `UNSUPPORTED_ENCODING_CAPTURE_LIMIT` | other | silent: `.min()` clamp in `unsupported_length` | `usize` | `24` | `crates/disrobe-sleigh/src/lifter/riscv.rs` |
| `disrobe-sleigh` | `MAX_CONDITION_DEPTH` | recursion | silent: `return` in `parse_unary` | `usize` | `64` | `crates/disrobe-sleigh/src/preprocessor.rs` |
| `disrobe-sleigh` | `MAX_ITEM_DEPTH` | recursion | silent: `return` in `parse_with` | `usize` | `64` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_PATTERN_NESTING` | recursion | silent: `return` in `pattern_nesting_exceeds` | `usize` | `64` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_SOURCE_BYTES` | size | error: `SleighError::Parse` | `usize` | `4 * 1024 * 1024` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_TOKEN_COUNT` | count | error: `SleighError::Parse` | `usize` | `500_000` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-taint` | `CALL_EDGE_TARGET_CAP` | other | recorded: `CallEdgeEvidence::CandidateSetLimit`; flag `over_cap` | `usize` | `4_096` | `crates/disrobe-taint/src/callgraph.rs` |
| `disrobe-taint` | `MAX_INTERNED` | other | recorded: flag `truncated` | `u16` | `63` | `crates/disrobe-taint/src/config.rs` |
| `disrobe-taint` | `MAX_OUT_ARGUMENTS_PER_SOURCE` | other | silent: skipped in `insert_out_argument` | `usize` | `32` | `crates/disrobe-taint/src/config.rs` |
| `disrobe-taint` | `MAX_PATH_STEPS` | work | silent: `.truncate()` in `append_step`; no action in `append_step` | `usize` | `128` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-taint` | `MAX_RECORDED_UNRESOLVED_CALLS` | other | silent: skipped in `collect_unresolved_calls` | `usize` | `4096` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-testkit` | `MAX_OPTIONAL_LIST_BYTES` | size | error: `PrerequisiteError::OptionalListTooLarge` | `u64` | `256 * 1024` | `crates/disrobe-testkit/src/prerequisite.rs` |
| `disrobe-testkit` | `MAX_RECORD_NAME` | other | silent: `.take()` in `record_name` | `usize` | `160` | `crates/disrobe-testkit/src/prerequisite.rs` |
| `disrobe-testkit` | `MAX_CORPUS_ENTRY_BYTES` | size | error: `StressError::CorpusEntryTooLarge` | `usize` | `MAX_WIRE_CASE_BYTES / 4` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-testkit` | `MAX_ENTRY_NAME_BYTES` | size | error: `ErrorKind::InvalidData`; `StressError::Inconsistent` | `usize` | `4096` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-testkit` | `MAX_WIRE_CASE_BYTES` | size | error: `ErrorKind::InvalidData`; `StressError::CorpusEntryTooLarge`; `StressError::MutatedCaseTooLarge` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-testkit/src/wire.rs` |
| `disrobe-tool-process` | `MAX_GROUP_MEMBERS` | count | silent: `return` in `macos_group_contains_only_zombies` | `usize` | `1024` | `crates/disrobe-tool-process/src/unix.rs` |
| `disrobe-tool-process` | `MAX_COMMAND_LINE_UNITS` | other | error: `LaunchError::InvalidInput` | `usize` | `32_767` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_BLOCK_UNITS` | other | error: `LaunchError::InvalidInput` | `usize` | `1_048_576` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_INPUT_ENTRIES` | count | error: `LaunchError::InvalidInput` | `usize` | `1_048_576` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_ENVIRONMENT_STRING_UNITS` | other | error: `LaunchError::InvalidInput` | `usize` | `32_767` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_NORMAL_PROGRAM_PATH_UNITS` | other | silent: `return` in `child_visible_path` | `usize` | `259` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-tool-process` | `MAX_RETAINED_ENVIRONMENT_BYTES` | size | error: `LaunchError::InvalidInput` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-typerec` | `MAX_COPY_DEPTH` | recursion | silent: `return` in `reg_slot_source` | `u8` | `8` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MAX_THUNK_INSNS` | other | silent: `.take()` in `follow_thunk`; slice in `follow_thunk` | `usize` | `8` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MIN_SOLVE_BUDGET` | work | silent: `break` in `solve` | `usize` | `4096` | `crates/disrobe-typerec/src/constraint.rs` |
| `disrobe-typerec` | `MAX_DECODE_INSNS` | other | silent: `while` condition in `decode_all` | `usize` | `1 << 16` | `crates/disrobe-typerec/src/decode.rs` |
| `disrobe-typerec` | `MAX_DIE_VISITS` | other | silent: `break` in `collect_unit`; `break` in `walk_functions` | `usize` | `1 << 20` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_FIELDS` | other | silent: `return` in `flatten_members` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_PARAMS` | other | silent: skipped in `collect_unit` | `usize` | `64` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_TYPE_DEPTH` | recursion | silent: `return` in `flatten_members`; `return` in `name_through_origin`; `return` in `resolve_int_type`; 2 more | `u8` | `16` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_UNITS` | other | silent: `break` in `walk_functions` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_VARS_PER_FUNCTION` | other | recorded: `.record_unlocated()`; `UnlocatedReason::VariableBudgetExhausted` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_EXPRESSION_OPERATIONS` | other | silent: `return` in `classify_expression` | `usize` | `64` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_LOCATION_LIST_ENTRIES` | count | silent: `while` condition in `frame_slots`; `while` condition in `resolve_frame_base`; skipped in `push_slots`; 1 more | `usize` | `512` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_PROLOGUE_INSTRUCTIONS` | other | silent: `while` condition in `frame_pointer_delta_from_prologue` | `usize` | `32` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_DESCRIPTORS` | other | silent: `break` in `collect_pe_delay`; `break` in `collect_pe_imports` | `usize` | `1 << 14` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_ENTRIES` | count | silent: `break` in `collect_pe_delay`; `break` in `collect_pe_imports`; `break` in `collect_pe_thunks`; 3 more | `usize` | `1 << 21` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_THUNKS` | other | silent: `break` in `collect_pe_delay`; `break` in `collect_pe_thunks` | `u64` | `1 << 20` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_HEAP_BLOCKS` | other | silent: `return` in `heap_registers` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_ROUNDS` | work | silent: `.min()` clamp in `heap_registers` | `usize` | `1 << 3` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_SLOTS` | other | silent: skipped in `heap_transfer` | `usize` | `1 << 6` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_REGION_CELLS` | other | recorded: flag `capped` | `usize` | `1 << 8` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_STACK_SLOTS` | other | silent: `return` in `group_offsets` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SITES` | other | silent: `return` in `record_allocator_site` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SYMBOLS` | other | silent: `.take()` in `absorb_allocator_definitions` | `usize` | `1 << 20` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_RELOC_TARGETS` | other | silent: `return` in `record_reloc_target` | `usize` | `1 << 16` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_SECTIONS` | other | silent: `.take()` in `absorb_allocator_thunks`; `.take()` in `absorb_relocations`; `.take()` in `absorb_sections` | `usize` | `1 << 12` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_THUNK_SCAN` | other | silent: `return` in `absorb_allocator_thunks`; slice in `absorb_allocator_thunks` | `usize` | `1 << 24` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-validator` | `MAX_CORPUS_DEPTH` | recursion | silent: `return` in `collect` | `usize` | `64` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-validator` | `MAX_CORPUS_ENTRIES` | count | silent: `return` in `collect` | `usize` | `65_536` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-validator` | `MAX_HASH_DEPTH` | recursion | error: untyped `format!` | `usize` | `64` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_HASH_FILES` | count | error: untyped `format!` | `usize` | `65_536` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_HASH_FILE_BYTES` | size | error: untyped `format!` | `u64` | `64 * 1024 * 1024` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-validator` | `MAX_SAMPLE_BYTES` | size | error: untyped `format!` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-validator/src/runner.rs` |
| `disrobe-vulnmatch` | `MAX_RESOLVED_INDIRECT_CALLEES_PER_SITE` | other | recorded: flag `traversal_complete` | `usize` | `16` | `crates/disrobe-vulnmatch/src/adapters.rs` |
| `disrobe-vulnmatch` | `MAX_CONSTRAINT_BYTES` | size | error: `ConstraintError::TooLong` | `usize` | `8 * 1024` | `crates/disrobe-vulnmatch/src/constraint.rs` |
| `disrobe-vulnmatch` | `MAX_CONSTRAINT_NODES` | count | error: `ConstraintError::TooManyPredicates`; `VersionScheme::Python` | `usize` | `256` | `crates/disrobe-vulnmatch/src/constraint.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_INPUTS` | other | recorded: `PackageMatchIssue::LimitExceeded`; flag `complete` | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_OUTPUT_BYTES` | output | recorded: `PackageMatchIssue::LimitExceeded`; flag `complete` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_RESULTS` | other | recorded: `PackageMatchIssue::LimitExceeded`; flag `complete` | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_TEXT_BYTES` | size | recorded: `PackageMatchIssue::LimitExceeded`; flag `complete` | `usize` | `8 * 1024` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_MATCH_WORK` | work | recorded: `PackageMatchIssue::LimitExceeded`; flag `complete` | `usize` | `1_048_576` | `crates/disrobe-vulnmatch/src/matcher.rs` |
| `disrobe-vulnmatch` | `MAX_AFFECTED` | other | error: `OfflineMatchError::OsvCountLimit` | `usize` | `4_096` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EVALUATION_WORK` | work | error: `EvaluationError::WorkLimit` | `usize` | `2_000_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EVENTS` | other | error: `OfflineMatchError::OsvCountLimit` | `usize` | `512` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_EXPLICIT_VERSIONS` | other | error: `OfflineMatchError::OsvCountLimit` | `usize` | `8_192` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_FIELD_BYTES` | size | error: `OfflineMatchError::InvalidOsReleaseValue`; `OfflineMatchError::MalformedStatus` | `usize` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_FINDINGS` | other | recorded: `OfflineMatchIssueKind::WorkLimitReached`; flag `complete` | `usize` | `10_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_ISSUES` | other | recorded: flag `complete` | `usize` | `10_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_LINE_BYTES` | size | error: `OfflineMatchError::LineTooLong` | `usize` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_OSV_BYTES` | size | error: `OfflineMatchError::AllocationFailed`; `OfflineMatchError::FileTooLarge` | `u64` | `16 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_OS_RELEASE_BYTES` | size | error: `OfflineMatchError::AllocationFailed`; `OfflineMatchError::FileTooLarge` | `u64` | `64 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGES` | other | error: `OfflineMatchError::TooManyPackages` | `usize` | `100_000` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_FIELD_BYTES` | size | error: `OfflineMatchError::InvalidOsvField` | `usize` | `4 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_RANGES` | other | error: `OfflineMatchError::OsvCountLimit` | `usize` | `128` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_STANZA_BYTES` | size | error: `OfflineMatchError::StanzaTooLarge` | `usize` | `1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_STATUS_BYTES` | size | error: `OfflineMatchError::FileTooLarge` | `u64` | `256 * 1024 * 1024` | `crates/disrobe-vulnmatch/src/offline.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_URL_INPUT_BYTES` | size | error: `PackageUrlError::TooLong` | `usize` | `16_384` | `crates/disrobe-vulnmatch/src/package_url.rs` |
| `disrobe-vulnmatch` | `MAX_PACKAGE_URL_OUTPUT_BYTES` | output | error: `PackageUrlError::OutputTooLong` | `usize` | `56 * 1024` | `crates/disrobe-vulnmatch/src/package_url.rs` |
| `disrobe-vulnmatch` | `MAX_VERSION_BYTES` | size | error: `VersionError::TooLong` | `usize` | `4 * 1024` | `crates/disrobe-vulnmatch/src/version.rs` |
| `disrobe-vulnmatch` | `MAX_VERSION_PARTS` | other | error: `VersionScheme::Alpine`; `VersionScheme::Python`; `VersionScheme::Semver` | `usize` | `256` | `crates/disrobe-vulnmatch/src/version.rs` |
| `disrobe-wasm` | `MAX_ENTROPY_BLOCKS` | other | silent: `while` condition in `entropy` | `usize` | `4096` | `crates/disrobe-wasm/src/entry.rs` |
| `disrobe-wasm` | `MAX_DECODED_BYTES` | size | error: untyped `format!`; untyped error | `u64` | `128 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_ENTRIES` | count | error: `.to_string()` | `usize` | `4096` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_ENTRY_BYTES` | size | error: untyped `format!` | `u64` | `32 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_MANIFEST_BYTES` | size | error: `.to_string()` | `u64` | `2 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/apk.rs` |
| `disrobe-wasm` | `MAX_INSTRUCTIONS` | other | error: `.to_owned()` | `usize` | `65_536` | `crates/disrobe-wasm/src/entry/dotnet.rs` |
| `disrobe-wasm` | `MAX_METHOD_INSTRUCTIONS` | other | error: `.to_owned()` | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/dotnet.rs` |
| `disrobe-wasm` | `MAX_IMAGE_NAMES` | other | error: `.to_string()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_INPUT` | other | error: `.to_string()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_RECORDS` | count | error: `.to_string()` | `usize` | `131_072` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_SYMBOLS` | other | error: `.to_string()` | `u64` | `65_536` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_TYPES` | other | error: `.to_string()` | `u64` | `16_384` | `crates/disrobe-wasm/src/entry/go.rs` |
| `disrobe-wasm` | `MAX_CONSTANT_POOL_SLOTS` | other | error: `.to_owned()` | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_FIELDS` | other | error: `.to_owned()` | `usize` | `4096` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_INSTRUCTIONS` | other | error: `.to_owned()` | `usize` | `65_536` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHODS` | other | error: `.to_owned()` | `usize` | `1024` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHOD_EDGES` | other | error: `.to_owned()` | `usize` | `2048` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_METHOD_INSTRUCTIONS` | other | error: `.to_owned()` | `usize` | `16_384` | `crates/disrobe-wasm/src/entry/jvm.rs` |
| `disrobe-wasm` | `MAX_ENTRIES` | count | error: `.to_string()` | `usize` | `4096` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_MEMBER_BYTES` | size | error: `.to_string()` | `usize` | `32 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_NAME_BYTES` | size | error: `.to_string()` | `usize` | `1024 * 1024` | `crates/disrobe-wasm/src/entry/phar.rs` |
| `disrobe-wasm` | `MAX_METADATA_BYTES` | size | error: `.to_string()` | `usize` | `8 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_RUNTIME_BYTES` | size | error: `.to_string()` | `usize` | `16 * 1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_WRAPPER_BYTES` | size | error: `.to_string()` | `usize` | `1024 * 1024` | `crates/disrobe-wasm/src/entry/pyarmor.rs` |
| `disrobe-wasm` | `MAX_GUEST_ALLOC` | other | silent: `return` in `disrobe_alloc`; `return` in `disrobe_free` | `usize` | `1 << 30` | `crates/disrobe-wasm/src/lib.rs` |
| `disrobe-wasm` | `MAX_INPUT_BYTES` | size | error: `.to_string()`; untyped error | `usize` | `64 * 1024 * 1024` | `crates/disrobe-wasm/src/lib.rs` |
| `disrobe-wasm` | `MAX_RESULT_PAYLOAD` | other | silent: `return` in `disrobe_result_free`; `return` in `pack_prefixed_result` | `usize` | `64 * 1024 * 1024` | `crates/disrobe-wasm/src/lib.rs` |

## Silent stops

1005 bounds stop a loop, clamp a value or skip work with no typed error and no record when input exceeds them. Each is a defect: a parser recovers or refuses with a label, and malformed input is a typed error.

| Crate | Constant | Use | File |
| --- | --- | --- | --- |
| `disrobe-binfmt` | `SCAN_HIT_CAP` | `while` condition in `scan_magics` | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `STREAM_DECODE_CAP` | `.take()` in `decode_validate`; `return` in `bzip2_exact_extent`; `return` in `gzip_exact_extent`; 1 more | `crates/disrobe-binfmt/src/carve.rs` |
| `disrobe-binfmt` | `MAX_OMAP_ENTRIES` | `break` in `omap_leaf_mappings`; `for` range in `walk_fs_tree_leaf` | `crates/disrobe-binfmt/src/containers/apfs.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_DEPTH` | `break` in `walk_cramfs` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_CRAMFS_FILES` | `break` in `walk_cramfs` | `crates/disrobe-binfmt/src/containers/cramfs.rs` |
| `disrobe-binfmt` | `MAX_DOC_LEN` | `.min()` clamp in `read_c_string`; `.take()` in `find_doc_starting_with` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_FILETABLE_ENTRIES` | `for` range in `recover_source_files` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_LEN` | `return` in `module_name_from_init`; no action in `locate_module_init` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_NAME_LEN` | `.min()` clamp in `read_c_string`; `return` in `is_valid_identifier`; skipped in `scan_source_strings` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_SOURCE_FILES` | skipped in `push_unique` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_RECORDS` | `return` in `recover_structural` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STRUCTURAL_SCAN_ATTEMPTS` | `return` in `recover_structural` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_TABLE_ENTRIES` | `while` condition in `walk_method_table` | `crates/disrobe-binfmt/src/containers/cython.rs` |
| `disrobe-binfmt` | `MAX_STUB_BYTES` | `return` in `render_cython_stub` | `crates/disrobe-binfmt/src/containers/cython_stub.rs` |
| `disrobe-binfmt` | `MAX_MAGIC_CANDIDATES` | `.take()` in `magic_offsets` | `crates/disrobe-binfmt/src/containers/deno_compile.rs` |
| `disrobe-binfmt` | `MAX_CHUNKS` | `return` in `parse_mish_chunks` | `crates/disrobe-binfmt/src/containers/dmg.rs` |
| `disrobe-binfmt` | `MAX_PLAUSIBLE_MAJOR_VERSION` | `return` in `header_is_plausible` | `crates/disrobe-binfmt/src/containers/dotnet_bundle.rs` |
| `disrobe-binfmt` | `PE_SECTION_LIMIT` | `return` in `pe_has_enigma_sections` | `crates/disrobe-binfmt/src/containers/enigma.rs` |
| `disrobe-binfmt` | `MAX_CANDIDATE_OFFSETS` | `.truncate()` in `candidate_offsets`; `break` in `scan_magic_offsets` | `crates/disrobe-binfmt/src/containers/eszip.rs` |
| `disrobe-binfmt` | `MAX_DIR_RECURSION` | `return` in `walk_dir` | `crates/disrobe-binfmt/src/containers/fat.rs` |
| `disrobe-binfmt` | `MAX_PART_OUTPUT` | `.take()` in `decompress_xz` | `crates/disrobe-binfmt/src/containers/flatpak.rs` |
| `disrobe-binfmt` | `MAX_FILES` | `return` in `walk_leaf_records` | `crates/disrobe-binfmt/src/containers/hfsplus.rs` |
| `disrobe-binfmt` | `MAX_INNO_HEADER_STRING` | `return` in `read_inno_string`; `return` in `skip_inno_string` | `crates/disrobe-binfmt/src/containers/innosetup.rs` |
| `disrobe-binfmt` | `MAX_FILE_GROUPS` | `while` condition in `read_file_groups` | `crates/disrobe-binfmt/src/containers/installshield.rs` |
| `disrobe-binfmt` | `MAX_FILES` | `continue` in `walk_jffs2` | `crates/disrobe-binfmt/src/containers/jffs2.rs` |
| `disrobe-binfmt` | `MAX_MODULE_NAME_BYTES` | `return` in `read_minidump_string` | `crates/disrobe-binfmt/src/containers/minidump/mod.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | `break` in `walk_minixfs` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | `break` in `walk_minixfs` | `crates/disrobe-binfmt/src/containers/minixfs.rs` |
| `disrobe-binfmt` | `MAX_STREAM_BYTES` | `.take()` in `read_msi_extractable` | `crates/disrobe-binfmt/src/containers/msi.rs` |
| `disrobe-binfmt` | `MAX_DEPTH` | `break` in `walk_ntfs` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILES` | `break` in `walk_ntfs` | `crates/disrobe-binfmt/src/containers/ntfs.rs` |
| `disrobe-binfmt` | `MAX_FILEZ_CONTENT` | `.take()` in `inflate_raw_deflate` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `MAX_OSTREE_DIR_ENTRIES` | `.take()` in `collect_refs_recursive`; `.take()` in `count_objects`; `.take()` in `reconstruct_delta_dirs` | `crates/disrobe-binfmt/src/containers/ostree.rs` |
| `disrobe-binfmt` | `PM1_TREE_WALK_LIMIT` | `for` range in `read_byte_decode_index` | `crates/disrobe-binfmt/src/containers/pmarc.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | `for` range in `make_decode_table`; `while` condition in `decode_number` | `crates/disrobe-binfmt/src/containers/rar_unpack3.rs` |
| `disrobe-binfmt` | `MAX_LENGTH` | `for` range in `make_decode_table`; `while` condition in `decode_number` | `crates/disrobe-binfmt/src/containers/rar_unpack5.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_DEPTH` | `continue` in `walk_romfs` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_ROMFS_FILES` | `return` in `walk_romfs` | `crates/disrobe-binfmt/src/containers/romfs.rs` |
| `disrobe-binfmt` | `MAX_METADATA_BLOCK` | `return` in `read_metadata_block_at`; `while` condition in `read_metadata_at` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_PATH_DEPTH` | `break` in `walk_squashfs` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_WALK_FILES` | `break` in `walk_squashfs` | `crates/disrobe-binfmt/src/containers/squashfs.rs` |
| `disrobe-binfmt` | `MAX_SECTION_NAME` | `return` in `section_name` | `crates/disrobe-binfmt/src/coverage/elf.rs` |
| `disrobe-binfmt` | `MAX_DT_STRSZ` | `return` in `parse_elf_dynamic` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_ENTRIES` | `return` in `parse_elf_dynamic` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DYNAMIC_STRING_OUTPUT` | `return` in `resolve_bounded_string` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_NEEDED` | `return` in `push_needed_offset` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_PROGRAM_HEADERS` | `return` in `parse_elf_dynamic` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_STRING_LEN` | `.min()` clamp in `read_cstr` | `crates/disrobe-binfmt/src/elf_dynamic.rs` |
| `disrobe-binfmt` | `MAX_DISK_NESTING_DEPTH` | `return` in `recurse_into_filesystem` | `crates/disrobe-binfmt/src/extract.rs` |
| `disrobe-binfmt` | `MAX_NOTES_PER_SEGMENT` | `for` range in `find_build_ids` | `crates/disrobe-binfmt/src/rewrite/elf.rs` |
| `disrobe-binfmt` | `MAX_DIRECTORY_SLOTS` | `.min()` clamp in `plan` | `crates/disrobe-binfmt/src/rewrite/pe.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURES` | `.take()` in `push_file_strings_with_limits` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_FEATURE_BYTES` | `continue` in `push_file_strings_with_limits` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_FILE_STRING_SCAN_BYTES` | `.min()` clamp in `push_file_strings_with_limits` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_NUMBER_FEATURES_PER_INSN` | skipped in `instruction_features` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `PE_HEADER_SCAN_CAP` | `.min()` clamp in `embedded_pe_offset` | `crates/disrobe-capabilities/src/extract.rs` |
| `disrobe-capabilities` | `MAX_IMPORT_ENTRIES` | `break` in `from_elf`; `break` in `from_pe` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-capabilities` | `MAX_STUB_SPAN` | `.min()` clamp in `name_at_thunk` | `crates/disrobe-capabilities/src/imports.rs` |
| `disrobe-cfg` | `RETURN_TAIL_NODE_CAP` | `return` in `private_return_tail` | `crates/disrobe-cfg/src/lib.rs` |
| `disrobe-cfg` | `MAX_RECONVERGENCE_CLONES` | `.min()` clamp in `tight_for_reconvergence` | `crates/disrobe-cfg/src/reconverge.rs` |
| `disrobe-cli` | `RESOURCE_PREVIEW_LIMIT` | `.min()` clamp in `render_resources` | `crates/disrobe-cli/src/cli/apk.rs` |
| `disrobe-cli` | `MAX_EVIDENCE_SHOWN` | `.take()` in `push_anti_analysis_evidence_lines`; `.take()` in `render_text`; no action in `push_anti_analysis_evidence_lines`; 1 more | `crates/disrobe-cli/src/cli/behavior.rs` |
| `disrobe-cli` | `MAX_SIDECAR_REDACTION_BYTES` | `return` in `sidecar_shape` | `crates/disrobe-cli/src/cli/chain_v1.rs` |
| `disrobe-cli` | `MAX_REPORTS_GRADED` | `break` in `find_reports` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_REPORT_SEARCH_DEPTH` | `for` range in `find_reports` | `crates/disrobe-cli/src/cli/context.rs` |
| `disrobe-cli` | `MAX_INSTALL_LOG_ENTRIES` | no action in `trim_install_log`; slice in `trim_install_log` | `crates/disrobe-cli/src/cli/install/mod.rs` |
| `disrobe-cli` | `DELPHI_LIST_LIMIT` | `.take()` in `render_delphi_classes`; `.take()` in `render_delphi_forms`; `.take()` in `render_delphi_types`; 3 more | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LOWEST_COVERED_CAP` | `.truncate()` in `lowest_covered` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `SYMBOL_PREVIEW_LIMIT` | `.min()` clamp in `render_cxx_class_rows`; `.min()` clamp in `render_import_rows`; `.min()` clamp in `render_symbol_rows` | `crates/disrobe-cli/src/cli/native.rs` |
| `disrobe-cli` | `LITERAL_PREVIEW_LIMIT` | `.take()` in `preview`; `return` in `preview` | `crates/disrobe-cli/src/cli/native_match.rs` |
| `disrobe-cli` | `MAX_BEHAVIOR_EVIDENCE` | `.take()` in `render_behavior_row`; no action in `render_behavior_row` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-cli` | `MAX_IOC_ROWS` | `.take()` in `render_indicators`; no action in `render_indicators` | `crates/disrobe-cli/src/cli/report_html.rs` |
| `disrobe-core` | `ANTI_ANALYSIS_SCAN_CAP` | slice in `scan_with_chain` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_EXEMPLARS_PER_KIND` | `.take()` in `cap_evidence`; no action in `cap_evidence` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_MACHO_LOAD_CMDS` | `.min()` clamp in `macho_code_layout` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_PARSED_SECTIONS` | `.min()` clamp in `elf_code_layout`; `.min()` clamp in `macho_segment_sections`; `.min()` clamp in `pe_code_layout` | `crates/disrobe-core/src/anti_analysis.rs` |
| `disrobe-core` | `MAX_CACHE_ENTRY_BYTES` | `.take()` in `read_entry_file`; `return` in `read_entry_file` | `crates/disrobe-core/src/cache.rs` |
| `disrobe-core` | `JOSE_HEADER_DECODE_CAP` | `return` in `decode_base64url`; `return` in `decode_jose_header` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_SCAN` | slice in `classify` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_STATIC_PASSPHRASES` | `break` in `static_passphrase_candidates`; `while` condition in `push_label_passphrases` | `crates/disrobe-core/src/codec/crypto_wall.rs` |
| `disrobe-core` | `MAX_ENTITY_NAME` | fallback value in `html_entity_decode_with_scan` | `crates/disrobe-core/src/codec/web_escape.rs` |
| `disrobe-core` | `MS_CAP` | `return` in `pretty_duration` | `crates/disrobe-core/src/provenance.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOBS` | `break` in `report_git` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_BLOB_BYTES` | `continue` in `report_git` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_HISTORY_COMMITS` | `break` in `report_git` | `crates/disrobe-core/src/recon/git_history.rs` |
| `disrobe-core` | `MAX_BLOB_DECODE` | `continue` in `decode_and_recurse`; `continue` in `decode_codecs_and_recurse` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_CODEC_TOKEN` | `continue` in `decode_codecs_and_recurse` | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_INDICATORS` | `break` in `extract_with_work`; `break` in `scan_text_layer`; `return` in `collect_domains`; 7 more | `crates/disrobe-core/src/recon/ioc.rs` |
| `disrobe-core` | `MAX_BASE64_DECODED_TOTAL` | `break` in `base64_decode_findings`; `continue` in `base64_decode_findings` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_DEPTH` | `return` in `base64_decode_findings` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_BASE64_RUNS` | `break` in `base64_decode_findings` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DECODED_TOTAL` | `break` in `codec_cascade_findings`; `return` in `codec_peel_token` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_DEPTH` | `return` in `codec_cascade_findings` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CODEC_RUN` | `return` in `codec_output_advances`; `return` in `codec_peel_token` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_CONTAINER_DEPTH` | skipped in `scan_blob` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_FILE_BYTES` | `.take()` in `read_scan_file`; `return` in `read_scan_file` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_TREE_FILES` | `break` in `walk_with_limit` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_WIDE_RUNS` | `break` in `merge_runs`; `return` in `push_narrow_run`; `return` in `push_wide_run`; 2 more | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_ZIP_ENTRIES` | `.min()` clamp in `scan_zip_bytes`; `break` in `scan_tar_bytes` | `crates/disrobe-core/src/recon/mod.rs` |
| `disrobe-core` | `MAX_RUNS` | `break` in `merge_runs`; `return` in `push_narrow_run`; `return` in `push_wide_run`; 2 more | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_RUN_BYTES` | `continue` in `unit_runs_wide`; no action in `collect_narrow_runs`; slice in `text_runs` | `crates/disrobe-core/src/recon/string_emu.rs` |
| `disrobe-core` | `MAX_DECODE_RECURSE_LEN` | `continue` in `recover_base64`; `continue` in `recover_codec` | `crates/disrobe-core/src/strings.rs` |
| `disrobe-core` | `MAX_PE_SECTIONS` | `return` in `pe_header_is_valid` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `ZIP_SEARCH_BUDGET` | `while` condition in `find_eocd` | `crates/disrobe-core/src/structural.rs` |
| `disrobe-core` | `MAX_STRINGS` | `break` in `select_strings` | `crates/disrobe-core/src/yara_gen.rs` |
| `disrobe-core` | `HEX_WORK_BUDGET` | `return` in `hex_matches_at` | `crates/disrobe-core/src/yara_match/atoms.rs` |
| `disrobe-irsummary` | `MAX_FIXPOINT_ROUNDS` | `for` range in `optimize_graph` | `crates/disrobe-irsummary/src/optimize.rs` |
| `disrobe-irsummary` | `MAX_BLOCKS` | `return` in `build_region`; `return` in `collect_leaders` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_BLOCK_INSNS` | `return` in `build_block`; `return` in `collect_leaders` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_INSNS` | `return` in `summarize_function` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_JOINS` | `return` in `summarize_region` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_OUTPUTS` | `return` in `finalize` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-irsummary` | `MAX_STACK_DEPTH` | `return` in `push` | `crates/disrobe-irsummary/src/symexec.rs` |
| `disrobe-lift-x86` | `MAX_X86_BLOCK_BYTES` | `.min()` clamp in `decode_block`; `.min()` clamp in `invalid_bitness_block`; fallback value in `with_limits` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-lift-x86` | `MAX_X86_INSTRUCTIONS` | `while` condition in `decode_block`; fallback value in `with_limits` | `crates/disrobe-lift-x86/src/lib.rs` |
| `disrobe-llm-metadata` | `MAX_PII_ENTRIES` | `.min()` clamp in `scan` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_SCAN_BYTES` | `.min()` clamp in `scan` | `crates/disrobe-llm-metadata/src/pii.rs` |
| `disrobe-llm-metadata` | `MAX_DECLARED_TYPE_BYTES` | `return` in `parse_declared_type` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_FUNCTIONS` | skipped in `add_function` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_OBSERVATIONS_PER_VAR_U32` | skipped in `observe` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-llm-metadata` | `MAX_VARIABLES_PER_FN` | skipped in `add_local`; skipped in `add_parameter` | `crates/disrobe-llm-metadata/src/usage_inference.rs` |
| `disrobe-mba` | `BFS_TABLE_BUDGET` | `return` in `minimal_bitwise_for_table` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BITWISE_SYNTH_VARS` | `return` in `synthesize_bitwise_masked`; no action in `simplify_l0_l5` | `crates/disrobe-mba/src/bitwise_synth.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_ATOMS` | `return` in `boolean_minimization_candidate`; `return` in `collect_boolean_atoms`; `return` in `collect_predicate_atoms`; 2 more | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_BOOLEAN_PRIMES` | `return` in `minimize_sop` | `crates/disrobe-mba/src/boolean.rs` |
| `disrobe-mba` | `MAX_CFF_BLOCKS` | `return` in `devirtualize_cheap`; `return` in `devirtualize_table_dispatch`; `return` in `devirtualize_traced` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `MAX_REGION_NODES` | `return` in `run` | `crates/disrobe-mba/src/cff/detect.rs` |
| `disrobe-mba` | `CHEAP_LOOP_CAP` | `for` range in `cheap_initial`; `for` range in `cheap_resolve_block`; `return` in `cheap_initial`; 1 more | `crates/disrobe-mba/src/cff/mod.rs` |
| `disrobe-mba` | `BANK_CAP` | skipped in `offer` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `GEN_BUDGET` | `return` in `expand_layer`; `return` in `grow`; `return` in `offer` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ATOMS` | `return` in `push_atom` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CANDIDATE_NODES` | `.min()` clamp in `synthesize` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CONSTS` | `.truncate()` in `build_consts` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_ROUNDS` | `for` range in `grow` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_VARS` | `return` in `synthesize` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `VERIFY_BUDGET` | no action in `offer` | `crates/disrobe-mba/src/enum_synth.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_DEGREE` | `return` in `composition_is_identity`; `return` in `polynomial_is_zero_function` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MULTIVAR_EVAL_BUDGET` | `return` in `multivar_induces_zero` | `crates/disrobe-mba/src/finite_diff.rs` |
| `disrobe-mba` | `MAX_TABLE_ENTRIES` | `.min()` clamp in `solver_resolve`; `return` in `solver_resolve`; `return` in `try_resolve_vsa` | `crates/disrobe-mba/src/jumptable/mod.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | `return` in `synthesize_linear_basis` | `crates/disrobe-mba/src/linear_mba.rs` |
| `disrobe-mba` | `MAX_SOLVER_VARS` | `return` in `solve_linear_mba`; `return` in `verify_equivalent`; no action in `simplify_l0_l5` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_COMBOS` | `return` in `subset_combinations` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_SUBSET_SEARCH_VARS` | skipped in `solve_linear_mba` | `crates/disrobe-mba/src/linear_solver.rs` |
| `disrobe-mba` | `MAX_ATOM_DEGREE` | `return` in `to_falling_factorial`; `return` in `to_power_basis` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_ATOMS` | `return` in `intern_atom` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MBA_VARS` | `return` in `polynomial_solver_work`; `return` in `solve_polynomial_mba`; no action in `simplify_l0_l5` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_POLY_MONOMIALS` | `return` in `multiply_poly`; `return` in `substitute_axis` | `crates/disrobe-mba/src/poly_mba.rs` |
| `disrobe-mba` | `MAX_CERTIFICATE_ATOMS` | `return` in `congruent_to_constant`; `return` in `induces_zero_over_free_atoms` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIALS` | `return` in `multiply` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_MONOMIAL_DEGREE` | `return` in `multiply_monomials` | `crates/disrobe-mba/src/poly_oracle.rs` |
| `disrobe-mba` | `MAX_REWRITE_PASSES` | `for` range in `canonicalize` | `crates/disrobe-mba/src/rewrite.rs` |
| `disrobe-mba` | `MAX_BASIS_VARS` | no action in `simplify_l0_l5` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_LINEAR_VARS` | skipped in `simplify_l0_l5` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `MAX_TEMPLATE_VARS` | skipped in `simplify_l0_l5` | `crates/disrobe-mba/src/simplify.rs` |
| `disrobe-mba` | `EVAL_NODE_BUDGET` | `return` in `eval_term` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_ASSIGNMENTS` | `return` in `enumeration_domain` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_STEPS` | `.min()` clamp in `enumerate_conjunction` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VARS` | `return` in `enumeration_domain` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_ENUM_VAR_BITS` | `return` in `enumeration_domain` | `crates/disrobe-mba/src/symexec/solver_cert.rs` |
| `disrobe-mba` | `MAX_COUNTEREXAMPLE_SLOTS` | `return` in `expand_counterexample` | `crates/disrobe-mba/src/verify.rs` |
| `disrobe-mcp` | `MAX_AMBIGUOUS_CANDIDATES` | `.take()` in `call_outcome_out` | `crates/disrobe-mcp/src/navigation.rs` |
| `disrobe-nir` | `MAX_INDENT_DEPTH` | `.min()` clamp in `write_indent` | `crates/disrobe-nir/src/emit.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_CLONE_BYTES` | `?` on a checked operation in `charge_condition_clone` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir` | `MAX_SHORT_CIRCUIT_TESTS` | `return` in `resolve_condition_edge`; `return` in `short_circuit_candidate` | `crates/disrobe-nir/src/hir.rs` |
| `disrobe-nir-lift` | `MAX_BIG_DECIMAL_BYTES` | `return` in `big_to_decimal` | `crates/disrobe-nir-lift/src/beam.rs` |
| `disrobe-nir-lift` | `MAX_REPORTED_GAPS` | `.take()` in `block_gaps` | `crates/disrobe-nir-lift/src/pcode/arch.rs` |
| `disrobe-nir-lift` | `MAX_FOLD_DEPTH` | `return` in `resolve` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-nir-lift` | `MAX_REACHING_ANALYSIS_ELEMENTS` | `return` in `compute_entries`; `return` in `eliminate_dead_values` | `crates/disrobe-nir-lift/src/pcode/flags.rs` |
| `disrobe-pass-as3` | `MULTINAME_RENDER_BUDGET` | `return` in `render_multiname_bounded` | `crates/disrobe-pass-as3/src/abc.rs` |
| `disrobe-pass-as3` | `MAX_DUP_EXPR_NODES` | `return` in `scope_node_count_capped`; `return` in `walk`; fallback value in `dup_clone` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_MERGE_DEFINITIONS` | `continue` in `merge_tracked_values` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_NEGATION_DEPTH` | `return` in `negate_without_introducing_not` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_OR_GUARD_TESTS` | `return` in `or_guard_shared_target` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_TERNARY_FOLDS` | `for` range in `resolve_ternary` | `crates/disrobe-pass-as3/src/lifter.rs` |
| `disrobe-pass-as3` | `MAX_ARCHNAME_BYTES` | slice in `is_byteloader_stream` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_BYTELOADER_LINE_BYTES` | slice in `skip_line` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_RUNTIME_SYMBOL_SCAN_BYTES` | slice in `detect_with_symbol_scan_limit` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-as3` | `MAX_SHEBANG_LINE_BYTES` | slice in `skip_line` | `crates/disrobe-pass-as3/src/other_langs.rs` |
| `disrobe-pass-beam` | `MAX_LABEL_VISITS` | `return` in `enter_label` | `crates/disrobe-pass-beam/src/body_lift/mod.rs` |
| `disrobe-pass-beam` | `MAX_ARMS` | `return` in `collect`; `return` in `descend`; `return` in `split_receive_arms` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_CONJUNCTS` | `return` in `split_receive_arms` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TERM_DEPTH` | `return` in `cannot_raise`; `return` in `is_guard_safe`; `return` in `is_literal`; 1 more | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_TREE_DEPTH` | `return` in `collect` | `crates/disrobe-pass-beam/src/body_lift/receive_clauses.rs` |
| `disrobe-pass-beam` | `MAX_SCAN_DEPTH` | `return` in `enforced_keys_in`; `return` in `find_enforced_keys`; `return` in `find_struct_list`; 1 more | `crates/disrobe-pass-beam/src/elixir.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | fallback value in `enter` | `crates/disrobe-pass-beam/src/elixir_quoted.rs` |
| `disrobe-pass-beam` | `MAX_RENDER_DEPTH` | fallback value in `enter` | `crates/disrobe-pass-beam/src/erlang_abstract.rs` |
| `disrobe-pass-dotnet` | `EAGER_CCTOR_SCAN_CAP` | `while` condition in `detect` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_NAME_LEN` | `return` in `read_metadata_name` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_PROFILE_MAJOR` | `continue` in `declared_profile` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_READY_TO_RUN_SECTIONS` | `return` in `read_ready_to_run_header` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAMES` | `break` in `recover_names_at_threshold`; `while` condition in `recover_names_at_threshold` | `crates/disrobe-pass-dotnet/src/aot.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_DEPTH` | `return` in `append_output_expression`; `return` in `binary`; `return` in `expression_contains_stack_input` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_EXPRESSION_NODES` | `return` in `binary` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_CIL_HANDLER_INSTRUCTIONS` | `return` in `summarize_cil_handler` | `crates/disrobe-pass-dotnet/src/devirt/cil_handler.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_NODES` | `.min()` clamp in `simplify_expression`; `return` in `count` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_DOTNET_MBA_VARS` | `return` in `intern_leaf`; `return` in `simplify_expression` | `crates/disrobe-pass-dotnet/src/devirt/mba.rs` |
| `disrobe-pass-dotnet` | `MAX_SAMPLES` | `return` in `append_input_case`; `return` in `append_input_values` | `crates/disrobe-pass-dotnet/src/devirt/oracle.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_RVA_BYTES` | `continue` in `build` | `crates/disrobe-pass-dotnet/src/field_rva.rs` |
| `disrobe-pass-dotnet` | `MAX_ARRAY_FIELD_BYTES` | `continue` in `array_field_data` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | `break` in `recover_bitmono_strings` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CIPHERTEXT_BYTES` | `return` in `decrypt_site` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | `continue` in `method_bodies` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_DERIVATIONS` | `return` in `decrypt_site` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PBKDF2_ITERATIONS` | `continue` in `locate_decryptor` | `crates/disrobe-pass-dotnet/src/peel/bitmono_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTANTS_POOL_BYTES` | `continue` in `recover_pool` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_DECODE_ATTEMPTS` | `return` in `recover_strings` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | `break` in `collect_ldc_i4_immediates`; `break` in `recover_pool` | `crates/disrobe-pass-dotnet/src/peel/confuserex_constants.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_CANDIDATES` | `break` in `collect_ldc_i4_immediates`; `break` in `peel_confuserex_resources` | `crates/disrobe-pass-dotnet/src/peel/confuserex_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_METHODS_SCANNED` | `break` in `recover_seeds_by_emulation` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `MAX_SEED_RUN` | `return` in `seed_run` | `crates/disrobe-pass-dotnet/src/peel/confuserex_seed.rs` |
| `disrobe-pass-dotnet` | `KEY_PATH_STEP_CAP` | `return` in `reaches_dispatcher_switch` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `MAX_BLOCKS` | `return` in `build` | `crates/disrobe-pass-dotnet/src/peel/deflatten/blocks.rs` |
| `disrobe-pass-dotnet` | `FIELD_RVA_READ_CAP` | `.min()` clamp in `build_field_env` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_CALL_SITES` | `return` in `scan_call_sites` | `crates/disrobe-pass-dotnet/src/peel/deflatten/decrypt.rs` |
| `disrobe-pass-dotnet` | `NATIVE_STUB_READ_CAP` | `.min()` clamp in `classify` | `crates/disrobe-pass-dotnet/src/peel/deflatten/predicate.rs` |
| `disrobe-pass-dotnet` | `MAX_VISIT` | `break` in `deflatten_with_oracle` | `crates/disrobe-pass-dotnet/src/peel/deflatten/rebuild.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK_VALUES` | `return` in `lower_postfix`; `return` in `verify_straight_line` | `crates/disrobe-pass-dotnet/src/peel/eazvm/cil_mba.rs` |
| `disrobe-pass-dotnet` | `MAX_RESOURCE_BYTES` | `return` in `locate_embedded_resource` | `crates/disrobe-pass-dotnet/src/peel/ilprotector_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_INSTRS_PER_BLOCK` | `for` range in `decode_block` | `crates/disrobe-pass-dotnet/src/peel/koivm/disasm.rs` |
| `disrobe-pass-dotnet` | `MAX_SECTION_BYTES` | `.min()` clamp in `locate_encrypted_section` | `crates/disrobe-pass-dotnet/src/peel/maxtocode_bodies.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_NAME_CHARS` | `.take()` in `bounded_eazvm_analysis_name` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_EAZVM_ANALYSIS_REFUSALS` | skipped in `apply_eazvm_tier` | `crates/disrobe-pass-dotnet/src/peel/mod.rs` |
| `disrobe-pass-dotnet` | `MAX_DISASM_BYTES` | `.min()` clamp in `surface_native_stub` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_SURFACED_INSNS` | `.take()` in `surface_native_stub` | `crates/disrobe-pass-dotnet/src/peel/native_surface.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSORS` | `return` in `prove_constructor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_CODE` | `return` in `prove_accessor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_ACCESSOR_INSTRUCTIONS` | `return` in `prove_accessor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_CODE` | `return` in `prove_constructor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_CONSTRUCTOR_INSTRUCTIONS` | `return` in `prove_constructor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_FIELD_DATA` | `return` in `prove_constructor` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_CODE` | `return` in `prove_getter` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_GETTER_INSTRUCTIONS` | `return` in `prove_getter` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_METHOD_PARSE_BYTES` | `.min()` clamp in `read_bodies` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_BYTES` | `return` in `prove_accessors` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_NAME_BYTES` | `?` on a checked operation in `prove_accessors` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STACK` | `return` in `prove_accessor`; `return` in `prove_constructor`; `return` in `prove_getter` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STRING_BYTES` | `return` in `prove_accessors` | `crates/disrobe-pass-dotnet/src/peel/obfuscar_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_STRINGS` | `break` in `read_unicode_records_varint`; `return` in `read_unicode_records_int32_strict`; `return` in `read_unicode_records_varint_strict` | `crates/disrobe-pass-dotnet/src/peel/protector_resources.rs` |
| `disrobe-pass-dotnet` | `MAX_ROT_SHIFT` | no action in `recover_spices` | `crates/disrobe-pass-dotnet/src/peel/spices_strings.rs` |
| `disrobe-pass-dotnet` | `MAX_PROBE_ARGS` | `for` range in `probe_decoder` | `crates/disrobe-pass-dotnet/src/peel/static_decrypt.rs` |
| `disrobe-pass-dotnet` | `MAX_DECRYPTOR_INSTRUCTIONS` | `continue` in `collect_from_type` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_RECOVERED_STRINGS` | `return` in `recover_emulated_strings` | `crates/disrobe-pass-dotnet/src/peel/string_emu.rs` |
| `disrobe-pass-dotnet` | `MAX_STRUCTURE_DEPTH` | `return` in `emit_region` | `crates/disrobe-pass-dotnet/src/structure_emit.rs` |
| `disrobe-pass-dotnet` | `MAX_EXPR_DEPTH` | `return` in `expression_depth`; fallback value in `bounded_expression` | `crates/disrobe-pass-dotnet/src/structurize.rs` |
| `disrobe-pass-dotnet` | `INFERENCE_DEPTH_LIMIT` | `return` in `infer_bounded`; `return` in `may_convert` | `crates/disrobe-pass-dotnet/src/structurize/operand_kind.rs` |
| `disrobe-pass-go` | `MAX_LISTED_FUNCS` | `.take()` in `push_defer_section`; `.take()` in `render_symbol_report`; no action in `push_defer_section`; 1 more | `crates/disrobe-pass-go/src/chain_detector.rs` |
| `disrobe-pass-go` | `MAX_PCDATA_ENTRIES` | `return` in `read_func_defer_view` | `crates/disrobe-pass-go/src/defers.rs` |
| `disrobe-pass-go` | `MAX_DECOMPRESSED_LEN` | `.take()` in `inflate_raw`; `return` in `decompress_zdebug`; fallback value in `inflate_raw` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_FUNCS` | `break` in `collect_unit`; `break` in `walk_dwarf`; skipped in `push_function` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_PER_FUNC` | `break` in `collect_unit`; skipped in `collect_unit` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_NAMES_TOTAL` | `break` in `collect_unit` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DWARF_TYPE_NAMES` | `break` in `walk_dwarf`; skipped in `collect_unit` | `crates/disrobe-pass-go/src/dwarf.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVES` | `break` in `collect_directives` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_DIRECTIVE_TAIL` | `.min()` clamp in `collect_directives` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_DATA_LEN` | `return` in `parse_record` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_EMBED_NAME_LEN` | `return` in `is_clean_embed_path`; `return` in `parse_record` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_MAP_ENTRIES` | `return` in `read_map` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_TOTAL_EMBED_BYTES` | `.min()` clamp in `read_member_bytes` | `crates/disrobe-pass-go/src/embed_fs.rs` |
| `disrobe-pass-go` | `MAX_LITERAL_SCAN_BYTES` | skipped in `recover_strings`; slice in `recover_strings` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_PLAIN_STRINGS` | `return` in `scan_ascii_strings`; skipped in `scan_ascii_strings` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_RECOVERED_STRINGS` | `.take()` in `recover_strings`; `.truncate()` in `recover_strings`; `return` in `scan_ascii_strings`; 2 more | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_REPEATING_KEY` | `for` range in `scan_repeating_xor` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `STRING_SCAN_BUDGET` | `break` in `recover_strings` | `crates/disrobe-pass-go/src/garble.rs` |
| `disrobe-pass-go` | `MAX_BLOB` | `.min()` clamp in `grow_clean_pair` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_BRIDGE_GAP` | `break` in `extract_string_window` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PERTURBED_BYTES` | `return` in `grow_clean_pair` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_PLACEHOLDER_RATIO_PCT` | `return` in `plausible_plaintext` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_RECOVERIES` | `return` in `recover_simple_literals` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_SIMPLE_SCAN_BYTES` | `return` in `recover_simple_literals` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `MAX_STRING_JUNK_BYTES` | `break` in `grow_clean_pair` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `WORK_BUDGET` | `return` in `recover_simple_literals` | `crates/disrobe-pass-go/src/garble_literals.rs` |
| `disrobe-pass-go` | `GLOBAL_STEP_BUDGET` | `break` in `run_block`; `return` in `call_into_text` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_CALLERS_PER_THUNK` | skipped in `build_caller_index` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_EMU_MEM_BYTES` | `continue` in `write_mem`; `for` range in `zero_fill` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_INLINE_STRING` | `return` in `span_is_printable`; no action in `snapshot_consumer_args` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_NESTED_CALL_DEPTH` | `return` in `call_into_text` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_STEPS` | `while` condition in `run_block` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_THUNK_BYTES` | `.min()` clamp in `slice_for` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `THUNK_SCAN_BUDGET` | `break` in `recover_thunk_literals` | `crates/disrobe-pass-go/src/garble_thunk.rs` |
| `disrobe-pass-go` | `MAX_BACKSEARCH_CANDIDATES` | `return` in `via_pclntab_backsearch` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_DEPS` | skipped in `build_info_from_parts` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_BUILDINFO_SETTINGS` | skipped in `build_info_from_parts` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SLICE_LEN` | `return` in `validated_slice` | `crates/disrobe-pass-go/src/moduledata.rs` |
| `disrobe-pass-go` | `MAX_PCLNTAB_CANDIDATES` | `while` condition in `collect_needles_in_section` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_SIG_FUNCS` | `return` in `validate_header_structure` | `crates/disrobe-pass-go/src/pclntab.rs` |
| `disrobe-pass-go` | `MAX_FILETAB_ENTRY_LEN` | `return` in `is_source_file`; fallback value in `read_filetab_name`; skipped in `collect_filetab_blob` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `MAX_PLAUSIBLE_FUNCS` | `return` in `bounded_func_count` | `crates/disrobe-pass-go/src/symbols.rs` |
| `disrobe-pass-go` | `DISAMBIG_CANDIDATE_BUDGET` | `break` in `disambiguate_shape_args` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_FIELDS_PER_STRUCT` | `return` in `read_struct_fields` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_IMETHODS_PER_INTERFACE` | `return` in `read_interface_methods` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_METHODS_PER_TYPE` | `return` in `read_type_methods` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-go` | `MAX_STRUCT_FIELD_TAG_LEN` | `return` in `decode_name_component` | `crates/disrobe-pass-go/src/types.rs` |
| `disrobe-pass-js-deob` | `MAX_NAMES_PER_SOURCE` | skipped in `collect_coverage_by_source` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RENAMED_BINDINGS` | `return` in `renamed_bindings` | `crates/disrobe-pass-js-deob/src/bundle/sourcemap_recover.rs` |
| `disrobe-pass-js-deob` | `MAX_RECURSIVE_DEPTH` | `return` in `recursive_descend` | `crates/disrobe-pass-js-deob/src/esoteric/atob_indirection.rs` |
| `disrobe-pass-js-deob` | `MAX_PEEL_LAYERS` | `while` condition in `unpack` | `crates/disrobe-pass-js-deob/src/esoteric/packer.rs` |
| `disrobe-pass-js-deob` | `MAX_CAPTURE_SCRIPT_BYTES` | `return` in `eval_to_source` | `crates/disrobe-pass-js-deob/src/esoteric/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_EXACT_MAGNITUDE` | `return` in `arith_combine`; `return` in `int_pattern`; `return` in `lower_arith` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_FIXPOINT_ROUNDS` | `for` range in `fold_algebraic_opaque` | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_LOWER_DEPTH` | `return` in `lower_arith`; `return` in `lower_bits`; `return` in `lower_predicate`; 1 more | `crates/disrobe-pass-js-deob/src/jsconfuser/algebraic_opaque.rs` |
| `disrobe-pass-js-deob` | `MAX_DENSE_ARRAY_ELEMENTS` | `return` in `assign_to` | `crates/disrobe-pass-js-deob/src/jsconfuser/cff_vm/interp.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_DICT_ENTRIES` | `return` in `lzstring_decompress_values` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_INPUT_UNITS` | `return` in `lzstring_decompress_base64`; `return` in `lzstring_decompress_uri`; `return` in `lzstring_decompress_utf16_raw`; 3 more | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_LZSTRING_OUTPUT_UNITS` | `return` in `lzstring_decompress_values` | `crates/disrobe-pass-js-deob/src/jsconfuser/string_compression.rs` |
| `disrobe-pass-js-deob` | `MAX_CALL_BYTES` | `return` in `try_fold_at` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_FOLD_PASSES` | `for` range in `fold_char_constructors` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_IIFE_BYTES` | `return` in `try_fold_iife` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RESULT_CHARS` | `return` in `is_safe_literal_body` | `crates/disrobe-pass-js-deob/src/jsobfu/fold_chars.rs` |
| `disrobe-pass-js-deob` | `MAX_RECOVER_PASSES` | `for` range in `try_recover` | `crates/disrobe-pass-js-deob/src/jsobfu/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_ROTATIONS` | `for` range in `simulate` | `crates/disrobe-pass-js-deob/src/string_array/rotate.rs` |
| `disrobe-pass-js-deob` | `MAX_BATCH_OUTPUT_UNITS` | `while` condition in `usize_decimal_len` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_CONCURRENT_PROBES` | `while` condition in `acquire_probe_permit_from` | `crates/disrobe-pass-js-deob/src/string_array/sandbox.rs` |
| `disrobe-pass-js-deob` | `MAX_MEMBER_CALL_LITERALS` | `.take()` in `restore_terser_mangled_bounded`; skipped in `restore_terser_mangled_bounded` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_NEARBY_STRINGS` | `.take()` in `static_member_call_literals_on_reference`; `return` in `collect_string_literals` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_SEARCH_DEPTH` | `return` in `collect_string_literals` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_SUFFIX_ATTEMPTS` | `for` range in `allocate` | `crates/disrobe-pass-js-deob/src/typescript/terser_restore.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | `for` range in `fold_binary` | `crates/disrobe-pass-js-deob/src/unminify/arithmetic.rs` |
| `disrobe-pass-js-deob` | `MAX_MBA_LOWER_DEPTH` | `return` in `lower_expression_at`; `return` in `render_expression_at` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_PREDICATE_VARS` | `return` in `classify_predicate` | `crates/disrobe-pass-js-deob/src/unminify/ast/mba_simplify.rs` |
| `disrobe-pass-js-deob` | `MAX_DEPENDENCY_SETTER_PAIRS` | `return` in `recover`; `return` in `registration` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_REGISTRATIONS` | `return` in `recover` | `crates/disrobe-pass-js-deob/src/unminify/ast/system_register_param.rs` |
| `disrobe-pass-js-deob` | `MAX_SIMPLIFY_ROUNDS` | `for` range in `simplify` | `crates/disrobe-pass-js-deob/src/unminify/ast/ts_async/emit.rs` |
| `disrobe-pass-js-deob` | `MAX_FIX_POINT_PASSES` | `for` range in `unminify` | `crates/disrobe-pass-js-deob/src/unminify/mod.rs` |
| `disrobe-pass-js-deob` | `MAX_CHAIN` | `break` in `collect_chain` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_PASSES` | `for` range in `fold_string_concat` | `crates/disrobe-pass-js-deob/src/unminify/string_split.rs` |
| `disrobe-pass-js-deob` | `MAX_OPERANDS` | `while` condition in `new` | `crates/disrobe-pass-js-deob/src/v8/bytecode_opcodes.rs` |
| `disrobe-pass-js-deob` | `MAX_FRAME_SIZE` | `return` in `recover_bytecode_array_with_layout` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_BODY` | `return` in `decode_string_from_run` | `crates/disrobe-pass-js-deob/src/v8/code_serializer.rs` |
| `disrobe-pass-js-deob` | `REGISTER_RANGE_SCAN_LIMIT` | no action in `prepare_accumulator` | `crates/disrobe-pass-js-deob/src/v8/flat_bytecode_lift.rs` |
| `disrobe-pass-js-deob` | `MAX_STRING_LEN` | `continue` in `extract_framed_strings` | `crates/disrobe-pass-js-deob/src/v8/serialized_code.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | `for` range in `next_bounded_int` | `crates/disrobe-pass-jvm/src/bytecode_eval.rs` |
| `disrobe-pass-jvm` | `MAX_DATAFLOW_VISITS_PER_INSTRUCTION` | `return` in `local_constants_at_block_entries` | `crates/disrobe-pass-jvm/src/const_fold.rs` |
| `disrobe-pass-jvm` | `MAX_MASK_SEARCH_PAIRS` | `return` in `recover_dispatch_mask` | `crates/disrobe-pass-jvm/src/dalvik_blackobf.rs` |
| `disrobe-pass-jvm` | `MAX_FLOW_WORDS` | `return` in `analyze` | `crates/disrobe-pass-jvm/src/dalvik_cfg.rs` |
| `disrobe-pass-jvm` | `MAX_DIAGNOSTICS` | no action in `analyze` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_MARKER_BYTES` | `return` in `parse_marker` | `crates/disrobe-pass-jvm/src/dalvik_core_library.rs` |
| `disrobe-pass-jvm` | `MAX_NESTED_CLASS_DEPTH` | `for` range in `lexically_encloses`; `for` range in `translated_owner_path`; no action in `compose_rendered_class` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | `return` in `render_region` | `crates/disrobe-pass-jvm/src/dalvik_decompile.rs` |
| `disrobe-pass-jvm` | `MAX_DESUGAR_SCAN_INSNS` | `return` in `exclusively_constructed`; `return` in `helper_references`; `return` in `scan_references` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_BODY_INSNS` | `return` in `inlinable_helper_body` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_REFERENCE_BODY_INSNS` | `return` in `match_reference_body` | `crates/disrobe-pass-jvm/src/dalvik_desugar.rs` |
| `disrobe-pass-jvm` | `MAX_RESOLVE_ROUNDS` | `break` in `unflatten_with_graph` | `crates/disrobe-pass-jvm/src/dalvik_dexguard.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DATA_ELEMENTS` | `return` in `array_data_elements` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_INLINE_DEPTH` | `return` in `inline_helper_body` | `crates/disrobe-pass-jvm/src/dalvik_lift.rs` |
| `disrobe-pass-jvm` | `MAX_HANDLER_BLOCKS` | `break` in `monitor_handler` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_MONITOR_BODY_BLOCKS` | `continue` in `releases_before_leaving`; `return` in `monitor_region` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | `for` range in `past_trampolines` | `crates/disrobe-pass-jvm/src/dalvik_monitor.rs` |
| `disrobe-pass-jvm` | `JAVA_RANDOM_REJECTION_CAP` | `for` range in `next_bounded_int` | `crates/disrobe-pass-jvm/src/dalvik_strdec.rs` |
| `disrobe-pass-jvm` | `MAX_CANDIDATE_PARAMS` | `return` in `signature_weight` | `crates/disrobe-pass-jvm/src/dalvik_strdec_generic.rs` |
| `disrobe-pass-jvm` | `MAX_BUCKET_TESTS` | `for` range in `bucket_chain` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_TRAMPOLINE_HOPS` | `for` range in `absorb_trampolines`; `for` range in `skip_trampolines` | `crates/disrobe-pass-jvm/src/dalvik_string_switch.rs` |
| `disrobe-pass-jvm` | `MAX_TRACKED_NARROW_CONSTANT_REGS` | `return` in `must_narrow_constant_states` | `crates/disrobe-pass-jvm/src/dalvik_to_jvm.rs` |
| `disrobe-pass-jvm` | `MAX_REGION_BLOCKS` | `for` range in `nearest_common_dominator`; `return` in `merge_ranges` | `crates/disrobe-pass-jvm/src/dalvik_try_regions.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_JOIN_DEPTH` | `return` in `join_ref` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `MAX_SUPERCLASS_DEPTH` | `while` condition in `root_first_chain` | `crates/disrobe-pass-jvm/src/dalvik_typestate.rs` |
| `disrobe-pass-jvm` | `ARM_CONDITION_BLOCK_CAP` | `return` in `arm_tree_value`; `return` in `arm_value`; `return` in `ternary_join_entry` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `INT_USE_SCAN_LIMIT` | `.take()` in `loaded_int_has_int_use` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_BOOL_EXPR_BYTES` | `return` in `eval_bool_node_memo` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENTS` | `return` in `replacement_nodes` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_GENERIC_REPLACEMENT_BYTES` | `return` in `replacement_nodes` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_RENDER_BYTES` | `return` in `append_inner_output`; `return` in `append_java_replacement`; `return` in `emit_nested_class_stubs`; 2 more | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `RECORD_ARITY_PROBE_CAP` | `while` condition in `infer_record_arity` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `REUSED_LOCAL_SPLIT_WORK_LIMIT` | `return` in `claim_reused_local_split_work` | `crates/disrobe-pass-jvm/src/decompile.rs` |
| `disrobe-pass-jvm` | `MAX_CONDITION_CHAIN` | `return` in `short_circuit_merge`; `return` in `structure_condition_chain`; `while` condition in `loop_condition_chain` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_JOIN_CHAIN` | `break` in `continuation_joins`; `for` range in `goto_chain_end`; `for` range in `handler_join_after`; 1 more | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_BLOCKS` | `return` in `duplicable_tail` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_TAIL_INSTRUCTIONS` | `return` in `duplicable_tail` | `crates/disrobe-pass-jvm/src/decompile_struct.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMENSIONS` | `return` in `parse_one`; `return` in `type_descriptor_end` | `crates/disrobe-pass-jvm/src/descriptor.rs` |
| `disrobe-pass-jvm` | `MAX_SYSTEM_METADATA_NORMALIZATION_ROUNDS` | `for` range in `normalize_system_metadata` | `crates/disrobe-pass-jvm/src/dex.rs` |
| `disrobe-pass-jvm` | `MAX_ARRAY_DIMS` | `return` in `consume_field_type` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_JNI_STRING_LEN` | `return` in `is_jni_method_name`; `return` in `read_c_string` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_INT_KEYS` | `break` in `extract_static_int_keys` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIBS` | `.take()` in `extract_static_int_keys` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_NATIVE_KEY_LIB_BYTES` | `continue` in `extract_static_int_keys` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_STUB_BYTES` | `.min()` clamp in `bytes_at_address` | `crates/disrobe-pass-jvm/src/jni.rs` |
| `disrobe-pass-jvm` | `MAX_HIERARCHY_DEPTH` | `return` in `resolve_field_with_inheritance`; `return` in `resolve_method_with_inheritance` | `crates/disrobe-pass-jvm/src/proguard.rs` |
| `disrobe-pass-jvm` | `MAX_METHOD_INSNS` | `return` in `unflatten_method` | `crates/disrobe-pass-jvm/src/protectors/unflatten.rs` |
| `disrobe-pass-jvm` | `MAX_DISPATCH_RESOLVE_STEPS` | `break` in `simplify_flattened_cfg` | `crates/disrobe-pass-jvm/src/sccp.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_VISITS_PER_NODE` | `.min()` clamp in `for_nodes` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_STRUCTURE_WORK` | `.min()` clamp in `for_nodes` | `crates/disrobe-pass-lua/src/decompile/luau_structure.rs` |
| `disrobe-pass-lua` | `MAX_RESERVED_NAME_SCAN` | `return` in `names_referenced_by` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_DEPTH` | `return` in `lift_structured_captured` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_STRUCT_NODES` | `return` in `lift_structured_captured` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `READ_SEARCH_STATE_BUDGET` | `return` in `read_after_control_flow` | `crates/disrobe-pass-lua/src/decompile/struct_lift.rs` |
| `disrobe-pass-lua` | `MAX_SCOPE_DEPTH` | `return` in `block_captures_in_closure`; `return` in `block_mentions`; `return` in `declare_in_block`; 3 more | `crates/disrobe-pass-lua/src/decompile/struct_lift/declare.rs` |
| `disrobe-pass-lua` | `MAX_CONDITION_CHAIN` | `while` condition in `recover_short_circuit_chains` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_EXIT_SCAN` | `.take()` in `retarget_exits_through_skip_jumps` | `crates/disrobe-pass-lua/src/decompile/struct_lift/structurer.rs` |
| `disrobe-pass-lua` | `MAX_BUILD_STEPS` | `return` in `build` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_REGION_INSTRUCTIONS` | `return` in `build`; `while` condition in `region_bounds` | `crates/disrobe-pass-lua/src/decompile/struct_lift/value_region.rs` |
| `disrobe-pass-lua` | `MAX_LOADER_DEPTH` | `for` range in `peel` | `crates/disrobe-pass-lua/src/obfuscator/hercules.rs` |
| `disrobe-pass-lua` | `LURAPH_SCAN_LIMIT` | `.min()` clamp in `find_lua_assignment_value` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_BOOTSTRAP_TABLE_VALUES` | `return` in `parse_numeric_table_len` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_LURAPH_EXPR_LEN` | `return` in `rewrite_hex_literals` | `crates/disrobe-pass-lua/src/obfuscator/luraph.rs` |
| `disrobe-pass-lua` | `MAX_NESTED_VMIFY_PASSES` | `while` condition in `apply_vmify_devirt` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `VMIFY_DISPATCH_SCAN_LIMIT` | `return` in `matches_vmify_container_shape` | `crates/disrobe-pass-lua/src/obfuscator/prometheus.rs` |
| `disrobe-pass-lua` | `MAX_ANTITAMPER_EXPRESSION_DEPTH` | `return` in `anti_tamper_value` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_LOOP_NESTING` | `return` in `render_loop` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_REGION_TREE_STEPS` | `?` on a checked operation in `collect_region_nodes`; `?` on a checked operation in `loop_exit_tails`; `?` on a checked operation in `region_contains_node`; 1 more | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_SCRATCH_CHAIN_DEPTH` | `return` in `resolve_and_expr`; `return` in `resolve_number_via_last_write` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `MAX_STATIC_NUMBER_DEPTH` | `return` in `evaluate_at_depth` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vm_cfg.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | `return` in `analyze_dispatch` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `MAX_FOLD_TOKENS` | `return` in `fold_one_expression`; `return` in `try_fold_span` | `crates/disrobe-pass-lua/src/obfuscator/prometheus_vmlift.rs` |
| `disrobe-pass-lua` | `BASE64_PAYLOAD_CHAR_CAP` | `return` in `decode_base64_payload_run` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `BOOTSTRAP_SCAN_LIMIT` | `.min()` clamp in `find_lua_assignment_value`; `while` condition in `extract_named_lua_byte_buffer` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `EMBEDDED_PAYLOAD_SCAN_LIMIT` | `.min()` clamp in `extract_lua_string_payload` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `LUA_TABLE_PAYLOAD_CAP` | `return` in `decode_lua_byte_table` | `crates/disrobe-pass-lua/src/obfuscator/vm_devirt.rs` |
| `disrobe-pass-lua` | `DISPATCH_BLOCK_LIMIT` | `break` in `lift_dispatch` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_GUARD_LIMIT` | `break` in `collect_threshold_cuts` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_PARSE_DEPTH_LIMIT` | `return` in `parse_dispatch_node` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-lua` | `DISPATCH_SCAN_LIMIT` | `.min()` clamp in `lift_dispatch` | `crates/disrobe-pass-lua/src/obfuscator/wearedevs.rs` |
| `disrobe-pass-mobile` | `MAX_EMBEDDED_DEX_CARVES` | `while` condition in `collect_plain_dex_carves`; `while` condition in `collect_xor_dex_carves` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_PROTECTOR_CARVE_SCAN` | skipped in `analyze`; skipped in `extract_android_dex_children` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_RESOLVED_RESOURCES` | `break` in `summarise_arsc` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_TEXT_ASSET` | skipped in `analyze` | `crates/disrobe-pass-mobile/src/apk_recon.rs` |
| `disrobe-pass-mobile` | `MAX_CERTS_PER_SIGNER` | `break` in `parse_signer` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_DIGESTS_PER_SIGNER` | `break` in `parse_signer` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_PAIRS` | `break` in `parse_id_value_pairs` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `MAX_SIGNERS` | `break` in `parse_scheme` | `crates/disrobe-pass-mobile/src/apk_signing.rs` |
| `disrobe-pass-mobile` | `TRAVERSAL_INSN_BUDGET` | `break` in `traverse` | `crates/disrobe-pass-mobile/src/flutter/arm64_traversal.rs` |
| `disrobe-pass-mobile` | `MAX_BOOLEAN_RETURN_INSTRUCTIONS` | `return` in `recover_boolean_return` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_SETUP_INSTRUCTIONS` | `?` on a checked operation in `skip` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_BOXED_DOUBLE_TRACE_INSTRUCTIONS` | `?` on a checked operation in `skip` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_CONSUMED_TEXT_BYTES` | skipped in `consumed_text` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FLOAT_RETURN_SPILL_DISTANCE` | `?` on a checked operation in `skip` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_FRAME_SLOTS` | `return` in `record_frame` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_MERGE_PREDECESSORS` | `return` in `entry_state` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_STACK_ARGUMENTS` | `return` in `record_stack`; `return` in `stack_arguments` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_CALLS` | `break` in `track_call_sites` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_TRACKED_EFFECTS` | `return` in `define`; skipped in `bookkeeping`; skipped in `step` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_DEPTH` | `return` in `render_value` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `MAX_VALUE_NODES` | `?` on a checked operation in `node_budget` | `crates/disrobe-pass-mobile/src/flutter/call_args.rs` |
| `disrobe-pass-mobile` | `CLUSTER_TAG_SCAN_LIMIT` | `.min()` clamp in `scan_cid_tags` | `crates/disrobe-pass-mobile/src/flutter/cluster.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_SLOTS` | skipped in `fill_object_pools` | `crates/disrobe-pass-mobile/src/flutter/dart_graph.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_INSNS` | `while` condition in `disassemble_function`; `while` condition in `disassemble_range` | `crates/disrobe-pass-mobile/src/flutter/disasm.rs` |
| `disrobe-pass-mobile` | `MEMBER_TABLE_CAP` | `return` in `member_table_from_count`; `return` in `parse` | `crates/disrobe-pass-mobile/src/flutter/kernel.rs` |
| `disrobe-pass-mobile` | `MAX_POOL_LITERALS` | `break` in `resolve_pool_literals`; `while` condition in `resolve_pool_literals` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_RUN_PROBE` | `while` condition in `pool_run_length` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `POOL_DECODE_BUDGET` | `.min()` clamp in `recover_object_pool_references` | `crates/disrobe-pass-mobile/src/flutter/object_pool.rs` |
| `disrobe-pass-mobile` | `MAX_DART_IDENTIFIER_COUNT` | `break` in `extract_dart_identifiers`; skipped in `flush_identifier` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_FUNCTION_BOUNDARIES` | `while` condition in `scan_function_boundaries` | `crates/disrobe-pass-mobile/src/flutter/snapshot.rs` |
| `disrobe-pass-mobile` | `MAX_STRING_CHARS` | `continue` in `scan_one_byte_strings` | `crates/disrobe-pass-mobile/src/flutter/string_pool.rs` |
| `disrobe-pass-mobile` | `MAX_ALLOCATOR_WORDS` | `for` range in `allocate_object_helper_inputs` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_REGISTER_SAVES` | `return` in `stub_frame_entry` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_STUB_ARGUMENT_STEPS` | `for` range in `runtime_call_stub` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_TAG_WORDS` | `return` in `allocation_stub_for_class` | `crates/disrobe-pass-mobile/src/flutter/stub_abi.rs` |
| `disrobe-pass-mobile` | `MAX_DECIMAL_BYTES` | fallback value in `bigint_literal` | `crates/disrobe-pass-mobile/src/hermes/bigint.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_INSTRUCTIONS` | `while` condition in `decode_instructions` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_BYTES` | no action in `closure_expr` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_INLINE_CLOSURE_DEPTH` | `return` in `inlined_closure_bodies` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_REG_EXPR_BYTES` | no action in `set_reg` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDERED_CALL_ARGS` | `.min()` clamp in `unrecovered_arg_list`; `return` in `call_window_registers` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_RENDER_BYTES` | `break` in `render_block_stmts`; `break` in `render_structured` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_SWITCH_CASES` | `return` in `switch_table_entries` | `crates/disrobe-pass-mobile/src/hermes/decompile.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_LITERALS` | `return` in `decode_literals`; `while` condition in `decode_literals` | `crates/disrobe-pass-mobile/src/hermes/literals.rs` |
| `disrobe-pass-mobile` | `MAX_REGEX_INSNS` | `while` condition in `decode_body`; `while` condition in `render_range_inner` | `crates/disrobe-pass-mobile/src/hermes/regex.rs` |
| `disrobe-pass-mobile` | `MAX_LOOP_EXTENSION_ROUNDS` | `for` range in `extend_loop_body` | `crates/disrobe-pass-mobile/src/hermes/structure.rs` |
| `disrobe-pass-mobile` | `MAX_DECODED_XML` | `break` in `decode_archive` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-mobile` | `MAX_VALUES_ENTRIES` | `break` in `reconstruct_values` | `crates/disrobe-pass-mobile/src/res_decode.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_INSNS` | `break` in `harvested_hash_constants` | `crates/disrobe-pass-native/src/api_hash.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_DEPTH` | `while` condition in `build_chain` | `crates/disrobe-pass-native/src/authenticode.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | `return` in `build_cfg`; `return` in `collect_leaders` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `return` in `build_block`; `return` in `collect_leaders` | `crates/disrobe-pass-native/src/basic_blocks.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_FUNCTIONS` | `return` in `native_pseudo_report` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_IMAGE_BYTES` | `return` in `native_pseudo_report` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_AUTO_PSEUDO_REPORT_BYTES` | no action in `build_image_children` | `crates/disrobe-pass-native/src/chain_detector.rs` |
| `disrobe-pass-native` | `MAX_X86_INSTRUCTION_BYTES` | slice in `is_import_thunk` | `crates/disrobe-pass-native/src/code_symbol.rs` |
| `disrobe-pass-native` | `MAX_DEPTH` | `return` in `process_value`; `return` in `read_object`; `return` in `read_prop_list` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `MAX_OBJECTS` | `return` in `read_object` | `crates/disrobe-pass-native/src/delphi/dfm.rs` |
| `disrobe-pass-native` | `BYTE_SCAN_LIMIT` | slice in `identify`; slice in `scan_window` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_SHORTSTRING_LEN` | `return` in `is_plausible_symbol_of_length`; `return` in `read_shortstring` | `crates/disrobe-pass-native/src/delphi/image.rs` |
| `disrobe-pass-native` | `MAX_STUB_BYTES` | slice in `entry_stub_addresses` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_STUB_INSTRUCTIONS` | `while` condition in `entry_stub_addresses` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_UNITS` | `return` in `parse_at` | `crates/disrobe-pass-native/src/delphi/init_table.rs` |
| `disrobe-pass-native` | `MAX_ENTRIES` | `.min()` clamp in `entry_count` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_NAME_CHARS` | `.min()` clamp in `read_res_name` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCES` | `return` in `walk_langs`; `return` in `walk_names`; `return` in `walk_types` | `crates/disrobe-pass-native/src/delphi/resource.rs` |
| `disrobe-pass-native` | `MAX_SCAN_POSITIONS` | `break` in `scan` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRINGS` | `break` in `scan` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_UNITS` | `return` in `read_candidate` | `crates/disrobe-pass-native/src/delphi/strings.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_METHODS` | `return` in `parse_dynamic_table` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELDS_PER_CLASS` | `return` in `parse_field_table` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_FIELD_CLASSES` | `return` in `field_class_candidates` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_INTERFACES` | `return` in `parse_interface_table` | `crates/disrobe-pass-native/src/delphi/tables.rs` |
| `disrobe-pass-native` | `MAX_ENUM_MEMBERS` | `return` in `fill_enumeration` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_FIELD_VISIBILITY` | `return` in `parse_record_fields` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_MANAGED_FIELDS` | `return` in `fill_record` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_FIELDS` | `return` in `parse_record_fields` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_RECORD_SIZE` | `return` in `fill_record` | `crates/disrobe-pass-native/src/delphi/typeinfo.rs` |
| `disrobe-pass-native` | `MAX_PATH_TAIL` | slice in `scan_toolchain_paths` | `crates/disrobe-pass-native/src/delphi/version.rs` |
| `disrobe-pass-native` | `MAX_INSTANCE_SIZE` | `return` in `validate_class` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_METHODS_PER_CLASS` | `.min()` clamp in `parse_method_table` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PARENT_DEPTH` | `break` in `accumulate` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_PROPS_PER_CLASS` | `.min()` clamp in `parse_typeinfo` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_TYPE_RECORDS` | `.take()` in `describe_types` | `crates/disrobe-pass-native/src/delphi/vmt.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/abi.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/bcf_dse.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/branchfold.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | `return` in `carve_blocks` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_DISPATCH_TREE_STEPS` | `break` in `compare_chain_blocks`; `return` in `model_compare_tree`; `while` condition in `enqueue_jump_table_targets`; 1 more | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_INSNS` | `return` in `build_program`; `return` in `recursive_decode` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_DEPTH` | `return` in `walk` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_REGION_STEPS` | `return` in `walk` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_RESOLVE_DEPTH` | `return` in `resolve_loc` | `crates/disrobe-pass-native/src/deobf/cff.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/copyprop.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/deadflags.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_TABLE_ENTRIES` | `.min()` clamp in `read_pic_table`; `.min()` clamp in `read_table`; `while` condition in `read_pic_table`; 1 more | `crates/disrobe-pass-native/src/deobf/jumptable.rs` |
| `disrobe-pass-native` | `MAX_LIFT_INSNS` | `return` in `lift_arith_value`; `return` in `lift_operand_pair` | `crates/disrobe-pass-native/src/deobf/mba_lift.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_PATH_BLOCKS` | `return` in `walk` | `crates/disrobe-pass-native/src/deobf/pathsense.rs` |
| `disrobe-pass-native` | `MAX_BLOCK_INSNS` | `return` in `build_block`; `return` in `collect_leaders` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DECODE_INSNS` | `while` condition in `decode_all` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_JOINS` | `return` in `summarize_region` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_LOOPS` | `for` range in `unroll_natural_loops` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_REGISTERS` | `return` in `finalize_summary` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_OUTPUT_STACK_CELLS` | `return` in `finalize_summary` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_BLOCKS` | `return` in `build_region`; `return` in `collect_leaders` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_REGION_INSNS` | `return` in `build_region` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLL` | `break` in `rs_emit_range`; `continue` in `forward_join_lowering_candidates`; `continue` in `prove_one`; 34 more | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_UNROLLED_BLOCKS` | `return` in `unroll_one` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `VERIFY_ARITY_CAP` | `return` in `densify` | `crates/disrobe-pass-native/src/deobf/summary.rs` |
| `disrobe-pass-native` | `MAX_DIRECT_CALL_SWEEP_OFFSETS` | `.min()` clamp in `add_linear_call_evidence`; `.min()` clamp in `sweep_direct_call_target_evidence`; `break` in `add_linear_call_evidence`; 1 more | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_INTERIOR_PROLOGUE_PROVENANCE` | skipped in `traverse_function` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_JUMP_TABLE_ENTRIES` | `while` condition in `resolve_jump_table` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_NORETURN_ITERATIONS` | `for` range in `noreturn_closure` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_BACKWARD_DISTANCE` | `return` in `direct_call_target` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_REL32_FORWARD_DISTANCE` | `return` in `direct_call_target` | `crates/disrobe-pass-native/src/desync.rs` |
| `disrobe-pass-native` | `MAX_BOUNDARY_PADDING_BYTES` | `return` in `is_alignment_boundary` | `crates/disrobe-pass-native/src/disasm_ir.rs` |
| `disrobe-pass-native` | `MAX_AARCH64_PLT_ENTRIES` | `for` range in `collect_elf_plt_entries` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_EXECUTABLE_RANGES` | `break` in `new`; `return` in `new_pe64` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_GUARD_CF_FUNCTIONS` | `.min()` clamp in `decode_pe_arm64_guard_cf_functions` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_PE_TLS_CALLBACKS` | `for` range in `decode_pe_arm64_tls_callbacks` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_POINTER_SLOTS` | `break` in `collect_data_pointers`; `return` in `collect_initializer_tables` | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_SEEDS` | `break` in `aarch64_boundary_prologue_seeds`; `break` in `aarch64_gap_boundary_prologue_seeds`; `return` in `aarch64_boundary_prologue_seeds`; 3 more | `crates/disrobe-pass-native/src/disasm_ir/aarch64_seeds.rs` |
| `disrobe-pass-native` | `MAX_DYNAMIC_ENTRIES` | `while` condition in `read_dynamic_entries` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_ELF_PROGRAM_HEADERS` | `return` in `is_well_formed_elf_executable`; `return` in `validate_section_table` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_GNU_HASH_BUCKETS` | `return` in `gnu_hash_symbol_count` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_NEEDED` | `.min()` clamp in `read_pointer_array`; `continue` in `analyze` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_RELOCATIONS` | `return` in `read_rel`; `return` in `read_rela` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_STRING_BYTES` | `.min()` clamp in `read_interpreter`; `.min()` clamp in `resolve_dynstr` | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_SYMBOLS` | `.min()` clamp in `bounded_symbol_scan`; `.min()` clamp in `read_dynamic_symbols`; `return` in `gnu_hash_symbol_count`; 2 more | `crates/disrobe-pass-native/src/elf.rs` |
| `disrobe-pass-native` | `MAX_BUFFERS_PER_CANDIDATE` | `.take()` in `emulate_string_decoders_inner` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_CANDIDATES` | `.take()` in `emulate_string_decoders_inner` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_DECODE_SPAN` | `.min()` clamp in `emulate_string_decoders_inner` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_HARVEST_PER_RUN` | `break` in `merge_harvests`; `return` in `harvest_ascii`; `return` in `harvest_utf16`; 3 more | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_STRING_LEN` | `return` in `insert_static_run`; `return` in `push_candidate`; `return` in `push_wide_candidate` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `PER_CANDIDATE_STEP_CAP` | `break` in `run` | `crates/disrobe-pass-native/src/emu_strings.rs` |
| `disrobe-pass-native` | `MAX_ENTROPY_BITS` | `.clamp()` clamp in `normalized_entropy` | `crates/disrobe-pass-native/src/entropy_viz.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | slice in `bytes_find` | `crates/disrobe-pass-native/src/identify.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_IMPORT_DESCRIPTORS` | `break` in `find_aspack_runtime_import_directory`; `return` in `find_aspack_runtime_import_directory`; `return` in `reconstruct_aspack_import_descriptors` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_MODULE_NAME_LEN` | `continue` in `collect_aspack_import_layouts`; `for` range in `read_guest_cstr`; `return` in `reconstruct_aspack_import_descriptors` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_ASPACK_THUNK_CANDIDATES` | `return` in `find_unique_thunk_tables` | `crates/disrobe-pass-native/src/packers/aspack_phase2.rs` |
| `disrobe-pass-native` | `MAX_POS_BITS` | fallback value in `decode_bit` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_POS_STATES` | fallback value in `decode_bit` | `crates/disrobe-pass-native/src/packers/mpress_lzma.rs` |
| `disrobe-pass-native` | `MAX_IMPORTED_MODULES` | `break` in `locate_import_record`; `while` condition in `locate_import_descriptors` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_IMPORTS_PER_MODULE` | `break` in `locate_import_record` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_MODULE_NAME_BYTES` | slice in `module_name_is_plausible` | `crates/disrobe-pass-native/src/packers/nspack_unpack.rs` |
| `disrobe-pass-native` | `MAX_GAP_SEARCH_BYTES` | `return` in `forced_leaf_placements` | `crates/disrobe-pass-native/src/packers/pe_resource.rs` |
| `disrobe-pass-native` | `MAX_RESOURCE_DEPTH` | `return` in `walk_resource_dir` | `crates/disrobe-pass-native/src/packers/pe_unbind.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | `return` in `decode_elf_extents_with_budget`; `return` in `walk_block_chain` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_BRUTE_FORCE_OFFSETS` | `.min()` clamp in `decode_image_with_budget`; `.min()` clamp in `decode_multiblock_with_budget`; `.min()` clamp in `locate_structural` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_L_INFO_SCAN` | `.min()` clamp in `elf_first_block_offset` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_RESYNC_OFFSETS` | `while` condition in `decode_elf_extents_with_budget` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_STRUCTURAL_CHECKSUM_BYTES` | `return` in `reserve` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_VERIFY_CANDIDATES` | `break` in `locate_structural` | `crates/disrobe-pass-native/src/packers/upx_decoder.rs` |
| `disrobe-pass-native` | `MAX_CARVED_PROTECTED_SECTIONS` | `.take()` in `carve_themida`; `.take()` in `carve_vmprotect` | `crates/disrobe-pass-native/src/packers/vmprotect_carve.rs` |
| `disrobe-pass-native` | `ADDRESS_SPACE_CAP` | `return` in `flatten_address_space` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `DEOBF_SECTION_CAP` | `.min()` clamp in `executable_sections` | `crates/disrobe-pass-native/src/pass.rs` |
| `disrobe-pass-native` | `MAX_FIELDLIST_CHAIN` | `for` range in `collect_fieldlist` | `crates/disrobe-pass-native/src/pdb_cxx/emit.rs` |
| `disrobe-pass-native` | `MAX_MODULES` | `continue` in `recover_module_procedures` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_PROCEDURES` | `continue` in `recover_module_procedures` | `crates/disrobe-pass-native/src/pdb_cxx/procedures.rs` |
| `disrobe-pass-native` | `MAX_RECURSION_BUDGET` | `return` in `resolve_spelling_bounded` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_UNWRAP_DEPTH` | `for` range in `resolve_spelling_bounded` | `crates/disrobe-pass-native/src/pdb_cxx/spelling.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_NAME_BYTES` | `return` in `resolve_macho_stub_imports` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_IMPORT_STUBS` | `return` in `resolve_macho_stub_imports` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SCANNED_NAME_BYTES` | `return` in `resolve_macho_stub_imports`; slice in `resolve_macho_stub_imports` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `MAX_MACHO_SYMBOL_NAME_BYTES` | slice in `resolve_macho_stub_imports` | `crates/disrobe-pass-native/src/plt_resolve.rs` |
| `disrobe-pass-native` | `ACYCLIC_JOIN_BLOCK_CAP` | `return` in `acyclic_join_lowering_plan`; `return` in `join_plan_preserves_blocks` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `FORWARD_JOIN_PLAN_CAP` | `return` in `forward_join_lowering_candidates` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `LOOP_EXIT_TAIL_ABSORPTION_BUDGET` | `for` range in `absorb_private_exit_tails` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_BYTES` | `return` in `local_noreturn_leaf_is_proven`; `return` in `outlined_noreturn_exit` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_CALLEES` | `continue` in `object_transfer_facts`; skipped in `object_transfer_facts` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_LOCAL_NORETURN_RELOCATIONS` | `.take()` in `read`; `return` in `read` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_OUTLINED_EXIT_SLOTS` | `return` in `outlined_noreturn_exit` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `PURE_TAIL_CLONE_BUDGET` | `for` range in `emit_cloned_pure_tail` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_LABEL_CAP` | `return` in `rs_forward_exit_labels`; `return` in `rs_resume_paths` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `RUST_RESUME_NODE_CAP` | `return` in `rs_forward_exit_labels`; `return` in `rs_resume_paths` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_JOIN_WALK_BUDGET` | `return` in `joins_every_non_tail_path` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SPLIT_BLOCK_CAP` | `return` in `closed_loop_body`; `return` in `render_cfg_blocks_via_cns`; `return` in `split_tail_regions` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `TAIL_SUBTREE_CAP` | `return` in `private_tail_subtree` | `crates/disrobe-pass-native/src/pseudo_c.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_CASES` | `return` in `readable_switch_table`; `return` in `recover_aarch64_switch` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_SLICE_INSTRUCTIONS` | `for` range in `matching_switch_guard`; `for` range in `single_block_definition`; `for` range in `single_block_pc_relative_definition`; 1 more | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `MAX_SWITCH_TABLE_BYTES` | `return` in `readable_switch_table` | `crates/disrobe-pass-native/src/pseudo_c/aarch64.rs` |
| `disrobe-pass-native` | `REGISTER_ARGUMENT_LIMIT` | `for` range in `prove_arguments` | `crates/disrobe-pass-native/src/pseudo_c/aarch64_callsite.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_BYTES` | `return` in `clobbers` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_CALLEE_FUNCTIONS` | `return` in `clobbers` | `crates/disrobe-pass-native/src/pseudo_c/call_clobber.rs` |
| `disrobe-pass-native` | `MAX_AFFINE_SHIFT` | fallback value in `remainder_register` | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_DIVIDEND_BITS` | `return` in `disjoint_or`; `return` in `divisor_reproduces_witness`; `return` in `quotient_ceiling`; 2 more | `crates/disrobe-pass-native/src/pseudo_c/idiom.rs` |
| `disrobe-pass-native` | `MAX_BLOCKS` | `return` in `specialize` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_EXPR_NODES` | `return` in `push_value` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_FOLDS` | `for` range in `specialize` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_PROOFS` | `?` on a checked operation in `prove_one` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_STATEMENTS` | `return` in `specialize` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_VALUES` | `return` in `definitions` | `crates/disrobe-pass-native/src/pseudo_c/invariant_branches.rs` |
| `disrobe-pass-native` | `MAX_INLINED_DEFINITIONS` | `for` range in `inline_single_use_definitions` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `MAX_RECORDED_DECISIONS` | `return` in `record` | `crates/disrobe-pass-native/src/pseudo_c/spill.rs` |
| `disrobe-pass-native` | `SCAN_LIMIT` | slice in `analyze`; slice in `dotnet_bundle_finding`; slice in `pkr_ce1a_finding`; 1 more | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `VERSION_TAIL_CAP` | slice in `dotted_after`; slice in `literal_tail` | `crates/disrobe-pass-native/src/sig_engine.rs` |
| `disrobe-pass-native` | `ADRP_PAIR_SCAN_LIMIT` | `for` range in `paired_low_bits` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WIDE_MOVE_CHAIN_LIMIT` | `while` condition in `fold_wide_move` | `crates/disrobe-pass-native/src/similarity.rs` |
| `disrobe-pass-native` | `WINDOW_INSTRUCTION_LIMIT` | `while` condition in `window_start` | `crates/disrobe-pass-native/src/similarity/opaque.rs` |
| `disrobe-pass-native` | `MAX_GROUP_SPAN` | no action in `reassemble_group` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_SCAN_INSNS` | `break` in `harvest_stack_stores` | `crates/disrobe-pass-native/src/stack_string.rs` |
| `disrobe-pass-native` | `MAX_RIP_REFS` | `break` in `scan_rip_relative_refs` | `crates/disrobe-pass-native/src/stream_disasm.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_PAGES` | `?` on a checked operation in `apply_chains` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_CHAIN_STEPS` | `?` on a checked operation in `apply_chains` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_FIXUP_BYTES` | `return` in `apply` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SECTIONS` | `return` in `loaded_section_ranges`; `return` in `validate_loaded_sections` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_SEGMENTS` | `return` in `apply_chains`; `return` in `apply` | `crates/disrobe-pass-native/src/vm_devirt/detect/chained_fixups.rs` |
| `disrobe-pass-native` | `MAX_GUARDIAN_BYTECODE_BYTES` | `.min()` clamp in `devirtualize_guardian_rs` | `crates/disrobe-pass-native/src/vm_devirt/guardian.rs` |
| `disrobe-pass-native` | `MAX_HANDLERS` | `return` in `read_pointer_table`; `return` in `recover_via_codescan`; `return` in `recover_via_exports`; 1 more | `crates/disrobe-pass-native/src/vm_devirt/mod.rs` |
| `disrobe-pass-nativelang` | `MAX_EMITTED_NAME_CHARS` | `.take()` in `emitted_identifier` | `crates/disrobe-pass-nativelang/src/bodies.rs` |
| `disrobe-pass-nativelang` | `MAX_DEPTH` | fallback value in `enter` | `crates/disrobe-pass-nativelang/src/d_mangle.rs` |
| `disrobe-pass-nativelang` | `MAX_NIM_DEPTH` | `return` in `read_nim_type` | `crates/disrobe-pass-nativelang/src/demangle.rs` |
| `disrobe-pass-nativelang` | `MAX_ARRAY_DIMENSIONS` | `while` condition in `array_dimensions` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATES` | `break` in `walk_dwarf`; skipped in `collect_aggregates`; skipped in `push_aggregate` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_DEPTH` | skipped in `collect_aggregates` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_AGGREGATE_ITEMS` | `return` in `collect_aggregates`; `return` in `take_aggregate_item` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_DIE_VISITS` | `break` in `walk_dwarf`; `return` in `collect_aggregates`; `return` in `visit_die` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCS` | `break` in `walk_dwarf`; `return` in `collect_unit`; skipped in `push_function` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_FUNCTION_PARAMS` | `return` in `collect_unit`; `return` in `take_function_param` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_DEPTH` | `continue` in `resolve_attr_queue`; skipped in `resolve_attr_queue` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_REFERENCE_VISITS` | `return` in `enqueue_references`; `while` condition in `resolve_attr_queue` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_DWARF_TYPE_DEPTH` | `return` in `resolve_type_name` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_LINE_ROWS` | `break` in `assign_line_ranges`; `break` in `fill_line_ranges` | `crates/disrobe-pass-nativelang/src/dwarf.rs` |
| `disrobe-pass-nativelang` | `MAX_REPORTED_TYPES` | `.take()` in `recover_types` | `crates/disrobe-pass-nativelang/src/dwarf_types.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_BYTES` | `return` in `recover_eh_frame_functions` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_EH_FRAME_FDES` | `while` condition in `recover_eh_frame_functions` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_RECOVERED_FUNCTIONS` | `break` in `recover_functions` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_TRAVERSAL_TEXT` | `return` in `run_traversal` | `crates/disrobe-pass-nativelang/src/functions.rs` |
| `disrobe-pass-nativelang` | `MAX_STRING_COUNT` | `return` in `push_capped` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_TABLE_FUNCTION_STARTS` | `.take()` in `parse`; `.take()` in `pe_unwind_table_starts`; `break` in `macho_function_starts` | `crates/disrobe-pass-nativelang/src/image.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_FUNCTIONS` | `.take()` in `lift_native_nir` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_NIR_SYMBOLS` | `.take()` in `lift_native_nir` | `crates/disrobe-pass-nativelang/src/nir.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_NAME_LEN` | `return` in `accept_d_rtti_name`; `return` in `demangle_d_struct_type`; `return` in `mapped_d_slice` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SEGMENTS` | `return` in `accept_d_rtti_name` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_SLICE_LEN` | `return` in `mapped_d_slice` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nativelang` | `MAX_D_RTTI_VECTOR_LEN` | `return` in `d_class_info_at`; `return` in `d_class_info_name_at` | `crates/disrobe-pass-nativelang/src/recover.rs` |
| `disrobe-pass-nuitka` | `MAX_CONTAINER_LEN` | `return` in `walk_sequence`; `return` in `walk_value` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | `return` in `walk_value` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAF_BYTES` | `.min()` clamp in `scan_constants_blob`; `?` on a checked operation in `read_zero_terminated_bytes`; `break` in `scan_constants_blob`; 1 more | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LEAVES` | `return` in `push_int`; `return` in `push_str` | `crates/disrobe-pass-nuitka/src/blob_scan.rs` |
| `disrobe-pass-nuitka` | `MAX_LIFT_DEPTH` | `return` in `eval_atom`; `return` in `eval_value`; `return` in `lift_block` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_PREPROCESSOR_NESTING` | `return` in `parse_primary` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENTS` | `return` in `split_top_args` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_TOP_LEVEL_ARGUMENT_BYTES` | `return` in `split_top_args` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_DIAMOND_DEPTH` | `return` in `arm_value` | `crates/disrobe-pass-nuitka/src/body.rs` |
| `disrobe-pass-nuitka` | `MAX_FIELD_LEN` | `continue` in `decode_record` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_RECORD_LEN` | `.min()` clamp in `scan_build_info` | `crates/disrobe-pass-nuitka/src/buildinfo.rs` |
| `disrobe-pass-nuitka` | `MAX_C_CALL_ARGUMENT_BYTES` | `return` in `split_top_level_args_with_mask` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_C_DIRECT_STATEMENT_BYTES` | `return` in `direct_statement_suffix` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MAX_FACTORY_TOP_LEVEL_STATEMENTS` | `return` in `factory_top_level_statements` | `crates/disrobe-pass-nuitka/src/c_module.rs` |
| `disrobe-pass-nuitka` | `MANIFEST_ENTRY_EXTRACT_CAP` | fallback value in `render_manifest_light` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_ONEFILE_MAIN_DECOMPILE_BYTES` | skipped in `extract_children` | `crates/disrobe-pass-nuitka/src/chain_detector.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_BYTES` | `return` in `plausible_table_header`; `return` in `try_chunk_with_layout` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_CHUNK_COUNT` | `return` in `big_int`; `return` in `plausible_table_header`; `return` in `sequence`; 2 more | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_DEPTH` | `return` in `value` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | `return` in `plausible_table_header`; `return` in `try_chunk_with_layout`; slice in `plausible_table_header`; 1 more | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_PREVIOUS_CLONE_WEIGHT` | `return` in `value_body` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_STORED_LAST_WEIGHT` | fallback value in `value` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_TABLE_HEADER_HINTS` | `while` condition in `table_header_hints` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_VALUE_BYTES` | `return` in `bounded_len` | `crates/disrobe-pass-nuitka/src/const_blob.rs` |
| `disrobe-pass-nuitka` | `MAX_SIBLING_BINARY_BYTES` | `.take()` in `read_file_bounded`; `return` in `read_file_bounded` | `crates/disrobe-pass-nuitka/src/decompile.rs` |
| `disrobe-pass-nuitka` | `MAX_PYTHON_ABI_MINOR` | `for` range in `find_python_runtime_name`; `for` range in `find_python_version_marker` | `crates/disrobe-pass-nuitka/src/detect.rs` |
| `disrobe-pass-nuitka` | `MAX_FROZEN_MODULES` | `while` condition in `recover_frozen_bytecode` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_MARSHAL_BYTES` | slice in `load_code` | `crates/disrobe-pass-nuitka/src/frozen.rs` |
| `disrobe-pass-nuitka` | `MAX_ENTRIES` | `break` in `map_names` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAMES` | `.take()` in `map_names` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_LEN` | `continue` in `map_names`; `return` in `map_names`; slice in `read_c_string` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_NAME_MAP_TEXT_BYTES` | `for` range in `map_names` | `crates/disrobe-pass-nuitka/src/name_map.rs` |
| `disrobe-pass-nuitka` | `MAX_API_CALLS` | `break` in `collect_api_calls` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_FUNCTIONS` | `.min()` clamp in `parse_pdata`; `break` in `locate_impls`; skipped in `collect_ctor_sites` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_IMPL_INSNS` | `while` condition in `decode_function` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `MAX_TEXT_BYTES` | `.min()` clamp in `parse_pe` | `crates/disrobe-pass-nuitka/src/native_body.rs` |
| `disrobe-pass-nuitka` | `GLOBAL_CANDIDATE_LOG_CAP` | skipped in `locate_onefile_payload` | `crates/disrobe-pass-nuitka/src/onefile_locator.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_EXPRESSION_BYTES` | `return` in `is_safe_annotation_expression` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_ANNOTATION_NESTING` | `return` in `enter_nesting` | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-nuitka` | `MAX_STATIC_PICKLE_DEPTH` | `return` in `contains_nonfinite_float`; `return` in `is_static_pickle_hashable`; `return` in `is_static_pickle_value`; 1 more | `crates/disrobe-pass-nuitka/src/surface.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | `return` in `parse_destructure_targets` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_STATEMENTS` | `return` in `parse_block_body`; `return` in `parse_destructure_targets`; `return` in `parse_program` | `crates/disrobe-pass-php/src/decode_loop.rs` |
| `disrobe-pass-php` | `MAX_UNRECOVERED_RECORDS` | `break` in `emit_body`; skipped in `limit`; skipped in `record_opaque_literals`; 2 more | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_CLAUSE_CAP` | `return` in `catch_region_end`; `return` in `lift_catch_arms` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CATCH_TYPE_CAP` | `return` in `catch_clause` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_CLOSURE_USE_CAP` | `return` in `fold_closure` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_FOR_STEP_CAP` | `return` in `for_step_start` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_ELEMENT_CAP` | `return` in `list_entries` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LIST_RENDER_CAP` | `return` in `fold_list_assign`; `return` in `list_entries`; `return` in `push_list_text` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_EXIT_FREE_CAP` | `return` in `exit_frees_match` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_LOOP_RELIFT_WORK_CAP` | `?` on a checked operation in `loop_relift_charge` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `SANE_SWITCH_STATE_WORK_CAP` | `return` in `structure_linear_match`; `return` in `structure_switch_dispatch` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `USE_SCAN_BUDGET` | `break` in `read_after_jump`; `return` in `free_unconsumed` | `crates/disrobe-pass-php/src/decompile.rs` |
| `disrobe-pass-php` | `MAX_LINEARIZE_DEPTH` | `return` in `try_emit_braced` | `crates/disrobe-pass-php/src/deflatten.rs` |
| `disrobe-pass-php` | `ZEND_OPTIMIZER_OBF_KEY_CAP` | `return` in `read_zend_optimizer_key` | `crates/disrobe-pass-php/src/encoder/container.rs` |
| `disrobe-pass-php` | `ZEND_OBFUSCATION_KEY_CAP` | `return` in `recover_zend_optimizer_obfuscation_key` | `crates/disrobe-pass-php/src/key_extractor.rs` |
| `disrobe-pass-php` | `MAX_OPAQUE_STATEMENT` | skipped in `parse_statements` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `MAX_PARSE_DEPTH` | `return` in `parse_expr`; `return` in `parse_var_ref` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `STR_REPEAT_OUTPUT_CAP` | `return` in `str_repeat` | `crates/disrobe-pass-php/src/loader.rs` |
| `disrobe-pass-php` | `EVAL_PROBE_MIN_BUDGET` | `?` on a checked operation in `next_eval_call_arg` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `RESOLVE_DEPTH_CAP` | `return` in `classify_inner_at_depth`; `return` in `resolve_arg` | `crates/disrobe-pass-php/src/peel.rs` |
| `disrobe-pass-php` | `MAX_RESTRUCTURE_DEPTH` | `return` in `emit_units`; `return` in `structure_region`; fallback value in `emit_unit` | `crates/disrobe-pass-php/src/restructure.rs` |
| `disrobe-pass-pickle` | `MAX_RENDER_DEPTH` | `return` in `inline_unused_refs`; `return` in `render` | `crates/disrobe-pass-pickle/src/decompile.rs` |
| `disrobe-pass-pickle` | `MAX_STACKED_STREAMS` | `break` in `disassemble_streams`; no action in `analyze_streams`; no action in `run` | `crates/disrobe-pass-pickle/src/disasm.rs` |
| `disrobe-pass-pickle` | `ANCHOR_OPCODE_BUDGET` | `.min()` clamp in `scan_for_embedded_with_work` | `crates/disrobe-pass-pickle/src/ml.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_BYTES` | `return` in `analyze_nested_pickle` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_NESTED_PICKLE_DEPTH` | `return` in `analyze_nested_pickle` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-pickle` | `MAX_SCAN_DEPTH` | `return` in `scan_nested_pickles`; `return` in `scan_value` | `crates/disrobe-pass-pickle/src/safety.rs` |
| `disrobe-pass-py-decompile` | `MAX_PATTERN_NEST_DEPTH` | `return` in `classify_mapping_pattern`; `return` in `classify_sequence_pattern` | `crates/disrobe-pass-py-decompile/src/ast/builder/branches.rs` |
| `disrobe-pass-py-decompile` | `MAX_IMPORT_LEVEL` | `continue` in `build_linear_stmts_sim_seed`; fallback value in `bounded_import_level` | `crates/disrobe-pass-py-decompile/src/ast/builder/exprs.rs` |
| `disrobe-pass-py-decompile` | `MAX_LAMBDA_BRANCH_DEPTH` | `return` in `returned_expr` | `crates/disrobe-pass-py-decompile/src/ast/builder/function_meta.rs` |
| `disrobe-pass-py-decompile` | `MAX_SYNTH_OPERANDS` | `.min()` clamp in `pop_n`; `for` range in `build_linear_stmts_sim_seed` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `STRUCTURE_REENTRY_LIMIT` | `return` in `enter_active_region` | `crates/disrobe-pass-py-decompile/src/ast/builder/mod.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_LITERAL_BYTES` | `.min()` clamp in `collect_byte_tokens` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCANNED_STRINGS` | `return` in `collect_code`; `return` in `collect_object` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_SCAN_DEPTH` | `return` in `collect_code`; `return` in `collect_object` | `crates/disrobe-pass-py-decompile/src/emit/marker_guard.rs` |
| `disrobe-pass-py-decompile` | `MAX_FRAME_NEST_DEPTH` | no action in `attach_into` | `crates/disrobe-pass-py-decompile/src/frame_tree/builder.rs` |
| `disrobe-pass-py-decompile` | `MAX_CANDIDATES` | `.take()` in `accept_reordering_core` | `crates/disrobe-pass-py-decompile/src/selfcheck/opcontent.rs` |
| `disrobe-pass-py-decompile` | `MAX_DEPTH` | `return` in `lower_seq`; `return` in `lower_try` | `crates/disrobe-pass-py-decompile/src/selfcheck/relower.rs` |
| `disrobe-pass-py-decompile` | `MAX_HOIST_CANDIDATES` | `.take()` in `repair_else_tail` | `crates/disrobe-pass-py-decompile/src/selfcheck/repair.rs` |
| `disrobe-pass-py-deob` | `MAX_KEY_CANDIDATES` | `.truncate()` in `dedup_and_rank` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_REPEATING_KEYLEN` | `for` range in `best_keylengths` | `crates/disrobe-pass-py-deob/src/cipher.rs` |
| `disrobe-pass-py-deob` | `MAX_FOLDED_LEN` | `return` in `fold_binop` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_PASSES` | `for` range in `fold` | `crates/disrobe-pass-py-deob/src/constant_fold.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | `return` in `collect_code_objects` | `crates/disrobe-pass-py-deob/src/hyperion_v2v3.rs` |
| `disrobe-pass-py-deob` | `MAX_CHAIN_DEPTH` | `for` range in `peel_to_marshal_blob` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | `return` in `collect_nested_blobs`; no action in `decompile_code` | `crates/disrobe-pass-py-deob/src/marshal.rs` |
| `disrobe-pass-py-deob` | `MAX_CODEPOINT` | `return` in `apply_shift`; `return` in `stage1_codepoints` | `crates/disrobe-pass-py-deob/src/obfuscators/de4py_family.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | `return` in `walk` | `crates/disrobe-pass-py-deob/src/obfuscators/obfuxtreme.rs` |
| `disrobe-pass-py-deob` | `MAX_LOADER_BYTECODE` | `return` in `looks_like_loader` | `crates/disrobe-pass-py-deob/src/obfuscators/pyc_zipper.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | `return` in `collect_code_objects` | `crates/disrobe-pass-py-deob/src/obfuscators/pyobfus.rs` |
| `disrobe-pass-py-deob` | `MAX_NESTED_CODE_DEPTH` | `return` in `collect_code_objects` | `crates/disrobe-pass-py-deob/src/obfuscators/pypacker.rs` |
| `disrobe-pass-py-deob` | `MAX_TOKEN_CHARS` | `return` in `recover` | `crates/disrobe-pass-py-deob/src/shuffled_base64.rs` |
| `disrobe-pass-py-deob` | `MAX_OUTER_PASSES` | `for` range in `cleanup_source` | `crates/disrobe-pass-py-deob/src/source_cleanup.rs` |
| `disrobe-pass-py-deob` | `MAX_CANONICAL_NAMES` | `continue` in `canonicalize_homoglyph_names` | `crates/disrobe-pass-py-deob/src/unrename.rs` |
| `disrobe-pass-py-disasm` | `MAX_CODE_UNITS` | `break` in `disassemble_code_tree` | `crates/disrobe-pass-py-disasm/src/alt_runtimes/pypy.rs` |
| `disrobe-pass-py-disasm` | `MAX_RENDER_DEPTH` | `return` in `repr_object` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_REPR_LONG_DIGITS` | `return` in `repr_bigint` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-py-disasm` | `MAX_SET_SIMULATION` | `return` in `cpython_set_order` | `crates/disrobe-pass-py-disasm/src/const_repr.rs` |
| `disrobe-pass-pyarmor` | `MAX_NAME_LEN` | `return` in `resolve_name` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_RECORDS` | `while` condition in `parse_records` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `MAX_SECTIONS` | `.min()` clamp in `enumerate_elf_sections` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch.rs` |
| `disrobe-pass-pyarmor` | `EXECUTION_BUDGET` | `return` in `run` | `crates/disrobe-pass-pyarmor/src/bcc/dispatch_recover.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_DEPTH` | no action in `build_node`; no action in `walk_artifacts` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_TREE_NODES` | `break` in `build_node`; `break` in `walk_artifacts` | `crates/disrobe-pass-pyarmor/src/bcc/residual.rs` |
| `disrobe-pass-pyarmor` | `MAX_STEPS` | `return` in `recover_idealized` | `crates/disrobe-pass-pyarmor/src/bcc/stmt_structure.rs` |
| `disrobe-pass-pyarmor` | `MAX_PACKAGE_DEPTH` | `break` in `derive_module_path` | `crates/disrobe-pass-pyarmor/src/bcc/stub.rs` |
| `disrobe-pass-pyarmor` | `MAX_CALL_TARGETS_SCANNED` | `.take()` in `resolve_sibling_calls` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_DISASM_LINES` | `break` in `render_unmodeled` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_FUNCTIONS` | `while` condition in `discover_functions` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_RESOLVED_CALLS` | `break` in `resolve_sibling_calls` | `crates/disrobe-pass-pyarmor/src/bcc_lift.rs` |
| `disrobe-pass-pyarmor` | `MAX_READ` | `.min()` clamp in `extract_runtime_key` | `crates/disrobe-pass-pyarmor/src/key.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SCAN_BYTES` | slice in `scan_import_symbols`; slice in `scan_printable_strings` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_IMPORT_SYMBOLS` | `return` in `scan_import_symbols` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_BYTES` | `.min()` clamp in `push_printable_string` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_CONSTANTS` | `return` in `scan_printable_strings` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_STRING_SCAN_BYTES` | slice in `scan_printable_strings` | `crates/disrobe-pass-pyarmor/src/static_unpack/mod.rs` |
| `disrobe-pass-pyarmor` | `MAX_BCC_SEGMENTS` | `while` condition in `peel_bcc` | `crates/disrobe-pass-pyarmor/src/v8v9.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ENTRY_BYTES` | `continue` in `carve_zip_members` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_ZIP_ENTRIES` | `.min()` clamp in `carve_zip_members` | `crates/disrobe-pass-pyfreeze/src/chain_detector.rs` |
| `disrobe-pass-pyfreeze` | `MAX_COMMENT` | `for` range in `locate` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `SEARCH_BUDGET` | `for` range in `locate` | `crates/disrobe-pass-pyfreeze/src/common/zip_tail.rs` |
| `disrobe-pass-pyfreeze` | `MAX_FREEZE_DIR_ENTRIES` | `.take()` in `find_python_runtime`; `break` in `sibling_native_extensions` | `crates/disrobe-pass-pyfreeze/src/lib.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SECTIONS` | `return` in `parse_blob_index` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_BLOB_SLICE` | `.min()` clamp in `extract_resources_blob` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_NAME_LEN` | `while` condition in `scan_name_start` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_RESOURCE_ENTRIES` | `break` in `heuristic_walk`; `return` in `extract_modules_structured`; `return` in `parse_structured_region` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_STRUCTURED_VERSION` | `for` range in `extract_resources_blob`; no action in `find_packed_magic` | `crates/disrobe-pass-pyfreeze/src/pyoxidizer/signatures.rs` |
| `disrobe-pass-pyfreeze` | `MAX_DISASM_BYTES` | slice in `surface_native` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyfreeze` | `SAMPLE_INSTRUCTION_CAP` | `.take()` in `surface_native` | `crates/disrobe-pass-pyfreeze/src/recover.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_COMMENT` | `return` in `find_eocd` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_ZIP_ENTRIES` | `while` condition in `walk_central_directory` | `crates/disrobe-pass-pyinstaller/src/base_library.rs` |
| `disrobe-pass-pyinstaller` | `MAX_NATIVE_SURFACE_BYTES` | skipped in `extract_children` | `crates/disrobe-pass-pyinstaller/src/chain_detector.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DEEP_ANALYZE_BYTES` | skipped in `surface_native_entry` | `crates/disrobe-pass-pyinstaller/src/native_surface.rs` |
| `disrobe-pass-pyinstaller` | `MAX_CODE_WALK_DEPTH` | `return` in `collect_byte_consts` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_DECOMPRESS_ATTEMPTS` | `break` in `unzip_pyc_with_limits`; `return` in `take` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-pyinstaller` | `MAX_RECOVERED_BYTES` | `.take()` in `read_capped`; `return` in `read_capped` | `crates/disrobe-pass-pyinstaller/src/pyc_zipper.rs` |
| `disrobe-pass-ruby` | `MAX_REGS` | skipped in `set_pending`; skipped in `set` | `crates/disrobe-pass-ruby/src/mruby/lift.rs` |
| `disrobe-pass-ruby` | `MAX_EXPR_LEN` | fallback value in `push` | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `MAX_NEST_DEPTH` | `return` in `emit_send`; `return` in `massign_targets`; `return` in `render_iseq_statements`; 1 more | `crates/disrobe-pass-ruby/src/yarv/decompile.rs` |
| `disrobe-pass-ruby` | `IBF_ARRAY_LEN_CAP` | `.min()` clamp in `decode_object`; `for` range in `parse_ci_entries` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_OBJECT_LIST_ENTRY_CAP` | `.min()` clamp in `parse_image` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-ruby` | `IBF_STRING_LEN_CAP` | `break` in `decode_iseq_body`; skipped in `decode_object` | `crates/disrobe-pass-ruby/src/yarv/ibf.rs` |
| `disrobe-pass-scriptlang` | `MAX_SWF_BYTES` | `return` in `inflate_cws` | `crates/disrobe-pass-scriptlang/src/lang/haxe.rs` |
| `disrobe-pass-scriptlang` | `MAX_RDS_BYTES` | `.take()` in `read_bounded`; `return` in `maybe_gunzip_rds_with_limit`; `return` in `read_bounded` | `crates/disrobe-pass-scriptlang/src/lang/mod.rs` |
| `disrobe-pass-scriptlang` | `MAX_OPS` | `while` condition in `read_bytecode` | `crates/disrobe-pass-scriptlang/src/lang/perl_bytecode.rs` |
| `disrobe-pass-scriptlang` | `MAX_MULTICONCAT_SEGMENTS` | `.take()` in `parse_multiconcat` | `crates/disrobe-pass-scriptlang/src/lang/perl_decompile.rs` |
| `disrobe-pass-scriptlang` | `COMPLEX_VECTOR_CAP` | `.min()` clamp in `walk_item_body` | `crates/disrobe-pass-scriptlang/src/lang/r_rds.rs` |
| `disrobe-pass-scriptlang` | `MAX_ENTRIES` | `for` range in `extract_zip_with_limits`; `while` condition in `scan_metakit_files` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_METAKIT_NAME_LEN` | `return` in `read_metakit_token`; skipped in `scan_metakit_files` | `crates/disrobe-pass-scriptlang/src/lang/tcl.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_CHUNK_BYTES` | `for` range in `base64_decode` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_BASE64_INPUT_BYTES` | `return` in `base64_decode`; skipped in `base64_blobs` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_BYTES` | `break` in `rebuild_replace`; `return` in `base64_decode`; `return` in `read_inflate_text`; 1 more | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_INFLATE_READ_BYTES` | `.take()` in `read_inflate_text` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-scriptlang` | `MAX_LAYERS` | `while` condition in `recover` | `crates/disrobe-pass-scriptlang/src/lang/winscript.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | `return` in `parse_expression`; `return` in `parse_unary` | `crates/disrobe-pass-shell/src/bash/arith.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | `return` in `parse_array_assignment` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_FOR_INDICES` | `return` in `parse_for_lookup_loop` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_PRINTF_BYTES` | `return` in `try_string_split_indirection` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_TAG_LEN` | `return` in `parse_md5_cut_chunk` | `crates/disrobe-pass-shell/src/bash/bash_eval.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | `return` in `try_compress_payload` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESS_BYTES` | `return` in `try_compress_payload` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | `for` range in `reverse_bashfuscator`; no action in `reverse_bashfuscator` | `crates/disrobe-pass-shell/src/bash/bashfuscator.rs` |
| `disrobe-pass-shell` | `MAX_DEPTH` | `return` in `eval_wrapped_command`; no action in `wall` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_OUTPUT` | `break` in `decode_pipeline`; `break` in `evaluate` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_REPEAT` | no action in `expand_tr_set` | `crates/disrobe-pass-shell/src/bash/decode.rs` |
| `disrobe-pass-shell` | `MAX_GZIP_OUTPUT` | `.take()` in `peel_non_eval_layers`; `.truncate()` in `peel_non_eval_layers`; fallback value in `peel_non_eval_layers` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEELED_OUTPUT` | `break` in `peel_indirection_with_policy` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_PEEL_ROUNDS` | `break` in `peel_indirection_with_policy` | `crates/disrobe-pass-shell/src/bash/indirect.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | `while` condition in `tokenize_bash` | `crates/disrobe-pass-shell/src/bash/lexer.rs` |
| `disrobe-pass-shell` | `MAX_RECOVERED_OUTPUT` | `break` in `reverse_node_bash_obfuscate` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_TABLE_ENTRIES` | `while` condition in `parse_chunk_table` | `crates/disrobe-pass-shell/src/bash/node_bash_obfuscate.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_PATTERN_LEN` | `return` in `substitute`; `return` in `trim_prefix`; `return` in `trim_suffix` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_ANCHORED_TEXT_LEN` | `return` in `substitute`; `return` in `trim_prefix`; `return` in `trim_suffix` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_PATTERN_LEN` | `return` in `substitute` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_GLOB_SCAN_TEXT_LEN` | `return` in `substitute` | `crates/disrobe-pass-shell/src/bash/param_expand.rs` |
| `disrobe-pass-shell` | `MAX_ARITH_DEPTH` | `return` in `parse_expr`; `return` in `parse_unary` | `crates/disrobe-pass-shell/src/batch/arith.rs` |
| `disrobe-pass-shell` | `MAX_CIPHERTEXT` | `continue` in `recover_stages` | `crates/disrobe-pass-shell/src/batch/chain.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_ROUNDS` | `for` range in `expand_repeated` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_LINES` | `break` in `deobfuscate_batch` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_TOTAL_OUTPUT` | `break` in `deobfuscate_batch` | `crates/disrobe-pass-shell/src/batch/engine.rs` |
| `disrobe-pass-shell` | `MAX_EXPANSION_OUTPUT` | `break` in `expand_sigil`; `return` in `reserve_expansion_bytes` | `crates/disrobe-pass-shell/src/batch/expand.rs` |
| `disrobe-pass-shell` | `MAX_FOR_ITERATIONS` | `return` in `numeric_sequence` | `crates/disrobe-pass-shell/src/batch/forloop.rs` |
| `disrobe-pass-shell` | `MAX_REVERSE_ADDED_BYTES` | `return` in `reserve_expansion_bytes` | `crates/disrobe-pass-shell/src/batch/mod.rs` |
| `disrobe-pass-shell` | `MAX_DECODE_LEN` | `continue` in `extract_base64_blobs`; `return` in `decode_base64_flexible` | `crates/disrobe-pass-shell/src/batch/payload.rs` |
| `disrobe-pass-shell` | `MAX_POWERSHELL_LAYER_ROUNDS` | `for` range in `reverse_powershell_layers` | `crates/disrobe-pass-shell/src/chain_detector.rs` |
| `disrobe-pass-shell` | `MAX_SCRIPT_SCAN_BYTES` | slice in `detect` | `crates/disrobe-pass-shell/src/detect.rs` |
| `disrobe-pass-shell` | `MAX_ACTION_DEPTH` | `return` in `handle_action` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_ELEMENTS` | `break` in `parse_array` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DICT_ENTRIES` | `break` in `parse_dictionary_or_stream` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_DOCUMENT_BYTES` | slice in `analyze` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FILTER_CHAIN` | `break` in `decode_stream` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDINGS` | `break` in `collect_name_tree`; `break` in `scan_hex_obfuscated_names`; `return` in `add_embedded`; 2 more | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_FINDING_TEXT` | `.truncate()` in `extract_javascript`; `while` condition in `cutoff`; no action in `cutoff` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_LZW_CODES` | skipped in `lzw_decode` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_BYTES` | `break` in `parse_name`; `break` in `scan_hex_obfuscated_names` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_NAME_TREE_NODES` | `break` in `collect_name_tree` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECTS` | `break` in `brute_force`; `return` in `insert_object` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJECT_DEPTH` | `return` in `parse_object` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_OBJSTM_OBJECTS` | `.min()` clamp in `expand_object_streams` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_PREDICTOR_COLUMNS` | `.clamp()` clamp in `apply_predictor` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_RESOLVE_STEPS` | `return` in `resolve` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_BYTES` | `break` in `parse_hex_string`; `break` in `parse_literal_string` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CONCAT` | `break` in `extract_javascript` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_WALK_NODES` | `break` in `global_sweep`; `break` in `walk_acroform`; `break` in `walk_pages`; 3 more | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_CHAIN` | `break` in `parse_xref_chain` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_ENTRIES` | `.min()` clamp in `parse_xref_stream`; `for` range in `parse_xref_table` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `MAX_XREF_FIELD_WIDTH` | `return` in `parse_xref_stream` | `crates/disrobe-pass-shell/src/pdf/limits.rs` |
| `disrobe-pass-shell` | `STATIC_EVAL_DEPTH_CAP` | `break` in `peel_indirection_with_policy`; `continue` in `unwrap`; `return` in `eval_wrapped_command`; 2 more | `crates/disrobe-pass-shell/src/policy.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | `return` in `decode_frombase64_payload` | `crates/disrobe-pass-shell/src/powershell/chameleon.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | `.take()` in `reverse_compress`; `.truncate()` in `reverse_compress`; fallback value in `reverse_compress` | `crates/disrobe-pass-shell/src/powershell/invoke_obfuscation.rs` |
| `disrobe-pass-shell` | `MAX_BASE64_INPUT` | `return` in `reverse_then_b64_decode` | `crates/disrobe-pass-shell/src/powershell/invoke_stealth.rs` |
| `disrobe-pass-shell` | `MAX_TOKEN_COUNT` | `while` condition in `tokenize` | `crates/disrobe-pass-shell/src/powershell/lexer.rs` |
| `disrobe-pass-shell` | `MAX_DECOMPRESSED` | `.take()` in `reverse_psobf`; `.truncate()` in `reverse_psobf`; fallback value in `reverse_psobf` | `crates/disrobe-pass-shell/src/powershell/psobf.rs` |
| `disrobe-pass-shell` | `PROJECT_INFORMATION_RECORD_LIMIT` | `for` range in `project_codepage` | `crates/disrobe-pass-shell/src/vba/extract.rs` |
| `disrobe-pass-shell` | `MAX_CALL_ARGS` | `.min()` clamp in `pop_n` | `crates/disrobe-pass-shell/src/vba/pcode_lift.rs` |
| `disrobe-pass-shell` | `MAX_CFB_ENTRIES` | `.take()` in `locate_vba_storages` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_FUNC_ARG_CHAIN` | `while` condition in `disasm_func` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_TYPE_DESCRIPTOR_DEPTH` | `return` in `named_type_from_descriptor` | `crates/disrobe-pass-shell/src/vba/pcode_real.rs` |
| `disrobe-pass-shell` | `MAX_ARRAY_VALUES` | `return` in `read_array_constant` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_EXTERN_NAMES` | `continue` in `build` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORDS` | `while` condition in `iter_biff12`; `while` condition in `iter_biff8` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RECORD_BODY` | `.min()` clamp in `iter_biff12`; `.min()` clamp in `iter_biff8`; fallback value in `iter_biff8` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_RGCE` | `return` in `parse_fmla_biff12`; `return` in `parse_formula_biff8`; `return` in `parse_lbl`; 1 more | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_SHEETS` | `break` in `enumerate_sheets` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_STRING_CHARS` | `.min()` clamp in `decode_chars`; `return` in `read_utf16_units` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_WORKBOOK_BYTES` | `.take()` in `read_cfb_stream`; `return` in `read_cfb_stream` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_XTI` | `.min()` clamp in `parse_externsheet` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRIES` | `return` in `open_biff12` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-shell` | `MAX_ZIP_ENTRY_BYTES` | `.take()` in `read_zip_entry`; `return` in `read_zip_entry` | `crates/disrobe-pass-shell/src/xlm/limits.rs` |
| `disrobe-pass-swift-objc` | `MAX_BLOB_LEN` | `break` in `parse` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_IDENTIFIER_LEN` | `?` on a checked operation in `read_cstr_bounded` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOT_COUNT` | `.min()` clamp in `parse` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_VERIFIED_PAGES` | `.min()` clamp in `verify_page_hashes` | `crates/disrobe-pass-swift-objc/src/code_signature.rs` |
| `disrobe-pass-swift-objc` | `MAX_NODES` | `?` on a checked operation in `spend` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPEAT_COUNT` | `return` in `demangle_repeated_standard_substitution`; `return` in `demangle_substitution_chain`; `return` in `demangle_substitution` | `crates/disrobe-pass-swift-objc/src/demangle.rs` |
| `disrobe-pass-swift-objc` | `MAX_RECORDED_AUTH_POINTERS` | skipped in `unapply_segment_slide` | `crates/disrobe-pass-swift-objc/src/dyld_cache.rs` |
| `disrobe-pass-swift-objc` | `MAX_DYLIBS` | skipped in `parse_slice` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_DEPTH` | `return` in `walk_export_node` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NAME` | `?` on a checked operation in `cstr_in`; `continue` in `walk_export_node` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_EXPORT_NODES` | `return` in `walk_export_node` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_STARTS` | `while` condition in `function_starts` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_INDIRECT_SYMBOLS` | `.min()` clamp in `import_thunks` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_RPATHS` | skipped in `parse_slice` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOLS` | `.min()` clamp in `function_symbols`; `.min()` clamp in `symbol_names` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_SYMBOL_LEN` | `?` on a checked operation in `read_cstr_bounded` | `crates/disrobe-pass-swift-objc/src/macho.rs` |
| `disrobe-pass-swift-objc` | `MAX_FUNCTION_BYTES` | `.min()` clamp in `end_boundary`; `return` in `carve` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LINES_PER_FUNCTION` | `.take()` in `lines_for` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_LISTED_FUNCTIONS` | `.take()` in `lift_native_nir`; `break` in `build_function_bodies` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_NIR_SYMBOLS` | `.take()` in `lift_native_nir` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_TYPES` | `.take()` in `recover_native_bodies` | `crates/disrobe-pass-swift-objc/src/native_bodies.rs` |
| `disrobe-pass-swift-objc` | `MAX_SELECTOR_HINT_WORK` | `continue` in `index_selectors` | `crates/disrobe-pass-swift-objc/src/objc.rs` |
| `disrobe-pass-swift-objc` | `MAX_BIND_OPS` | `while` condition in `interpret_bind` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CALL_SITES` | `break` in `annotate_instructions` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_DEPTH` | `return` in `reaching_def_from`; `return` in `reaching_slot` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CFG_STEPS` | `return` in `build` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_IMPORTS` | `.min()` clamp in `parse_chained_imports` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_PAGES` | `.min()` clamp in `walk_chained_pages`; `for` range in `walk_chained_pages` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CHAINED_SEGMENTS` | `.min()` clamp in `chained_segment_infos` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | `?` on a checked operation in `chained_symbol_at`; `?` on a checked operation in `cstr_at_offset` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_MOVE_HOPS` | `for` range in `trace_pointer_slot` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_SLOTS` | `.min()` clamp in `build_classref_map`; `.min()` clamp in `build_selref_map`; `.min()` clamp in `interpret_bind` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_STUB_ENTRIES` | `while` condition in `build_arm64_stub_map`; `while` condition in `build_x86_stub_map` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOTAL_BINDS` | `break` in `interpret_bind`; `for` range in `walk_chain`; `while` condition in `interpret_bind` | `crates/disrobe-pass-swift-objc/src/objc_dispatch.rs` |
| `disrobe-pass-swift-objc` | `MAX_CATEGORIES` | `.take()` in `recover_categories` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CLASSES` | `.take()` in `recover_interfaces` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | `?` on a checked operation in `cstr_at_offset` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_LIST_COUNT` | `return` in `read_entsize_list_header` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOLS` | `.take()` in `recover_protocols` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REFS` | `return` in `parse_protocol_refs` | `crates/disrobe-pass-swift-objc/src/objc_records.rs` |
| `disrobe-pass-swift-objc` | `MAX_REPORTED_INSTALL_NAMES` | `.take()` in `dyld_cache_report` | `crates/disrobe-pass-swift-objc/src/pass.rs` |
| `disrobe-pass-swift-objc` | `MAX_CSTR` | `?` on a checked operation in `cstr_at_offset`; `?` on a checked operation in `mangled_name_at_offset` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_DESCRIPTORS` | `while` condition in `parse_field_descriptors` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_FIELDS_PER_TYPE` | `.min()` clamp in `read_field_list`; `break` in `parse_field_descriptors` | `crates/disrobe-pass-swift-objc/src/swift_reflect.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | `?` on a checked operation in `cstr_at_offset` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | `break` in `synthesize_nominal_mangling` | `crates/disrobe-pass-swift-objc/src/swift_symbolic.rs` |
| `disrobe-pass-swift-objc` | `MAX_NAME_LEN` | `?` on a checked operation in `cstr_at_offset` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PARENT_WALK` | `break` in `walk_parent_names` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_PROTOCOL_REQUIREMENTS` | `.min()` clamp in `read_protocol_requirements` | `crates/disrobe-pass-swift-objc/src/swift_typedump.rs` |
| `disrobe-pass-swift-objc` | `MAX_TOOLCHAIN_HINTS` | `.take()` in `report` | `crates/disrobe-pass-swift-objc/src/toolchain.rs` |
| `disrobe-pass-wasm-deob` | `MAX_BODY_OPS` | `break` in `fingerprint_body` | `crates/disrobe-pass-wasm-deob/src/fingerprint.rs` |
| `disrobe-pass-wasm-deob` | `MAX_RENDER_INDENT` | `.min()` clamp in `pad`; `.min()` clamp in `render_operators` | `crates/disrobe-pass-wasm-deob/src/lib.rs` |
| `disrobe-pass-wasm-deob` | `MAX_SYNTHETIC_STRUCT_FIELDS` | `.clamp()` clamp in `record_struct_field_count`; `.min()` clamp in `record_struct_new_field_types`; `return` in `record_struct_field_index` | `crates/disrobe-pass-wasm-deob/src/lift_wat.rs` |
| `disrobe-pass-wasm-deob` | `MAX_TREE_NODES` | `return` in `lower_inner` | `crates/disrobe-pass-wasm-deob/src/obfuscators/mba.rs` |
| `disrobe-pass-wasm-deob` | `MAX_ITERATIONS` | `break` in `unflatten`; `for` range in `unflatten_to_fixed_point` | `crates/disrobe-pass-wasm-deob/src/obfuscators/tigress/unflatten.rs` |
| `disrobe-pass-wasm-deob` | `MAX_EXPR_NODES` | `return` in `parse_value` | `crates/disrobe-pass-wasm-deob/src/recover.rs` |
| `disrobe-pass-wasm-deob` | `MAX_GUARD_LEN` | `return` in `match_diamond` | `crates/disrobe-pass-wasm-deob/src/recover/opaque.rs` |
| `disrobe-pass-wasm-deob` | `MAX_CALL_DEPTH` | `return` in `invoke` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_STEPS` | `return` in `eval_guard`; `return` in `run_seq` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `MAX_VALUE_STACK` | `return` in `run_seq` | `crates/disrobe-pass-wasm-deob/src/recover/pure_eval.rs` |
| `disrobe-pass-wasm-deob` | `NODE_LIMIT` | `.take()` in `collect_branch_transitions`; `return` in `accesses_cell_outside_root`; `return` in `accesses_cell`; 8 more | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `STATE_EXPRESSION_LIMIT` | `?` on a checked operation in `expression_suffix`; `?` on a checked operation in `state_write_expression`; `return` in `eval_value`; 5 more | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-wasm-deob` | `TRANSITION_INSTRUCTION_LIMIT` | `return` in `classify_select_conditional`; `return` in `condition_has_isolated_value_stack`; `return` in `structured_work_is_bounded` | `crates/disrobe-pass-wasm-deob/src/recover/reloop.rs` |
| `disrobe-pass-webview` | `COMPRESSED_SAMPLE_CAP` | `.min()` clamp in `looks_compressed` | `crates/disrobe-pass-webview/src/decompress.rs` |
| `disrobe-pass-webview` | `MAX_EVIDENCE_MARKERS` | `.truncate()` in `classify_all`; `.truncate()` in `marker_evidence` | `crates/disrobe-pass-webview/src/detect.rs` |
| `disrobe-pass-webview` | `MAX_ENTRY_PATH_BYTES` | `return` in `bounded_join`; `while` condition in `bounded_join`; slice in `bounded_join` | `crates/disrobe-pass-webview/src/electron.rs` |
| `disrobe-pass-webview` | `MAX_EXTENSION_LEN` | `continue` in `scan`; no action in `best_window` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_HASH_HAMMING` | fallback value in `hash_window` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_PATH_LEN` | `return` in `validate` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_SCAN_RECORDS` | `return` in `collect_runs`; skipped in `collect_runs` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_UNREADABLE_GAP` | `break` in `collect_runs` | `crates/disrobe-pass-webview/src/embedded.rs` |
| `disrobe-pass-webview` | `MAX_FAT_SLICES` | `.take()` in `build_slices` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_OVERLAP_WALK` | slice in `containing` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-pass-webview` | `MAX_SPANS` | `break` in `build` | `crates/disrobe-pass-webview/src/resolve.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILES_SCANNED` | `break` in `scan_circularity` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_CIRCULAR_FILE_BYTES` | `.take()` in `read_text_bounded`; `return` in `read_text_bounded` | `crates/disrobe-playground/src/circular.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_PACKED_PAIRS` | `break` in `discover_packed_pairs` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_DISCOVERED_RECOMPILE_PYC` | `break` in `discover_recompile_pyc` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_FILES` | `break` in `build` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-playground` | `MAX_MANIFEST_TOML_BYTES` | `.take()` in `read_text_bounded`; `return` in `read_text_bounded` | `crates/disrobe-playground/src/manifest.rs` |
| `disrobe-pyarmor-pytrace` | `MAX_CAPTURED` | skipped in `_trace_callback` | `crates/disrobe-pyarmor-pytrace/src/lib.rs` |
| `disrobe-semdiff` | `MAX_LINEAGE_VARIANTS` | slice in `variant_lineage` | `crates/disrobe-semdiff/src/lineage.rs` |
| `disrobe-semdiff` | `MAX_ADDRESS_PEEL_STEPS` | `while` condition in `address_form` | `crates/disrobe-semdiff/src/summary.rs` |
| `disrobe-similarity` | `REFINEMENT_ROUND_CAP` | `for` range in `refine` | `crates/disrobe-similarity/src/fingerprint.rs` |
| `disrobe-similarity` | `PROPAGATION_ROUND_CAP` | `for` range in `propagate` | `crates/disrobe-similarity/src/matcher/propagation.rs` |
| `disrobe-sleigh` | `MAX_FIXED_BITS_MEMO_ENTRIES` | skipped in `table_bits` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_CLAUSES` | `return` in `remember_table_clauses` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `MAX_TABLE_CLAUSE_MEMO_ENTRIES` | `return` in `remember_table_clauses` | `crates/disrobe-sleigh/src/compiler.rs` |
| `disrobe-sleigh` | `UNSUPPORTED_ENCODING_CAPTURE_LIMIT` | `.min()` clamp in `unsupported_length` | `crates/disrobe-sleigh/src/lifter/riscv.rs` |
| `disrobe-sleigh` | `MAX_CONDITION_DEPTH` | `return` in `parse_unary` | `crates/disrobe-sleigh/src/preprocessor.rs` |
| `disrobe-sleigh` | `MAX_ITEM_DEPTH` | `return` in `parse_with` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-sleigh` | `MAX_PATTERN_NESTING` | `return` in `pattern_nesting_exceeds` | `crates/disrobe-sleigh/src/syntax.rs` |
| `disrobe-taint` | `MAX_OUT_ARGUMENTS_PER_SOURCE` | skipped in `insert_out_argument` | `crates/disrobe-taint/src/config.rs` |
| `disrobe-taint` | `MAX_PATH_STEPS` | `.truncate()` in `append_step`; no action in `append_step` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-taint` | `MAX_RECORDED_UNRESOLVED_CALLS` | skipped in `collect_unresolved_calls` | `crates/disrobe-taint/src/engine.rs` |
| `disrobe-testkit` | `MAX_RECORD_NAME` | `.take()` in `record_name` | `crates/disrobe-testkit/src/prerequisite.rs` |
| `disrobe-tool-process` | `MAX_GROUP_MEMBERS` | `return` in `macos_group_contains_only_zombies` | `crates/disrobe-tool-process/src/unix.rs` |
| `disrobe-tool-process` | `MAX_NORMAL_PROGRAM_PATH_UNITS` | `return` in `child_visible_path` | `crates/disrobe-tool-process/src/windows.rs` |
| `disrobe-typerec` | `MAX_COPY_DEPTH` | `return` in `reg_slot_source` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MAX_THUNK_INSNS` | `.take()` in `follow_thunk`; slice in `follow_thunk` | `crates/disrobe-typerec/src/callsite.rs` |
| `disrobe-typerec` | `MIN_SOLVE_BUDGET` | `break` in `solve` | `crates/disrobe-typerec/src/constraint.rs` |
| `disrobe-typerec` | `MAX_DECODE_INSNS` | `while` condition in `decode_all` | `crates/disrobe-typerec/src/decode.rs` |
| `disrobe-typerec` | `MAX_DIE_VISITS` | `break` in `collect_unit`; `break` in `walk_functions` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_FIELDS` | `return` in `flatten_members` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_PARAMS` | skipped in `collect_unit` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_TYPE_DEPTH` | `return` in `flatten_members`; `return` in `name_through_origin`; `return` in `resolve_int_type`; 2 more | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_UNITS` | `break` in `walk_functions` | `crates/disrobe-typerec/src/dwarf_gt.rs` |
| `disrobe-typerec` | `MAX_EXPRESSION_OPERATIONS` | `return` in `classify_expression` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_LOCATION_LIST_ENTRIES` | `while` condition in `frame_slots`; `while` condition in `resolve_frame_base`; skipped in `push_slots`; 1 more | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_PROLOGUE_INSTRUCTIONS` | `while` condition in `frame_pointer_delta_from_prologue` | `crates/disrobe-typerec/src/dwarf_location.rs` |
| `disrobe-typerec` | `MAX_DESCRIPTORS` | `break` in `collect_pe_delay`; `break` in `collect_pe_imports` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_ENTRIES` | `break` in `collect_pe_delay`; `break` in `collect_pe_imports`; `break` in `collect_pe_thunks`; 3 more | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_THUNKS` | `break` in `collect_pe_delay`; `break` in `collect_pe_thunks` | `crates/disrobe-typerec/src/import_map.rs` |
| `disrobe-typerec` | `MAX_HEAP_BLOCKS` | `return` in `heap_registers` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_ROUNDS` | `.min()` clamp in `heap_registers` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_HEAP_SLOTS` | skipped in `heap_transfer` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_STACK_SLOTS` | `return` in `group_offsets` | `crates/disrobe-typerec/src/memssa.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SITES` | `return` in `record_allocator_site` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_ALLOCATOR_SYMBOLS` | `.take()` in `absorb_allocator_definitions` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_RELOC_TARGETS` | `return` in `record_reloc_target` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_SECTIONS` | `.take()` in `absorb_allocator_thunks`; `.take()` in `absorb_relocations`; `.take()` in `absorb_sections` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-typerec` | `MAX_THUNK_SCAN` | `return` in `absorb_allocator_thunks`; slice in `absorb_allocator_thunks` | `crates/disrobe-typerec/src/region.rs` |
| `disrobe-validator` | `MAX_CORPUS_DEPTH` | `return` in `collect` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-validator` | `MAX_CORPUS_ENTRIES` | `return` in `collect` | `crates/disrobe-validator/src/corpus.rs` |
| `disrobe-wasm` | `MAX_ENTROPY_BLOCKS` | `while` condition in `entropy` | `crates/disrobe-wasm/src/entry.rs` |
| `disrobe-wasm` | `MAX_GUEST_ALLOC` | `return` in `disrobe_alloc`; `return` in `disrobe_free` | `crates/disrobe-wasm/src/lib.rs` |
| `disrobe-wasm` | `MAX_RESULT_PAYLOAD` | `return` in `disrobe_result_free`; `return` in `pack_prefixed_result` | `crates/disrobe-wasm/src/lib.rs` |

## Panics

0 bounds panic when input exceeds them. Each is a defect: malformed input is a typed error, never a panic.
