#![allow(clippy::expect_used, clippy::panic, clippy::print_stdout)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::any::Any;
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Mutex, Once};
use std::thread;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde::de::{Deserializer, Error as DeError};

use disrobe_pass_lua::decompile::{DecompiledChunk, Fidelity};
use disrobe_pass_lua::error::Error;
use disrobe_pass_lua::luvit::{self, LuvitBundle};
use disrobe_pass_lua::obfuscator::{
    DeobfOptions, PeelResult, ironbrew2, ironbrew2_real, moonsec_v1, moonsec_v3,
};
use disrobe_pass_lua::reader::{self, DetectedFormat, LuaChunk};

struct PeakTrackingAlloc;

thread_local! {
    static PEAK_SINGLE_ALLOC: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation(size: usize) {
    let _ = PEAK_SINGLE_ALLOC.try_with(|peak: &Cell<usize>| {
        if size > peak.get() {
            peak.set(size);
        }
    });
}

fn reset_peak_allocation() {
    let _ = PEAK_SINGLE_ALLOC.try_with(|peak: &Cell<usize>| peak.set(0));
}

fn peak_allocation() -> usize {
    PEAK_SINGLE_ALLOC.try_with(Cell::get).unwrap_or_default()
}

unsafe impl GlobalAlloc for PeakTrackingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOC: PeakTrackingAlloc = PeakTrackingAlloc;

static IN_FLIGHT: Mutex<BTreeMap<String, Instant>> = Mutex::new(BTreeMap::new());
static WALL_CLOCK_MS: AtomicU64 = AtomicU64::new(0);
static WATCHDOG: Once = Once::new();
const WATCHDOG_TICK: Duration = Duration::from_millis(100);

fn start_watchdog(budget: Duration) {
    WALL_CLOCK_MS.store(
        u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
        Ordering::SeqCst,
    );
    WATCHDOG.call_once(|| {
        thread::spawn(|| {
            loop {
                thread::sleep(WATCHDOG_TICK);
                let budget: Duration =
                    Duration::from_millis(WALL_CLOCK_MS.load(Ordering::SeqCst).max(1));
                let overdue: Vec<String> = IN_FLIGHT.lock().map_or_else(
                    |_| Vec::new(),
                    |guard: std::sync::MutexGuard<'_, BTreeMap<String, Instant>>| {
                        guard
                            .iter()
                            .filter(|(_, started)| started.elapsed() > budget)
                            .map(|(label, _)| label.clone())
                            .collect()
                    },
                );
                if !overdue.is_empty() {
                    eprintln!(
                        "negative corpus entries {overdue:?} did not return within {budget:?}. A \
                         parser that never returns on hostile input is a defect, so this run \
                         fails instead of hanging."
                    );
                    std::process::exit(1);
                }
            }
        });
    });
}

fn in_flight_key(label: &str) -> String {
    format!("{:?}/{label}", thread::current().id())
}

fn enter(label: &str) {
    if let Ok(mut guard) = IN_FLIGHT.lock() {
        guard.insert(in_flight_key(label), Instant::now());
    }
}

fn leave(label: &str) {
    if let Ok(mut guard) = IN_FLIGHT.lock() {
        guard.remove(&in_flight_key(label));
    }
}

macro_rules! labeled_enum {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        enum $name { $($variant),+ }

        impl $name {
            const ALL: &'static [Self] = &[$(Self::$variant),+];

            const fn label(self) -> &'static str {
                match self { $(Self::$variant => $label),+ }
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(
                deserializer: D,
            ) -> Result<Self, D::Error> {
                let raw: String = String::deserialize(deserializer)?;
                Self::ALL
                    .iter()
                    .copied()
                    .find(|candidate: &Self| candidate.label() == raw)
                    .ok_or_else(|| {
                        D::Error::custom(format!("unknown {} value {raw}", stringify!($name)))
                    })
            }
        }
    };
}

labeled_enum!(HostileShape {
    TruncationAtMagic => "truncation_at_magic",
    TruncationMidHeader => "truncation_mid_header",
    TruncationMidTable => "truncation_mid_table",
    TruncationMidRecord => "truncation_mid_record",
    TruncationMidCompressedStream => "truncation_mid_compressed_stream",
    TruncationOneByteShort => "truncation_one_byte_short",
    DeclaredSizeExceedsFile => "declared_size_exceeds_file",
    CountTimesEntrySizeOverflows => "count_times_entry_size_overflows",
    OffsetPlusLengthWrapsU64 => "offset_plus_length_wraps_u64",
    NegativeSignedWidened => "negative_signed_widened",
    IndexEqualsContainerLength => "index_equals_container_length",
    OverlappingRegions => "overlapping_regions",
    HeaderInsideItsOwnPayload => "header_inside_its_own_payload",
    DirectoryEntryIntoHeader => "directory_entry_into_header",
    SelfReferencingEntry => "self_referencing_entry",
    ArchiveSymlinkLoop => "archive_symlink_loop",
    SelfDecompressingContainer => "self_decompressing_container",
    MetadataTypeReferenceCycle => "metadata_type_reference_cycle",
    DeclaredOutputSizeBomb => "declared_output_size_bomb",
    DeeplyNestedContainer => "deeply_nested_container",
    VeryLargeEntryCount => "very_large_entry_count",
    LookalikeValidMagicRandomBody => "lookalike_valid_magic_random_body",
    LookalikeTwoMagics => "lookalike_two_magics",
    LookalikeTextMatchesMagic => "lookalike_text_matches_magic",
    UnsupportedVersionWord => "unsupported_version_word",
    AbsentOptionalStructure => "absent_optional_structure",
    InvalidUtf8Name => "invalid_utf8_name",
    TraversalName => "traversal_name",
    AbsolutePathName => "absolute_path_name",
    EmbeddedNulName => "embedded_nul_name",
    OverlongName => "overlong_name",
    AbsentDecoderKey => "absent_decoder_key",
    CorruptPackerStub => "corrupt_packer_stub",
    UnsupportedProtection => "unsupported_protection",
    InvalidWidthField => "invalid_width_field",
    StructuralSelfCheckViolation => "structural_self_check_violation",
    UnknownRecordTag => "unknown_record_tag",
    VarintOverflow => "varint_overflow",
    AuthorizationGated => "authorization_gated",
    AbsentSignature => "absent_signature",
});

labeled_enum!(LuaErrorId {
    Io => "io",
    BadSignature => "bad_signature",
    UnsupportedLuaVersion => "unsupported_lua_version",
    Truncated => "truncated",
    UnsupportedFormat => "unsupported_format",
    BadLuacData => "bad_luac_data",
    BadIntSize => "bad_int_size",
    BadNumberSize => "bad_number_size",
    EndianMismatch => "endian_mismatch",
    FloatMismatch => "float_mismatch",
    BadConstantTag => "bad_constant_tag",
    BadLuaJitSignature => "bad_luajit_signature",
    UnsupportedLuaJitVersion => "unsupported_luajit_version",
    BadUleb128 => "bad_uleb128",
    NotLuau => "not_luau",
    UnsupportedLuauVersion => "unsupported_luau_version",
    LuauTruncated => "luau_truncated",
    GLuaUnknownQuirk => "glua_unknown_quirk",
    LuvitMalformed => "luvit_malformed",
    DecompileUnsupported => "decompile_unsupported",
    NoObfuscatorSignature => "no_obfuscator_signature",
    AuthorizationRequired => "authorization_required",
    IntegrityViolated => "integrity_violated",
    BadUtf8 => "bad_utf8",
    ProtoNestingTooDeep => "proto_nesting_too_deep",
    BootstrapEmulationFailed => "bootstrap_emulation_failed",
    LimitExceeded => "limit_exceeded",
    LuauMainProtoOutOfRange => "luau_main_proto_out_of_range",
    PrometheusVmifyRefused => "prometheus_vmify_refused",
    LuauOpcodeMap => "luau_opcode_map",
});

labeled_enum!(PartialFlag {
    PeelResidual => "peel_residual",
    DecompileBestEffort => "decompile_best_effort",
});

labeled_enum!(DetectedFormatId {
    Lua51 => "lua51",
    Lua52 => "lua52",
    Lua53 => "lua53",
    Lua54 => "lua54",
    LuaJit => "luajit",
    Luau => "luau",
    GLua => "glua",
    Unknown => "unknown",
});

labeled_enum!(SurfaceId {
    ReadAuto => "read_auto",
    ReadLua51 => "read_lua51",
    ReadLua52 => "read_lua52",
    ReadLua53 => "read_lua53",
    ReadLua54 => "read_lua54",
    ReadLuaJit => "read_luajit",
    ReadLuau => "read_luau",
    DecompileAuto => "decompile_auto",
    DecompileLuaJitBytes => "decompile_luajit_bytes",
    LuvitExtract => "luvit_extract",
    PeelIronbrew2Unauthorized => "peel_ironbrew2_unauthorized",
    PeelIronbrew2Authorized => "peel_ironbrew2_authorized",
    PeelMoonSecV1 => "peel_moonsec_v1",
    PeelMoonSecV3Authorized => "peel_moonsec_v3_authorized",
    LzwDecompressBase36 => "lzw_decompress_base36",
});

labeled_enum!(FailureClass {
    ProductionFailed => "production_failed",
    DigestMismatch => "digest_mismatch",
    ControlDidNotRecover => "control_did_not_recover",
    Panicked => "panicked",
    MemoryCapExceeded => "memory_cap_exceeded",
    SilentRecovery => "silent_recovery",
    WrongErrorIdentity => "wrong_error_identity",
    WrongErrorDetail => "wrong_error_detail",
    WrongVersionPayload => "wrong_version_payload",
    WrongPartialFlag => "wrong_partial_flag",
    UnexpectedRefusal => "unexpected_refusal",
    DetectionMismatch => "detection_mismatch",
});

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: u32,
    regeneration: String,
    entry_wall_clock_ms: u64,
    entry_peak_alloc_bytes: usize,
    worker_threads: usize,
    uncovered_shapes: Vec<UncoveredShape>,
    entries: Vec<CorpusEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UncoveredShape {
    shape: HostileShape,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CorpusEntry {
    id: String,
    shape: HostileShape,
    surface: SurfaceId,
    input: Production,
    input_fnv1a64: String,
    #[serde(default)]
    peak_alloc_bytes_override: Option<usize>,
    expect: Vec<ExpectedOutcome>,
    guard: Guard,
    reason: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Guard {
    file: String,
    symbol: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Production {
    Authored {
        bytes_hex: String,
        reason: String,
    },
    Mutation {
        base: String,
        seed: u64,
        ops: Vec<MutationOp>,
        reason: String,
    },
    Constructed {
        builder: Builder,
        reason: String,
    },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum MutationOp {
    TruncateTo { len: usize },
    DropLastBytes { count: usize },
    SetBytes { offset: usize, bytes_hex: String },
    SetU32Le { offset: usize, value: u32 },
    RandomizeRange { offset: usize, len: usize },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "builder", rename_all = "snake_case", deny_unknown_fields)]
enum Builder {
    Lua51NestedProtos { depth: usize },
    Lua51WideSizeTHugeStringLength,
    LuauMainProtoIndexEqualsCount,
    LuauStringCountExceedsFile,
    LuaJitProtoLenExceedsFile,
    LuaJitUleb128Overflow,
    Ironbrew2LzwExpansionBomb { tokens: usize },
    Ironbrew2LzwTruncatedFinalToken,
    Ironbrew2LzwOverlongToken { digits: usize },
}

#[derive(Debug, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
enum ExpectedOutcome {
    Refuse {
        error: LuaErrorId,
        #[serde(default)]
        detail_contains: Option<String>,
    },
    UnsupportedVersion {
        error: LuaErrorId,
        version: u64,
    },
    Partial {
        flag: PartialFlag,
    },
    DetectionOnly {
        format: DetectedFormatId,
        error: LuaErrorId,
    },
}

#[derive(Debug, Clone)]
struct Recovery {
    partial: Option<PartialFlag>,
    summary: String,
}

#[derive(Debug, Clone)]
enum Verdict {
    Refused {
        error: LuaErrorId,
        version: Option<u64>,
        text: String,
    },
    Recovered(Recovery),
    Panicked(String),
}

#[derive(Debug, Clone)]
struct EntryReport {
    id: String,
    line: String,
    failure: Option<(FailureClass, String)>,
}

#[derive(Debug, Clone)]
struct Produced {
    hostile: Vec<u8>,
    control: Option<Vec<u8>>,
}

fn workspace_root() -> PathBuf {
    let manifest_dir: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map_or_else(|| manifest_dir.to_path_buf(), Path::to_path_buf)
}

fn manifest_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/negative_corpus/manifest.json")
}

fn load_manifest() -> Manifest {
    let path: PathBuf = manifest_path();
    let text: String = fs::read_to_string(&path).unwrap_or_else(|error| {
        panic!(
            "negative corpus manifest {} unreadable: {error}",
            path.display()
        )
    });
    serde_json::from_str::<Manifest>(&text).unwrap_or_else(|error| {
        panic!(
            "negative corpus manifest {} rejected: {error}",
            path.display()
        )
    })
}

fn fnv1a64(bytes: &[u8]) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err(format!("hex string of odd length {}", text.len()));
    }
    let raw: &[u8] = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(text.len() / 2);
    for pair in raw.chunks_exact(2) {
        let hi: u8 = hex_nibble(pair[0])?;
        let lo: u8 = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("invalid hex digit {other:#04x}")),
    }
}

const fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z: u64 = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

fn apply_op(buffer: &mut Vec<u8>, op: &MutationOp, seed: u64) -> Result<(), String> {
    match op {
        MutationOp::TruncateTo { len } => {
            if *len > buffer.len() {
                return Err(format!(
                    "truncate_to {len} exceeds the {} byte base",
                    buffer.len()
                ));
            }
            buffer.truncate(*len);
            Ok(())
        }
        MutationOp::DropLastBytes { count } => {
            if *count > buffer.len() {
                return Err(format!(
                    "drop_last_bytes {count} exceeds the {} byte base",
                    buffer.len()
                ));
            }
            let keep: usize = buffer.len() - *count;
            buffer.truncate(keep);
            Ok(())
        }
        MutationOp::SetBytes { offset, bytes_hex } => {
            let patch: Vec<u8> = decode_hex(bytes_hex)?;
            let end: usize = offset
                .checked_add(patch.len())
                .ok_or_else(|| "set_bytes range overflows".to_owned())?;
            if end > buffer.len() {
                return Err(format!(
                    "set_bytes at {offset} length {} exceeds the {} byte base",
                    patch.len(),
                    buffer.len()
                ));
            }
            buffer[*offset..end].copy_from_slice(&patch);
            Ok(())
        }
        MutationOp::SetU32Le { offset, value } => {
            let end: usize = offset
                .checked_add(4)
                .ok_or_else(|| "set_u32_le range overflows".to_owned())?;
            if end > buffer.len() {
                return Err(format!(
                    "set_u32_le at {offset} exceeds the {} byte base",
                    buffer.len()
                ));
            }
            buffer[*offset..end].copy_from_slice(&value.to_le_bytes());
            Ok(())
        }
        MutationOp::RandomizeRange { offset, len } => {
            let end: usize = offset
                .checked_add(*len)
                .ok_or_else(|| "randomize_range overflows".to_owned())?;
            if end > buffer.len() {
                return Err(format!(
                    "randomize_range at {offset} length {len} exceeds the {} byte base",
                    buffer.len()
                ));
            }
            let mut state: u64 = seed;
            for slot in &mut buffer[*offset..end] {
                *slot = (splitmix64(&mut state) >> 24) as u8;
            }
            Ok(())
        }
    }
}

fn push_u32_le(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_u64_le(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn push_varint(out: &mut Vec<u8>, value: u64) {
    let mut rest: u64 = value;
    loop {
        let mut byte: u8 = (rest & 0x7F) as u8;
        rest >>= 7;
        if rest != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if rest == 0 {
            break;
        }
    }
}

fn lua51_nested_protos(depth: usize) -> Vec<u8> {
    fn write_proto(out: &mut Vec<u8>, remaining: usize) {
        push_u32_le(out, 0);
        push_u32_le(out, 0);
        push_u32_le(out, 0);
        out.push(0);
        out.push(0);
        out.push(0);
        out.push(2);
        push_u32_le(out, 0);
        push_u32_le(out, 0);
        push_u32_le(out, u32::from(remaining > 0));
        if remaining > 0 {
            write_proto(out, remaining - 1);
        }
        push_u32_le(out, 0);
        push_u32_le(out, 0);
        push_u32_le(out, 0);
    }

    let mut bytes: Vec<u8> = vec![
        0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x04, 0x04, 0x04, 0x08, 0x00,
    ];
    write_proto(&mut bytes, depth);
    bytes
}

fn lua51_wide_size_t(source_length: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![
        0x1B, b'L', b'u', b'a', 0x51, 0x00, 0x01, 0x08, 0x08, 0x04, 0x08, 0x00,
    ];
    push_u64_le(&mut bytes, source_length);
    push_u64_le(&mut bytes, 0);
    push_u64_le(&mut bytes, 0);
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    bytes.push(2);
    for _ in 0..6 {
        push_u64_le(&mut bytes, 0);
    }
    bytes
}

fn luau_minimal(main_proto_id: u64, string_count: u64) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0x06, 0x00];
    push_varint(&mut bytes, string_count);
    push_varint(&mut bytes, 5);
    bytes.extend_from_slice(b"print");
    push_varint(&mut bytes, 1);
    bytes.push(2);
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    bytes.push(0);
    push_varint(&mut bytes, 1);
    push_u32_le(&mut bytes, 0);
    push_varint(&mut bytes, 0);
    push_varint(&mut bytes, 0);
    push_varint(&mut bytes, 0);
    push_varint(&mut bytes, 0);
    bytes.push(0);
    bytes.push(0);
    push_varint(&mut bytes, main_proto_id);
    bytes
}

fn luajit_with_proto_len(declared_len: u64, body: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0x1B, b'L', b'J', 0x02];
    push_varint(&mut bytes, 0x02);
    push_varint(&mut bytes, declared_len);
    bytes.extend_from_slice(body);
    bytes.push(0x00);
    bytes
}

fn luajit_minimal_proto_body() -> Vec<u8> {
    let mut body: Vec<u8> = vec![0x00, 0x00, 0x02, 0x00];
    push_varint(&mut body, 0);
    push_varint(&mut body, 0);
    push_varint(&mut body, 1);
    push_u32_le(&mut body, 0);
    body
}

fn luajit_uleb128_overflow() -> Vec<u8> {
    let mut bytes: Vec<u8> = vec![0x1B, b'L', b'J', 0x02];
    push_varint(&mut bytes, 0x02);
    bytes.extend_from_slice(&[0x80; 10]);
    bytes.push(0x02);
    bytes
}

fn base36_digit(value: u64) -> char {
    let v: u64 = value % 36;
    if v < 10 {
        char::from(b'0' + v as u8)
    } else {
        char::from(b'A' + (v - 10) as u8)
    }
}

fn encode_lzw_token(out: &mut String, value: u64) {
    let mut digits: Vec<char> = Vec::new();
    let mut rest: u64 = value;
    if rest == 0 {
        digits.push('0');
    }
    while rest != 0 {
        digits.push(base36_digit(rest % 36));
        rest /= 36;
    }
    digits.reverse();
    out.push(base36_digit(digits.len() as u64));
    for digit in digits {
        out.push(digit);
    }
}

fn lzw_expansion_bomb(tokens: usize) -> String {
    let mut stream: String = String::new();
    encode_lzw_token(&mut stream, 65);
    for next_index in 256u64..256u64 + tokens as u64 {
        encode_lzw_token(&mut stream, next_index);
    }
    stream
}

fn lzw_two_tokens() -> String {
    let mut stream: String = String::new();
    encode_lzw_token(&mut stream, 72);
    encode_lzw_token(&mut stream, 73);
    stream
}

fn build(builder: &Builder) -> Produced {
    match builder {
        Builder::Lua51NestedProtos { depth } => Produced {
            hostile: lua51_nested_protos(*depth),
            control: Some(lua51_nested_protos(4)),
        },
        Builder::Lua51WideSizeTHugeStringLength => Produced {
            hostile: lua51_wide_size_t(0xFFFF_FFFF_FFFF_FFF0),
            control: Some(lua51_wide_size_t(0)),
        },
        Builder::LuauMainProtoIndexEqualsCount => Produced {
            hostile: luau_minimal(1, 1),
            control: Some(luau_minimal(0, 1)),
        },
        Builder::LuauStringCountExceedsFile => Produced {
            hostile: luau_minimal(0, 0x00FF_FFFF),
            control: Some(luau_minimal(0, 1)),
        },
        Builder::LuaJitProtoLenExceedsFile => Produced {
            hostile: luajit_with_proto_len(0x000F_FFFF, &luajit_minimal_proto_body()),
            control: Some(luajit_with_proto_len(
                luajit_minimal_proto_body().len() as u64,
                &luajit_minimal_proto_body(),
            )),
        },
        Builder::LuaJitUleb128Overflow => Produced {
            hostile: luajit_uleb128_overflow(),
            control: Some(luajit_with_proto_len(
                luajit_minimal_proto_body().len() as u64,
                &luajit_minimal_proto_body(),
            )),
        },
        Builder::Ironbrew2LzwExpansionBomb { tokens } => Produced {
            hostile: lzw_expansion_bomb(*tokens).into_bytes(),
            control: Some(lzw_two_tokens().into_bytes()),
        },
        Builder::Ironbrew2LzwOverlongToken { digits } => {
            let mut overlong: String = String::new();
            encode_lzw_token(&mut overlong, 72);
            overlong.push(base36_digit(*digits as u64));
            for _ in 0..*digits {
                overlong.push('Z');
            }
            Produced {
                hostile: overlong.into_bytes(),
                control: Some(lzw_two_tokens().into_bytes()),
            }
        }
        Builder::Ironbrew2LzwTruncatedFinalToken => {
            let mut truncated: String = lzw_two_tokens();
            truncated.push('3');
            truncated.push('A');
            Produced {
                hostile: truncated.into_bytes(),
                control: Some(lzw_two_tokens().into_bytes()),
            }
        }
    }
}

fn produce(entry: &CorpusEntry, root: &Path) -> Result<Produced, String> {
    match &entry.input {
        Production::Authored { bytes_hex, .. } => Ok(Produced {
            hostile: decode_hex(bytes_hex)?,
            control: None,
        }),
        Production::Mutation {
            base, seed, ops, ..
        } => {
            let path: PathBuf = root.join(base);
            let original: Vec<u8> = fs::read(&path)
                .map_err(|error| format!("base sample {} unreadable: {error}", path.display()))?;
            let mut mutated: Vec<u8> = original.clone();
            for op in ops {
                apply_op(&mut mutated, op, *seed)?;
            }
            if mutated == original {
                return Err("mutation produced bytes identical to its base".to_owned());
            }
            Ok(Produced {
                hostile: mutated,
                control: Some(original),
            })
        }
        Production::Constructed { builder, .. } => Ok(build(builder)),
    }
}

const fn authorized() -> DeobfOptions {
    DeobfOptions {
        i_have_authorization: true,
        strict: false,
    }
}

fn chunk_recovery(chunk: &LuaChunk) -> Recovery {
    Recovery {
        partial: None,
        summary: format!(
            "chunk dialect={:?} instructions={} constants={} children={} named={}",
            chunk.dialect,
            chunk.main.code.len(),
            chunk.main.constants.len(),
            chunk.main.protos.len(),
            chunk.main.source.is_some()
        ),
    }
}

fn decompiled_recovery(chunk: &DecompiledChunk) -> Recovery {
    let partial: Option<PartialFlag> = match chunk.fidelity {
        Fidelity::Lossless => None,
        Fidelity::Lossy | Fidelity::BestEffort => Some(PartialFlag::DecompileBestEffort),
    };
    Recovery {
        partial,
        summary: format!(
            "decompiled fidelity={:?} bytes={} warnings={}",
            chunk.fidelity,
            chunk.source.len(),
            chunk.warnings.len()
        ),
    }
}

fn peel_recovery(peel: &PeelResult) -> Recovery {
    let partial: Option<PartialFlag> = if peel.fully_recovered {
        None
    } else {
        Some(PartialFlag::PeelResidual)
    };
    Recovery {
        partial,
        summary: format!(
            "peel bytes={} passes={} residual={} strings={} full={}",
            peel.deobfuscated.len(),
            peel.passes_run.len(),
            peel.residual_markers.len(),
            peel.recovered_strings.len(),
            peel.fully_recovered
        ),
    }
}

fn bundle_recovery(bundle: &LuvitBundle) -> Recovery {
    Recovery {
        partial: None,
        summary: format!(
            "luvit format={:?} files={} manifest={}",
            bundle.format,
            bundle.files.len(),
            bundle.manifest.len()
        ),
    }
}

fn run_surface(surface: SurfaceId, bytes: &[u8]) -> Result<Recovery, Error> {
    match surface {
        SurfaceId::ReadAuto => {
            reader::read_auto(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLua51 => {
            reader::lua51::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLua52 => {
            reader::lua52::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLua53 => {
            reader::lua53::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLua54 => {
            reader::lua54::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLuaJit => {
            reader::luajit::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::ReadLuau => {
            reader::luau::read(bytes).map(|chunk: LuaChunk| chunk_recovery(&chunk))
        }
        SurfaceId::DecompileAuto => disrobe_pass_lua::decompile_auto(bytes)
            .map(|chunk: DecompiledChunk| decompiled_recovery(&chunk)),
        SurfaceId::DecompileLuaJitBytes => disrobe_pass_lua::decompile_luajit_bytes(bytes)
            .map(|chunk: DecompiledChunk| decompiled_recovery(&chunk)),
        SurfaceId::LuvitExtract => {
            luvit::extract(bytes).map(|bundle: LuvitBundle| bundle_recovery(&bundle))
        }
        SurfaceId::PeelIronbrew2Unauthorized => ironbrew2::peel(bytes, &DeobfOptions::default())
            .map(|peel: PeelResult| peel_recovery(&peel)),
        SurfaceId::PeelIronbrew2Authorized => {
            ironbrew2::peel(bytes, &authorized()).map(|peel: PeelResult| peel_recovery(&peel))
        }
        SurfaceId::PeelMoonSecV1 => moonsec_v1::peel(bytes, &DeobfOptions::default())
            .map(|peel: PeelResult| peel_recovery(&peel)),
        SurfaceId::PeelMoonSecV3Authorized => {
            moonsec_v3::peel(bytes, &authorized()).map(|peel: PeelResult| peel_recovery(&peel))
        }
        SurfaceId::LzwDecompressBase36 => {
            let text: std::borrow::Cow<'_, str> = String::from_utf8_lossy(bytes);
            ironbrew2_real::lzw_decompress_base36(&text).map(|out: Vec<u8>| Recovery {
                partial: None,
                summary: format!("lzw output bytes={}", out.len()),
            })
        }
    }
}

const fn error_id(error: &Error) -> LuaErrorId {
    match error {
        Error::Io(_) => LuaErrorId::Io,
        Error::BadSignature => LuaErrorId::BadSignature,
        Error::UnsupportedLuaVersion(_) => LuaErrorId::UnsupportedLuaVersion,
        Error::Truncated { .. } => LuaErrorId::Truncated,
        Error::UnsupportedFormat(_) => LuaErrorId::UnsupportedFormat,
        Error::BadLuacData(_) => LuaErrorId::BadLuacData,
        Error::BadIntSize(_) => LuaErrorId::BadIntSize,
        Error::BadNumberSize(_) => LuaErrorId::BadNumberSize,
        Error::EndianMismatch { .. } => LuaErrorId::EndianMismatch,
        Error::FloatMismatch { .. } => LuaErrorId::FloatMismatch,
        Error::BadConstantTag(_, _) => LuaErrorId::BadConstantTag,
        Error::BadLuaJitSignature => LuaErrorId::BadLuaJitSignature,
        Error::UnsupportedLuaJitVersion(_) => LuaErrorId::UnsupportedLuaJitVersion,
        Error::BadUleb128(_) => LuaErrorId::BadUleb128,
        Error::NotLuau => LuaErrorId::NotLuau,
        Error::UnsupportedLuauVersion(_) => LuaErrorId::UnsupportedLuauVersion,
        Error::LuauTruncated { .. } => LuaErrorId::LuauTruncated,
        Error::GLuaUnknownQuirk(_) => LuaErrorId::GLuaUnknownQuirk,
        Error::LuvitMalformed(_) => LuaErrorId::LuvitMalformed,
        Error::DecompileUnsupported(_) => LuaErrorId::DecompileUnsupported,
        Error::NoObfuscatorSignature(_) => LuaErrorId::NoObfuscatorSignature,
        Error::AuthorizationRequired(_) => LuaErrorId::AuthorizationRequired,
        Error::IntegrityViolated(_) => LuaErrorId::IntegrityViolated,
        Error::BadUtf8(_) => LuaErrorId::BadUtf8,
        Error::ProtoNestingTooDeep(_) => LuaErrorId::ProtoNestingTooDeep,
        Error::BootstrapEmulationFailed(_) => LuaErrorId::BootstrapEmulationFailed,
        Error::LimitExceeded { .. } => LuaErrorId::LimitExceeded,
        Error::LuauMainProtoOutOfRange { .. } => LuaErrorId::LuauMainProtoOutOfRange,
        Error::PrometheusVmifyRefused(_) => LuaErrorId::PrometheusVmifyRefused,
        Error::LuauOpcodeMap(_) => LuaErrorId::LuauOpcodeMap,
    }
}

fn error_version(error: &Error) -> Option<u64> {
    match error {
        Error::UnsupportedLuaVersion(version)
        | Error::UnsupportedLuaJitVersion(version)
        | Error::UnsupportedLuauVersion(version) => Some(u64::from(*version)),
        _ => None,
    }
}

const fn detected_format_id(format: DetectedFormat) -> DetectedFormatId {
    match format {
        DetectedFormat::Lua51 => DetectedFormatId::Lua51,
        DetectedFormat::Lua52 => DetectedFormatId::Lua52,
        DetectedFormat::Lua53 => DetectedFormatId::Lua53,
        DetectedFormat::Lua54 => DetectedFormatId::Lua54,
        DetectedFormat::LuaJit => DetectedFormatId::LuaJit,
        DetectedFormat::Luau => DetectedFormatId::Luau,
        DetectedFormat::GLua => DetectedFormatId::GLua,
        DetectedFormat::Unknown => DetectedFormatId::Unknown,
    }
}

fn panic_text(payload: &(dyn Any + Send)) -> String {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .cloned()
                .unwrap_or_else(|| "non-string panic payload".to_owned())
        },
        |text: &&str| (*text).to_owned(),
    )
}

fn observe(surface: SurfaceId, bytes: &[u8], label: &str) -> (Verdict, usize) {
    enter(label);
    reset_peak_allocation();
    let outcome: Result<Result<Recovery, Error>, Box<dyn Any + Send>> =
        catch_unwind(AssertUnwindSafe(|| run_surface(surface, bytes)));
    let peak: usize = peak_allocation();
    leave(label);
    let verdict: Verdict = match outcome {
        Ok(Ok(recovery)) => Verdict::Recovered(recovery),
        Ok(Err(error)) => Verdict::Refused {
            error: error_id(&error),
            version: error_version(&error),
            text: error.to_string(),
        },
        Err(payload) => Verdict::Panicked(panic_text(payload.as_ref())),
    };
    (verdict, peak)
}

fn verdict_line(verdict: &Verdict) -> String {
    match verdict {
        Verdict::Refused { error, .. } => format!("refused:{}", error.label()),
        Verdict::Recovered(recovery) => recovery.partial.map_or_else(
            || "recovered:complete".to_owned(),
            |flag: PartialFlag| format!("recovered:partial:{}", flag.label()),
        ),
        Verdict::Panicked(_) => "panicked".to_owned(),
    }
}

fn outcome_matches(
    expected: &ExpectedOutcome,
    verdict: &Verdict,
    detected: DetectedFormatId,
) -> Result<(), (FailureClass, String)> {
    match (expected, verdict) {
        (
            ExpectedOutcome::Refuse {
                error,
                detail_contains,
            },
            Verdict::Refused {
                error: got, text, ..
            },
        ) => {
            if error != got {
                return Err((
                    FailureClass::WrongErrorIdentity,
                    format!(
                        "expected {} but got {} ({text})",
                        error.label(),
                        got.label()
                    ),
                ));
            }
            match detail_contains {
                Some(fragment) if !text.contains(fragment.as_str()) => Err((
                    FailureClass::WrongErrorDetail,
                    format!("expected the refusal text to contain {fragment:?} but got {text:?}"),
                )),
                _ => Ok(()),
            }
        }
        (
            ExpectedOutcome::UnsupportedVersion { error, version },
            Verdict::Refused {
                error: got,
                version: got_version,
                text,
            },
        ) => {
            if error != got {
                return Err((
                    FailureClass::WrongErrorIdentity,
                    format!(
                        "expected {} but got {} ({text})",
                        error.label(),
                        got.label()
                    ),
                ));
            }
            if *got_version != Some(*version) {
                return Err((
                    FailureClass::WrongVersionPayload,
                    format!("expected version {version} but got {got_version:?} ({text})"),
                ));
            }
            Ok(())
        }
        (
            ExpectedOutcome::DetectionOnly { format, error },
            Verdict::Refused {
                error: got, text, ..
            },
        ) => {
            if *format != detected {
                return Err((
                    FailureClass::DetectionMismatch,
                    format!(
                        "expected detect to classify {} but it said {}",
                        format.label(),
                        detected.label()
                    ),
                ));
            }
            if error != got {
                return Err((
                    FailureClass::WrongErrorIdentity,
                    format!(
                        "expected {} but got {} ({text})",
                        error.label(),
                        got.label()
                    ),
                ));
            }
            Ok(())
        }
        (ExpectedOutcome::Partial { flag }, Verdict::Recovered(recovery)) => {
            if recovery.partial == Some(*flag) {
                Ok(())
            } else {
                Err((
                    FailureClass::WrongPartialFlag,
                    format!(
                        "expected the {} flag but got {:?} ({})",
                        flag.label(),
                        recovery.partial.map(PartialFlag::label),
                        recovery.summary
                    ),
                ))
            }
        }
        (
            ExpectedOutcome::Refuse { error, .. }
            | ExpectedOutcome::UnsupportedVersion { error, .. }
            | ExpectedOutcome::DetectionOnly { error, .. },
            Verdict::Recovered(recovery),
        ) => Err((
            FailureClass::SilentRecovery,
            format!(
                "expected a refusal with {} but the surface recovered: {}",
                error.label(),
                recovery.summary
            ),
        )),
        (ExpectedOutcome::Partial { flag }, Verdict::Refused { error, text, .. }) => Err((
            FailureClass::UnexpectedRefusal,
            format!(
                "expected the {} flag but the surface refused with {} ({text})",
                flag.label(),
                error.label()
            ),
        )),
        (_, Verdict::Panicked(message)) => Err((
            FailureClass::Panicked,
            format!("the surface panicked: {message}"),
        )),
    }
}

fn evaluate(entry: &CorpusEntry, root: &Path, default_alloc_cap: usize) -> EntryReport {
    let alloc_cap: usize = entry.peak_alloc_bytes_override.unwrap_or(default_alloc_cap);
    let produced: Produced = match produce(entry, root) {
        Ok(produced) => produced,
        Err(error) => {
            return EntryReport {
                id: entry.id.clone(),
                line: format!("{} | {} | production_failed", entry.id, entry.shape.label()),
                failure: Some((FailureClass::ProductionFailed, error)),
            };
        }
    };
    let digest: String = fnv1a64(&produced.hostile);
    if digest != entry.input_fnv1a64 {
        return EntryReport {
            id: entry.id.clone(),
            line: format!("{} | {} | digest_mismatch", entry.id, entry.shape.label()),
            failure: Some((
                FailureClass::DigestMismatch,
                format!(
                    "the recorded digest {} does not regenerate; the produced input hashes to {digest}",
                    entry.input_fnv1a64
                ),
            )),
        };
    }
    if let Some(control) = &produced.control {
        let control_label: String = format!("{}#control", entry.id);
        let (control_verdict, control_peak): (Verdict, usize) =
            observe(entry.surface, control, &control_label);
        let control_failure: Option<String> = match &control_verdict {
            Verdict::Recovered(_) if control_peak <= alloc_cap => None,
            Verdict::Recovered(_) => Some(format!(
                "the control input allocated {control_peak} bytes in one request, over the {alloc_cap} byte cap"
            )),
            Verdict::Refused { error, text, .. } => Some(format!(
                "the control input must recover, but {} refused it with {} ({text})",
                entry.surface.label(),
                error.label()
            )),
            Verdict::Panicked(message) => Some(format!("the control input panicked: {message}")),
        };
        if let Some(detail) = control_failure {
            return EntryReport {
                id: entry.id.clone(),
                line: format!(
                    "{} | {} | control_did_not_recover",
                    entry.id,
                    entry.shape.label()
                ),
                failure: Some((FailureClass::ControlDidNotRecover, detail)),
            };
        }
    }
    let (verdict, peak): (Verdict, usize) = observe(entry.surface, &produced.hostile, &entry.id);
    let detected: DetectedFormatId = detected_format_id(reader::detect(&produced.hostile));
    let line: String = format!(
        "{} | {} | {} | {}",
        entry.id,
        entry.shape.label(),
        entry.surface.label(),
        verdict_line(&verdict)
    );
    if peak > alloc_cap {
        return EntryReport {
            id: entry.id.clone(),
            line,
            failure: Some((
                FailureClass::MemoryCapExceeded,
                format!("one allocation reserved {peak} bytes, over the {alloc_cap} byte cap"),
            )),
        };
    }
    let mut rejections: Vec<(FailureClass, String)> = Vec::new();
    for expected in &entry.expect {
        match outcome_matches(expected, &verdict, detected) {
            Ok(()) => {
                return EntryReport {
                    id: entry.id.clone(),
                    line,
                    failure: None,
                };
            }
            Err(rejection) => rejections.push(rejection),
        }
    }
    let class: FailureClass = rejections
        .first()
        .map_or(FailureClass::WrongErrorIdentity, |(class, _)| *class);
    let detail: String = rejections
        .iter()
        .map(|(class, message)| format!("[{}] {message}", class.label()))
        .collect::<Vec<String>>()
        .join("; ");
    EntryReport {
        id: entry.id.clone(),
        line,
        failure: Some((class, detail)),
    }
}

fn run_corpus(manifest: &Manifest, workers: usize) -> Vec<EntryReport> {
    start_watchdog(Duration::from_millis(manifest.entry_wall_clock_ms));
    let root: PathBuf = workspace_root();
    let next: AtomicUsize = AtomicUsize::new(0);
    let collected: Mutex<Vec<EntryReport>> = Mutex::new(Vec::with_capacity(manifest.entries.len()));
    let lanes: usize = workers.clamp(1, manifest.entries.len().max(1));
    thread::scope(|scope: &thread::Scope<'_, '_>| {
        for _ in 0..lanes {
            let next_ref: &AtomicUsize = &next;
            let collected_ref: &Mutex<Vec<EntryReport>> = &collected;
            let root_ref: &Path = root.as_path();
            scope.spawn(move || {
                loop {
                    let index: usize = next_ref.fetch_add(1, Ordering::SeqCst);
                    let Some(entry): Option<&CorpusEntry> = manifest.entries.get(index) else {
                        break;
                    };
                    let report: EntryReport =
                        evaluate(entry, root_ref, manifest.entry_peak_alloc_bytes);
                    if let Ok(mut guard) = collected_ref.lock() {
                        guard.push(report);
                    }
                }
            });
        }
    });
    let mut reports: Vec<EntryReport> = collected.into_inner().unwrap_or_default();
    reports.sort_by(|left: &EntryReport, right: &EntryReport| left.id.cmp(&right.id));
    reports
}

fn render(reports: &[EntryReport]) -> String {
    let mut out: String = String::new();
    for report in reports {
        let status: String = report.failure.as_ref().map_or_else(
            || "pass".to_owned(),
            |(class, _)| format!("FAIL:{}", class.label()),
        );
        let _ = writeln!(out, "{} | {status}", report.line);
    }
    out
}

#[test]
fn every_negative_entry_produces_its_labeled_outcome() {
    let manifest: Manifest = load_manifest();
    assert_eq!(manifest.schema_version, 1, "unknown manifest schema");
    let reports: Vec<EntryReport> = run_corpus(&manifest, manifest.worker_threads);
    assert_eq!(
        reports.len(),
        manifest.entries.len(),
        "every entry must produce exactly one report"
    );
    let failures: Vec<&EntryReport> = reports
        .iter()
        .filter(|report: &&EntryReport| report.failure.is_some())
        .collect();
    let passed: usize = reports.len() - failures.len();
    println!(
        "negative corpus entries meeting their label: {passed}/{}",
        reports.len()
    );
    assert!(
        failures.is_empty(),
        "{}/{} negative corpus entries did not produce their labeled outcome:\n{}",
        failures.len(),
        reports.len(),
        failures
            .iter()
            .filter_map(|report: &&EntryReport| report
                .failure
                .as_ref()
                .map(|(class, detail)| format!("  {} [{}] {detail}", report.id, class.label())))
            .collect::<Vec<String>>()
            .join("\n")
    );
}

#[test]
fn corpus_report_is_independent_of_worker_count() {
    let manifest: Manifest = load_manifest();
    let single: String = render(&run_corpus(&manifest, 1));
    let parallel: String = render(&run_corpus(&manifest, manifest.worker_threads.max(4)));
    assert_eq!(
        single, parallel,
        "the corpus report must be byte-identical at one worker and at many"
    );
}

#[test]
fn every_hostile_shape_is_covered_or_excused() {
    let manifest: Manifest = load_manifest();
    let covered: BTreeSet<HostileShape> = manifest
        .entries
        .iter()
        .map(|entry: &CorpusEntry| entry.shape)
        .collect();
    let excused: BTreeSet<HostileShape> = manifest
        .uncovered_shapes
        .iter()
        .map(|shape: &UncoveredShape| shape.shape)
        .collect();
    let overlap: Vec<&'static str> = covered
        .intersection(&excused)
        .map(|shape: &HostileShape| shape.label())
        .collect();
    assert!(
        overlap.is_empty(),
        "a shape cannot be both covered and excused: {overlap:?}"
    );
    for excuse in &manifest.uncovered_shapes {
        assert!(
            excuse.reason.len() > 40,
            "shape {} is excused without a substantive reason",
            excuse.shape.label()
        );
    }
    let missing: Vec<&'static str> = HostileShape::ALL
        .iter()
        .filter(|shape: &&HostileShape| !covered.contains(shape) && !excused.contains(shape))
        .map(|shape: &HostileShape| shape.label())
        .collect();
    println!(
        "hostile shapes with at least one entry: {}/{}; excused with a reason: {}",
        covered.len(),
        HostileShape::ALL.len(),
        excused.len()
    );
    assert!(
        missing.is_empty(),
        "every hostile shape must be covered by an entry or excused with a reason: {missing:?}"
    );
}

#[test]
fn every_entry_is_labeled_and_names_a_real_guard() {
    let manifest: Manifest = load_manifest();
    let crate_root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut guarded: BTreeSet<String> = BTreeSet::new();
    for entry in &manifest.entries {
        assert!(
            seen.insert(entry.id.as_str()),
            "duplicate corpus entry id {}",
            entry.id
        );
        assert!(
            !entry.expect.is_empty(),
            "entry {} declares no acceptable outcome",
            entry.id
        );
        assert!(
            entry.reason.len() > 40,
            "entry {} does not state why its outcome is the correct one",
            entry.id
        );
        let production_reason: &str = match &entry.input {
            Production::Authored { reason, .. }
            | Production::Mutation { reason, .. }
            | Production::Constructed { reason, .. } => reason.as_str(),
        };
        assert!(
            production_reason.len() > 20,
            "entry {} does not record how it was produced",
            entry.id
        );
        let guard_path: PathBuf = crate_root.join(&entry.guard.file);
        let guard_source: String = fs::read_to_string(&guard_path).unwrap_or_else(|error| {
            panic!(
                "entry {} names guard file {} which cannot be read: {error}",
                entry.id,
                guard_path.display()
            )
        });
        assert!(
            guard_source.contains(&entry.guard.symbol),
            "entry {} names guard {} in {}, which does not contain it",
            entry.id,
            entry.guard.symbol,
            entry.guard.file
        );
        guarded.insert(format!("{}::{}", entry.guard.file, entry.guard.symbol));
    }
    println!(
        "corpus entries: {}; distinct guards pinned: {}",
        manifest.entries.len(),
        guarded.len()
    );
    assert!(
        guarded.len() >= 3,
        "the corpus must pin at least three distinct guards, found {}",
        guarded.len()
    );
    assert!(
        manifest.regeneration.contains("negative_corpus"),
        "the manifest must record how its digests are regenerated"
    );
}

#[test]
#[ignore = "prints the digest of every produced input so the manifest can record it"]
fn print_entry_digests() {
    let manifest: Manifest = load_manifest();
    let root: PathBuf = workspace_root();
    for entry in &manifest.entries {
        match produce(entry, root.as_path()) {
            Ok(produced) => println!(
                "{} {} {}",
                entry.id,
                fnv1a64(&produced.hostile),
                produced.hostile.len()
            ),
            Err(error) => println!("{} PRODUCTION_FAILED {error}", entry.id),
        }
    }
}
