use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-MOB-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-MOB-0002: zip read error: {0}")]
    Zip(String),

    #[error("DR-MOB-0003: APK/IPA does not contain expected entry: {0}")]
    EntryMissing(String),

    #[error("DR-MOB-0004: Hermes header truncated (need {need} bytes, got {got})")]
    HermesTruncated { need: usize, got: usize },

    #[error("DR-MOB-0005: Hermes magic mismatch: expected c61fbc03c103191f, got {0:#018x}")]
    HermesBadMagic(u64),

    #[error("DR-MOB-0006: Hermes version {0} not in supported range 60..=96")]
    HermesUnsupportedVersion(u32),

    #[error(
        "DR-MOB-0022: Hermes header declares {declared} bytes of tables/storage but input is only {available} bytes (corrupt or hostile header)"
    )]
    HermesHeaderCountsExceedInput { declared: usize, available: usize },

    #[error("DR-MOB-0007: Hermes function table OOB at index {index} of {count}")]
    HermesFunctionOob { index: usize, count: usize },

    #[error("DR-MOB-0008: Hermes string-kind table truncated")]
    HermesStringKindTruncated,

    #[error(
        "DR-MOB-0009: Hermes string-storage OOB: offset {offset}, length {length}, storage size {storage}"
    )]
    HermesStringOob {
        offset: usize,
        length: usize,
        storage: usize,
    },

    #[error("DR-MOB-0010: ELF parse failed: {0}")]
    ElfParse(String),

    #[error(
        "DR-MOB-0011: Dart AOT snapshot magic mismatch (expected kSnapshotMagic 0xf5f5dcdc, bytes f5 f5 dc dc)"
    )]
    DartBadMagic,

    #[error("DR-MOB-0012: Dart AOT snapshot version {0:?} unknown (recognized: 2.10..3.5)")]
    DartUnknownVersion(String),

    #[error("DR-MOB-0013: Dart AOT snapshot section {0} missing")]
    DartSectionMissing(&'static str),

    #[error("DR-MOB-0014: Flutter obfuscation map malformed: {0}")]
    FlutterMapMalformed(String),

    #[error("DR-MOB-0015: webview bundle missing required asset {0}")]
    WebviewAssetMissing(&'static str),

    #[error("DR-MOB-0016: NativeScript bundle missing app/bundle.js or app/runtime.js")]
    NativeScriptBundleMissing,

    #[error("DR-MOB-0017: Xamarin assembly store header truncated")]
    XamarinHeaderTruncated,

    #[error("DR-MOB-0018: Mach-O fat magic mismatch (expected 0xcafebabe / 0xcafebabf)")]
    MachOFatBadMagic,

    #[error("DR-MOB-0019: Mach-O fat header truncated (need {need}, got {got})")]
    MachOFatTruncated { need: usize, got: usize },

    #[error("DR-MOB-0031: Mach-O fat arch count {count} exceeds the {limit} arch cap")]
    MachOFatTooManyArches { count: usize, limit: usize },

    #[error("DR-MOB-0020: envelope decode failed: {0}")]
    EnvelopeDecode(String),

    #[error("DR-MOB-0021: input does not match any recognized mobile bundle format")]
    Unrecognized,

    #[error("DR-MOB-0023: Dart kernel magic mismatch (expected 0x90abcdef, bytes 90 ab cd ef)")]
    DartKernelBadMagic,

    #[error("DR-MOB-0024: Dart kernel section {0} unreadable or truncated")]
    DartKernelSection(&'static str),

    #[error("DR-MOB-0025: Android binary XML magic mismatch (expected RES_XML_TYPE 0x0003)")]
    AxmlBadMagic,

    #[error("DR-MOB-0026: Android binary XML chunk truncated or out of bounds")]
    AxmlTruncated,

    #[error("DR-MOB-0027: Android binary XML string pool malformed")]
    AxmlBadStringPool,

    #[error("DR-MOB-0028: resources.arsc magic mismatch (expected RES_TABLE_TYPE 0x0002)")]
    ArscBadMagic,

    #[error("DR-MOB-0029: resources.arsc chunk truncated or out of bounds")]
    ArscTruncated,

    #[error("DR-MOB-0030: resources.arsc string pool malformed")]
    ArscBadStringPool,

    #[error("DR-MOB-0032: Dart AOT snapshot section {section} is outside readable ELF data")]
    DartSectionOutOfBounds { section: String },

    #[error(
        "DR-MOB-0033: Hermes exception handler table malformed or truncated for function {index}"
    )]
    HermesExceptionTableMalformed { index: usize },

    #[error(
        "DR-MOB-0034: Dart pinned snapshot graph ran out of bytes at offset {offset} while reading {resource}"
    )]
    DartGraphTruncated {
        offset: usize,
        resource: &'static str,
    },

    #[error(
        "DR-MOB-0035: Dart pinned snapshot graph {resource} at offset {offset} is {actual}, exceeding the cap of {limit}"
    )]
    DartGraphLimitExceeded {
        resource: &'static str,
        offset: usize,
        actual: usize,
        limit: usize,
    },

    #[error(
        "DR-MOB-0036: Dart pinned snapshot graph cluster {index} uses unsupported class id {cid} at offset {offset}"
    )]
    DartGraphUnsupportedCluster {
        index: usize,
        cid: u32,
        offset: usize,
    },

    #[error(
        "DR-MOB-0037: Dart pinned snapshot graph cluster {index} has malformed {field} value {value} at offset {offset}"
    )]
    DartGraphInvalidClusterValue {
        index: usize,
        field: &'static str,
        value: i64,
        offset: usize,
    },

    #[error(
        "DR-MOB-0038: Dart pinned snapshot graph object counts are inconsistent: base {base}, total {total}"
    )]
    DartGraphInvalidObjectCounts { base: usize, total: usize },

    #[error(
        "DR-MOB-0039: Dart pinned snapshot graph cluster {index} allocated through reference {actual}, expected {expected}"
    )]
    DartGraphAllocationMismatch {
        index: usize,
        actual: usize,
        expected: usize,
    },

    #[error(
        "DR-MOB-0040: Dart pinned snapshot graph base object count {actual} does not match the preceding vm snapshot count {expected}"
    )]
    DartGraphBaseObjectMismatch { actual: usize, expected: usize },

    #[error(
        "DR-MOB-0041: Dart pinned snapshot graph reference {reference} exceeds object count {objects} at offset {offset}"
    )]
    DartGraphReferenceOutOfBounds {
        reference: u32,
        objects: usize,
        offset: usize,
    },

    #[error(
        "DR-MOB-0042: Dart pinned snapshot graph cluster {index} object {object} repeats length {actual}, expected {expected}, at offset {offset}"
    )]
    DartGraphRepeatedLengthMismatch {
        index: usize,
        object: u32,
        actual: usize,
        expected: usize,
        offset: usize,
    },

    #[error("DR-MOB-0043: Dart pinned snapshot vm and isolate headers disagree on {field}")]
    DartGraphHeaderMismatch { field: &'static str },

    #[error(
        "DR-MOB-0044: Dart pinned snapshot graph recovery limit for {resource} is {actual}, exceeding the hard cap of {limit}"
    )]
    DartGraphConfiguredLimitExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },

    #[error(
        "DR-MOB-0045: Dart pinned snapshot declares {declared} bytes but input holds {available}"
    )]
    DartGraphDeclaredLengthOutOfBounds { declared: usize, available: usize },

    #[error(
        "DR-MOB-0046: Dart pinned snapshot graph object pool entry at cluster {index} object {object} has unsupported bits {bits}"
    )]
    DartGraphInvalidObjectPoolEntry { index: usize, object: u32, bits: u8 },

    #[error("DR-MOB-0047: Dart pinned snapshot header at offset {offset} is malformed: {reason}")]
    DartGraphInvalidHeader { offset: usize, reason: &'static str },

    #[error("DR-MOB-0048: Dart instructions table is not readable: {reason}")]
    DartCodeTableUnavailable { reason: &'static str },

    #[error(
        "DR-MOB-0049: Dart instructions table at offset {offset} declares {declared} entries but the snapshot preamble declares {expected}"
    )]
    DartCodeTableLengthMismatch {
        offset: usize,
        declared: usize,
        expected: usize,
    },

    #[error(
        "DR-MOB-0050: Dart instructions table entry {index} has payload offset {offset}, which is not ascending within the {limit}-byte instructions image"
    )]
    DartCodeTableEntryOutOfOrder {
        index: usize,
        offset: u64,
        limit: usize,
    },

    #[error("DR-MOB-0051: Flutter engine symbol map is malformed: {0}")]
    FlutterEngineSymbolMapMalformed(String),

    #[error("DR-MOB-0052: Flutter engine symbol map version {version} is unsupported")]
    FlutterEngineSymbolMapUnsupportedVersion { version: u32 },

    #[error(
        "DR-MOB-0053: Flutter engine symbol map has {actual} bytes, exceeding the {limit}-byte cap"
    )]
    FlutterEngineSymbolMapTooLarge { actual: usize, limit: usize },

    #[error(
        "DR-MOB-0054: Flutter engine symbol map has {count} entries, exceeding the {limit}-entry cap"
    )]
    FlutterEngineSymbolMapTooManyEntries { count: usize, limit: usize },

    #[error("DR-MOB-0055: Flutter engine symbol map repeats address {address:#x}")]
    FlutterEngineSymbolMapDuplicateAddress { address: u64 },

    #[error(
        "DR-MOB-0056: Flutter engine symbol map address {address:#x} is outside image range [{start:#x}, {end:#x})"
    )]
    FlutterEngineSymbolMapAddressOutsideImage { address: u64, start: u64, end: u64 },

    #[error(
        "DR-MOB-0057: Flutter engine image range start {start:#x} plus size {size:#x} overflows"
    )]
    FlutterEngineSymbolMapImageRangeOverflow { start: u64, size: u64 },

    #[error("DR-MOB-0058: Flutter engine symbol map requires an elf-build-id identity")]
    FlutterEngineSymbolMapIdentityKind,

    #[error("DR-MOB-0059: Flutter ELF carries no unambiguous GNU build ID")]
    FlutterEngineSymbolMapIdentityUnavailable,

    #[error(
        "DR-MOB-0060: Flutter engine symbol map identity {map} does not match input build ID {input}"
    )]
    FlutterEngineSymbolMapIdentityMismatch { map: String, input: String },

    #[error("DR-MOB-0061: Flutter engine image cannot be bounded: {0}")]
    FlutterEngineSymbolMapImage(String),

    #[error(
        "DR-MOB-0062: Flutter engine symbol map address {address:#x} is outside every image segment"
    )]
    FlutterEngineSymbolMapAddressOutsideSegments { address: u64 },
}

impl From<zip::result::ZipError> for Error {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Zip(value.to_string())
    }
}
