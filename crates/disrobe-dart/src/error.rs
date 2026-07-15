use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("input has {actual} bytes but at least {minimum} are required")]
    InputTooSmall { actual: usize, minimum: usize },
    #[error("input does not begin with a Dart snapshot magic value")]
    InvalidMagic,
    #[error("snapshot length {value} is invalid")]
    InvalidDeclaredLength { value: i64 },
    #[error("snapshot declares {declared} bytes but input contains {available}")]
    DeclaredLengthOutOfBounds { declared: usize, available: usize },
    #[error("snapshot kind {0} is not full AOT")]
    UnsupportedSnapshotKind(i64),
    #[error("snapshot compatibility hash is not 32 hexadecimal bytes")]
    InvalidSnapshotCompatibilityHash,
    #[error("snapshot feature string is not NUL terminated")]
    UnterminatedFeatures,
    #[error("snapshot feature string exceeds the {limit} byte cap")]
    FeatureStringTooLong { limit: usize },
    #[error("snapshot feature string is not UTF-8")]
    InvalidFeatures,
    #[error("native object parse failed: {0}")]
    ObjectParse(String),
    #[error("required snapshot symbol {0} is missing")]
    MissingSnapshotSymbol(&'static str),
    #[error("snapshot symbol {symbol} has an invalid file range")]
    InvalidSymbolRange { symbol: &'static str },
    #[error("snapshot symbol {symbol} resolves to conflicting file ranges")]
    AmbiguousSnapshotSymbol { symbol: &'static str },
    #[error("snapshot ended at byte {offset} while reading {needed} bytes")]
    UnexpectedEnd { offset: usize, needed: usize },
    #[error("snapshot unsigned integer at byte {offset} is malformed")]
    InvalidUnsigned { offset: usize },
    #[error("snapshot reference at byte {offset} is malformed")]
    InvalidReferenceEncoding { offset: usize },
    #[error("snapshot reference {reference} exceeds object count {objects} at byte {offset}")]
    ReferenceOutOfBounds {
        reference: u32,
        objects: usize,
        offset: usize,
    },
    #[error("cluster {index} fill failed at byte {offset}: {source}")]
    ClusterFill {
        index: usize,
        offset: usize,
        source: Box<Self>,
    },
    #[error("snapshot declares {actual} {resource}, exceeding the cap of {limit}")]
    LimitExceeded {
        resource: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("allocation of {requested} {resource} failed")]
    AllocationFailed {
        resource: &'static str,
        requested: usize,
    },
    #[error("snapshot object counts are inconsistent: base {base}, total {total}")]
    InvalidObjectCounts { base: usize, total: usize },
    #[error(
        "snapshot base count {actual} does not match the preceding VM snapshot count {expected}"
    )]
    BaseObjectMismatch { actual: usize, expected: usize },
    #[error("cluster {index} uses unsupported class id {cid} at byte {offset}")]
    UnsupportedCluster {
        index: usize,
        cid: u32,
        offset: usize,
    },
    #[error("cluster {index} has malformed {field} value {value}")]
    InvalidClusterValue {
        index: usize,
        field: &'static str,
        value: i64,
    },
    #[error("cluster {index} allocated through reference {actual}, expected {expected}")]
    ObjectAllocationMismatch {
        index: usize,
        actual: usize,
        expected: usize,
    },
    #[error(
        "cluster {index} object {object} repeats length {actual}, expected {expected}, at byte {offset}"
    )]
    RepeatedLengthMismatch {
        index: usize,
        object: u32,
        actual: usize,
        expected: usize,
        offset: usize,
    },
    #[error("cluster {index} object {object} has unsupported object pool bits {bits}")]
    InvalidObjectPoolEntry { index: usize, object: u32, bits: u8 },
    #[error("file read failed for {path}: {message}")]
    FileRead { path: String, message: String },
    #[error("report serialization failed: {0}")]
    ReportSerialization(String),
    #[error("VM and isolate snapshot headers disagree on {field}")]
    SnapshotHeaderMismatch { field: &'static str },
}

pub type Result<T> = std::result::Result<T, Error>;
