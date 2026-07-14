use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-NUITKA-0001: input does not appear to be a Nuitka-compiled binary")]
    NotNuitka,

    #[error("DR-NUITKA-0002: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-NUITKA-0003: PE/ELF/Mach-O parse error: {0}")]
    ObjectParse(String),

    #[error("DR-NUITKA-0004: onefile payload magic mismatch (expected 'KA[XY]', got {0:?})")]
    BadOnefileMagic([u8; 3]),

    #[error("DR-NUITKA-0005: zstd decompression failed: {0}")]
    Zstd(String),

    #[error("DR-NUITKA-0006: onefile entry record truncated at offset {0}")]
    EntryTruncated(usize),

    #[error(
        "DR-NUITKA-0007: Nuitka emits native code, so the original Python source text is not present in the artifact; constants and symbols are, and where the build .c is shipped, body recovery is partial"
    )]
    NoSource,

    #[error("DR-NUITKA-0008: build-info section not found in image")]
    BuildInfoMissing,

    #[error("DR-NUITKA-0009: build-info record malformed at offset {offset}: {reason}")]
    BuildInfoMalformed { offset: usize, reason: String },

    #[error("DR-NUITKA-0010: reassembly requires at least one payload entry")]
    EmptyPayload,

    #[error("DR-NUITKA-0011: constants manifest (__constant.txt) malformed: {0}")]
    ConstManifestMalformed(String),

    #[error("DR-NUITKA-0012: .const stream at offset {offset} had no STOP opcode")]
    ConstStreamNoStop { offset: usize },

    #[error(
        "DR-NUITKA-0013: .const file had {consumed} bytes consumed but {total} on disk (dropped streams - likely a per-stream memo reset bug)"
    )]
    ConstTrailingBytes { consumed: usize, total: usize },

    #[error("DR-NUITKA-0014: pickle decode error in constants stream: {0}")]
    ConstPickle(String),

    #[error("DR-NUITKA-0015: constants flatten recursion exceeded depth limit")]
    ConstFlattenDepth,

    #[error("DR-NUITKA-0016: constants file exceeded stream cap")]
    ConstTooManyStreams,

    #[error("DR-NUITKA-0017: no Nuitka constants source found (no *.const files or build dir)")]
    NoConstantsSource,

    #[error("DR-NUITKA-0018: surface binding failed: {0}")]
    SurfaceBinding(String),

    #[error("DR-NUITKA-0019: pickle decode error in __bytecode table: {0}")]
    BytecodePickle(String),

    #[error("DR-NUITKA-0020: marshal decode error for a frozen module code object: {0}")]
    BytecodeMarshal(#[source] disrobe_py_marshal::Error),

    #[error("DR-NUITKA-0021: __bytecode entry unmarshalled to a non-code object: {0}")]
    BytecodeNotCode(String),

    #[error(
        "DR-NUITKA-0022: could not determine the marshal layout for the __bytecode table (no python ABI and no probed version decoded it)"
    )]
    BytecodeVersionUnknown,

    #[error("DR-NUITKA-0023: C source has {bytes} bytes, above the {max_bytes}-byte parsing cap")]
    CSourceTooLarge { bytes: usize, max_bytes: usize },

    #[error("DR-NUITKA-0024: artifact path is not a regular file: {path}")]
    NonRegularArtifact { path: std::path::PathBuf },

    #[error("DR-NUITKA-0025: C source is not valid UTF-8: {0}")]
    CSourceInvalidUtf8(#[source] std::str::Utf8Error),

    #[error("DR-NUITKA-0026: artifact {path} has {bytes} bytes, above the {max_bytes}-byte cap")]
    ArtifactTooLarge {
        path: std::path::PathBuf,
        bytes: u64,
        max_bytes: u64,
    },

    #[error("DR-NUITKA-0027: C source {resource} count {count} exceeds the {max_count} limit")]
    CSourceComplexityExceeded {
        resource: &'static str,
        count: usize,
        max_count: usize,
    },

    #[error(
        "DR-NUITKA-0028: build directory has {count} .const files, above the {max_count} limit"
    )]
    TooManyConstFiles { count: usize, max_count: usize },

    #[error(
        "DR-NUITKA-0029: build directory constants total {bytes} bytes, above the {max_bytes}-byte cap"
    )]
    BuildConstantsTooLarge { bytes: u64, max_bytes: u64 },

    #[error(
        "DR-NUITKA-0030: constant manifest has {count} object members, above the {max_count} limit"
    )]
    ConstManifestTooManyEntries { count: usize, max_count: usize },

    #[error("DR-NUITKA-0031: directory {path} has more than {max_count} entries")]
    TooManyDirectoryEntries {
        path: std::path::PathBuf,
        max_count: usize,
    },

    #[error("DR-NUITKA-0032: {resource} has {bytes} bytes, above the {max_bytes}-byte cap")]
    InputTooLarge {
        resource: &'static str,
        bytes: u64,
        max_bytes: u64,
    },

    #[error("DR-NUITKA-0033: constant input set has {count} files, above the {max_count} limit")]
    TooManyConstantInputs { count: usize, max_count: usize },
}
