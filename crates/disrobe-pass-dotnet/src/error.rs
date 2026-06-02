use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-DOTNET-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-DOTNET-0002: not a PE image: bad DOS header (got 0x{0:04X}, want 0x5A4D)")]
    BadDosMagic(u16),

    #[error("DR-DOTNET-0003: PE NT header signature mismatch (got 0x{0:08X}, want 0x00004550)")]
    BadNtSignature(u32),

    #[error("DR-DOTNET-0004: unsupported PE optional-header magic 0x{0:04X} (want 0x10B or 0x20B)")]
    BadOptionalMagic(u16),

    #[error("DR-DOTNET-0005: PE truncated at offset {offset} (needed {needed}, had {had})")]
    Truncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-DOTNET-0006: no CLR data directory - image is native, not managed")]
    NoClrHeader,

    #[error("DR-DOTNET-0007: invalid CLR metadata signature 0x{0:08X} (want 0x424A5342 'BSJB')")]
    BadMetadataSignature(u32),

    #[error("DR-DOTNET-0008: unknown metadata stream name: {0}")]
    UnknownStream(String),

    #[error(
        "DR-DOTNET-0009: metadata heap index out of range: index {index}, heap_size {heap_size}"
    )]
    HeapOutOfRange { index: usize, heap_size: usize },

    #[error("DR-DOTNET-0010: invalid CIL method header byte 0x{0:02X}")]
    BadMethodHeader(u8),

    #[error("DR-DOTNET-0011: CIL stream truncated at offset {0}")]
    CilTruncated(usize),

    #[error("DR-DOTNET-0012: unknown CIL opcode 0x{0:04X} at offset {1}")]
    UnknownOpcode(u16, usize),

    #[error("DR-DOTNET-0013: utf-16 decode failure in user-string heap at offset {0}")]
    BadUserString(usize),

    #[error("DR-DOTNET-0014: invalid CompressedUInt at offset {0}")]
    BadCompressedUint(usize),

    #[error("DR-DOTNET-0015: ReadyToRun magic mismatch (got 0x{0:08X}, want 0x00525452 'RTR\\0')")]
    BadR2rMagic(u32),

    #[error("DR-DOTNET-0016: unsupported ReadyToRun major version {0}")]
    UnsupportedR2rVersion(u32),

    #[error("DR-DOTNET-0017: Native AOT MethodTable signature not found")]
    NoAotMethodTable,

    #[error("DR-DOTNET-0018: protector signature not present: {0}")]
    NoProtectorSignature(&'static str),

    #[error("DR-DOTNET-0019: authorization required for {0} - re-run with --i-have-authorization")]
    AuthorizationRequired(&'static str),

    #[error("DR-DOTNET-0020: external backend '{0}' not on PATH")]
    MissingTool(&'static str),

    #[error("DR-DOTNET-0021: external backend '{tool}' exited with status {status}: {stderr}")]
    BackendFailed {
        tool: &'static str,
        status: i32,
        stderr: String,
    },

    #[error("DR-DOTNET-0022: external backend '{0}' exceeded {1} ms timeout")]
    BackendTimeout(&'static str, u64),

    #[error("DR-DOTNET-0023: unsupported .NET runtime metadata version: {0}")]
    UnsupportedRuntimeVersion(String),

    #[error("DR-DOTNET-0024: detect-only protector cannot be removed: {0}")]
    DetectOnlyProtector(&'static str),

    #[error("DR-DOTNET-0025: protector watermark not present in image: {0}")]
    ProtectorMissing(String),
}
