use miette::Diagnostic;
use thiserror::Error;

use disrobe_bytes::ByteReadError;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-JVM-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-JVM-0002: invalid class magic: expected 0xCAFEBABE, got 0x{0:08X}")]
    BadMagic(u32),

    #[error(
        "DR-JVM-0003: truncated class file at offset {offset} (needed {needed} bytes, had {had})"
    )]
    Truncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-JVM-0004: unsupported class major version {major} (supported 45..=69)")]
    UnsupportedClassVersion { major: u16 },

    #[error("DR-JVM-0005: unknown constant pool tag {0} at index {1}")]
    UnknownConstantTag(u8, usize),

    #[error("DR-JVM-0006: constant pool index {idx} out of range (size {size})")]
    BadConstantIndex { idx: usize, size: usize },

    #[error("DR-JVM-0007: invalid Modified UTF-8 in constant pool")]
    BadModifiedUtf8,

    #[error("DR-JVM-0008: invalid DEX magic: {0:?}")]
    BadDexMagic([u8; 8]),

    #[error("DR-JVM-0009: unsupported DEX format version {0:?}")]
    UnsupportedDexVersion([u8; 3]),

    #[error("DR-JVM-0010: DEX endian tag invalid (expected 0x12345678, got 0x{0:08X})")]
    BadDexEndian(u32),

    #[error("DR-JVM-0011: ZIP archive error: {0}")]
    Zip(String),

    #[error("DR-JVM-0012: AndroidManifest.xml is not binary XML (missing 0x0080 chunk type)")]
    BadAxmlMagic,

    #[error("DR-JVM-0013: AndroidManifest.xml truncated or malformed at offset {0}")]
    BadAxml(usize),

    #[error("DR-JVM-0014: JIMAGE magic mismatch (expected 0xCAFEDADA, got 0x{0:08X})")]
    BadJimageMagic(u32),

    #[error("DR-JVM-0015: JMOD magic mismatch (expected 'JM' + version, got {0:?})")]
    BadJmodMagic([u8; 4]),

    #[error("DR-JVM-0026: JIMAGE table/region offset {offset} out of range (image size {size})")]
    JimageOutOfRange { offset: usize, size: usize },

    #[error("DR-JVM-MissingTool: required external backend not on PATH: {0}")]
    MissingTool(String),

    #[error("DR-JVM-0016: external tool '{tool}' exited with status {status}: {stderr}")]
    BackendFailed {
        tool: String,
        status: i32,
        stderr: String,
    },

    #[error("DR-JVM-0017: external tool '{0}' exceeded {1} ms timeout")]
    BackendTimeout(String, u64),

    #[error("DR-JVM-0018: ProGuard mapping parse failed at line {0}: {1}")]
    BadMapping(usize, String),

    #[error("DR-JVM-0019: protector signature not present: {0}")]
    NoProtectorSignature(&'static str),

    #[error("DR-JVM-0020: Kotlin @Metadata annotation malformed: {0}")]
    BadKotlinMetadata(&'static str),

    #[error("DR-JVM-0021: authorization required for {0} - re-run with --i-have-authorization")]
    AuthorizationRequired(&'static str),

    #[error("DR-JVM-0022: smali emission would lose data: {0}")]
    SmaliLossy(&'static str),

    #[error("DR-JVM-0023: zlib decompression failed: {0}")]
    Zlib(String),

    #[error(
        "DR-JVM-0090: DexGuard reverse requested but caller did not pass an authorization gate; \
         pass --i-have-authorization in CLI"
    )]
    DexGuardRequiresAuthorization,

    #[error("DR-JVM-0091: DexGuard input does not begin with 'dex\\n' magic (need a raw .dex)")]
    DexGuardNotDex,

    #[error("DR-JVM-0024: unknown JVM opcode 0x{0:02X} at code offset {1}")]
    UnknownOpcode(u8, usize),

    #[error("DR-JVM-0025: malformed bytecode at offset {offset}: {reason}")]
    BadBytecode { offset: usize, reason: &'static str },

    #[error("DR-JVM-0093: method body not recovered: {reason}")]
    UnrecoveredRegion { reason: &'static str },

    #[error("DR-JVM-0092: not an Android App Bundle (missing BundleConfig.pb at zip root)")]
    NotAab,

    #[error("DR-JVM-0027: invalid OAT magic: expected 'oat\\n', got {0:?}")]
    BadOatMagic([u8; 4]),

    #[error("DR-JVM-0028: invalid ODEX (DexOptHeader) magic: expected 'dey\\n', got {0:?}")]
    BadOdexMagic([u8; 4]),

    #[error("DR-JVM-0029: unsupported OAT version {0:?}")]
    UnsupportedOatVersion([u8; 4]),

    #[error(
        "DR-JVM-0030: OAT data region not locatable (no 'oatdata' symbol or '.rodata' section); \
         offset {offset} out of range (size {size})"
    )]
    OatOffsetOutOfRange { offset: usize, size: usize },

    #[error(
        "DR-JVM-0031: invalid resources.arsc chunk: expected RES_TABLE_TYPE 0x0002, got type 0x{0:04X}"
    )]
    BadArscChunk(u16),

    #[error(
        "DR-JVM-0032: resources.arsc truncated at offset {offset} (needed {needed}, had {had})"
    )]
    ArscTruncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-JVM-0033: resource string index {idx} out of range (size {size})")]
    BadArscStringIndex { idx: usize, size: usize },

    #[error("DR-JVM-0034: not an Android Archive (missing classes.jar entry at the .aar zip root)")]
    NotAar,

    #[error("DR-JVM-0035: not an APK Set (no .apk member entries found in the .apks zip)")]
    NotApks,

    #[error(
        "DR-JVM-0036: OAT multi-dex extraction unsupported: {count} embedded dex file(s) \
         declared, but the per-entry OatDexFile record stride past the first entry is \
         version-dependent and not derivable from the header alone"
    )]
    OatMultiDexUnsupported { count: u32 },
}

impl From<ByteReadError> for Error {
    fn from(error: ByteReadError) -> Self {
        Self::Truncated {
            offset: error.offset,
            needed: error.needed,
            had: error.available,
        }
    }
}
