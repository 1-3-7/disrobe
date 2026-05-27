use miette::Diagnostic;
use thiserror::Error;

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

    #[error("DR-JVM-0021: authorization required for {0} — re-run with --i-have-authorization")]
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
}
