use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-LUA-0001: I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("DR-LUA-0002: not a Lua bytecode chunk (missing 0x1B 'Lua' signature)")]
    BadSignature,

    #[error("DR-LUA-0003: unsupported Lua bytecode version 0x{0:02X}")]
    UnsupportedLuaVersion(u8),

    #[error("DR-LUA-0004: truncated chunk at offset {offset} (needed {needed} bytes, had {had})")]
    Truncated {
        offset: usize,
        needed: usize,
        had: usize,
    },

    #[error("DR-LUA-0005: unsupported Lua format byte 0x{0:02X} (expected official 0x00)")]
    UnsupportedFormat(u8),

    #[error(
        "DR-LUA-0006: header data check mismatch (expected 0x19 0x93 0x0D 0x0A 0x1A 0x0A from offset {0})"
    )]
    BadLuacData(usize),

    #[error("DR-LUA-0007: unexpected integer size {0} (expected 4 or 8)")]
    BadIntSize(u8),

    #[error("DR-LUA-0008: unexpected number size {0} (expected 4 or 8)")]
    BadNumberSize(u8),

    #[error("DR-LUA-0009: endian check failed: integer round-trip 0x{got:016X} != expected 0x5678")]
    EndianMismatch { got: u64 },

    #[error("DR-LUA-0010: float check failed: round-trip {got} != expected 370.5")]
    FloatMismatch { got: f64 },

    #[error("DR-LUA-0011: unknown constant tag 0x{0:02X} at offset {1}")]
    BadConstantTag(u8, usize),

    #[error("DR-LUA-0012: not a LuaJIT bytecode chunk (missing 0x1B LJ signature)")]
    BadLuaJitSignature,

    #[error("DR-LUA-0013: unsupported LuaJIT version {0} (supported 1=2.0, 2=2.1)")]
    UnsupportedLuaJitVersion(u8),

    #[error("DR-LUA-0014: malformed LuaJIT ULEB128 at offset {0}")]
    BadUleb128(usize),

    #[error("DR-LUA-0015: not a Luau bytecode chunk (version byte 0)")]
    NotLuau,

    #[error(
        "DR-LUA-0016: unsupported Luau bytecode version {0} (supported 1..=11 per current spec)"
    )]
    UnsupportedLuauVersion(u8),

    #[error("DR-LUA-0017: Luau truncated at offset {offset}")]
    LuauTruncated { offset: usize },

    #[error("DR-LUA-0018: gLua bytecode quirk not recognized: {0}")]
    GLuaUnknownQuirk(&'static str),

    #[error("DR-LUA-0019: Luvit/lit packed-bundle parse failed: {0}")]
    LuvitMalformed(&'static str),

    #[error("DR-LUA-0020: decompiler limitation: {0}")]
    DecompileUnsupported(&'static str),

    #[error("DR-LUA-0021: obfuscator signature not found: {0}")]
    NoObfuscatorSignature(&'static str),

    #[error("DR-LUA-0022: authorization required for {0} — re-run with --i-have-authorization")]
    AuthorizationRequired(&'static str),

    #[error("DR-LUA-0023: protected payload integrity violated: {0}")]
    IntegrityViolated(&'static str),

    #[error("DR-LUA-0024: invalid UTF-8 in string constant at offset {0}")]
    BadUtf8(usize),
}
