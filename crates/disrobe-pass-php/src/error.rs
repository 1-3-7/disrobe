use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error, Diagnostic)]
pub enum Error {
    #[error("DR-PHP-0001: input does not appear to be PHP source (no <?php / <? open tag)")]
    NotPhpSource,

    #[error("DR-PHP-0010: PHP token stream truncated at offset {offset}: {reason}")]
    TokenTruncated { offset: usize, reason: &'static str },

    #[error("DR-PHP-0011: PHP token stream had unterminated {kind} starting at offset {offset}")]
    UnterminatedToken { kind: &'static str, offset: usize },

    #[error("DR-PHP-0012: PHP token stream exceeded token limit {cap}")]
    TokenCountExceeded { cap: usize },

    #[error("DR-PHP-0013: PHP lexer made no progress at offset {offset}")]
    TokenNoProgress { offset: usize },

    #[error("DR-PHP-0020: phar archive too small ({0} bytes, need >=4)")]
    PharTooSmall(usize),

    #[error(
        "DR-PHP-0021: phar __HALT_COMPILER(); sentinel not found (input does not contain a Zend phar payload)"
    )]
    PharNoHaltSentinel,

    #[error("DR-PHP-0022: phar manifest truncated at offset {offset} (need {need} more bytes)")]
    PharManifestTruncated { offset: usize, need: usize },

    #[error("DR-PHP-0023: phar manifest entry count {count} exceeds sane cap {cap}")]
    PharManifestTooLarge { count: u32, cap: u32 },

    #[error("DR-PHP-0024: phar alias length {0} exceeds cap")]
    PharAliasOversize(u32),

    #[error("DR-PHP-0025: phar file entry payload truncated for '{name}' (need {need}, got {got})")]
    PharEntryPayloadTruncated { name: String, need: u32, got: usize },

    #[error("DR-PHP-0026: phar entry '{name}' uses unsupported compression flag bits {bits:#010x}")]
    PharUnsupportedCompression { name: String, bits: u32 },

    #[error("DR-PHP-0027: phar entry '{name}' decompress failed: {reason}")]
    PharDecompressFailed { name: String, reason: String },

    #[error(
        "DR-PHP-0028: phar entry '{name}' decompressed output exceeded bomb cap of {cap} bytes"
    )]
    PharDecompressBomb { name: String, cap: usize },

    #[error(
        "DR-PHP-0029: phar entry '{name}' declares {declared} uncompressed bytes behind only {stored} stored bytes, past the {ceiling}-byte ceiling its compressed length supports"
    )]
    PharDeclaredSizeImplausible {
        name: String,
        declared: u32,
        stored: u32,
        ceiling: usize,
    },

    #[error(
        "DR-PHP-0037: phar archive declares {declared} recovered bytes, exceeding archive quota {cap}"
    )]
    PharArchiveQuotaExceeded { declared: usize, cap: usize },

    #[error("DR-PHP-0030: FOPO peel failed: {0}")]
    FopoPeel(&'static str),

    #[error("DR-PHP-0031: eval-chain peel exceeded depth budget {depth}")]
    EvalChainDepthExceeded { depth: u32 },

    #[error("DR-PHP-0032: eval-chain peel saw no recognized layer at depth {depth}")]
    EvalChainStuck { depth: u32 },

    #[error("DR-PHP-0033: base64 decode failed at depth {depth}: {reason}")]
    Base64Decode { depth: u32, reason: String },

    #[error("DR-PHP-0034: gzinflate failed at depth {depth}: {reason}")]
    GzInflateFailed { depth: u32, reason: String },

    #[error(
        "DR-PHP-0035: gzinflate output at depth {depth} exceeded decompression-bomb cap of {cap} bytes"
    )]
    GzInflateBomb { depth: u32, cap: usize },

    #[error("DR-PHP-0036: str_replace output exceeded expansion cap of {cap} bytes")]
    StrReplaceExpansion { cap: usize },

    #[error("DR-PHP-0040: BCompiler .bcg header too small ({0} bytes)")]
    BcgTooSmall(usize),

    #[error("DR-PHP-0041: BCompiler .bcg magic mismatch: expected 'BCG' or 'BC\\x01', got {0:?}")]
    BcgBadMagic([u8; 4]),

    #[error(
        "DR-PHP-0060: ionCube decode requested but caller did not pass an authorization gate; pass --i-have-authorization in CLI"
    )]
    IonCubeRequiresAuthorization,

    #[error(
        "DR-PHP-0061: ionCube structural decode unsupported for loader version {0}; only legacy v<=10 framing is publicly understood"
    )]
    IonCubeUnsupportedVersion(String),

    #[error("DR-PHP-0062: ionCube payload header malformed: {0}")]
    IonCubeBadHeader(&'static str),

    #[error(
        "DR-PHP-0070: SourceGuardian decode requested but caller did not pass an authorization gate"
    )]
    SourceGuardianRequiresAuthorization,

    #[error(
        "DR-PHP-0071: SourceGuardian structural decode unsupported for loader version {0}; modern variants gate behind cryptographic integrity"
    )]
    SourceGuardianUnsupportedVersion(String),

    #[error("DR-PHP-0072: SourceGuardian payload header malformed: {0}")]
    SourceGuardianBadHeader(&'static str),

    #[error(
        "DR-PHP-0080: Zend Guard decode requested but caller did not pass an authorization gate"
    )]
    ZendGuardRequiresAuthorization,

    #[error(
        "DR-PHP-0081: Zend Guard structural decode unsupported for loader version {0}; samples are scarce post-discontinuation"
    )]
    ZendGuardUnsupportedVersion(String),

    #[error("DR-PHP-0082: Zend Guard payload header malformed: {0}")]
    ZendGuardBadHeader(&'static str),

    #[error("DR-PHP-0090: op_array container magic mismatch (expected 'DZOA')")]
    OpArrayBadMagic,

    #[error(
        "DR-PHP-0091: op_array container schema version {version} is outside the layout this parser decodes ({min}..={max}); a version {min_minus} or lower predates the current 21-byte op-record/literal-pool encoding, a version {max_plus} or higher reorders or adds op_array fields the parser does not yet read",
        min_minus = min.saturating_sub(1),
        max_plus = max.saturating_add(1),
    )]
    OpArrayUnsupportedVersion { version: u8, min: u8, max: u8 },

    #[error("DR-PHP-0092: op_array truncated at offset {offset}: need {need} more bytes")]
    OpArrayTruncated { offset: usize, need: usize },

    #[error("DR-PHP-0093: op_array field '{field}' value {value} exceeds sane cap {cap}")]
    OpArrayFieldOversize {
        field: &'static str,
        value: u32,
        cap: u32,
    },

    #[error(
        "DR-PHP-0094: op_array bad operand-type byte {0:#04x} (not one of IS_UNUSED/CONST/TMP/VAR/CV)"
    )]
    OpArrayBadOperandType(u8),

    #[error("DR-PHP-0095: op_array bad op_array kind tag {0}")]
    OpArrayBadKind(u8),

    #[error("DR-PHP-0096: op_array bad literal tag {0}")]
    OpArrayBadLiteralTag(u8),

    #[error("DR-PHP-0097: op_array nesting too deep ({0})")]
    OpArrayNestTooDeep(u32),

    #[error("DR-PHP-0100: {family} container framing malformed: {reason}")]
    ContainerBadFraming {
        family: &'static str,
        reason: &'static str,
    },

    #[error("DR-PHP-0101: {family} static layer '{layer}' decode failed: {reason}")]
    ContainerLayerDecode {
        family: &'static str,
        layer: &'static str,
        reason: String,
    },

    #[error(
        "DR-PHP-0102: {family} static layer '{layer}' inflate output exceeded bomb cap of {cap} bytes"
    )]
    ContainerInflateBomb {
        family: &'static str,
        layer: &'static str,
        cap: usize,
    },

    #[error("DR-PHP-0110: goto-deflatten failed: {reason}")]
    Deflatten { reason: String },
}
