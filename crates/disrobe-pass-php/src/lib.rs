#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::missing_const_for_fn)]

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod bcompiler;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod decompile;
pub mod detect;
pub mod encoder;
pub mod error;
pub mod format_wire;
pub mod pass;
pub mod peel;
pub mod phar;
pub mod protectors;
pub mod provenance_header;
pub mod sigs;
pub mod token;

pub use bcompiler::{BCG_MIN_HEADER, BcgHeader, BcgKind, read_header as read_bcg_header};
pub use decompile::{
    Branch, Cfg, Decompilation, Fidelity, Literal, OPARRAY_MAGIC, OPARRAY_VERSION, Op, OpArray,
    OpArrayKind, OperandType, build_cfg, decompile as decompile_oparray, opcode_name,
    parse_oparray,
};
pub use detect::{PhpConfidence, PhpDetection, PhpKind, detect as detect_php};
pub use encoder::{
    AuthorizationToken, DecodeOutcome, EncoderDetection, EncoderFamily, EncoderHeader,
    ioncube as ioncube_encoder, sourceguardian as sourceguardian_encoder,
    zend_guard as zend_guard_encoder,
};
pub use error::{Error, Result};
pub use format_wire::format_php;
pub use pass::{PASS_INPUT_PATH_CAP, PassInput, PhpPass, PhpPassReport, decode_pass_input};
pub use peel::{
    DEFAULT_MAX_DEPTH, PeelLayer, PeelOptions, PeelReport, PeelTrace, peel as peel_eval_chain,
};
pub use phar::{
    PharArchive, PharCompression, PharEntry, extract_entry as extract_phar_entry,
    parse as parse_phar,
};
pub use protectors::{
    ProtectorDetection, ProtectorFamily, ioncube as ioncube_protector,
    sourceguardian as sourceguardian_protector, zend_guard as zend_guard_protector,
};
pub use provenance_header::{
    php_deobfuscated_header, php_extracted_header, render_php_deobfuscated_with_header,
    render_php_extracted_with_header,
};
pub use sigs::{ScanReport, SignatureFamily, SignatureHit, scan as signature_scan};
pub use token::{Lexer, TokKind, Token, tokenize};

pub fn version() -> &'static str {
    VERSION
}
