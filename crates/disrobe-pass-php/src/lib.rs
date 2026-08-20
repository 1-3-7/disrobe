#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::missing_const_for_fn)]
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub mod bcompiler;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub(crate) mod debug;
#[cfg(feature = "chain")]
pub use chain_detector::{PhpCatalogEntry, PhpDetectorImpl};
pub mod decode_loop;
pub mod decompile;
pub mod deflatten;
pub mod detect;
pub mod encoder;
pub mod error;
pub mod format_wire;
pub mod key_extractor;
mod literal;
pub mod loader;
pub mod peel;
pub mod phar;
pub mod pipeline;
pub mod protectors;
pub mod provenance_header;
pub mod restructure;
pub mod sigs;
pub mod token;

pub use bcompiler::{BCG_MIN_HEADER, BcgHeader, BcgKind, read_header as read_bcg_header};
pub use decompile::{
    Branch, Cfg, Decompilation, Fidelity, Literal, OPARRAY_MAGIC, OPARRAY_MAX_VERSION,
    OPARRAY_MIN_VERSION, OPARRAY_VERSION, Op, OpArray, OpArrayKind, OperandType, TryCatch,
    UnrecoveredOp, build_cfg, decompile as decompile_oparray, opcode_name, parse_oparray,
};
pub use deflatten::{DeflattenReport, deflatten};
pub use detect::{PhpConfidence, PhpDetection, PhpKind, detect as detect_php};
pub use encoder::{
    AuthorizationToken, ContainerSurface, DecodeOutcome, EncoderDetection, EncoderFamily,
    EncoderHeader, StaticLayer, build_ioncube_container, build_sourceguardian_container,
    build_zend_guard_obfuscated, ioncube as ioncube_encoder, reverse_ioncube_container,
    reverse_sourceguardian_container, sourceguardian as sourceguardian_encoder, surface_zend_guard,
    synthetic_transport_surface_ioncube, synthetic_transport_surface_sourceguardian,
    zend_guard as zend_guard_encoder,
};
pub use error::{Error, Result};
pub use format_wire::format_php;
pub use key_extractor::{
    AesOutcome, KeyProvenance, KeyScan, aes_cbc_decrypt, scan as scan_key, xor_decrypt,
};
pub use loader::{
    DEFAULT_LOADER_DEPTH, LoaderReport, LoaderSink, peel_loader as peel_modern_loader,
};
pub use peel::{
    DEFAULT_MAX_DEPTH, PeelLayer, PeelOptions, PeelReport, PeelTrace, peel as peel_eval_chain,
};
pub use phar::{
    PHAR_DECOMPRESS_CAP, PHAR_MAX_EXPANSION_RATIO, PHAR_MIN_DECOMPRESS_ALLOWANCE, PharArchive,
    PharCompression, PharEntry, decompress_ceiling as phar_decompress_ceiling,
    extract_entry as extract_phar_entry, parse as parse_phar,
};
pub use pipeline::{RecoveryReport, RecoveryStage, recover as recover_php};
pub use protectors::{
    ProtectorDetection, ProtectorFamily, ioncube as ioncube_protector,
    sourceguardian as sourceguardian_protector, zend_guard as zend_guard_protector,
};
pub use provenance_header::{
    php_deobfuscated_header, php_extracted_header, render_php_deobfuscated_with_header,
    render_php_extracted_with_header,
};
pub use restructure::{RestructureReport, restructure};
pub use sigs::{ScanReport, SignatureFamily, SignatureHit, scan as signature_scan};
pub use token::{Lexer, TokKind, Token, tokenize};

#[must_use]
pub fn version() -> &'static str {
    VERSION
}
