#![forbid(unsafe_code)]
#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::option_if_let_else,
    clippy::single_match_else,
    clippy::unreadable_literal,
    clippy::match_same_arms,
    clippy::map_unwrap_or,
    clippy::missing_const_for_fn,
    clippy::similar_names,
    clippy::struct_field_names
)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub(crate) mod debug;
pub mod error;
pub mod lang;
pub mod pass;
pub mod provenance_header;

pub use error::{Error, Result};
pub use lang::hashlink::{
    HlCode, HlConstant, HlEnumData, HlError, HlFunData, HlFunction, HlNative, HlObjData,
    HlObjField, HlObjProto, HlOpcode, HlSummary, HlType, read_code,
};
pub use lang::haxe::{
    HaxeCrossRoute, HaxeCrossTarget, HaxeFingerprint, HaxeTarget, route_cross_target,
};
pub use lang::perl::{PerlOp, PerlOpTree, PerlSub};
pub use lang::perl_bytecode::{ByteOrder, BytecodeHeader, is_bytecode, read_bytecode};
pub use lang::perl_decompile::{DecompileWalker, PerlSource, PerlStatement, PerlSubSource};
pub use lang::r_rds::{RdsClosure, RdsEncoding, RdsEnvironment, RdsFormal, RdsHeader, RdsObject};
pub use lang::rcpp::{EmbeddedNativeImage, NativeImageFormat, RcppFingerprint};
pub use lang::tcl::{
    StarkitContainer, StarkitEntry, StarkitFormat, TclExtractionCompleteness, TclObfuscation,
    TclObfuscationHit, TclObfuscationKind,
};
pub use lang::winscript::{
    RecoveredLayer, WallReason, WinScriptLang, WinScriptRecovery, WinTechnique, WinWall,
};
pub use lang::{ScriptArtifact, ScriptLang, analyze, analyze_rcpp, classify};
pub use pass::{ScriptLangPass, ScriptLangReport};
pub use provenance_header::{language_for, render_with_header, scriptlang_header};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
