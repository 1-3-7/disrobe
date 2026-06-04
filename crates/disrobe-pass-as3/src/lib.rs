#![forbid(unsafe_code)]
#![allow(clippy::missing_const_for_fn)]

pub mod abc;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod decompile;
pub mod error;
pub mod lifter;
pub mod obf;
pub mod other_langs;
pub mod pass;
pub mod provenance_header;
pub mod swf;

pub use abc::{AbcFile, ConstantPool, DisasmLine, Multiname};
pub use decompile::{render_class_skeleton, render_program};
pub use error::{Error, Result};
pub use lifter::{Expr, LiftedBody, LocalNames, Stmt, lift_body, local_names_for, render_body};
pub use obf::{ConfidenceScore, ObfuscationReport, ObfuscationSignal, analyze};
pub use other_langs::{DetectedLanguage, DetectionReport, detect_source_or_binary};
pub use pass::{As3Pass, As3PassReport, PASS_INPUT_PATH_CAP, PassInput, decode_pass_input};
pub use provenance_header::{as3_decompiled_header, render_as3_with_header};
pub use swf::{
    DefineSprite, DoAbc, FileAttributes, Swf, SwfCompression, SwfHeader, SwfTag, SymbolClassEntry,
    TagCode,
};

pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
