#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::use_self)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::trivially_copy_pass_by_ref)]
pub mod alt_lift;
pub mod ast;
pub mod bytecode;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod codegen;
pub mod emit;
pub mod engine;
pub mod error;
pub mod frame_tree;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod reader;
pub mod recompile;
pub mod roundtrip;
pub mod selfcheck;

pub use engine::{
    NativeDecompile, decompile_micropython, decompile_pyc, decompile_pypy, pypy_variant_label,
};
pub use error::{DecompileError, Result};
#[cfg(feature = "llm-metadata")]
pub use llm::{DisasmIns as LlmDisasmIns, METADATA_CAPABILITY, PyDecompileLlmInput};
pub use recompile::{RoundtripOutcome, RoundtripStatus, roundtrip_native, roundtrip_skipped};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
