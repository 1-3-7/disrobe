#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]
#![allow(unreachable_pub)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::unused_self)]
#![allow(clippy::use_self)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::module_inception)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::needless_lifetimes)]
#![allow(clippy::trivially_copy_pass_by_ref)]

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
pub mod pass;
pub mod reader;
pub mod recompile;
pub mod roundtrip;

pub use engine::{NativeDecompile, decompile_pyc};
pub use error::{DecompileError, Result};
#[cfg(feature = "llm-metadata")]
pub use llm::{DisasmIns as LlmDisasmIns, METADATA_CAPABILITY, PyDecompileLlmInput};
pub use pass::DecompilePass;
pub use recompile::{RoundtripOutcome, RoundtripStatus, roundtrip_native};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
