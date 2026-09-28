#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

#[cfg(feature = "as3")]
mod avm2;
#[cfg(feature = "beam")]
mod beam;
#[cfg(feature = "dotnet")]
mod cil;
#[cfg(feature = "jvm")]
mod dalvik;
mod error;
#[cfg(feature = "jvm")]
mod jvm;
#[cfg(feature = "lua")]
mod lua;
#[cfg(any(feature = "dotnet", feature = "jvm", feature = "wasm"))]
#[allow(clippy::redundant_pub_crate)]
mod operand;
mod pcode;
#[cfg(feature = "python")]
mod python;
#[cfg(feature = "wasm")]
mod wasm;
#[cfg(feature = "ruby")]
mod yarv;

#[cfg(feature = "as3")]
pub use avm2::{function_address as avm2_function_address, lift_abc, lift_swf_abc};
#[cfg(feature = "beam")]
pub use beam::{function_address as beam_function_address, lift_beam_module};
#[cfg(feature = "dotnet")]
pub use cil::{function_address as cil_function_address, lift_pe as lift_dotnet_pe};
#[cfg(feature = "jvm")]
pub use dalvik::{function_address as dalvik_function_address, lift_dex};
pub use disrobe_sleigh::coverage::{DECODE_STATUSES, DecodeCoverage, StatusCounts, status_name};
pub use disrobe_sleigh::pcode::DecodeStatus;
pub use error::{LiftError, ProvenanceLiftError, ProvenanceResult, Result};
#[cfg(feature = "jvm")]
pub use jvm::{function_address as jvm_function_address, lift_classfile};
#[cfg(feature = "lua")]
pub use lua::{function_address as lua_function_address, lift_lua_chunk};
pub use pcode::{
    ArchLift, LiftGap, LiftGaps, PcodeArch, PcodeLiftConfig, RegisterCell, block_gaps,
    lower_aarch64, lower_arch, lower_arm32, lower_mips32, lower_pcode_block,
    lower_pcode_block_with_provenance, lower_x86_64,
};
#[cfg(feature = "python")]
pub use python::{function_address as python_function_address, lift_pyc, lift_python};
#[cfg(feature = "wasm")]
pub use wasm::{function_address as wasm_function_address, lift_wasm_module};
#[cfg(feature = "ruby")]
pub use yarv::{function_address as yarv_function_address, lift_ruby_iseq};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(any(
    feature = "as3",
    feature = "dotnet",
    feature = "jvm",
    feature = "lua",
    feature = "python",
    feature = "ruby",
    feature = "wasm"
))]
pub(crate) fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).map_or(u32::MAX, |converted: u32| converted)
}

#[cfg(feature = "lua")]
pub(crate) fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).map_or(u64::MAX, |converted: u64| converted)
}
