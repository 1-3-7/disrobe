#![forbid(unsafe_code)]
#![deny(unreachable_pub)]

mod avm2;
mod beam;
mod cil;
mod dalvik;
mod error;
mod jvm;
mod lua;
#[allow(clippy::redundant_pub_crate)]
mod operand;
mod pcode;
mod python;
#[cfg(feature = "wasm")]
mod wasm;
mod yarv;

pub use avm2::{function_address as avm2_function_address, lift_abc, lift_swf_abc};
pub use beam::{function_address as beam_function_address, lift_beam_module};
pub use cil::{function_address as cil_function_address, lift_pe as lift_dotnet_pe};
pub use dalvik::{function_address as dalvik_function_address, lift_dex};
pub use error::{LiftError, Result};
pub use jvm::{function_address as jvm_function_address, lift_classfile};
pub use lua::{function_address as lua_function_address, lift_lua_chunk};
pub use pcode::{PcodeLiftConfig, RegisterCell, lower_aarch64, lower_pcode_block, lower_x86_64};
pub use python::{function_address as python_function_address, lift_pyc, lift_python};
#[cfg(feature = "wasm")]
pub use wasm::{function_address as wasm_function_address, lift_wasm_module};
pub use yarv::{function_address as yarv_function_address, lift_ruby_iseq};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub(crate) fn usize_to_u32_saturating(value: usize) -> u32 {
    u32::try_from(value).map_or(u32::MAX, |converted: u32| converted)
}

pub(crate) fn usize_to_u64_saturating(value: usize) -> u64 {
    u64::try_from(value).map_or(u64::MAX, |converted: u64| converted)
}
