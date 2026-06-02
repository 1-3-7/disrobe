#![forbid(unsafe_code)]
#![allow(
    clippy::redundant_pub_crate,
    clippy::too_many_lines,
    clippy::naive_bytecount,
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::option_if_let_else,
    clippy::single_match_else,
    clippy::single_char_pattern,
    clippy::unreadable_literal,
    clippy::no_effect_underscore_binding,
    clippy::needless_type_cast,
    clippy::match_same_arms,
    clippy::map_unwrap_or,
    clippy::use_self,
    clippy::only_used_in_recursion,
    clippy::manual_saturating_arithmetic,
    clippy::missing_const_for_fn,
    clippy::format_push_string,
    clippy::similar_names,
    clippy::unnecessary_wraps,
    clippy::or_fun_call,
    clippy::struct_field_names
)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod cursor;
pub mod decompile;
pub mod error;
pub mod format_wire;
pub mod luvit;
pub mod obfuscator;
pub mod pass;
pub mod provenance_header;
pub mod reader;

pub use decompile::{DecompiledChunk, Fidelity};
pub use error::{Error, Result};
pub use format_wire::format_lua;
pub use luvit::{LuvitBundle, LuvitFormat};
pub use obfuscator::{
    DeobfOptions, LuaObfuscatorKind, ObfuscatorDetection, PeelResult, aztup_brew, boronide,
    darksec, ironbrew2, luaobfuscator_com, moonsec_v1, moonsec_v2, moonsec_v3, prometheus, psu,
    wearedevs,
};
pub use provenance_header::{
    lua_decompiled_header, lua_deobfuscated_header, render_lua_decompiled_with_header,
    render_lua_deobfuscated_with_header,
};
pub use reader::{
    DetectedFormat, LUA_SIGNATURE, LUAC_DATA_TAIL, LUAJIT_SIGNATURE, LuaChunk, LuaConstant,
    LuaDialect, LuaLocal, LuaProto, LuaUpvalueName, detect, read_auto,
};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
