#![forbid(unsafe_code)]
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::cast_lossless,
    clippy::needless_type_cast,
    clippy::trivially_copy_pass_by_ref,
    clippy::missing_const_for_fn,
    clippy::derive_partial_eq_without_eq,
    clippy::option_if_let_else,
    clippy::map_unwrap_or,
    clippy::format_push_string,
    clippy::similar_names,
    clippy::single_char_add_str,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::format_collect,
    clippy::match_same_arms,
    clippy::unnecessary_wraps,
    clippy::or_fun_call,
    clippy::too_many_lines,
    clippy::use_self
)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod chunks;
pub mod core_erlang;
pub mod dbgi;
pub mod disasm;
pub mod elixir;
pub mod error;
pub mod etf;
pub mod ez;
pub mod file;
pub mod opcodes;
pub mod provenance_header;
pub mod reader;
pub mod surface;

pub use chunks::{AtomTable, Chunks, CodeChunk};
pub use core_erlang::{CoreFunction, CoreModule, lift};
pub use dbgi::{DebugInfo, parse as parse_dbgi};
pub use disasm::{Disassembly, Instruction, Operand, disassemble};
pub use elixir::{ElixirDefinition, ElixirRecovery, recover as recover_elixir};
pub use error::{Error, Result};
pub use etf::{Term, decode_etf};
pub use ez::{EzArchive, EzEntry};
pub use file::{BeamFile, RawBeam, RawChunk};
pub use provenance_header::{
    core_erlang_lifted_header, elixir_decompiled_header, erlang_decompiled_header,
    render_core_erlang_with_header, render_elixir_with_header, render_erlang_with_header,
};
pub use surface::{ErlangSurface, RecoverySource, recover as recover_erlang};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
