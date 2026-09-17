#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
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
    clippy::use_self,
    clippy::redundant_pub_crate
)]

pub mod body_lift;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod chunks;
pub mod core_erlang;
pub mod dbgi;
pub(crate) mod debug;
pub mod disasm;
pub mod docs;
pub mod elixir;
pub mod elixir_quoted;
pub mod erlang_abstract;
pub mod error;
pub mod etf;
pub mod ez;
pub mod file;
pub mod opcodes;
pub mod provenance_header;
pub mod reader;
pub mod surface;
pub mod symbolic;

pub use chunks::{AtomTable, Chunks, CodeChunk};
pub use core_erlang::{CoreFunction, CoreModule, lift};
pub use dbgi::{DebugInfo, parse as parse_dbgi};
pub use disasm::{Disassembly, Instruction, Operand, disassemble};
pub use docs::{ModuleDocs, parse as parse_docs};
pub use elixir::{
    ElixirDefinition, ElixirRecovery, recover as recover_elixir,
    recover_with_docs as recover_elixir_with_docs,
};
pub use error::{Error, Result};
pub use etf::{Term, decode_etf};
pub use ez::{EzArchive, EzEntry, EzQuota};
pub use file::{BeamFile, RawBeam, RawChunk};
pub use provenance_header::{
    core_erlang_lifted_header, elixir_decompiled_header, erlang_decompiled_header,
    render_core_erlang_with_header, render_elixir_with_header, render_erlang_with_header,
};
pub use surface::{ErlangSurface, RecoverySource, recover as recover_erlang};
pub use symbolic::{
    SymbolicFunction, SymbolicInstruction, SymbolicModule, render_symbolic, symbolic_disassemble,
};

#[must_use]
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
