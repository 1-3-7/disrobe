#![forbid(unsafe_code)]

#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod detect;
pub mod error;
pub mod format_wire;
pub mod jruby;
pub mod mri;
pub mod mruby;
pub mod pass;
pub mod provenance_header;
pub mod truffleruby;
pub mod wrappers;
pub mod yarv;

pub use detect::Flavor;
pub use error::RubyError;
pub use format_wire::format_ruby;
pub use jruby::JrubyDelegation;
pub use mri::{DefinitionRecord, MriAst, Token, TokenKind};
pub use mruby::MrubyAnalysis;
pub use mruby::decompile::MrubyDecompiled;
pub use mruby::disasm::MrubyInstruction;
pub use mruby::irep::{IrepRecord, IrepTree, PoolEntry, PoolKind};
pub use mruby::ops::{MrubyOp, OperandFormat};
pub use mruby::reader::{RiteBinary, RiteHeader, RiteSection};
pub use pass::{
    PASS_INPUT_PATH_CAP, PassInput, RubyAnalysis, RubyPass, analyze_bytes, decode_pass_input,
};
pub use provenance_header::{
    mruby_decompiled_header, render_ruby_with_header, render_yarv_with_header,
    ruby_decompiled_header, yarv_disasm_header,
};
pub use truffleruby::TruffleRubyAot;
pub use wrappers::{WrapperExtract, WrapperKind};
pub use yarv::YarvAnalysis;
pub use yarv::decompile::{Fidelity, YarvDecompiled};
pub use yarv::disasm::{YarvDisasm, YarvInstruction, disassemble_body, render_image_disasm};
pub use yarv::ibf::{
    CatchType, IbfImage, IbfObject, IbfObjectKind, YarvCatchEntry, YarvIbfInstruction,
    YarvIseqBody, YarvOperand,
};
pub use yarv::opcodes::{OpcodeSpec, TsKind, YarvVersion, opcode_count, opcode_spec};
pub use yarv::reader::YarvBinaryHeader;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[must_use]
pub const fn version() -> &'static str {
    VERSION
}
