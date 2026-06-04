#![forbid(unsafe_code)]
#![allow(clippy::redundant_pub_crate)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_lossless)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::if_not_else)]
#![allow(clippy::similar_names)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::needless_continue)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::needless_raw_string_hashes)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::map_unwrap_or)]
#![allow(clippy::redundant_closure)]
#![allow(clippy::manual_is_multiple_of)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::assigning_clones)]
#![allow(clippy::redundant_clone)]
#![allow(clippy::enum_variant_names)]
#![allow(clippy::use_self)]
#![allow(clippy::format_push_string)]

pub(crate) mod regex_util;

pub mod bash;
pub mod batch;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod detect;
pub mod error;
pub mod format_wire;
pub mod pass;
pub mod powershell;
pub mod provenance_header;
pub mod vba;

pub use bash::{
    BashToken, BashTokenKind, BashfuscatorLevel, BashfuscatorReport, IndirectionReport,
    peel_indirection, reverse_bashfuscator, tokenize_bash,
};
pub use batch::{BasicBlock, BatchCfg, BatchReport, CfgEdge, EdgeKind, resolve_cfg, reverse_batch};
pub use detect::{Detection, Dialect, Family, detect};
pub use error::{Error, Result};
pub use format_wire::format_identity;
pub use powershell::{
    Ast, AstNode, InvokeObfuscationLevel, Lexer, ObfTechnique, ObfuscatorDetection, PsObfuscator,
    ReverseReport, Token, TokenKind, obfuscator_detect, parse_ast, parse_bible, reverse_ast,
    reverse_chameleon, reverse_compress, reverse_encoding, reverse_invoke_stealth,
    reverse_isesteroids, reverse_launcher, reverse_powerhell, reverse_psobf, reverse_string,
    reverse_token,
};
pub use provenance_header::{
    bash_deobfuscated_header, batch_deobfuscated_header, powershell_deobfuscated_header,
    render_bash_with_header, render_batch_with_header, render_powershell_with_header,
    render_vba_with_header, vba_deobfuscated_header,
};
pub use vba::extract::ContainerKind;
pub use vba::{
    ExtractedModule, ExtractedProject, PCodeDisasm, PCodeInstruction, RealModuleDisasm,
    RealPCodeLine, RealPCodeReport, SemanticLift, VbsReport, deobfuscate_vbs, disassemble_pcode,
    disassemble_pcode_real, extract_from_bytes, semantic_lift,
};
pub use vba::{PCodeStreamHeader, PCodeWall, PCodeWallDetail};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
