#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
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
pub mod pdf;
pub mod policy;
pub mod powershell;
pub mod provenance_header;
pub mod vba;
pub mod xlm;

pub use bash::{
    BashToken, BashTokenKind, BashfuscatorLevel, BashfuscatorReport, IndirectionReport,
    NodeBashObfuscateReport, is_node_bash_obfuscate, peel_indirection,
    peel_indirection_with_policy, reverse_bashfuscator, reverse_bashfuscator_auto,
    reverse_node_bash_obfuscate, tokenize_bash,
};
pub use batch::{
    BasicBlock, BatchCfg, BatchDeobReport, BatchIndicator, BatchIocKind, BatchIocReport,
    BatchReport, CfgEdge, DecryptedStage, EdgeKind, EmbeddedPayload, EmuResult, EmuState,
    ExpandStats, ForKind, ForLoop, IfOutcome, NormalizeReport, PayloadKind, RecoveryState,
    StageMethod, StageOutcome, deobfuscate_batch, emulate, eval_if, expand_line, expand_repeated,
    extract_embedded, normalize as normalize_batch, parse_for_f_string, parse_for_l,
    recover_stages, resolve_cfg, reverse_batch, surface_iocs, unroll,
};
pub use detect::{Detection, Dialect, Family, detect};
pub use error::{Error, Result};
pub use format_wire::format_identity;
pub use pdf::{
    ActionFinding, EmbeddedFileFinding, EncryptionInfo, JsFinding, NameObfuscation, PdfReport,
    analyze_pdf, is_pdf_document, render_report,
};
pub use policy::{DynamicPolicy, STATIC_EVAL_DEPTH_CAP};
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
    ExtractedModule, ExtractedProject, ModuleStompReport, PCodeDisasm, PCodeInstruction,
    RealModuleDisasm, RealPCodeLine, RealPCodeReport, SemanticLift, StompReport, StompVerdict,
    VbsReport, analyze_stomp, analyze_stomp_parts, deobfuscate_vbs, deobfuscate_vbs_with_policy,
    disassemble_pcode, disassemble_pcode_real, extract_from_bytes, semantic_lift,
    vba_project_bin_from_bytes,
};
pub use vba::{PCodeStreamHeader, PCodeWall, PCodeWallDetail};
pub use xlm::{
    XlmCell, XlmContainerKind, XlmDefinedName, XlmEntryPoint, XlmRecovery, XlmSheet,
    is_xlm_macro_document, recover_xlm, render_source as render_xlm_source,
};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
