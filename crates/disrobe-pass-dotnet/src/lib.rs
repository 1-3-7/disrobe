#![forbid(unsafe_code)]
#![deny(unreachable_pub)]
#![allow(clippy::redundant_pub_crate)]
pub mod aot;
pub mod backends;
pub mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod cil;
pub mod cil_emulator;
pub mod closure_reverse;
pub(crate) mod debug;
pub mod decompile;
pub mod error;
pub mod format_wire;
pub mod iterator_reverse;
pub mod lambda_reverse;
pub(crate) mod list_switch_reverse;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod metadata;
pub mod model;
pub mod names;
pub mod pass;
pub mod pe;
pub mod peel;
pub(crate) mod positional_switch_reverse;
pub(crate) mod property_switch_reverse;
pub mod protectors;
pub mod provenance_header;
pub mod r2r;
pub(crate) mod range_switch_reverse;
pub mod records;
pub mod signature;
pub mod state_machine;
pub mod state_machine_cfg;
pub mod state_machine_reverse;
pub mod structure_emit;
pub mod structurize;
pub mod switch_expr_reverse;
pub mod tables;
pub(crate) mod tuple_switch_reverse;
pub(crate) mod with_reverse;

pub use aot::{AotReport, AotRuntime};
pub use backends::{Backend, BackendInvocation};
pub use cil::{
    ExceptionClause, ExceptionClauseKind, FlowControl, Instruction, MethodBody, ONE_BYTE_OPCODES,
    OpcodeDef, OperandKind, OperandValue, TWO_BYTE_OPCODES, coverage_percent, disassemble,
    ecma_335_spec_total, lookup, parse_method_body, total_opcode_count,
};
pub use decompile::{
    CSharpPseudo, DecompiledAssembly, FlowSummary, decompile_assembly, decompile_assembly_in,
    emit_csharp,
};
pub use error::{Error, Result};
pub use format_wire::format_csharp;
#[cfg(feature = "llm-metadata")]
pub use llm::{DotnetInstr, DotnetLlmInput, METADATA_CAPABILITY as DOTNET_METADATA_CAPABILITY};
pub use metadata::{
    MetadataRoot, RuntimeLabel, StreamHeader, TableStream, decompress_uint, parse_metadata_root,
    parse_table_stream, read_strings_heap, read_us_heap_strings,
};
pub use model::{AssemblyModel, FieldModel, MethodModel, ParamModel, Resolver, TypeModel};
pub use names::NameTable;
pub use pass::{EazVmSummary, KoiVmSummary, PassSummary, analyze};
pub use pe::{
    ClrHeader, DataDirectory, PeBitness, PeImage, SectionHeader, parse, parse_clr_header,
};
pub use peel::deflatten::{
    DeflattenSummary, MethodDeflatten, MethodRecovery, analyze as analyze_cff, deflatten_body,
    is_flattened as is_cff_flattened,
};
pub use peel::koivm::{
    KoiVmDetection, KoiVmError, KoiVmMethod, KoiVmRecovery, detect as detect_koivm,
    devirtualize as devirtualize_koivm,
};
pub use peel::static_decrypt::{
    DecodedValue, RecoveredConstant, StaticDecryptReport, recover_static_decoders,
};
pub use peel::{
    ConfuserExRecovery, ManifestResourceClassification, NameClassification, PeelReport,
    PeelStrategy, RecoveredMethod, classify_names, peel_agile_net, peel_armdot, peel_babel_net,
    peel_by, peel_confuserex_resources, peel_crypto_obfuscator, peel_deepsea, peel_dotfuscator,
    peel_dotnet_reactor, peel_eazfuscator, peel_goliath, peel_ilprotector, peel_maxtocode,
    peel_skater, peel_smartassembly, peel_spices_net, peel_themida_dotnet,
};
pub use protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, GreyZone, Handling, Protector, detect_all,
    is_dotnet_assembly, plan_execution,
};
pub use provenance_header::{
    cil_disasm_header, csharp_decompiled_header, fsharp_decompiled_header, render_cil_with_header,
    render_csharp_with_header, render_fsharp_with_header, render_vbnet_with_header,
    vbnet_decompiled_header,
};
pub use r2r::{R2rHeader, R2rReport};
pub use signature::{
    MethodSig, TypeSig, TypeSigOrVoid, parse_field_sig, parse_local_sig, parse_method_sig,
};
pub use structurize::{
    CallInfo, HexNamer, MethodNamer, StructuredMethod, TargetLang, TokenNamer, decompile_method,
    decompile_method_in, decompile_method_named, decompile_move_next_named,
};
pub use tables::{Tables, parse_tables};

#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
