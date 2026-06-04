#![forbid(unsafe_code)]

pub mod aot;
pub mod backends;
pub mod cfg;
#[cfg(feature = "chain")]
pub mod chain_detector;
pub mod cil;
pub mod cil_emulator;
pub mod decompile;
pub mod error;
pub mod format_wire;
#[cfg(feature = "llm-metadata")]
pub mod llm;
pub mod metadata;
pub mod model;
pub mod pass;
pub mod pe;
pub mod peel;
pub mod protectors;
pub mod provenance_header;
pub mod r2r;
pub mod signature;
pub mod state_machine;
pub mod state_machine_reverse;
pub mod structure_emit;
pub mod structurize;
pub mod tables;

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
pub use pass::{DotnetPass, PASS_INPUT_PE_CAP, PassSummary, analyze};
pub use pe::{
    ClrHeader, DataDirectory, PeBitness, PeImage, SectionHeader, parse, parse_clr_header,
};
pub use peel::static_decrypt::{
    DecodedValue, RecoveredConstant, StaticDecryptReport, recover_static_decoders,
};
pub use peel::{
    ConfuserExRecovery, ManifestResourceClassification, NameClassification, PeelReport,
    PeelStrategy, classify_names, peel_agile_net, peel_armdot, peel_babel_net, peel_by,
    peel_confuserex_resources, peel_crypto_obfuscator, peel_deepsea, peel_dotfuscator,
    peel_dotnet_reactor, peel_eazfuscator, peel_goliath, peel_ilprotector, peel_maxtocode,
    peel_skater, peel_smartassembly, peel_spices_net, peel_themida_dotnet,
};
pub use protectors::{
    DetectionReport, ExecuteOptions, ExecutionOutcome, GreyZone, Handling, Protector, detect_all,
    plan_execution,
};
pub use provenance_header::{
    cil_disasm_header, csharp_decompiled_header, fsharp_decompiled_header, render_cil_with_header,
    render_csharp_with_header, render_fsharp_with_header, render_vbnet_with_header,
    vbnet_decompiled_header,
};
pub use r2r::{R2rHeader, R2rReport};
pub use signature::{MethodSig, TypeSig, TypeSigOrVoid, parse_field_sig, parse_method_sig};
pub use structurize::{
    CallInfo, HexNamer, MethodNamer, StructuredMethod, TargetLang, TokenNamer, decompile_method,
    decompile_method_in,
};
pub use tables::{Tables, parse_tables};

#[must_use]
pub const fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
