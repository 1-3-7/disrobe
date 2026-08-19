pub mod extract;
pub mod pcode;
pub mod pcode_lift;
pub mod pcode_real;
pub mod stomp;
pub mod vbs;

pub use extract::{
    ExtractedModule, ExtractedProject, extract_from_bytes, vba_project_bin_from_bytes,
};
pub use pcode::{
    PCodeDisasm, PCodeInstruction, PCodeStreamHeader, PCodeWall, PCodeWallDetail, disassemble_pcode,
};
pub use pcode_lift::{SemanticLift, semantic_lift};
pub use pcode_real::{
    RealModuleDisasm, RealPCodeLine, RealPCodeReport, UNKNOWN_OPCODE_MNEMONIC_PREFIX,
    disassemble_pcode_real, opcode_table, opcode_table_slots,
};
pub use stomp::{ModuleStompReport, StompReport, StompVerdict, analyze_stomp, analyze_stomp_parts};
pub use vbs::{VbsReport, deobfuscate_vbs, deobfuscate_vbs_with_policy};
