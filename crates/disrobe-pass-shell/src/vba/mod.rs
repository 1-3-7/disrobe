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
pub use pcode_real::{RealModuleDisasm, RealPCodeLine, RealPCodeReport, disassemble_pcode_real};
pub use stomp::{ModuleStompReport, StompReport, StompVerdict, analyze_stomp, analyze_stomp_parts};
pub use vbs::{VbsReport, deobfuscate_vbs, deobfuscate_vbs_with_policy};
