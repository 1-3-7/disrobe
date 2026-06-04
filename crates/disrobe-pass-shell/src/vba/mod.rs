pub mod extract;
pub mod pcode;
pub mod pcode_lift;
pub mod pcode_real;
pub mod vbs;

pub use extract::{ExtractedModule, ExtractedProject, extract_from_bytes};
pub use pcode::{
    PCodeDisasm, PCodeInstruction, PCodeStreamHeader, PCodeWall, PCodeWallDetail, disassemble_pcode,
};
pub use pcode_lift::{SemanticLift, semantic_lift};
pub use pcode_real::{RealModuleDisasm, RealPCodeLine, RealPCodeReport, disassemble_pcode_real};
pub use vbs::{VbsReport, deobfuscate_vbs};
