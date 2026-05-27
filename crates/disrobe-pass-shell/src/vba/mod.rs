pub mod extract;
pub mod pcode;
pub mod vbs;

pub use extract::{ExtractedModule, ExtractedProject, extract_from_bytes};
pub use pcode::{PCodeDisasm, PCodeInstruction, PCodeOpcode, disassemble_pcode};
pub use vbs::{VbsReport, deobfuscate_vbs};
