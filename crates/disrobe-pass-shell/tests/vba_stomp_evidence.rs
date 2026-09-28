#![cfg(feature = "chain")]
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

#[path = "support/vba_source_grade.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_source_grade;

#[path = "support/vba_stomp_harness.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod vba_stomp_harness;

use disrobe_pass_shell::chain_detector::recover_vba_source;
use disrobe_pass_shell::{
    ModuleStompReport, PCodeInstruction, RealModuleDisasm, RealPCodeLine, RealPCodeReport,
    StompReport, StompVerdict, analyze_stomp, disassemble_pcode_real,
};

use vba_source_grade::read_corpus;
use vba_stomp_harness::{module_text_offset, patch_module_stream, stomp_with_decoy_source};

const MODULE: &str = "Module1";
const UNKNOWN_OPCODE: u16 = 0x03FE;
const DECOY: &str = "Attribute VB_Name = \"Module1\"\nSub Harmless()\n    Debug.Print \"nothing to see\"\nEnd Sub\n";
const DECOY_MARKER: &str = "' ----- source stream, which the compiled p-code does not match -----";

fn end_sub_opcode_offset(project: &[u8]) -> usize {
    let report: RealPCodeReport = disassemble_pcode_real(project).expect("disassemble the corpus");
    let module: &RealModuleDisasm = report
        .modules
        .iter()
        .find(|m: &&RealModuleDisasm| m.name.eq_ignore_ascii_case(MODULE))
        .expect("the corpus project carries Module1 p-code");
    module
        .lines
        .iter()
        .find_map(|line: &RealPCodeLine| match line.instructions.as_slice() {
            [only] if only.mnemonic == "EndSub" => Some(only),
            _ => None,
        })
        .map(|instruction: &PCodeInstruction| instruction.offset - 2)
        .expect("Module1 p-code carries a line holding only EndSub")
}

fn stomped_with_unliftable_pcode() -> Vec<u8> {
    let project: Vec<u8> = read_corpus("vba/vbaProject.bin");
    let at: usize = end_sub_opcode_offset(&project);
    let patched: Vec<u8> = patch_module_stream(&project, MODULE, at, &UNKNOWN_OPCODE.to_le_bytes());
    let text_offset: usize = module_text_offset(&patched, MODULE);
    stomp_with_decoy_source(&patched, MODULE, text_offset, DECOY)
}

fn module_report(report: &StompReport) -> &ModuleStompReport {
    report
        .modules
        .iter()
        .find(|m: &&ModuleStompReport| m.module.eq_ignore_ascii_case(MODULE))
        .expect("Module1 is in the stomp report")
}

fn position(rendered: &str, needle: &str) -> usize {
    rendered
        .find(needle)
        .unwrap_or_else(|| panic!("the recovered source lacks {needle:?}:\n{rendered}"))
}

#[test]
fn a_stomped_module_renders_the_verdict_the_unlifted_count_the_walls_and_the_decoy() {
    let stomped: Vec<u8> = stomped_with_unliftable_pcode();
    let report: StompReport = analyze_stomp(&stomped).expect("analyze the stomped project");
    let module: &ModuleStompReport = module_report(&report);
    assert_eq!(module.verdict, StompVerdict::Stomped, "{module:?}");
    assert!(
        module.unlifted_lines >= 1,
        "the unknown opcode leaves a p-code line unlifted: {module:?}"
    );
    assert!(
        module
            .walls
            .iter()
            .any(|wall: &String| wall.contains("unterminated Procedure block")),
        "the missing EndSub leaves the procedure closed synthetically: {:?}",
        module.walls
    );
    let rendered: String = recover_vba_source(&stomped).expect("VBA source is recovered");
    let header: String = format!(
        "' ===== module: {MODULE} (Stomped: source recovered from compiled p-code; {} p-code lines not lifted) =====",
        module.unlifted_lines
    );
    let header_at: usize = position(&rendered, &header);
    let pcode_at: usize = position(&rendered, "MsgBox \"hello world\"");
    let mut last_wall_at: usize = pcode_at;
    for wall in &module.walls {
        last_wall_at = last_wall_at.max(position(&rendered, &format!("' wall: {wall}\n")));
    }
    let marker_at: usize = position(&rendered, DECOY_MARKER);
    assert!(
        header_at < pcode_at && pcode_at < last_wall_at && last_wall_at < marker_at,
        "header, p-code source, walls and decoy come in that order:\n{rendered}"
    );
    let decoy_section: Vec<&str> = rendered[marker_at..]
        .lines()
        .skip(1)
        .take_while(|line: &&str| !line.is_empty())
        .collect();
    let commented_decoy: Vec<String> = DECOY
        .lines()
        .map(|line: &str| format!("' {line}"))
        .collect();
    assert_eq!(
        decoy_section, commented_decoy,
        "the source-stream decoy follows the marker, commented line by line:\n{rendered}"
    );
    assert!(
        !rendered.lines().any(|line: &str| line == "Sub Harmless()"),
        "the decoy stays commented and never replaces the p-code source:\n{rendered}"
    );
}
