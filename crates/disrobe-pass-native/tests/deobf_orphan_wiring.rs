//! Reachability gate for the three native anti-obfuscation defeats that the section audit
//! found published but unwired: register copy-propagation + dead-store elimination, MBA
//! simplification of opaque-predicate expressions, and correlated-branch dead-path proof.
//! Each is now driven by `analyze_deobf_report`, the exact entry the production `NativePass`
//! and the chain-driven `deobf.json` child both call, so a populated field here means the
//! capability reaches the user surface. Correctness of each defeat is graded by its own
//! crate unit tests against an independent oracle; this test only proves the wiring.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items
)]

use disrobe_pass_native::{DeobfReport, FoldVerdict, OpaqueResult, analyze_deobf_report};
use iced_x86::code_asm::{CodeAssembler, CodeLabel, al, eax, ebx, ecx, edi, edx, esi};
use object::write::{
    Object as WriteObject, StandardSection, Symbol as WriteSymbol, SymbolFlags as WriteSymbolFlags,
    SymbolKind as WriteSymbolKind, SymbolScope, SymbolSection,
};
use object::{Architecture, BinaryFormat, Endianness};

const TEXT_BASE: u64 = 0;

fn copy_shuffle_block(asm: &mut CodeAssembler) {
    asm.mov(ecx, esi).unwrap();
    asm.mov(ebx, ecx).unwrap();
    asm.mov(edi, ebx).unwrap();
    asm.mov(eax, edi).unwrap();
    asm.add(eax, edx).unwrap();
    asm.ret().unwrap();
}

fn xor_self_opaque_block(asm: &mut CodeAssembler) {
    let mut keep: CodeLabel = asm.create_label();
    asm.xor(al, al).unwrap();
    asm.test(al, al).unwrap();
    asm.jne(keep).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.ret().unwrap();
    asm.set_label(&mut keep).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.ret().unwrap();
}

fn correlated_branch_block(asm: &mut CodeAssembler) {
    let mut after: CodeLabel = asm.create_label();
    let mut dead: CodeLabel = asm.create_label();
    let mut end: CodeLabel = asm.create_label();
    asm.cmp(eax, 5i32).unwrap();
    asm.jg(after).unwrap();
    asm.cmp(eax, 10i32).unwrap();
    asm.jg(dead).unwrap();
    asm.mov(ecx, 1i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut dead).unwrap();
    asm.mov(ecx, 99i32).unwrap();
    asm.jmp(end).unwrap();
    asm.set_label(&mut after).unwrap();
    asm.mov(ecx, 2i32).unwrap();
    asm.set_label(&mut end).unwrap();
    asm.ret().unwrap();
}

fn build_text() -> Vec<u8> {
    let mut asm: CodeAssembler = CodeAssembler::new(64).expect("assembler");
    correlated_branch_block(&mut asm);
    copy_shuffle_block(&mut asm);
    xor_self_opaque_block(&mut asm);
    asm.assemble(TEXT_BASE).expect("assemble text")
}

fn build_elf(text: &[u8]) -> Vec<u8> {
    let mut obj: WriteObject<'_> =
        WriteObject::new(BinaryFormat::Elf, Architecture::X86_64, Endianness::Little);
    let section: object::write::SectionId = obj.section_id(StandardSection::Text);
    let _ = obj.append_section_data(section, text, 16);
    let sym: WriteSymbol = WriteSymbol {
        name: b"_start".to_vec(),
        value: 0,
        size: text.len() as u64,
        kind: WriteSymbolKind::Text,
        scope: SymbolScope::Dynamic,
        weak: false,
        section: SymbolSection::Section(section),
        flags: WriteSymbolFlags::None,
    };
    let _ = obj.add_symbol(sym);
    obj.write().expect("elf write")
}

#[test]
fn analyze_deobf_report_surfaces_copyprop_pathsense_and_mba() {
    let text: Vec<u8> = build_text();
    let elf: Vec<u8> = build_elf(&text);

    let report: DeobfReport =
        analyze_deobf_report(&elf).expect("deobf report on the obfuscated .text");

    assert!(
        !report.copyprop_report.is_empty(),
        "the eax<-edi<-ebx<-ecx<-esi shuffle must surface a copy-propagation finding: {:?}",
        report.copyprop_report
    );
    assert!(
        report.copyprop_report.iter().any(|b| b.report.changed
            && (b.report.eliminated_copies > 0
                || b.report.propagated_reads > 0
                || b.report.eliminated_dead_stores > 0)),
        "at least one copy-prop block must report a real reduction: {:?}",
        report.copyprop_report
    );

    let pathsense = report
        .pathsense_report
        .as_ref()
        .expect("the correlated signed-branch block must produce a path-sense report");
    assert!(
        !pathsense.dead_edges.is_empty(),
        "eax>10 given eax<=5 is unsatisfiable; that taken-edge must be proven dead: {pathsense:?}"
    );
    assert!(
        pathsense
            .dead_edges
            .iter()
            .any(|e| e.edge_taken && e.reason.contains("correlated")),
        "the dead edge must be the correlated taken-edge: {:?}",
        pathsense.dead_edges
    );

    assert!(
        !report.mba_simplifications.is_empty(),
        "the xor-self opaque predicate must surface an MBA simplification: {:?}",
        report.mba_simplifications
    );
    assert!(
        report.mba_simplifications.iter().any(|m| {
            m.simplification.proven
                && m.simplification.changed
                && matches!(
                    m.result,
                    OpaqueResult::AlwaysTaken | OpaqueResult::AlwaysNotTaken
                )
        }),
        "the MBA summary must carry a proven simplification tied to a folded opaque branch: {:?}",
        report.mba_simplifications
    );

    assert!(
        !report.branch_folds.is_empty(),
        "the xor-self opaque branch must surface a branch-fold finding: {:?}",
        report.branch_folds
    );
    assert!(
        report
            .branch_folds
            .iter()
            .any(|f| matches!(f.verdict, FoldVerdict::AlwaysNotTaken)),
        "(x ^ x) is always 0, so the jne on it must fold to always-not-taken: {:?}",
        report.branch_folds
    );

    let listing: &str = report
        .cleaned_listing
        .as_deref()
        .expect("the cleaned listing must be produced");
    assert!(
        listing.contains("copy-propagation")
            && listing.contains("MBA-simplified")
            && listing.contains("correlated-branch dead paths")
            && listing.contains("folded constant / opaque-predicate branches"),
        "all defeats must be annotated into the readable listing:\n{listing}"
    );
}
