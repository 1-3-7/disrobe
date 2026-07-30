#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{TaintConfig, TaintReport, UnresolvedCall, UnresolvedCallKind, analyze};

const X86_ENTRY: u64 = 0x1390;
const X86_FGETS_STUB: u64 = 0x13d0;
const X86_SYSTEM_STUB: u64 = 0x13e0;

const AARCH64_ENTRY: u64 = 0x1039c;
const AARCH64_FGETS_STUB: u64 = 0x103f0;
const AARCH64_SYSTEM_STUB: u64 = 0x10400;

fn instr(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    let text: Vec<String> = operands.iter().map(|o: &&str| (*o).to_owned()).collect();
    let reads_memory: bool = text.iter().any(|o: &String| o.contains('['));
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: text,
        reads_memory,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn call(address: u64, mnemonic: &str, target: u64) -> NirInstr {
    instr(
        address,
        NirOp::Call {
            target: Some(target),
        },
        mnemonic,
        &[],
    )
}

fn import(address: u64, name: &str) -> NirSymbol {
    NirSymbol {
        address,
        name: name.to_owned(),
        kind: SymbolKind::Import,
    }
}

fn module(function: NirFunction, symbols: Vec<NirSymbol>) -> NirModule {
    NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols,
    }
}

fn config() -> TaintConfig {
    TaintConfig::from_lists(["fgets"], ["system"])
}

fn x86_taint_entry() -> NirFunction {
    NirFunction {
        name: "taint_entry".to_owned(),
        address: X86_ENTRY,
        end: 0x13b8,
        is_export: true,
        instructions: vec![
            instr(
                0x1390,
                NirOp::BinOp { op: BinaryOp::Sub },
                "sub",
                &["rsp", "0x48"],
            ),
            instr(0x1394, NirOp::Load, "mov", &["rax", "[rip+0x1125]"]),
            instr(0x139b, NirOp::Load, "mov", &["rdx", "[rax]"]),
            instr(0x139e, NirOp::Nop, "mov", &["rdi", "rsp"]),
            instr(0x13a1, NirOp::Nop, "mov", &["esi", "0x40"]),
            call(0x13a6, "call", X86_FGETS_STUB),
            instr(0x13ab, NirOp::Nop, "mov", &["rdi", "rax"]),
            call(0x13ae, "call", X86_SYSTEM_STUB),
            instr(
                0x13b3,
                NirOp::BinOp { op: BinaryOp::Add },
                "add",
                &["rsp", "0x48"],
            ),
            instr(0x13b7, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::labelled(SourceLang::NativeX86, X86_ENTRY, "taint_entry".to_owned()),
    }
}

fn aarch64_taint_entry(overwrite_before_the_sink: bool) -> NirFunction {
    let mut instructions: Vec<NirInstr> = vec![
        instr(
            0x1039c,
            NirOp::BinOp { op: BinaryOp::Sub },
            "sub",
            &["sp", "sp", "0x50"],
        ),
        instr(0x103a0, NirOp::Load, "stp", &["x29", "x30", "[sp, 0x40]"]),
        instr(
            0x103a4,
            NirOp::BinOp { op: BinaryOp::Add },
            "add",
            &["x29", "sp", "0x40"],
        ),
        instr(0x103a8, NirOp::Nop, "adrp", &["x8", "0x20000"]),
        instr(0x103ac, NirOp::Nop, "mov", &["x0", "sp"]),
        instr(0x103b0, NirOp::Nop, "mov", &["w1", "0x40"]),
        instr(0x103b4, NirOp::Load, "ldr", &["x8", "[x8, 0x4e0]"]),
        instr(0x103b8, NirOp::Load, "ldr", &["x2", "[x8]"]),
        call(0x103bc, "bl", AARCH64_FGETS_STUB),
    ];
    if overwrite_before_the_sink {
        instructions.push(instr(0x103be, NirOp::Nop, "mov", &["x0", "xzr"]));
    }
    instructions.extend([
        call(0x103c0, "bl", AARCH64_SYSTEM_STUB),
        instr(0x103c4, NirOp::Load, "ldp", &["x29", "x30", "[sp, 0x40]"]),
        instr(
            0x103c8,
            NirOp::BinOp { op: BinaryOp::Add },
            "add",
            &["sp", "sp", "0x50"],
        ),
        instr(0x103cc, NirOp::Return, "ret", &[]),
    ]);
    NirFunction {
        name: "taint_entry".to_owned(),
        address: AARCH64_ENTRY,
        end: 0x103d0,
        is_export: true,
        instructions,
        source: SourceRef::labelled(
            SourceLang::NativeX86,
            AARCH64_ENTRY,
            "taint_entry".to_owned(),
        ),
    }
}

fn named_stubs(fgets_stub: u64, system_stub: u64) -> Vec<NirSymbol> {
    vec![import(fgets_stub, "fgets"), import(system_stub, "system")]
}

fn undefined_imports() -> Vec<NirSymbol> {
    vec![import(0, "fgets"), import(0, "system")]
}

fn unresolved_targets(report: &TaintReport) -> Vec<u64> {
    report
        .unresolved_calls()
        .iter()
        .filter_map(|call: &UnresolvedCall| call.target)
        .collect()
}

#[test]
fn naming_the_import_thunks_is_the_only_difference_between_a_seen_and_an_unseen_flow() {
    let named: TaintReport = analyze(
        &module(
            x86_taint_entry(),
            named_stubs(X86_FGETS_STUB, X86_SYSTEM_STUB),
        ),
        &config(),
    );
    assert_eq!(
        named.count(),
        1,
        "with the two import thunks named, fgets feeding system is one flow: {named:?}"
    );
    assert!(named.flow_in("taint_entry", "fgets", "system"));
    assert!(
        !named.has_unresolved_calls(),
        "every call site in the image resolves once the thunks carry their names: {:?}",
        named.unresolved_calls()
    );

    let unnamed: TaintReport = analyze(&module(x86_taint_entry(), undefined_imports()), &config());
    assert_eq!(
        unnamed.count(),
        0,
        "an elf symbol table places an undefined import at address zero, not at its plt stub, so neither call names a callee"
    );
    assert_eq!(
        unnamed.unresolved_call_count(),
        2,
        "the two calls whose targets carry no name must be reported, not silently read as no call at all: {:?}",
        unnamed.unresolved_calls()
    );
    assert_eq!(
        unresolved_targets(&unnamed),
        vec![X86_FGETS_STUB, X86_SYSTEM_STUB],
        "the report names the exact stub addresses the analysis could not attribute"
    );
    assert!(
        unnamed
            .unresolved_calls()
            .iter()
            .all(|call: &UnresolvedCall| call.kind == UnresolvedCallKind::UnnamedTarget),
        "a direct call to an address with no symbol is an unnamed target, not an indirect one"
    );
    assert_eq!(
        unnamed.unresolved_call_sites("taint_entry"),
        vec![0x13a6, 0x13ae]
    );
}

#[test]
fn a_module_whose_every_call_resolves_reports_no_unresolved_call() {
    let function: NirFunction = NirFunction {
        name: "quiet".to_owned(),
        address: 0x100,
        end: 0x110,
        is_export: true,
        instructions: vec![
            instr(
                0x100,
                NirOp::BinOp { op: BinaryOp::Xor },
                "xor",
                &["eax", "eax"],
            ),
            instr(0x104, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x100),
    };
    let report: TaintReport = analyze(&module(function, undefined_imports()), &config());
    assert_eq!(report.unresolved_call_count(), 0);
    assert!(report.unresolved_calls().is_empty());
    assert!(
        !report.has_unresolved_calls(),
        "no call site at all is a different result from a call site the analysis could not name"
    );
}

#[test]
fn an_indirect_call_is_reported_as_an_unresolvable_callee_of_its_own_kind() {
    let function: NirFunction = NirFunction {
        name: "through_pointer".to_owned(),
        address: 0x200,
        end: 0x210,
        is_export: true,
        instructions: vec![
            instr(0x200, NirOp::IndirectCall, "call", &["[rax]"]),
            instr(0x208, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x200),
    };
    let report: TaintReport = analyze(&module(function, undefined_imports()), &config());
    assert_eq!(report.unresolved_call_count(), 1);
    assert_eq!(
        report.unresolved_calls()[0].kind,
        UnresolvedCallKind::IndirectTarget
    );
    assert_eq!(report.unresolved_calls()[0].target, None);
    assert_eq!(report.unresolved_calls()[0].site, 0x200);
}

#[test]
fn the_aarch64_register_file_carries_the_flow_the_x86_one_cannot_see() {
    let report: TaintReport = analyze(
        &module(
            aarch64_taint_entry(false),
            named_stubs(AARCH64_FGETS_STUB, AARCH64_SYSTEM_STUB),
        ),
        &config(),
    );
    assert_eq!(
        report.count(),
        1,
        "aapcs64 returns fgets in x0 and reads the system argument from x0, with no move in between: {report:?}"
    );
    assert!(report.flow_in("taint_entry", "fgets", "system"));
    let finding: &disrobe_taint::TaintFinding = &report.findings()[0];
    assert_eq!(finding.source_site, 0x103bc);
    assert_eq!(finding.sink_site, 0x103c0);
    assert!(!report.has_unresolved_calls());
}

#[test]
fn overwriting_x0_between_the_two_aarch64_calls_kills_the_flow() {
    let report: TaintReport = analyze(
        &module(
            aarch64_taint_entry(true),
            named_stubs(AARCH64_FGETS_STUB, AARCH64_SYSTEM_STUB),
        ),
        &config(),
    );
    assert_eq!(
        report.count(),
        0,
        "x0 is rewritten from the zero register before the sink reads it: {report:?}"
    );
    assert!(
        !report.has_unresolved_calls(),
        "the kill must come from the overwrite, not from a callee the analysis failed to name: {:?}",
        report.unresolved_calls()
    );
}

#[test]
fn an_unnamed_aarch64_stub_is_reported_rather_than_read_as_a_clean_image() {
    let report: TaintReport = analyze(
        &module(aarch64_taint_entry(false), undefined_imports()),
        &config(),
    );
    assert_eq!(report.count(), 0);
    assert_eq!(
        unresolved_targets(&report),
        vec![AARCH64_FGETS_STUB, AARCH64_SYSTEM_STUB],
        "a mach-o stubs entry resolves to an unnamed thunk exactly as an elf plt entry does"
    );
}

#[test]
fn a_tail_called_sink_is_attributed_like_a_plain_call() {
    let function: NirFunction = NirFunction {
        name: "tail_to_system".to_owned(),
        address: 0x300,
        end: 0x320,
        is_export: true,
        instructions: vec![
            call(0x300, "call", X86_FGETS_STUB),
            instr(0x308, NirOp::Nop, "mov", &["rdi", "rax"]),
            instr(
                0x30c,
                NirOp::TailCall {
                    target: Some(X86_SYSTEM_STUB),
                },
                "jmp",
                &[],
            ),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x300),
    };
    let report: TaintReport = analyze(
        &module(function, named_stubs(X86_FGETS_STUB, X86_SYSTEM_STUB)),
        &config(),
    );
    assert_eq!(
        report.count(),
        1,
        "returning the result of a sink call lowers to a tail jump into the sink's thunk: {report:?}"
    );
    assert!(report.flow_in("tail_to_system", "fgets", "system"));
    assert_eq!(report.findings()[0].sink_site, 0x30c);
}

#[test]
fn a_no_return_called_sink_is_attributed_like_a_plain_call() {
    const EXECVE_STUB: u64 = 0x14e0;
    let function: NirFunction = NirFunction {
        name: "replace_image".to_owned(),
        address: 0x400,
        end: 0x420,
        is_export: true,
        instructions: vec![
            call(0x400, "call", X86_FGETS_STUB),
            instr(0x408, NirOp::Nop, "mov", &["rdi", "rax"]),
            instr(
                0x40c,
                NirOp::NoReturnCall {
                    target: Some(EXECVE_STUB),
                },
                "call",
                &[],
            ),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x400),
    };
    let symbols: Vec<NirSymbol> = vec![
        import(X86_FGETS_STUB, "fgets"),
        import(EXECVE_STUB, "execve"),
    ];
    let report: TaintReport = analyze(
        &module(function, symbols),
        &TaintConfig::from_lists(["fgets"], ["execve"]),
    );
    assert_eq!(
        report.count(),
        1,
        "execve does not return, and a call the lifter marks terminal still reaches its sink: {report:?}"
    );
    assert!(report.flow_in("replace_image", "fgets", "execve"));
    assert!(!report.has_unresolved_calls());
}

#[test]
fn a_tail_call_into_an_unnamed_thunk_is_reported_as_unresolved() {
    let function: NirFunction = NirFunction {
        name: "tail_to_nowhere".to_owned(),
        address: 0x500,
        end: 0x510,
        is_export: true,
        instructions: vec![instr(
            0x500,
            NirOp::TailCall {
                target: Some(X86_SYSTEM_STUB),
            },
            "jmp",
            &[],
        )],
        source: SourceRef::new(SourceLang::NativeX86, 0x500),
    };
    let report: TaintReport = analyze(&module(function, undefined_imports()), &config());
    assert_eq!(report.unresolved_call_count(), 1);
    assert_eq!(
        report.unresolved_calls()[0].kind,
        UnresolvedCallKind::UnnamedTarget
    );
    assert_eq!(report.unresolved_calls()[0].target, Some(X86_SYSTEM_STUB));
}
