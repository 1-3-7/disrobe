use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{TaintConfig, TaintReport, analyze};

const SOURCE_ADDR: u64 = 0xA000;
const SINK_ADDR: u64 = 0xB000;

fn extern_symbols() -> Vec<NirSymbol> {
    vec![
        NirSymbol {
            address: SOURCE_ADDR,
            name: "recv".to_owned(),
            kind: SymbolKind::Import,
        },
        NirSymbol {
            address: SINK_ADDR,
            name: "system".to_owned(),
            kind: SymbolKind::Import,
        },
    ]
}

fn instr(address: u64, op: NirOp, mnemonic: &str) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn call_extern(address: u64, symbol: &str) -> NirInstr {
    instr(
        address,
        NirOp::ExternCall {
            symbol: symbol.to_owned(),
        },
        "call",
    )
}

fn config() -> TaintConfig {
    TaintConfig::new().with_source("recv").with_sink("system")
}

#[test]
fn straight_line_source_to_sink_is_reached() {
    let function: NirFunction = NirFunction {
        name: "handle".to_owned(),
        address: 0x100,
        end: 0x140,
        is_export: true,
        instructions: vec![
            call_extern(0x100, "recv"),
            instr(0x108, NirOp::BinOp { op: BinaryOp::Xor }, "xor"),
            instr(0x110, NirOp::Store, "store"),
            call_extern(0x118, "system"),
            instr(0x120, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x100),
    };
    let module: NirModule = NirModule {
        source_hash: [0u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols: extern_symbols(),
    };
    let report: TaintReport = analyze(&module, &config());
    assert_eq!(report.count(), 1, "exactly one recv -> system flow");
    assert!(report.reaches("recv", "system"));
    let finding = &report.findings()[0];
    assert_eq!(finding.source_site, 0x100);
    assert_eq!(finding.sink_site, 0x118);
    assert!(
        finding
            .path
            .iter()
            .any(|s| s.kind == "propagate" && s.symbol == "xor"),
        "the xor between source and sink is recorded as a propagation step: {:?}",
        finding.path
    );
}

#[test]
fn taint_only_on_the_untaken_branch_does_not_reach_the_sink() {
    let function: NirFunction = NirFunction {
        name: "guarded".to_owned(),
        address: 0x200,
        end: 0x260,
        is_export: true,
        instructions: vec![
            instr(
                0x200,
                NirOp::CondBranch {
                    target: Some(0x230),
                },
                "jz",
            ),
            call_extern(0x208, "recv"),
            instr(0x210, NirOp::Return, "ret"),
            call_extern(0x230, "system"),
            instr(0x238, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x200),
    };
    let module: NirModule = NirModule {
        source_hash: [1u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols: extern_symbols(),
    };
    let report: TaintReport = analyze(&module, &config());
    assert!(
        report.is_empty(),
        "recv sits on the fall-through arm, system on the taken arm; the two never join on a tainted path: {report:?}"
    );
}

#[test]
fn taint_reaches_a_sink_only_through_the_block_the_source_dominates() {
    let function: NirFunction = NirFunction {
        name: "joined".to_owned(),
        address: 0x300,
        end: 0x380,
        is_export: true,
        instructions: vec![
            call_extern(0x300, "recv"),
            instr(
                0x308,
                NirOp::CondBranch {
                    target: Some(0x330),
                },
                "jz",
            ),
            instr(0x310, NirOp::Store, "store"),
            instr(
                0x318,
                NirOp::Branch {
                    target: Some(0x340),
                },
                "jmp",
            ),
            instr(0x330, NirOp::Load, "load"),
            call_extern(0x340, "system"),
            instr(0x348, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x300),
    };
    let module: NirModule = NirModule {
        source_hash: [2u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols: extern_symbols(),
    };
    let report: TaintReport = analyze(&module, &config());
    assert!(
        report.reaches("recv", "system"),
        "source dominates both arms, so the post-join sink is reachable: {report:?}"
    );
    assert_eq!(report.count(), 1);
}

#[test]
fn no_source_means_no_flow() {
    let function: NirFunction = NirFunction {
        name: "clean".to_owned(),
        address: 0x400,
        end: 0x420,
        is_export: true,
        instructions: vec![
            call_extern(0x400, "system"),
            instr(0x408, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x400),
    };
    let module: NirModule = NirModule {
        source_hash: [3u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols: extern_symbols(),
    };
    let report: TaintReport = analyze(&module, &config());
    assert!(
        report.is_empty(),
        "a sink with no upstream source is not a flow"
    );
}
