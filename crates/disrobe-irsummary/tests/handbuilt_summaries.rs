#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_irsummary::{capability_summary, cfg_summary, dfg_summary};
use disrobe_nir::{
    BinaryOp, BlockKind, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef,
    SymbolKind,
};
use disrobe_query::Capability;

const fn instr(address: u64, op: NirOp) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: String::new(),
        operands: Vec::new(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn mem(address: u64, op: NirOp, reads: bool, writes: bool) -> NirInstr {
    NirInstr {
        reads_memory: reads,
        writes_memory: writes,
        ..instr(address, op)
    }
}

fn extern_sym(address: u64, name: &str) -> NirSymbol {
    NirSymbol {
        address,
        name: name.to_owned(),
        kind: SymbolKind::Import,
    }
}

fn branchy_capability_module() -> NirModule {
    let handler: NirFunction = NirFunction {
        name: "handler".to_owned(),
        address: 0x0,
        end: 0x9,
        is_export: true,
        instructions: vec![
            instr(
                0x0,
                NirOp::ExternCall {
                    symbol: "recv".to_owned(),
                },
            ),
            mem(0x1, NirOp::Store, false, true),
            instr(0x2, NirOp::CondBranch { target: Some(0x6) }),
            instr(
                0x4,
                NirOp::ExternCall {
                    symbol: "CryptEncrypt".to_owned(),
                },
            ),
            mem(0x6, NirOp::Load, true, false),
            instr(
                0x7,
                NirOp::ExternCall {
                    symbol: "WriteFile".to_owned(),
                },
            ),
            instr(0x8, NirOp::Return),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x0),
    };
    NirModule {
        source_hash: [0x11; 32],
        lang: SourceLang::NativeX86,
        functions: vec![handler],
        symbols: vec![
            extern_sym(0x100, "recv"),
            extern_sym(0x104, "CryptEncrypt"),
            extern_sym(0x108, "WriteFile"),
        ],
    }
}

#[test]
fn capability_summary_classifies_each_extern_call_family() {
    let module: NirModule = branchy_capability_module();
    let summary = capability_summary(&module);

    assert!(summary.has(Capability::Network), "recv -> network");
    assert!(summary.has(Capability::Crypto), "CryptEncrypt -> crypto");
    assert!(
        summary.has(Capability::Filesystem),
        "WriteFile -> filesystem"
    );
    assert!(!summary.has(Capability::Process), "no process api present");

    let net = summary.tag(Capability::Network).expect("network tag");
    assert_eq!(net.site_count, 1);
    assert_eq!(net.symbols, vec!["recv".to_owned()]);
    assert_eq!(net.functions, vec!["handler".to_owned()]);

    let labels: Vec<&str> = summary.labels();
    assert_eq!(labels, vec!["network", "crypto", "filesystem"]);
}

#[test]
fn cfg_summary_matches_hand_verified_blocks_and_complexity() {
    let module: NirModule = branchy_capability_module();
    let summary = cfg_summary(&module);
    let handler = summary.function("handler").expect("handler in cfg");

    assert_eq!(handler.cyclomatic_complexity, 2, "one conditional branch");
    assert_eq!(handler.blocks.len(), 3, "entry, taken-skip arm, merge");
    assert!(handler.is_export);

    let entry = &handler.blocks[0];
    assert_eq!(entry.start, 0x0);
    assert_eq!(entry.kind, BlockKind::Conditional);
    assert_eq!(entry.successors, vec![0x4, 0x6]);

    let merge = handler.blocks.last().expect("merge block");
    assert_eq!(merge.start, 0x6);
    assert_eq!(merge.kind, BlockKind::Return);
    assert!(merge.successors.is_empty());

    assert_eq!(summary.total_edges(), handler.edge_count);
}

#[test]
fn dfg_summary_links_a_store_to_a_downstream_load() {
    let module: NirModule = branchy_capability_module();
    let summary = dfg_summary(&module);
    let handler = summary.function("handler").expect("handler in dfg");

    assert_eq!(handler.write_sites, vec![0x1]);
    assert_eq!(handler.read_sites, vec![0x6]);
    assert!(
        summary.reaches("handler", 0x1, 0x6),
        "store at 0x1 reaches load at 0x6 through the merge block"
    );
    assert_eq!(summary.total_edges(), 1);
}

#[test]
fn a_store_after_the_load_does_not_flow_backward() {
    let f: NirFunction = NirFunction {
        name: "rev".to_owned(),
        address: 0x0,
        end: 0x4,
        is_export: false,
        instructions: vec![
            mem(0x0, NirOp::Load, true, false),
            instr(0x1, NirOp::BinOp { op: BinaryOp::Xor }),
            mem(0x2, NirOp::Store, false, true),
            instr(0x3, NirOp::Return),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x0),
    };
    let module: NirModule = NirModule {
        source_hash: [0x22; 32],
        lang: SourceLang::NativeX86,
        functions: vec![f],
        symbols: Vec::new(),
    };
    let summary = dfg_summary(&module);
    let rev = summary.function("rev").expect("rev in dfg");
    assert_eq!(rev.write_sites, vec![0x2]);
    assert_eq!(rev.read_sites, vec![0x0]);
    assert!(
        rev.edges.is_empty(),
        "the only read precedes the only write"
    );
}

#[test]
fn an_internal_call_is_not_a_capability_site() {
    let caller: NirFunction = NirFunction {
        name: "caller".to_owned(),
        address: 0x0,
        end: 0x2,
        is_export: true,
        instructions: vec![
            instr(0x0, NirOp::Call { target: Some(0x10) }),
            instr(0x1, NirOp::Return),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x0),
    };
    let callee: NirFunction = NirFunction {
        name: "system".to_owned(),
        address: 0x10,
        end: 0x11,
        is_export: false,
        instructions: vec![instr(0x10, NirOp::Return)],
        source: SourceRef::new(SourceLang::NativeX86, 0x10),
    };
    let module: NirModule = NirModule {
        source_hash: [0x33; 32],
        lang: SourceLang::NativeX86,
        functions: vec![caller, callee],
        symbols: Vec::new(),
    };
    let summary = capability_summary(&module);
    assert!(
        summary.tags.is_empty(),
        "a call to a defined internal function named `system` is not an external process site"
    );
}
