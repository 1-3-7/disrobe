#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{
    NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{TaintConfig, TaintReport, analyze};

const RECV_ADDR: u64 = 0xA000;
const SYSTEM_ADDR: u64 = 0xB000;
const READER_ADDR: u64 = 0x100;
const ENTRY_ADDR: u64 = 0x200;
const RUNNER_ADDR: u64 = 0x300;

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

fn call_internal(address: u64, target: u64) -> NirInstr {
    instr(
        address,
        NirOp::Call {
            target: Some(target),
        },
        "call",
    )
}

fn module() -> NirModule {
    let reader: NirFunction = NirFunction {
        name: "read_input".to_owned(),
        address: READER_ADDR,
        end: 0x140,
        is_export: false,
        instructions: vec![
            call_extern(READER_ADDR, "recv"),
            instr(0x108, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, READER_ADDR),
    };
    let runner: NirFunction = NirFunction {
        name: "run_cmd".to_owned(),
        address: RUNNER_ADDR,
        end: 0x340,
        is_export: false,
        instructions: vec![
            call_extern(RUNNER_ADDR, "system"),
            instr(0x308, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, RUNNER_ADDR),
    };
    let entry: NirFunction = NirFunction {
        name: "dispatch".to_owned(),
        address: ENTRY_ADDR,
        end: 0x240,
        is_export: true,
        instructions: vec![
            call_internal(ENTRY_ADDR, READER_ADDR),
            instr(0x208, NirOp::Store, "store"),
            call_internal(0x210, RUNNER_ADDR),
            instr(0x218, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, ENTRY_ADDR),
    };
    NirModule {
        source_hash: [9u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![reader, runner, entry],
        symbols: vec![
            NirSymbol {
                address: RECV_ADDR,
                name: "recv".to_owned(),
                kind: SymbolKind::Import,
            },
            NirSymbol {
                address: SYSTEM_ADDR,
                name: "system".to_owned(),
                kind: SymbolKind::Import,
            },
            NirSymbol {
                address: READER_ADDR,
                name: "read_input".to_owned(),
                kind: SymbolKind::Function,
            },
            NirSymbol {
                address: RUNNER_ADDR,
                name: "run_cmd".to_owned(),
                kind: SymbolKind::Function,
            },
        ],
    }
}

fn config() -> TaintConfig {
    TaintConfig::from_lists(["recv"], ["system"])
}

#[test]
fn a_source_returning_callee_taints_its_caller_into_a_sink_wrapper() {
    let report: TaintReport = analyze(&module(), &config());
    assert!(
        report.flow_in("dispatch", "read_input", "run_cmd"),
        "read_input returns tainted; run_cmd wraps the sink; dispatch wires source-to-sink: {report:?}"
    );
}

#[test]
fn severing_the_caller_edge_removes_the_cross_function_flow() {
    let mut m: NirModule = module();
    let dispatch: &mut NirFunction = m
        .functions
        .iter_mut()
        .find(|f: &&mut NirFunction| f.name == "dispatch")
        .expect("dispatch present");
    dispatch.instructions[0] = instr(ENTRY_ADDR, NirOp::Nop, "nop");
    let report: TaintReport = analyze(&m, &config());
    assert!(
        report.is_empty(),
        "with the read_input call removed, dispatch never imports the taint: {report:?}"
    );
}

#[test]
fn analysis_is_deterministic() {
    let first: TaintReport = analyze(&module(), &config());
    let second: TaintReport = analyze(&module(), &config());
    assert_eq!(first, second);
}
