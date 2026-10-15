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
const RELAY_ADDR: u64 = 0x400;

fn instr(address: u64, op: NirOp, mnemonic: &str) -> NirInstr {
    instr_with_operands(address, op, mnemonic, &[])
}

fn instr_with_operands(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: operands
            .iter()
            .map(|value: &&str| (*value).to_owned())
            .collect(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn memory_input_module(offset: &str) -> NirModule {
    let source_and_caller: NirFunction = NirFunction {
        name: "dispatch_memory".to_owned(),
        address: ENTRY_ADDR,
        end: ENTRY_ADDR + 0x40,
        is_export: true,
        instructions: vec![
            call_extern(ENTRY_ADDR, "recv"),
            instr_with_operands(0x208, NirOp::Store, "mov", &["[rsp+30h]", "rax"]),
            instr_with_operands(0x210, NirOp::Load, "lea", &["rcx", "[rsp+30h]"]),
            call_internal(0x218, RUNNER_ADDR),
            instr(0x220, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, ENTRY_ADDR),
    };
    let sink: NirFunction = NirFunction {
        name: "memory_sink".to_owned(),
        address: RUNNER_ADDR,
        end: RUNNER_ADDR + 0x30,
        is_export: false,
        instructions: vec![
            instr_with_operands(
                RUNNER_ADDR,
                NirOp::Load,
                "mov",
                &["rcx", &format!("[rcx{offset}]")],
            ),
            instr_with_operands(
                RUNNER_ADDR + 8,
                NirOp::ExternCall {
                    symbol: "system".to_owned(),
                },
                "call",
                &["rcx"],
            ),
            instr(RUNNER_ADDR + 0x10, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, RUNNER_ADDR),
    };
    NirModule {
        source_hash: [10u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![source_and_caller, sink],
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
                address: RUNNER_ADDR,
                name: "memory_sink".to_owned(),
                kind: SymbolKind::Function,
            },
        ],
    }
}

fn global_input_module(sink_address: &str) -> NirModule {
    let source_and_caller: NirFunction = NirFunction {
        name: "dispatch_global".to_owned(),
        address: ENTRY_ADDR,
        end: ENTRY_ADDR + 0x30,
        is_export: true,
        instructions: vec![
            call_extern(ENTRY_ADDR, "recv"),
            instr_with_operands(0x208, NirOp::Store, "mov", &["[rel 5000h]", "rax"]),
            call_internal(0x210, RUNNER_ADDR),
            instr(0x218, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, ENTRY_ADDR),
    };
    let sink: NirFunction = NirFunction {
        name: "global_sink".to_owned(),
        address: RUNNER_ADDR,
        end: RUNNER_ADDR + 0x30,
        is_export: false,
        instructions: vec![
            instr_with_operands(RUNNER_ADDR, NirOp::Load, "mov", &["rcx", sink_address]),
            instr_with_operands(
                RUNNER_ADDR + 8,
                NirOp::ExternCall {
                    symbol: "system".to_owned(),
                },
                "call",
                &["rcx"],
            ),
            instr(RUNNER_ADDR + 0x10, NirOp::Return, "ret"),
        ],
        source: SourceRef::new(SourceLang::NativeX86, RUNNER_ADDR),
    };
    NirModule {
        source_hash: [11u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![source_and_caller, sink],
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
                address: RUNNER_ADDR,
                name: "global_sink".to_owned(),
                kind: SymbolKind::Function,
            },
        ],
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

fn tail_relay_module(relay_target: Option<u64>) -> NirModule {
    let mut value: NirModule = module();
    let relay_op: NirOp = relay_target.map_or(NirOp::Return, |target: u64| NirOp::Branch {
        target: Some(target),
    });
    value.functions.push(NirFunction {
        name: "relay".to_owned(),
        address: RELAY_ADDR,
        end: RELAY_ADDR + 0x10,
        is_export: false,
        instructions: vec![instr(RELAY_ADDR, relay_op, "jmp")],
        source: SourceRef::new(SourceLang::NativeX86, RELAY_ADDR),
    });
    let dispatch: &mut NirFunction = value
        .functions
        .iter_mut()
        .find(|function: &&mut NirFunction| function.name == "dispatch")
        .expect("dispatch present");
    dispatch.instructions[2] = call_internal(0x210, RELAY_ADDR);
    value.symbols.push(NirSymbol {
        address: RELAY_ADDR,
        name: "relay".to_owned(),
        kind: SymbolKind::Function,
    });
    value
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

#[test]
fn a_cross_function_tail_jump_composes_the_sink_summary_at_depth_two() {
    let report: TaintReport = analyze(&tail_relay_module(Some(RUNNER_ADDR)), &config());
    assert!(
        report.flow_in("dispatch", "read_input", "relay"),
        "the relay's jump to the sink wrapper is a cross-function tail transfer and must compose \
         through the caller's source summary: {report:?}"
    );

    let severed: TaintReport = analyze(&tail_relay_module(None), &config());
    assert!(
        severed.is_empty(),
        "replacing the relay's cross-function jump with a return removes the only path to the \
         sink, so the mutation control must stay red: {severed:?}"
    );
}

#[test]
fn a_callee_memory_projection_resolves_the_callers_exact_pointer_target() {
    let report: TaintReport = analyze(&memory_input_module(""), &config());
    assert!(
        report.flow_in("dispatch_memory", "recv", "memory_sink"),
        "the callee dereferences its pointer argument, so its summary must resolve the caller's \
         established stack-cell alias: {report:?}"
    );

    let severed: TaintReport = analyze(&memory_input_module("+8h"), &config());
    assert!(
        severed.is_empty(),
        "changing the callee projection to a different stack cell must sever the flow: {severed:?}"
    );
}

#[test]
fn a_callee_global_read_resolves_the_callers_exact_global_write() {
    let report: TaintReport = analyze(&global_input_module("[rel 5000h]"), &config());
    assert!(
        report.flow_in("dispatch_global", "recv", "global_sink"),
        "the caller's tainted write and callee's read use the same global slot: {report:?}"
    );

    let severed: TaintReport = analyze(&global_input_module("[rel 6000h]"), &config());
    assert!(
        severed.is_empty(),
        "a different global slot must not inherit the caller's tainted write: {severed:?}"
    );
}
