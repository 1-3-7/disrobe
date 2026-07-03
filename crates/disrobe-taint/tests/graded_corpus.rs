#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{BinaryOp, NirFunction, NirInstr, NirModule, NirOp, SourceLang, SourceRef};
use disrobe_taint::{TaintConfig, TaintReport, analyze};

fn ext(address: u64, symbol: &str, operands: &[&str]) -> NirInstr {
    build(
        address,
        NirOp::ExternCall {
            symbol: symbol.to_owned(),
        },
        "call",
        operands,
    )
}

fn call_internal(address: u64, target: u64) -> NirInstr {
    build(
        address,
        NirOp::Call {
            target: Some(target),
        },
        "call",
        &[],
    )
}

fn mov(address: u64, dst: &str, src: &str) -> NirInstr {
    build(
        address,
        NirOp::BinOp { op: BinaryOp::Add },
        "mov",
        &[dst, src],
    )
}

fn ret(address: u64) -> NirInstr {
    build(address, NirOp::Return, "ret", &[])
}

fn build(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
    NirInstr {
        address,
        op,
        mnemonic: mnemonic.to_owned(),
        operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
        reads_memory: false,
        writes_memory: false,
        byte_width: false,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

fn func(name: &str, address: u64, instructions: Vec<NirInstr>) -> NirFunction {
    let end: u64 = instructions
        .last()
        .map_or(address, |i: &NirInstr| i.address + 1);
    NirFunction {
        name: name.to_owned(),
        address,
        end,
        is_export: true,
        instructions,
        source: SourceRef::new(SourceLang::NativeX86, address),
    }
}

const fn module(functions: Vec<NirFunction>) -> NirModule {
    NirModule {
        source_hash: [0x5a; 32],
        lang: SourceLang::NativeX86,
        functions,
        symbols: Vec::new(),
    }
}

fn corpus_config() -> TaintConfig {
    TaintConfig::from_lists(["recv", "getenv"], ["system", "query", "printf"])
        .with_sanitizer_for("escape_shell", "system")
        .with_sanitizer_for("escape_sql", "query")
        .with_sanitizer_for("escape_fmt", "printf")
}

fn direct_flow(source: &str, sink: &str, sanitizer: Option<&str>) -> NirModule {
    let mut instrs: Vec<NirInstr> = vec![ext(0x100, source, &[])];
    let mut next: u64 = 0x108;
    if let Some(clean) = sanitizer {
        instrs.push(ext(next, clean, &["rax"]));
        next += 8;
    }
    instrs.push(mov(next, "rdi", "rax"));
    next += 8;
    instrs.push(ext(next, sink, &["rdi"]));
    next += 8;
    instrs.push(ret(next));
    module(vec![func("handle", 0x100, instrs)])
}

fn interprocedural_flow(sanitizer: Option<&str>) -> NirModule {
    let reader: NirFunction = func(
        "read_input",
        0x200,
        vec![ext(0x200, "recv", &[]), ret(0x208)],
    );
    let runner: NirFunction = func(
        "run_cmd",
        0x300,
        vec![ext(0x300, "system", &["rdi"]), ret(0x308)],
    );
    let mut instrs: Vec<NirInstr> = vec![call_internal(0x400, 0x200)];
    let mut next: u64 = 0x408;
    if let Some(clean) = sanitizer {
        instrs.push(ext(next, clean, &["rax"]));
        next += 8;
    }
    instrs.push(mov(next, "rdi", "rax"));
    next += 8;
    instrs.push(call_internal(next, 0x300));
    next += 8;
    instrs.push(ret(next));
    let dispatch: NirFunction = func("dispatch", 0x400, instrs);
    module(vec![reader, runner, dispatch])
}

fn out_parameter_flow(sanitizer: Option<&str>) -> NirModule {
    let forward: NirFunction = func("forward", 0x500, vec![mov(0x500, "rsi", "rdi"), ret(0x508)]);
    let mut instrs: Vec<NirInstr> = vec![ext(0x600, "recv", &[])];
    let mut next: u64 = 0x608;
    if let Some(clean) = sanitizer {
        instrs.push(ext(next, clean, &["rax"]));
        next += 8;
    }
    instrs.push(mov(next, "rdi", "rax"));
    next += 8;
    instrs.push(call_internal(next, 0x500));
    next += 8;
    instrs.push(mov(next, "rdi", "rsi"));
    next += 8;
    instrs.push(ext(next, "system", &["rdi"]));
    next += 8;
    instrs.push(ret(next));
    let caller: NirFunction = func("use_forward", 0x600, instrs);
    module(vec![forward, caller])
}

fn lift_wasm(wat: &str) -> NirModule {
    let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat");
    disrobe_nir_lift::lift_wasm_module(&bytes).expect("lift wasm module")
}

fn wasm_direct(sanitizer: bool) -> NirModule {
    let body: &str = if sanitizer {
        "(call $system (call $escape_shell (call $recv)))"
    } else {
        "(call $system (call $recv))"
    };
    let wat: String = format!(
        "(module \
           (import \"env\" \"recv\" (func $recv (result i32))) \
           (import \"env\" \"escape_shell\" (func $escape_shell (param i32) (result i32))) \
           (import \"env\" \"system\" (func $system (param i32) (result i32))) \
           (memory (export \"memory\") 1) \
           (func (export \"handle\") (result i32) {body}))"
    );
    lift_wasm(&wat)
}

struct Case {
    name: &'static str,
    module: NirModule,
    genuine: bool,
}

fn corpus() -> Vec<Case> {
    vec![
        Case {
            name: "cmd_injection_bad",
            module: direct_flow("recv", "system", None),
            genuine: true,
        },
        Case {
            name: "cmd_injection_good",
            module: direct_flow("recv", "system", Some("escape_shell")),
            genuine: false,
        },
        Case {
            name: "sql_injection_bad",
            module: direct_flow("getenv", "query", None),
            genuine: true,
        },
        Case {
            name: "sql_injection_good",
            module: direct_flow("getenv", "query", Some("escape_sql")),
            genuine: false,
        },
        Case {
            name: "format_string_bad",
            module: direct_flow("recv", "printf", None),
            genuine: true,
        },
        Case {
            name: "format_string_good",
            module: direct_flow("recv", "printf", Some("escape_fmt")),
            genuine: false,
        },
        Case {
            name: "interprocedural_bad",
            module: interprocedural_flow(None),
            genuine: true,
        },
        Case {
            name: "interprocedural_good",
            module: interprocedural_flow(Some("escape_shell")),
            genuine: false,
        },
        Case {
            name: "out_parameter_bad",
            module: out_parameter_flow(None),
            genuine: true,
        },
        Case {
            name: "out_parameter_good",
            module: out_parameter_flow(Some("escape_shell")),
            genuine: false,
        },
        Case {
            name: "wasm_direct_bad",
            module: wasm_direct(false),
            genuine: true,
        },
        Case {
            name: "wasm_direct_good",
            module: wasm_direct(true),
            genuine: false,
        },
        Case {
            name: "wrong_sanitizer_still_flags",
            module: direct_flow("recv", "system", Some("escape_sql")),
            genuine: true,
        },
    ]
}

fn flagged(module: &NirModule) -> bool {
    let report: TaintReport = analyze(module, &corpus_config());
    !report.is_empty()
}

#[test]
fn every_bad_case_is_flagged_and_every_good_twin_is_clean() {
    for case in corpus() {
        let observed: bool = flagged(&case.module);
        assert_eq!(
            observed, case.genuine,
            "{}: expected genuine-flow={}, engine flagged={observed}",
            case.name, case.genuine
        );
    }
}

#[test]
fn discrimination_score_is_perfect_and_beats_a_taint_everything_cheat() {
    let cases: Vec<Case> = corpus();
    let bad: Vec<&Case> = cases.iter().filter(|c: &&Case| c.genuine).collect();
    let good: Vec<&Case> = cases.iter().filter(|c: &&Case| !c.genuine).collect();
    assert!(!bad.is_empty() && !good.is_empty());

    let true_positive: usize = bad.iter().filter(|c: &&&Case| flagged(&c.module)).count();
    let false_positive: usize = good.iter().filter(|c: &&&Case| flagged(&c.module)).count();
    let tpr: f64 = true_positive as f64 / bad.len() as f64;
    let fpr: f64 = false_positive as f64 / good.len() as f64;
    let discrimination: f64 = tpr - fpr;

    assert!(
        (tpr - 1.0).abs() < f64::EPSILON,
        "every genuine flow must be caught: tpr={tpr}"
    );
    assert!(
        fpr.abs() < f64::EPSILON,
        "no sanitized twin may be flagged: fpr={fpr}"
    );
    assert!(
        discrimination > 0.99,
        "a taint-everything cheat scores 0; discrimination={discrimination}"
    );
}

#[test]
fn interprocedural_finding_attributes_callee_source_and_sink() {
    let report: TaintReport = analyze(&interprocedural_flow(None), &corpus_config());
    assert!(
        report.flow_in("dispatch", "read_input", "run_cmd"),
        "the source-returning callee and the sink-wrapping callee are named in the flow: {report:?}"
    );
}

#[test]
fn out_parameter_flow_travels_argument_to_argument() {
    let report: TaintReport = analyze(&out_parameter_flow(None), &corpus_config());
    assert!(
        report.reaches("recv", "system"),
        "recv taints rdi, forward copies rdi into rsi, and rsi feeds the sink: {report:?}"
    );
}
