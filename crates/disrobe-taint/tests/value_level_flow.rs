#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_nir::{
    BinaryOp, NirFunction, NirInstr, NirModule, NirOp, NirSymbol, SourceLang, SourceRef, SymbolKind,
};
use disrobe_taint::{TaintConfig, TaintReport, analyze};

const RECV_ADDR: u64 = 0xA000;
const GETENV_ADDR: u64 = 0xA800;
const SYSTEM_ADDR: u64 = 0xB000;

fn extern_symbols() -> Vec<NirSymbol> {
    vec![
        NirSymbol {
            address: RECV_ADDR,
            name: "recv".to_owned(),
            kind: SymbolKind::Import,
        },
        NirSymbol {
            address: GETENV_ADDR,
            name: "getenv".to_owned(),
            kind: SymbolKind::Import,
        },
        NirSymbol {
            address: SYSTEM_ADDR,
            name: "system".to_owned(),
            kind: SymbolKind::Import,
        },
    ]
}

fn op(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
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

fn call_recv(address: u64) -> NirInstr {
    op(
        address,
        NirOp::ExternCall {
            symbol: "recv".to_owned(),
        },
        "call",
        &[],
    )
}

fn call_getenv(address: u64) -> NirInstr {
    op(
        address,
        NirOp::ExternCall {
            symbol: "getenv".to_owned(),
        },
        "call",
        &[],
    )
}

fn call_system(address: u64) -> NirInstr {
    op(
        address,
        NirOp::ExternCall {
            symbol: "system".to_owned(),
        },
        "call",
        &["rdi"],
    )
}

fn config() -> TaintConfig {
    TaintConfig::new().with_source("recv").with_sink("system")
}

fn multi_source_config() -> TaintConfig {
    TaintConfig::from_lists(["recv", "getenv"], ["system"])
}

fn module(function: NirFunction) -> NirModule {
    NirModule {
        source_hash: [7u8; 32],
        lang: SourceLang::NativeX86,
        functions: vec![function],
        symbols: extern_symbols(),
    }
}

fn genuine_flow() -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0x100,
        end: 0x180,
        is_export: true,
        instructions: vec![
            call_recv(0x100),
            op(
                0x108,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rbx", "rax"],
            ),
            op(
                0x110,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rbx"],
            ),
            call_system(0x118),
            op(0x120, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x100),
    }
}

fn unrelated_pair() -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0x100,
        end: 0x180,
        is_export: true,
        instructions: vec![
            call_recv(0x100),
            op(
                0x108,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rbx", "rax"],
            ),
            op(0x110, NirOp::Const, "mov", &["rdi", "0x2a"]),
            call_system(0x118),
            op(0x120, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x100),
    }
}

fn two_source_join() -> NirFunction {
    NirFunction {
        name: "joined_sources".to_owned(),
        address: 0x500,
        end: 0x560,
        is_export: true,
        instructions: vec![
            op(
                0x500,
                NirOp::CondBranch {
                    target: Some(0x530),
                },
                "jz",
                &[],
            ),
            call_recv(0x508),
            op(
                0x510,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            op(
                0x518,
                NirOp::Branch {
                    target: Some(0x540),
                },
                "jmp",
                &[],
            ),
            call_getenv(0x530),
            op(
                0x538,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            call_system(0x540),
            op(0x548, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x500),
    }
}

fn dangling_successor() -> NirFunction {
    NirFunction {
        name: "dangling_successor".to_owned(),
        address: 0x700,
        end: 0x730,
        is_export: true,
        instructions: vec![
            op(
                0x700,
                NirOp::CondBranch {
                    target: Some(0x720),
                },
                "jz",
                &[],
            ),
            op(0x708, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x700),
    }
}

#[test]
fn value_reaching_the_sink_operand_is_a_flow() {
    let report: TaintReport = analyze(&module(genuine_flow()), &config());
    assert!(
        report.reaches("recv", "system"),
        "recv result moves rax -> rbx -> rdi, the system argument register: {report:?}"
    );
    assert_eq!(report.count(), 1, "exactly one value-level flow");
    let finding = &report.findings()[0];
    assert_eq!(finding.source_site, 0x100);
    assert_eq!(finding.sink_site, 0x118);
    assert!(
        finding
            .path
            .iter()
            .any(|s| s.kind == "propagate" && s.address == 0x110),
        "the rdi <- rbx move that carries the value is recorded: {:?}",
        finding.path
    );
}

#[test]
fn unrelated_source_and_sink_in_the_same_block_is_not_a_flow() {
    let report: TaintReport = analyze(&module(unrelated_pair()), &config());
    assert!(
        report.is_empty(),
        "recv taints rax/rbx but the system argument rdi is loaded from an immediate, so nothing flows: {report:?}"
    );
}

#[test]
fn overwriting_the_argument_register_severs_the_flow() {
    let mut function: NirFunction = genuine_flow();
    function.instructions[2] = op(0x110, NirOp::Const, "mov", &["rdi", "0x2a"]);
    let report: TaintReport = analyze(&module(function), &config());
    assert!(
        report.is_empty(),
        "killing rdi with an immediate after the taint move severs the value-level flow: {report:?}"
    );
}

#[test]
fn joined_branches_preserve_each_source_origin() {
    let report: TaintReport = analyze(&module(two_source_join()), &multi_source_config());
    assert!(
        report.reaches("recv", "system"),
        "the fall-through source reaches the joined sink: {report:?}"
    );
    assert!(
        report.reaches("getenv", "system"),
        "the taken-branch source reaches the joined sink: {report:?}"
    );
    assert_eq!(report.count(), 2, "both feasible origins are reported");
}

#[test]
fn analysis_is_deterministic_for_value_level_flow() {
    let first: TaintReport = analyze(&module(genuine_flow()), &config());
    let second: TaintReport = analyze(&module(genuine_flow()), &config());
    assert_eq!(first, second);
}

#[test]
fn state_cap_marks_report_truncated() {
    let capped: TaintConfig = multi_source_config().with_max_states_per_function(1);
    let report: TaintReport = analyze(&module(two_source_join()), &capped);
    assert!(report.is_truncated());
}

#[test]
fn dangling_cfg_successor_marks_report_truncated() {
    let report: TaintReport = analyze(&module(dangling_successor()), &config());
    assert!(report.is_truncated());
}
