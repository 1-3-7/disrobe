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

fn call_system_reading(address: u64, register: &str) -> NirInstr {
    op(
        address,
        NirOp::ExternCall {
            symbol: "system".to_owned(),
        },
        "call",
        &[register],
    )
}

fn call_fgets(address: u64) -> NirInstr {
    op(
        address,
        NirOp::ExternCall {
            symbol: "fgets".to_owned(),
        },
        "call",
        &[],
    )
}

fn setup_buffer_argument(address: u64, register: &str) -> NirInstr {
    op(address, NirOp::Const, "lea", &[register, "0x7000"])
}

fn config() -> TaintConfig {
    TaintConfig::new().with_source("recv").with_sink("system")
}

fn out_argument_config() -> TaintConfig {
    TaintConfig::new().with_source("fgets").with_sink("system")
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

fn fgets_argument_flow_via(register: &str) -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0x900,
        end: 0x980,
        is_export: true,
        instructions: vec![
            setup_buffer_argument(0x900, register),
            call_fgets(0x908),
            call_system_reading(0x910, register),
            op(0x918, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x900),
    }
}

fn fgets_argument_flow() -> NirFunction {
    fgets_argument_flow_via("rdi")
}

fn indexed_write_base_read_flow() -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0xD00,
        end: 0xD80,
        is_export: true,
        instructions: vec![
            op(0xD00, NirOp::Load, "lea", &["rdi", "[rsp+r9+30h]"]),
            call_fgets(0xD08),
            op(0xD10, NirOp::Load, "lea", &["rdi", "[rsp+30h]"]),
            call_system(0xD18),
            op(0xD20, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0xD00),
    }
}

fn fgets_call_with_no_established_argument() -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0x900,
        end: 0x980,
        is_export: true,
        instructions: vec![
            call_fgets(0x900),
            call_system(0x908),
            op(0x910, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x900),
    }
}

fn fgets_return_only_flow() -> NirFunction {
    NirFunction {
        name: "handle".to_owned(),
        address: 0xB00,
        end: 0xB80,
        is_export: true,
        instructions: vec![
            call_fgets(0xB00),
            op(
                0xB08,
                NirOp::BinOp { op: BinaryOp::Add },
                "mov",
                &["rdi", "rax"],
            ),
            call_system(0xB10),
            op(0xB18, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0xB00),
    }
}

fn recv_argument_flow() -> NirFunction {
    NirFunction {
        name: "handle_recv".to_owned(),
        address: 0x900,
        end: 0x980,
        is_export: true,
        instructions: vec![
            setup_buffer_argument(0x900, "rdi"),
            call_recv(0x908),
            call_system(0x910),
            op(0x918, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0x900),
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

#[test]
fn a_source_configured_with_an_out_argument_taints_the_established_argument_register() {
    let report: TaintReport = analyze(&module(fgets_argument_flow()), &out_argument_config());
    assert!(
        report.reaches("fgets", "system"),
        "fgets is configured with an out-argument at index 0, rdi is established right before the \
         call by a real setup instruction, and the very next call reads rdi, so the buffer argument \
         itself must carry the taint even though nothing ever touches the return register rax: \
         {report:?}"
    );
    assert_eq!(report.count(), 1);
}

#[test]
fn the_out_argument_gate_corroborates_either_the_system_v_or_microsoft_x64_argument_register() {
    for register in ["rdi", "rcx"] {
        let report: TaintReport = analyze(
            &module(fgets_argument_flow_via(register)),
            &out_argument_config(),
        );
        assert!(
            report.reaches("fgets", "system"),
            "index 0 of fgets' declared out-argument must corroborate against whichever native \
             calling convention the compiled code actually established, rdi under system v or rcx \
             under microsoft x64, since disrobe-taint has no way to know ahead of time which one \
             produced this binary: register {register}: {report:?}"
        );
    }
}

#[test]
fn overwriting_the_out_argument_register_after_the_call_severs_the_flow() {
    let mut function: NirFunction = fgets_argument_flow();
    function
        .instructions
        .insert(2, op(0x90c, NirOp::Const, "mov", &["rdi", "0x2a"]));
    let report: TaintReport = analyze(&module(function), &out_argument_config());
    assert!(
        report.is_empty(),
        "killing rdi with an immediate right after the fgets call must sever the out-argument \
         flow the same way an overwrite already severs a return-value flow, reusing the engine's \
         existing def liveness rather than a separate mechanism: {report:?}"
    );
}

#[test]
fn a_declared_out_argument_register_never_established_before_the_call_produces_no_flow() {
    let report: TaintReport = analyze(
        &module(fgets_call_with_no_established_argument()),
        &out_argument_config(),
    );
    assert!(
        report.is_empty(),
        "fgets declares an out-argument at index 0, but nothing in this function ever assigns rdi \
         or rcx before the call, so there is no evidence the compiled code actually passed a \
         pointer there; this is the same absence of evidence a byval struct argument (never a \
         pointer, so never a corroborating setup at this index) and a dead-store-eliminated buffer \
         (the compiler never materializes the argument register at all) both leave behind, so both \
         are covered by refusing to inject a def without corroboration rather than by detecting \
         either shape specifically: {report:?}"
    );
}

#[test]
fn a_source_can_taint_the_return_value_even_when_it_also_declares_an_out_argument() {
    let report: TaintReport = analyze(&module(fgets_return_only_flow()), &out_argument_config());
    assert!(
        report.reaches("fgets", "system"),
        "fgets also still taints its return value, so a flow that only ever moves rax into the \
         sink argument (never establishing rdi as an argument before the call) must still be \
         found: {report:?}"
    );
    assert_eq!(report.count(), 1);
}

#[test]
fn a_source_without_a_declared_out_argument_never_taints_an_argument_register_post_call() {
    let report: TaintReport = analyze(&module(recv_argument_flow()), &config());
    assert!(
        report.is_empty(),
        "recv carries no out-argument declaration, built-in or explicit, so establishing rdi \
         before the call must not manufacture a flow into system: recv's return lands in rax, \
         never rdi, and the only reason rdi would read as tainted is if the engine trusted the \
         table position of a declaration recv never made: {report:?}"
    );
}

#[test]
fn a_write_at_an_indexed_offset_is_still_found_when_the_sink_reads_the_unindexed_base() {
    let report: TaintReport = analyze(
        &module(indexed_write_base_read_flow()),
        &out_argument_config(),
    );
    assert!(
        report.reaches("fgets", "system"),
        "fgets writes through rdi computed as [rsp+r9+30h] (buffer base plus a runtime offset), and \
         the sink later re-derives its own argument as [rsp+30h] (the same buffer's base, no \
         offset); this is the shape every Juliet CWE-78 char/console/system testcase uses (data+len \
         written, data read), so the out-argument def must also land on the reduced base address, \
         not only on the exact indexed expression fgets was called with: {report:?}"
    );
    assert_eq!(report.count(), 1);
}

#[test]
fn overwriting_the_buffer_base_before_the_reload_severs_the_indexed_write_flow() {
    let mut function: NirFunction = indexed_write_base_read_flow();
    function
        .instructions
        .insert(2, op(0xD0C, NirOp::Store, "mov", &["[rsp+30h]", "0x2a"]));
    let report: TaintReport = analyze(&module(function), &out_argument_config());
    assert!(
        report.is_empty(),
        "storing an untainted value to [rsp+30h] between the fgets call and the reload must kill \
         the reduced base-address taint the same way an ordinary store kills any other tracked \
         location, reusing the engine's existing def liveness: {report:?}"
    );
}

#[test]
fn a_custom_out_argument_declaration_at_a_non_zero_index_is_honored() {
    let config: TaintConfig = TaintConfig::new()
        .with_source_out_argument("read", 1)
        .with_sink("system");
    let function: NirFunction = NirFunction {
        name: "handle_read".to_owned(),
        address: 0xC00,
        end: 0xC80,
        is_export: true,
        instructions: vec![
            setup_buffer_argument(0xC00, "rsi"),
            op(
                0xC08,
                NirOp::ExternCall {
                    symbol: "read".to_owned(),
                },
                "call",
                &[],
            ),
            call_system_reading(0xC10, "rsi"),
            op(0xC18, NirOp::Return, "ret", &[]),
        ],
        source: SourceRef::new(SourceLang::NativeX86, 0xC00),
    };
    let report: TaintReport = analyze(&module(function), &config);
    assert!(
        report.reaches("read", "system"),
        "read's second argument (index 1, rsi under system v) is declared as an out-argument by \
         the caller, not by a built-in table entry, and rsi is established right before the call: \
         {report:?}"
    );
}
