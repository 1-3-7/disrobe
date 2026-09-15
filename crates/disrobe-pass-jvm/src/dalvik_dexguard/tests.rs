use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::dalvik::decode_method;
use crate::dalvik_cfg::{build_dalvik_cfg, collect_switch_payloads};
use crate::decompile_struct::Cfg;
use crate::dex::CodeItem;

#[derive(Debug, Clone)]
enum Asm {
    Label(u32),
    Const4 {
        reg: u8,
        value: i32,
    },
    Const16 {
        reg: u8,
        value: i16,
    },
    Goto16 {
        target: u32,
    },
    IfEqz {
        reg: u8,
        target: u32,
    },
    AddIntLit8 {
        dst: u8,
        src: u8,
        lit: i8,
    },
    ReturnVoid,
    Return {
        reg: u8,
    },
    PackedSwitch {
        reg: u8,
        payload: u32,
    },
    PackedSwitchPayload {
        id: u32,
        first_key: i32,
        cases: Vec<u32>,
    },
}

fn width(item: &Asm) -> u32 {
    match item {
        Asm::Label(_) => 0,
        Asm::Const4 { .. } | Asm::ReturnVoid | Asm::Return { .. } => 1,
        Asm::Const16 { .. } | Asm::Goto16 { .. } | Asm::IfEqz { .. } | Asm::AddIntLit8 { .. } => 2,
        Asm::PackedSwitch { .. } => 3,
        Asm::PackedSwitchPayload { cases, .. } => 4 + cases.len() as u32 * 2,
    }
}

fn assemble(items: &[Asm]) -> Vec<u16> {
    let mut label_pc: BTreeMap<u32, u32> = BTreeMap::new();
    let mut payload_pc: BTreeMap<u32, u32> = BTreeMap::new();
    let mut switch_pc_for_payload: BTreeMap<u32, u32> = BTreeMap::new();
    let mut pc: u32 = 0;
    for item in items {
        match item {
            Asm::Label(l) => {
                label_pc.insert(*l, pc);
            }
            Asm::PackedSwitchPayload { id, .. } => {
                payload_pc.insert(*id, pc);
            }
            Asm::PackedSwitch { payload, .. } => {
                switch_pc_for_payload.insert(*payload, pc);
            }
            _ => {}
        }
        pc += width(item);
    }

    let mut out: Vec<u16> = Vec::new();
    let mut here: u32 = 0;
    for item in items {
        match item {
            Asm::Label(_) => {}
            Asm::Const4 { reg, value } => {
                let nibble: u16 = (*value as u16) & 0x0F;
                out.push(0x12 | (u16::from(*reg) << 8) | (nibble << 12));
            }
            Asm::Const16 { reg, value } => {
                out.push(0x13 | (u16::from(*reg) << 8));
                out.push(*value as u16);
            }
            Asm::Goto16 { target } => {
                out.push(0x0029);
                let rel: i32 = label_pc[target] as i32 - here as i32;
                out.push(rel as i16 as u16);
            }
            Asm::IfEqz { reg, target } => {
                out.push(0x38 | (u16::from(*reg) << 8));
                let rel: i32 = label_pc[target] as i32 - here as i32;
                out.push(rel as i16 as u16);
            }
            Asm::AddIntLit8 { dst, src, lit } => {
                out.push(0x00D8 | (u16::from(*dst) << 8));
                out.push(u16::from(*src) | ((*lit as u16 & 0xFF) << 8));
            }
            Asm::ReturnVoid => out.push(0x000E),
            Asm::Return { reg } => out.push(0x000F | (u16::from(*reg) << 8)),
            Asm::PackedSwitch { reg, payload } => {
                out.push(0x002B | (u16::from(*reg) << 8));
                let rel: i32 = payload_pc[payload] as i32 - here as i32;
                out.push((rel as u32 & 0xFFFF) as u16);
                out.push(((rel as u32 >> 16) & 0xFFFF) as u16);
            }
            Asm::PackedSwitchPayload {
                id,
                first_key,
                cases,
            } => {
                let switch_pc: u32 = switch_pc_for_payload[id];
                out.push(0x0100);
                out.push(cases.len() as u16);
                out.push((*first_key as u32 & 0xFFFF) as u16);
                out.push(((*first_key as u32 >> 16) & 0xFFFF) as u16);
                for case in cases {
                    let rel: i32 = label_pc[case] as i32 - switch_pc as i32;
                    out.push((rel as u32 & 0xFFFF) as u16);
                    out.push(((rel as u32 >> 16) & 0xFFFF) as u16);
                }
            }
        }
        here += width(item);
    }
    out
}

fn code_item(insns: Vec<u16>) -> CodeItem {
    CodeItem {
        method_name: "m".to_owned(),
        method_descriptor: "()V".to_owned(),
        class: "LSample;".to_owned(),
        is_direct: true,
        registers_size: 8,
        ins_size: 0,
        outs_size: 0,
        insns,
        tries: Vec::new(),
        param_names: Vec::new(),
    }
}

fn build_cfg_from_units(units: &[u16]) -> (Cfg, Vec<DalvikInsn>) {
    let insns: Vec<DalvikInsn> = decode_method(units);
    let switches: Vec<(u32, SwitchPayload)> = collect_switch_payloads(units, &insns);
    let cfg: Cfg = build_dalvik_cfg(&insns, &[], &switches).expect("clean cfg");
    (cfg, insns)
}

fn is_flattening_machinery(insn: &DalvikInsn, state_regs: &BTreeSet<u16>) -> bool {
    if insn.is_unconditional_goto() || insn.is_switch() {
        return true;
    }
    const_int_to(insn)
        .map(|(dst, _): (u16, i32)| dst)
        .is_some_and(|dst: u16| state_regs.contains(&dst))
}

fn collect_state_regs(insns: &[DalvikInsn], switches: &[(u32, SwitchPayload)]) -> BTreeSet<u16> {
    let _ = switches;
    insns
        .iter()
        .filter(|i: &&DalvikInsn| i.is_switch())
        .filter_map(|i: &DalvikInsn| i.regs.first().copied())
        .collect()
}

fn normalized_opcode_stream(
    cfg: &Cfg,
    insns: &[DalvikInsn],
    state_regs: &BTreeSet<u16>,
) -> Vec<u8> {
    let order: Vec<u32> = reachable_order(cfg);
    let mut start_to_block: BTreeMap<u32, &BasicBlock> = BTreeMap::new();
    for block in &cfg.blocks {
        start_to_block.insert(block.start_pc, block);
    }
    let mut stream: Vec<u8> = Vec::new();
    for start in order {
        let Some(block): Option<&&BasicBlock> = start_to_block.get(&start) else {
            continue;
        };
        let (s, e): (usize, usize) = block.insn_range;
        for insn in &insns[s..e] {
            if is_flattening_machinery(insn, state_regs) {
                continue;
            }
            stream.push(insn.op);
        }
    }
    stream
}

fn clean_opcode_stream(units: &[u16]) -> Vec<u8> {
    let (cfg, insns): (Cfg, Vec<DalvikInsn>) = build_cfg_from_units(units);
    let switches: Vec<(u32, SwitchPayload)> = collect_switch_payloads(units, &insns);
    let state_regs: BTreeSet<u16> = collect_state_regs(&insns, &switches);
    normalized_opcode_stream(&cfg, &insns, &state_regs)
}

fn clean_straight_line() -> Vec<u16> {
    let items: Vec<Asm> = vec![
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 5,
        },
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 7,
        },
        Asm::Return { reg: 0 },
    ];
    assemble(&items)
}

fn flattened_straight_line() -> Vec<u16> {
    const DISPATCH: u32 = 100;
    const PAYLOAD: u32 = 200;
    const B0: u32 = 0;
    const B1: u32 = 1;
    const B2: u32 = 2;
    let items: Vec<Asm> = vec![
        Asm::Const4 { reg: 1, value: 0 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B0),
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 5,
        },
        Asm::Const4 { reg: 1, value: 1 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B1),
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 7,
        },
        Asm::Const4 { reg: 1, value: 2 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B2),
        Asm::Return { reg: 0 },
        Asm::Label(DISPATCH),
        Asm::PackedSwitch {
            reg: 1,
            payload: PAYLOAD,
        },
        Asm::ReturnVoid,
        Asm::Label(PAYLOAD),
        Asm::PackedSwitchPayload {
            id: PAYLOAD,
            first_key: 0,
            cases: vec![B0, B1, B2],
        },
    ];
    assemble(&items)
}

fn flattened_with_opaque_branch() -> Vec<u16> {
    const DISPATCH: u32 = 100;
    const PAYLOAD: u32 = 200;
    const B0: u32 = 0;
    const B1: u32 = 1;
    const EXIT: u32 = 2;
    let items: Vec<Asm> = vec![
        Asm::Const4 { reg: 1, value: 0 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B0),
        Asm::Const4 { reg: 2, value: 0 },
        Asm::IfEqz { reg: 2, target: B1 },
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 9,
        },
        Asm::Label(B1),
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 7,
        },
        Asm::Const4 { reg: 1, value: 1 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(EXIT),
        Asm::Return { reg: 0 },
        Asm::Label(DISPATCH),
        Asm::PackedSwitch {
            reg: 1,
            payload: PAYLOAD,
        },
        Asm::ReturnVoid,
        Asm::Label(PAYLOAD),
        Asm::PackedSwitchPayload {
            id: PAYLOAD,
            first_key: 0,
            cases: vec![B0, EXIT],
        },
    ];
    assemble(&items)
}

fn clean_with_branch_folded() -> Vec<u16> {
    let items: Vec<Asm> = vec![
        Asm::Const4 { reg: 2, value: 0 },
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 7,
        },
        Asm::Return { reg: 0 },
    ];
    assemble(&items)
}

#[test]
fn clean_method_is_not_flagged_flattened() {
    let units: Vec<u16> = clean_straight_line();
    let item: CodeItem = code_item(units);
    let result: DalvikMethodCff = unflatten_code_item(&item).expect("decoded");
    assert!(
        !result.flattened,
        "a straight-line method has no state dispatcher"
    );
    assert_eq!(result.dispatchers_resolved, 0);
}

#[test]
fn flattened_straight_line_unflattens_to_clean_cfg() {
    let flat_units: Vec<u16> = flattened_straight_line();
    let flat_insns: Vec<DalvikInsn> = decode_method(&flat_units);
    let flat_switches: Vec<(u32, SwitchPayload)> =
        collect_switch_payloads(&flat_units, &flat_insns);
    let flat_cfg: Cfg = build_dalvik_cfg(&flat_insns, &[], &flat_switches).expect("flat cfg");
    let pre_dispatchers: Vec<Dispatcher> = find_dispatchers(&flat_cfg, &flat_insns, &flat_switches);
    assert_eq!(
        pre_dispatchers.len(),
        1,
        "the flattened fixture must carry exactly one switch dispatcher"
    );

    let item: CodeItem = code_item(flat_units);
    let result: DalvikMethodCff = unflatten_code_item(&item).expect("decoded");
    assert!(result.flattened, "fixture is a state-dispatcher method");
    assert!(
        result.fully_unflattened,
        "every predecessor const-state must resolve to a real case: {result:?}"
    );
    assert_eq!(
        result.residual_dispatcher_edges, 0,
        "no edge may still target the dispatcher after unflattening"
    );
    assert_eq!(result.dispatchers_resolved, 1);
    assert!(result.edges_redirected >= 3);

    let built: DalvikMethodCfg = build_dalvik_cfg_from_code_item(&item).expect("rebuild");
    let DalvikMethodCfg {
        mut cfg,
        insns,
        switch_payloads,
        ..
    } = built;
    let state_regs: BTreeSet<u16> = collect_state_regs(&insns, &switch_payloads);
    run_unflatten_in_place(&mut cfg, &insns, &switch_payloads);

    let recovered: Vec<u8> = normalized_opcode_stream(&cfg, &insns, &state_regs);
    let clean: Vec<u8> = clean_opcode_stream(&clean_straight_line());
    assert_eq!(
        recovered, clean,
        "recovered linear opcode stream must equal the clean method's own opcode stream"
    );
}

#[test]
fn flattened_with_opaque_predicate_folds_and_unflattens() {
    let item: CodeItem = code_item(flattened_with_opaque_branch());
    let result: DalvikMethodCff = unflatten_code_item(&item).expect("decoded");
    assert!(result.flattened);
    assert!(
        result.dead_branches_folded >= 1,
        "the const-zero if-eqz opaque predicate must be folded: {result:?}"
    );
    assert!(
        result.fully_unflattened,
        "after folding the opaque branch the dispatcher must fully resolve: {result:?}"
    );

    let built: DalvikMethodCfg = build_dalvik_cfg_from_code_item(&item).expect("rebuild");
    let DalvikMethodCfg {
        mut cfg,
        insns,
        switch_payloads,
        ..
    } = built;
    let state_regs: BTreeSet<u16> = collect_state_regs(&insns, &switch_payloads);
    run_unflatten_in_place(&mut cfg, &insns, &switch_payloads);
    let recovered: Vec<u8> = normalized_opcode_stream(&cfg, &insns, &state_regs);
    let clean: Vec<u8> = clean_opcode_stream(&clean_with_branch_folded());
    assert_eq!(
        recovered, clean,
        "opaque-branch path must reduce to the dead-code-eliminated clean opcode stream"
    );
}

fn flattened_const16_state() -> Vec<u16> {
    const DISPATCH: u32 = 100;
    const PAYLOAD: u32 = 200;
    const B0: u32 = 0;
    const B1: u32 = 1;
    const B2: u32 = 2;
    let items: Vec<Asm> = vec![
        Asm::Const16 { reg: 3, value: 0 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B0),
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 5,
        },
        Asm::Const16 { reg: 3, value: 1 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B1),
        Asm::AddIntLit8 {
            dst: 0,
            src: 0,
            lit: 7,
        },
        Asm::Const16 { reg: 3, value: 2 },
        Asm::Goto16 { target: DISPATCH },
        Asm::Label(B2),
        Asm::Return { reg: 0 },
        Asm::Label(DISPATCH),
        Asm::PackedSwitch {
            reg: 3,
            payload: PAYLOAD,
        },
        Asm::ReturnVoid,
        Asm::Label(PAYLOAD),
        Asm::PackedSwitchPayload {
            id: PAYLOAD,
            first_key: 0,
            cases: vec![B0, B1, B2],
        },
    ];
    assemble(&items)
}

#[test]
fn const16_state_writes_resolve() {
    let item: CodeItem = code_item(flattened_const16_state());
    let result: DalvikMethodCff = unflatten_code_item(&item).expect("decoded");
    assert!(result.flattened);
    assert!(
        result.fully_unflattened,
        "16-bit const state writes must resolve to real cases: {result:?}"
    );
    assert_eq!(result.residual_dispatcher_edges, 0);

    let built: DalvikMethodCfg = build_dalvik_cfg_from_code_item(&item).expect("rebuild");
    let DalvikMethodCfg {
        mut cfg,
        insns,
        switch_payloads,
        ..
    } = built;
    let state_regs: BTreeSet<u16> = collect_state_regs(&insns, &switch_payloads);
    run_unflatten_in_place(&mut cfg, &insns, &switch_payloads);
    let recovered: Vec<u8> = normalized_opcode_stream(&cfg, &insns, &state_regs);
    let clean: Vec<u8> = clean_opcode_stream(&clean_straight_line());
    assert_eq!(
        recovered, clean,
        "const/16 state path must recover the same opcode stream as the clean method"
    );
}

#[test]
fn aggregate_counts_one_unflattened_method() {
    let items: Vec<CodeItem> = vec![
        code_item(clean_straight_line()),
        code_item(flattened_straight_line()),
    ];
    let (report, per_method): (DalvikCffReport, Vec<DalvikMethodCff>) =
        unflatten_dex_methods(&items);
    assert_eq!(report.methods_scanned, 2);
    assert_eq!(report.flattened_methods, 1);
    assert_eq!(
        report.methods_unflattened, 1,
        "exactly the flattened method must be fully recovered: {report:?}"
    );
    assert!(report.unhandled_shapes.is_empty());
    assert_eq!(per_method.len(), 1);
}

fn run_unflatten_in_place(cfg: &mut Cfg, insns: &[DalvikInsn], switches: &[(u32, SwitchPayload)]) {
    let folded: u32 = fold_opaque_conditionals(cfg, insns);
    if folded > 0 {
        rebuild_predecessors(cfg);
    }
    let mut rounds: usize = 0;
    loop {
        rounds += 1;
        if rounds > 1024 {
            break;
        }
        let dispatchers: Vec<Dispatcher> = find_dispatchers(cfg, insns, switches);
        if dispatchers.is_empty() {
            break;
        }
        let mut progressed: bool = false;
        let mut stats: ResolveStats = ResolveStats::default();
        for d in &dispatchers {
            if resolve_dispatcher(cfg, insns, d, &mut stats) {
                progressed = true;
            }
        }
        if !progressed {
            break;
        }
        rebuild_predecessors(cfg);
    }
    let _pruned: u32 = prune_unreachable(cfg);
    rebuild_predecessors(cfg);
}
