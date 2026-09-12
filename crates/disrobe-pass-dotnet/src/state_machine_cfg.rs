use std::collections::BTreeSet;

use crate::cfg::{BlockId, Cfg, Terminator};
use crate::cil::{Instruction, MethodBody, OperandValue, SlotOp, slot_index_of};

#[must_use]
pub(crate) fn normalize_move_next(cfg: &mut Cfg, body: &MethodBody) -> bool {
    let Some(state_token): Option<u32> = state_field_token(cfg, body) else {
        return false;
    };
    if reweave_suspends(cfg, body, state_token) {
        return true;
    }
    let dispatch: BTreeSet<BlockId> = dispatch_region(cfg, body, state_token);
    if dispatch.is_empty() {
        return false;
    }
    let resume_blocks: Vec<BlockId> = resume_targets(cfg, body, state_token, &dispatch);
    if resume_blocks.is_empty() {
        return false;
    }
    let preserved: BTreeSet<BlockId> = (0..cfg.blocks.len())
        .filter(|&b: &BlockId| {
            cfg.is_reachable(b) && !dispatch.contains(&b) && !resume_blocks.contains(&b)
        })
        .collect();
    let loops_before: usize = cfg.loops.len();

    let mut candidate: Cfg = cfg.clone();
    for &r in &resume_blocks {
        let entries: Vec<BlockId> = candidate.blocks[r]
            .preds
            .iter()
            .copied()
            .filter(|p: &BlockId| dispatch.contains(p))
            .collect();
        for from in entries {
            candidate.cut_edge(from, r);
        }
        let outs: Vec<BlockId> = candidate.blocks[r].succs.clone();
        for to in outs {
            candidate.cut_edge(r, to);
        }
    }
    candidate.recompute_derived();

    let formed_loop: bool = candidate.loops.len() > loops_before;
    let body_intact: bool = preserved
        .iter()
        .all(|&b: &BlockId| candidate.is_reachable(b));
    if !formed_loop || !body_intact {
        return false;
    }
    *cfg = candidate;
    true
}

const STATE_RUNNING: i64 = -1;
const STATE_FINISHED: i64 = -2;

fn reweave_suspends(cfg: &mut Cfg, body: &MethodBody, state_token: u32) -> bool {
    let Some(mirror): Option<u16> = state_mirror_local(cfg, body, state_token) else {
        return false;
    };
    let dispatch: BTreeSet<BlockId> = dispatch_blocks(cfg, body, mirror);
    if dispatch.is_empty() {
        return false;
    }
    let decoded: Vec<(i64, BlockId)> = decode_dispatch(cfg, body, &dispatch);
    if decoded.is_empty() {
        return false;
    }
    let suspends: Vec<(BlockId, i64)> = find_suspends(cfg, body, state_token, &decoded);
    if suspends.is_empty() {
        return false;
    }
    let resume_candidates: Vec<(i64, BlockId)> = decoded
        .iter()
        .copied()
        .filter(|(v, _): &(i64, BlockId)| suspends.iter().any(|(_, sv): &(BlockId, i64)| sv == v))
        .collect();
    if resume_candidates.is_empty() {
        return false;
    }
    let resume_map: Vec<(i64, BlockId)> =
        restore_per_value(cfg, body, state_token, &resume_candidates);
    let initial: Option<BlockId> = initial_path_target(cfg, &dispatch, &resume_candidates);
    let Some(initial): Option<BlockId> = initial else {
        return false;
    };
    let body_blocks: BTreeSet<BlockId> = (0..cfg.blocks.len())
        .filter(|&b: &BlockId| cfg.is_reachable(b) && !dispatch.contains(&b))
        .collect();

    let mut candidate: Cfg = cfg.clone();
    for &(suspend, state_value) in &suspends {
        let Some(&(_, resume)): Option<&(i64, BlockId)> = resume_map
            .iter()
            .find(|(v, _): &&(i64, BlockId)| *v == state_value)
        else {
            continue;
        };
        candidate.retarget_to_goto(suspend, resume);
    }
    for &d in &dispatch {
        let fresh: BlockId = fresh_successor(cfg, body, d, initial, &resume_candidates);
        candidate.retarget_to_goto(d, fresh);
    }
    candidate.recompute_derived();

    let body_intact: bool = body_blocks.iter().all(|&b: &BlockId| {
        candidate.is_reachable(b)
            || is_plumbing_tail(cfg, body, b)
            || is_trivial_const_return_tail(cfg, body, b)
    });
    let resume_reachable: bool = resume_map
        .iter()
        .all(|(_, r): &(i64, BlockId)| candidate.is_reachable(*r));
    if !body_intact || !resume_reachable {
        return false;
    }
    *cfg = candidate;
    true
}

fn state_mirror_local(cfg: &Cfg, body: &MethodBody, state_token: u32) -> Option<u16> {
    let entry: &[Instruction] = block_instrs(cfg, body, cfg.entry);
    for window in entry.windows(3) {
        if window[0].name == "ldarg.0"
            && window[1].name == "ldfld"
            && window[1].operand == OperandValue::Token(state_token)
        {
            return stloc_slot(&window[2]);
        }
    }
    None
}

fn stloc_slot(ins: &Instruction) -> Option<u16> {
    slot_index_of(ins, SlotOp::StoreLocal)
}

fn ldloc_slot(ins: &Instruction) -> Option<u16> {
    slot_index_of(ins, SlotOp::LoadLocal)
}

fn dispatch_blocks(cfg: &Cfg, body: &MethodBody, mirror: u16) -> BTreeSet<BlockId> {
    let mut out: BTreeSet<BlockId> = BTreeSet::new();
    for bid in 0..cfg.blocks.len() {
        if !cfg.is_reachable(bid) {
            continue;
        }
        if !matches!(
            cfg.terminators[bid],
            Terminator::Switch { .. } | Terminator::Cond { .. }
        ) {
            continue;
        }
        let instrs: &[Instruction] = block_instrs(cfg, body, bid);
        let tests_mirror: bool = instrs
            .iter()
            .any(|ins: &Instruction| ldloc_slot(ins) == Some(mirror));
        let does_real_work: bool = instrs.iter().any(|ins: &Instruction| {
            matches!(ins.name.as_str(), "call" | "callvirt" | "newobj" | "stfld")
        });
        if tests_mirror && !does_real_work {
            out.insert(bid);
        }
    }
    out
}

fn decode_dispatch(
    cfg: &Cfg,
    body: &MethodBody,
    dispatch: &BTreeSet<BlockId>,
) -> Vec<(i64, BlockId)> {
    let mut out: Vec<(i64, BlockId)> = Vec::new();
    for &d in dispatch {
        let instrs: &[Instruction] = block_instrs(cfg, body, d);
        match &cfg.terminators[d] {
            Terminator::Switch { cases, fallthrough } => {
                let base: i64 = switch_base_offset(instrs);
                for (idx, &target) in cases.iter().enumerate() {
                    let value: i64 = i64::try_from(idx).unwrap_or(0) + base;
                    if is_resume_state(value)
                        && target != *fallthrough
                        && !dispatch.contains(&target)
                    {
                        push_unique(&mut out, value, target);
                    }
                }
            }
            Terminator::Cond { taken, fallthrough } => {
                if let Some((value, on_equal)) = cond_state_value(instrs) {
                    let target: BlockId = if on_equal { *taken } else { *fallthrough };
                    if is_resume_state(value) && !dispatch.contains(&target) {
                        push_unique(&mut out, value, target);
                    }
                }
            }
            _ => {}
        }
    }
    out
}

fn push_unique(out: &mut Vec<(i64, BlockId)>, value: i64, target: BlockId) {
    if !out
        .iter()
        .any(|&(v, t): &(i64, BlockId)| v == value && t == target)
    {
        out.push((value, target));
    }
}

const fn is_resume_state(value: i64) -> bool {
    value != STATE_RUNNING && value != STATE_FINISHED
}

fn restore_per_value(
    cfg: &Cfg,
    body: &MethodBody,
    state_token: u32,
    candidates: &[(i64, BlockId)],
) -> Vec<(i64, BlockId)> {
    let mut out: Vec<(i64, BlockId)> = Vec::new();
    for &(value, _) in candidates {
        if out.iter().any(|&(v, _): &(i64, BlockId)| v == value) {
            continue;
        }
        let targets: Vec<BlockId> = candidates
            .iter()
            .filter(|&&(v, _): &&(i64, BlockId)| v == value)
            .map(|&(_, t): &(i64, BlockId)| t)
            .collect();
        let restore: BlockId = targets
            .iter()
            .copied()
            .find(|&t: &BlockId| resets_state_to_running(cfg, body, t, state_token))
            .or_else(|| targets.first().copied())
            .unwrap_or(0);
        out.push((value, restore));
    }
    out
}

fn resets_state_to_running(cfg: &Cfg, body: &MethodBody, bid: BlockId, state_token: u32) -> bool {
    bid < cfg.blocks.len() && stores_running_state(block_instrs(cfg, body, bid), state_token)
}

fn fresh_successor(
    cfg: &Cfg,
    body: &MethodBody,
    dispatch_block: BlockId,
    initial: BlockId,
    candidates: &[(i64, BlockId)],
) -> BlockId {
    let instrs: &[Instruction] = block_instrs(cfg, body, dispatch_block);
    match &cfg.terminators[dispatch_block] {
        Terminator::Cond { taken, fallthrough } => {
            let Some((_, on_equal)): Option<(i64, bool)> = cond_state_value(instrs) else {
                return initial;
            };
            let (match_edge, other_edge): (BlockId, BlockId) = if on_equal {
                (*taken, *fallthrough)
            } else {
                (*fallthrough, *taken)
            };
            if reaches_initial_directly(cfg, match_edge, initial, candidates) {
                match_edge
            } else {
                other_edge
            }
        }
        Terminator::Switch { fallthrough, .. } => *fallthrough,
        Terminator::Goto(t) | Terminator::FallThrough(t) => *t,
        _ => initial,
    }
}

fn reaches_initial_directly(
    cfg: &Cfg,
    start: BlockId,
    initial: BlockId,
    candidates: &[(i64, BlockId)],
) -> bool {
    let is_resume_target = |b: BlockId| candidates.iter().any(|&(_, t): &(i64, BlockId)| t == b);
    let mut cur: BlockId = start;
    for _ in 0..cfg.blocks.len() {
        if cur == initial {
            return true;
        }
        if is_resume_target(cur) {
            return false;
        }
        match &cfg.terminators[cur] {
            Terminator::Goto(next) | Terminator::FallThrough(next) => cur = *next,
            _ => return false,
        }
    }
    false
}

fn switch_base_offset(instrs: &[Instruction]) -> i64 {
    for window in instrs.windows(2) {
        if window[1].name == "sub"
            && let Some(c) = const_value(&window[0])
        {
            return c;
        }
        if window[1].name == "add"
            && let Some(c) = const_value(&window[0])
        {
            return -c;
        }
    }
    0
}

fn cond_state_value(instrs: &[Instruction]) -> Option<(i64, bool)> {
    let last: &Instruction = instrs.last()?;
    match last.name.as_str() {
        "brfalse" | "brfalse.s" => Some((0, true)),
        "brtrue" | "brtrue.s" => Some((0, false)),
        "beq" | "beq.s" => {
            let c: i64 = const_value(&instrs[instrs.len().checked_sub(2)?])?;
            Some((c, true))
        }
        "bne.un" | "bne.un.s" => {
            let c: i64 = const_value(&instrs[instrs.len().checked_sub(2)?])?;
            Some((c, false))
        }
        _ => None,
    }
}

fn const_value(ins: &Instruction) -> Option<i64> {
    match ins.name.as_str() {
        "ldc.i4.m1" => Some(-1),
        "ldc.i4.0" => Some(0),
        "ldc.i4.1" => Some(1),
        "ldc.i4.2" => Some(2),
        "ldc.i4.3" => Some(3),
        "ldc.i4.4" => Some(4),
        "ldc.i4.5" => Some(5),
        "ldc.i4.6" => Some(6),
        "ldc.i4.7" => Some(7),
        "ldc.i4.8" => Some(8),
        "ldc.i4.s" => match ins.operand {
            OperandValue::U8(v) => Some(i64::from(v.cast_signed())),
            OperandValue::I32(v) => Some(i64::from(v)),
            _ => None,
        },
        "ldc.i4" => match ins.operand {
            OperandValue::I32(v) => Some(i64::from(v)),
            _ => None,
        },
        _ => None,
    }
}

fn find_suspends(
    cfg: &Cfg,
    body: &MethodBody,
    state_token: u32,
    resume_map: &[(i64, BlockId)],
) -> Vec<(BlockId, i64)> {
    let mut out: Vec<(BlockId, i64)> = Vec::new();
    for bid in 0..cfg.blocks.len() {
        if !cfg.is_reachable(bid) || !leads_to_exit(cfg, bid) {
            continue;
        }
        let Some(value): Option<i64> =
            stored_state_value(block_instrs(cfg, body, bid), state_token)
        else {
            continue;
        };
        if resume_map.iter().any(|(v, _): &(i64, BlockId)| *v == value) {
            out.push((bid, value));
        }
    }
    out
}

fn is_plumbing_tail(cfg: &Cfg, body: &MethodBody, bid: BlockId) -> bool {
    if !leads_to_exit(cfg, bid) {
        return false;
    }
    let instrs: &[Instruction] = block_instrs(cfg, body, bid);
    let mut calls: usize = 0;
    for ins in instrs {
        match ins.name.as_str() {
            "call" | "callvirt" => calls += 1,
            "stfld" | "stsfld" | "newobj" | "stelem" | "stind.ref" | "throw" => return false,
            _ if ins.name.starts_with("stloc") => return false,
            _ => {}
        }
    }
    calls <= 1
}

fn is_trivial_const_return_tail(cfg: &Cfg, body: &MethodBody, bid: BlockId) -> bool {
    if !leads_to_exit(cfg, bid) {
        return false;
    }
    let instrs: &[Instruction] = block_instrs(cfg, body, bid);
    let mut saw_const: bool = false;
    let mut stores: usize = 0;
    for ins in instrs {
        if const_value(ins).is_some() {
            saw_const = true;
            continue;
        }
        match ins.name.as_str() {
            "dup" | "nop" | "br" | "br.s" | "leave" | "leave.s" | "ret" | "ldloc.0" | "ldloc.1"
            | "ldloc.2" | "ldloc.3" | "ldloc.s" => {}
            "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "stloc" => stores += 1,
            _ => return false,
        }
    }
    saw_const && stores <= 1
}

fn leads_to_exit(cfg: &Cfg, bid: BlockId) -> bool {
    let mut cur: BlockId = bid;
    for _ in 0..cfg.blocks.len() {
        match &cfg.terminators[cur] {
            Terminator::Return | Terminator::EndFinally => return true,
            Terminator::Goto(next) | Terminator::FallThrough(next) => cur = *next,
            _ => return false,
        }
    }
    false
}

fn stored_state_value(instrs: &[Instruction], state_token: u32) -> Option<i64> {
    let mut last_const: Option<i64> = None;
    let mut found: Option<i64> = None;
    for ins in instrs {
        if let Some(c) = const_value(ins) {
            last_const = Some(c);
            continue;
        }
        if ins.name == "stfld" && ins.operand == OperandValue::Token(state_token) {
            if let Some(c) = last_const {
                found = Some(c);
            }
            last_const = None;
            continue;
        }
        if !matches!(
            ins.name.as_str(),
            "dup" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "ldarg.0"
        ) {
            last_const = None;
        }
    }
    found.filter(|&v: &i64| is_resume_state(v))
}

fn initial_path_target(
    cfg: &Cfg,
    dispatch: &BTreeSet<BlockId>,
    resume_map: &[(i64, BlockId)],
) -> Option<BlockId> {
    let resume_set: BTreeSet<BlockId> = resume_map
        .iter()
        .map(|(_, b): &(i64, BlockId)| *b)
        .collect();
    for &d in dispatch {
        if let Terminator::Switch { fallthrough, .. } = &cfg.terminators[d]
            && !dispatch.contains(fallthrough)
            && !resume_set.contains(fallthrough)
        {
            return Some(*fallthrough);
        }
    }
    for &d in dispatch {
        for &s in &cfg.blocks[d].succs {
            if !dispatch.contains(&s) && !resume_set.contains(&s) {
                return Some(s);
            }
        }
    }
    None
}

fn block_instrs<'b>(cfg: &Cfg, body: &'b MethodBody, bid: BlockId) -> &'b [Instruction] {
    let blk: &crate::cfg::BasicBlock = &cfg.blocks[bid];
    &body.instructions[blk.first..=blk.last]
}

fn state_field_token(cfg: &Cfg, body: &MethodBody) -> Option<u32> {
    let entry: &[Instruction] = block_instrs(cfg, body, cfg.entry);
    let mut candidate: Option<u32> = None;
    for pair in entry.windows(2) {
        if pair[0].name == "ldarg.0"
            && pair[1].name == "ldfld"
            && let OperandValue::Token(tok) = pair[1].operand
        {
            candidate = Some(tok);
            break;
        }
    }
    let tok: u32 = candidate?;
    stores_running_state(&body.instructions, tok).then_some(tok)
}

fn stores_running_state(instrs: &[Instruction], state_token: u32) -> bool {
    let mut saw_neg: bool = false;
    for ins in instrs {
        let stores_state: bool =
            ins.name == "stfld" && ins.operand == OperandValue::Token(state_token);
        if saw_neg && stores_state {
            return true;
        }
        if is_neg_state_const(ins) {
            saw_neg = true;
        } else if !is_stack_passthrough(ins) {
            saw_neg = false;
        }
    }
    false
}

fn is_stack_passthrough(ins: &Instruction) -> bool {
    matches!(
        ins.name.as_str(),
        "dup" | "stloc.0" | "stloc.1" | "stloc.2" | "stloc.3" | "stloc.s" | "ldarg.0"
    )
}

fn is_neg_state_const(ins: &Instruction) -> bool {
    match ins.name.as_str() {
        "ldc.i4.m1" => true,
        "ldc.i4.s" => matches!(ins.operand, OperandValue::U8(254)),
        "ldc.i4" => matches!(ins.operand, OperandValue::I32(-1 | -2)),
        _ => false,
    }
}

fn is_dispatch_only(cfg: &Cfg, body: &MethodBody, bid: BlockId, state_token: u32) -> bool {
    block_instrs(cfg, body, bid)
        .iter()
        .all(|ins: &Instruction| {
            matches!(
                ins.name.as_str(),
                "ldarg.0"
                    | "stloc.0"
                    | "stloc.1"
                    | "stloc.2"
                    | "stloc.3"
                    | "stloc.s"
                    | "ldloc.0"
                    | "ldloc.1"
                    | "ldloc.2"
                    | "ldloc.3"
                    | "ldloc.s"
                    | "dup"
                    | "sub"
                    | "ldc.i4.0"
                    | "ldc.i4.1"
                    | "ldc.i4.2"
                    | "ldc.i4.3"
                    | "ldc.i4.4"
                    | "ldc.i4.5"
                    | "ldc.i4.6"
                    | "ldc.i4.7"
                    | "ldc.i4.8"
                    | "ldc.i4.m1"
                    | "ldc.i4.s"
                    | "ldc.i4"
                    | "beq"
                    | "beq.s"
                    | "bne.un"
                    | "bne.un.s"
                    | "brtrue"
                    | "brtrue.s"
                    | "brfalse"
                    | "brfalse.s"
                    | "br"
                    | "br.s"
                    | "switch"
                    | "ret"
            ) || (ins.name == "ldfld" && ins.operand == OperandValue::Token(state_token))
        })
}

fn dispatch_region(cfg: &Cfg, body: &MethodBody, state_token: u32) -> BTreeSet<BlockId> {
    if !is_dispatch_only(cfg, body, cfg.entry, state_token) {
        return BTreeSet::new();
    }
    let mut region: BTreeSet<BlockId> = BTreeSet::new();
    let mut work: Vec<BlockId> = vec![cfg.entry];
    region.insert(cfg.entry);
    while let Some(b) = work.pop() {
        for &s in &cfg.blocks[b].succs {
            if !region.contains(&s) && is_dispatch_only(cfg, body, s, state_token) {
                region.insert(s);
                work.push(s);
            }
        }
    }
    region
}

fn resume_targets(
    cfg: &Cfg,
    body: &MethodBody,
    state_token: u32,
    dispatch: &BTreeSet<BlockId>,
) -> Vec<BlockId> {
    let mut targets: Vec<BlockId> = Vec::new();
    for &d in dispatch {
        for &s in &cfg.blocks[d].succs {
            if dispatch.contains(&s) {
                continue;
            }
            if is_resume_block(cfg, body, s, state_token) && !targets.contains(&s) {
                targets.push(s);
            }
        }
    }
    targets
}

fn is_resume_block(cfg: &Cfg, body: &MethodBody, bid: BlockId, state_token: u32) -> bool {
    let instrs: &[Instruction] = block_instrs(cfg, body, bid);
    if !stores_running_state(instrs, state_token) {
        return false;
    }
    let initializes_loop_var: bool = instrs.windows(2).any(|p: &[Instruction]| {
        p[0].name == "ldc.i4.0"
            && p[1].name == "stfld"
            && p[1].operand != OperandValue::Token(state_token)
    });
    let exits_to_loop: bool = matches!(
        cfg.terminators[bid],
        Terminator::FallThrough(_) | Terminator::Goto(_)
    );
    !initializes_loop_var && exits_to_loop
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn ins(name: &str, operand: OperandValue) -> Instruction {
        Instruction {
            offset: 0,
            opcode: 0,
            name: name.to_owned(),
            operand,
            flow: crate::cil::FlowControl::Next,
        }
    }

    fn flow_for(name: &str) -> crate::cil::FlowControl {
        match name {
            "ret" => crate::cil::FlowControl::Return,
            "leave" | "leave.s" | "br" | "br.s" => crate::cil::FlowControl::Branch,
            _ => crate::cil::FlowControl::Next,
        }
    }

    fn single_block_cfg(named: &[(&str, OperandValue)]) -> (Cfg, MethodBody) {
        let instructions: Vec<Instruction> = named
            .iter()
            .enumerate()
            .map(
                |(i, (name, operand)): (usize, &(&str, OperandValue))| Instruction {
                    offset: i as u32,
                    opcode: 0,
                    name: (*name).to_owned(),
                    operand: operand.clone(),
                    flow: flow_for(name),
                },
            )
            .collect();
        let body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: instructions.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions,
            exception_clauses: Vec::new(),
        };
        let cfg: Cfg = Cfg::build(&body);
        (cfg, body)
    }

    #[test]
    fn trivial_const_return_tail_accepts_const_store_leave() {
        let (cfg, body): (Cfg, MethodBody) = single_block_cfg(&[
            ("ldc.i4.0", OperandValue::None),
            ("stloc.0", OperandValue::None),
            ("ret", OperandValue::None),
        ]);
        assert!(is_trivial_const_return_tail(&cfg, &body, 0));
    }

    #[test]
    fn trivial_const_return_tail_rejects_real_work() {
        let token: u32 = 0x0400_0001;
        let (cfg, body): (Cfg, MethodBody) = single_block_cfg(&[
            ("ldc.i4.0", OperandValue::None),
            ("stfld", OperandValue::Token(token)),
            ("ret", OperandValue::None),
        ]);
        assert!(!is_trivial_const_return_tail(&cfg, &body, 0));

        let (cfg2, body2): (Cfg, MethodBody) = single_block_cfg(&[
            ("ldarg.0", OperandValue::None),
            ("call", OperandValue::Token(token)),
            ("ret", OperandValue::None),
        ]);
        assert!(!is_trivial_const_return_tail(&cfg2, &body2, 0));
    }

    #[test]
    fn restore_per_value_prefers_the_state_resetting_target() {
        let token: u32 = 0x0400_00AF;
        let region_head: Vec<Instruction> = vec![ins("nop", OperandValue::None)];
        let restore: Vec<Instruction> = vec![
            ins("ldarg.0", OperandValue::None),
            ins("ldc.i4.m1", OperandValue::None),
            ins("stfld", OperandValue::Token(token)),
        ];
        let body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: 8,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: region_head.into_iter().chain(restore).collect(),
            exception_clauses: Vec::new(),
        };
        let mut cfg: Cfg = Cfg::build(&body);
        cfg.blocks = vec![
            crate::cfg::BasicBlock {
                start: 0,
                first: 0,
                last: 0,
                succs: vec![],
                preds: vec![],
            },
            crate::cfg::BasicBlock {
                start: 1,
                first: 1,
                last: 3,
                succs: vec![],
                preds: vec![],
            },
        ];
        cfg.terminators = vec![Terminator::Return, Terminator::Return];
        cfg.postorder_num = vec![1, 0];
        let candidates: Vec<(i64, BlockId)> = vec![(0, 0), (0, 1)];
        let picked: Vec<(i64, BlockId)> = restore_per_value(&cfg, &body, token, &candidates);
        assert_eq!(picked, vec![(0, 1)]);
    }

    #[test]
    fn const_value_sign_extends_short_form() {
        assert_eq!(const_value(&ins("ldc.i4.m1", OperandValue::None)), Some(-1));
        assert_eq!(
            const_value(&ins("ldc.i4.s", OperandValue::U8(252))),
            Some(-4)
        );
        assert_eq!(const_value(&ins("ldc.i4", OperandValue::I32(7))), Some(7));
        assert_eq!(const_value(&ins("ldc.i4.0", OperandValue::None)), Some(0));
    }

    #[test]
    fn switch_base_offset_decodes_sub_constant() {
        let block: Vec<Instruction> = vec![
            ins("ldloc.0", OperandValue::None),
            ins("ldc.i4.s", OperandValue::U8(252)),
            ins("sub", OperandValue::None),
            ins("switch", OperandValue::Switch(vec![0, 0])),
        ];
        assert_eq!(switch_base_offset(&block), -4);
    }

    #[test]
    fn resume_states_exclude_running_and_finished() {
        assert!(!is_resume_state(STATE_RUNNING));
        assert!(!is_resume_state(STATE_FINISHED));
        assert!(is_resume_state(0));
        assert!(is_resume_state(1));
        assert!(is_resume_state(-4));
    }

    #[test]
    fn cond_state_value_reads_beq_constant() {
        let block: Vec<Instruction> = vec![
            ins("ldloc.0", OperandValue::None),
            ins("ldc.i4.1", OperandValue::None),
            ins("beq.s", OperandValue::BrTarget(2)),
        ];
        assert_eq!(cond_state_value(&block), Some((1, true)));
    }

    #[test]
    fn stored_state_value_finds_const_before_state_store() {
        let token: u32 = 0x0400_00AF;
        let block: Vec<Instruction> = vec![
            ins("ldarg.0", OperandValue::None),
            ins("ldc.i4.s", OperandValue::U8(252)),
            ins("dup", OperandValue::None),
            ins("stloc.0", OperandValue::None),
            ins("stfld", OperandValue::Token(token)),
        ];
        assert_eq!(stored_state_value(&block, token), Some(-4));
    }
}
