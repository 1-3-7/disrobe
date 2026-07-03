use serde::Serialize;
use walrus::ir::{BinaryOp, Instr, InstrSeqId, InstrSeqType, UnaryOp, Value};
use walrus::{FunctionId, FunctionKind, LocalFunction, Module};

use super::RecoveryReport;
use super::pure_eval::{PureModule, Scalar};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollatzWitness {
    pub seed: i64,
    pub steps: u32,
    pub reached_one: bool,
}

const COLLATZ_MAX_STEPS: u32 = 1_000;

pub(super) fn fold_constant_branches(func: &mut LocalFunction, report: &mut RecoveryReport) {
    let seq_ids: Vec<InstrSeqId> = super::collect_seq_ids(func);
    for seq_id in seq_ids {
        fold_seq(func, seq_id, report);
    }
}

fn fold_seq(func: &mut LocalFunction, seq_id: InstrSeqId, report: &mut RecoveryReport) {
    let instrs: Vec<Instr> = func
        .block(seq_id)
        .instrs
        .iter()
        .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let mut decisions: Vec<Decision> = Vec::new();
    for (idx, instr) in instrs.iter().enumerate() {
        let Instr::IfElse(ifelse): &Instr = instr else {
            continue;
        };
        let Some(verdict): Option<ConstVerdict> = const_condition(&instrs, idx) else {
            continue;
        };
        let taken: InstrSeqId = if verdict.value != 0 {
            ifelse.consequent
        } else {
            ifelse.alternative
        };
        decisions.push(Decision {
            if_index: idx,
            cond_start: verdict.cond_start,
            taken,
            collatz: verdict.collatz,
        });
    }
    if decisions.is_empty() {
        return;
    }
    decisions.sort_by_key(|decision: &Decision| std::cmp::Reverse(decision.if_index));
    for decision in decisions {
        apply_decision(func, seq_id, &decision, report);
    }
}

#[derive(Debug, Clone)]
struct Decision {
    if_index: usize,
    cond_start: usize,
    taken: InstrSeqId,
    collatz: Option<CollatzWitness>,
}

fn apply_decision(
    func: &mut LocalFunction,
    seq_id: InstrSeqId,
    decision: &Decision,
    report: &mut RecoveryReport,
) {
    let taken_body: Vec<(Instr, walrus::ir::InstrLocId)> =
        func.block(decision.taken).instrs.clone();
    let seq: &mut walrus::ir::InstrSeq = func.block_mut(seq_id);
    if decision.if_index >= seq.instrs.len() || decision.cond_start > decision.if_index {
        return;
    }
    let loc: walrus::ir::InstrLocId = seq.instrs[decision.if_index].1;
    let tail: Vec<(Instr, walrus::ir::InstrLocId)> = seq.instrs.split_off(decision.if_index + 1);
    seq.instrs.truncate(decision.cond_start);
    for (instr, _) in taken_body {
        seq.instrs.push((instr, loc));
    }
    seq.instrs.extend(tail);
    if decision.collatz.is_some() {
        report.collatz_predicates_removed += 1;
        if let Some(witness) = &decision.collatz {
            report.collatz_witnesses.push(witness.clone());
        }
    } else {
        report.opaque_predicates_removed += 1;
    }
}

#[derive(Debug, Clone)]
struct ConstVerdict {
    value: i32,
    cond_start: usize,
    collatz: Option<CollatzWitness>,
}

fn const_condition(instrs: &[Instr], if_index: usize) -> Option<ConstVerdict> {
    let collatz: Option<ConstVerdict> = collatz_condition(instrs, if_index);
    if let Some(collatz) = collatz {
        return Some(collatz);
    }
    let mut cursor: usize = if_index;
    let mut budget: usize = 64;
    let value: i32 = eval_value(instrs, &mut cursor, &mut budget)?;
    Some(ConstVerdict {
        value,
        cond_start: cursor,
        collatz: None,
    })
}

fn eval_value(instrs: &[Instr], cursor: &mut usize, budget: &mut usize) -> Option<i32> {
    if *cursor == 0 || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let idx: usize = *cursor - 1;
    match instrs.get(idx)? {
        Instr::Const(c) => match c.value {
            Value::I32(v) => {
                *cursor -= 1;
                Some(v)
            }
            _ => None,
        },
        Instr::Unop(u) => {
            *cursor -= 1;
            let inner: i32 = eval_value(instrs, cursor, budget)?;
            eval_unop(u.op, inner)
        }
        Instr::Binop(b) => {
            *cursor -= 1;
            let rhs: i32 = eval_value(instrs, cursor, budget)?;
            let lhs: i32 = eval_value(instrs, cursor, budget)?;
            eval_binop(b.op, lhs, rhs)
        }
        _ => None,
    }
}

fn eval_unop(op: UnaryOp, value: i32) -> Option<i32> {
    Some(match op {
        UnaryOp::I32Eqz => i32::from(value == 0),
        _ => return None,
    })
}

fn eval_binop(op: BinaryOp, a: i32, b: i32) -> Option<i32> {
    let ua: u32 = a.cast_unsigned();
    let ub: u32 = b.cast_unsigned();
    Some(match op {
        BinaryOp::I32Add => a.wrapping_add(b),
        BinaryOp::I32Sub => a.wrapping_sub(b),
        BinaryOp::I32Mul => a.wrapping_mul(b),
        BinaryOp::I32DivS => a.checked_div(b)?,
        BinaryOp::I32DivU => ua.checked_div(ub)?.cast_signed(),
        BinaryOp::I32RemS => a.checked_rem(b)?,
        BinaryOp::I32RemU => ua.checked_rem(ub)?.cast_signed(),
        BinaryOp::I32And => a & b,
        BinaryOp::I32Or => a | b,
        BinaryOp::I32Xor => a ^ b,
        BinaryOp::I32Shl => a.wrapping_shl(ub & 31),
        BinaryOp::I32ShrU => ua.wrapping_shr(ub & 31).cast_signed(),
        BinaryOp::I32ShrS => a.wrapping_shr(ub & 31),
        BinaryOp::I32Rotl => a.rotate_left(ub & 31),
        BinaryOp::I32Rotr => a.rotate_right(ub & 31),
        BinaryOp::I32Eq => i32::from(a == b),
        BinaryOp::I32Ne => i32::from(a != b),
        BinaryOp::I32LtS => i32::from(a < b),
        BinaryOp::I32LtU => i32::from(ua < ub),
        BinaryOp::I32GtS => i32::from(a > b),
        BinaryOp::I32GtU => i32::from(ua > ub),
        BinaryOp::I32LeS => i32::from(a <= b),
        BinaryOp::I32LeU => i32::from(ua <= ub),
        BinaryOp::I32GeS => i32::from(a >= b),
        BinaryOp::I32GeU => i32::from(ua >= ub),
        _ => return None,
    })
}

fn collatz_condition(instrs: &[Instr], if_index: usize) -> Option<ConstVerdict> {
    let cmp: &Instr = instrs.get(if_index.checked_sub(1)?)?;
    let BinaryOp::I32Eq = binop_of(cmp)? else {
        return None;
    };
    let one: &Instr = instrs.get(if_index.checked_sub(2)?)?;
    if !is_i32_const(one, 1) {
        return None;
    }
    let cursor: usize = if_index - 2;
    let mut budget: usize = 96;
    let (seed, start): (i64, usize) = collatz_chain(instrs, cursor, &mut budget)?;
    let (steps, reached): (u32, bool) = run_collatz(seed);
    if !reached {
        return None;
    }
    Some(ConstVerdict {
        value: 1,
        cond_start: start,
        collatz: Some(CollatzWitness {
            seed,
            steps,
            reached_one: true,
        }),
    })
}

fn collatz_chain(instrs: &[Instr], cursor: usize, budget: &mut usize) -> Option<(i64, usize)> {
    let mut value: Option<i64> = None;
    let start: usize = scan_collatz_seed(instrs, cursor, budget, &mut value)?;
    Some((value?, start))
}

fn scan_collatz_seed(
    instrs: &[Instr],
    cursor: usize,
    budget: &mut usize,
    value: &mut Option<i64>,
) -> Option<usize> {
    let mut local_cursor: usize = cursor;
    while local_cursor > 0 && *budget > 0 {
        *budget -= 1;
        let idx: usize = local_cursor - 1;
        match instrs.get(idx)? {
            Instr::Const(c) => {
                if let Value::I32(v) = c.value {
                    *value = Some(i64::from(v));
                    return Some(idx);
                }
                return None;
            }
            Instr::Binop(_) | Instr::Unop(_) | Instr::Call(_) => {
                local_cursor -= 1;
            }
            _ => return None,
        }
    }
    None
}

fn run_collatz(seed: i64) -> (u32, bool) {
    if seed <= 0 {
        return (0, false);
    }
    let mut value: u64 = seed.cast_unsigned();
    let mut steps: u32 = 0;
    while value != 1 && steps < COLLATZ_MAX_STEPS {
        value = if value.is_multiple_of(2) {
            value / 2
        } else {
            match value.checked_mul(3).and_then(|v| v.checked_add(1)) {
                Some(v) => v,
                None => return (steps, false),
            }
        };
        steps += 1;
    }
    (steps, value == 1)
}

const fn binop_of(instr: &Instr) -> Option<BinaryOp> {
    match instr {
        Instr::Binop(b) => Some(b.op),
        _ => None,
    }
}

const fn is_i32_const(instr: &Instr, expected: i32) -> bool {
    matches!(instr, Instr::Const(c) if matches!(c.value, Value::I32(v) if v == expected))
}

const MAX_GUARD_LEN: usize = 64;

pub(super) fn fold_interprocedural(module: &mut Module, report: &mut RecoveryReport) {
    let snapshot: PureModule = PureModule::snapshot(module);
    let local_ids: Vec<FunctionId> = module.funcs.iter_local().map(|(id, _)| id).collect();
    for fid in local_ids {
        let FunctionKind::Local(func): &mut FunctionKind = &mut module.funcs.get_mut(fid).kind
        else {
            continue;
        };
        fold_function_interprocedural(func, &snapshot, report);
    }
}

fn fold_function_interprocedural(
    func: &mut LocalFunction,
    snapshot: &PureModule,
    report: &mut RecoveryReport,
) {
    let seq_ids: Vec<InstrSeqId> = super::collect_seq_ids(func);
    for seq_id in seq_ids {
        fold_diamonds_in_seq(func, seq_id, snapshot, report);
    }
}

#[derive(Debug)]
struct Diamond {
    parent_index: usize,
    survivor: Vec<Instr>,
}

fn fold_diamonds_in_seq(
    func: &mut LocalFunction,
    seq_id: InstrSeqId,
    snapshot: &PureModule,
    report: &mut RecoveryReport,
) {
    let parent: Vec<Instr> = func
        .block(seq_id)
        .instrs
        .iter()
        .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let mut folds: Vec<Diamond> = Vec::new();
    for (idx, instr) in parent.iter().enumerate() {
        let Instr::Block(outer): &Instr = instr else {
            continue;
        };
        let Some(survivor): Option<Vec<Instr>> = match_diamond(func, outer.seq, snapshot) else {
            continue;
        };
        folds.push(Diamond {
            parent_index: idx,
            survivor,
        });
    }
    if folds.is_empty() {
        return;
    }
    folds.sort_by_key(|d: &Diamond| std::cmp::Reverse(d.parent_index));
    let seq: &mut walrus::ir::InstrSeq = func.block_mut(seq_id);
    for fold in folds {
        if fold.parent_index >= seq.instrs.len() {
            continue;
        }
        let loc: walrus::ir::InstrLocId = seq.instrs[fold.parent_index].1;
        let tail: Vec<(Instr, walrus::ir::InstrLocId)> =
            seq.instrs.split_off(fold.parent_index + 1);
        seq.instrs.truncate(fold.parent_index);
        for instr in fold.survivor {
            seq.instrs.push((instr, loc));
        }
        seq.instrs.extend(tail);
        report.opaque_predicates_removed += 1;
    }
}

fn match_diamond(
    func: &LocalFunction,
    outer_id: InstrSeqId,
    snapshot: &PureModule,
) -> Option<Vec<Instr>> {
    if !is_empty_result(func.block(outer_id).ty) {
        return None;
    }
    let outer: &[(Instr, walrus::ir::InstrLocId)] = &func.block(outer_id).instrs;
    let Some((Instr::Block(inner), _)): Option<&(Instr, walrus::ir::InstrLocId)> = outer.first()
    else {
        return None;
    };
    let inner_id: InstrSeqId = inner.seq;
    if !is_empty_result(func.block(inner_id).ty) {
        return None;
    }
    let alternative: Vec<Instr> = outer[1..]
        .iter()
        .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let inner: Vec<Instr> = func
        .block(inner_id)
        .instrs
        .iter()
        .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
        .collect();
    let brif_index: usize = inner
        .iter()
        .position(|instr: &Instr| matches!(instr, Instr::BrIf(br) if br.block == inner_id))?;
    let guard: &[Instr] = &inner[..brif_index];
    if guard.is_empty() || guard.len() > MAX_GUARD_LEN || !is_flat_guard(guard) {
        return None;
    }
    let consequent_full: &[Instr] = inner.get(brif_index + 1..)?;
    let (Some(Instr::Br(br_out)), consequent): (Option<&Instr>, &[Instr]) =
        split_last_instr(consequent_full)
    else {
        return None;
    };
    if br_out.block != outer_id {
        return None;
    }
    if has_nested_control(consequent) || has_nested_control(&alternative) {
        return None;
    }
    if branches_escape(guard, inner_id, outer_id)
        || branches_escape(consequent, inner_id, outer_id)
        || branches_escape(&alternative, inner_id, outer_id)
    {
        return None;
    }
    let verdict: Scalar = snapshot.eval_guard(guard)?;
    match verdict {
        Scalar::I32(0) => Some(consequent.to_vec()),
        Scalar::I32(_) => Some(alternative),
        Scalar::I64(_) => None,
    }
}

const fn split_last_instr(instrs: &[Instr]) -> (Option<&Instr>, &[Instr]) {
    match instrs.split_last() {
        Some((last, rest)) => (Some(last), rest),
        None => (None, instrs),
    }
}

const fn is_empty_result(ty: InstrSeqType) -> bool {
    matches!(ty, InstrSeqType::Simple(None))
}

fn is_flat_guard(guard: &[Instr]) -> bool {
    guard.iter().all(|instr: &Instr| {
        matches!(
            instr,
            Instr::Const(_)
                | Instr::Binop(_)
                | Instr::Unop(_)
                | Instr::Select(_)
                | Instr::Drop(_)
                | Instr::Call(_)
        )
    })
}

fn has_nested_control(instrs: &[Instr]) -> bool {
    instrs.iter().any(|instr: &Instr| {
        matches!(
            instr,
            Instr::Block(_) | Instr::Loop(_) | Instr::IfElse(_) | Instr::BrTable(_)
        )
    })
}

fn branches_escape(instrs: &[Instr], inner_id: InstrSeqId, outer_id: InstrSeqId) -> bool {
    instrs.iter().any(|instr: &Instr| {
        let target: Option<InstrSeqId> = match instr {
            Instr::Br(br) => Some(br.block),
            Instr::BrIf(br) => Some(br.block),
            _ => None,
        };
        matches!(target, Some(t) if t == inner_id || t == outer_id)
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn collatz_from_27_reaches_one() {
        let (steps, reached): (u32, bool) = run_collatz(27);
        assert!(reached);
        assert_eq!(steps, 111);
    }

    #[test]
    fn collatz_from_one_is_already_one() {
        let (steps, reached): (u32, bool) = run_collatz(1);
        assert!(reached);
        assert_eq!(steps, 0);
    }

    #[test]
    fn eval_const_comparison() {
        let instrs: Vec<Instr> = vec![
            Instr::Const(walrus::ir::Const {
                value: Value::I32(7),
            }),
            Instr::Const(walrus::ir::Const {
                value: Value::I32(7),
            }),
            Instr::Binop(walrus::ir::Binop {
                op: BinaryOp::I32Eq,
            }),
        ];
        let verdict: ConstVerdict = const_condition(&instrs, 3).expect("const verdict");
        assert_eq!(verdict.value, 1);
        assert_eq!(verdict.cond_start, 0);
    }

    fn recover(wat: &str) -> crate::recover::RecoveredModule {
        let bytes: Vec<u8> = wat::parse_str(wat).expect("assemble wat");
        crate::recover::recover_module(&bytes).expect("recover")
    }

    #[test]
    fn interprocedural_call_over_constant_folds_block_brif_diamond() {
        let wat: &str = r#"
            (module
              (func $pure (param i32) (result i32)
                local.get 0
                i32.const 3
                i32.mul
                i32.const 1
                i32.add)
              (func (export "guarded") (param i32) (result i32)
                (local i32)
                block
                  block
                    i32.const 7
                    call $pure
                    i32.const 22
                    i32.eq
                    i32.eqz
                    br_if 0
                    local.get 0
                    i32.const 100
                    i32.add
                    local.set 1
                    br 1
                  end
                  local.get 0
                  i32.const 999
                  i32.add
                  local.set 1
                end
                local.get 1))
        "#;
        let recovered: crate::recover::RecoveredModule = recover(wat);
        assert_eq!(
            recovered.report.opaque_predicates_removed, 1,
            "pure(7)=22 so the equality guard is a build-time constant and the diamond must collapse: {:?}",
            recovered.report
        );
        assert!(wasmparser::validate(&recovered.bytes).is_ok());
    }

    #[test]
    fn runtime_parameter_guard_is_not_folded() {
        let wat: &str = r#"
            (module
              (func (export "guarded") (param i32) (result i32)
                (local i32)
                block
                  block
                    local.get 0
                    i32.const 5
                    i32.eq
                    i32.eqz
                    br_if 0
                    i32.const 100
                    local.set 1
                    br 1
                  end
                  i32.const 999
                  local.set 1
                end
                local.get 1))
        "#;
        let recovered: crate::recover::RecoveredModule = recover(wat);
        assert_eq!(
            recovered.report.opaque_predicates_removed, 0,
            "the guard reads a runtime parameter, so it is not a build-time constant and must stay: {:?}",
            recovered.report
        );
    }
}
