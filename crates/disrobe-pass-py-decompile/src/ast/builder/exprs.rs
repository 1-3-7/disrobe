use super::comprehensions::try_build_comprehension_expr;
use super::function_meta::{
    FunctionMeta, TypeParamKind, annotate_codeobj_dict, annotations_from_expr, attach_fn_meta,
    build_legacy_call, build_nested_function_def, build_typevar_marker, call_ex_args,
    call_ex_kwargs, defaults_from_expr, fold_set_function_attributes, is_typevar_marker,
    kwdefaults_from_expr, load_const, make_function_meta, make_function_meta_legacy, merge_extend,
    nested_code_index, pop_legacy_slice_bounds, slice_bound, starred, try_build_class_def,
    try_build_decorated_class_def, try_build_decorated_function_def,
    try_build_decorated_generic_def, try_build_generic_def, try_build_generic_type_alias,
    try_build_lambda_expr, try_build_type_alias, type_alias_marker_call,
    type_param_kind_from_intrinsic1, unwrap_evaluator_expr, update_last_import_from_asname,
};
use super::stmts::{
    PY_CO_FLAG_ASYNC_GENERATOR, PY_CO_FLAG_COROUTINE, build_tstr_expr, collect_unpack_targets,
    filter_async_gen_return, is_await_null_slot, is_await_poll_yield, is_pre23_statement_yield,
    is_yield_from_send_pattern, merge_or_push_delete, name_at_either, resolve_jump_target,
};
use super::try_with::{is_comprehension_expr, special_method_name};
use super::{
    DecodedStream, MAX_SYNTH_OPERANDS, active_version, boolop_merge_after, loop_frame_depth,
};
use crate::ast::node::{Alias, ConstValue, Expr, ExprCtx, FormatConversion, Stmt, TStrItem};
use crate::bytecode::opcode::{CanonicalOp, deref_local_payload, is_deref_local};
use crate::bytecode::version::PyVersion;
use crate::error::{DecompileError, Result};
use disrobe_py_marshal::{CodeObject, Object};

const DR_CHAIN_SENTINEL: &str = "__DR_CHAIN_SENTINEL__";

fn chain_sentinel() -> Expr {
    Expr::Name {
        id: DR_CHAIN_SENTINEL.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

fn is_chain_sentinel(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_CHAIN_SENTINEL)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ChainLink {
    None,

    Legacy,

    Modern,

    ModernTest,
}

fn classify_chain_link(ops: &[CanonicalOp], idx: usize) -> ChainLink {
    if !preceded_by_dup_rot(ops, idx) {
        return ChainLink::None;
    }
    let significant: Vec<&CanonicalOp> = ops
        .iter()
        .skip(idx + 1)
        .filter(|op: &&CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::ToBool
            )
        })
        .take(2)
        .collect();
    let mut after: std::slice::Iter<'_, &CanonicalOp> = significant.iter();
    match after.next().copied() {
        Some(CanonicalOp::JumpIfFalseOrPop(_) | CanonicalOp::JumpIfTrueOrPop(_)) => {
            ChainLink::Legacy
        }
        Some(CanonicalOp::Copy(1)) => match after.next().copied() {
            Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)) => {
                ChainLink::Modern
            }
            _ => ChainLink::None,
        },
        Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)) => {
            ChainLink::ModernTest
        }
        _ => ChainLink::None,
    }
}

pub(super) fn is_chain_cond_jump(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut compare_idx: Option<usize> = None;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::ToBool
            | CanonicalOp::Copy(1) => {}
            CanonicalOp::Compare(_) => {
                compare_idx = Some(back);
                break;
            }
            _ => break,
        }
    }
    compare_idx.is_some_and(|cmp: usize| {
        matches!(
            classify_chain_link(ops, cmp),
            ChainLink::Modern | ChainLink::ModernTest
        )
    })
}

pub(super) fn is_chain_compare_jump(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut compare_idx: Option<usize> = None;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::ToBool
            | CanonicalOp::Copy(1) => {}
            CanonicalOp::Compare(_) => {
                compare_idx = Some(back);
                break;
            }
            _ => break,
        }
    }
    compare_idx.is_some_and(|cmp: usize| classify_chain_link(ops, cmp) != ChainLink::None)
}

pub(super) fn is_modern_test_chain_link_jump(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut compare_idx: Option<usize> = None;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::ToBool => {}
            CanonicalOp::Compare(_) => {
                compare_idx = Some(back);
                break;
            }
            _ => break,
        }
    }
    compare_idx.is_some_and(|cmp: usize| classify_chain_link(ops, cmp) == ChainLink::ModernTest)
}

pub(super) fn modern_test_chain_then_end(
    stream: &DecodedStream,
    guard: usize,
    hi: usize,
) -> Option<usize> {
    if !matches!(
        stream.ops[guard],
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
    ) {
        return None;
    }
    let link_jump: usize = (0..guard)
        .rev()
        .take_while(|&k: &usize| is_chain_region_filler(&stream.ops, k, guard + 1))
        .find(|&k: &usize| is_modern_test_chain_link_jump(&stream.ops, k))?;
    resolve_jump_target(stream, link_jump, &stream.ops[link_jump])
        .filter(|t: &usize| *t > guard && *t <= hi)
}

fn is_chain_region_filler(ops: &[CanonicalOp], idx: usize, guard: usize) -> bool {
    idx < guard
        && matches!(
            ops[idx],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::ToBool
                | CanonicalOp::Swap(_)
                | CanonicalOp::RotN(_)
                | CanonicalOp::Copy(_)
                | CanonicalOp::Dup
                | CanonicalOp::Compare(_)
                | CanonicalOp::LoadFast(_)
                | CanonicalOp::LoadFastLoadFast(..)
                | CanonicalOp::LoadName(_)
                | CanonicalOp::LoadGlobal(_)
                | CanonicalOp::LoadFromDictOrGlobals(_)
                | CanonicalOp::LoadConst(_)
                | CanonicalOp::LoadSmallInt(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
        )
}

fn preceded_by_dup_rot(ops: &[CanonicalOp], idx: usize) -> bool {
    let mut seen_swap: bool = false;
    let mut seen_dup: bool = false;
    for back in (0..idx).rev() {
        match &ops[back] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_) => seen_swap = true,
            CanonicalOp::Dup | CanonicalOp::Copy(_) => seen_dup = true,
            CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadFromDictOrGlobals(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
                if !(seen_swap && seen_dup) => {}
            _ => return seen_swap && seen_dup,
        }
    }
    seen_swap && seen_dup
}

pub(super) fn build_linear_stmts_sim(
    code: &CodeObject,
    ops: &[CanonicalOp],
) -> Result<(Vec<Stmt>, Vec<Expr>)> {
    build_linear_stmts_sim_seed(code, ops, Vec::new())
}

fn compare_chain_cleanup_skip(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    let after: &[CanonicalOp] = ops.get(idx + 1..)?;
    match after {
        [
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_),
            CanonicalOp::Pop,
            ..,
        ] => Some(2),
        _ => None,
    }
}

fn iterator_return_cleanup_pair(ops: &[CanonicalOp], idx: usize) -> Option<usize> {
    if loop_frame_depth() == 0 {
        return None;
    }
    let allow_borrow_triple: bool =
        active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) >= (3, 15));
    let head_len: usize = cleanup_group_len(ops, idx, allow_borrow_triple)?;
    let mut k: usize = idx + head_len;
    while let Some(op) = ops.get(k) {
        match op {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => k += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return Some(head_len),
            _ => match cleanup_group_len(ops, k, allow_borrow_triple) {
                Some(len) => k += len,
                None => return None,
            },
        }
    }
    None
}

#[inline]
fn cleanup_group_len(ops: &[CanonicalOp], idx: usize, allow_borrow_triple: bool) -> Option<usize> {
    match ops.get(idx) {
        Some(CanonicalOp::Swap(2) | CanonicalOp::RotN(2))
            if matches!(ops.get(idx + 1), Some(CanonicalOp::Pop)) =>
        {
            Some(2)
        }
        Some(CanonicalOp::Swap(3))
            if allow_borrow_triple
                && matches!(ops.get(idx + 1), Some(CanonicalOp::Pop))
                && matches!(ops.get(idx + 2), Some(CanonicalOp::Pop)) =>
        {
            Some(3)
        }
        _ => None,
    }
}

fn try_swap_simultaneous_assign(
    code: &CodeObject,
    ops: &[CanonicalOp],
    reorder_idx: usize,
    n: usize,
    post_reorder: Vec<Expr>,
) -> Option<(Stmt, usize)> {
    if !matches!(n, 2 | 3) || post_reorder.len() != n {
        return None;
    }
    let region_start: usize = reorder_idx + 1;
    if !matches!(
        ops.get(region_start),
        Some(
            CanonicalOp::LoadFast(_)
                | CanonicalOp::LoadName(_)
                | CanonicalOp::LoadGlobal(_)
                | CanonicalOp::LoadFromDictOrGlobals(_)
                | CanonicalOp::LoadFastLoadFast(_, _)
                | CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreFastLoadFast(_, _)
                | CanonicalOp::UnpackSequence(_)
                | CanonicalOp::UnpackEx(_)
        )
    ) {
        return None;
    }
    let mut end: usize = region_start;
    while end < ops.len() {
        let slice: &[CanonicalOp] = ops.get(region_start..=end)?;
        if let Ok((stmts, residual)) =
            build_linear_stmts_sim_seed(code, slice, post_reorder.clone())
            && residual.is_empty()
            && stmts.len() == n
            && stmts.iter().all(is_single_target_store_assign)
        {
            let mut targets: Vec<Expr> = Vec::with_capacity(n);
            let mut values: Vec<Expr> = Vec::with_capacity(n);
            for stmt in stmts {
                let Stmt::Assign {
                    targets: mut assign_targets,
                    value,
                    ..
                }: Stmt = stmt
                else {
                    return None;
                };
                targets.push(assign_targets.pop()?);
                values.push(value);
            }
            if !values.iter().all(|v: &Expr| post_reorder.contains(v)) {
                end += 1;
                continue;
            }
            let merged: Stmt = Stmt::Assign {
                targets: vec![Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                }],
                value: Expr::Tuple {
                    elts: values,
                    ctx: ExprCtx::Load,
                },
                type_comment: None,
                line: None,
            };
            return Some((merged, end - reorder_idx));
        }
        end += 1;
    }
    None
}

fn significant_run_len(ops: &[CanonicalOp], from: usize, to: usize) -> usize {
    (from..to)
        .take_while(|&k: &usize| {
            matches!(
                ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .count()
}

fn reorder_run(
    stack: &[Expr],
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<(usize, Vec<Expr>, usize)> {
    match &ops[idx] {
        CanonicalOp::Swap(k) if matches!(usize::from(*k), 2 | 3) => {
            let n: usize = usize::from(*k);
            if stack.len() < n {
                return None;
            }
            let mut top: Vec<Expr> = stack[stack.len() - n..].to_vec();
            let last: usize = top.len() - 1;
            top.swap(last, last - (n - 1));
            Some((n, top, 1))
        }
        CanonicalOp::RotN(first) if matches!(usize::from(*first), 2..=4) => {
            let n: usize = usize::from(*first);
            if stack.len() < n {
                return None;
            }
            let mut expected: u8 = *first;
            let mut cursor: usize = idx;
            while expected >= 2 {
                if !matches!(ops.get(cursor), Some(CanonicalOp::RotN(k)) if *k == expected) {
                    return None;
                }
                let after: usize = cursor + 1;
                cursor = after + significant_run_len(ops, after, ops.len());
                expected -= 1;
            }
            let mut top: Vec<Expr> = stack[stack.len() - n..].to_vec();
            top.reverse();
            Some((n, top, cursor - idx))
        }
        _ => None,
    }
}

fn simple_store_target(code: &CodeObject, op: &CanonicalOp, idx: usize) -> Option<Expr> {
    match op {
        CanonicalOp::StoreFast(slot) => local_target(code, *slot, idx).ok(),
        CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => Some(Expr::Name {
            id: name_at(&code.names, *slot, idx, "name").ok()?,
            ctx: ExprCtx::Store,
            line: None,
        }),
        _ => None,
    }
}

fn storeless_run_prefix_ok(ops: &[CanonicalOp], idx: usize) -> bool {
    (0..idx).rev().find_map(|k: usize| match &ops[k] {
        CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => None,
        CanonicalOp::Dup
        | CanonicalOp::DupTwo
        | CanonicalOp::Copy(_)
        | CanonicalOp::Swap(_)
        | CanonicalOp::RotN(_)
        | CanonicalOp::StoreFast(_)
        | CanonicalOp::StoreName(_)
        | CanonicalOp::StoreGlobal(_)
        | CanonicalOp::StoreAttr(_)
        | CanonicalOp::StoreSubscr
        | CanonicalOp::StoreSlice
        | CanonicalOp::UnpackSequence(_)
        | CanonicalOp::UnpackEx(_) => Some(false),
        _ => Some(true),
    }) == Some(true)
}

fn try_storeless_simultaneous_assign(
    code: &CodeObject,
    ops: &[CanonicalOp],
    stack: &[Expr],
    idx: usize,
) -> Option<(Stmt, usize)> {
    if !storeless_run_prefix_ok(ops, idx) {
        return None;
    }
    let mut store_targets: Vec<Expr> = Vec::new();
    let mut cursor: usize = idx;
    let mut span: usize = 0;
    while let Some(target) = ops.get(cursor).and_then(|op: &CanonicalOp| {
        if matches!(
            op,
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        ) {
            None
        } else {
            simple_store_target(code, op, cursor)
        }
    }) {
        store_targets.push(target);
        span = cursor + 1 - idx;
        cursor += 1 + significant_run_len(ops, cursor + 1, ops.len());
    }
    let k: usize = store_targets.len();
    if k < 2 || stack.len() < k {
        return None;
    }
    if store_targets
        .iter()
        .any(|t: &Expr| !matches!(t, Expr::Name { .. }))
    {
        return None;
    }
    let values: Vec<Expr> = stack[stack.len() - k..].to_vec();
    let mut targets: Vec<Expr> = store_targets;
    targets.reverse();
    let merged: Stmt = Stmt::Assign {
        targets: vec![Expr::Tuple {
            elts: targets,
            ctx: ExprCtx::Store,
        }],
        value: Expr::Tuple {
            elts: values,
            ctx: ExprCtx::Load,
        },
        type_comment: None,
        line: None,
    };
    Some((merged, span))
}

fn is_single_target_store_assign(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign { targets, value, .. }
            if targets.len() == 1
                && matches!(
                    targets[0],
                    Expr::Subscript { .. }
                        | Expr::Attribute { .. }
                        | Expr::Name { .. }
                        | Expr::Tuple { .. }
                )
                && !matches!(value, Expr::NamedExpr { .. })
    )
}

#[derive(Debug, Clone)]
struct AccOperand {
    expr: Expr,
    sc_idx: usize,
    value_lo: usize,
}

#[derive(Debug)]
struct BoolopAccState {
    kind: crate::ast::node::BoolOpKind,
    operands: Vec<AccOperand>,
    descriptors: Option<Vec<super::ScDesc>>,
    tail_value_lo: usize,
}

type BoolopAcc = Option<BoolopAccState>;

impl BoolopAccState {
    fn fold_with(&self, tail: &Expr) -> Option<Expr> {
        let descriptors: &Vec<super::ScDesc> = self.descriptors.as_ref()?;
        if descriptors.is_empty() || self.operands.is_empty() {
            return None;
        }
        let mut items: Vec<ShortCircuitItem> = Vec::with_capacity(self.operands.len() + 1);
        let mut region_exit: usize = 0;
        for operand in &self.operands {
            let desc: &super::ScDesc = descriptors
                .iter()
                .find(|d: &&super::ScDesc| d.sc_idx == operand.sc_idx)?;
            region_exit = region_exit.max(desc.target);
            items.push(ShortCircuitItem {
                expr: operand.expr.clone(),
                op: desc.kind,
                target: desc.target,
                sc_idx: operand.sc_idx,
                value_lo: operand.value_lo,
            });
        }
        let tail_value_lo: usize = self.tail_value_lo;
        let exit_sc: usize = region_exit.max(tail_value_lo + 1);
        items.push(ShortCircuitItem {
            expr: tail.clone(),
            op: self.kind,
            target: exit_sc,
            sc_idx: exit_sc,
            value_lo: tail_value_lo,
        });
        fold_short_circuit_items(items)
    }
}

pub(super) fn build_linear_stmts_sim_seed(
    code: &CodeObject,
    ops: &[CanonicalOp],
    seed_stack: Vec<Expr>,
) -> Result<(Vec<Stmt>, Vec<Expr>)> {
    let mut sim: StackSim = StackSim::new();
    sim.stack = seed_stack;
    let mut out: Vec<Stmt> = Vec::new();
    let mut cmp_chain: Option<(Expr, Vec<crate::bytecode::opcode::CmpOp>, Vec<Expr>)> = None;
    let mut fn_meta: std::collections::BTreeMap<u32, FunctionMeta> =
        std::collections::BTreeMap::new();
    let mut boolop: BoolopAcc = None;
    let sc_descriptors: Option<Vec<super::ScDesc>> = super::boolop_sc_descriptors(ops);
    let mut boolop_base_depth: usize = 0;
    let mut boolop_merge_idx: usize = 0;
    let mut next_operand_value_lo: usize = 0;
    let mut skip_next: usize = 0;
    let mut print_acc: Option<(Option<Expr>, Vec<Expr>)> = None;
    for (idx, op) in ops.iter().enumerate() {
        if skip_next > 0 {
            skip_next -= 1;
            continue;
        }
        if matches!(op, CanonicalOp::JumpForward(_))
            && let Some(after_skip) = compare_chain_cleanup_skip(ops, idx)
        {
            skip_next = after_skip;
            continue;
        }
        if let Some(group_len) = iterator_return_cleanup_pair(ops, idx) {
            skip_next = group_len - 1;
            continue;
        }
        if boolop.is_some()
            && (idx >= boolop_merge_idx || boolop_value_consumer(op))
            && !is_value_boolop_shortcircuit(ops, idx)
            && sim.stack.len() == boolop_base_depth + 1
            && !sim
                .peek_clone()
                .is_some_and(|e: Expr| is_call_assembly_marker(&e))
        {
            flush_boolop(&mut sim, &mut boolop);
        }
        if let Some(kind) = value_boolop_at(ops, idx) {
            let operand: Expr = sim.pop_or_synth(code, idx);
            let descriptors_cover_idx: bool =
                sc_descriptors
                    .as_ref()
                    .is_some_and(|d: &Vec<super::ScDesc>| {
                        d.iter().any(|s: &super::ScDesc| s.sc_idx == idx)
                    });
            let keep_accumulating: bool = boolop.as_ref().is_some_and(|acc: &BoolopAccState| {
                (acc.descriptors.is_some() && descriptors_cover_idx) || acc.kind == kind
            });
            if keep_accumulating && let Some(acc) = boolop.as_mut() {
                acc.operands.push(AccOperand {
                    expr: operand,
                    sc_idx: idx,
                    value_lo: next_operand_value_lo,
                });
            } else {
                sim.push(operand);
                flush_boolop(&mut sim, &mut boolop);
                let restart: Expr = sim.pop_or_synth(code, idx);
                boolop_base_depth = sim.stack.len();
                boolop = Some(BoolopAccState {
                    kind,
                    operands: vec![AccOperand {
                        expr: restart,
                        sc_idx: idx,
                        value_lo: 0,
                    }],
                    descriptors: sc_descriptors.clone(),
                    tail_value_lo: 0,
                });
            }
            boolop_merge_idx = boolop_merge_after(ops, idx);
            if boolop_merge_idx == 0
                && let Some(descriptors) = sc_descriptors.as_ref()
                && let Some(desc) = descriptors
                    .iter()
                    .find(|s: &&super::ScDesc| s.sc_idx == idx)
            {
                boolop_merge_idx = boolop_operand_merge_point(ops, desc.target);
            }
            skip_next = boolop_shortcircuit_skip(ops, idx);
            next_operand_value_lo =
                first_significant_after(ops, idx + 1 + skip_next).unwrap_or(idx + 1 + skip_next);
            if let Some(acc) = boolop.as_mut() {
                acc.kind = kind;
                acc.tail_value_lo = next_operand_value_lo;
            }
            continue;
        }
        if matches!(op, CanonicalOp::Swap(_) | CanonicalOp::RotN(_))
            && let Some((n, post_reorder, run_len)) = reorder_run(&sim.stack, ops, idx)
            && let Some((merged, skip)) =
                try_swap_simultaneous_assign(code, ops, idx + run_len - 1, n, post_reorder)
        {
            for _ in 0..n {
                let _ = sim.try_pop();
            }
            out.push(merged);
            skip_next = skip + run_len - 1;
            continue;
        }
        if matches!(
            op,
            CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::StoreGlobal(_)
        ) && let Some((merged, span)) =
            try_storeless_simultaneous_assign(code, ops, &sim.stack, idx)
        {
            let popped: usize = match &merged {
                Stmt::Assign { targets, .. } => match targets.first() {
                    Some(Expr::Tuple { elts, .. }) => elts.len(),
                    _ => 0,
                },
                _ => 0,
            };
            for _ in 0..popped {
                let _ = sim.try_pop();
            }
            out.push(merged);
            skip_next = span - 1;
            continue;
        }
        match op {
            CanonicalOp::LoadConst(i) => sim.push(load_const(code, *i, idx)?),
            CanonicalOp::LoadSmallInt(value) => sim.push(Expr::Constant {
                value: ConstValue::Int(i128::from(*value)),
                line: None,
            }),
            CanonicalOp::LoadCommonConst(slot) => sim.push(load_common_constant(*slot)),
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                sim.push(load_name(code, *i, idx)?);
            }
            CanonicalOp::LoadFast(i) | CanonicalOp::LoadFastAndClear(i) => {
                sim.push(load_local(code, *i, idx)?);
            }
            CanonicalOp::LoadFromDictOrDeref(i) => {
                let _mapping: Expr = sim.pop_or_synth(code, idx);
                sim.push(load_local(code, *i, idx)?);
            }
            CanonicalOp::LoadFromDictOrGlobals(i) => {
                let _mapping: Expr = sim.pop_or_synth(code, idx);
                sim.push(load_name(code, *i, idx)?);
            }
            CanonicalOp::LoadAttr(i) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                if decode_import_module_marker(&value).is_some()
                    || decode_import_fromset_marker(&value).is_some()
                {
                    sim.push(value);
                    continue;
                }
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSpecial(slot) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr: special_method_name(*slot).to_owned(),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSuperAttr { name, two_arg } => {
                let self_obj: Expr = sim.pop_or_synth(code, idx);
                let class_expr: Expr = sim.pop_or_synth(code, idx);
                let super_callable: Expr = sim.pop_or_synth(code, idx);
                let attr: String =
                    name_at_either(code, *name).unwrap_or_else(|_| format!("attr_{name}"));
                let args: Vec<Expr> = if *two_arg {
                    vec![class_expr, self_obj]
                } else {
                    Vec::new()
                };
                sim.push(Expr::Attribute {
                    value: Box::new(Expr::Call {
                        func: Box::new(super_callable),
                        args,
                        keywords: Vec::new(),
                    }),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::ImportName(i) => {
                let fromlist_expr: Expr = sim.pop_or_synth(code, idx);
                let level_expr: Expr = sim.pop_or_synth(code, idx);
                let module: String = name_at(&code.names, *i, idx, "name")?;
                let level: u32 = extract_level_const(&level_expr).unwrap_or(0);
                let fromlist: Option<Vec<String>> = extract_tuple_of_strings(&fromlist_expr);
                let is_star: bool = matches!(fromlist.as_deref(), Some([s]) if s == "*");
                if is_star {
                    sim.push(Expr::Name {
                        id: encode_import_module_marker(&ImportModuleMarker {
                            module: module.clone(),
                            level,
                            fromlist: Some(vec!["*".to_owned()]),
                        }),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                if let Some(names) = fromlist.clone() {
                    let aliases: Vec<Alias> = names
                        .iter()
                        .map(|n: &String| Alias {
                            name: n.clone(),
                            asname: None,
                        })
                        .collect();
                    out.push(Stmt::ImportFrom {
                        module: if module.is_empty() {
                            None
                        } else {
                            Some(module.clone())
                        },
                        names: aliases,
                        level,
                        line: None,
                    });
                    sim.push(Expr::Name {
                        id: encode_import_fromset_marker(&module, level),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                sim.push(Expr::Name {
                    id: encode_import_module_marker(&ImportModuleMarker {
                        module,
                        level,
                        fromlist,
                    }),
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::ImportFrom(i) => {
                let attr: String = name_at(&code.names, *i, idx, "name")?;
                let module_top: Option<Expr> = sim.peek_clone();
                if let Some(top) = &module_top
                    && let Some((module, level)) = decode_import_fromset_marker(top)
                {
                    sim.push(Expr::Name {
                        id: encode_import_attr_marker(&module, level, &attr),
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                    continue;
                }
                sim.push(Expr::Name {
                    id: attr,
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::ImportStar => {
                out.push(import_star_stmt(sim.try_pop()));
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BinarySlice => {
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                let obj: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(obj),
                    slice: Box::new(Expr::Slice {
                        lower: slice_bound(lower),
                        upper: slice_bound(upper),
                        step: None,
                    }),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::StoreSlice => {
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower: slice_bound(lower),
                            upper: slice_bound(upper),
                            step: None,
                        }),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::LoadSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let obj: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(obj),
                    slice: Box::new(Expr::Slice {
                        lower,
                        upper,
                        step: None,
                    }),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::StoreSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower,
                            upper,
                            step: None,
                        }),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::DeleteSliceLegacy(variant) => {
                let (lower, upper): (Option<Box<Expr>>, Option<Box<Expr>>) =
                    pop_legacy_slice_bounds(&mut sim, code, idx, *variant);
                let container: Expr = sim.pop_or_synth(code, idx);
                merge_or_push_delete(
                    &mut out,
                    Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(Expr::Slice {
                            lower,
                            upper,
                            step: None,
                        }),
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::StoreAttr(i) => {
                let target_value: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                out.push(Stmt::Assign {
                    targets: vec![Expr::Attribute {
                        value: Box::new(target_value),
                        attr,
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::StoreSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let container: Expr = sim.pop_or_synth(code, idx);
                let rhs: Expr = sim.pop_or_synth(code, idx);
                let legacy_dict_idiom: bool =
                    active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) < (2, 6));
                if legacy_dict_idiom
                    && matches!(container, Expr::Dict { .. })
                    && matches!(sim.peek_clone(), Some(Expr::Dict { .. }))
                    && let Some(Expr::Dict {
                        mut keys,
                        mut values,
                    }) = sim.try_pop()
                {
                    keys.push(Some(slice));
                    values.push(rhs);
                    sim.push(Expr::Dict { keys, values });
                    continue;
                }
                out.push(Stmt::Assign {
                    targets: vec![Expr::Subscript {
                        value: Box::new(container),
                        slice: Box::new(slice),
                        ctx: ExprCtx::Store,
                    }],
                    value: rhs,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.pop_or_synth(code, idx);
                let left: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::UnaryOp(op_kind) => {
                let operand: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::UnaryOp {
                    op: *op_kind,
                    operand: Box::new(operand),
                });
            }
            CanonicalOp::Compare(cmp) => {
                let right: Expr = sim.pop_or_synth(code, idx);
                let left: Expr = sim.pop_or_synth(code, idx);
                let link: ChainLink = classify_chain_link(ops, idx);
                let is_chain_link: bool = link != ChainLink::None;
                if let Some((_, chain_ops, comparators)) = cmp_chain.as_mut() {
                    chain_ops.push(*cmp);
                    comparators.push(right);
                    drop(left);
                } else if is_chain_link {
                    cmp_chain = Some((left, vec![*cmp], vec![right]));
                } else {
                    sim.push(Expr::Compare {
                        left: Box::new(left),
                        ops: vec![*cmp],
                        comparators: vec![right],
                    });
                }
                if cmp_chain.is_some() {
                    if is_chain_link {
                        if link == ChainLink::Modern {
                            sim.push(chain_sentinel());
                        }
                    } else if let Some((chain_left, chain_ops, comparators)) = cmp_chain.take() {
                        sim.push(Expr::Compare {
                            left: Box::new(chain_left),
                            ops: chain_ops,
                            comparators,
                        });
                    }
                }
            }
            CanonicalOp::KwNames(i) => {
                let names: Vec<String> = load_const(code, *i, idx)
                    .ok()
                    .and_then(|e: Expr| extract_tuple_of_strings(&e))
                    .unwrap_or_default();
                sim.push(Expr::Name {
                    id: encode_kw_names(&names),
                    ctx: ExprCtx::Load,
                    line: None,
                });
            }
            CanonicalOp::CallFunction(argc) => {
                let pending_kw: Option<Vec<String>> =
                    sim.peek_clone().as_ref().and_then(decode_kw_names);
                if let Some(kw_names) = pending_kw {
                    let _: Option<Expr> = sim.try_pop();
                    let total: usize = usize::from(*argc);
                    let kw_count: usize = kw_names.len().min(total);
                    let pos_count: usize = total - kw_count;
                    let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                    for _ in 0..kw_count {
                        kw_values.insert(0, sim.pop_or_synth(code, idx));
                    }
                    let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                    for _ in 0..pos_count {
                        args.insert(0, sim.pop_or_synth(code, idx));
                    }
                    let (func, implicit_self): (Expr, Option<Expr>) =
                        sim.pop_call_target(code, idx);
                    if let Some(self_arg) = implicit_self {
                        args.insert(0, self_arg);
                    }
                    let keywords: Vec<crate::ast::node::Keyword> = kw_names
                        .into_iter()
                        .zip(kw_values)
                        .map(|(name, value): (String, Expr)| crate::ast::node::Keyword {
                            arg: Some(name),
                            value,
                        })
                        .collect();
                    sim.push(Expr::Call {
                        func: Box::new(func),
                        args,
                        keywords,
                    });
                    continue;
                }
                let mut args: Vec<Expr> = Vec::with_capacity(usize::from(*argc));
                for _ in 0..*argc {
                    args.insert(0, sim.pop_or_synth(code, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                if let Some(comp) = try_build_comprehension_expr(code, &func, &args) {
                    sim.push(comp);
                    continue;
                }
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords: Vec::new(),
                });
            }
            CanonicalOp::CallFunctionKw(argc) => {
                let kw_names_expr: Expr = sim.pop_or_synth(code, idx);
                let kw_names: Vec<String> = decode_kw_names(&kw_names_expr)
                    .or_else(|| extract_tuple_of_strings(&kw_names_expr))
                    .unwrap_or_default();
                let total: usize = usize::from(*argc);
                let kw_count: usize = kw_names.len().min(total);
                let pos_count: usize = total - kw_count;
                let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                for _ in 0..kw_count {
                    kw_values.insert(0, sim.pop_or_synth(code, idx));
                }
                let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                for _ in 0..pos_count {
                    args.insert(0, sim.pop_or_synth(code, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                let keywords: Vec<crate::ast::node::Keyword> = kw_names
                    .into_iter()
                    .zip(kw_values)
                    .map(|(name, value): (String, Expr)| crate::ast::node::Keyword {
                        arg: Some(name),
                        value,
                    })
                    .collect();
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords,
                });
            }
            CanonicalOp::CallFunctionLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, false, false, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionVarLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, true, false, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionKwLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, false, true, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionVarKwLegacy(packed) => {
                let call: Expr = build_legacy_call(code, idx, *packed, true, true, &mut sim);
                sim.push(call);
            }
            CanonicalOp::CallFunctionEx(has_kw) => {
                let kwargs_on_314: bool =
                    active_version().is_some_and(|v: PyVersion| v.major() > 3 || v.minor() >= 14);
                let kwargs: Option<Expr> = if kwargs_on_314 {
                    let top: Expr = sim.pop_or_synth(code, idx);
                    if is_null_marker(&top) {
                        None
                    } else {
                        Some(top)
                    }
                } else if *has_kw {
                    Some(sim.pop_or_synth(code, idx))
                } else {
                    None
                };
                let args_iter: Expr = sim.pop_or_synth(code, idx);
                let (func, _implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(code, idx);
                let args: Vec<Expr> = call_ex_args(args_iter);
                let keywords: Vec<crate::ast::node::Keyword> =
                    kwargs.map(call_ex_kwargs).unwrap_or_default();
                sim.push(Expr::Call {
                    func: Box::new(func),
                    args,
                    keywords,
                });
            }
            CanonicalOp::BuildList(n) | CanonicalOp::BuildSet(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize);
                let pushed: Expr = if matches!(op, CanonicalOp::BuildSet(_)) {
                    Expr::Set(elts)
                } else {
                    Expr::List {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                };
                sim.push(pushed);
            }
            CanonicalOp::BuildTuple(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BuildMap(n) => {
                let presize_hint: bool =
                    active_version().is_some_and(|v: PyVersion| (v.major(), v.minor()) < (3, 5));
                let pair_count: usize = if presize_hint { 0 } else { *n as usize };
                let pairs: Vec<Expr> = sim.pop_n(pair_count.saturating_mul(2));
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(pairs.len() / 2);
                let mut values: Vec<Expr> = Vec::with_capacity(pairs.len() / 2);
                let mut pair_iter: std::vec::IntoIter<Expr> = pairs.into_iter();
                while let (Some(k), Some(v)) = (pair_iter.next(), pair_iter.next()) {
                    keys.push(Some(k));
                    values.push(v);
                }
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::StoreMap => {
                let key: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                match sim.try_pop() {
                    Some(Expr::Dict {
                        mut keys,
                        mut values,
                    }) => {
                        keys.push(Some(key));
                        values.push(value);
                        sim.push(Expr::Dict { keys, values });
                    }
                    Some(other) => {
                        sim.push(other);
                        sim.push(value);
                        sim.push(key);
                    }
                    None => {
                        sim.push(value);
                        sim.push(key);
                    }
                }
            }
            CanonicalOp::BuildConstKeyMap(n) => {
                let key_tuple: Expr = sim.pop_or_synth(code, idx);
                let key_exprs: Vec<Expr> = match key_tuple {
                    Expr::Tuple { elts, .. } => elts,
                    Expr::Constant {
                        value: ConstValue::Tuple(parts),
                        line,
                    } => parts
                        .into_iter()
                        .map(|c: ConstValue| Expr::Constant { value: c, line })
                        .collect(),
                    other => vec![other],
                };
                let count: usize = *n as usize;
                let values: Vec<Expr> = sim.pop_n(count);
                let mut keys: Vec<Option<Expr>> = Vec::with_capacity(values.len());
                for k in key_exprs.into_iter().take(count) {
                    keys.push(Some(k));
                }
                while keys.len() < values.len() {
                    keys.push(None);
                }
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::BuildString(n) => {
                let parts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::JoinedStr {
                    values: parts,
                    line: None,
                });
            }
            CanonicalOp::BuildSlice(n) => {
                let step: Option<Box<Expr>> = if *n == 3 {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let upper: Expr = sim.pop_or_synth(code, idx);
                let lower: Expr = sim.pop_or_synth(code, idx);
                sim.push(Expr::Slice {
                    lower: slice_bound(lower),
                    upper: slice_bound(upper),
                    step,
                });
            }
            CanonicalOp::FormatValue(flags) => {
                let conv_bits: u8 = flags & 0x03;
                let has_spec: bool = (flags & 0x04) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match conv_bits {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec,
                    line: None,
                });
            }
            CanonicalOp::ConvertValue(flags) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match flags & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::FormattedValue {
                    value: Box::new(value),
                    conversion,
                    format_spec: None,
                    line: None,
                });
            }
            CanonicalOp::FormatSimple => {
                let value: Expr = sim.pop_or_synth(code, idx);
                match value {
                    Expr::FormattedValue {
                        conversion,
                        format_spec: None,
                        ..
                    } if conversion != FormatConversion::None => sim.push(value),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: None,
                        line: None,
                    }),
                }
            }
            CanonicalOp::FormatWithSpec => {
                let spec: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                match value {
                    Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: None,
                        line,
                    } if conversion != FormatConversion::None => sim.push(Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: Some(Box::new(spec)),
                        line,
                    }),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: Some(Box::new(spec)),
                        line: None,
                    }),
                }
            }
            CanonicalOp::BuildInterpolation(flags) => {
                let has_spec: bool = (flags & 0x01) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(code, idx)))
                } else {
                    None
                };
                let popped_text: Expr = sim.pop_or_synth(code, idx);
                let expr_text: Option<String> = match popped_text {
                    Expr::Constant {
                        value: ConstValue::Str(s),
                        ..
                    } => Some(s),
                    _ => None,
                };
                let value: Expr = sim.pop_or_synth(code, idx);
                let conversion: FormatConversion = match (flags >> 2) & 0x03 {
                    1 => FormatConversion::Str,
                    2 => FormatConversion::Repr,
                    3 => FormatConversion::Ascii,
                    _ => FormatConversion::None,
                };
                sim.push(Expr::TStr {
                    items: vec![TStrItem::Interp {
                        value,
                        expr_text,
                        conversion,
                        format_spec: format_spec.map(|b: Box<Expr>| *b),
                    }],
                    line: None,
                });
            }
            CanonicalOp::BuildTemplate => {
                let interps: Expr = sim.pop_or_synth(code, idx);
                let statics: Expr = sim.pop_or_synth(code, idx);
                sim.push(build_tstr_expr(statics, interps));
            }
            CanonicalOp::GetIter
            | CanonicalOp::GetAiter
            | CanonicalOp::GetAnext
            | CanonicalOp::ToBool => {
                let value: Expr = sim.pop_or_synth(code, idx);
                sim.push(value);
            }
            CanonicalOp::Dup | CanonicalOp::Copy(1)
                if cmp_chain.is_none()
                    && boolop.is_none()
                    && let Some((groups, chain_end)) = detect_assign_chain(ops, idx)
                    && let Some(targets) = groups
                        .iter()
                        .map(|&(s, e): &(usize, usize)| recover_chain_target(code, ops, s, e))
                        .collect::<Option<Vec<Expr>>>() =>
            {
                let value: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Assign {
                    targets,
                    value,
                    type_comment: None,
                    line: None,
                });
                skip_next = chain_end - idx - 1;
            }
            CanonicalOp::Dup => {
                if let Some(top) = sim.peek_clone() {
                    sim.push(top);
                }
            }
            CanonicalOp::DupTwo => sim.dup_two(),
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n))
                    && !is_chain_sentinel(&v)
                {
                    sim.push(v);
                }
            }
            CanonicalOp::Swap(n) => sim.swap(usize::from(*n)),
            CanonicalOp::RotN(n) => sim.rotn(usize::from(*n)),
            CanonicalOp::Push(_) if is_await_null_slot(ops, idx) => {}
            CanonicalOp::Push(_) => sim.push(Expr::Name {
                id: DR_NULL_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::LoadBuildClass => sim.push(Expr::Name {
                id: DR_BUILD_CLASS_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::LoadAssertionError => sim.push(Expr::Name {
                id: DR_ASSERTION_ERROR_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::MakeFunction(flags) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let mut meta: FunctionMeta = make_function_meta(*flags, &mut sim);
                    let after_attrs: usize =
                        fold_set_function_attributes(code, ops, idx + 1, &mut sim, &mut meta);
                    skip_next = after_attrs.saturating_sub(idx + 1);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::MakeFunctionLegacy(packed) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let meta: FunctionMeta = make_function_meta_legacy(*packed, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::MakeClosureLegacy(packed) => {
                let top: Option<Expr> = sim.try_pop();
                let code_marker: Option<Expr> = match top {
                    Some(t) if nested_code_index(&t).is_some() => Some(t),
                    Some(t) => {
                        let under: Option<Expr> = sim.try_pop();
                        match under {
                            Some(u) if nested_code_index(&u).is_some() => Some(u),
                            other => {
                                if let Some(u) = other {
                                    sim.push(u);
                                }
                                sim.push(t);
                                None
                            }
                        }
                    }
                    None => None,
                };
                if let Some(marker) = code_marker {
                    let _closure: Option<Expr> = sim.try_pop();
                    let meta: FunctionMeta = make_function_meta_legacy(*packed, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker) {
                        if let Some(lambda) = try_build_lambda_expr(code, const_idx, &meta) {
                            sim.push(lambda);
                            continue;
                        }
                        fn_meta.insert(const_idx, meta);
                    }
                    sim.push(marker);
                }
            }
            CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::Resume(_)
            | CanonicalOp::MakeCell(_)
            | CanonicalOp::ReturnGenerator
            | CanonicalOp::BeforeAsyncWith
            | CanonicalOp::SetupAsyncWith
            | CanonicalOp::AsyncForLoop
            | CanonicalOp::AsyncWithExitStart
            | CanonicalOp::AsyncWithExitFinish
            | CanonicalOp::AsyncGenWrap
            | CanonicalOp::PushExcInfo
            | CanonicalOp::PopExcept
            | CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::CleanupThrow
            | CanonicalOp::WithExceptStart
            | CanonicalOp::BeforeWith
            | CanonicalOp::SetupWith(_)
            | CanonicalOp::MatchClass(_)
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchKeys
            | CanonicalOp::GetLen
            | CanonicalOp::EndAsyncFor
            | CanonicalOp::EndSend
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::ForIter(_)
            | CanonicalOp::ForLoopLegacy(_)
            | CanonicalOp::Send(_)
            | CanonicalOp::Specialized(_)
            | CanonicalOp::Other(_, _) => {}
            CanonicalOp::ContinueLoop(_) => out.push(Stmt::Continue),
            CanonicalOp::PrintItem => {
                let item: Expr = sim.pop_or_synth(code, idx);
                let entry: &mut (Option<Expr>, Vec<Expr>) =
                    print_acc.get_or_insert_with(|| (None, Vec::new()));
                entry.1.push(item);
            }
            CanonicalOp::PrintItemTo => {
                let dest: Expr = sim.pop_or_synth(code, idx);
                let item: Expr = sim.pop_or_synth(code, idx);
                let entry: &mut (Option<Expr>, Vec<Expr>) =
                    print_acc.get_or_insert_with(|| (None, Vec::new()));
                if entry.0.is_none() {
                    entry.0 = Some(dest);
                }
                entry.1.push(item);
            }
            CanonicalOp::PrintNewlineTo => {
                let stream: Expr = sim.pop_or_synth(code, idx);
                let (dest, items): (Option<Expr>, Vec<Expr>) =
                    print_acc.take().unwrap_or((None, Vec::new()));
                let dest: Option<Expr> = dest.or(Some(stream));
                out.push(Stmt::Expr(build_print_call(dest, items, false)));
            }
            CanonicalOp::PrintNewline => {
                let (dest, items): (Option<Expr>, Vec<Expr>) =
                    print_acc.take().unwrap_or((None, Vec::new()));
                out.push(Stmt::Expr(build_print_call(dest, items, false)));
            }
            CanonicalOp::PrintExpr => {
                let value: Expr = sim.pop_or_synth(code, idx);
                out.push(Stmt::Expr(value));
            }
            CanonicalOp::Exec => {
                let locals: Expr = sim.pop_or_synth(code, idx);
                let globals: Expr = sim.pop_or_synth(code, idx);
                let body: Expr = sim.pop_or_synth(code, idx);
                let args: Vec<Expr> = build_exec_args(body, globals, locals);
                out.push(Stmt::Expr(Expr::Call {
                    func: Box::new(Expr::Name {
                        id: "exec".to_owned(),
                        ctx: ExprCtx::Load,
                        line: None,
                    }),
                    args,
                    keywords: Vec::new(),
                }));
            }
            CanonicalOp::BuildClassLegacy => {
                let class_dict: Expr = sim.pop_or_synth(code, idx);
                let bases_expr: Expr = sim.pop_or_synth(code, idx);
                let name_expr: Expr = sim.pop_or_synth(code, idx);
                let code_marker: Expr = match class_dict {
                    Expr::Call { func, ref args, .. } if args.is_empty() => *func,
                    other => other,
                };
                let name: String = extract_str_const(&name_expr).unwrap_or_default();
                let bases: Vec<Expr> = match bases_expr {
                    Expr::Tuple { elts, .. } => elts,
                    _ => Vec::new(),
                };
                let mut call_args: Vec<Expr> = Vec::with_capacity(bases.len() + 2);
                call_args.push(code_marker);
                call_args.push(Expr::Constant {
                    value: ConstValue::Str(name),
                    line: None,
                });
                call_args.extend(bases);
                sim.push(Expr::Call {
                    func: Box::new(Expr::Name {
                        id: DR_BUILD_CLASS_MARKER.to_owned(),
                        ctx: ExprCtx::Load,
                        line: None,
                    }),
                    args: call_args,
                    keywords: Vec::new(),
                });
            }
            CanonicalOp::Pop => {
                if print_acc
                    .as_ref()
                    .is_some_and(|(dest, _): &(Option<Expr>, Vec<Expr>)| dest.is_some())
                {
                    let _stream: Expr = sim.pop_or_synth(code, idx);
                    let (dest, items): (Option<Expr>, Vec<Expr>) =
                        print_acc.take().unwrap_or((None, Vec::new()));
                    out.push(Stmt::Expr(build_print_call(dest, items, true)));
                    continue;
                }
                if let Some(value) = sim.try_pop() {
                    if is_chain_sentinel(&value)
                        || is_null_marker(&value)
                        || decode_import_fromset_marker(&value).is_some()
                        || decode_import_module_marker(&value).is_some()
                        || decode_import_attr_marker(&value).is_some()
                    {
                        continue;
                    }
                    out.push(Stmt::Expr(value));
                }
            }
            CanonicalOp::DiscardTop => {
                let _ = sim.try_pop();
            }
            CanonicalOp::SetFunctionAttribute(flag) => {
                let func: Option<Expr> = sim.try_pop();
                let attr: Option<Expr> = sim.try_pop();
                if let (Some(f), Some(a)) = (&func, attr)
                    && let Some(const_idx) = nested_code_index(f)
                {
                    let entry: &mut FunctionMeta = fn_meta.entry(const_idx).or_default();
                    match flag {
                        1 => entry.defaults = defaults_from_expr(a),
                        2 => entry.kw_defaults = kwdefaults_from_expr(a),
                        4 => {
                            let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                annotations_from_expr(a);
                            entry.annotations = params;
                            entry.returns = ret;
                        }
                        16 => {
                            if let Some(dict) = annotate_codeobj_dict(code, &a) {
                                let (params, ret): (Vec<(String, Expr)>, Option<Expr>) =
                                    annotations_from_expr(dict);
                                if !params.is_empty() {
                                    entry.annotations = params;
                                }
                                if ret.is_some() {
                                    entry.returns = ret;
                                }
                            }
                        }
                        _ => {}
                    }
                }
                if let Some(f) = func {
                    sim.push(f);
                }
            }
            CanonicalOp::CallIntrinsic1(intrinsic) => match intrinsic {
                2 => {
                    out.push(import_star_stmt(sim.try_pop()));
                }
                7..=9 => {
                    let name_expr: Expr = sim.pop_or_synth(code, idx);
                    let name: String = extract_str_const(&name_expr).unwrap_or_default();
                    let kind: TypeParamKind = type_param_kind_from_intrinsic1(*intrinsic)
                        .unwrap_or(TypeParamKind::TypeVar);
                    sim.push(build_typevar_marker(kind, &name, None));
                }
                11 => {
                    let tuple: Expr = sim.pop_or_synth(code, idx);
                    if let Expr::Tuple { mut elts, .. } = tuple
                        && elts.len() == 3
                    {
                        let evaluator: Expr = elts.pop().unwrap_or(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                        let _type_params: Option<Expr> = elts.pop();
                        let name: String = elts
                            .pop()
                            .as_ref()
                            .and_then(extract_str_const)
                            .unwrap_or_default();
                        let value: Expr =
                            unwrap_evaluator_expr(code, &evaluator).unwrap_or(evaluator);
                        sim.push(type_alias_marker_call(&name, value));
                    }
                }
                5 => {
                    let operand: Expr = sim.pop_or_synth(code, idx);
                    sim.push(Expr::UnaryOp {
                        op: crate::bytecode::opcode::UnaryOp::Positive,
                        operand: Box::new(operand),
                    });
                }
                6 => {
                    let value: Expr = sim.pop_or_synth(code, idx);
                    let elts: Vec<Expr> = match value {
                        Expr::List { elts, .. } => elts,
                        other => vec![other],
                    };
                    sim.push(Expr::Tuple {
                        elts,
                        ctx: ExprCtx::Load,
                    });
                }
                _ => {}
            },
            CanonicalOp::CallIntrinsic2(intrinsic) => match intrinsic {
                2 | 3 => {
                    let evaluator: Expr = sim.pop_or_synth(code, idx);
                    let name_expr: Expr = sim.pop_or_synth(code, idx);
                    let name: String = extract_str_const(&name_expr).unwrap_or_default();
                    let bound: Option<Expr> = unwrap_evaluator_expr(code, &evaluator);
                    sim.push(build_typevar_marker(TypeParamKind::TypeVar, &name, bound));
                }
                4 => {
                    let _type_params: Expr = sim.pop_or_synth(code, idx);
                    let func: Expr = sim.pop_or_synth(code, idx);
                    sim.push(func);
                }
                _ => {}
            },
            CanonicalOp::Return => {
                let value: Option<Expr> = sim.try_pop();
                let value: Option<Expr> = filter_async_gen_return(code, value);
                out.push(Stmt::Return(value));
            }
            CanonicalOp::ReturnConst(i) => {
                let value: Expr = load_const(code, *i, idx)?;
                let value: Option<Expr> = filter_async_gen_return(code, Some(value));
                out.push(Stmt::Return(value));
            }
            CanonicalOp::Yield => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let is_async_ctx: bool =
                    (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
                let is_none_const: bool = matches!(
                    value,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                );
                if is_async_ctx && is_none_const && is_await_poll_yield(ops, idx) {
                    continue;
                }
                if is_async_ctx
                    && is_none_const
                    && sim.peek_clone().is_some_and(|u: Expr| {
                        matches!(u, Expr::Await(_)) || is_comprehension_expr(&u)
                    })
                {
                    continue;
                }
                if !is_async_ctx
                    && is_none_const
                    && is_yield_from_send_pattern(ops, idx)
                    && let Some(iter) = sim.try_pop()
                {
                    sim.push(Expr::YieldFrom(Box::new(iter)));
                    continue;
                }
                if is_pre23_statement_yield() {
                    out.push(Stmt::Expr(Expr::Yield(Some(Box::new(value)))));
                    continue;
                }
                sim.push(Expr::Yield(Some(Box::new(value))));
            }
            CanonicalOp::YieldFrom => {
                let top: Expr = sim.pop_or_synth(code, idx);
                let is_none_const: bool = matches!(
                    top,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                );
                let is_async_ctx: bool =
                    (code.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
                if is_async_ctx {
                    if is_none_const && matches!(sim.peek_clone(), Some(Expr::Await(_))) {
                        continue;
                    }
                    if let Some(under) = sim.peek_clone() {
                        let _ = sim.try_pop();
                        if matches!(under, Expr::Await(_)) || is_comprehension_expr(&under) {
                            sim.push(under);
                        } else {
                            sim.push(Expr::Await(Box::new(under)));
                        }
                        continue;
                    }
                    continue;
                }
                let value: Expr = if is_none_const {
                    match sim.peek_clone() {
                        Some(under)
                            if !matches!(
                                under,
                                Expr::Await(_) | Expr::Yield(_) | Expr::YieldFrom(_)
                            ) =>
                        {
                            let _ = sim.try_pop();
                            under
                        }
                        _ => top,
                    }
                } else {
                    top
                };
                let expr: Expr = Expr::YieldFrom(Box::new(value));
                sim.push(expr);
            }
            CanonicalOp::StoreGlobal(i) | CanonicalOp::StoreName(i) => {
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                if is_walrus_store(ops, idx, &target_name) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: target_name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                if let Some((mod_name, _level, attr)) = decode_import_attr_marker(&value) {
                    let _ = mod_name;
                    if attr != target_name {
                        update_last_import_from_asname(&mut out, &attr, &target_name);
                    }
                    continue;
                }
                if let Some(marker) = decode_import_module_marker(&value) {
                    out.push(import_module_to_stmt(&marker, &target_name));
                    continue;
                }
                if let Some(alias) = try_build_type_alias(&value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(alias) = try_build_generic_type_alias(code, &value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(generic_def) = try_build_generic_def(code, &value, &target_name) {
                    out.push(generic_def);
                    continue;
                }
                if let Some(decorated) = try_build_decorated_generic_def(code, &value, &target_name)
                {
                    out.push(decorated);
                    continue;
                }
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(class_def) = try_build_decorated_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(mut fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
                {
                    if let Some(meta) = fn_meta.get(&const_idx) {
                        attach_fn_meta(&mut fn_def, meta);
                    }
                    out.push(fn_def);
                    continue;
                }
                if let Some(fn_def) =
                    try_build_decorated_function_def(code, &value, &target_name, &fn_meta)
                {
                    out.push(fn_def);
                    continue;
                }
                let target: Expr = Expr::Name {
                    id: target_name,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::StoreAnnotation(i) => {
                let annotation: Expr = sim.pop_or_synth(code, idx);
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                out.push(Stmt::AnnAssign {
                    target: Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Store,
                        line: None,
                    },
                    annotation,
                    value: None,
                    simple: true,
                    line: None,
                });
            }
            CanonicalOp::StoreFast(i) => {
                let target_name: String = local_name_at(code, *i, idx)?;
                if is_walrus_store(ops, idx, &target_name) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: target_name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                if is_typevar_marker(&value) {
                    continue;
                }
                if let Some((mod_name, _level, attr)) = decode_import_attr_marker(&value) {
                    let _ = mod_name;
                    if attr != target_name {
                        update_last_import_from_asname(&mut out, &attr, &target_name);
                    }
                    continue;
                }
                if let Some(marker) = decode_import_module_marker(&value) {
                    out.push(import_module_to_stmt(&marker, &target_name));
                    continue;
                }
                if let Some(alias) = try_build_type_alias(&value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(alias) = try_build_generic_type_alias(code, &value, &target_name) {
                    out.push(alias);
                    continue;
                }
                if let Some(generic_def) = try_build_generic_def(code, &value, &target_name) {
                    out.push(generic_def);
                    continue;
                }
                if let Some(decorated) = try_build_decorated_generic_def(code, &value, &target_name)
                {
                    out.push(decorated);
                    continue;
                }
                if let Some(class_def) = try_build_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(class_def) = try_build_decorated_class_def(code, &value, &target_name) {
                    out.push(class_def);
                    continue;
                }
                if let Some(const_idx) = nested_code_index(&value)
                    && let Some(mut fn_def) =
                        build_nested_function_def(code, const_idx, target_name.clone(), false)
                {
                    if let Some(meta) = fn_meta.get(&const_idx) {
                        attach_fn_meta(&mut fn_def, meta);
                    }
                    out.push(fn_def);
                    continue;
                }
                if let Some(fn_def) =
                    try_build_decorated_function_def(code, &value, &target_name, &fn_meta)
                {
                    out.push(fn_def);
                    continue;
                }
                let target: Expr = Expr::Name {
                    id: target_name,
                    ctx: ExprCtx::Store,
                    line: None,
                };
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                sim.push(load_local(code, *a, idx)?);
                sim.push(load_local(code, *b, idx)?);
            }
            CanonicalOp::StoreFastLoadFast(a, b) => {
                if idx > 0 && matches!(ops[idx - 1], CanonicalOp::Copy(1) | CanonicalOp::Dup) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    let name: String = local_name_at(code, *a, idx)?;
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    sim.push(load_local(code, *b, idx)?);
                    continue;
                }
                let value: Expr = sim.pop_or_synth(code, idx);
                let target: Expr = local_target(code, *a, idx)?;
                out.push(Stmt::Assign {
                    targets: vec![target],
                    value,
                    type_comment: None,
                    line: None,
                });
                sim.push(load_local(code, *b, idx)?);
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if idx > 0 && matches!(ops[idx - 1], CanonicalOp::Copy(1) | CanonicalOp::Dup) {
                    let _dup: Expr = sim.pop_or_synth(code, idx);
                    let underlying: Expr = sim.pop_or_synth(code, idx);
                    let inner_name: String = local_name_at(code, *a, idx)?;
                    let outer_target: Expr = local_target(code, *b, idx)?;
                    out.push(Stmt::Assign {
                        targets: vec![outer_target],
                        value: Expr::NamedExpr {
                            target: Box::new(Expr::Name {
                                id: inner_name,
                                ctx: ExprCtx::Store,
                                line: None,
                            }),
                            value: Box::new(underlying),
                        },
                        type_comment: None,
                        line: None,
                    });
                    continue;
                }
                if let Some(trailing_idx) = three_target_sfsf_tail(ops, idx, &sim) {
                    let t1: Expr = store_target_at(code, &ops[trailing_idx], trailing_idx)?;
                    let t2: Expr = local_target(code, *b, idx)?;
                    let t3: Expr = local_target(code, *a, idx)?;
                    let v3: Expr = sim.pop_or_synth(code, idx);
                    let v2: Expr = sim.pop_or_synth(code, idx);
                    let v1: Expr = sim.pop_or_synth(code, idx);
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: vec![t1, t2, t3],
                            ctx: ExprCtx::Store,
                        }],
                        value: Expr::Tuple {
                            elts: vec![v1, v2, v3],
                            ctx: ExprCtx::Load,
                        },
                        type_comment: None,
                        line: None,
                    });
                    skip_next = trailing_idx - idx;
                    continue;
                }
                let v_b: Expr = sim.pop_or_synth(code, idx);
                let v_a: Expr = sim.pop_or_synth(code, idx);
                let target_a: Expr = local_target(code, *a, idx)?;
                let target_b: Expr = local_target(code, *b, idx)?;
                out.push(Stmt::Assign {
                    targets: vec![Expr::Tuple {
                        elts: vec![target_b, target_a],
                        ctx: ExprCtx::Store,
                    }],
                    value: Expr::Tuple {
                        elts: vec![v_a, v_b],
                        ctx: ExprCtx::Load,
                    },
                    type_comment: None,
                    line: None,
                });
            }
            CanonicalOp::MapAdd => {
                let pre38_order: bool =
                    active_version().is_some_and(|v: PyVersion| v.major() == 3 && v.minor() < 8);
                let top: Expr = sim.pop_or_synth(code, idx);
                let below: Expr = sim.pop_or_synth(code, idx);
                let (key, value): (Expr, Expr) = if pre38_order {
                    (top, below)
                } else {
                    (below, top)
                };
                match sim.try_pop() {
                    Some(Expr::Dict {
                        mut keys,
                        mut values,
                    }) => {
                        keys.push(Some(key));
                        values.push(value);
                        sim.push(Expr::Dict { keys, values });
                    }
                    Some(other) => {
                        sim.push(other);
                        sim.push(value);
                        sim.push(key);
                    }
                    None => {
                        sim.push(value);
                        sim.push(key);
                    }
                }
            }
            CanonicalOp::UnpackSequence(n) => {
                let source: Expr = sim.pop_or_synth(code, idx);
                let n_usize: usize = *n as usize;
                if n_usize == 0 {
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: Vec::new(),
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                } else if let Some((targets, skip)) =
                    collect_unpack_targets(code, ops, idx + 1, n_usize)
                {
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: targets,
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                    skip_next = skip;
                } else {
                    sim.push(source);
                    for _ in 0..n_usize.min(MAX_SYNTH_OPERANDS) {
                        sim.push(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                    }
                }
            }
            CanonicalOp::UnpackEx(arg) => {
                let source: Expr = sim.pop_or_synth(code, idx);
                let before: u32 = arg & 0xFF;
                let after: u32 = arg >> 8;
                let total: usize = (before + after + 1) as usize;
                if let Some((mut targets, skip)) = collect_unpack_targets(code, ops, idx + 1, total)
                {
                    let star_idx: usize = before as usize;
                    if star_idx < targets.len() {
                        let starred_val: Expr = targets.remove(star_idx);
                        targets.insert(
                            star_idx,
                            Expr::Starred {
                                value: Box::new(starred_val),
                                ctx: ExprCtx::Store,
                            },
                        );
                    }
                    out.push(Stmt::Assign {
                        targets: vec![Expr::Tuple {
                            elts: targets,
                            ctx: ExprCtx::Store,
                        }],
                        value: source,
                        type_comment: None,
                        line: None,
                    });
                    skip_next = skip;
                } else {
                    for _ in 0..total.min(MAX_SYNTH_OPERANDS) {
                        sim.push(Expr::Constant {
                            value: ConstValue::None,
                            line: None,
                        });
                    }
                }
            }
            CanonicalOp::ListExtend(_) | CanonicalOp::SetUpdate(_) => {
                let iterable: Expr = sim.pop_or_synth(code, idx);
                let base: Option<Expr> = sim.try_pop();
                let merged: Expr = merge_extend(base, iterable, false);
                sim.push(merged);
            }
            CanonicalOp::DictMerge(_) | CanonicalOp::DictUpdate(_) => {
                let mapping: Expr = sim.pop_or_synth(code, idx);
                let base: Option<Expr> = sim.try_pop();
                let merged: Expr = merge_extend(base, mapping, true);
                sim.push(merged);
            }
            CanonicalOp::ListToTuple => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let elts: Vec<Expr> = match value {
                    Expr::List { elts, .. } => elts,
                    other => vec![other],
                };
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BuildTupleUnpack(n) | CanonicalOp::BuildListUnpack(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize).into_iter().map(starred).collect();
                sim.push(if matches!(op, CanonicalOp::BuildTupleUnpack(_)) {
                    Expr::Tuple {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                } else {
                    Expr::List {
                        elts,
                        ctx: ExprCtx::Load,
                    }
                });
            }
            CanonicalOp::BuildSetUnpack(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize).into_iter().map(starred).collect();
                sim.push(Expr::Set(elts));
            }
            CanonicalOp::BuildMapUnpack(n) => {
                let values: Vec<Expr> = sim.pop_n(*n as usize);
                let keys: Vec<Option<Expr>> = vec![None; values.len()];
                sim.push(Expr::Dict { keys, values });
            }
            CanonicalOp::GetAwaitable => {
                let value: Expr = sim.pop_or_synth(code, idx);
                if is_comprehension_expr(&value) {
                    sim.push(value);
                } else {
                    sim.push(Expr::Await(Box::new(value)));
                }
            }
            CanonicalOp::Raise(argc) => {
                let cause: Option<Expr> = if *argc >= 2 { sim.try_pop() } else { None };
                let exc: Option<Expr> = if *argc >= 1 { sim.try_pop() } else { None };
                if let Some(e) = &exc
                    && is_assertion_error_marker(e)
                {
                    out.push(Stmt::Assert {
                        test: Expr::Constant {
                            value: ConstValue::False,
                            line: None,
                        },
                        msg: None,
                        line: None,
                    });
                    continue;
                }
                out.push(Stmt::Raise {
                    exc,
                    cause,
                    line: None,
                });
            }
            CanonicalOp::Reraise(_) => {
                out.push(Stmt::Raise {
                    exc: None,
                    cause: None,
                    line: None,
                });
            }
            CanonicalOp::DeleteFast(i) => {
                let target_name: String = local_name_at(code, *i, idx)?;
                merge_or_push_delete(
                    &mut out,
                    Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Del,
                        line: None,
                    },
                );
            }
            CanonicalOp::DeleteName(i) => {
                let target_name: String = name_at(&code.names, *i, idx, "name")?;
                merge_or_push_delete(
                    &mut out,
                    Expr::Name {
                        id: target_name,
                        ctx: ExprCtx::Del,
                        line: None,
                    },
                );
            }
            CanonicalOp::DeleteAttr(i) => {
                let value: Expr = sim.pop_or_synth(code, idx);
                let attr: String = name_at_either(code, *i).unwrap_or_else(|_| format!("attr_{i}"));
                merge_or_push_delete(
                    &mut out,
                    Expr::Attribute {
                        value: Box::new(value),
                        attr,
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::DeleteSubscr => {
                let slice: Expr = sim.pop_or_synth(code, idx);
                let value: Expr = sim.pop_or_synth(code, idx);
                merge_or_push_delete(
                    &mut out,
                    Expr::Subscript {
                        value: Box::new(value),
                        slice: Box::new(slice),
                        ctx: ExprCtx::Del,
                    },
                );
            }
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
            | CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::JumpIfFalseOrPop(_) => {
                if is_chain_compare_jump(ops, idx) {
                    continue;
                }
                let _condition: Expr = sim.pop_or_synth(code, idx);
            }
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                let item: Expr = sim.pop_or_synth(code, idx);
                match sim.peek_clone() {
                    Some(Expr::List {
                        elts: list_elts,
                        ctx,
                    }) => {
                        let mut elts: Vec<Expr> = list_elts;
                        elts.push(item);
                        let _ = sim.try_pop();
                        sim.push(Expr::List { elts, ctx });
                    }
                    Some(Expr::Set(set_elts)) => {
                        let mut elts: Vec<Expr> = set_elts;
                        elts.push(item);
                        let _ = sim.try_pop();
                        sim.push(Expr::Set(elts));
                    }
                    _ => {}
                }
            }
        }
    }
    if let Some((dest, items)) = print_acc.take() {
        out.push(Stmt::Expr(build_print_call(dest, items, true)));
    }
    flush_boolop(&mut sim, &mut boolop);
    let residual: Vec<Expr> = sim.stack;
    Ok((out, residual))
}

const DR_PRINT_DEST_MARKER: &str = "__DR_PRINT_DEST__";
const DR_PRINT_NONL_MARKER: &str = "__DR_PRINT_NONL__";

fn build_print_call(dest: Option<Expr>, items: Vec<Expr>, trailing_comma: bool) -> Expr {
    let mut args: Vec<Expr> = Vec::with_capacity(items.len() + 3);
    if let Some(stream) = dest {
        args.push(Expr::Name {
            id: DR_PRINT_DEST_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        });
        args.push(stream);
    }
    args.extend(items);
    if trailing_comma {
        args.push(Expr::Name {
            id: DR_PRINT_NONL_MARKER.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        });
    }
    Expr::Call {
        func: Box::new(Expr::Name {
            id: "print".to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }),
        args,
        keywords: Vec::new(),
    }
}

fn build_exec_args(body: Expr, globals: Expr, locals: Expr) -> Vec<Expr> {
    let globals_is_none: bool = matches!(
        globals,
        Expr::Constant {
            value: ConstValue::None,
            ..
        }
    );
    if globals_is_none {
        vec![body]
    } else if globals == locals {
        vec![body, globals]
    } else {
        vec![body, globals, locals]
    }
}

pub(super) fn value_boolop_at(
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<crate::ast::node::BoolOpKind> {
    use crate::ast::node::BoolOpKind;
    if is_chain_compare_jump(ops, idx) {
        return None;
    }
    match ops[idx] {
        CanonicalOp::JumpIfFalseOrPop(_) => Some(BoolOpKind::And),
        CanonicalOp::JumpIfTrueOrPop(_) => Some(BoolOpKind::Or),
        CanonicalOp::Copy(1) => {
            let jump: usize = skip_to_bool_jump(ops, idx + 1)?;
            match ops[jump] {
                CanonicalOp::PopJumpIfFalse(_) => Some(BoolOpKind::And),
                CanonicalOp::PopJumpIfTrue(_) => Some(BoolOpKind::Or),
                _ => None,
            }
        }
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => {
            inner_short_circuit_polarity(ops, idx)
        }
        _ => None,
    }
}

fn is_value_boolop_shortcircuit(ops: &[CanonicalOp], idx: usize) -> bool {
    value_boolop_at(ops, idx).is_some()
}

fn boolop_value_consumer(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Return
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
    )
}

fn boolop_operand_merge_point(ops: &[CanonicalOp], target: usize) -> usize {
    if target > 0
        && matches!(ops.get(target), Some(CanonicalOp::Push(_)))
        && matches!(
            ops.get(target - 1),
            Some(
                CanonicalOp::LoadAttr(_)
                    | CanonicalOp::LoadSpecial(_)
                    | CanonicalOp::LoadSuperAttr { .. }
            )
        )
    {
        return target - 1;
    }
    target
}

pub(super) fn inner_short_circuit_polarity(
    ops: &[CanonicalOp],
    idx: usize,
) -> Option<crate::ast::node::BoolOpKind> {
    use crate::ast::node::BoolOpKind;
    let local_kind: BoolOpKind = match ops[idx] {
        CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
        CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
        _ => return None,
    };
    let next: usize = first_significant_after(ops, idx + 1)?;
    let after_load: usize = first_significant_after(ops, next + 1)?;
    let outer_kind: BoolOpKind = match ops.get(after_load)? {
        CanonicalOp::JumpIfFalseOrPop(_) => BoolOpKind::And,
        CanonicalOp::JumpIfTrueOrPop(_) => BoolOpKind::Or,
        CanonicalOp::Copy(1) => {
            let jump: usize = skip_to_bool_jump(ops, after_load + 1)?;
            match ops[jump] {
                CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
                CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
                _ => return None,
            }
        }
        _ => return None,
    };
    if outer_kind == local_kind {
        return None;
    }
    Some(local_kind)
}

pub(super) fn first_significant_after(ops: &[CanonicalOp], from: usize) -> Option<usize> {
    let mut i: usize = from;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            _ => return Some(i),
        }
    }
    None
}

pub(super) fn skip_to_bool_jump(ops: &[CanonicalOp], start: usize) -> Option<usize> {
    let mut i: usize = start;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::ToBool | CanonicalOp::Cache | CanonicalOp::Nop => i += 1,
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => return Some(i),
            _ => return None,
        }
    }
    None
}

pub(super) fn boolop_shortcircuit_skip(ops: &[CanonicalOp], idx: usize) -> usize {
    if !matches!(ops[idx], CanonicalOp::Copy(1)) {
        return 0;
    }
    let Some(jump): Option<usize> = skip_to_bool_jump(ops, idx + 1) else {
        return 0;
    };
    let mut count: usize = jump - idx;
    let mut i: usize = jump + 1;
    while i < ops.len() {
        match ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop => {
                count += 1;
                i += 1;
            }
            CanonicalOp::Pop => {
                count += 1;
                break;
            }
            _ => break,
        }
    }
    count
}

#[derive(Debug, Clone)]
pub(super) struct ShortCircuitItem {
    pub(super) expr: Expr,
    pub(super) op: crate::ast::node::BoolOpKind,
    pub(super) target: usize,
    pub(super) sc_idx: usize,
    pub(super) value_lo: usize,
}

pub(super) fn fold_short_circuit_items(items: Vec<ShortCircuitItem>) -> Option<Expr> {
    use crate::ast::node::BoolOpKind;
    let mut items: Vec<ShortCircuitItem> = items;
    let exit: usize = items
        .last()
        .map_or(usize::MAX, |o: &ShortCircuitItem| o.sc_idx);
    let group_span = |items: &[ShortCircuitItem], i: usize| -> usize {
        let target: usize = items[i].target;
        let mut k: usize = i + 1;
        while k < items.len() && items[k].value_lo < target {
            k += 1;
        }
        k
    };
    loop {
        let inner_idx: Option<usize> = (0..items.len()).rev().find(|&i: &usize| {
            i + 1 != items.len() && items[i].target != exit && group_span(&items, i) > i + 1
        });
        let Some(i): Option<usize> = inner_idx else {
            break;
        };
        let group_op: BoolOpKind = items[i].op;
        let k: usize = group_span(&items, i);
        if k <= i + 1 || k > items.len() {
            return None;
        }
        let group: Vec<ShortCircuitItem> = items.splice(i..k, std::iter::empty()).collect();
        let (tail_op, tail_target, tail_sc, tail_lo): (BoolOpKind, usize, usize, usize) = {
            let last: &ShortCircuitItem = group.last()?;
            (last.op, last.target, last.sc_idx, group[0].value_lo)
        };
        let mut values: Vec<Expr> = Vec::with_capacity(group.len());
        for member in group {
            match member.expr {
                Expr::BoolOp { op, values: inner } if op == group_op => values.extend(inner),
                other => values.push(other),
            }
        }
        let merged: Expr = if values.len() == 1 {
            values.into_iter().next()?
        } else {
            Expr::BoolOp {
                op: group_op,
                values,
            }
        };
        items.insert(
            i,
            ShortCircuitItem {
                expr: merged,
                op: tail_op,
                target: tail_target,
                sc_idx: tail_sc,
                value_lo: tail_lo,
            },
        );
    }
    fold_same_level_items(&items)
}

fn fold_same_level_items(items: &[ShortCircuitItem]) -> Option<Expr> {
    use crate::ast::node::BoolOpKind;
    if items.is_empty() {
        return None;
    }
    if items.len() == 1 {
        return Some(items[0].expr.clone());
    }
    let level_op: BoolOpKind = items[0].op;
    let last: usize = items.len() - 1;
    let mut values: Vec<Expr> = Vec::new();
    let mut i: usize = 0;
    while i < items.len() {
        if i == last || items[i].op == level_op {
            values.push(items[i].expr.clone());
            i += 1;
            continue;
        }
        let mut group_end: usize = i;
        while group_end < last && items[group_end].op != level_op {
            group_end += 1;
        }
        group_end += 1;
        let nested: Expr = fold_same_level_items(&items[i..group_end])?;
        values.push(nested);
        i = group_end;
    }
    if values.len() < 2 {
        return values.into_iter().next();
    }
    Some(Expr::BoolOp {
        op: level_op,
        values,
    })
}

fn flush_boolop(sim: &mut StackSim, boolop: &mut BoolopAcc) {
    let Some(acc): Option<BoolopAccState> = boolop.take() else {
        return;
    };
    let Some(tail): Option<Expr> = sim.try_pop() else {
        if let Some(first) = acc.operands.into_iter().next() {
            sim.push(first.expr);
        }
        return;
    };
    if let Some(expr) = acc.fold_with(&tail) {
        sim.push(expr);
        return;
    }
    let mut values: Vec<Expr> = acc
        .operands
        .into_iter()
        .map(|o: AccOperand| o.expr)
        .collect();
    values.push(tail);
    sim.push(Expr::BoolOp {
        op: acc.kind,
        values,
    });
}

#[derive(Debug, Default)]
pub(super) struct StackSim {
    pub(super) stack: Vec<Expr>,
}

impl StackSim {
    pub(super) fn new() -> Self {
        Self { stack: Vec::new() }
    }

    pub(super) fn push(&mut self, e: Expr) {
        self.stack.push(e);
    }

    fn len(&self) -> usize {
        self.stack.len()
    }

    pub(super) fn try_pop(&mut self) -> Option<Expr> {
        self.stack.pop()
    }

    pub(super) fn peek_clone(&self) -> Option<Expr> {
        self.stack.last().cloned()
    }

    pub(super) fn peek_at(&self, n: usize) -> Option<Expr> {
        if n == 0 || self.stack.len() < n {
            return None;
        }
        self.stack.get(self.stack.len() - n).cloned()
    }

    pub(super) fn swap(&mut self, n: usize) {
        let len: usize = self.stack.len();
        if n >= 2 && len >= n {
            self.stack.swap(len - 1, len - n);
        }
    }

    fn rotn(&mut self, n: usize) {
        let len: usize = self.stack.len();
        if n >= 2 && len >= n {
            let top: Expr = self.stack.remove(len - 1);
            self.stack.insert(len - n, top);
        }
    }

    pub(super) fn dup_two(&mut self) {
        let len: usize = self.stack.len();
        if len >= 2 {
            let second: Expr = self.stack[len - 2].clone();
            let first: Expr = self.stack[len - 1].clone();
            self.stack.push(second);
            self.stack.push(first);
        } else if let Some(top) = self.stack.last().cloned() {
            self.stack.push(top);
        }
    }

    pub(super) fn pop_or_synth(&mut self, code: &CodeObject, idx: usize) -> Expr {
        let _: (&CodeObject, usize) = (code, idx);
        self.stack.pop().unwrap_or(Expr::Constant {
            value: ConstValue::None,
            line: None,
        })
    }

    pub(super) fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        let len: usize = self.stack.len();
        let take: usize = n.min(len);
        let target: usize = n.min(len.saturating_add(MAX_SYNTH_OPERANDS));
        let fill: usize = target.saturating_sub(take);
        let mut out: Vec<Expr> = Vec::with_capacity(target);
        for _ in 0..fill {
            out.push(Expr::Constant {
                value: ConstValue::None,
                line: None,
            });
        }
        out.extend(self.stack.drain(len - take..));
        out
    }

    pub(super) fn pop_call_target(
        &mut self,
        code: &CodeObject,
        idx: usize,
    ) -> (Expr, Option<Expr>) {
        let two_slot: bool = active_version().is_some_and(|v: PyVersion| !v.is_pre_311());
        if !two_slot {
            return (self.pop_or_synth(code, idx), None);
        }
        let tos1: Expr = self.pop_or_synth(code, idx);
        if is_null_marker(&tos1) {
            return (self.pop_or_synth(code, idx), None);
        }
        match self.try_pop() {
            Some(callable) if is_null_marker(&callable) => (tos1, None),
            Some(callable) => (callable, Some(tos1)),
            None => (tos1, None),
        }
    }

    #[allow(dead_code)]
    fn pop(&mut self, offset: usize, ctx: &'static str) -> Result<Expr> {
        self.stack.pop().ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("stack underflow at {ctx}"),
        })
    }
}

pub(super) const DR_CODE_CONST_PREFIX: &str = "__DR_CODE_CONST_";
const DR_IMPORT_MODULE_PREFIX: &str = "__DR_IMPORT_MOD__";
const DR_IMPORT_FROMSET_PREFIX: &str = "__DR_IMPORT_FROMSET__";
const DR_IMPORT_ATTR_PREFIX: &str = "__DR_IMPORT_ATTR__";
pub(super) const DR_BUILD_CLASS_MARKER: &str = "__DR_BUILD_CLASS__";
const DR_ASSERTION_ERROR_MARKER: &str = "__DR_ASSERTION_ERROR__";
pub(super) const DR_NULL_MARKER: &str = "__DR_NULL__";
pub(super) const DR_UNRECOVERED_TARGET: &str = "__DR_UNRECOVERED_TARGET__";
const DR_KW_NAMES_PREFIX: &str = "__DR_KW_NAMES__\u{0}";
pub(super) const DR_TYPE_ALIAS_MARKER: &str = "__DR_TYPE_ALIAS__";
pub(super) const DR_TYPEVAR_MARKER: &str = "__DR_TYPEVAR__";
const MAX_IMPORT_LEVEL: u32 = 32;

const fn bounded_import_level(level: u32) -> u32 {
    if level > MAX_IMPORT_LEVEL {
        MAX_IMPORT_LEVEL
    } else {
        level
    }
}

pub(super) fn is_build_class_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_BUILD_CLASS_MARKER)
}

fn is_walrus_store(ops: &[CanonicalOp], idx: usize, target_name: &str) -> bool {
    idx > 0
        && matches!(ops[idx - 1], CanonicalOp::Dup | CanonicalOp::Copy(1))
        && !matches!(target_name, "__classcell__" | "__class__")
}

const DR_CHAIN_VALUE_MARKER: &str = "__DR_CHAIN_VALUE__";

fn is_chain_value_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_CHAIN_VALUE_MARKER)
}

fn is_chain_target_store(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreSlice
    )
}

pub(super) fn chain_group_end(ops: &[CanonicalOp], start: usize) -> Option<usize> {
    let mut i: usize = start;
    let mut pending: usize = 1;
    while i < ops.len() {
        match &ops[i] {
            CanonicalOp::UnpackSequence(n) => {
                pending = pending - 1 + *n as usize;
            }
            CanonicalOp::UnpackEx(arg) => {
                let before: usize = (arg & 0xFF) as usize;
                let after: usize = (arg >> 8) as usize;
                pending = pending - 1 + before + after + 1;
            }
            op if is_chain_target_store(op) => {
                pending -= 1;
            }
            _ => {}
        }
        i += 1;
        if pending == 0 {
            return Some(i);
        }
    }
    None
}

fn detect_assign_chain(
    ops: &[CanonicalOp],
    dup_idx: usize,
) -> Option<(Vec<(usize, usize)>, usize)> {
    if !matches!(
        ops.get(dup_idx),
        Some(CanonicalOp::Dup | CanonicalOp::Copy(1))
    ) {
        return None;
    }
    let mut groups: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = dup_idx;
    while matches!(ops.get(i), Some(CanonicalOp::Dup | CanonicalOp::Copy(1))) {
        let group_start: usize = i + 1;
        let group_end: usize = chain_group_end(ops, group_start)?;
        groups.push((group_start, group_end));
        i = group_end;
    }
    let terminal_end: usize = chain_group_end(ops, i)?;
    groups.push((i, terminal_end));
    if groups.len() < 2 {
        return None;
    }
    if groups
        .iter()
        .any(|&(s, e): &(usize, usize)| !group_is_pure_target(ops, s, e))
    {
        return None;
    }
    Some((groups, terminal_end))
}

fn group_is_pure_target(ops: &[CanonicalOp], start: usize, end: usize) -> bool {
    let mut last_store: bool = false;
    for op in &ops[start..end] {
        last_store = is_chain_target_store(op);
        if matches!(
            op,
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::ForIter(_)
                | CanonicalOp::Return
                | CanonicalOp::Dup
                | CanonicalOp::Copy(_)
        ) {
            return false;
        }
    }
    last_store || matches!(ops.get(end - 1), Some(CanonicalOp::UnpackSequence(0)))
}

pub(super) fn recover_chain_target(
    code: &CodeObject,
    ops: &[CanonicalOp],
    start: usize,
    end: usize,
) -> Option<Expr> {
    let slice: Vec<CanonicalOp> = ops[start..end].to_vec();
    let seed: Vec<Expr> = vec![Expr::Name {
        id: DR_CHAIN_VALUE_MARKER.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }];
    let (stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &slice, seed).ok()?;
    let [Stmt::Assign { targets, value, .. }]: [Stmt; 1] = stmts.try_into().ok()? else {
        return None;
    };
    if !is_chain_value_marker(&value) {
        return None;
    }
    let [target]: [Expr; 1] = targets.try_into().ok()?;
    Some(target)
}

fn is_null_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_NULL_MARKER)
}

fn is_call_assembly_marker(expr: &Expr) -> bool {
    is_null_marker(expr) || is_build_class_marker(expr)
}

fn is_assertion_error_marker(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id == DR_ASSERTION_ERROR_MARKER)
}

fn encode_kw_names(names: &[String]) -> String {
    format!("{DR_KW_NAMES_PREFIX}{}__", names.join("\u{1F}"))
}

pub(super) fn decode_kw_names(expr: &Expr) -> Option<Vec<String>> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id.strip_prefix(DR_KW_NAMES_PREFIX)?.strip_suffix("__")?;
    if inner.is_empty() {
        return Some(Vec::new());
    }
    Some(inner.split('\u{1F}').map(str::to_owned).collect())
}

#[derive(Debug, Clone)]
struct ImportModuleMarker {
    module: String,
    level: u32,
    fromlist: Option<Vec<String>>,
}

fn encode_import_module_marker(m: &ImportModuleMarker) -> String {
    let fl: String = m.fromlist.as_ref().map_or_else(
        || "NONE".to_owned(),
        |items| format!("LIST|{}", items.join("\u{1F}")),
    );
    format!("{DR_IMPORT_MODULE_PREFIX}{}|{}|{}__", m.module, m.level, fl)
}

fn decode_import_module_marker(expr: &Expr) -> Option<ImportModuleMarker> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id
        .strip_prefix(DR_IMPORT_MODULE_PREFIX)?
        .strip_suffix("__")?;
    let mut parts: std::str::SplitN<'_, char> = inner.splitn(3, '|');
    let module: &str = parts.next()?;
    let level_str: &str = parts.next()?;
    let level: u32 = bounded_import_level(level_str.parse::<u32>().ok()?);
    let fromlist_str: &str = parts.next()?;
    let fromlist: Option<Vec<String>> = if fromlist_str == "NONE" {
        None
    } else if let Some(items) = fromlist_str.strip_prefix("LIST|") {
        if items.is_empty() {
            Some(Vec::new())
        } else {
            Some(
                items
                    .split('\u{1F}')
                    .map(str::to_owned)
                    .collect::<Vec<String>>(),
            )
        }
    } else {
        return None;
    };
    Some(ImportModuleMarker {
        module: module.to_owned(),
        level,
        fromlist,
    })
}

fn encode_import_fromset_marker(module: &str, level: u32) -> String {
    format!("{DR_IMPORT_FROMSET_PREFIX}{module}|{level}__")
}

fn decode_import_fromset_marker(expr: &Expr) -> Option<(String, u32)> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id
        .strip_prefix(DR_IMPORT_FROMSET_PREFIX)?
        .strip_suffix("__")?;
    let (module, level_str): (&str, &str) = inner.split_once('|')?;
    let level: u32 = bounded_import_level(level_str.parse::<u32>().ok()?);
    Some((module.to_owned(), level))
}

fn encode_import_attr_marker(module: &str, level: u32, attr: &str) -> String {
    format!("{DR_IMPORT_ATTR_PREFIX}{module}|{level}|{attr}__")
}

fn decode_import_attr_marker(expr: &Expr) -> Option<(String, u32, String)> {
    let Expr::Name { id, .. } = expr else {
        return None;
    };
    let inner: &str = id.strip_prefix(DR_IMPORT_ATTR_PREFIX)?.strip_suffix("__")?;
    let mut parts: std::str::SplitN<'_, char> = inner.splitn(3, '|');
    let module: &str = parts.next()?;
    let level_str: &str = parts.next()?;
    let level: u32 = bounded_import_level(level_str.parse::<u32>().ok()?);
    let attr: &str = parts.next()?;
    Some((module.to_owned(), level, attr.to_owned()))
}

fn extract_str_const(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Constant {
            value: ConstValue::Str(s),
            ..
        } => Some(s.clone()),
        _ => None,
    }
}

pub(super) fn extract_tuple_of_strings(expr: &Expr) -> Option<Vec<String>> {
    match expr {
        Expr::Constant {
            value: ConstValue::Tuple(items),
            ..
        } => {
            let mut out: Vec<String> = Vec::with_capacity(items.len());
            for item in items {
                let ConstValue::Str(s) = item else {
                    return None;
                };
                out.push(s.clone());
            }
            Some(out)
        }
        Expr::Tuple { elts, .. } => {
            let mut out: Vec<String> = Vec::with_capacity(elts.len());
            for elt in elts {
                let s: String = extract_str_const(elt)?;
                out.push(s);
            }
            Some(out)
        }
        _ => None,
    }
}

fn extract_level_const(expr: &Expr) -> Option<u32> {
    match expr {
        Expr::Constant {
            value: ConstValue::Int(i),
            ..
        } => u32::try_from((*i).max(0)).ok().map(bounded_import_level),
        Expr::Constant {
            value: ConstValue::None,
            ..
        } => Some(0),
        _ => None,
    }
}

fn import_star_stmt(top: Option<Expr>) -> Stmt {
    let (module, level): (Option<String>, u32) = top.map_or((None, 0), |t: Expr| {
        if let Some(m) = decode_import_module_marker(&t) {
            (Some(m.module), m.level)
        } else if let Some((mod_name, lvl)) = decode_import_fromset_marker(&t) {
            (Some(mod_name), lvl)
        } else {
            (None, 0)
        }
    });
    Stmt::ImportFrom {
        module,
        names: vec![Alias {
            name: "*".to_owned(),
            asname: None,
        }],
        level,
        line: None,
    }
}

fn import_module_to_stmt(marker: &ImportModuleMarker, store_name: &str) -> Stmt {
    let top_level: &str = marker.module.split('.').next().unwrap_or(&marker.module);
    let asname: Option<String> = if store_name == top_level {
        None
    } else {
        Some(store_name.to_owned())
    };
    Stmt::Import(vec![Alias {
        name: marker.module.clone(),
        asname,
    }])
}

pub(super) fn load_name(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = name_at(&code.names, idx, offset, "name")?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Load,
        line: None,
    })
}

pub(super) fn load_common_constant(slot: u8) -> Expr {
    let const_value: Option<ConstValue> = match slot {
        7 => Some(ConstValue::None),
        8 => Some(ConstValue::Str(String::new())),
        9 => Some(ConstValue::True),
        10 => Some(ConstValue::False),
        11 => Some(ConstValue::Int(-1)),
        _ => None,
    };
    if let Some(value) = const_value {
        return Expr::Constant { value, line: None };
    }
    let id: &'static str = match slot {
        0 => "AssertionError",
        1 => "NotImplementedError",
        2 => "tuple",
        3 => "all",
        4 => "any",
        5 => "list",
        6 => "set",
        _ => "None",
    };
    Expr::Name {
        id: id.to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    }
}

pub(super) fn local_name_at(code: &CodeObject, idx: u32, offset: usize) -> Result<String> {
    if is_deref_local(idx) {
        let payload: u32 = deref_local_payload(idx);
        let cell_len: u32 = u32::try_from(code.cellvars.len()).unwrap_or(0);
        if !code.cellvars.is_empty()
            && payload < cell_len
            && let Ok(s) = name_at(&code.cellvars, payload, offset, "cellvar")
        {
            return Ok(s);
        }
        if !code.freevars.is_empty() {
            let free_idx: u32 = payload.saturating_sub(cell_len);
            if let Ok(s) = name_at(&code.freevars, free_idx, offset, "freevar") {
                return Ok(s);
            }
        }
        if !code.localsplusnames.is_empty()
            && let Ok(s) = name_at(&code.localsplusnames, payload, offset, "localsplus")
        {
            return Ok(s);
        }
        return Err(DecompileError::AstDesync {
            offset,
            reason: format!("deref index {payload} out of range"),
        });
    }
    if !code.varnames.is_empty()
        && let Ok(s) = name_at(&code.varnames, idx, offset, "varname")
    {
        return Ok(s);
    }
    if !code.localsplusnames.is_empty()
        && let Ok(s) = name_at(&code.localsplusnames, idx, offset, "localsplus")
    {
        return Ok(s);
    }
    Err(DecompileError::AstDesync {
        offset,
        reason: format!("local index {idx} out of range"),
    })
}

pub(super) fn load_local(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = local_name_at(code, idx, offset)?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Load,
        line: None,
    })
}

pub(super) fn local_target(code: &CodeObject, idx: u32, offset: usize) -> Result<Expr> {
    let id: String = local_name_at(code, idx, offset)?;
    Ok(Expr::Name {
        id,
        ctx: ExprCtx::Store,
        line: None,
    })
}

fn store_target_at(code: &CodeObject, op: &CanonicalOp, offset: usize) -> Result<Expr> {
    match op {
        CanonicalOp::StoreFast(slot) => local_target(code, *slot, offset),
        CanonicalOp::StoreName(slot) | CanonicalOp::StoreGlobal(slot) => Ok(Expr::Name {
            id: name_at(&code.names, *slot, offset, "name")?,
            ctx: ExprCtx::Store,
            line: None,
        }),
        other => Err(DecompileError::AstDesync {
            offset,
            reason: format!("expected a single store op, found {other:?}"),
        }),
    }
}

fn three_target_sfsf_tail(ops: &[CanonicalOp], idx: usize, sim: &StackSim) -> Option<usize> {
    if !active_version().is_some_and(|v: PyVersion| v.major() == 3 && v.minor() >= 13) {
        return None;
    }
    if sim.len() < 3 {
        return None;
    }
    let is_filler = |op: &CanonicalOp| {
        matches!(
            op,
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    };
    let prev_is_store: bool = (0..idx)
        .rev()
        .find(|&k: &usize| !is_filler(&ops[k]))
        .is_some_and(|k: usize| {
            matches!(
                ops[k],
                CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::StoreFastStoreFast(_, _)
                    | CanonicalOp::StoreFastLoadFast(_, _)
                    | CanonicalOp::UnpackSequence(_)
                    | CanonicalOp::UnpackEx(_)
            )
        });
    if prev_is_store {
        return None;
    }
    let trailing_idx: usize = ((idx + 1)..ops.len()).find(|&k: &usize| !is_filler(&ops[k]))?;
    matches!(
        ops[trailing_idx],
        CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::StoreGlobal(_)
    )
    .then_some(trailing_idx)
}

pub(super) fn name_at(
    pool: &[Object],
    idx: u32,
    offset: usize,
    kind: &'static str,
) -> Result<String> {
    let obj: &Object = pool
        .get(idx as usize)
        .ok_or_else(|| DecompileError::AstDesync {
            offset,
            reason: format!("{kind} index {idx} out of range"),
        })?;
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Ok(value.clone()),
        other => Err(DecompileError::AstDesync {
            offset,
            reason: format!("{kind} pool slot {idx} is not a string: {other:?}"),
        }),
    }
}

pub(super) fn const_string_tuple(code: &CodeObject, idx: u32) -> Option<Vec<String>> {
    match code.consts.get(idx as usize)? {
        Object::Tuple(items) => items
            .iter()
            .map(|obj: &Object| match obj {
                Object::String { value, .. }
                | Object::Unicode { value, .. }
                | Object::ShortAscii { value, .. } => Some(value.clone()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
}

pub(super) fn object_to_const(obj: &Object) -> ConstValue {
    match obj {
        Object::Ellipsis => ConstValue::Ellipsis,
        Object::True => ConstValue::True,
        Object::False => ConstValue::False,
        Object::Int(i) => ConstValue::Int(i128::from(*i)),
        Object::Int64(i) => ConstValue::Int(i128::from(*i)),
        Object::Long(bi) => ConstValue::BigInt(crate::ast::node::BigUint {
            sign: bi.sign,
            digits: bi.digits.clone(),
        }),
        Object::Float(f) => ConstValue::Float(*f),
        Object::Complex { real, imag } => ConstValue::Complex {
            real: *real,
            imag: *imag,
        },
        Object::String { value, .. } | Object::ShortAscii { value, .. } => {
            ConstValue::Str(value.clone())
        }
        Object::Unicode { value, .. } => {
            if active_version().is_some_and(|v: PyVersion| v.major() < 3) {
                ConstValue::Unicode(value.clone())
            } else {
                ConstValue::Str(value.clone())
            }
        }
        Object::Bytes(b) => ConstValue::Bytes(b.clone()),
        Object::Tuple(items) => ConstValue::Tuple(items.iter().map(object_to_const).collect()),
        Object::FrozenSet(items) => {
            ConstValue::Frozenset(items.iter().map(object_to_const).collect())
        }
        Object::Slice { lower, upper, step } => ConstValue::Slice {
            lower: Box::new(object_to_const(lower)),
            upper: Box::new(object_to_const(upper)),
            step: Box::new(object_to_const(step)),
        },
        Object::None
        | Object::StopIteration
        | Object::Dict(_)
        | Object::List(_)
        | Object::Set(_)
        | Object::FrozenDict(_)
        | Object::Code(_)
        | Object::Ref(_)
        | Object::Null => ConstValue::None,
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalOp, Expr, ExprCtx, StackSim, reorder_run};

    fn name(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }
    }

    #[test]
    fn rot_three_reorder_run_matches_stack_effect() {
        let stack: Vec<Expr> = vec![name("a"), name("b"), name("c")];
        let ops: Vec<CanonicalOp> = vec![CanonicalOp::RotN(3), CanonicalOp::RotN(2)];
        let result: Option<(usize, Vec<Expr>, usize)> = reorder_run(&stack, &ops, 0);
        assert!(result.is_some(), "rot run");
        let (n, reordered, skip): (usize, Vec<Expr>, usize) = match result {
            Some(result) => result,
            None => return,
        };
        assert_eq!(n, 3);
        assert_eq!(skip, 2);
        assert_eq!(reordered, vec![name("c"), name("b"), name("a")]);
    }

    #[test]
    fn dup_two_preserves_pair_order() {
        let mut sim: StackSim = StackSim::new();
        sim.stack = vec![name("a"), name("b")];
        sim.dup_two();
        assert_eq!(sim.stack, vec![name("a"), name("b"), name("a"), name("b")]);
    }
}
