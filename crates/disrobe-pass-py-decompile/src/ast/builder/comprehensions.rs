use super::exprs::{
    DR_NULL_MARKER, StackSim, build_linear_stmts_sim, decode_kw_names, extract_tuple_of_strings,
    is_chain_compare_jump, load_common_constant, load_local, load_name, local_name_at,
};
use super::function_meta::{
    FunctionMeta, fold_set_function_attributes, load_const, make_function_meta,
    make_function_meta_legacy, nested_code_index, nested_code_object_at, slice_bound,
    try_build_lambda_expr,
};
use super::loops::{cond_expr_start, is_walrus_store_shape};
use super::stmts::{
    PY_CO_FLAG_ASYNC_GENERATOR, PY_CO_FLAG_COROUTINE, first_significant, is_await_null_slot,
    name_at_either, placeholder_target, resolve_jump_target, single_store_target,
};
use super::try_with::{is_back_edge, is_value_boundary, is_value_form_shortcircuit};
use super::{
    DecodedStream, NoneJumpKind, active_version, decode_stream_with_offsets, pick_nested_version,
};
use crate::ast::node::{Comprehension, ConstValue, Expr, ExprCtx, FormatConversion, Stmt};
use crate::bytecode::opcode::{CanonicalOp, CmpOp, OpcodeMap, map_for};
use crate::bytecode::version::PyVersion;
use disrobe_py_marshal::{CodeObject, Object};

pub(super) fn try_build_comprehension_expr(
    parent: &CodeObject,
    func: &Expr,
    args: &[Expr],
) -> Option<Expr> {
    let const_idx: u32 = nested_code_index(func)?;
    let nested: &CodeObject = nested_code_object_at(parent, const_idx)?;
    let name: &str = match &nested.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => value.as_str(),
        _ => return None,
    };
    let comp_kind: CompKind = match name {
        "<listcomp>" => CompKind::List,
        "<setcomp>" => CompKind::Set,
        "<dictcomp>" => CompKind::Dict,
        "<genexpr>" => CompKind::Gen,
        _ => return None,
    };
    let iter: Expr = args.first().cloned().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let nested_version: PyVersion = pick_nested_version(nested);
    let opmap: Box<dyn OpcodeMap> = map_for(nested_version.clone());
    let stream: DecodedStream = decode_stream_with_offsets(nested, opmap.as_ref(), &nested_version);
    let parts: ComprehensionParts = extract_comprehension_parts(nested, &stream, comp_kind);
    let is_async: bool = (nested.flags & (PY_CO_FLAG_COROUTINE | PY_CO_FLAG_ASYNC_GENERATOR)) != 0;
    let mut generators: Vec<Comprehension> =
        comprehension_generators(nested, &stream, comp_kind, iter);
    if generators.is_empty() {
        generators.push(Comprehension {
            target: parts.target,
            iter: Expr::Constant {
                value: ConstValue::None,
                line: None,
            },
            ifs: parts.ifs,
            is_async,
            ifs_own_line: false,
        });
    }
    let elt: Expr = parts.elt;
    let key_value: Option<(Expr, Expr)> = parts.key_value;
    let result: Expr = match comp_kind {
        CompKind::List => Expr::ListComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Set => Expr::SetComp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Gen => Expr::GeneratorExp {
            elt: Box::new(elt),
            generators,
        },
        CompKind::Dict => {
            let (k, v): (Expr, Expr) = key_value.unwrap_or((
                elt,
                Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                },
            ));
            Expr::DictComp {
                key: Box::new(k),
                value: Box::new(v),
                generators,
            }
        }
    };
    Some(result)
}

fn pop_make_function_marker(sim: &mut StackSim) -> Option<Expr> {
    let top: Expr = sim.try_pop()?;
    if nested_code_index(&top).is_some() {
        return Some(top);
    }
    let Some(under): Option<Expr> = sim.try_pop() else {
        sim.push(top);
        return None;
    };
    if nested_code_index(&under).is_some() {
        return Some(under);
    }
    sim.push(under);
    sim.push(top);
    None
}

fn comprehension_generators(
    nested: &CodeObject,
    stream: &DecodedStream,
    kind: CompKind,
    outer_iter: Expr,
) -> Vec<Comprehension> {
    comprehension_generators_in(nested, stream, kind, outer_iter, 0, stream.ops.len())
}

#[derive(Debug, Clone, Copy)]
struct CompClause {
    header: usize,
    is_async: bool,
}

pub(super) fn comprehension_generators_in(
    nested: &CodeObject,
    stream: &DecodedStream,
    kind: CompKind,
    outer_iter: Expr,
    lo: usize,
    hi: usize,
) -> Vec<Comprehension> {
    let hi: usize = hi.min(stream.ops.len());
    let mut clauses: Vec<CompClause> = (lo..hi)
        .filter_map(|k: usize| match stream.ops[k] {
            CanonicalOp::ForIter(_) => Some(CompClause {
                header: k,
                is_async: false,
            }),
            CanonicalOp::GetAnext => Some(CompClause {
                header: k,
                is_async: true,
            }),
            _ => None,
        })
        .collect();
    clauses.sort_unstable_by_key(|c: &CompClause| c.header);
    if clauses.is_empty() {
        return Vec::new();
    }
    let mut generators: Vec<Comprehension> = Vec::with_capacity(clauses.len());
    let mut prev_target_end: usize = lo;
    for (gi, clause) in clauses.iter().enumerate() {
        let iter: Expr = if gi == 0 {
            outer_iter.clone()
        } else {
            comp_inner_iter(nested, stream, prev_target_end, clause.header)
        };
        let target_scan_start: usize = comp_clause_target_start(stream, clause, hi);
        let (target, after_target): (Expr, usize) =
            comp_loop_target(nested, stream, target_scan_start);
        let clause_end: usize = clauses
            .get(gi + 1)
            .map_or(hi, |next: &CompClause| next.header);
        let ifs: Vec<Expr> = comp_clause_filters(nested, stream, after_target, clause_end);
        let ifs_own_line: bool =
            !ifs.is_empty() && clause_filters_use_skip_form(stream, after_target, clause_end);
        generators.push(Comprehension {
            target,
            iter,
            ifs,
            is_async: clause.is_async,
            ifs_own_line,
        });
        prev_target_end = after_target;
    }
    let _ = kind;
    generators
}

fn comp_clause_target_start(stream: &DecodedStream, clause: &CompClause, hi: usize) -> usize {
    if !clause.is_async {
        return clause.header + 1;
    }
    (clause.header + 1..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreFastLoadFast(_, _)
                    | CanonicalOp::StoreFastStoreFast(_, _)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::UnpackSequence(_)
                    | CanonicalOp::UnpackEx(_)
            )
        })
        .unwrap_or(clause.header + 1)
}

fn filter_jump_target_is_skip(stream: &DecodedStream, cond_idx: usize) -> bool {
    resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])
        .and_then(|t: usize| first_significant(stream, t, stream.ops.len()))
        .is_some_and(|s: usize| {
            is_back_edge(&stream.ops[s])
                || matches!(
                    stream.ops[s],
                    CanonicalOp::ForIter(_) | CanonicalOp::GetAnext | CanonicalOp::EndAsyncFor
                )
        })
}

fn filter_keeps_when_true(stream: &DecodedStream, cond_idx: usize) -> bool {
    let jump_true: bool = matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    );
    if filter_jump_target_is_skip(stream, cond_idx) {
        !jump_true
    } else {
        jump_true
    }
}

pub(super) fn comp_loop_target(
    nested: &CodeObject,
    stream: &DecodedStream,
    start: usize,
) -> (Expr, usize) {
    single_store_target(nested, &stream.ops, start)
        .unwrap_or_else(|| (placeholder_target(), start + 1))
}

fn comp_inner_iter(
    nested: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    for_iter: usize,
) -> Expr {
    let get_iter: usize = (lo..for_iter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
        .unwrap_or(for_iter);
    let expr_lo: usize = (lo..get_iter)
        .rev()
        .find(|&k: &usize| is_value_boundary(&stream.ops[k]))
        .map_or(lo, |b: usize| b + 1);
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(nested, slice_clamped(&stream.ops, expr_lo, get_iter))
            .unwrap_or_default();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

pub(super) fn slice_clamped(ops: &[CanonicalOp], lo: usize, hi: usize) -> &[CanonicalOp] {
    let hi: usize = hi.min(ops.len());
    let lo: usize = lo.min(hi);
    &ops[lo..hi]
}

fn cond_jump_is_ternary(stream: &DecodedStream, cond_idx: usize) -> bool {
    if filter_jump_target_is_skip(stream, cond_idx) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])
    else {
        return false;
    };
    let mut k: usize = target;
    while k > cond_idx + 1 {
        k -= 1;
        match &stream.ops[k] {
            CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => {
                return resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|j: usize| j >= target);
            }
            _ => return false,
        }
    }
    false
}

fn build_comp_element_ternary(
    nested: &CodeObject,
    stream: &DecodedStream,
    cond_idx: usize,
    sim: &mut StackSim,
) -> Option<(Expr, usize)> {
    let test: Expr = sim.try_pop()?;
    let else_lo: usize = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])?;
    let mut true_jump: usize = else_lo;
    while true_jump > cond_idx + 1 {
        true_jump -= 1;
        match &stream.ops[true_jump] {
            CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => break,
            _ => return None,
        }
    }
    let join: usize = resolve_jump_target(stream, true_jump, &stream.ops[true_jump])?;
    if join > stream.ops.len() || true_jump <= cond_idx {
        return None;
    }
    let arm_a: Expr = comp_residual_expr(nested, &stream.ops, cond_idx + 1, true_jump)?;
    let arm_b: Expr = comp_residual_expr(nested, &stream.ops, else_lo, join)?;
    let jump_if_true: bool = matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    );
    let (body, orelse): (Expr, Expr) = if jump_if_true {
        (arm_b, arm_a)
    } else {
        (arm_a, arm_b)
    };
    Some((
        Expr::IfExp {
            test: Box::new(test),
            body: Box::new(body),
            orelse: Box::new(orelse),
        },
        join,
    ))
}

fn build_comp_element_boolop(
    nested: &CodeObject,
    stream: &DecodedStream,
    cond_idx: usize,
    sim: &mut StackSim,
) -> Option<(Expr, usize)> {
    let join: usize = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx])?;
    if join <= cond_idx || join > stream.ops.len() {
        return None;
    }
    let right_lo: usize = first_significant(stream, cond_idx + 1, join)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Pop))
        .map_or(cond_idx + 1, |k: usize| k + 1);
    let test_copy: Expr = sim.try_pop()?;
    let left: Expr = sim.try_pop().unwrap_or(test_copy);
    let right: Expr = comp_residual_expr(nested, &stream.ops, right_lo, join)?;
    let op: crate::ast::node::BoolOpKind = if matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    ) {
        crate::ast::node::BoolOpKind::Or
    } else {
        crate::ast::node::BoolOpKind::And
    };
    Some((
        Expr::BoolOp {
            op,
            values: vec![left, right],
        },
        join,
    ))
}

fn comp_residual_expr(
    nested: &CodeObject,
    ops: &[CanonicalOp],
    lo: usize,
    hi: usize,
) -> Option<Expr> {
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(nested, slice_clamped(ops, lo, hi)).unwrap_or_default();
    residual.into_iter().next_back()
}

fn comp_element_complete(ops: &[CanonicalOp], after: usize) -> bool {
    let mut k: usize = after;
    while k < ops.len() {
        match &ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => k += 1,
            CanonicalOp::ListAppend
            | CanonicalOp::SetAdd
            | CanonicalOp::MapAdd
            | CanonicalOp::Yield => return true,
            _ => return false,
        }
    }
    false
}

fn rebuild_chain_element(
    nested: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<Expr> {
    if lo >= hi {
        return None;
    }
    let has_chain: bool = (lo..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) && is_chain_compare_jump(&stream.ops, k)
    });
    if !has_chain {
        return None;
    }
    comp_residual_expr(nested, &stream.ops, lo, hi)
}

pub(super) fn clause_filters_use_skip_form(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    if active_version().is_none_or(|v: PyVersion| (v.major(), v.minor()) != (3, 12)) {
        return false;
    }
    let hi: usize = hi.min(stream.ops.len());
    (lo..hi).any(|i: usize| {
        matches!(
            stream.ops[i],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) && !cond_jump_is_ternary(stream, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
            && !is_chain_compare_jump(&stream.ops, i)
            && filter_jump_target_is_skip(stream, i)
    })
}

fn comp_clause_filters(
    nested: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Vec<Expr> {
    let mut ifs: Vec<Expr> = Vec::new();
    let mut i: usize = lo;
    while i < hi {
        if matches!(
            stream.ops[i],
            CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
        ) && !cond_jump_is_ternary(stream, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
        {
            let expr_lo: usize = cond_expr_start(stream, i, lo);
            let (_, residual): (Vec<Stmt>, Vec<Expr>) =
                build_linear_stmts_sim(nested, slice_clamped(&stream.ops, expr_lo, i))
                    .unwrap_or_default();
            if let Some(cond) = residual.into_iter().next_back() {
                if is_exc_match_compare(&cond) {
                    i += 1;
                    continue;
                }
                ifs.push(comp_filter_expr(stream, i, cond));
            }
        }
        i += 1;
    }
    ifs
}

fn comp_filter_expr(stream: &DecodedStream, cond_idx: usize, cond: Expr) -> Expr {
    if let Some(none_kind) = stream.none_jump_kind.get(&cond_idx).copied() {
        let kept_kind: NoneJumpKind = if filter_jump_target_is_skip(stream, cond_idx) {
            none_kind
        } else {
            match none_kind {
                NoneJumpKind::IsNone => NoneJumpKind::IsNotNone,
                NoneJumpKind::IsNotNone => NoneJumpKind::IsNone,
            }
        };
        let op: CmpOp = match kept_kind {
            NoneJumpKind::IsNone => CmpOp::Is,
            NoneJumpKind::IsNotNone => CmpOp::IsNot,
        };
        return Expr::Compare {
            left: Box::new(cond),
            ops: vec![op],
            comparators: vec![Expr::Constant {
                value: ConstValue::None,
                line: None,
            }],
        };
    }
    if filter_keeps_when_true(stream, cond_idx) {
        cond
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(cond),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CompKind {
    List,
    Set,
    Dict,
    Gen,
}

#[derive(Debug, Clone)]
pub(super) struct ComprehensionParts {
    pub(super) target: Expr,
    pub(super) elt: Expr,
    pub(super) key_value: Option<(Expr, Expr)>,
    pub(super) ifs: Vec<Expr>,
}

fn is_exc_match_compare(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Compare { ops, .. }
            if ops.iter().any(|c: &crate::bytecode::opcode::CmpOp| {
                matches!(c, crate::bytecode::opcode::CmpOp::ExcMatch)
            })
    )
}

#[allow(clippy::match_same_arms)]
fn extract_comprehension_parts(
    nested: &CodeObject,
    stream: &DecodedStream,
    kind: CompKind,
) -> ComprehensionParts {
    let ops: &[CanonicalOp] = &stream.ops;
    let mut sim: StackSim = StackSim::new();
    let mut target: Option<Expr> = None;
    let mut elt: Option<Expr> = None;
    let mut key_value: Option<(Expr, Expr)> = None;
    let mut ifs: Vec<Expr> = Vec::new();
    let mut seen_target: bool = false;
    let mut pending_unpack: u32 = 0;
    let mut tuple_targets: Vec<Expr> = Vec::new();
    let mut elt_lo: usize = 0;
    let mut idx: usize = 0;
    while idx < ops.len() {
        let op: &CanonicalOp = &ops[idx];
        match op {
            CanonicalOp::UnpackSequence(n) if !seen_target => {
                pending_unpack = *n;
                tuple_targets.clear();
                idx += 1;
                continue;
            }
            CanonicalOp::UnpackEx(_) if !seen_target => {
                pending_unpack = 0;
                tuple_targets.clear();
                idx += 1;
                continue;
            }
            _ => {}
        }
        match op {
            CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
                if seen_target && elt.is_none() =>
            {
                if is_chain_compare_jump(&stream.ops, idx) {
                    idx += 1;
                    continue;
                }
                if cond_jump_is_ternary(stream, idx)
                    && let Some((ternary, after)) =
                        build_comp_element_ternary(nested, stream, idx, &mut sim)
                {
                    if comp_element_complete(&stream.ops, after) {
                        elt = Some(ternary);
                    } else {
                        sim.push(ternary);
                    }
                    idx = after;
                    continue;
                }
                if is_value_form_shortcircuit(&stream.ops, idx)
                    && let Some((boolop, after)) =
                        build_comp_element_boolop(nested, stream, idx, &mut sim)
                {
                    if comp_element_complete(&stream.ops, after) {
                        elt = Some(boolop);
                    } else {
                        sim.push(boolop);
                    }
                    idx = after;
                    continue;
                }
                if let Some(cond) = sim.try_pop() {
                    if is_exc_match_compare(&cond) {
                        idx += 1;
                        continue;
                    }
                    let cond: Expr = if matches!(
                        op,
                        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueBackward(_)
                    ) {
                        Expr::UnaryOp {
                            op: crate::bytecode::opcode::UnaryOp::Not,
                            operand: Box::new(cond),
                        }
                    } else {
                        cond
                    };
                    ifs.push(cond);
                    elt_lo = idx + 1;
                }
            }
            CanonicalOp::Compare(cmp) => {
                let right: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                let left: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                sim.push(Expr::Compare {
                    left: Box::new(left),
                    ops: vec![*cmp],
                    comparators: vec![right],
                });
            }
            CanonicalOp::LoadConst(i) => {
                if let Ok(e) = load_const(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadSmallInt(value) => sim.push(Expr::Constant {
                value: ConstValue::Int(i128::from(*value)),
                line: None,
            }),
            CanonicalOp::LoadCommonConst(slot) => sim.push(load_common_constant(*slot)),
            CanonicalOp::LoadName(i) | CanonicalOp::LoadGlobal(i) => {
                if let Ok(e) = load_name(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadFromDictOrGlobals(i) => {
                let _mapping: Expr = sim.pop_or_synth(nested, idx);
                if let Ok(e) = load_name(nested, *i, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::LoadAttr(i) => {
                let value: Expr = sim.pop_or_synth(nested, idx);
                let attr: String =
                    name_at_either(nested, *i).unwrap_or_else(|_| format!("attr_{i}"));
                sim.push(Expr::Attribute {
                    value: Box::new(value),
                    attr,
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::LoadSubscr => {
                let slice: Expr = sim.pop_or_synth(nested, idx);
                let value: Expr = sim.pop_or_synth(nested, idx);
                sim.push(Expr::Subscript {
                    value: Box::new(value),
                    slice: Box::new(slice),
                    ctx: ExprCtx::Load,
                });
            }
            CanonicalOp::BinarySlice => {
                let upper: Expr = sim.pop_or_synth(nested, idx);
                let lower: Expr = sim.pop_or_synth(nested, idx);
                let obj: Expr = sim.pop_or_synth(nested, idx);
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
            CanonicalOp::BuildSlice(n) => {
                let step: Option<Box<Expr>> = if *n == 3 {
                    Some(Box::new(sim.pop_or_synth(nested, idx)))
                } else {
                    None
                };
                let upper: Expr = sim.pop_or_synth(nested, idx);
                let lower: Expr = sim.pop_or_synth(nested, idx);
                sim.push(Expr::Slice {
                    lower: slice_bound(lower),
                    upper: slice_bound(upper),
                    step,
                });
            }
            CanonicalOp::Push(_) if is_await_null_slot(ops, idx) => {}
            CanonicalOp::Push(_) => sim.push(Expr::Name {
                id: DR_NULL_MARKER.to_owned(),
                ctx: ExprCtx::Load,
                line: None,
            }),
            CanonicalOp::BuildString(n) => {
                let parts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::JoinedStr {
                    values: parts,
                    line: None,
                });
            }
            CanonicalOp::BuildTuple(n) => {
                let elts: Vec<Expr> = sim.pop_n(*n as usize);
                sim.push(Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Load,
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
            CanonicalOp::BuildConstKeyMap(n) => {
                let key_tuple: Expr = sim.pop_or_synth(nested, idx);
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
            CanonicalOp::FormatValue(flags) => {
                let has_spec: bool = (flags & 0x04) != 0;
                let format_spec: Option<Box<Expr>> = if has_spec {
                    Some(Box::new(sim.pop_or_synth(nested, idx)))
                } else {
                    None
                };
                let value: Expr = sim.pop_or_synth(nested, idx);
                let conversion: FormatConversion = match flags & 0x03 {
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
                let value: Expr = sim.pop_or_synth(nested, idx);
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
                let value: Expr = sim.pop_or_synth(nested, idx);
                match value {
                    Expr::FormattedValue {
                        format_spec: None, ..
                    } => sim.push(value),
                    other => sim.push(Expr::FormattedValue {
                        value: Box::new(other),
                        conversion: FormatConversion::None,
                        format_spec: None,
                        line: None,
                    }),
                }
            }
            CanonicalOp::FormatWithSpec => {
                let spec: Expr = sim.pop_or_synth(nested, idx);
                let value: Expr = sim.pop_or_synth(nested, idx);
                match value {
                    Expr::FormattedValue {
                        value: inner,
                        conversion,
                        format_spec: None,
                        line,
                    } => sim.push(Expr::FormattedValue {
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
            CanonicalOp::LoadFast(i) => {
                if let Ok(name) = local_name_at(nested, *i, idx)
                    && name != ".0"
                {
                    sim.push(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Load,
                        line: None,
                    });
                }
            }
            CanonicalOp::LoadFastLoadFast(a, b) => {
                if let Ok(e) = load_local(nested, *a, idx) {
                    sim.push(e);
                }
                if let Ok(e) = load_local(nested, *b, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::StoreFastLoadFast(t, r) => {
                if target.is_none()
                    && let Ok(name) = local_name_at(nested, *t, idx)
                    && name != ".0"
                {
                    target = Some(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    seen_target = true;
                    elt_lo = idx + 1;
                }
                let _ = sim.try_pop();
                if let Ok(e) = load_local(nested, *r, idx) {
                    sim.push(e);
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if target.is_none()
                    && let (Ok(name_a), Ok(name_b)) = (
                        local_name_at(nested, *a, idx),
                        local_name_at(nested, *b, idx),
                    )
                {
                    target = Some(Expr::Tuple {
                        elts: vec![
                            Expr::Name {
                                id: name_a,
                                ctx: ExprCtx::Store,
                                line: None,
                            },
                            Expr::Name {
                                id: name_b,
                                ctx: ExprCtx::Store,
                                line: None,
                            },
                        ],
                        ctx: ExprCtx::Store,
                    });
                    seen_target = true;
                    elt_lo = idx + 1;
                }
                let _ = sim.try_pop();
                let _ = sim.try_pop();
            }
            CanonicalOp::StoreFast(i) => {
                if pending_unpack > 0
                    && let Ok(name) = local_name_at(nested, *i, idx)
                {
                    tuple_targets.push(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    pending_unpack -= 1;
                    if pending_unpack == 0 {
                        target = Some(Expr::Tuple {
                            elts: std::mem::take(&mut tuple_targets),
                            ctx: ExprCtx::Store,
                        });
                        seen_target = true;
                        elt_lo = idx + 1;
                    }
                    idx += 1;
                    continue;
                }
                if seen_target
                    && is_walrus_store_shape(ops, idx)
                    && let Ok(name) = local_name_at(nested, *i, idx)
                {
                    let _dup: Option<Expr> = sim.try_pop();
                    let underlying: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    });
                    sim.push(Expr::NamedExpr {
                        target: Box::new(Expr::Name {
                            id: name,
                            ctx: ExprCtx::Store,
                            line: None,
                        }),
                        value: Box::new(underlying),
                    });
                    idx += 1;
                    continue;
                }
                if target.is_none()
                    && let Ok(name) = local_name_at(nested, *i, idx)
                    && name != ".0"
                {
                    target = Some(Expr::Name {
                        id: name,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
                    seen_target = true;
                    elt_lo = idx + 1;
                }
                let _ = sim.try_pop();
            }
            CanonicalOp::BinaryOp(op_kind) => {
                let right: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                let left: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                sim.push(Expr::BinOp {
                    left: Box::new(left),
                    op: *op_kind,
                    right: Box::new(right),
                });
            }
            CanonicalOp::UnaryOp(op_kind) => {
                let operand: Expr = sim.try_pop().unwrap_or(Expr::Constant {
                    value: ConstValue::None,
                    line: None,
                });
                sim.push(Expr::UnaryOp {
                    op: *op_kind,
                    operand: Box::new(operand),
                });
            }
            CanonicalOp::MakeFunction(flags) => {
                let code_marker: Option<Expr> = pop_make_function_marker(&mut sim);
                let Some(marker): Option<Expr> = code_marker else {
                    idx += 1;
                    continue;
                };
                let mut meta: FunctionMeta = make_function_meta(*flags, &mut sim);
                let after_attrs: usize =
                    fold_set_function_attributes(nested, ops, idx + 1, &mut sim, &mut meta);
                if let Some(const_idx) = nested_code_index(&marker)
                    && let Some(lambda) = try_build_lambda_expr(nested, const_idx, &meta)
                {
                    sim.push(lambda);
                } else {
                    sim.push(marker);
                }
                idx = after_attrs;
                continue;
            }
            CanonicalOp::MakeFunctionLegacy(packed) => {
                let code_marker: Option<Expr> = pop_make_function_marker(&mut sim);
                if let Some(marker) = code_marker {
                    let meta: FunctionMeta = make_function_meta_legacy(*packed, &mut sim);
                    if let Some(const_idx) = nested_code_index(&marker)
                        && let Some(lambda) = try_build_lambda_expr(nested, const_idx, &meta)
                    {
                        sim.push(lambda);
                    } else {
                        sim.push(marker);
                    }
                }
            }
            CanonicalOp::Dup => {
                if let Some(top) = sim.peek_clone() {
                    sim.push(top);
                }
            }
            CanonicalOp::DupTwo => sim.dup_two(),
            CanonicalOp::Copy(n) => {
                if let Some(v) = sim.peek_at(usize::from(*n)) {
                    sim.push(v);
                }
            }
            CanonicalOp::GetIter
            | CanonicalOp::GetAiter
            | CanonicalOp::Send(_)
            | CanonicalOp::EndSend
            | CanonicalOp::Resume(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_) => {}
            CanonicalOp::GetAwaitable => {
                if let Some(value) = sim.try_pop() {
                    sim.push(Expr::Await(Box::new(value)));
                }
            }
            CanonicalOp::YieldFrom => {
                let top: Option<Expr> = sim.try_pop();
                let top_is_none: bool = matches!(
                    top,
                    Some(Expr::Constant {
                        value: ConstValue::None,
                        ..
                    })
                );
                if !top_is_none && let Some(value) = top {
                    sim.push(value);
                }
            }
            CanonicalOp::CallFunction(argc) => {
                let mut args: Vec<Expr> = Vec::with_capacity(usize::from(*argc));
                for _ in 0..*argc {
                    args.insert(0, sim.pop_or_synth(nested, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(nested, idx);
                if let Some(self_arg) = implicit_self {
                    args.insert(0, self_arg);
                }
                if let Some(inner) = try_build_comprehension_expr(nested, &func, &args) {
                    sim.push(inner);
                } else {
                    sim.push(Expr::Call {
                        func: Box::new(func),
                        args,
                        keywords: Vec::new(),
                    });
                }
            }
            CanonicalOp::CallFunctionKw(argc) => {
                let kw_names_expr: Expr = sim.pop_or_synth(nested, idx);
                let kw_names: Vec<String> = decode_kw_names(&kw_names_expr)
                    .or_else(|| extract_tuple_of_strings(&kw_names_expr))
                    .unwrap_or_default();
                let total: usize = usize::from(*argc);
                let kw_count: usize = kw_names.len().min(total);
                let pos_count: usize = total - kw_count;
                let mut kw_values: Vec<Expr> = Vec::with_capacity(kw_count);
                for _ in 0..kw_count {
                    kw_values.insert(0, sim.pop_or_synth(nested, idx));
                }
                let mut args: Vec<Expr> = Vec::with_capacity(pos_count);
                for _ in 0..pos_count {
                    args.insert(0, sim.pop_or_synth(nested, idx));
                }
                let (func, implicit_self): (Expr, Option<Expr>) = sim.pop_call_target(nested, idx);
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
            CanonicalOp::ListAppend | CanonicalOp::SetAdd => {
                if elt.is_none() {
                    if let Some(chained) = rebuild_chain_element(nested, stream, elt_lo, idx) {
                        elt = Some(chained);
                    } else if let Some(e) = sim.try_pop() {
                        elt = Some(e);
                    }
                }
                break;
            }
            CanonicalOp::MapAdd => {
                if matches!(kind, CompKind::Dict) {
                    let pre38_order: bool = active_version()
                        .is_some_and(|v: PyVersion| v.major() == 3 && v.minor() < 8);
                    let top: Option<Expr> = sim.try_pop();
                    let below: Option<Expr> = sim.try_pop();
                    let (k, v): (Option<Expr>, Option<Expr>) = if pre38_order {
                        (top, below)
                    } else {
                        (below, top)
                    };
                    if let (Some(kk), Some(vv)) = (k, v) {
                        elt = Some(kk.clone());
                        key_value = Some((kk, vv));
                    }
                }
                break;
            }
            CanonicalOp::Yield => {
                let top_is_none: bool = matches!(
                    sim.peek_clone(),
                    Some(Expr::Constant {
                        value: ConstValue::None,
                        ..
                    })
                );
                if top_is_none {
                    let _ = sim.try_pop();
                    idx += 1;
                    continue;
                }
                if matches!(kind, CompKind::Gen) && elt.is_none() {
                    if let Some(chained) = rebuild_chain_element(nested, stream, elt_lo, idx) {
                        elt = Some(chained);
                    } else if let Some(e) = sim.try_pop() {
                        elt = Some(e);
                    }
                }
                break;
            }
            _ => {}
        }
        idx += 1;
    }
    let target_final: Expr = target.unwrap_or_else(|| Expr::Name {
        id: "_".to_owned(),
        ctx: ExprCtx::Store,
        line: None,
    });
    let elt_final: Expr = elt.unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    ComprehensionParts {
        target: target_final,
        elt: elt_final,
        key_value,
        ifs,
    }
}
