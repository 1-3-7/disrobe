use super::exprs::{
    DR_CODE_CONST_PREFIX, ShortCircuitItem, boolop_shortcircuit_skip, build_linear_stmts_sim,
    build_linear_stmts_sim_seed, const_string_tuple, first_significant_after,
    fold_short_circuit_items, is_chain_cond_jump, is_modern_test_chain_link_jump, local_name_at,
    name_at, skip_to_bool_jump, value_boolop_at,
};
use super::function_meta::load_const;
use super::loops::{find_loop, is_walrus_store_shape, non_empty};
use super::stmts::{
    chain_landing_pad_cleanup_len, first_significant, last_significant_back, loads_none,
    name_at_either, resolve_jump_target, structure_stmts,
};
use super::try_with::{
    LoopRegion, TryRegion, find_try_region, is_back_edge, is_forward_cond_jump,
    is_shortcircuit_cleanup_pop, is_value_form_shortcircuit,
};
use super::{
    DecodedStream, ScDesc, active_version, fallthrough_cond_test, loop_break_target,
    loop_continue_target, negate_cond_expr, none_jump_test, none_jump_test_taken,
    with_boolop_context, with_boolop_merges,
};
use crate::ast::node::{ConstValue, Expr, ExprCtx, MatchCase, Pattern, Stmt};
use crate::bytecode::opcode::{CanonicalOp, CmpOp, UnaryOp};
use crate::bytecode::version::PyVersion;
use crate::error::{DecompileError, Result};
use disrobe_py_marshal::CodeObject;

fn ternary_body_jump_before(stream: &DecodedStream, from: usize, target: usize) -> usize {
    let mut k: usize = target;
    while k > from {
        k -= 1;
        match stream.ops[k] {
            CanonicalOp::Push(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {}
            _ => return k,
        }
    }
    target.saturating_sub(1)
}

pub(super) fn try_structure_ternary_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if target <= jump_idx + 1 || target > hi {
        return Ok(None);
    }
    let last_test_jump: usize = ternary_test_chain_end(stream, lo, jump_idx, target);
    let body_last: usize = ternary_body_jump_before(stream, last_test_jump + 1, target);
    if !matches!(
        stream.ops[body_last],
        CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
    ) {
        return Ok(None);
    }
    let orelse_start: usize = body_last + 1;
    let Some(join): Option<usize> = resolve_jump_target(stream, body_last, &stream.ops[body_last])
        .filter(|j: &usize| *j > body_last && *j <= hi)
    else {
        return Ok(None);
    };
    if last_test_jump + 1 > body_last {
        return Ok(None);
    }
    let Some((head_stmts, below_stack, test_raw)): Option<TernaryTest> =
        build_ternary_test_expr(code, stream, lo, jump_idx, last_test_jump, target)?
    else {
        return Ok(None);
    };
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, last_test_jump + 1, body_last)?
    else {
        return Ok(None);
    };
    let Some(else_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, orelse_start, join)?
    else {
        return Ok(None);
    };
    let none_jump: bool = stream.none_jump_kind.contains_key(&last_test_jump);
    let negate: bool = matches!(stream.ops[last_test_jump], CanonicalOp::PopJumpIfFalse(_));
    let single_test: bool = last_test_jump == jump_idx;
    let (then_expr, otherwise_expr, test_raw): (Expr, Expr, Expr) = if none_jump {
        let fallthrough_test: Expr = if single_test {
            fallthrough_cond_test(stream, last_test_jump, test_raw)
        } else {
            test_raw
        };
        (body_expr, else_expr, fallthrough_test)
    } else if negate {
        (body_expr, else_expr, test_raw)
    } else if single_test {
        (body_expr, else_expr, negate_cond_expr(test_raw))
    } else {
        (body_expr, else_expr, test_raw)
    };
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(test_raw),
        body: Box::new(then_expr),
        orelse: Box::new(otherwise_expr),
    };
    let mut out: Vec<Stmt> = head_stmts;
    let mut seed: Vec<Expr> = below_stack;
    seed.push(if_exp);
    if let Some(consumer_end) = ternary_tail_split(stream, join, hi) {
        let (consumer_stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim_seed(code, &stream.ops[join..consumer_end], seed)?;
        out.extend(consumer_stmts);
        let rest: Vec<Stmt> = structure_stmts(code, stream, consumer_end, hi)?;
        out.extend(rest);
        return Ok(Some(out));
    }
    let (tail_stmts, _residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[join..hi], seed)?;
    out.extend(tail_stmts);
    Ok(Some(out))
}

fn ternary_tail_split(stream: &DecodedStream, join: usize, hi: usize) -> Option<usize> {
    let consumer_end: usize = ternary_consumer_end(stream, join, hi)?;
    if consumer_end >= hi {
        return None;
    }
    let has_nested_construct: bool = (consumer_end..hi).any(|i: usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
            && resolve_jump_target(stream, i, &stream.ops[i])
                .is_some_and(|t: usize| t > i && t <= hi)
    });
    if has_nested_construct {
        Some(consumer_end)
    } else {
        None
    }
}

fn ternary_consumer_end(stream: &DecodedStream, join: usize, hi: usize) -> Option<usize> {
    (join..hi)
        .find(|&i: &usize| is_ternary_consumer_sink(&stream.ops[i]))
        .map(|i: usize| i + 1)
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn is_ternary_consumer_sink(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreName(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreFastStoreFast(_, _)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreSlice
            | CanonicalOp::Pop
            | CanonicalOp::PrintExpr
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
    )
}

fn ternary_test_chain_end(
    stream: &DecodedStream,
    lo: usize,
    jump_idx: usize,
    target: usize,
) -> usize {
    let mut last: usize = jump_idx;
    let mut cursor: usize = jump_idx + 1;
    while cursor < target {
        let next_opt: Option<usize> = (cursor..target).find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        });
        let Some(next_jump): Option<usize> = next_opt else {
            break;
        };
        let next_target_opt: Option<usize> =
            resolve_jump_target(stream, next_jump, &stream.ops[next_jump]);
        if next_target_opt != Some(target) {
            break;
        }
        last = next_jump;
        cursor = next_jump + 1;
    }
    let _ = lo;
    last
}

type TernaryTest = (Vec<Stmt>, Vec<Expr>, Expr);

fn build_ternary_test_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    first_jump: usize,
    last_test_jump: usize,
    target: usize,
) -> Result<Option<TernaryTest>> {
    let (head_stmts, mut head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..first_jump])?;
    let Some(first_operand): Option<Expr> = head_residual.pop() else {
        return Ok(None);
    };
    let below_stack: Vec<Expr> = head_residual;
    if last_test_jump == first_jump {
        return Ok(Some((head_stmts, below_stack, first_operand)));
    }
    let mut values: Vec<Expr> = vec![negate_operand(stream, first_jump, target, first_operand)];
    let mut prev_jump: usize = first_jump;
    let mut cursor: usize = first_jump + 1;
    while prev_jump < last_test_jump {
        let Some(next_jump): Option<usize> = (cursor..=last_test_jump).find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        }) else {
            return Ok(None);
        };
        let Some(operand): Option<Expr> =
            build_region_as_single_expr(code, stream, prev_jump + 1, next_jump)?
        else {
            return Ok(None);
        };
        values.push(negate_operand(stream, next_jump, target, operand));
        prev_jump = next_jump;
        cursor = next_jump + 1;
    }
    let test: Expr = Expr::BoolOp {
        op: crate::ast::node::BoolOpKind::And,
        values,
    };
    Ok(Some((head_stmts, below_stack, test)))
}

fn negate_operand(stream: &DecodedStream, jump_idx: usize, _target: usize, operand: Expr) -> Expr {
    fallthrough_cond_test(stream, jump_idx, operand)
}

fn build_region_as_single_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    if lo >= hi {
        return Ok(None);
    }
    let nested_jump_opt: Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    });
    if let Some(nested_jump) = nested_jump_opt {
        let nested_target: usize =
            resolve_jump_target(stream, nested_jump, &stream.ops[nested_jump])
                .filter(|t: &usize| *t > nested_jump && *t <= hi)
                .unwrap_or(hi);
        if nested_target > nested_jump + 1 && nested_target < hi {
            let nested_body_last: usize = nested_target - 1;
            let body_jump_ok: bool = matches!(
                stream.ops[nested_body_last],
                CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
            );
            let nested_join_opt: Option<usize> = if body_jump_ok {
                resolve_jump_target(stream, nested_body_last, &stream.ops[nested_body_last])
                    .filter(|j: &usize| *j > nested_target && *j <= hi)
            } else {
                None
            };
            if let Some(nested_join) = nested_join_opt {
                let folded_opt: Option<Expr> = try_fold_nested_ternary(
                    code,
                    stream,
                    lo,
                    hi,
                    nested_jump,
                    nested_target,
                    nested_join,
                )?;
                if let Some(folded) = folded_opt {
                    return Ok(Some(folded));
                }
            }
        }
    }
    let region: &[CanonicalOp] = &stream.ops[lo..hi];
    let merges: Vec<usize> = collect_value_boolop_merges(stream, lo, hi);
    let sc: Vec<ScDesc> = collect_value_boolop_sc(stream, lo, hi);
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        with_boolop_context(region, merges, sc, || build_linear_stmts_sim(code, region))?;
    if !stmts.is_empty() || residual.len() != 1 {
        return Ok(None);
    }
    Ok(residual.into_iter().next_back())
}

fn try_fold_nested_ternary(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    nested_jump: usize,
    nested_target: usize,
    nested_join: usize,
) -> Result<Option<Expr>> {
    let (_, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..nested_jump])?;
    let Some(test_raw): Option<Expr> = head_residual.into_iter().next_back() else {
        return Ok(None);
    };
    let nested_body_last: usize = nested_target - 1;
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, nested_jump + 1, nested_body_last)?
    else {
        return Ok(None);
    };
    let Some(else_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, nested_target, nested_join)?
    else {
        return Ok(None);
    };
    let negate: bool = matches!(stream.ops[nested_jump], CanonicalOp::PopJumpIfFalse(_));
    let (then_expr, otherwise_expr): (Expr, Expr) = if negate {
        (body_expr, else_expr)
    } else {
        (else_expr, body_expr)
    };
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(test_raw),
        body: Box::new(then_expr),
        orelse: Box::new(otherwise_expr),
    };
    let (tail_stmts, tail_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[nested_join..hi], vec![if_exp])?;
    if !tail_stmts.is_empty() || tail_residual.len() != 1 {
        return Ok(None);
    }
    Ok(tail_residual.into_iter().next_back())
}

fn dup_ternary_significant_indices(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<usize> {
    (lo..hi)
        .filter(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .collect()
}

fn dup_ternary_arm_is_straight_line(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).all(|k: usize| {
        let jumping: bool = matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::PopJumpIfFalseRel(_)
                | CanonicalOp::PopJumpIfTrueRel(_)
                | CanonicalOp::PopJumpIfFalseBackward(_)
                | CanonicalOp::PopJumpIfTrueBackward(_)
                | CanonicalOp::JumpIfTrueOrPop(_)
                | CanonicalOp::JumpIfFalseOrPop(_)
        );
        !jumping || is_value_form_shortcircuit(&stream.ops, k)
    })
}

fn dup_ternary_op_is_terminal(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_)
    )
}

pub(super) fn try_structure_dup_consumer_ternary(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if target <= jump_idx + 1 || target >= hi || is_chain_cond_jump(&stream.ops, jump_idx) {
        return Ok(None);
    }
    let arm1_lo: usize = jump_idx + 1;
    let arm1_hi: usize = target;
    let arm2_lo: usize = target;
    let arm2_hi: usize = hi;
    if !dup_ternary_arm_is_straight_line(stream, arm1_lo, arm1_hi)
        || !dup_ternary_arm_is_straight_line(stream, arm2_lo, arm2_hi)
    {
        return Ok(None);
    }
    let sig1: Vec<usize> = dup_ternary_significant_indices(stream, arm1_lo, arm1_hi);
    let sig2: Vec<usize> = dup_ternary_significant_indices(stream, arm2_lo, arm2_hi);
    if sig1.is_empty() || sig2.is_empty() {
        return Ok(None);
    }
    let last1: usize = sig1[sig1.len() - 1];
    if !dup_ternary_op_is_terminal(&stream.ops[last1]) {
        return Ok(None);
    }
    let mut matched: usize = 0;
    while matched < sig1.len() && matched < sig2.len() {
        let i1: usize = sig1[sig1.len() - 1 - matched];
        let i2: usize = sig2[sig2.len() - 1 - matched];
        if stream.ops[i1] != stream.ops[i2] {
            break;
        }
        matched += 1;
    }
    if matched == 0 || matched >= sig1.len() || matched >= sig2.len() {
        return Ok(None);
    }
    let consumer1_first: usize = sig1[sig1.len() - matched];
    let consumer2_first: usize = sig2[sig2.len() - matched];
    let consumer_has_sink: bool = (consumer1_first..arm1_hi).any(|k: usize| {
        dup_ternary_op_is_terminal(&stream.ops[k]) || is_ternary_consumer_sink(&stream.ops[k])
    });
    if !consumer_has_sink {
        return Ok(None);
    }
    let Some(arm1_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, arm1_lo, consumer1_first)?
    else {
        return Ok(None);
    };
    let Some(arm2_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, arm2_lo, consumer2_first)?
    else {
        return Ok(None);
    };
    let (head_stmts, mut head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..jump_idx])?;
    let Some(test_operand): Option<Expr> = head_residual.pop() else {
        return Ok(None);
    };
    let below_stack: Vec<Expr> = head_residual;
    if below_stack.is_empty() {
        return Ok(None);
    }
    let none_jump: bool = stream.none_jump_kind.contains_key(&jump_idx);
    let negate: bool = matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
    );
    let test_final: Expr = if none_jump {
        fallthrough_cond_test(stream, jump_idx, test_operand)
    } else if negate {
        test_operand
    } else {
        negate_cond_expr(test_operand)
    };
    let if_exp: Expr = Expr::IfExp {
        test: Box::new(test_final),
        body: Box::new(arm1_expr),
        orelse: Box::new(arm2_expr),
    };
    let mut seed: Vec<Expr> = below_stack;
    seed.push(if_exp);
    let (consumer_stmts, consumer_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim_seed(code, &stream.ops[consumer1_first..arm1_hi], seed)?;
    if !consumer_residual.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<Stmt> = head_stmts;
    out.extend(consumer_stmts);
    Ok(Some(out))
}

#[derive(Debug, Clone, Copy)]
struct BoolOperand {
    value_lo: usize,
    value_hi: usize,
    op: crate::ast::node::BoolOpKind,
    target: usize,
    sc_idx: usize,
}

#[derive(Debug, Clone, Copy)]
struct ShortCircuit {
    value_hi: usize,
    sc_idx: usize,
    op: crate::ast::node::BoolOpKind,
    target: usize,
    after: usize,
}

fn next_shortcircuit(stream: &DecodedStream, from: usize, hi: usize) -> Option<ShortCircuit> {
    use crate::ast::node::BoolOpKind;
    let mut i: usize = from;
    while i < hi {
        match stream.ops[i] {
            CanonicalOp::Copy(1) => {
                let jump: usize = skip_to_bool_jump(&stream.ops, i + 1)?;
                if jump >= hi {
                    return None;
                }
                let op: BoolOpKind = match stream.ops[jump] {
                    CanonicalOp::PopJumpIfFalse(_) => BoolOpKind::And,
                    CanonicalOp::PopJumpIfTrue(_) => BoolOpKind::Or,
                    _ => return None,
                };
                let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])?;
                let mut after: usize = jump + 1;
                while after < hi
                    && matches!(
                        stream.ops[after],
                        CanonicalOp::Pop | CanonicalOp::Cache | CanonicalOp::Nop
                    )
                {
                    after += 1;
                }
                return Some(ShortCircuit {
                    value_hi: i,
                    sc_idx: i,
                    op,
                    target,
                    after,
                });
            }
            CanonicalOp::JumpIfFalseOrPop(_)
            | CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_) => {
                let op: BoolOpKind = match stream.ops[i] {
                    CanonicalOp::JumpIfFalseOrPop(_) | CanonicalOp::PopJumpIfFalse(_) => {
                        BoolOpKind::And
                    }
                    _ => BoolOpKind::Or,
                };
                let target: usize = resolve_jump_target(stream, i, &stream.ops[i])?;
                if target > hi {
                    return None;
                }
                return Some(ShortCircuit {
                    value_hi: i,
                    sc_idx: i,
                    op,
                    target,
                    after: i + 1,
                });
            }
            _ => i += 1,
        }
    }
    None
}

fn split_boolop_operands(stream: &DecodedStream, lo: usize, hi: usize) -> Option<Vec<BoolOperand>> {
    let mut operands: Vec<BoolOperand> = Vec::new();
    let mut cursor: usize = lo;
    while let Some(sc) = next_shortcircuit(stream, cursor, hi) {
        operands.push(BoolOperand {
            value_lo: cursor,
            value_hi: sc.value_hi,
            op: sc.op,
            target: sc.target,
            sc_idx: sc.sc_idx,
        });
        cursor = sc.after;
    }
    if operands.is_empty() {
        return None;
    }
    operands.push(BoolOperand {
        value_lo: cursor,
        value_hi: hi,
        op: crate::ast::node::BoolOpKind::And,
        target: hi,
        sc_idx: hi,
    });
    Some(operands)
}

pub(super) fn collect_value_boolop_merges(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Vec<usize> {
    let mut merges: Vec<usize> = Vec::new();
    for i in lo..hi {
        if value_boolop_at(&stream.ops, i).is_none() {
            continue;
        }
        let jump: usize = match stream.ops[i] {
            CanonicalOp::Copy(1) => match skip_to_bool_jump(&stream.ops, i + 1) {
                Some(j) => j,
                None => continue,
            },
            CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::JumpIfFalseOrPop(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalse(_) => i,
            _ => continue,
        };
        let Some(target): Option<usize> = resolve_jump_target(stream, jump, &stream.ops[jump])
        else {
            continue;
        };
        if target > i && target <= hi && rhs_is_multi_op(&stream.ops, i, target) {
            merges.push(target - lo);
        }
    }
    merges.sort_unstable();
    merges.dedup();
    merges
}

pub(super) fn collect_value_boolop_sc(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<ScDesc> {
    let mut descriptors: Vec<ScDesc> = Vec::new();
    for i in lo..hi {
        let Some(kind): Option<crate::ast::node::BoolOpKind> = value_boolop_at(&stream.ops, i)
        else {
            continue;
        };
        let jump: usize = match stream.ops[i] {
            CanonicalOp::Copy(1) => match skip_to_bool_jump(&stream.ops, i + 1) {
                Some(j) => j,
                None => continue,
            },
            CanonicalOp::JumpIfTrueOrPop(_)
            | CanonicalOp::JumpIfFalseOrPop(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalse(_) => i,
            _ => continue,
        };
        let Some(target): Option<usize> = resolve_jump_target(stream, jump, &stream.ops[jump])
        else {
            continue;
        };
        if target <= i || target > hi {
            continue;
        }
        descriptors.push(ScDesc {
            sc_idx: i - lo,
            target: target - lo,
            kind,
        });
    }
    descriptors
}

fn rhs_is_multi_op(ops: &[CanonicalOp], sc: usize, target: usize) -> bool {
    let skip: usize = boolop_shortcircuit_skip(ops, sc);
    let Some(rhs_start): Option<usize> = first_significant_after(ops, sc + skip + 1) else {
        return false;
    };
    let mut depth: i32 = 0;
    let mut grew_past_one: bool = false;
    let Some(region): Option<&[CanonicalOp]> = ops.get(rhs_start..target) else {
        return false;
    };
    for op in region {
        let Some(effect): Option<i32> = net_stack_effect(op) else {
            return false;
        };
        depth += effect;
        if depth > 1 {
            grew_past_one = true;
        }
    }
    grew_past_one && depth == 1
}

fn net_stack_effect(op: &CanonicalOp) -> Option<i32> {
    Some(match op {
        CanonicalOp::Cache
        | CanonicalOp::Nop
        | CanonicalOp::ExtendedArg(_)
        | CanonicalOp::Resume(_)
        | CanonicalOp::LoadAttr(_)
        | CanonicalOp::LoadSpecial(_)
        | CanonicalOp::UnaryOp(_)
        | CanonicalOp::ToBool
        | CanonicalOp::FormatSimple
        | CanonicalOp::ConvertValue(_)
        | CanonicalOp::GetIter
        | CanonicalOp::GetAwaitable
        | CanonicalOp::ImportFrom(_)
        | CanonicalOp::LoadFromDictOrGlobals(_) => 0,
        CanonicalOp::LoadConst(_)
        | CanonicalOp::LoadSmallInt(_)
        | CanonicalOp::LoadCommonConst(_)
        | CanonicalOp::LoadName(_)
        | CanonicalOp::LoadFast(_)
        | CanonicalOp::LoadFastAndClear(_)
        | CanonicalOp::LoadGlobal(_)
        | CanonicalOp::LoadBuildClass
        | CanonicalOp::LoadAssertionError
        | CanonicalOp::Push(_) => 1,
        CanonicalOp::LoadFastLoadFast(_, _) => 2,
        CanonicalOp::LoadSubscr
        | CanonicalOp::BinaryOp(_)
        | CanonicalOp::Compare(_)
        | CanonicalOp::BinarySlice
        | CanonicalOp::FormatValue(_)
        | CanonicalOp::FormatWithSpec
        | CanonicalOp::ImportName(_) => -1,
        CanonicalOp::CallFunction(argc) | CanonicalOp::CallFunctionKw(argc) => {
            -i32::from(*argc) - 1
        }
        CanonicalOp::BuildList(n)
        | CanonicalOp::BuildTuple(n)
        | CanonicalOp::BuildSet(n)
        | CanonicalOp::BuildString(n) => 1 - i32::try_from(*n).unwrap_or(i32::MAX),
        CanonicalOp::BuildMap(n) => 1 - 2 * i32::try_from(*n).unwrap_or(i32::MAX / 2),
        CanonicalOp::BuildConstKeyMap(n) => -i32::try_from(*n).unwrap_or(i32::MAX),
        CanonicalOp::BuildSlice(n) => 1 - i32::from(*n),
        _ => return None,
    })
}

pub(super) fn build_shortcircuit_stack_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    let Some(mut operands): Option<Vec<BoolOperand>> = split_boolop_operands(stream, lo, hi) else {
        return Ok(None);
    };
    if operands.len() < 2 {
        return Ok(None);
    }
    let outer_coercions: Vec<UnaryOp> = peel_outer_boolop_coercions(stream, &mut operands, hi);
    let mut resolved: Vec<ShortCircuitItem> = Vec::with_capacity(operands.len());
    for o in &operands {
        let Some(expr): Option<Expr> =
            build_region_as_single_expr(code, stream, o.value_lo, o.value_hi)?
        else {
            return Ok(None);
        };
        resolved.push(ShortCircuitItem {
            expr,
            op: o.op,
            target: o.target,
            sc_idx: o.sc_idx,
            value_lo: o.value_lo,
        });
    }
    let Some(folded): Option<Expr> = fold_short_circuit_items(resolved) else {
        return Ok(None);
    };
    Ok(Some(apply_outer_coercions(folded, outer_coercions)))
}

fn peel_outer_boolop_coercions(
    stream: &DecodedStream,
    operands: &mut [BoolOperand],
    hi: usize,
) -> Vec<UnaryOp> {
    let Some((terminal, leading)): Option<(&mut BoolOperand, &mut [BoolOperand])> =
        operands.split_last_mut()
    else {
        return Vec::new();
    };
    let Some(merge_point): Option<usize> = leading.iter().map(|o: &BoolOperand| o.target).max()
    else {
        return Vec::new();
    };
    if merge_point <= terminal.value_lo || merge_point >= hi {
        return Vec::new();
    }
    let all_coercions: bool = (merge_point..hi).all(|i: usize| {
        matches!(
            stream.ops[i],
            CanonicalOp::ToBool
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::UnaryOp(UnaryOp::Not)
        )
    });
    if !all_coercions {
        return Vec::new();
    }
    let coercions: Vec<UnaryOp> = (merge_point..hi)
        .filter_map(|i: usize| match stream.ops[i] {
            CanonicalOp::UnaryOp(op @ UnaryOp::Not) => Some(op),
            _ => None,
        })
        .collect();
    terminal.value_hi = merge_point;
    coercions
}

fn apply_outer_coercions(expr: Expr, coercions: Vec<UnaryOp>) -> Expr {
    coercions
        .into_iter()
        .fold(expr, |acc: Expr, op: UnaryOp| Expr::UnaryOp {
            op,
            operand: Box::new(acc),
        })
}

fn is_assertion_error_load(code: &CodeObject, op: &CanonicalOp) -> bool {
    match op {
        CanonicalOp::LoadAssertionError | CanonicalOp::LoadCommonConst(0) => true,
        CanonicalOp::LoadGlobal(slot)
        | CanonicalOp::LoadName(slot)
        | CanonicalOp::LoadFromDictOrGlobals(slot) => {
            name_at_either(code, *slot).is_ok_and(|n: String| n == "AssertionError")
        }
        _ => false,
    }
}

fn is_dedicated_assertion_marker(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::LoadAssertionError | CanonicalOp::LoadCommonConst(0)
    )
}

fn version_has_dedicated_assertion_opcode() -> bool {
    active_version().is_some_and(|v: PyVersion| v.major() == 3 && v.minor() >= 9)
}

fn skip_chain_assert_dup_raise(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    raise_idx: usize,
    raw_pass_target: usize,
    hi: usize,
) -> usize {
    if !(lo..raise_idx).any(|k: usize| is_modern_test_chain_link_jump(&stream.ops, k)) {
        return raw_pass_target;
    }
    let Some(cleanup): Option<usize> = chain_landing_pad_cleanup_len(stream, raw_pass_target, hi)
    else {
        return raw_pass_target;
    };
    dup_raise_pass_target(code, stream, raw_pass_target + cleanup, hi).unwrap_or(raw_pass_target)
}

fn dup_raise_pass_target(
    code: &CodeObject,
    stream: &DecodedStream,
    dup_start: usize,
    hi: usize,
) -> Option<usize> {
    let marker: usize = first_significant(stream, dup_start, hi)?;
    if !is_assertion_error_load(code, &stream.ops[marker]) {
        return None;
    }
    let (dup_raise_op, _has_msg): (usize, bool) = assert_raise_after(stream, marker, hi)?;
    first_significant(stream, dup_raise_op + 1, hi).filter(|t: &usize| *t <= hi)
}

fn assert_enclosed_by_if(
    stream: &DecodedStream,
    jump_indices: &[usize],
    pass_target: usize,
    hi: usize,
) -> bool {
    let continuation: usize = skip_call_null_setup(stream, pass_target, hi);
    jump_indices.iter().any(|&jump: &usize| {
        resolve_jump_target(stream, jump, &stream.ops[jump])
            .is_some_and(|target: usize| target > continuation && target < hi)
    })
}

fn only_call_setup_span(stream: &DecodedStream, from: usize, to: usize) -> bool {
    from < to
        && (from..to).all(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Push(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        })
}

fn align_assert_pass_target(
    stream: &DecodedStream,
    jump_indices: &[usize],
    raw_pass_target: usize,
    raise_idx: usize,
) -> usize {
    jump_indices
        .iter()
        .filter_map(|&jump: &usize| resolve_jump_target(stream, jump, &stream.ops[jump]))
        .filter(|&target: &usize| {
            target > raw_pass_target
                && target > raise_idx
                && only_call_setup_span(stream, raw_pass_target, target)
        })
        .max()
        .unwrap_or(raw_pass_target)
}

fn skip_call_null_setup(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut k: usize = from;
    while k < hi && matches!(stream.ops[k], CanonicalOp::Push(_)) {
        k += 1;
    }
    k
}

pub(super) fn try_structure_compound_assert(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(raise_idx): Option<usize> = (lo..hi).find(|&k: &usize| {
        is_assertion_error_load(code, &stream.ops[k]) && assert_raise_after(stream, k, hi).is_some()
    }) else {
        return Ok(None);
    };
    let (raise_op, msg): (usize, Option<Expr>) = match assert_raise_after(stream, raise_idx, hi) {
        Some((r, m)) => (r, assert_msg_expr(code, stream, raise_idx, r, m)?),
        None => return Ok(None),
    };
    let dedicated_marker: bool = is_dedicated_assertion_marker(&stream.ops[raise_idx]);
    if !dedicated_marker && version_has_dedicated_assertion_opcode() {
        return Ok(None);
    }
    let raw_pass_target: usize = first_significant(stream, raise_op + 1, hi).unwrap_or(hi);
    let pass_target: usize =
        skip_chain_assert_dup_raise(code, stream, lo, raise_idx, raw_pass_target, hi);
    if !assert_marker_is_guarded(stream, lo, raise_idx, raw_pass_target) {
        return structure_const_false_assert(code, stream, lo, hi, raise_idx, pass_target, msg);
    }
    let jump_indices: Vec<usize> = (lo..raise_idx)
        .filter(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        .collect();
    if jump_indices.is_empty() {
        return structure_const_false_assert(code, stream, lo, hi, raise_idx, pass_target, msg);
    }
    let enclosure_target: usize =
        align_assert_pass_target(stream, &jump_indices, pass_target, raise_idx);
    if assert_enclosed_by_if(stream, &jump_indices, enclosure_target, hi) {
        return Ok(None);
    }
    let continuation: usize = skip_call_null_setup(stream, pass_target, hi);
    let mut head: Vec<Stmt> = Vec::new();
    let mut operands: Vec<CondOperand> = Vec::new();
    let mut value_lo: usize = lo;
    for (n, &jump) in jump_indices.iter().enumerate() {
        let target: usize = match resolve_jump_target(stream, jump, &stream.ops[jump]) {
            Some(t) => t,
            None => return Ok(None),
        };
        let jumps_false: bool = matches!(
            stream.ops[jump],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        );
        let is_none_jump: bool = stream.none_jump_kind.contains_key(&jump);
        let intermediate: bool = target > jump && target < raise_idx;
        let negated_skip_to_pass: bool = jumps_false && target >= pass_target && dedicated_marker;
        let into_skipped_dup_raise: bool = jumps_false
            && dedicated_marker
            && pass_target > raw_pass_target
            && (raw_pass_target..pass_target).contains(&target);
        let conjunct_ok: bool = (jumps_false && target <= raise_idx)
            || (!jumps_false && target >= pass_target)
            || (is_none_jump && target <= raise_idx)
            || negated_skip_to_pass
            || into_skipped_dup_raise
            || intermediate;
        if !conjunct_ok {
            return Ok(None);
        }
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        if n == 0 {
            head = stmts;
        } else if !stmts.is_empty() {
            return Ok(None);
        }
        let into_continuation: bool = !jumps_false
            && pass_target < continuation
            && (pass_target..=continuation).contains(&target);
        let operand_target: usize = if into_skipped_dup_raise {
            raise_idx
        } else if into_continuation {
            pass_target
        } else {
            target
        };
        operands.push(CondOperand {
            expr: none_jump_test_taken(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true: jump_taken_if_true(stream, jump),
            target: operand_target,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, raise_idx).unwrap_or(jump + 1);
    }
    let Some(test): Option<Expr> = parse_cond_range(&operands, pass_target, raise_idx) else {
        return Ok(None);
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::Assert {
        test,
        msg,
        line: None,
    });
    out.extend(structure_stmts(code, stream, pass_target, hi)?);
    Ok(Some(out))
}

fn structure_const_false_assert(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    raise_idx: usize,
    pass_target: usize,
    msg: Option<Expr>,
) -> Result<Option<Vec<Stmt>>> {
    if !is_dedicated_assertion_marker(&stream.ops[raise_idx]) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..raise_idx])?;
    if !residual.is_empty() {
        return Ok(None);
    }
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::Assert {
        test: Expr::Constant {
            value: ConstValue::False,
            line: None,
        },
        msg,
        line: None,
    });
    out.extend(structure_stmts(code, stream, pass_target, hi)?);
    Ok(Some(out))
}

#[derive(Debug, Clone)]
pub(super) struct CondOperand {
    pub(super) expr: Expr,
    pub(super) is_jump_if_true: bool,
    pub(super) target: usize,
    pub(super) value_lo: usize,
}

#[derive(Debug)]
pub(super) struct CompoundIf {
    pub(super) head: Vec<Stmt>,
    pub(super) test: Expr,
    pub(super) last_jump: usize,
    pub(super) exit_target: Option<usize>,
}

fn body_entry_index(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let bound: usize = hi.min(stream.ops.len());
    (from..bound)
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Push(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        })
        .unwrap_or(from)
}

fn is_return_none_sink(code: &CodeObject, stream: &DecodedStream, idx: usize) -> bool {
    let Some(first): Option<usize> = first_significant(stream, idx, stream.ops.len()) else {
        return false;
    };
    match &stream.ops[first] {
        CanonicalOp::ReturnConst(_) => loads_none(code, &stream.ops[first]),
        CanonicalOp::LoadConst(_) if loads_none(code, &stream.ops[first]) => {
            first_significant(stream, first + 1, stream.ops.len())
                .is_some_and(|next: usize| matches!(stream.ops[next], CanonicalOp::Return))
        }
        _ => false,
    }
}

pub(super) fn try_recover_compound_if(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<CompoundIf>> {
    let Some(first_jump): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return Ok(None);
    };
    let Some((jumps, body, exit)): Option<(Vec<usize>, usize, usize)> =
        collect_if_cond_jumps(stream, first_jump, hi)
    else {
        return Ok(None);
    };
    let Some(&last_jump): Option<&usize> = jumps.last().filter(|_| jumps.len() >= 2) else {
        return Ok(None);
    };
    let Some(last_target): Option<usize> =
        resolve_jump_target(stream, last_jump, &stream.ops[last_jump])
    else {
        return Ok(None);
    };
    if last_target != exit && last_target != body {
        return Ok(None);
    }
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jumps.len());
    let head_end: usize = first_jump_value_lo(stream, lo, first_jump);
    let body_entry: usize = body_entry_index(stream, body, hi);
    let exit_is_none_sink: bool = is_return_none_sink(code, stream, exit);
    let mut canonical_exit: Option<usize> = None;
    let mut value_lo: usize = head_end;
    for (n, &jump) in jumps.iter().enumerate() {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        if n != 0 && !stmts.is_empty() {
            return Ok(None);
        }
        let is_jump_if_true: bool = jump_taken_if_true(stream, jump);
        let Some(target): Option<usize> = resolve_jump_target(stream, jump, &stream.ops[jump])
            .map(|t: usize| if t == body_entry { body } else { t })
            .map(|t: usize| {
                if t != body
                    && t != exit
                    && exit_is_none_sink
                    && is_return_none_sink(code, stream, t)
                {
                    canonical_exit = Some(canonical_exit.unwrap_or(exit).min(t));
                    exit
                } else {
                    t
                }
            })
            .filter(|t: &usize| *t == body || *t == exit || (*t > jump && *t < body))
        else {
            return Ok(None);
        };
        operands.push(CondOperand {
            expr: none_jump_test_taken(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true,
            target,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, hi).unwrap_or(jump + 1);
    }
    let head_region: &[CanonicalOp] = &stream.ops[lo..head_end];
    let head_merges: Vec<usize> = collect_value_boolop_merges(stream, lo, head_end);
    let (head, _): (Vec<Stmt>, Vec<Expr>) = with_boolop_merges(head_region, head_merges, || {
        build_linear_stmts_sim(code, head_region)
    })?;
    let Some(test): Option<Expr> = parse_cond_range(&operands, body, exit) else {
        return Ok(None);
    };
    Ok(Some(CompoundIf {
        head,
        test,
        last_jump,
        exit_target: canonical_exit.filter(|&c: &usize| c < exit),
    }))
}

pub(super) struct OrBodyGuard {
    pub(super) head: Vec<Stmt>,
    pub(super) test: Expr,
    pub(super) body_start: usize,
}

pub(super) fn try_recover_or_body_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    continue_target: usize,
) -> Result<Option<OrBodyGuard>> {
    let Some(first_jump): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return Ok(None);
    };
    let Some((jumps, fall_body, _exit)): Option<(Vec<usize>, usize, usize)> =
        collect_if_cond_jumps(stream, first_jump, hi)
    else {
        return Ok(None);
    };
    if jumps.len() < 2 {
        return Ok(None);
    }
    let mut targets: Vec<usize> = Vec::with_capacity(jumps.len());
    for &jump in &jumps {
        let Some(target): Option<usize> = resolve_jump_target(stream, jump, &stream.ops[jump])
        else {
            return Ok(None);
        };
        targets.push(target);
    }
    let Some(&body): Option<&usize> = targets.iter().max() else {
        return Ok(None);
    };
    if body <= fall_body || body > hi {
        return Ok(None);
    }
    let all_true_to_body: bool = jumps
        .iter()
        .zip(&targets)
        .all(|(&jump, &t): (&usize, &usize)| t == body && jump_taken_if_true(stream, jump));
    if !all_true_to_body {
        return Ok(None);
    }
    if !region_is_only_continue_back_edge_to(stream, fall_body, body, continue_target) {
        return Ok(None);
    }
    let head_end: usize = first_jump_value_lo(stream, lo, first_jump);
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jumps.len());
    let mut value_lo: usize = head_end;
    for (n, &jump) in jumps.iter().enumerate() {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        if n != 0 && !stmts.is_empty() {
            return Ok(None);
        }
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        operands.push(CondOperand {
            expr: none_jump_test_taken(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true: jump_taken_if_true(stream, jump),
            target: body,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, hi).unwrap_or(jump + 1);
    }
    let Some(test): Option<Expr> = parse_cond_range(&operands, body, fall_body) else {
        return Ok(None);
    };
    let head_region: &[CanonicalOp] = &stream.ops[lo..head_end];
    let head_merges: Vec<usize> = collect_value_boolop_merges(stream, lo, head_end);
    let (head, _): (Vec<Stmt>, Vec<Expr>) = with_boolop_merges(head_region, head_merges, || {
        build_linear_stmts_sim(code, head_region)
    })?;
    Ok(Some(OrBodyGuard {
        head,
        test,
        body_start: body,
    }))
}

fn region_is_only_continue_back_edge_to(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    continue_target: usize,
) -> bool {
    let Some(edge): Option<usize> = first_significant(stream, lo, hi) else {
        return false;
    };
    if !is_back_edge(&stream.ops[edge]) {
        return false;
    }
    if first_significant(stream, edge + 1, hi).is_some() {
        return false;
    }
    resolve_jump_target(stream, edge, &stream.ops[edge])
        .is_some_and(|t: usize| t <= continue_target)
}

pub(super) fn structure_guarded_break(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(exit): Option<usize> = loop_break_target() else {
        return Ok(None);
    };
    if exit <= hi {
        return Ok(None);
    }
    let Some(first_jump): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return Ok(None);
    };
    if resolve_jump_target(stream, first_jump, &stream.ops[first_jump]) != Some(exit) {
        return Ok(None);
    }
    let Some((jumps, fallthrough)): Option<(Vec<usize>, usize)> =
        collect_break_cond_jumps(stream, first_jump, exit, hi)
    else {
        return Ok(None);
    };
    let head_end: usize = first_jump_value_lo(stream, lo, first_jump);
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jumps.len());
    let mut value_lo: usize = head_end;
    for (n, &jump) in jumps.iter().enumerate() {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        if n != 0 && !stmts.is_empty() {
            return Ok(None);
        }
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        operands.push(CondOperand {
            expr: none_jump_test_taken(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true: jump_taken_if_true(stream, jump),
            target: resolve_jump_target(stream, jump, &stream.ops[jump]).unwrap_or(exit),
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, hi).unwrap_or(jump + 1);
    }
    let Some(test): Option<Expr> = parse_cond_range(&operands, exit, fallthrough) else {
        return Ok(None);
    };
    let head_region: &[CanonicalOp] = &stream.ops[lo..head_end];
    let (head, _): (Vec<Stmt>, Vec<Expr>) = build_linear_stmts_sim(code, head_region)?;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: vec![Stmt::Break],
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, fallthrough, hi)?);
    Ok(Some(out))
}

pub(super) fn structure_break_on_false_continue(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(exit): Option<usize> = loop_break_target() else {
        return Ok(None);
    };
    if exit <= hi {
        return Ok(None);
    }
    let Some(first_jump): Option<usize> = (lo..hi).find(|&i: &usize| {
        is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    }) else {
        return Ok(None);
    };
    let break_targets_exit: bool = resolve_jump_target(stream, first_jump, &stream.ops[first_jump])
        .is_some_and(|t: usize| {
            t > hi && t <= exit && first_significant(stream, t, exit).is_none()
        });
    if jump_taken_if_true(stream, first_jump) || !break_targets_exit {
        return Ok(None);
    }
    let Some(body_lo): Option<usize> = first_significant(stream, first_jump + 1, hi) else {
        return Ok(None);
    };
    if body_lo >= hi {
        return Ok(None);
    }
    let body_breaks_again: bool = (body_lo..hi).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > hi)
    });
    if body_breaks_again {
        return Ok(None);
    }
    let Some(header): Option<usize> = loop_continue_target() else {
        return Ok(None);
    };
    let true_path_continues: bool = first_significant(stream, hi, exit).is_some_and(|e: usize| {
        is_back_edge(&stream.ops[e])
            && resolve_jump_target(stream, e, &stream.ops[e]).is_some_and(|t: usize| t <= header)
    });
    if !true_path_continues {
        return Ok(None);
    }
    let head_end: usize = first_jump_value_lo(stream, lo, first_jump);
    let (head, _): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..head_end])?;
    let (cond_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[head_end..first_jump])?;
    if !cond_stmts.is_empty() {
        return Ok(None);
    }
    let Some(value): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    let test: Expr = none_jump_test(stream, first_jump, value.clone()).unwrap_or(value);
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_lo, hi)?;
    if !matches!(
        body.last(),
        Some(Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Break | Stmt::Continue)
    ) {
        body.push(Stmt::Continue);
    }
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(body),
        orelse: Vec::new(),
        line: None,
    });
    out.push(Stmt::Break);
    Ok(Some(out))
}

fn collect_break_cond_jumps(
    stream: &DecodedStream,
    first_jump: usize,
    exit: usize,
    hi: usize,
) -> Option<(Vec<usize>, usize)> {
    let mut jumps: Vec<usize> = vec![first_jump];
    let mut cursor: usize = first_jump;
    loop {
        let Some(next_op): Option<usize> = first_significant(stream, cursor + 1, hi) else {
            return Some((jumps, hi));
        };
        let next_jump: Option<usize> = scan_to_cond_jump(stream, next_op, exit.min(hi));
        match next_jump {
            Some(j) if !region_has_statement(stream, next_op, j) => {
                let target: usize = resolve_jump_target(stream, j, &stream.ops[j])?;
                if target != exit && !(target > first_jump && target < hi) {
                    return None;
                }
                jumps.push(j);
                cursor = j;
            }
            _ => return Some((jumps, next_op)),
        }
    }
}

fn first_jump_value_lo(stream: &DecodedStream, lo: usize, first_jump: usize) -> usize {
    let mut start: usize = lo;
    for k in lo..first_jump {
        let is_boundary: bool = (is_statement_boundary_op(&stream.ops[k])
            && !is_walrus_store_shape(&stream.ops, k))
            || (matches!(stream.ops[k], CanonicalOp::Pop)
                && !is_shortcircuit_cleanup_pop(stream, k));
        if is_boundary {
            start = k + 1;
        }
    }
    start
}

fn is_statement_boundary_op(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreFastLoadFast(_, _)
            | CanonicalOp::StoreFastStoreFast(_, _)
    )
}

pub(super) fn jump_taken_if_true(stream: &DecodedStream, jump_idx: usize) -> bool {
    if stream.none_jump_kind.contains_key(&jump_idx) {
        return true;
    }
    matches!(
        stream.ops[jump_idx],
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueRel(_)
    )
}

fn collect_if_cond_jumps(
    stream: &DecodedStream,
    first_jump: usize,
    hi: usize,
) -> Option<(Vec<usize>, usize, usize)> {
    let mut jumps: Vec<usize> = Vec::new();
    let mut targets: Vec<usize> = Vec::new();
    let mut body_targets: Vec<usize> = Vec::new();
    let mut cursor: usize = first_jump;
    loop {
        if !is_forward_cond_jump(&stream.ops[cursor])
            || is_chain_cond_jump(&stream.ops, cursor)
            || is_value_form_shortcircuit(&stream.ops, cursor)
        {
            return None;
        }
        let target: usize = resolve_jump_target(stream, cursor, &stream.ops[cursor])
            .filter(|t: &usize| *t > cursor && *t <= hi)?;
        let jumps_if_true: bool = jump_taken_if_true(stream, cursor);
        jumps.push(cursor);
        targets.push(target);
        if jumps_if_true {
            body_targets.push(target);
        }
        let next_op: usize = first_significant(stream, cursor + 1, hi)?;
        let next_entry: usize = body_entry_index(stream, next_op, hi);
        if body_targets
            .iter()
            .any(|&t: &usize| t == next_op || t == next_entry)
        {
            let body: usize = next_op;
            let exit: usize = *targets.iter().filter(|&&t: &&usize| t != body).max()?;
            if exit <= body || jumps.iter().any(|&j: &usize| j >= body) {
                return None;
            }
            return Some((jumps, body, exit));
        }
        let next_jump: Option<usize> = scan_to_cond_jump(stream, next_op, target);
        let pure_and_run: bool =
            body_targets.is_empty() && targets.iter().all(|&t: &usize| t == target);
        let continues: bool = next_jump.is_some_and(|j: usize| {
            if j >= target || region_has_statement(stream, next_op, j) {
                return false;
            }
            if pure_and_run && !jump_taken_if_true(stream, j) {
                return resolve_jump_target(stream, j, &stream.ops[j])
                    .is_none_or(|t: usize| t >= target);
            }
            true
        });
        match next_jump {
            Some(j) if continues => cursor = j,
            _ => {
                let body: usize = next_op;
                let exit: usize = *targets.iter().max()?;
                if exit <= body || jumps.iter().any(|&j: &usize| j >= body) {
                    return None;
                }
                return Some((jumps, body, exit));
            }
        }
    }
}

fn region_has_statement(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        (is_statement_boundary_op(&stream.ops[k]) && !is_walrus_store_shape(&stream.ops, k))
            || matches!(stream.ops[k], CanonicalOp::Pop)
    })
}

fn scan_to_cond_jump(stream: &DecodedStream, from: usize, limit: usize) -> Option<usize> {
    let mut i: usize = from;
    while i < limit {
        if is_forward_cond_jump(&stream.ops[i])
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
        {
            return Some(i);
        }
        if matches!(
            stream.ops[i],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
        ) {
            return None;
        }
        i += 1;
    }
    None
}

pub(super) fn parse_cond_range(
    operands: &[CondOperand],
    true_sink: usize,
    false_sink: usize,
) -> Option<Expr> {
    use crate::ast::node::BoolOpKind;
    if operands.is_empty() {
        return None;
    }
    let first: &CondOperand = &operands[0];
    if operands.len() == 1 {
        return Some(terminal_operand(first, true_sink, false_sink));
    }
    let intermediate: bool = first.target != true_sink && first.target != false_sink;
    if intermediate {
        let split: usize =
            (1..operands.len()).find(|&k: &usize| operands[k].value_lo == first.target)?;
        let head_ops: &[CondOperand] = &operands[..split];
        let group_exits_true: bool = head_ops.iter().any(|o: &CondOperand| o.target == true_sink);
        let group_exits_false: bool = head_ops
            .iter()
            .any(|o: &CondOperand| o.target == false_sink);
        let join_with_and: bool = if group_exits_true == group_exits_false {
            first.is_jump_if_true
        } else {
            group_exits_false
        };
        let (op, sub_true, sub_false): (BoolOpKind, usize, usize) = if join_with_and {
            (BoolOpKind::And, first.target, false_sink)
        } else {
            (BoolOpKind::Or, true_sink, first.target)
        };
        let head: Expr = parse_cond_range(head_ops, sub_true, sub_false)?;
        let rest: Expr = parse_cond_range(&operands[split..], true_sink, false_sink)?;
        return Some(merge_boolop(op, head, rest));
    }
    let to_true: bool = first.target == true_sink;
    let op: BoolOpKind = if to_true {
        BoolOpKind::Or
    } else {
        BoolOpKind::And
    };
    let negated: bool = first.is_jump_if_true != to_true;
    let value: Expr = maybe_not(first.expr.clone(), negated);
    let rest: Expr = parse_cond_range(&operands[1..], true_sink, false_sink)?;
    Some(merge_boolop(op, value, rest))
}

fn terminal_operand(operand: &CondOperand, true_sink: usize, false_sink: usize) -> Expr {
    let negated: bool = if operand.target == false_sink {
        operand.is_jump_if_true
    } else if operand.target == true_sink {
        !operand.is_jump_if_true
    } else {
        false
    };
    maybe_not(operand.expr.clone(), negated)
}

fn maybe_not(expr: Expr, negated: bool) -> Expr {
    if negated {
        negate_cond_expr(expr)
    } else {
        expr
    }
}

fn merge_boolop(op: crate::ast::node::BoolOpKind, head: Expr, rest: Expr) -> Expr {
    let mut values: Vec<Expr> = vec![head];
    match rest {
        Expr::BoolOp {
            op: inner_op,
            values: inner,
        } if inner_op == op => values.extend(inner),
        other => values.push(other),
    }
    Expr::BoolOp { op, values }
}

fn assert_marker_is_guarded(
    stream: &DecodedStream,
    lo: usize,
    marker_idx: usize,
    pass_target: usize,
) -> bool {
    (lo..marker_idx).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t >= pass_target)
    })
}

fn assert_raise_after(
    stream: &DecodedStream,
    raise_idx: usize,
    hi: usize,
) -> Option<(usize, bool)> {
    let raise: usize =
        (raise_idx + 1..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Raise(_)))?;
    let has_message: bool = (raise_idx + 1..raise)
        .any(|k: usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)));
    Some((raise, has_message))
}

fn assert_msg_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    raise_idx: usize,
    raise_op: usize,
    has_message: bool,
) -> Result<Option<Expr>> {
    if !has_message {
        return Ok(None);
    }
    let call: usize = match (raise_idx + 1..raise_op)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))
    {
        Some(c) => c,
        None => return Ok(None),
    };
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[raise_idx + 1..call])?;
    Ok(residual.into_iter().next_back())
}

pub(super) fn try_structure_return_ternary(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !matches!(stream.ops[jump_idx], CanonicalOp::PopJumpIfFalse(_)) {
        return Ok(None);
    }
    let Some(expr): Option<Expr> =
        build_return_ternary_expr(code, stream, lo, hi, jump_idx, target)?
    else {
        return Ok(None);
    };
    Ok(Some(vec![Stmt::Return(Some(expr))]))
}

fn build_return_ternary_expr(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    jump_idx: usize,
    target: usize,
) -> Result<Option<Expr>> {
    if target <= jump_idx + 1 || target >= hi {
        return Ok(None);
    }
    let body_ret: usize = target - 1;
    if !matches!(stream.ops[body_ret], CanonicalOp::Return) {
        return Ok(None);
    }
    let last_test_jump: usize = ternary_test_chain_end(stream, lo, jump_idx, target);
    let body_start: usize =
        first_significant(stream, last_test_jump + 1, body_ret).unwrap_or(last_test_jump + 1);
    let Some(test): Option<Expr> = build_return_ternary_test(
        code,
        stream,
        lo,
        jump_idx,
        last_test_jump,
        target,
        body_start,
    )?
    else {
        return Ok(None);
    };
    let Some(body_expr): Option<Expr> =
        build_region_as_single_expr(code, stream, body_start, body_ret)?
    else {
        return Ok(None);
    };
    let else_expr: Expr = match region_return_or_nested(code, stream, target, hi)? {
        Some(e) => e,
        None => return Ok(None),
    };
    Ok(Some(Expr::IfExp {
        test: Box::new(test),
        body: Box::new(body_expr),
        orelse: Box::new(else_expr),
    }))
}

fn build_return_ternary_test(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    first_jump: usize,
    last_test_jump: usize,
    else_target: usize,
    body_start: usize,
) -> Result<Option<Expr>> {
    let jumps: Vec<usize> = (first_jump..=last_test_jump)
        .filter(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k])
                && !is_chain_cond_jump(&stream.ops, k)
                && !is_value_form_shortcircuit(&stream.ops, k)
        })
        .collect();
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jumps.len());
    let mut value_lo: usize = lo;
    for &jump in &jumps {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump])?;
        if !stmts.is_empty() {
            return Ok(None);
        }
        let Some(value): Option<Expr> = residual.into_iter().next_back() else {
            return Ok(None);
        };
        let is_jump_if_true: bool = matches!(
            stream.ops[jump],
            CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueRel(_)
        );
        let Some(jump_target): Option<usize> = resolve_jump_target(stream, jump, &stream.ops[jump])
            .filter(|t: &usize| {
                *t == body_start || *t == else_target || (*t > jump && *t < body_start)
            })
        else {
            return Ok(None);
        };
        operands.push(CondOperand {
            expr: none_jump_test(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true,
            target: jump_target,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, last_test_jump + 1).unwrap_or(jump + 1);
    }
    Ok(parse_cond_range(&operands, body_start, else_target))
}

fn region_return_or_nested(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Expr>> {
    if lo >= hi {
        return Ok(None);
    }
    let nested_jump_opt: Option<usize> = (lo..hi).find(|&i: &usize| {
        matches!(stream.ops[i], CanonicalOp::PopJumpIfFalse(_))
            && !is_chain_cond_jump(&stream.ops, i)
            && !is_value_form_shortcircuit(&stream.ops, i)
    });
    if let Some(nested_jump) = nested_jump_opt {
        let nested_target: usize =
            resolve_jump_target(stream, nested_jump, &stream.ops[nested_jump])
                .filter(|t: &usize| *t > nested_jump && *t <= hi)
                .unwrap_or(hi);
        return build_return_ternary_expr(code, stream, lo, hi, nested_jump, nested_target);
    }
    let last: usize = hi - 1;
    if !matches!(stream.ops[last], CanonicalOp::Return) {
        return Ok(None);
    }
    build_region_as_single_expr(code, stream, lo, last)
}

fn is_subject_dup(op: &CanonicalOp) -> bool {
    matches!(op, CanonicalOp::Dup | CanonicalOp::Copy(1))
}

fn is_capture_store(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreFastStoreFast(_, _)
            | CanonicalOp::StoreFastLoadFast(_, _)
    )
}

fn is_match_fail_jump(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)
    )
}

fn is_arm_gate(stream: &DecodedStream, idx: usize, fail_target: usize) -> bool {
    let _ = fail_target;
    is_match_fail_jump(&stream.ops[idx])
        && resolve_jump_target(stream, idx, &stream.ops[idx]).is_some_and(|t: usize| t > idx)
}

fn dup_leads_match_test(stream: &DecodedStream, from: usize, hi: usize) -> bool {
    let mut k: usize = from;
    let mut comparand: Option<&CanonicalOp> = None;
    let mut saw_capture_store: bool = false;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::Dup
            | CanonicalOp::Copy(_)
            | CanonicalOp::GetLen => k += 1,
            op if is_capture_store(op) => {
                saw_capture_store = true;
                k += 1;
            }
            load @ (CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadFromDictOrGlobals(_)
            | CanonicalOp::LoadAttr(_)) => {
                comparand = Some(load);
                k += 1;
            }
            CanonicalOp::Compare(op) => {
                if !saw_capture_store && !is_match_value_compare(*op, comparand) {
                    return false;
                }
                return first_significant(stream, k + 1, hi)
                    .is_some_and(|n: usize| is_match_fail_jump(&stream.ops[n]));
            }
            CanonicalOp::MatchSequence | CanonicalOp::MatchMapping | CanonicalOp::MatchClass(_) => {
                return first_significant(stream, k + 1, hi)
                    .is_some_and(|n: usize| is_match_fail_jump(&stream.ops[n]));
            }
            _ => return false,
        }
    }
    false
}

pub(super) fn region_contains_match_head(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    match_head_index(stream, lo, hi).is_some()
}

#[must_use]
fn match_head_index(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    let mut k: usize = lo;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::MatchClass(_)
            | CanonicalOp::MatchSequence
            | CanonicalOp::MatchMapping
            | CanonicalOp::MatchKeys
            | CanonicalOp::GetLen => return Some(k),
            op if is_subject_dup(op) => {
                if dup_leads_match_test(stream, k + 1, hi) {
                    return Some(k);
                }
                k += 1;
            }
            _ => k += 1,
        }
    }
    None
}

#[must_use]
pub(super) fn match_head_enclosed_by_try(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let Some(head): Option<usize> = match_head_index(stream, lo, hi) else {
        return false;
    };
    let Some(region): Option<TryRegion> = find_try_region(stream, lo, hi) else {
        return false;
    };
    region.try_start <= head && head < region.handler_start
}

#[must_use]
pub(super) fn match_head_enclosed_by_loop(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let Some(head): Option<usize> = match_head_index(stream, lo, hi) else {
        return false;
    };
    let Some(region): Option<LoopRegion> = find_loop(stream, lo, hi) else {
        return false;
    };
    region.header < head && region.back_edge > head && region.back_edge <= hi
}

fn match_subject_split(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    (lo..hi).find(|&k: &usize| {
        is_subject_dup(&stream.ops[k])
            || matches!(
                stream.ops[k],
                CanonicalOp::Compare(CmpOp::Is | CmpOp::IsNot)
                    | CanonicalOp::MatchSequence
                    | CanonicalOp::MatchMapping
                    | CanonicalOp::MatchClass(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalse(_)
            )
    })
}

fn subject_region_is_straight_line(stream: &DecodedStream, lo: usize, split: usize) -> bool {
    !(lo..split).any(|k: usize| is_match_fail_jump(&stream.ops[k]))
}

#[derive(Debug)]
struct ParsedArm {
    pattern: Pattern,
    guard: Option<Expr>,
    body_start: usize,
    next_arm: usize,
}

#[derive(Debug)]
struct PendingArm {
    pattern: Pattern,
    guard: Option<Expr>,
    body_start: usize,
    next_arm: usize,
    arm_start: usize,
}

fn match_arm_head(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    (from..hi).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) | CanonicalOp::Pop
        )
    })
}

fn arm_fail_target(
    stream: &DecodedStream,
    start: usize,
    region_end: usize,
) -> Option<(usize, usize)> {
    let mut k: usize = start;
    while k < region_end {
        if is_arm_body_terminator(&stream.ops[k]) {
            return None;
        }
        if is_match_fail_jump(&stream.ops[k])
            && let Some(t) = resolve_jump_target(stream, k, &stream.ops[k])
            && t > k
            && t <= region_end
        {
            return Some((k, t));
        }
        k += 1;
    }
    None
}

fn is_arm_body_terminator(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_)
    )
}

fn collect_capture_names(
    code: &CodeObject,
    stream: &DecodedStream,
    start: usize,
    end: usize,
) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for k in start..end.min(stream.ops.len()) {
        match &stream.ops[k] {
            CanonicalOp::StoreFast(slot) => {
                if let Ok(id) = local_name_at(code, *slot, k) {
                    names.push(id);
                }
            }
            CanonicalOp::StoreName(slot) => {
                if let Ok(id) = name_at(&code.names, *slot, k, "name") {
                    names.push(id);
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Ok(id) = local_name_at(code, *a, k) {
                    names.push(id);
                }
                if let Ok(id) = local_name_at(code, *b, k) {
                    names.push(id);
                }
            }
            CanonicalOp::StoreFastLoadFast(store_slot, _) => {
                if let Ok(id) = local_name_at(code, *store_slot, k) {
                    names.push(id);
                }
            }
            _ => {}
        }
    }
    names
}

fn match_body_start(
    stream: &DecodedStream,
    from: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let mut k: usize = from;
    while k < region_end && is_match_binding_op(stream, k, fail_target, region_end) {
        k += 1;
    }
    k.min(region_end)
}

fn is_match_binding_op(
    stream: &DecodedStream,
    idx: usize,
    fail_target: usize,
    region_end: usize,
) -> bool {
    match &stream.ops[idx] {
        CanonicalOp::Pop
        | CanonicalOp::Nop
        | CanonicalOp::Cache
        | CanonicalOp::ExtendedArg(_)
        | CanonicalOp::StoreFast(_)
        | CanonicalOp::StoreName(_)
        | CanonicalOp::StoreFastStoreFast(_, _)
        | CanonicalOp::UnpackSequence(_)
        | CanonicalOp::UnpackEx(_)
        | CanonicalOp::RotN(_)
        | CanonicalOp::Swap(_)
        | CanonicalOp::Dup
        | CanonicalOp::Copy(_)
        | CanonicalOp::LoadSubscr
        | CanonicalOp::MatchKeys
        | CanonicalOp::GetLen
        | CanonicalOp::MatchSequence
        | CanonicalOp::MatchMapping
        | CanonicalOp::BuildMap(_)
        | CanonicalOp::DictUpdate(_)
        | CanonicalOp::DeleteSubscr
        | CanonicalOp::MatchClass(_)
        | CanonicalOp::ToBool
        | CanonicalOp::Compare(_) => true,
        CanonicalOp::LoadConst(_) | CanonicalOp::LoadSmallInt(_) => matches!(
            first_significant(stream, idx + 1, region_end).map(|n: usize| &stream.ops[n]),
            Some(
                CanonicalOp::LoadSubscr
                    | CanonicalOp::Compare(_)
                    | CanonicalOp::MatchKeys
                    | CanonicalOp::MatchClass(_)
            )
        ),
        op if is_match_fail_jump(op) => is_arm_gate(stream, idx, fail_target),
        _ => false,
    }
}

fn captures_to_patterns(names: &[String]) -> Vec<Pattern> {
    names
        .iter()
        .map(|n: &String| Pattern::MatchAs {
            pattern: None,
            name: Some(n.clone()),
        })
        .collect()
}

#[derive(Debug)]
struct ForwardOrAlt {
    pattern: Pattern,
    after: usize,
}

fn uses_forward_jump_or(stream: &DecodedStream) -> bool {
    stream.version.major() == 3 && stream.version.minor() >= 10
}

fn forward_or_alt_jump(
    stream: &DecodedStream,
    value_start: usize,
    region_end: usize,
) -> Option<(usize, usize, usize)> {
    let mut k: usize = value_start;
    let mut last_gate: Option<usize> = None;
    let mut fail_target: Option<usize> = None;
    while k < region_end && fail_target.is_none_or(|t: usize| k < t) {
        match &stream.ops[k] {
            op if is_match_fail_jump(op) => {
                let t: usize = resolve_jump_target(stream, k, op).filter(|t: &usize| *t > k)?;
                fail_target.get_or_insert(t);
                last_gate = Some(k);
            }
            CanonicalOp::JumpForward(_) => {
                resolve_jump_target(stream, k, &stream.ops[k])
                    .filter(|t: &usize| *t > k && *t <= region_end)?;
                return Some((k, last_gate?, fail_target?));
            }
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Pop => return None,
            _ => {}
        }
        k += 1;
    }
    None
}

fn parse_forward_or_alt(
    code: &CodeObject,
    stream: &DecodedStream,
    alt_start: usize,
    region_end: usize,
) -> Option<(ForwardOrAlt, usize, usize)> {
    let head: usize = match_arm_head(stream, alt_start, region_end)?;
    if !is_subject_dup(&stream.ops[head]) {
        return None;
    }
    let value_start: usize = first_significant(stream, head + 1, region_end)?;
    let (jump_idx, last_gate, fail_target): (usize, usize, usize) =
        forward_or_alt_jump(stream, value_start, region_end)?;
    let shared_target: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= region_end)?;
    let pattern: Pattern =
        classify_simple_pattern(code, stream, value_start, last_gate, region_end);
    if !matches!(
        pattern,
        Pattern::MatchValue(_)
            | Pattern::MatchSingleton(_)
            | Pattern::MatchSequence(_)
            | Pattern::MatchMapping { .. }
            | Pattern::MatchClass { .. }
    ) {
        return None;
    }
    let after: usize = first_significant(stream, jump_idx + 1, region_end).unwrap_or(region_end);
    Some((ForwardOrAlt { pattern, after }, fail_target, shared_target))
}

fn extract_forward_jump_or_arm(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    region_end: usize,
) -> Option<ParsedArm> {
    if !uses_forward_jump_or(stream) {
        return None;
    }
    let mut alts: Vec<Pattern> = Vec::new();
    let mut cursor: usize = arm_start;
    let mut shared_target: Option<usize> = None;
    let mut last_fail: usize = region_end;
    while let Some((alt, fail_target, shared)) =
        parse_forward_or_alt(code, stream, cursor, region_end)
    {
        if shared_target.is_some_and(|t: usize| t != shared) {
            break;
        }
        shared_target = Some(shared);
        last_fail = fail_target;
        alts.push(alt.pattern);
        if alt.after <= cursor {
            break;
        }
        cursor = alt.after;
    }
    if alts.len() < 2 {
        return None;
    }
    let body_target: usize = shared_target?;
    let next_arm: usize = forward_or_next_arm(stream, last_fail, region_end);
    let bind_name: Option<String> =
        forward_or_binding(code, stream, body_target, next_arm, region_end);
    let body_start: usize = match_body_start(stream, body_target, next_arm, region_end);
    let merged: Pattern = Pattern::MatchOr(alts);
    let pattern: Pattern = match bind_name {
        Some(name) => Pattern::MatchAs {
            pattern: Some(Box::new(merged)),
            name: Some(name),
        },
        None => merged,
    };
    Some(ParsedArm {
        pattern,
        guard: None,
        body_start,
        next_arm,
    })
}

fn forward_or_next_arm(stream: &DecodedStream, last_fail: usize, region_end: usize) -> usize {
    let mut cursor: usize = last_fail;
    loop {
        let Some(idx): Option<usize> = first_significant(stream, cursor, region_end) else {
            return last_fail;
        };
        match stream.ops[idx] {
            CanonicalOp::Pop => cursor = idx + 1,
            CanonicalOp::JumpForward(_) => {
                return resolve_jump_target(stream, idx, &stream.ops[idx])
                    .filter(|t: &usize| *t > idx && *t <= region_end)
                    .unwrap_or(last_fail);
            }
            _ => return last_fail,
        }
    }
}

fn forward_or_binding(
    code: &CodeObject,
    stream: &DecodedStream,
    body_target: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<String> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in body_target..scan_end {
        match &stream.ops[k] {
            CanonicalOp::Pop
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::StoreFast(slot) => return local_name_at(code, *slot, k).ok(),
            CanonicalOp::StoreName(slot) => return name_at(&code.names, *slot, k, "name").ok(),
            _ => return None,
        }
    }
    None
}

fn wildcard_discards_subject(stream: &DecodedStream, arm_start: usize, region_end: usize) -> bool {
    (arm_start..region_end.min(stream.ops.len()))
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
            )
        })
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::Pop | CanonicalOp::Nop))
}

fn extract_match_case(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    region_end: usize,
) -> Option<ParsedArm> {
    if let Some(arm) = extract_forward_jump_or_arm(code, stream, arm_start, region_end) {
        return Some(arm);
    }
    let _first: usize = first_significant(stream, arm_start, region_end)?;

    let Some((_fail_idx, fail_target)): Option<(usize, usize)> =
        arm_fail_target(stream, arm_start, region_end)
    else {
        let names: Vec<String> = collect_capture_names(code, stream, arm_start, region_end);
        if names.is_empty() && !wildcard_discards_subject(stream, arm_start, region_end) {
            return None;
        }
        let body_start: usize = match_body_start(stream, arm_start, region_end, region_end);
        let pattern: Pattern = Pattern::MatchAs {
            pattern: None,
            name: names.first().cloned(),
        };
        return Some(ParsedArm {
            pattern,
            guard: None,
            body_start,
            next_arm: region_end,
        });
    };

    let pattern: Pattern = classify_pattern(code, stream, arm_start, fail_target, region_end);

    if is_irrefutable_capture(&pattern) {
        let store_end: usize = capture_store_end(stream, arm_start, fail_target, region_end);
        let guard: Option<Expr> = extract_guard(code, stream, store_end, fail_target, region_end);
        let body_start: usize = guard
            .as_ref()
            .map_or(store_end, |_| {
                guard_body_start(stream, store_end, fail_target, region_end)
            })
            .max(arm_start);
        return Some(ParsedArm {
            pattern,
            guard,
            body_start,
            next_arm: fail_target,
        });
    }

    let scan_resume: usize = last_gate_after(stream, arm_start, fail_target, region_end);
    if let Some((guard, guard_body)) =
        extract_refutable_guard(code, stream, arm_start, fail_target, region_end)
    {
        return Some(ParsedArm {
            pattern,
            guard: Some(guard),
            body_start: guard_body.max(arm_start),
            next_arm: fail_target,
        });
    }
    let body_start: usize =
        match_body_start(stream, scan_resume, fail_target, region_end).max(arm_start);
    Some(ParsedArm {
        pattern,
        guard: None,
        body_start,
        next_arm: fail_target,
    })
}

fn extract_refutable_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<(Expr, usize)> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let last_pattern_gate: usize = (arm_start..scan_end).rfind(|&k: &usize| {
        is_match_fail_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k]) == Some(fail_target)
    })?;
    let guard_start: usize =
        match_body_start(stream, last_pattern_gate + 1, fail_target, region_end);
    let guard_gate: usize = (guard_start..scan_end).find(|&k: &usize| {
        is_match_fail_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > k && t != fail_target)
    })?;
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[guard_start..guard_gate]).ok()?;
    let expr: Expr = residual.into_iter().next_back()?;
    if matches!(expr, Expr::Constant { .. } | Expr::Tuple { .. }) {
        return None;
    }
    let guard: Expr = if matches!(stream.ops[guard_gate], CanonicalOp::PopJumpIfTrue(_)) {
        Expr::UnaryOp {
            op: crate::ast::node::UnaryOpKind::Not,
            operand: Box::new(expr),
        }
    } else {
        expr
    };
    let body_start: usize = match_body_start(stream, guard_gate + 1, fail_target, region_end);
    Some((guard, body_start))
}

fn is_irrefutable_capture(pattern: &Pattern) -> bool {
    matches!(pattern, Pattern::MatchAs { pattern: None, .. })
}

fn capture_store_end(
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut end: usize = arm_start;
    for k in arm_start..scan_end {
        match stream.ops[k] {
            CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreFastStoreFast(_, _) => end = k + 1,
            CanonicalOp::StoreFastLoadFast(_, _) => end = k,
            _ => {}
        }
    }
    end
}

fn pattern_capture_region_end(
    stream: &DecodedStream,
    inner_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let first_gate: Option<usize> =
        (inner_start..scan_end).find(|&k: &usize| is_arm_gate(stream, k, fail_target));
    let from: usize = first_gate.map_or(inner_start, |gate: usize| gate + 1);
    let mut k: usize = from;
    while k < scan_end
        && (is_match_binding_op(stream, k, fail_target, region_end)
            || matches!(stream.ops[k], CanonicalOp::StoreFastLoadFast(_, _)))
    {
        k += 1;
    }
    k.min(scan_end)
}

fn last_gate_after(
    stream: &DecodedStream,
    arm_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut last_gate: usize = arm_start;
    for k in arm_start..scan_end {
        if is_arm_gate(stream, k, fail_target) {
            last_gate = k + 1;
        }
    }
    last_gate
}

fn pattern_capture_count(pattern: &Pattern) -> usize {
    match pattern {
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => 0,
        Pattern::MatchStar(name) => usize::from(name.is_some()),
        Pattern::MatchAs { pattern, name } => {
            usize::from(name.is_some()) + pattern.as_deref().map_or(0, pattern_capture_count)
        }
        Pattern::MatchSequence(elems) | Pattern::MatchOr(elems) => {
            elems.iter().map(pattern_capture_count).sum()
        }
        Pattern::MatchMapping { patterns, rest, .. } => {
            patterns.iter().map(pattern_capture_count).sum::<usize>() + usize::from(rest.is_some())
        }
        Pattern::MatchClass {
            patterns,
            kwd_patterns,
            ..
        } => {
            patterns.iter().map(pattern_capture_count).sum::<usize>()
                + kwd_patterns
                    .iter()
                    .map(pattern_capture_count)
                    .sum::<usize>()
        }
    }
}

fn structural_capture_count(
    stream: &DecodedStream,
    from: usize,
    scan_end: usize,
    inner: &Pattern,
) -> Option<usize> {
    match inner {
        Pattern::MatchClass { .. } => Some(pattern_capture_count(inner)),
        Pattern::MatchSequence(_) => {
            let mut count: Option<usize> = None;
            for k in from..scan_end.min(stream.ops.len()) {
                match &stream.ops[k] {
                    CanonicalOp::UnpackSequence(n) => {
                        count = Some(count.unwrap_or(0) + *n as usize);
                    }
                    CanonicalOp::UnpackEx(arg) => {
                        count = Some(
                            count.unwrap_or(0) + (arg & 0xFF) as usize + (arg >> 8) as usize + 1,
                        );
                    }
                    _ => {}
                }
            }
            count.or_else(|| Some(pattern_capture_count(inner)))
        }
        _ => None,
    }
}

fn strip_trailing_outer_as(inner: Pattern, outer: &str) -> Pattern {
    match inner {
        Pattern::MatchSequence(mut elems)
            if matches!(
                elems.last(),
                Some(Pattern::MatchAs { name: Some(n), .. }) if n == outer
            ) =>
        {
            elems.pop();
            Pattern::MatchSequence(elems)
        }
        other => other,
    }
}

fn classify_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head_search: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let Some(head): Option<usize> = match_arm_head(stream, head_search, scan_end) else {
        return Pattern::MatchAs {
            pattern: None,
            name: None,
        };
    };
    let dup_lead: bool = is_subject_dup(&stream.ops[head]);
    let after_first: usize = if dup_lead { head + 1 } else { head };
    let double_dup: bool = dup_lead
        && first_significant(stream, after_first, scan_end)
            .is_some_and(|n: usize| is_subject_dup(&stream.ops[n]));
    let inner_start: usize = if double_dup {
        first_significant(stream, after_first, scan_end).map_or(after_first, |n: usize| n + 1)
    } else {
        after_first
    };

    if dup_lead
        && !double_dup
        && let Some(store) = first_significant(stream, after_first, scan_end)
        && matches!(
            stream.ops[store],
            CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreFastLoadFast(_, _)
        )
    {
        let name: Option<String> = match &stream.ops[store] {
            CanonicalOp::StoreFast(slot) | CanonicalOp::StoreFastLoadFast(slot, _) => {
                local_name_at(code, *slot, store).ok()
            }
            CanonicalOp::StoreName(slot) => name_at(&code.names, *slot, store, "name").ok(),
            _ => None,
        };
        return Pattern::MatchAs {
            pattern: None,
            name,
        };
    }

    let inner: Pattern =
        classify_simple_pattern(code, stream, inner_start, fail_target, region_end);

    let capture_end: usize =
        pattern_capture_region_end(stream, inner_start, fail_target, region_end);

    if let Some(structural) = structural_capture_count(stream, inner_start, scan_end, &inner) {
        let names: Vec<String> = collect_capture_names(code, stream, inner_start, capture_end);
        if names.len() == structural + 1
            && let Some(outer) = names.last()
        {
            return Pattern::MatchAs {
                pattern: Some(Box::new(strip_trailing_outer_as(inner, outer))),
                name: Some(outer.clone()),
            };
        }
        if double_dup && let Some(name) = names.last() {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name.clone()),
            };
        }
    } else if double_dup
        && !matches!(
            inner,
            Pattern::MatchMapping { .. } | Pattern::MatchAs { .. }
        )
    {
        let names: Vec<String> = collect_capture_names(code, stream, inner_start, capture_end);
        if let Some(name) = names.last() {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name.clone()),
            };
        }
    }

    if matches!(inner, Pattern::MatchValue(_) | Pattern::MatchSingleton(_)) {
        let last_gate: usize = last_gate_after(stream, head_search, fail_target, region_end);
        if let Some(name) = scalar_as_binding(code, stream, last_gate, fail_target, region_end) {
            return Pattern::MatchAs {
                pattern: Some(Box::new(inner)),
                name: Some(name),
            };
        }
    }
    inner
}

fn scalar_as_binding(
    code: &CodeObject,
    stream: &DecodedStream,
    from: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<String> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in from..scan_end {
        match &stream.ops[k] {
            CanonicalOp::Pop
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::StoreFast(slot) => return local_name_at(code, *slot, k).ok(),
            CanonicalOp::StoreName(slot) => return name_at(&code.names, *slot, k, "name").ok(),
            _ => return None,
        }
    }
    None
}

fn body_scan_limit(stream: &DecodedStream, fail_target: usize, region_end: usize) -> usize {
    fail_target.min(region_end).min(stream.ops.len())
}

fn classify_simple_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    test_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let Some(first): Option<usize> = first_significant(stream, test_start, scan_end) else {
        return Pattern::MatchAs {
            pattern: None,
            name: None,
        };
    };
    match &stream.ops[first] {
        CanonicalOp::MatchSequence => {
            classify_sequence_pattern(code, stream, first, fail_target, region_end)
        }
        CanonicalOp::MatchMapping => {
            classify_mapping_pattern(code, stream, first, fail_target, region_end)
        }
        CanonicalOp::LoadGlobal(_)
        | CanonicalOp::LoadName(_)
        | CanonicalOp::LoadFromDictOrGlobals(_) => {
            classify_dotted_value_pattern(code, stream, first, fail_target, region_end)
                .unwrap_or_else(|| {
                    classify_class_pattern(code, stream, first, fail_target, region_end)
                })
        }
        CanonicalOp::LoadConst(slot) => {
            if let Some(next) = first_significant(stream, first + 1, scan_end) {
                if matches!(
                    stream.ops[next],
                    CanonicalOp::Compare(CmpOp::Is | CmpOp::IsNot)
                ) && let Ok(Expr::Constant { value, .. }) = load_const(code, *slot, first)
                {
                    return Pattern::MatchSingleton(value);
                }
                if matches!(stream.ops[next], CanonicalOp::Compare(_))
                    && let Ok(expr) = load_const(code, *slot, first)
                {
                    return Pattern::MatchValue(expr);
                }
            }
            load_const(code, *slot, first).map_or(
                Pattern::MatchAs {
                    pattern: None,
                    name: None,
                },
                Pattern::MatchValue,
            )
        }
        CanonicalOp::LoadSmallInt(v) => {
            let val: i32 = *v;
            Pattern::MatchValue(Expr::Constant {
                value: ConstValue::Int(i128::from(val)),
                line: None,
            })
        }
        CanonicalOp::PopJumpIfTrue(_) => Pattern::MatchSingleton(ConstValue::None),
        _ => collect_or_value_pattern(code, stream, test_start, fail_target, region_end),
    }
}

fn collect_or_value_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    test_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    for k in test_start..scan_end {
        match &stream.ops[k] {
            CanonicalOp::LoadConst(slot) => {
                if let Ok(expr) = load_const(code, *slot, k) {
                    return Pattern::MatchValue(expr);
                }
            }
            CanonicalOp::LoadSmallInt(v) => {
                return Pattern::MatchValue(Expr::Constant {
                    value: ConstValue::Int(i128::from(*v)),
                    line: None,
                });
            }
            _ => {}
        }
    }
    Pattern::MatchAs {
        pattern: None,
        name: None,
    }
}

fn skip_element_value_gate(stream: &DecodedStream, from: usize, scan_end: usize) -> usize {
    first_significant(stream, from, scan_end)
        .filter(|&g: &usize| is_match_fail_jump(&stream.ops[g]))
        .map_or(from, |g: usize| g + 1)
}

fn recover_fixed_sequence_elements(
    code: &CodeObject,
    stream: &DecodedStream,
    unpack_idx: usize,
    n: usize,
    scan_end: usize,
) -> Option<Vec<Pattern>> {
    let mut elems: Vec<Pattern> = Vec::with_capacity(n);
    let mut k: usize = first_significant(stream, unpack_idx + 1, scan_end)?;
    while elems.len() < n {
        let (pat, next): (Pattern, usize) =
            recover_one_sequence_element(code, stream, k, scan_end)?;
        elems.push(pat);
        match first_significant(stream, next, scan_end) {
            Some(nk) => k = nk,
            None => break,
        }
    }
    (elems.len() == n).then_some(elems)
}

fn recover_one_sequence_element(
    code: &CodeObject,
    stream: &DecodedStream,
    k: usize,
    scan_end: usize,
) -> Option<(Pattern, usize)> {
    match &stream.ops[k] {
        CanonicalOp::LoadConst(slot) => {
            let cmp: usize = first_significant(stream, k + 1, scan_end)?;
            if !matches!(stream.ops[cmp], CanonicalOp::Compare(_)) {
                return None;
            }
            let val: Expr = load_const(code, *slot, k).ok()?;
            Some((
                Pattern::MatchValue(val),
                skip_element_value_gate(stream, cmp + 1, scan_end),
            ))
        }
        CanonicalOp::LoadSmallInt(v) => {
            let cmp: usize = first_significant(stream, k + 1, scan_end)?;
            if !matches!(stream.ops[cmp], CanonicalOp::Compare(_)) {
                return None;
            }
            Some((
                Pattern::MatchValue(Expr::Constant {
                    value: ConstValue::Int(i128::from(*v)),
                    line: None,
                }),
                skip_element_value_gate(stream, cmp + 1, scan_end),
            ))
        }
        CanonicalOp::StoreFast(slot) => {
            let name: String = local_name_at(code, *slot, k).ok()?;
            Some((
                Pattern::MatchAs {
                    pattern: None,
                    name: Some(name),
                },
                k + 1,
            ))
        }
        CanonicalOp::StoreName(slot) => {
            let name: String = name_at(&code.names, *slot, k, "name").ok()?;
            Some((
                Pattern::MatchAs {
                    pattern: None,
                    name: Some(name),
                },
                k + 1,
            ))
        }
        CanonicalOp::Copy(1)
            if first_significant(stream, k + 1, scan_end).is_some_and(|n: usize| {
                matches!(
                    stream.ops[n],
                    CanonicalOp::LoadGlobal(_)
                        | CanonicalOp::LoadName(_)
                        | CanonicalOp::LoadFromDictOrGlobals(_)
                ) && element_is_class_pattern(stream, n, scan_end)
            }) =>
        {
            let cls_head: usize = first_significant(stream, k + 1, scan_end)?;
            recover_class_sequence_element(code, stream, k, cls_head, scan_end)
        }
        CanonicalOp::LoadGlobal(_)
        | CanonicalOp::LoadName(_)
        | CanonicalOp::LoadFromDictOrGlobals(_)
            if element_is_class_pattern(stream, k, scan_end) =>
        {
            recover_class_sequence_element(code, stream, k, k, scan_end)
        }
        CanonicalOp::Pop => Some((
            Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            k + 1,
        )),
        _ => None,
    }
}

fn element_is_class_pattern(stream: &DecodedStream, head: usize, scan_end: usize) -> bool {
    for k in head..scan_end {
        match &stream.ops[k] {
            CanonicalOp::MatchClass(_) => return true,
            CanonicalOp::Compare(_) | CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::Pop => {
                return false;
            }
            _ => {}
        }
    }
    false
}

fn recover_class_sequence_element(
    code: &CodeObject,
    stream: &DecodedStream,
    subject_dup: usize,
    cls_head: usize,
    scan_end: usize,
) -> Option<(Pattern, usize)> {
    let match_class: usize = (cls_head..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::MatchClass(_)))?;
    let CanonicalOp::MatchClass(positional) = stream.ops[match_class] else {
        return None;
    };
    let kwd_count: usize = (cls_head..match_class)
        .rev()
        .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::LoadConst(_)))
        .and_then(|prev: usize| match stream.ops[prev] {
            CanonicalOp::LoadConst(slot) => {
                const_string_tuple(code, slot).map(|s: Vec<String>| s.len())
            }
            _ => None,
        })
        .unwrap_or(0);
    let total_slots: usize = positional as usize + kwd_count;
    let none_gate: usize = (match_class..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::PopJumpIfFalse(_)))?;
    let class_region_end: usize =
        class_element_region_end(stream, none_gate, total_slots, scan_end);
    let inner: Pattern = classify_class_pattern(code, stream, cls_head, class_region_end, scan_end);
    let mut end: usize = class_region_end;
    let mut outer_as: Option<String> = None;
    while end < scan_end {
        match &stream.ops[end] {
            CanonicalOp::Swap(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => end += 1,
            CanonicalOp::StoreFast(slot) if subject_dup != cls_head => {
                outer_as = local_name_at(code, *slot, end).ok();
                end += 1;
                break;
            }
            CanonicalOp::StoreName(slot) if subject_dup != cls_head => {
                outer_as = name_at(&code.names, *slot, end, "name").ok();
                end += 1;
                break;
            }
            CanonicalOp::Pop => {
                end += 1;
            }
            _ => break,
        }
    }
    if let Some(p) = first_significant(stream, end, scan_end)
        && matches!(stream.ops[p], CanonicalOp::Pop)
    {
        end = p + 1;
    }
    let pattern: Pattern = match outer_as {
        Some(name) => Pattern::MatchAs {
            pattern: Some(Box::new(inner)),
            name: Some(name),
        },
        None => inner,
    };
    Some((pattern, end))
}

fn class_element_region_end(
    stream: &DecodedStream,
    none_gate: usize,
    total_slots: usize,
    scan_end: usize,
) -> usize {
    let Some(unpack): Option<usize> = (none_gate + 1..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::UnpackSequence(_)))
        .filter(|&u: &usize| {
            (none_gate + 1..u).all(|j: usize| {
                matches!(
                    stream.ops[j],
                    CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
                )
            })
        })
    else {
        return none_gate + 1;
    };
    let mut end: usize = unpack + 1;
    let mut consumed: usize = 0;
    while end < scan_end && consumed < total_slots {
        match &stream.ops[end] {
            CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_) => {
                consumed += 1;
                end += 1;
            }
            CanonicalOp::Compare(_) | CanonicalOp::Cache | CanonicalOp::Nop => end += 1,
            op if is_match_fail_jump(op) => end += 1,
            _ => break,
        }
    }
    end
}

fn recover_star_sequence_elements(
    code: &CodeObject,
    stream: &DecodedStream,
    unpack_idx: usize,
    before: usize,
    after: usize,
    scan_end: usize,
) -> Option<Vec<Pattern>> {
    let mut elems: Vec<Pattern> = Vec::with_capacity(before + after + 1);
    let mut k: usize = first_significant(stream, unpack_idx + 1, scan_end)?;
    for _ in 0..before {
        let (pat, next): (Pattern, usize) =
            recover_one_sequence_element(code, stream, k, scan_end)?;
        elems.push(pat);
        k = first_significant(stream, next, scan_end)?;
    }
    let star: Pattern = match &stream.ops[k] {
        CanonicalOp::StoreFast(slot) => {
            Pattern::MatchStar(Some(local_name_at(code, *slot, k).ok()?))
        }
        CanonicalOp::StoreName(slot) => {
            Pattern::MatchStar(Some(name_at(&code.names, *slot, k, "name").ok()?))
        }
        CanonicalOp::Pop => Pattern::MatchStar(None),
        _ => return None,
    };
    elems.push(star);
    let mut after_cursor: Option<usize> = first_significant(stream, k + 1, scan_end);
    for _ in 0..after {
        let ak: usize = after_cursor?;
        let (pat, next): (Pattern, usize) =
            recover_one_sequence_element(code, stream, ak, scan_end)?;
        elems.push(pat);
        after_cursor = first_significant(stream, next, scan_end);
    }
    Some(elems)
}

fn recover_indexed_star_sequence_elements(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    scan_end: usize,
) -> Option<Vec<Pattern>> {
    let getlen: usize =
        (head..scan_end).find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::GetLen))?;
    let ge_cmp: usize = (getlen..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::Compare(CmpOp::Ge)))?;
    let mut by_index: std::collections::BTreeMap<u32, Pattern> = std::collections::BTreeMap::new();
    let mut k: usize = ge_cmp + 1;
    while k < scan_end {
        if !matches!(stream.ops[k], CanonicalOp::Copy(1)) {
            k += 1;
            continue;
        }
        let load: usize = first_significant(stream, k + 1, scan_end)?;
        let idx: u32 = match &stream.ops[load] {
            CanonicalOp::LoadSmallInt(v) if *v >= 0 => *v as u32,
            CanonicalOp::LoadConst(slot) => match load_const(code, *slot, load).ok()? {
                Expr::Constant {
                    value: ConstValue::Int(i),
                    ..
                } if i >= 0 && i <= i128::from(u32::MAX) => i as u32,
                _ => return None,
            },
            _ => return None,
        };
        let subscr: usize = first_significant(stream, load + 1, scan_end)?;
        if !matches!(stream.ops[subscr], CanonicalOp::LoadSubscr) {
            return None;
        }
        let elem_start: usize = first_significant(stream, subscr + 1, scan_end)?;
        let (pat, next): (Pattern, usize) =
            recover_one_sequence_element(code, stream, elem_start, scan_end)?;
        by_index.insert(idx, pat);
        k = next;
    }
    if by_index.is_empty() {
        return None;
    }
    let expected: usize = by_index.len();
    if by_index.keys().copied().ne(0..expected as u32) {
        return None;
    }
    let mut elems: Vec<Pattern> = by_index.into_values().collect();
    elems.push(Pattern::MatchStar(None));
    Some(elems)
}

fn classify_sequence_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let indexed_star: bool = (head..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::GetLen))
        .is_some_and(|gl: usize| {
            (gl..scan_end).any(|i: usize| matches!(stream.ops[i], CanonicalOp::Compare(CmpOp::Ge)))
        });
    if indexed_star
        && let Some(elems) = recover_indexed_star_sequence_elements(code, stream, head, scan_end)
    {
        return Pattern::MatchSequence(elems);
    }
    let mut star_before: Option<u32> = None;
    let mut star_after: u32 = 0;
    let mut fixed_len: Option<u32> = None;
    let mut unpack_idx: usize = head;
    let mut k: usize = head;
    while k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::UnpackSequence(n) => {
                fixed_len = Some(*n);
                unpack_idx = k;
                break;
            }
            CanonicalOp::UnpackEx(arg) => {
                star_before = Some(arg & 0xFF);
                star_after = (arg >> 8) & 0xFF;
                unpack_idx = k;
                break;
            }
            CanonicalOp::Compare(_) if fixed_len.is_none() && star_before.is_none() => {}
            _ => {}
        }
        k += 1;
    }
    if star_before.is_none()
        && let Some(n) = fixed_len
        && n > 0
        && let Some(elems) =
            recover_fixed_sequence_elements(code, stream, unpack_idx, n as usize, scan_end)
    {
        return Pattern::MatchSequence(elems);
    }
    if let Some(before) = star_before
        && let Some(elems) = recover_star_sequence_elements(
            code,
            stream,
            unpack_idx,
            before as usize,
            star_after as usize,
            scan_end,
        )
    {
        return Pattern::MatchSequence(elems);
    }
    let names: Vec<String> = collect_capture_names(code, stream, head, scan_end);
    star_before.map_or_else(
        || match fixed_len {
            Some(0) => Pattern::MatchSequence(Vec::new()),
            Some(n) if (n as usize) < names.len() => {
                Pattern::MatchSequence(captures_to_patterns(&names[..n as usize]))
            }
            _ => Pattern::MatchSequence(captures_to_patterns(&names)),
        },
        |before: u32| {
            let before_n: usize = before as usize;
            let elems: Vec<Pattern> = names
                .iter()
                .enumerate()
                .map(|(i, n): (usize, &String)| {
                    if i == before_n {
                        Pattern::MatchStar(Some(n.clone()))
                    } else {
                        Pattern::MatchAs {
                            pattern: None,
                            name: Some(n.clone()),
                        }
                    }
                })
                .collect();
            Pattern::MatchSequence(elems)
        },
    )
}

fn recover_nested_mapping_values(
    code: &CodeObject,
    stream: &DecodedStream,
    keys_end: usize,
    key_count: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<Vec<Pattern>> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let none_gate: usize = (keys_end..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::PopJumpIfFalse(_)))?;
    let unpack: usize = (none_gate + 1..scan_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::UnpackSequence(_)))?;
    if scan_end <= unpack {
        return None;
    }
    let CanonicalOp::UnpackSequence(spilled) = stream.ops[unpack] else {
        return None;
    };
    if spilled as usize != key_count {
        return None;
    }
    let mut patterns: Vec<Pattern> = Vec::with_capacity(key_count);
    let mut any_structural: bool = false;
    let mut cursor: usize = first_significant(stream, unpack + 1, scan_end)?;
    for _ in 0..key_count {
        let (pat, next): (Pattern, usize) =
            recover_one_mapping_value(code, stream, cursor, scan_end, region_end)?;
        if matches!(
            pat,
            Pattern::MatchSequence(_) | Pattern::MatchMapping { .. } | Pattern::MatchClass { .. }
        ) || matches!(
            &pat,
            Pattern::MatchAs {
                pattern: Some(_),
                ..
            }
        ) {
            any_structural = true;
        }
        patterns.push(pat);
        cursor = match first_significant(stream, next, scan_end) {
            Some(c) => c,
            None => break,
        };
    }
    (any_structural && patterns.len() == key_count).then_some(patterns)
}

fn recover_one_mapping_value(
    code: &CodeObject,
    stream: &DecodedStream,
    cursor: usize,
    scan_end: usize,
    region_end: usize,
) -> Option<(Pattern, usize)> {
    match &stream.ops[cursor] {
        CanonicalOp::MatchSequence => {
            let gate: usize = nested_subpattern_end(stream, cursor, scan_end);
            let pat: Pattern = classify_sequence_pattern(code, stream, cursor, gate, region_end);
            Some((pat, gate))
        }
        CanonicalOp::MatchMapping => {
            let gate: usize = nested_subpattern_end(stream, cursor, scan_end);
            let pat: Pattern = classify_mapping_pattern(code, stream, cursor, gate, region_end);
            Some((pat, gate))
        }
        _ => recover_one_sequence_element(code, stream, cursor, scan_end),
    }
}

fn nested_subpattern_end(stream: &DecodedStream, cursor: usize, scan_end: usize) -> usize {
    let mut last_gate: Option<usize> = None;
    for k in cursor..scan_end {
        match &stream.ops[k] {
            op if is_match_fail_jump(op) => last_gate = Some(k),
            CanonicalOp::Pop if last_gate.is_some() => return k + 1,
            CanonicalOp::MatchSequence | CanonicalOp::MatchMapping | CanonicalOp::MatchClass(_)
                if k > cursor && last_gate.is_none() =>
            {
                return k;
            }
            _ => {}
        }
    }
    scan_end
}

fn classify_mapping_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let mut keys: Vec<Expr> = Vec::new();
    let mut k: usize = head;
    while k < scan_end {
        if matches!(stream.ops[k], CanonicalOp::MatchKeys) {
            if let Some(prev) = (head..k)
                .rev()
                .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::LoadConst(_)))
                && let CanonicalOp::LoadConst(slot) = stream.ops[prev]
                && let Some(strs) = const_string_tuple(code, slot)
            {
                keys = strs
                    .into_iter()
                    .map(|s: String| Expr::Constant {
                        value: ConstValue::Str(s),
                        line: None,
                    })
                    .collect();
            }
            break;
        }
        k += 1;
    }
    let keys_end: usize = (head..scan_end)
        .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::MatchKeys))
        .map_or(head, |j: usize| j + 1);
    let key_count: usize = keys.len();

    if key_count > 0
        && let Some(nested) = recover_nested_mapping_values(
            code,
            stream,
            keys_end,
            key_count,
            fail_target,
            region_end,
        )
    {
        return Pattern::MatchMapping {
            keys,
            patterns: nested,
            rest: None,
        };
    }
    let dict_rest_marker: Option<usize> = (keys_end..scan_end).rev().find(|&j: &usize| {
        matches!(
            stream.ops[j],
            CanonicalOp::DeleteSubscr | CanonicalOp::DictUpdate(_) | CanonicalOp::BuildMap(_)
        )
    });

    let mut value_patterns: Vec<Pattern> = Vec::new();
    let mut stores: Vec<MappingStore> = Vec::new();
    let mut k2: usize = keys_end;
    while k2 < scan_end {
        match &stream.ops[k2] {
            CanonicalOp::Compare(_) => {
                if let Some(lit) = (keys_end..k2).rev().find(|&j: &usize| {
                    matches!(
                        stream.ops[j],
                        CanonicalOp::LoadConst(_) | CanonicalOp::LoadSmallInt(_)
                    )
                }) {
                    let val: Pattern = match &stream.ops[lit] {
                        CanonicalOp::LoadConst(slot) => load_const(code, *slot, lit).map_or(
                            Pattern::MatchAs {
                                pattern: None,
                                name: None,
                            },
                            Pattern::MatchValue,
                        ),
                        CanonicalOp::LoadSmallInt(v) => Pattern::MatchValue(Expr::Constant {
                            value: ConstValue::Int(i128::from(*v)),
                            line: None,
                        }),
                        _ => Pattern::MatchAs {
                            pattern: None,
                            name: None,
                        },
                    };
                    value_patterns.push(val);
                }
            }
            CanonicalOp::StoreFast(slot) => {
                if let Ok(name) = local_name_at(code, *slot, k2) {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            CanonicalOp::StoreName(slot) => {
                if let Ok(name) = name_at(&code.names, *slot, k2, "name") {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Ok(name) = local_name_at(code, *a, k2) {
                    stores.push(MappingStore { name, fused: true });
                }
                if let Ok(name) = local_name_at(code, *b, k2) {
                    stores.push(MappingStore { name, fused: false });
                }
            }
            _ => {}
        }
        k2 += 1;
    }

    let capture_key_count: usize = key_count.saturating_sub(value_patterns.len());
    let (rest_idx, outer_idx): (Option<usize>, Option<usize>) = mapping_rest_and_outer(
        &stores,
        capture_key_count,
        dict_rest_marker.is_some(),
        stream.version.minor(),
    );
    let rest: Option<String> =
        rest_idx.and_then(|i: usize| stores.get(i).map(|s: &MappingStore| s.name.clone()));
    let outer_as: Option<String> =
        outer_idx.and_then(|i: usize| stores.get(i).map(|s: &MappingStore| s.name.clone()));
    let capture_names: Vec<String> = stores
        .iter()
        .enumerate()
        .filter(|(i, _): &(usize, &MappingStore)| Some(*i) != rest_idx && Some(*i) != outer_idx)
        .map(|(_, s): (usize, &MappingStore)| s.name.clone())
        .collect();

    let mut value_iter: usize = 0;
    let mut name_iter: usize = 0;
    let patterns: Vec<Pattern> = (0..key_count)
        .map(|_| {
            if value_iter < value_patterns.len() {
                let p: Pattern = value_patterns[value_iter].clone();
                value_iter += 1;
                p
            } else if name_iter < capture_names.len() {
                let p: Pattern = Pattern::MatchAs {
                    pattern: None,
                    name: Some(capture_names[name_iter].clone()),
                };
                name_iter += 1;
                p
            } else {
                Pattern::MatchAs {
                    pattern: None,
                    name: None,
                }
            }
        })
        .collect();

    let mapping: Pattern = Pattern::MatchMapping {
        keys,
        patterns,
        rest,
    };
    match outer_as {
        Some(name) => Pattern::MatchAs {
            pattern: Some(Box::new(mapping)),
            name: Some(name),
        },
        None => mapping,
    }
}

#[derive(Debug, Clone)]
struct MappingStore {
    name: String,
    fused: bool,
}

fn mapping_rest_and_outer(
    stores: &[MappingStore],
    capture_key_count: usize,
    has_rest_marker: bool,
    minor: u8,
) -> (Option<usize>, Option<usize>) {
    let total: usize = stores.len();
    if !has_rest_marker {
        let outer_idx: Option<usize> = (total > capture_key_count).then(|| total - 1);
        return (None, outer_idx);
    }
    let extra: usize = total.saturating_sub(capture_key_count);
    if extra == 0 {
        return (None, None);
    }
    let has_outer: bool = extra >= 2;
    if let Some(fused_first) = stores.iter().position(|s: &MappingStore| s.fused)
        && fused_first + 1 < total
    {
        let outer_idx: Option<usize> = has_outer.then_some(fused_first + 1);
        return (Some(fused_first), outer_idx);
    }
    if minor <= 10 {
        let rest_idx: usize = capture_key_count.min(total - 1);
        let outer_idx: Option<usize> = has_outer.then(|| total - 1);
        (Some(rest_idx), outer_idx)
    } else {
        let outer_idx: Option<usize> = has_outer.then_some(1);
        (Some(0), outer_idx)
    }
}

fn classify_dotted_value_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<Pattern> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let base_id: String = match &stream.ops[head] {
        CanonicalOp::LoadGlobal(slot) => name_at_either(code, *slot).ok()?,
        CanonicalOp::LoadName(slot) | CanonicalOp::LoadFromDictOrGlobals(slot) => {
            name_at(&code.names, *slot, head, "name").ok()?
        }
        _ => return None,
    };
    let mut expr: Expr = Expr::Name {
        id: base_id,
        ctx: ExprCtx::Load,
        line: None,
    };
    let mut attr_count: usize = 0;
    let mut k: usize = head + 1;
    while k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            CanonicalOp::LoadAttr(slot) => {
                let attr: String = name_at(&code.names, *slot, k, "attr").ok()?;
                expr = Expr::Attribute {
                    value: Box::new(expr),
                    attr,
                    ctx: ExprCtx::Load,
                };
                attr_count += 1;
            }
            CanonicalOp::Compare(CmpOp::Eq) if attr_count > 0 => {
                return Some(Pattern::MatchValue(expr));
            }
            _ => return None,
        }
        k += 1;
    }
    None
}

fn classify_class_pattern(
    code: &CodeObject,
    stream: &DecodedStream,
    head: usize,
    fail_target: usize,
    region_end: usize,
) -> Pattern {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let cls_name: Result<String> = match &stream.ops[head] {
        CanonicalOp::LoadGlobal(slot) => name_at_either(code, *slot),
        CanonicalOp::LoadName(slot) | CanonicalOp::LoadFromDictOrGlobals(slot) => {
            name_at(&code.names, *slot, head, "name")
        }
        _ => Err(DecompileError::AstDesync {
            offset: head,
            reason: "match-class head is not a class load".to_owned(),
        }),
    };
    let cls: Expr = cls_name.map_or(
        Expr::Constant {
            value: ConstValue::None,
            line: None,
        },
        |id: String| Expr::Name {
            id,
            ctx: ExprCtx::Load,
            line: None,
        },
    );
    let mut kwd_attrs: Vec<String> = Vec::new();
    let mut positional: u8 = 0;
    let mut match_class_idx: Option<usize> = None;
    let mut k: usize = head;
    while k < scan_end {
        if let CanonicalOp::MatchClass(count) = stream.ops[k] {
            positional = count;
            match_class_idx = Some(k);
            if let Some(prev) = (head..k)
                .rev()
                .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::LoadConst(_)))
                && let CanonicalOp::LoadConst(slot) = stream.ops[prev]
                && let Some(strs) = const_string_tuple(code, slot)
            {
                kwd_attrs = strs;
            }
            break;
        }
        k += 1;
    }
    let positional_count: usize = positional as usize;
    let kwd_count: usize = kwd_attrs.len();
    let total_slots: usize = positional_count + kwd_count;
    let slot_patterns: Vec<Pattern> = match_class_idx.map_or_else(Vec::new, |mc: usize| {
        recover_class_subpatterns(code, stream, mc, scan_end, total_slots)
    });
    let mut slot_iter: std::vec::IntoIter<Pattern> = slot_patterns.into_iter();
    let patterns: Vec<Pattern> = (0..positional_count)
        .map(|_| {
            slot_iter.next().unwrap_or(Pattern::MatchAs {
                pattern: None,
                name: None,
            })
        })
        .collect();
    let kwd_patterns: Vec<Pattern> = (0..kwd_count)
        .map(|_| {
            slot_iter.next().unwrap_or(Pattern::MatchAs {
                pattern: None,
                name: None,
            })
        })
        .collect();
    Pattern::MatchClass {
        cls,
        patterns,
        kwd_attrs,
        kwd_patterns,
    }
}

fn recover_class_subpatterns(
    code: &CodeObject,
    stream: &DecodedStream,
    match_class_idx: usize,
    scan_end: usize,
    total_slots: usize,
) -> Vec<Pattern> {
    if total_slots == 0 {
        return Vec::new();
    }
    let total_slots: usize = total_slots.min(stream.ops.len());
    let Some(unpack_idx): Option<usize> = (match_class_idx + 1..scan_end)
        .find(|&j: &usize| matches!(stream.ops[j], CanonicalOp::UnpackSequence(_)))
    else {
        return recover_class_subpatterns_subscript(
            code,
            stream,
            match_class_idx,
            scan_end,
            total_slots,
        );
    };
    let mut slots: Vec<Pattern> = vec![
        Pattern::MatchAs {
            pattern: None,
            name: None
        };
        total_slots
    ];
    let mut value_stack: Vec<usize> = (0..total_slots).rev().collect();
    let mut k: usize = unpack_idx + 1;
    while !value_stack.is_empty() && k < scan_end {
        match &stream.ops[k] {
            CanonicalOp::Swap(depth) => {
                let len: usize = value_stack.len();
                let d: usize = *depth as usize;
                if d >= 2 && d <= len {
                    value_stack.swap(len - 1, len - d);
                }
                k += 1;
            }
            CanonicalOp::Pop => {
                value_stack.pop();
                k += 1;
            }
            CanonicalOp::StoreFast(slot) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        local_name_at(code, *slot, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreName(slot) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        name_at(&code.names, *slot, k, "name").unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreFastLoadFast(store_slot, _) => {
                if let Some(si) = value_stack.pop() {
                    let name: String =
                        local_name_at(code, *store_slot, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name),
                    };
                }
                k += 1;
            }
            CanonicalOp::StoreFastStoreFast(a, b) => {
                if let Some(si) = value_stack.pop() {
                    let name_a: String =
                        local_name_at(code, *a, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name_a),
                    };
                }
                if let Some(si) = value_stack.pop() {
                    let name_b: String =
                        local_name_at(code, *b, k).unwrap_or_else(|_| "_".to_owned());
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(name_b),
                    };
                }
                k += 1;
            }
            CanonicalOp::LoadConst(slot) => {
                if let Some(si) = value_stack.pop() {
                    let expr: Expr = load_const(code, *slot, k).unwrap_or(Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    });
                    slots[si] = Pattern::MatchValue(expr);
                }
                k = skip_value_test(stream, k + 1, scan_end);
            }
            CanonicalOp::LoadSmallInt(v) => {
                if let Some(si) = value_stack.pop() {
                    slots[si] = Pattern::MatchValue(Expr::Constant {
                        value: ConstValue::Int(i128::from(*v)),
                        line: None,
                    });
                }
                k = skip_value_test(stream, k + 1, scan_end);
            }
            _ => {
                k += 1;
            }
        }
    }
    slots
}

fn recover_class_subpatterns_subscript(
    code: &CodeObject,
    stream: &DecodedStream,
    match_class_idx: usize,
    scan_end: usize,
    total_slots: usize,
) -> Vec<Pattern> {
    let mut slots: Vec<Pattern> = vec![
        Pattern::MatchAs {
            pattern: None,
            name: None
        };
        total_slots
    ];
    let mut capture_indices: Vec<usize> = Vec::new();
    let mut k: usize = match_class_idx + 1;
    while k < scan_end
        && matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::Pop
        )
    {
        k += 1;
    }
    while k + 2 < scan_end {
        if !matches!(stream.ops[k], CanonicalOp::Dup) {
            break;
        }
        let idx_at: usize = k + 1;
        let CanonicalOp::LoadConst(idx_const) = stream.ops[idx_at] else {
            break;
        };
        if !matches!(stream.ops[idx_at + 1], CanonicalOp::LoadSubscr) {
            break;
        }
        let slot_idx: Option<usize> = const_index_value(code, idx_const, idx_at);
        let body: usize = idx_at + 2;
        match &stream.ops[body] {
            CanonicalOp::LoadConst(lit) => {
                if let Some(si) = slot_idx
                    && si < slots.len()
                    && let Ok(expr) = load_const(code, *lit, body)
                {
                    slots[si] = Pattern::MatchValue(expr);
                }
                k = skip_value_test(stream, body + 1, scan_end);
            }
            CanonicalOp::LoadSmallInt(v) => {
                if let Some(si) = slot_idx
                    && si < slots.len()
                {
                    slots[si] = Pattern::MatchValue(Expr::Constant {
                        value: ConstValue::Int(i128::from(*v)),
                        line: None,
                    });
                }
                k = skip_value_test(stream, body + 1, scan_end);
            }
            CanonicalOp::RotN(_) | CanonicalOp::Swap(_) => {
                if let Some(si) = slot_idx {
                    capture_indices.push(si);
                }
                k = body + 1;
            }
            _ => {
                break;
            }
        }
    }
    if !capture_indices.is_empty() {
        let mut store_at: usize = k;
        let mut bound: usize = 0;
        while store_at < scan_end && bound < capture_indices.len() {
            let name: Option<String> = match stream.ops[store_at] {
                CanonicalOp::StoreFast(s) => local_name_at(code, s, store_at).ok(),
                CanonicalOp::StoreName(s) => name_at(&code.names, s, store_at, "name").ok(),
                _ => None,
            };
            if let Some(n) = name {
                let si: usize = capture_indices[bound];
                if si < slots.len() {
                    slots[si] = Pattern::MatchAs {
                        pattern: None,
                        name: Some(n),
                    };
                }
                bound += 1;
            }
            store_at += 1;
        }
    }
    slots
}

fn const_index_value(code: &CodeObject, idx_const: u32, offset: usize) -> Option<usize> {
    match load_const(code, idx_const, offset).ok()? {
        Expr::Constant {
            value: ConstValue::Int(i),
            ..
        } => usize::try_from(i).ok(),
        _ => None,
    }
}

fn skip_value_test(stream: &DecodedStream, from: usize, scan_end: usize) -> usize {
    let mut k: usize = from;
    while k < scan_end
        && matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    {
        k += 1;
    }
    if k < scan_end && matches!(stream.ops[k], CanonicalOp::Compare(_) | CanonicalOp::ToBool) {
        k += 1;
        while k < scan_end
            && matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        {
            k += 1;
        }
        if k < scan_end && is_match_fail_jump(&stream.ops[k]) {
            k += 1;
        }
    }
    k
}

fn extract_guard(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    fail_target: usize,
    region_end: usize,
) -> Option<Expr> {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    let guard_jump: usize =
        (body_start..scan_end).find(|&k: &usize| is_arm_gate(stream, k, fail_target))?;
    let (_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[body_start..guard_jump]).ok()?;
    let expr: Expr = residual.into_iter().next_back()?;
    if matches!(stream.ops[guard_jump], CanonicalOp::PopJumpIfTrue(_)) {
        Some(Expr::UnaryOp {
            op: crate::ast::node::UnaryOpKind::Not,
            operand: Box::new(expr),
        })
    } else {
        Some(expr)
    }
}

fn guard_body_start(
    stream: &DecodedStream,
    body_start: usize,
    fail_target: usize,
    region_end: usize,
) -> usize {
    let scan_end: usize = body_scan_limit(stream, fail_target, region_end);
    (body_start..scan_end)
        .find(|&k: &usize| is_arm_gate(stream, k, fail_target))
        .map_or(body_start, |j: usize| {
            match_body_start(stream, j + 1, fail_target, region_end)
        })
}

fn region_has_match_op(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::MatchClass(_)
                | CanonicalOp::MatchSequence
                | CanonicalOp::MatchMapping
                | CanonicalOp::MatchKeys
        )
    })
}

fn is_genuine_match_region(stream: &DecodedStream, subject_split: usize, hi: usize) -> bool {
    if region_has_match_op(stream, subject_split, hi) {
        return true;
    }
    (subject_split..hi).any(|k: usize| is_dup_value_arm_with_cleanup(stream, k, hi))
}

fn is_pattern_literal_load(op: &CanonicalOp) -> bool {
    matches!(op, CanonicalOp::LoadConst(_) | CanonicalOp::LoadSmallInt(_))
}

fn is_match_value_compare(op: CmpOp, comparand: Option<&CanonicalOp>) -> bool {
    match op {
        CmpOp::Eq => true,
        CmpOp::Is | CmpOp::IsNot => comparand.is_some_and(is_pattern_literal_load),
        _ => false,
    }
}

fn is_dup_value_arm_with_cleanup(stream: &DecodedStream, idx: usize, hi: usize) -> bool {
    if !is_subject_dup(&stream.ops[idx]) {
        return false;
    }
    let mut k: usize = idx + 1;
    let mut comparand: Option<&CanonicalOp> = None;
    let mut saw_capture_store: bool = false;
    let mut saw_arm_compare: bool = false;
    while k < hi {
        match &stream.ops[k] {
            CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::Dup
            | CanonicalOp::Copy(_)
            | CanonicalOp::ToBool => k += 1,
            op if is_capture_store(op) => {
                saw_capture_store = true;
                k += 1;
            }
            load @ (CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadFromDictOrGlobals(_)
            | CanonicalOp::LoadAttr(_)) => {
                comparand = Some(load);
                k += 1;
            }
            CanonicalOp::Compare(op) => {
                if !saw_capture_store && !is_match_value_compare(*op, comparand) {
                    return false;
                }
                saw_arm_compare = true;
                k += 1;
            }
            op if saw_arm_compare && is_match_fail_jump(op) => {
                return matches!(
                    first_significant(stream, k + 1, hi).map(|n: usize| &stream.ops[n]),
                    Some(CanonicalOp::Pop | CanonicalOp::JumpForward(_))
                );
            }
            _ => return false,
        }
    }
    false
}

pub(super) fn try_structure_literal_wildcard_match(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if !stream.supports_match() {
        return Ok(None);
    }
    let Some(jump_idx): Option<usize> = (lo..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        )
    }) else {
        return Ok(None);
    };
    let Some(cmp_idx): Option<usize> = last_significant_back(stream, lo, jump_idx) else {
        return Ok(None);
    };
    if !matches!(stream.ops[cmp_idx], CanonicalOp::Compare(CmpOp::Eq)) {
        return Ok(None);
    }
    let Some(lit_idx): Option<usize> = last_significant_back(stream, lo, cmp_idx) else {
        return Ok(None);
    };
    let literal: Expr = match &stream.ops[lit_idx] {
        CanonicalOp::LoadConst(slot) => load_const(code, *slot, lit_idx)?,
        CanonicalOp::LoadSmallInt(v) => Expr::Constant {
            value: ConstValue::Int(i128::from(*v)),
            line: None,
        },
        _ => return Ok(None),
    };
    let Some(wild): Option<usize> = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t < hi)
    else {
        return Ok(None);
    };
    if !matches!(stream.ops[wild], CanonicalOp::Nop) {
        return Ok(None);
    }
    let subject_end: usize = lit_idx;
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..subject_end])?;
    let Some(subject): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    if !head.is_empty() {
        return Ok(None);
    }
    let arm1: Vec<Stmt> = structure_stmts(code, stream, jump_idx + 1, wild)?;
    if !matches!(
        arm1.last(),
        Some(Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Break | Stmt::Continue)
    ) {
        return Ok(None);
    }
    let arm2: Vec<Stmt> = structure_stmts(code, stream, wild + 1, hi)?;
    let cases: Vec<MatchCase> = vec![
        MatchCase {
            pattern: Pattern::MatchValue(literal),
            guard: None,
            body: non_empty(arm1),
        },
        MatchCase {
            pattern: Pattern::MatchAs {
                pattern: None,
                name: None,
            },
            guard: None,
            body: non_empty(arm2),
        },
    ];
    Ok(Some(vec![Stmt::Match {
        subject,
        cases,
        line: None,
    }]))
}

pub(super) fn structure_match(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<(Vec<Stmt>, usize)>> {
    let Some(subject_split): Option<usize> = match_subject_split(stream, lo, hi) else {
        return Ok(None);
    };
    if subject_split <= lo {
        return Ok(None);
    }
    if let Some(head) = match_head_index(stream, lo, hi)
        && !subject_region_is_straight_line(stream, lo, head)
    {
        return Ok(None);
    }
    let (head_stmts, head_residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..subject_split])?;
    let Some(subject): Option<Expr> = head_residual.into_iter().next_back() else {
        return Ok(None);
    };

    if !is_genuine_match_region(stream, subject_split, hi) {
        return Ok(None);
    }

    let mut parsed: Vec<PendingArm> = Vec::new();
    let mut arm_start: usize = subject_split;
    while arm_start < hi {
        let Some(arm): Option<ParsedArm> = extract_match_case(code, stream, arm_start, hi) else {
            break;
        };
        let next_arm: usize = arm.next_arm;
        parsed.push(PendingArm {
            pattern: arm.pattern,
            guard: arm.guard,
            body_start: arm.body_start,
            next_arm,
            arm_start,
        });
        if next_arm <= arm_start {
            break;
        }
        arm_start = next_arm;
    }

    if parsed.len() < 2 {
        return Ok(None);
    }

    let wildcard_start: usize = parsed.last().map_or(hi, |a: &PendingArm| a.arm_start);
    let trailing_join: usize = parsed
        .iter()
        .take(parsed.len().saturating_sub(1))
        .flat_map(|a: &PendingArm| {
            (a.arm_start..a.next_arm.min(hi)).filter_map(|k: usize| {
                matches!(
                    stream.ops[k],
                    CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
                )
                .then(|| resolve_jump_target(stream, k, &stream.ops[k]))
                .flatten()
            })
        })
        .filter(|&t: &usize| t > wildcard_start && t <= hi)
        .max()
        .unwrap_or(hi);

    let mut cases: Vec<MatchCase> = Vec::with_capacity(parsed.len());
    for (i, arm) in parsed.iter().enumerate() {
        let raw_end: usize = if i + 1 == parsed.len() {
            trailing_join
        } else {
            arm.next_arm
        };
        let body_end: usize = raw_end.min(hi);
        let body_start: usize = arm.body_start.min(body_end);
        let body: Vec<Stmt> = if body_start < body_end {
            structure_stmts(code, stream, body_start, body_end)?
        } else {
            Vec::new()
        };
        cases.push(MatchCase {
            pattern: arm.pattern.clone(),
            guard: arm.guard.clone(),
            body: non_empty(body),
        });
    }

    if expr_references_code_const(&subject) || !cases.iter().all(case_is_plausible) {
        return Ok(None);
    }

    let cases: Vec<MatchCase> = merge_or_arms(cases);

    let mut out: Vec<Stmt> = head_stmts;
    out.push(Stmt::Match {
        subject,
        cases,
        line: None,
    });
    if trailing_join < hi {
        out.extend(structure_stmts(code, stream, trailing_join, hi)?);
    }
    Ok(Some((out, hi)))
}

fn expr_references_code_const(expr: &Expr) -> bool {
    matches!(expr, Expr::Name { id, .. } if id.starts_with(DR_CODE_CONST_PREFIX))
}

fn name_is_code_const(name: Option<&String>) -> bool {
    name.is_some_and(|n: &String| n.starts_with(DR_CODE_CONST_PREFIX))
}

fn pattern_is_plausible(pattern: &Pattern) -> bool {
    match pattern {
        Pattern::MatchValue(expr) => !expr_references_code_const(expr),
        Pattern::MatchClass { cls, .. } => !expr_references_code_const(cls),
        Pattern::MatchStar(name) => !name_is_code_const(name.as_ref()),
        Pattern::MatchAs { pattern, name } => {
            !name_is_code_const(name.as_ref())
                && pattern
                    .as_deref()
                    .is_none_or(|p: &Pattern| pattern_is_plausible(p))
        }
        Pattern::MatchOr(alts) => alts.iter().all(pattern_is_plausible),
        Pattern::MatchSequence(items) => items.iter().all(pattern_is_plausible),
        Pattern::MatchMapping { patterns, .. } => patterns.iter().all(pattern_is_plausible),
        Pattern::MatchSingleton(_) => true,
    }
}

fn case_is_plausible(case: &MatchCase) -> bool {
    pattern_is_plausible(&case.pattern)
}

fn collect_pattern_captures(p: &Pattern, out: &mut std::collections::BTreeSet<String>) {
    match p {
        Pattern::MatchValue(_) | Pattern::MatchSingleton(_) => {}
        Pattern::MatchSequence(items) => {
            for x in items {
                collect_pattern_captures(x, out);
            }
        }
        Pattern::MatchMapping { patterns, rest, .. } => {
            for x in patterns {
                collect_pattern_captures(x, out);
            }
            if let Some(r) = rest {
                out.insert(r.clone());
            }
        }
        Pattern::MatchClass {
            patterns,
            kwd_patterns,
            ..
        } => {
            for x in patterns.iter().chain(kwd_patterns.iter()) {
                collect_pattern_captures(x, out);
            }
        }
        Pattern::MatchStar(name) => {
            if let Some(n) = name {
                out.insert(n.clone());
            }
        }
        Pattern::MatchAs { pattern, name } => {
            if let Some(n) = name {
                out.insert(n.clone());
            }
            if let Some(inner) = pattern {
                collect_pattern_captures(inner, out);
            }
        }
        Pattern::MatchOr(alts) => {
            for x in alts {
                collect_pattern_captures(x, out);
            }
        }
    }
}

fn pattern_capture_set(p: &Pattern) -> std::collections::BTreeSet<String> {
    let mut s: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    collect_pattern_captures(p, &mut s);
    s
}

fn merge_or_arms(cases: Vec<MatchCase>) -> Vec<MatchCase> {
    let mut out: Vec<MatchCase> = Vec::with_capacity(cases.len());
    for case in cases {
        if let Some(last) = out.last_mut()
            && last.guard.is_none()
            && case.guard.is_none()
            && last.body == case.body
            && let Some((last_inner, last_name)) = or_mergeable_parts(&last.pattern)
            && let Some((case_inner, case_name)) = or_mergeable_parts(&case.pattern)
            && last_name == case_name
            && pattern_capture_set(&last.pattern) == pattern_capture_set(&case.pattern)
        {
            let alts: Vec<Pattern> = merge_patterns(last_inner, case_inner);
            let merged: Pattern = Pattern::MatchOr(alts);
            last.pattern = match last_name {
                Some(name) => Pattern::MatchAs {
                    pattern: Some(Box::new(merged)),
                    name: Some(name),
                },
                None => merged,
            };
            continue;
        }
        out.push(case);
    }
    out
}

fn pattern_is_or_fusable(pattern: &Pattern) -> bool {
    matches!(
        pattern,
        Pattern::MatchValue(_)
            | Pattern::MatchSingleton(_)
            | Pattern::MatchOr(_)
            | Pattern::MatchSequence(_)
            | Pattern::MatchMapping { .. }
            | Pattern::MatchClass { .. }
    )
}

fn or_mergeable_parts(pattern: &Pattern) -> Option<(Pattern, Option<String>)> {
    match pattern {
        p if pattern_is_or_fusable(p) => Some((p.clone(), None)),
        Pattern::MatchAs {
            pattern: Some(inner),
            name: Some(name),
        } if pattern_is_or_fusable(inner.as_ref()) => {
            Some((inner.as_ref().clone(), Some(name.clone())))
        }
        _ => None,
    }
}

fn merge_patterns(left: Pattern, right: Pattern) -> Vec<Pattern> {
    let mut alts: Vec<Pattern> = match left {
        Pattern::MatchOr(existing) => existing,
        other => vec![other],
    };
    match right {
        Pattern::MatchOr(more) => alts.extend(more),
        other => alts.push(other),
    }
    alts
}
