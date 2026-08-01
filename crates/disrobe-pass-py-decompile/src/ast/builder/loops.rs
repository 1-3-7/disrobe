use super::branches::{
    CondOperand, collect_value_boolop_merges, collect_value_boolop_sc, first_jump_value_lo,
    parse_cond_range,
};
use super::exprs::{build_linear_stmts_sim, is_chain_cond_jump, local_target, name_at};
use super::stmts::{
    InlineComp, collect_unpack_targets, detect_inline_comprehension, first_significant,
    last_significant_back, placeholder_target, recover_tuple_target, resolve_jump_target,
    rewrite_legacy_async_for_body, single_store_target, structure_stmts, then_terminating_jump,
};
use super::try_with::{
    LoopKind, LoopRegion, TryRegion, find_try_region, handler_chain_end, handler_join,
    is_async_cleanup_throw_back_edge, is_async_send_back_edge, is_back_edge, is_cond_back_edge,
    is_cond_jump_with_backward_target, is_forward_cond_jump, is_pure_finally_handler_shape,
    is_shortcircuit_cleanup_pop, is_simple_guard_prelude_stmt, is_value_boundary,
    is_value_form_shortcircuit, leading_guard_prelude_split, offset_is_unprotected,
    structure_for_bare_except_continue_epilogue, structure_for_typed_except_continue_epilogue,
    structure_try,
};
use super::{
    DecodedStream, LoopFrame, MAX_SYNTH_OPERANDS, PY_CO_FLAG_FUNCTION_SCOPE, ScDesc,
    StructureHiCapGuard, loop_frame_has_header, negate_cond_expr, none_jump_test, pop_loop_frame,
    push_loop_frame, with_boolop_context,
};
use crate::ast::node::{ConstValue, Expr, ExprCtx, Stmt};
use crate::bytecode::opcode::CanonicalOp;
use crate::error::Result;
use disrobe_py_marshal::CodeObject;

fn find_async_for_loop(stream: &DecodedStream, lo: usize, hi: usize) -> Option<LoopRegion> {
    let anext: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAnext))?;
    let aiter: usize = (lo..anext)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))?;
    let end_async_for: usize =
        (anext..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor))?;
    let back_edge: usize = (anext + 1..end_async_for)
        .rfind(|&k: &usize| {
            is_back_edge(&stream.ops[k])
                && !is_async_send_back_edge(stream, k)
                && !is_async_cleanup_throw_back_edge(stream, k)
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t <= anext && t >= aiter)
        })
        .unwrap_or_else(|| end_async_for.saturating_sub(1).max(anext + 1));
    let store_idx: usize = async_for_store_idx(stream, anext + 1, back_edge);
    Some(LoopRegion {
        kind: LoopKind::AsyncFor,
        header: anext,
        body_start: store_idx,
        body_end: back_edge,
        back_edge,
        exit: (end_async_for + 1).min(hi),
        infinite: false,
    })
}

pub(super) fn find_legacy_async_for_loop(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<LoopRegion> {
    let anext: usize =
        (lo..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAnext))?;
    if (anext..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::EndAsyncFor)) {
        return None;
    }
    let aiter: usize = (lo..anext)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))?;
    let (handler_start, matched, region_end): (usize, usize, usize) =
        legacy_async_for_handler(code, stream, anext + 1, hi)?;
    let store_idx: usize = async_for_store_idx(stream, anext + 1, handler_start);
    let post_store_jump: Option<usize> = (store_idx + 1..handler_start).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
        )
    });
    let inline_body_start: Option<usize> = post_store_jump.and_then(|j: usize| {
        resolve_jump_target(stream, j, &stream.ops[j])
            .filter(|t: &usize| *t > handler_start && *t < region_end)
    });
    let fallthrough_body: Option<(usize, usize)> = if inline_body_start.is_none() {
        legacy_async_for_fallthrough_body(stream, handler_start, matched, anext, aiter)
    } else {
        None
    };
    let body_start: usize = match fallthrough_body {
        Some((start, _)) => start,
        None => inline_body_start.unwrap_or(store_idx + 1),
    };
    let back_edge: usize = (body_start..region_end)
        .rfind(|&k: &usize| {
            is_back_edge(&stream.ops[k])
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t <= anext && t >= aiter)
        })
        .unwrap_or_else(|| post_store_jump.unwrap_or(handler_start));
    let body_end: usize = match (fallthrough_body, inline_body_start) {
        (Some((_, end)), _) => end,
        (None, Some(_)) => back_edge.max(body_start),
        (None, None) => handler_start.min(back_edge.max(store_idx + 1)),
    };
    Some(LoopRegion {
        kind: LoopKind::AsyncFor,
        header: anext,
        body_start,
        body_end,
        back_edge,
        exit: region_end.min(hi),
        infinite: false,
    })
}

fn legacy_async_for_fallthrough_body(
    stream: &DecodedStream,
    handler_start: usize,
    matched: usize,
    anext: usize,
    aiter: usize,
) -> Option<(usize, usize)> {
    let end_finally: usize =
        (handler_start..matched).find(|k: &usize| stream.pre311_end_finally_idx.contains(k))?;
    let body_start: usize = end_finally + 1;
    let back_edge: usize = (body_start..matched).rfind(|&k: &usize| {
        is_back_edge(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t <= anext && t >= aiter)
    })?;
    if back_edge <= body_start {
        return None;
    }
    Some((body_start, back_edge))
}

fn legacy_async_for_handler(
    code: &CodeObject,
    stream: &DecodedStream,
    anext: usize,
    hi: usize,
) -> Option<(usize, usize, usize)> {
    let dup: usize = (anext..hi).find(|&k: &usize| {
        matches!(stream.ops[k], CanonicalOp::Dup)
            && matches!(
                significant_after(stream, k + 1, hi),
                Some((
                    _,
                    CanonicalOp::LoadGlobal(_)
                        | CanonicalOp::LoadName(_)
                        | CanonicalOp::LoadFromDictOrGlobals(_),
                ))
            )
    })?;
    let (global_idx, _): (usize, &CanonicalOp) = significant_after(stream, dup + 1, hi)?;
    let name_arg: u32 = match stream.ops[global_idx] {
        CanonicalOp::LoadGlobal(i)
        | CanonicalOp::LoadName(i)
        | CanonicalOp::LoadFromDictOrGlobals(i) => i,
        _ => return None,
    };
    if name_at(&code.names, name_arg, global_idx, "name")
        .ok()
        .as_deref()
        != Some("StopAsyncIteration")
    {
        return None;
    }
    let (compare_idx, _): (usize, &CanonicalOp) = significant_after(stream, global_idx + 1, hi)?;
    if !matches!(
        stream.ops[compare_idx],
        CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
    ) {
        return None;
    }
    let (jump_idx, jump_op): (usize, &CanonicalOp) =
        significant_after(stream, compare_idx + 1, hi)?;
    if !matches!(
        jump_op,
        CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
    ) {
        return None;
    }
    let matched: usize = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
        .filter(|t: &usize| *t > jump_idx && *t <= hi)?;
    Some((dup, matched, skip_async_for_cleanup(stream, matched, hi)))
}

fn skip_async_for_cleanup(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi
        && matches!(
            stream.ops[i],
            CanonicalOp::Pop | CanonicalOp::PopExcept | CanonicalOp::Nop | CanonicalOp::Cache
        )
    {
        if matches!(stream.ops[i], CanonicalOp::Nop) && opens_protected_region(stream, i) {
            break;
        }
        i += 1;
    }
    i
}

fn significant_after(
    stream: &DecodedStream,
    from: usize,
    hi: usize,
) -> Option<(usize, &CanonicalOp)> {
    (from..hi)
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
            )
        })
        .map(|k: usize| (k, &stream.ops[k]))
}

fn async_for_store_idx(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let terminal: Option<usize> = (from..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreFastStoreFast(_, _)
                | CanonicalOp::UnpackSequence(_)
                | CanonicalOp::UnpackEx(_)
                | CanonicalOp::BuildTuple(_)
                | CanonicalOp::StoreAttr(_)
                | CanonicalOp::StoreSubscr
                | CanonicalOp::StoreSlice
        )
    });
    let Some(store): Option<usize> = terminal else {
        return from;
    };
    match stream.ops[store] {
        CanonicalOp::StoreAttr(_) | CanonicalOp::StoreSubscr | CanonicalOp::StoreSlice => (from
            ..store)
            .rev()
            .find(|&k: &usize| {
                is_value_boundary(&stream.ops[k])
                    || matches!(
                        stream.ops[k],
                        CanonicalOp::YieldFrom
                            | CanonicalOp::EndSend
                            | CanonicalOp::Send(_)
                            | CanonicalOp::GetAnext
                    )
            })
            .map_or(from, |b: usize| b + 1),
        _ => store,
    }
}

fn has_for_iter(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| matches!(stream.ops[k], CanonicalOp::ForIter(_)))
}

fn has_loop_entry_gate(stream: &DecodedStream, lo: usize, header: usize) -> bool {
    let Some(prev): Option<usize> = (lo..header).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    is_forward_cond_jump(&stream.ops[prev])
        && !is_chain_cond_jump(&stream.ops, prev)
        && resolve_jump_target(stream, prev, &stream.ops[prev]).is_some_and(|t: usize| t > header)
}

fn find_infinite_while(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    allow_inline_break: bool,
) -> Option<LoopRegion> {
    for header in lo..hi {
        if matches!(
            stream.ops[header],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) {
            continue;
        }
        let back_edge: Option<usize> = (header + 1..hi).find(|&j: &usize| {
            is_back_edge(&stream.ops[j])
                && !is_async_send_back_edge(stream, j)
                && !is_async_cleanup_throw_back_edge(stream, j)
                && !back_edge_inside_exc_handler_cold_block(stream, header, j)
                && resolve_jump_target(stream, j, &stream.ops[j]) == Some(header)
        });
        let Some(back_edge): Option<usize> = back_edge else {
            continue;
        };
        if loop_frame_has_header(header) {
            continue;
        }
        if has_loop_entry_gate(stream, lo, header) {
            continue;
        }
        if allow_inline_break
            && let Some(exit) = infinite_inline_break_exit(stream, header, back_edge, hi)
        {
            return Some(LoopRegion {
                kind: LoopKind::While,
                header,
                body_start: header,
                body_end: back_edge,
                back_edge,
                exit,
                infinite: true,
            });
        }
        if loop_has_jump_exit(stream, header, back_edge, hi)
            && !infinite_while_only_break_exits(stream, header, back_edge, hi)
        {
            continue;
        }
        if back_edge_reenters_for_iter(stream, header, back_edge) {
            continue;
        }
        if back_edge_inside_exc_handler_cold_block(stream, header, back_edge) {
            continue;
        }
        return Some(LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: back_edge,
            back_edge,
            exit: (back_edge + 1).min(hi),
            infinite: true,
        });
    }
    None
}

fn back_edge_inside_exc_handler_cold_block(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
) -> bool {
    if stream.is_pre_311() {
        return false;
    }
    let Some(handler_start): Option<usize> = (header + 1..=back_edge)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
    else {
        return false;
    };
    let handler_off: u32 = match stream.offsets.get(handler_start) {
        Some(&o) => o,
        None => return false,
    };
    stream
        .exception_table
        .iter()
        .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| e.target == handler_off)
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            stream
                .index_for_offset(e.start)
                .is_some_and(|try_start: usize| try_start < header)
        })
}

fn back_edge_reenters_for_iter(stream: &DecodedStream, header: usize, back_edge: usize) -> bool {
    let Some(target): Option<usize> =
        resolve_jump_target(stream, back_edge, &stream.ops[back_edge])
    else {
        return false;
    };
    (header..back_edge).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) && target <= k
            && !(target..k).any(|g: usize| matches!(stream.ops[g], CanonicalOp::GetIter))
    })
}

fn infinite_inline_break_exit(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    hi: usize,
) -> Option<usize> {
    let first_cond: usize = (header..back_edge).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    let body_label: usize = resolve_jump_target(stream, first_cond, &stream.ops[first_cond])
        .filter(|t: &usize| *t > first_cond && *t < back_edge)?;
    let block_start: usize = first_significant(stream, first_cond + 1, body_label)?;
    if block_start >= body_label
        || !block_breaks_loop(stream, block_start, body_label, back_edge, hi)
    {
        return None;
    }
    if (block_start..body_label)
        .any(|k: usize| is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k))
    {
        return None;
    }
    Some(infinite_break_exit(
        stream,
        block_start,
        body_label,
        back_edge,
        hi,
    ))
}

fn loop_has_jump_exit(stream: &DecodedStream, header: usize, back_edge: usize, hi: usize) -> bool {
    (header..back_edge).any(|k: usize| {
        let exits: bool = match &stream.ops[k] {
            op if is_forward_cond_jump(op) => !is_chain_cond_jump(&stream.ops, k),
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => true,
            _ => false,
        };
        exits
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t >= back_edge && t <= hi)
    })
}

fn infinite_while_only_break_exits(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    hi: usize,
) -> bool {
    if is_cond_back_edge(&stream.ops[back_edge]) {
        return false;
    }
    if !loop_body_wraps_try_or_for(stream, header, back_edge, hi) {
        return false;
    }
    let Some(first_cond): Option<usize> = (header..back_edge).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return false;
    };
    if !(header..first_cond).any(|k: usize| completes_body_stmt(stream, k)) {
        return false;
    }
    !(header..back_edge).any(|k: usize| {
        let is_exit_jump: bool = match &stream.ops[k] {
            op if is_forward_cond_jump(op) => !is_chain_cond_jump(&stream.ops, k),
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => true,
            _ => false,
        };
        is_exit_jump
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > back_edge && t <= hi)
    })
}

fn loop_body_wraps_try_or_for(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    hi: usize,
) -> bool {
    if (header..back_edge).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        )
    }) {
        return true;
    }
    stream
        .exception_table
        .iter()
        .any(|entry: &crate::bytecode::flow::ExceptionTableEntry| {
            let (Some(try_start), Some(handler_start)): (Option<usize>, Option<usize>) = (
                stream.index_for_offset(entry.start),
                stream.index_for_offset(entry.target),
            ) else {
                return false;
            };
            try_start >= header
                && try_start < back_edge
                && handler_start >= back_edge
                && handler_start <= hi
        })
}

fn infinite_break_exit(
    stream: &DecodedStream,
    lo: usize,
    hi_block: usize,
    back_edge: usize,
    hi: usize,
) -> usize {
    let only_jump: bool = (lo..hi_block).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
        )
    });
    if only_jump
        && let Some(t) = resolve_jump_target(stream, lo, &stream.ops[lo])
        && t > back_edge
        && t <= hi
    {
        return t;
    }
    lo
}

fn block_breaks_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    back_edge: usize,
    cap: usize,
) -> bool {
    let terminal: Option<usize> = (lo..hi).rev().find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
        )
    });
    terminal.is_some_and(|idx: usize| match &stream.ops[idx] {
        CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_) => {
            resolve_jump_target(stream, idx, &stream.ops[idx])
                .is_some_and(|t: usize| t > back_edge && t <= cap)
        }
        _ => false,
    })
}

pub(super) fn leading_guard_if_encloses_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> bool {
    (lo..region.header).any(|guard: usize| {
        is_forward_cond_jump(&stream.ops[guard])
            && !is_chain_cond_jump(&stream.ops, guard)
            && !is_value_form_shortcircuit(&stream.ops, guard)
            && resolve_jump_target(stream, guard, &stream.ops[guard])
                .is_some_and(|t: usize| t > region.header && t > region.exit && t <= hi)
    })
}

pub(super) fn loop_is_else_arm_of_leading_if(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> bool {
    if region.exit > hi {
        return false;
    }
    (lo..region.header).any(|guard: usize| {
        if !is_forward_cond_jump(&stream.ops[guard])
            || is_chain_cond_jump(&stream.ops, guard)
            || is_value_form_shortcircuit(&stream.ops, guard)
        {
            return false;
        }
        let Some(cond_target): Option<usize> =
            resolve_jump_target(stream, guard, &stream.ops[guard])
        else {
            return false;
        };
        if cond_target <= guard || cond_target > region.header {
            return false;
        }
        let Some(then_jump): Option<usize> = then_terminating_jump(stream, guard + 1, cond_target)
        else {
            return false;
        };
        resolve_jump_target(stream, then_jump, &stream.ops[then_jump])
            .is_some_and(|t: usize| t >= region.exit && t <= hi)
    })
}

pub(super) fn leading_cond_arm_holds_loop(
    stream: &DecodedStream,
    lo: usize,
    region: &LoopRegion,
) -> bool {
    if !matches!(region.kind, LoopKind::For | LoopKind::AsyncFor) {
        return false;
    }
    (lo..region.header).any(|guard: usize| {
        if !is_forward_cond_jump(&stream.ops[guard])
            || is_chain_cond_jump(&stream.ops, guard)
            || is_value_form_shortcircuit(&stream.ops, guard)
        {
            return false;
        }
        let Some(target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        else {
            return false;
        };
        if target <= guard || target > region.header {
            return false;
        }
        let false_fall: usize = guard + 1;
        let only_continue: bool = (false_fall..target).all(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::Push(_)
            ) || is_continue_back_edge(stream, k)
        });
        let has_continue: bool =
            (false_fall..target).any(|k: usize| is_continue_back_edge(stream, k));
        let setup_only: bool = (target..region.header)
            .all(|k: usize| !is_forward_cond_jump(&stream.ops[k]) && !is_back_edge(&stream.ops[k]))
            && matches!(
                stream.ops.get(region.header.saturating_sub(1)),
                Some(CanonicalOp::GetIter | CanonicalOp::GetAiter)
            );
        let no_enclosing_loop_in_region: bool = !(lo..region.header).any(|k: usize| {
            (is_back_edge(&stream.ops[k])
                || is_cond_back_edge(&stream.ops[k])
                || is_cond_jump_with_backward_target(stream, k))
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t >= lo && t < region.header)
        });
        only_continue && has_continue && setup_only && no_enclosing_loop_in_region
    })
}

fn is_continue_back_edge(stream: &DecodedStream, idx: usize) -> bool {
    is_back_edge(&stream.ops[idx])
        && resolve_jump_target(stream, idx, &stream.ops[idx])
            .is_some_and(|t: usize| t < idx && loop_frame_has_header(t))
}

fn back_edge_targets_at_or_before(
    stream: &DecodedStream,
    from: usize,
    to: usize,
    bound: usize,
) -> bool {
    (from..to.min(stream.ops.len())).any(|k: usize| {
        (is_back_edge(&stream.ops[k])
            || is_cond_back_edge(&stream.ops[k])
            || is_cond_jump_with_backward_target(stream, k))
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t <= bound)
    })
}

pub(super) fn loop_structure_guarded_loop(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) != PY_CO_FLAG_FUNCTION_SCOPE {
        return Ok(None);
    }
    let mut guard_lo: usize = lo;
    let mut chosen: Option<(usize, usize, usize, usize, LoopRegion)> = None;
    while let Some(guard) = (guard_lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    }) {
        guard_lo = guard + 1;
        let Some(prior_split): Option<usize> = leading_guard_prelude_split(stream, lo, guard)
        else {
            return Ok(None);
        };
        let Some(false_target): Option<usize> =
            resolve_jump_target(stream, guard, &stream.ops[guard])
                .filter(|t: &usize| *t > guard && *t < hi)
        else {
            continue;
        };
        let after_guard: usize = match first_significant(stream, guard + 1, false_target) {
            Some(idx) => idx,
            None => continue,
        };
        let Some(region): Option<LoopRegion> = find_loop(stream, after_guard, false_target) else {
            continue;
        };
        let guard_unprotected: bool = stream
            .offsets
            .get(guard)
            .copied()
            .is_some_and(|off: u32| offset_is_unprotected(stream, off));
        if region.exit != false_target
            || region.header <= guard
            || !guarded_loop_is_top_tested_or_empty_body(stream, &region)
            || !guard_unprotected
            || !is_back_edge(&stream.ops[region.back_edge])
            || back_edge_targets_at_or_before(stream, guard + 1, false_target, guard)
            || guard_opens_with_branch(stream, after_guard, &region)
        {
            continue;
        }
        chosen = Some((guard, prior_split, after_guard, false_target, region));
        break;
    }
    let Some((guard, prior_split, after_guard, false_target, region)): Option<(
        usize,
        usize,
        usize,
        usize,
        LoopRegion,
    )> = chosen
    else {
        return Ok(None);
    };
    let mut prior: Vec<Stmt> = structure_stmts(code, stream, lo, prior_split)?;
    if !prior.iter().all(is_simple_guard_prelude_stmt) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[prior_split..guard])?;
    if residual.len() != 1 {
        return Ok(None);
    }
    prior.extend(head);
    let Some(raw_test): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    let is_none_jump: bool = stream.none_jump_kind.contains_key(&guard);
    let test: Expr = none_jump_test(stream, guard, raw_test.clone()).unwrap_or(raw_test);
    let test: Expr = if is_none_jump
        || matches!(
            stream.ops[guard],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        ) {
        test
    } else {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    };
    let if_body: Vec<Stmt> = structure_loop(code, stream, after_guard, false_target, &region)?;
    let tail: Vec<Stmt> = structure_stmts(code, stream, false_target, hi)?;
    let mut out: Vec<Stmt> = prior;
    if guard_matches_enclosed_while(&if_body, &test) {
        out.extend(if_body);
        out.extend(tail);
        return Ok(Some(out));
    }
    out.push(Stmt::If {
        test,
        body: non_empty(if_body),
        orelse: Vec::new(),
        line: None,
    });
    out.extend(tail);
    Ok(Some(out))
}

pub(super) fn guard_matches_enclosed_while(if_body: &[Stmt], guard_test: &Expr) -> bool {
    let Some((first, rest)): Option<(&Stmt, &[Stmt])> = if_body.split_first() else {
        return false;
    };
    let Stmt::While {
        test: while_test,
        orelse,
        ..
    } = first
    else {
        return false;
    };
    orelse.is_empty()
        && exprs_equal_ignoring_lines(while_test, guard_test)
        && rest.iter().all(is_simple_loop_epilogue_stmt)
}

fn is_simple_loop_epilogue_stmt(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Return(_) | Stmt::Continue | Stmt::Break | Stmt::Pass
    )
}

struct LineStripper;

impl crate::ast::visitor::VisitorMut for LineStripper {
    fn visit_expr_mut(&mut self, expr: &mut Expr) {
        match expr {
            Expr::Constant { line, .. }
            | Expr::Name { line, .. }
            | Expr::FormattedValue { line, .. }
            | Expr::JoinedStr { line, .. }
            | Expr::TStr { line, .. } => *line = None,
            _ => {}
        }
        crate::ast::visitor::walk_expr_mut(self, expr);
    }
}

fn exprs_equal_ignoring_lines(a: &Expr, b: &Expr) -> bool {
    use crate::ast::visitor::VisitorMut as _;
    let mut sa: Expr = a.clone();
    let mut sb: Expr = b.clone();
    let mut stripper: LineStripper = LineStripper;
    stripper.visit_expr_mut(&mut sa);
    stripper.visit_expr_mut(&mut sb);
    sa == sb
}

fn guard_opens_with_branch(
    stream: &DecodedStream,
    after_guard: usize,
    region: &LoopRegion,
) -> bool {
    (after_guard..region.header).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    })
}

fn guarded_loop_is_top_tested_or_empty_body(stream: &DecodedStream, region: &LoopRegion) -> bool {
    if region.body_start > region.header {
        return true;
    }
    let Some(bottom): Option<usize> = (region.header..region.back_edge).rev().find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]) == Some(region.exit)
    }) else {
        return false;
    };
    let value_start: usize = cond_expr_start(stream, bottom, region.header);
    !(region.header..value_start).any(|k: usize| completes_body_stmt(stream, k))
}

fn inline_comp_envelopes(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<(usize, usize)> {
    let mut envelopes: Vec<(usize, usize)> = Vec::new();
    let mut cursor: usize = lo;
    while cursor < hi {
        let Some(comp): Option<InlineComp> = detect_inline_comprehension(stream, cursor, hi) else {
            break;
        };
        if comp.end_for <= comp.clear_idx {
            break;
        }
        envelopes.push((comp.clear_idx, comp.end_for));
        cursor = comp.end_for;
    }
    envelopes
}

#[inline]
fn in_any_envelope(envelopes: &[(usize, usize)], idx: usize) -> bool {
    envelopes
        .iter()
        .any(|&(start, end): &(usize, usize)| idx >= start && idx < end)
}

fn max_back_edge_to_header(stream: &DecodedStream, header: usize, lo: usize, hi: usize) -> usize {
    (lo..hi.min(stream.ops.len()))
        .rev()
        .find(|&k: &usize| {
            is_back_edge(&stream.ops[k])
                && !is_async_send_back_edge(stream, k)
                && !is_async_cleanup_throw_back_edge(stream, k)
                && !back_edge_inside_exc_handler_cold_block(stream, header, k)
                && resolve_jump_target(stream, k, &stream.ops[k]) == Some(header)
        })
        .unwrap_or(header)
}

fn is_generator_stopiteration_terminal(
    stream: &DecodedStream,
    handler_start: usize,
    cap: usize,
) -> bool {
    let mut i: usize = handler_start;
    while i < cap
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        i += 1;
    }
    if !matches!(stream.ops.get(i), Some(CanonicalOp::CallIntrinsic1(3))) {
        return false;
    }
    i += 1;
    while i < cap
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        i += 1;
    }
    matches!(stream.ops.get(i), Some(CanonicalOp::Reraise(_)))
}

fn infinite_while_body_end(
    stream: &DecodedStream,
    header: usize,
    first_back_edge: usize,
    hi: usize,
) -> usize {
    let cap: usize = hi.min(stream.ops.len());
    let mut end: usize = first_back_edge.min(cap);
    loop {
        let mut grew: bool = false;
        for entry in &stream.exception_table {
            let Some(try_start): Option<usize> = stream.index_for_offset(entry.start) else {
                continue;
            };
            let Some(handler_start): Option<usize> = stream.index_for_offset(entry.target) else {
                continue;
            };
            if try_start < header || try_start >= end || handler_start < end || handler_start >= cap
            {
                continue;
            }
            if is_generator_stopiteration_terminal(stream, handler_start, cap) {
                continue;
            }
            let handler_end: usize =
                handler_join(stream, handler_start, cap).max(handler_start + 1);
            if handler_wraps_loop_header(stream, entry.target, header)
                && is_pure_finally_handler_shape(
                    stream,
                    handler_start,
                    handler_end,
                    stream.is_pre_311(),
                )
            {
                continue;
            }
            if handler_end > end {
                end = handler_end;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    end
}

fn handler_wraps_loop_header(stream: &DecodedStream, handler_offset: u32, header: usize) -> bool {
    stream
        .exception_table
        .iter()
        .any(|sibling: &crate::bytecode::flow::ExceptionTableEntry| {
            sibling.target == handler_offset
                && stream
                    .index_for_offset(sibling.start)
                    .is_some_and(|sibling_ts: usize| sibling_ts <= header)
        })
}

fn handler_encloses_loop(stream: &DecodedStream, handler_offset: u32, body_start: usize) -> bool {
    stream
        .exception_table
        .iter()
        .any(|sibling: &crate::bytecode::flow::ExceptionTableEntry| {
            sibling.target == handler_offset
                && stream
                    .index_for_offset(sibling.start)
                    .is_some_and(|sibling_ts: usize| sibling_ts < body_start)
        })
}

fn first_cold_for_handler(
    stream: &DecodedStream,
    body_start: usize,
    raw_exit: usize,
    cap: usize,
) -> Option<usize> {
    stream
        .exception_table
        .iter()
        .filter_map(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            let ts: usize = stream.index_for_offset(e.start)?;
            let hs: usize = stream.index_for_offset(e.target)?;
            if ts < body_start
                || ts >= raw_exit
                || hs < raw_exit
                || hs >= cap
                || !matches!(stream.ops.get(hs), Some(CanonicalOp::PushExcInfo))
                || handler_encloses_loop(stream, e.target, body_start)
            {
                return None;
            }
            Some(hs)
        })
        .min()
}

fn find_for_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    comp_envelopes: &[(usize, usize)],
) -> Option<LoopRegion> {
    for header in lo..hi {
        if !matches!(
            stream.ops[header],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) || in_any_envelope(comp_envelopes, header)
        {
            continue;
        }
        let Some(raw_exit): Option<usize> =
            resolve_jump_target(stream, header, &stream.ops[header])
                .filter(|target: &usize| *target > header)
        else {
            continue;
        };
        let back_edge: usize = (header + 1..hi)
            .filter(|&candidate: &usize| is_back_edge(&stream.ops[candidate]))
            .find(|&candidate: &usize| {
                resolve_jump_target(stream, candidate, &stream.ops[candidate])
                    .is_some_and(|target: usize| target <= header)
            })
            .unwrap_or_else(|| raw_exit.min(hi).saturating_sub(1).max(header + 1));
        let exit_via_foriter: usize = raw_exit.min(hi).max((back_edge + 1).min(hi));
        let body_start: usize = (header + 1).min(hi);
        let absorbed_end: usize =
            for_body_end_absorbing_cold_handlers(stream, body_start, raw_exit, hi);
        let body_end: usize = exit_via_foriter.max(absorbed_end);
        let region: LoopRegion = LoopRegion {
            kind: LoopKind::For,
            header,
            body_start,
            body_end,
            back_edge,
            exit: body_end,
            infinite: false,
        };
        if loop_enclosed_by_guard(stream, lo, &region)
            && (has_earlier_while_back_edge(stream, lo, header)
                || for_enclosed_by_later_while_back_edge(stream, lo, hi, &region))
        {
            continue;
        }
        return Some(region);
    }
    None
}

pub(super) fn find_for_with_cold_handler(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    handler_cap: usize,
) -> Option<LoopRegion> {
    let comp_envelopes: Vec<(usize, usize)> = inline_comp_envelopes(stream, lo, hi);
    let mut next_header: usize = lo;
    while next_header < hi {
        let region: LoopRegion = find_for_loop(stream, next_header, hi, &comp_envelopes)?;
        let raw_exit: Option<usize> =
            resolve_jump_target(stream, region.header, &stream.ops[region.header])
                .filter(|exit: &usize| region.header < *exit && *exit <= hi);
        if raw_exit.is_some_and(|exit: usize| {
            first_cold_for_handler(stream, region.body_start, exit, handler_cap).is_some()
        }) {
            return Some(region);
        }
        next_header = region.header.saturating_add(1);
    }
    None
}

pub(super) fn for_cold_handler_exit_epilogue(
    stream: &DecodedStream,
    body_start: usize,
    raw_exit: usize,
    hi: usize,
) -> Option<(usize, usize)> {
    if stream.is_pre_311() || stream.exception_table.is_empty() {
        return None;
    }
    let cap: usize = hi.min(stream.ops.len());
    let start: usize = raw_exit.min(cap);
    let first_cold: usize = first_cold_for_handler(stream, body_start, start, cap)?;
    let stmt_start: usize = (start..first_cold).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Pop | CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    })?;
    (stmt_start < first_cold).then_some((stmt_start, first_cold))
}

fn epilogue_absent_from_body(body: &[Stmt], tail: &[Stmt]) -> bool {
    matches!(tail.last(), Some(Stmt::Return(_) | Stmt::Raise { .. }))
        && !matches!(
            body.last(),
            Some(Stmt::Return(_) | Stmt::Raise { .. }) | None
        )
}

fn lift_cold_handler_exit_epilogue(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    body_start: usize,
    body: &mut Vec<Stmt>,
    body_bounded_at_raw_exit: bool,
) -> Result<Vec<Stmt>> {
    let raw_exit: Option<usize> =
        resolve_jump_target(stream, region.header, &stream.ops[region.header])
            .filter(|t: &usize| *t > region.header);
    let Some(raw_exit): Option<usize> = raw_exit else {
        return Ok(Vec::new());
    };
    let Some((stmt_start, first_cold)): Option<(usize, usize)> =
        for_cold_handler_exit_epilogue(stream, body_start, raw_exit, region.body_end)
    else {
        return Ok(Vec::new());
    };
    let tail: Vec<Stmt> = structure_stmts(code, stream, stmt_start, first_cold)?;
    if tail.is_empty() {
        return Ok(Vec::new());
    }
    let body_breaks_to_epilogue: bool = last_significant_back(stream, body_start, raw_exit)
        .is_some_and(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
            ) && resolve_jump_target(stream, k, &stream.ops[k]) == Some(stmt_start)
        });
    if body_bounded_at_raw_exit {
        if body_breaks_to_epilogue
            && !matches!(
                body.last(),
                Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
            )
        {
            body.push(Stmt::Break);
        }
        return Ok(tail);
    }
    if tail.len() <= body.len() {
        let split: usize = body.len() - tail.len();
        if body[split..] == tail[..] {
            body.truncate(split);
            if body_breaks_to_epilogue
                && !matches!(
                    body.last(),
                    Some(Stmt::Break | Stmt::Continue | Stmt::Return(_) | Stmt::Raise { .. })
                )
            {
                body.push(Stmt::Break);
            }
            return Ok(tail);
        }
    }
    if epilogue_absent_from_body(body, &tail) {
        return Ok(tail);
    }
    Ok(Vec::new())
}

fn structure_for_body(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    body_start: usize,
) -> Result<(Vec<Stmt>, Vec<Stmt>)> {
    let raw_exit: usize = resolve_jump_target(stream, region.header, &stream.ops[region.header])
        .filter(|target: &usize| *target > region.header)
        .map_or(region.body_end, |target: usize| target.min(region.body_end));
    let has_cold_extension: bool = region.body_end > raw_exit;
    let nested_for_has_cold_handler: bool =
        find_for_with_cold_handler(stream, body_start, raw_exit, region.body_end).is_some();
    let body_bounded_at_raw_exit: bool = has_cold_extension && nested_for_has_cold_handler;
    let _handler_cap: Option<StructureHiCapGuard> =
        body_bounded_at_raw_exit.then(|| StructureHiCapGuard::enter(region.body_end));
    let except_continue: Option<(Vec<Stmt>, Vec<Stmt>)> =
        match structure_for_bare_except_continue_epilogue(code, stream, region, body_start)? {
            Some(value) => Some(value),
            None => structure_for_typed_except_continue_epilogue(code, stream, region, body_start)?,
        };
    if let Some(result) = except_continue {
        return Ok(result);
    }
    let body_end: usize = if body_bounded_at_raw_exit {
        raw_exit
    } else {
        region.body_end
    };
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
    let epilogue: Vec<Stmt> = lift_cold_handler_exit_epilogue(
        code,
        stream,
        region,
        body_start,
        &mut body,
        body_bounded_at_raw_exit,
    )?;
    Ok((body, epilogue))
}

fn for_body_end_absorbing_cold_handlers(
    stream: &DecodedStream,
    body_start: usize,
    raw_exit: usize,
    hi: usize,
) -> usize {
    if stream.is_pre_311() || stream.exception_table.is_empty() {
        return raw_exit;
    }
    let cap: usize = hi.min(stream.ops.len());
    let start: usize = raw_exit.min(cap);
    if first_cold_for_handler(stream, body_start, start, cap).is_none() {
        return raw_exit;
    }
    let mut end: usize = start;
    loop {
        let mut grew: bool = false;
        for entry in &stream.exception_table {
            let (Some(ts), Some(hs)): (Option<usize>, Option<usize>) = (
                stream.index_for_offset(entry.start),
                stream.index_for_offset(entry.target),
            ) else {
                continue;
            };
            if ts < body_start
                || ts >= end
                || hs < end
                || hs >= cap
                || !matches!(stream.ops.get(hs), Some(CanonicalOp::PushExcInfo))
                || handler_encloses_loop(stream, entry.target, body_start)
            {
                continue;
            }
            let absorbed_end: usize = handler_chain_end(stream, hs, cap)
                .unwrap_or_else(|| handler_join(stream, hs, cap).max(hs + 1));
            if absorbed_end > end {
                end = absorbed_end;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    end
}

fn has_earlier_while_back_edge(stream: &DecodedStream, lo: usize, before: usize) -> bool {
    (lo..before.min(stream.ops.len())).any(|j: usize| {
        (is_back_edge(&stream.ops[j])
            || is_cond_back_edge(&stream.ops[j])
            || is_cond_jump_with_backward_target(stream, j))
            && resolve_jump_target(stream, j, &stream.ops[j])
                .is_some_and(|t: usize| t >= lo && t < before)
    })
}

fn for_enclosed_by_later_while_back_edge(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> bool {
    (region.back_edge + 1..hi.min(stream.ops.len())).any(|j: usize| {
        is_back_edge(&stream.ops[j])
            && !is_async_send_back_edge(stream, j)
            && !is_async_cleanup_throw_back_edge(stream, j)
            && resolve_jump_target(stream, j, &stream.ops[j]).is_some_and(|outer_header: usize| {
                outer_header >= lo
                    && outer_header < region.header
                    && (outer_header..region.header).any(|k: usize| {
                        is_forward_cond_jump(&stream.ops[k])
                            && !is_chain_cond_jump(&stream.ops, k)
                            && resolve_jump_target(stream, k, &stream.ops[k])
                                .is_some_and(|t: usize| t > j)
                    })
            })
    })
}

fn completes_body_stmt(stream: &DecodedStream, idx: usize) -> bool {
    match &stream.ops[idx] {
        CanonicalOp::StoreFast(_)
        | CanonicalOp::StoreName(_)
        | CanonicalOp::StoreGlobal(_)
        | CanonicalOp::StoreFastStoreFast(_, _) => !is_walrus_store_shape(&stream.ops, idx),
        CanonicalOp::StoreAttr(_)
        | CanonicalOp::StoreSubscr
        | CanonicalOp::StoreSlice
        | CanonicalOp::UnpackSequence(_)
        | CanonicalOp::UnpackEx(_) => true,
        CanonicalOp::Pop => !is_shortcircuit_cleanup_pop(stream, idx),
        _ => false,
    }
}

fn has_entry_guard_to_exit(stream: &DecodedStream, lo: usize, header: usize, exit: usize) -> bool {
    let Some(prev): Option<usize> = (lo..header).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    is_forward_cond_jump(&stream.ops[prev])
        && !is_chain_cond_jump(&stream.ops, prev)
        && resolve_jump_target(stream, prev, &stream.ops[prev]) == Some(exit)
}

fn unconditional_back_edge_is_infinite(
    stream: &DecodedStream,
    lo: usize,
    header: usize,
    back_edge: usize,
    conds: &[usize],
) -> bool {
    let Some(&first_cond): Option<&usize> = conds.first() else {
        return false;
    };
    let pre_314: bool = stream.version.major() == 3 && stream.version.minor() <= 13;
    if pre_314
        && conds
            .last()
            .copied()
            .is_some_and(|c: usize| is_bottom_test(stream, c, back_edge))
    {
        return false;
    }
    let exit: Option<usize> = resolve_jump_target(stream, first_cond, &stream.ops[first_cond]);
    if exit.is_some_and(|e: usize| has_entry_guard_to_exit(stream, lo, header, e)) {
        return false;
    }
    (header..first_cond).any(|k: usize| completes_body_stmt(stream, k))
}

fn legacy_guarded_continue_region(
    stream: &DecodedStream,
    header: usize,
    early_back_edge: usize,
    hi: usize,
    conds: &[usize],
) -> Option<LoopRegion> {
    if !stream.is_pre_311() || conds.len() < 2 {
        return None;
    }
    let first_exit: usize = resolve_jump_target(stream, conds[0], &stream.ops[conds[0]])
        .filter(|target: &usize| *target > early_back_edge)?;
    if first_exit > hi {
        return None;
    }
    for &nested_cond in &conds[1..] {
        if nested_cond >= early_back_edge || is_value_form_shortcircuit(&stream.ops, nested_cond) {
            continue;
        }
        let reentry: usize = first_jump_value_lo(stream, conds[0] + 1, nested_cond);
        if reentry <= header {
            continue;
        }
        let false_entry: usize =
            resolve_jump_target(stream, nested_cond, &stream.ops[nested_cond])?;
        if false_entry <= early_back_edge {
            continue;
        }
        for latch in early_back_edge + 1..first_exit {
            if !(is_cond_back_edge(&stream.ops[latch])
                || is_cond_jump_with_backward_target(stream, latch))
                || resolve_jump_target(stream, latch, &stream.ops[latch]) != Some(reentry)
            {
                continue;
            }
            let bottom_start: usize = bottom_test_span_start(stream, header, latch);
            if false_entry >= bottom_start
                || !(false_entry..bottom_start).any(|k: usize| completes_body_stmt(stream, k))
                || (bottom_start..=latch).any(|k: usize| completes_body_stmt(stream, k))
            {
                continue;
            }
            return Some(LoopRegion {
                kind: LoopKind::While,
                header,
                body_start: reentry,
                body_end: bottom_start,
                back_edge: latch,
                exit: first_exit.min(hi),
                infinite: false,
            });
        }
    }
    None
}

pub(super) fn find_loop(stream: &DecodedStream, lo: usize, hi: usize) -> Option<LoopRegion> {
    if let Some(region) = find_async_for_loop(stream, lo, hi) {
        return Some(region);
    }
    if let Some(region) = find_infinite_while(stream, lo, hi, !has_for_iter(stream, lo, hi)) {
        return Some(region);
    }
    let comp_envelopes: Vec<(usize, usize)> = inline_comp_envelopes(stream, lo, hi);
    let for_region: Option<LoopRegion> = find_for_loop(stream, lo, hi, &comp_envelopes);
    if for_region.is_some() {
        return for_region;
    }
    let mut best: Option<LoopRegion> = None;
    for j in lo..hi {
        if in_any_envelope(&comp_envelopes, j) {
            continue;
        }
        if (is_cond_back_edge(&stream.ops[j]) || is_cond_jump_with_backward_target(stream, j))
            && let Some(t) = resolve_jump_target(stream, j, &stream.ops[j])
            && t >= lo
            && t < j
        {
            let header: usize = t;
            let back_edge: usize = last_cond_back_edge_in_run(stream, j, header, hi);
            let exit: usize = (back_edge + 1).min(hi);
            let region: LoopRegion = LoopRegion {
                kind: LoopKind::While,
                header,
                body_start: header,
                body_end: bottom_test_start(stream, j, header, exit)
                    .min(bottom_test_span_start(stream, header, back_edge))
                    .max(terminator_floor(stream, header, back_edge)),
                back_edge,
                exit,
                infinite: false,
            };
            if best.is_none_or(|b: LoopRegion| header < b.header) {
                best = Some(region);
            }
            continue;
        }
        if is_back_edge(&stream.ops[j])
            && let Some(t) = resolve_jump_target(stream, j, &stream.ops[j])
            && t >= lo
            && t < j
        {
            if is_async_send_back_edge(stream, j)
                || is_async_cleanup_throw_back_edge(stream, j)
                || back_edge_inside_exc_handler_cold_block(stream, t, j)
            {
                continue;
            }
            let header: usize = t;
            let back_edge: usize = max_back_edge_to_header(stream, header, lo, hi);
            if back_edge != j {
                continue;
            }
            let conds: Vec<usize> = (header..back_edge)
                .filter(|&k: &usize| {
                    is_forward_cond_jump(&stream.ops[k])
                        && !is_chain_cond_jump(&stream.ops, k)
                        && resolve_jump_target(stream, k, &stream.ops[k])
                            .is_some_and(|tt: usize| tt > back_edge)
                })
                .collect();
            let region: LoopRegion =
                legacy_guarded_continue_region(stream, header, back_edge, hi, &conds)
                    .unwrap_or_else(|| {
                        if unconditional_back_edge_is_infinite(
                            stream, lo, header, back_edge, &conds,
                        ) {
                            let legacy_exit: usize = conds
                                .first()
                                .and_then(|&c: &usize| {
                                    resolve_jump_target(stream, c, &stream.ops[c])
                                })
                                .filter(|&t: &usize| t > back_edge)
                                .unwrap_or_else(|| (back_edge + 1).min(hi));
                            let exit: usize =
                                infinite_loop_reach_exit(stream, header, legacy_exit, lo, hi)
                                    .min(hi);
                            LoopRegion {
                                kind: LoopKind::While,
                                header,
                                body_start: header,
                                body_end: back_edge,
                                back_edge,
                                exit: exit.min(hi),
                                infinite: true,
                            }
                        } else {
                            let bottom_cond: Option<usize> = conds
                                .last()
                                .copied()
                                .filter(|&c: &usize| is_bottom_test(stream, c, back_edge));
                            let effective: Vec<usize> = if bottom_cond.is_some() {
                                conds.clone()
                            } else {
                                top_test_run(stream, &conds, header)
                            };
                            while_region(stream, header, back_edge, hi, &effective, bottom_cond)
                        }
                    });
            if best.is_none_or(|b: LoopRegion| header < b.header) {
                best = Some(region);
            }
        }
    }
    best
}

pub(super) fn loop_enclosed_by_guard(
    stream: &DecodedStream,
    lo: usize,
    region: &LoopRegion,
) -> bool {
    if !matches!(region.kind, LoopKind::For | LoopKind::AsyncFor) {
        return false;
    }
    (lo..region.header).any(|j: usize| {
        is_forward_cond_jump(&stream.ops[j])
            && !is_chain_cond_jump(&stream.ops, j)
            && !is_value_form_shortcircuit(&stream.ops, j)
            && resolve_jump_target(stream, j, &stream.ops[j])
                .is_some_and(|t: usize| t > region.back_edge)
    })
}

pub(super) fn try_enclosed_by_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> bool {
    let Some(loop_region): Option<LoopRegion> = find_loop(stream, lo, hi) else {
        return false;
    };
    if stream.is_pre_311() {
        return loop_region.header < region.try_start
            && loop_region.back_edge > region.handler_start
            && loop_region.back_edge <= hi;
    }
    if !loop_region.infinite {
        if matches!(loop_region.kind, LoopKind::While)
            && !region.is_with()
            && !region.is_finally()
            && loop_region.header <= region.try_start
            && region.try_start < loop_region.back_edge
            && region.protected_end() <= loop_region.back_edge
            && region.handler_start >= loop_region.back_edge
        {
            return true;
        }
        return matches!(loop_region.kind, LoopKind::For)
            && loop_region.header <= region.try_start
            && region.try_start < loop_region.body_end
            && region.handler_start < loop_region.body_end;
    }
    let body_end: usize =
        infinite_while_body_end(stream, loop_region.header, loop_region.back_edge, hi);
    loop_region.header <= region.try_start
        && region.try_start < body_end
        && region.handler_start < body_end
}

pub(super) fn legacy_async_for_enclosed_by_try(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    loop_region: &LoopRegion,
) -> bool {
    if !stream.is_pre_311() {
        return false;
    }
    let Some(region): Option<TryRegion> = find_try_region(stream, lo, hi) else {
        return false;
    };
    region.try_start <= loop_region.header && region.handler_start >= loop_region.exit
}

pub(super) fn legacy_async_for_enclosed_by_loop(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    loop_region: &LoopRegion,
) -> bool {
    if !stream.is_pre_311() {
        return false;
    }
    let aiter: usize = (lo..loop_region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))
        .unwrap_or(loop_region.header);
    for f in lo..aiter {
        if !matches!(
            stream.ops[f],
            CanonicalOp::ForIter(_) | CanonicalOp::ForLoopLegacy(_)
        ) {
            continue;
        }
        let Some(exit): Option<usize> =
            resolve_jump_target(stream, f, &stream.ops[f]).filter(|t: &usize| *t > f)
        else {
            continue;
        };
        if exit > loop_region.back_edge && exit <= hi {
            return true;
        }
    }
    for j in (loop_region.back_edge + 1).min(hi)..hi {
        if (is_cond_back_edge(&stream.ops[j]) || is_cond_jump_with_backward_target(stream, j))
            && let Some(header) = resolve_jump_target(stream, j, &stream.ops[j])
            && header >= lo
            && header < aiter
        {
            return true;
        }
    }
    false
}

fn top_test_run(stream: &DecodedStream, conds: &[usize], header: usize) -> Vec<usize> {
    let mut kept: Vec<usize> = Vec::with_capacity(conds.len());
    let mut prev_end: usize = header;
    for &cond in conds {
        let value_start: usize = cond_expr_start(stream, cond, header);
        if !kept.is_empty()
            && (prev_end..value_start).any(|k: usize| completes_body_stmt(stream, k))
        {
            break;
        }
        kept.push(cond);
        prev_end = cond + 1;
    }
    kept
}

fn bottom_test_run_start(
    stream: &DecodedStream,
    conds: &[usize],
    bottom: usize,
    header: usize,
) -> usize {
    let mut first: usize = bottom;
    for &cond in conds.iter().rev() {
        if cond >= first {
            continue;
        }
        let value_start: usize = cond_expr_start(stream, first, header);
        if (cond + 1..value_start).any(|k: usize| completes_body_stmt(stream, k)) {
            break;
        }
        first = cond;
    }
    cond_expr_start(stream, first, header)
}

fn while_region(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    hi: usize,
    conds: &[usize],
    bottom_cond: Option<usize>,
) -> LoopRegion {
    if let Some(bottom) = bottom_cond {
        let exit: usize = resolve_jump_target(stream, bottom, &stream.ops[bottom])
            .filter(|t: &usize| *t > back_edge)
            .unwrap_or(back_edge + 1);
        let run_start: usize = bottom_test_run_start(stream, conds, bottom, header);
        let span_start: usize = bottom_test_span_start(stream, header, back_edge);
        let raw_end: usize = run_start.min(span_start);
        return LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: raw_end.max(terminator_floor(stream, header, back_edge)),
            back_edge,
            exit: exit.min(hi),
            infinite: false,
        };
    }
    let Some(&last_top): Option<&usize> = conds.last() else {
        return LoopRegion {
            kind: LoopKind::While,
            header,
            body_start: header,
            body_end: back_edge,
            back_edge,
            exit: (back_edge + 1).min(hi),
            infinite: true,
        };
    };
    let exit: usize = conds
        .first()
        .copied()
        .and_then(|c: usize| {
            resolve_jump_target(stream, c, &stream.ops[c]).filter(|t: &usize| *t > back_edge)
        })
        .unwrap_or(back_edge + 1);
    let capped_exit: usize = exit.min(hi);
    LoopRegion {
        kind: LoopKind::While,
        header,
        body_start: last_top + 1,
        body_end: while_cond_tail_body_end(stream, header, back_edge, capped_exit),
        back_edge,
        exit: capped_exit,
        infinite: false,
    }
}

fn while_cond_tail_body_end(
    stream: &DecodedStream,
    header: usize,
    back_edge: usize,
    exit: usize,
) -> usize {
    let cap: usize = exit.min(stream.ops.len());
    if header >= cap || back_edge + 1 >= cap {
        return back_edge;
    }
    let Some(gap_stmt): Option<usize> = (back_edge + 1..cap).find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
                | CanonicalOp::Pop
                | CanonicalOp::PopExcept
        )
    }) else {
        return back_edge;
    };
    let reach: Vec<bool> = reachable_in_loop(stream, header, header, cap);
    if !reach.get(gap_stmt).copied().unwrap_or(false)
        || !trailing_block_absorbable(stream, &reach, back_edge + 1, header, cap)
    {
        return back_edge;
    }
    let Some(last_reach): Option<usize> = (back_edge + 1..cap).rev().find(|&i: &usize| reach[i])
    else {
        return back_edge;
    };
    if is_stmt_terminator(&stream.ops[last_reach]) {
        cap
    } else {
        back_edge
    }
}

fn is_bottom_test(stream: &DecodedStream, cond: usize, back_edge: usize) -> bool {
    (cond + 1..back_edge).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    })
}

pub(super) fn is_walrus_store_shape(ops: &[CanonicalOp], idx: usize) -> bool {
    matches!(
        ops.get(idx),
        Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::StoreGlobal(_))
    ) && idx > 0
        && matches!(
            ops.get(idx - 1),
            Some(CanonicalOp::Dup | CanonicalOp::Copy(1))
        )
}

pub(super) fn cond_expr_start(stream: &DecodedStream, cond: usize, header: usize) -> usize {
    let mut i: usize = cond;
    while i > header {
        let prev: usize = i - 1;
        if is_walrus_store_shape(&stream.ops, prev) && prev > header {
            i = prev - 1;
            continue;
        }
        if is_value_boundary(&stream.ops[prev]) {
            break;
        }
        i = prev;
    }
    i
}

fn bottom_test_start(
    stream: &DecodedStream,
    back_edge: usize,
    header: usize,
    exit: usize,
) -> usize {
    let mut start: usize = cond_expr_start(stream, back_edge, header);
    loop {
        let mut probe: usize = start;
        while probe > header
            && matches!(
                stream.ops.get(probe - 1),
                Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
            )
        {
            probe -= 1;
        }
        let Some(prev): Option<usize> = probe.checked_sub(1) else {
            break;
        };
        let is_exit_cond: bool = matches!(
            stream.ops.get(prev),
            Some(
                CanonicalOp::PopJumpIfFalse(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalseBackward(_)
                    | CanonicalOp::PopJumpIfTrueBackward(_)
            )
        ) && resolve_jump_target(stream, prev, &stream.ops[prev])
            .is_some_and(|t: usize| t >= exit || t <= header);
        if !is_exit_cond {
            break;
        }
        start = cond_expr_start(stream, prev, header);
    }
    start
}

fn absorb_hoists_nested_try(
    stream: &DecodedStream,
    region: &LoopRegion,
    region_try: &TryRegion,
) -> bool {
    let handler_reenters_body: bool =
        (region_try.handler_start..region_try.region_end()).any(|k: usize| {
            is_back_edge(&stream.ops[k])
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t <= region.back_edge)
        });
    if !handler_reenters_body {
        return false;
    }
    (region.body_start..region_try.try_start).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t > region_try.try_start)
    })
}

fn while_break_handler_try(
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Option<TryRegion> {
    let region_try: TryRegion =
        find_try_region(stream, region.body_start, hi.min(stream.ops.len()))?;
    let try_start: usize = region_try.try_start;
    let inside_body: bool = try_start >= region.body_start && try_start < region.back_edge;
    let protected_within: bool = region_try.protected_end() <= region.back_edge;
    let handler_after_body: bool = region_try.handler_start >= region.back_edge;
    if region_try.is_with()
        || region_try.is_finally()
        || !inside_body
        || !protected_within
        || !handler_after_body
    {
        return None;
    }
    Some(region_try)
}

fn loop_exit_leading_return(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Option<Expr> {
    let tail_start: usize = loop_tail_start(stream, region, hi);
    if tail_start >= hi {
        return None;
    }
    let tail: Vec<Stmt> = structure_stmts(code, stream, tail_start, hi).ok()?;
    match tail.first() {
        Some(Stmt::Return(Some(value))) => Some(value.clone()),
        _ => None,
    }
}

fn loop_exit_return_absorbed(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
    body: &[Stmt],
) -> bool {
    let Some(Stmt::Return(Some(last_val))): Option<&Stmt> = body.last() else {
        return false;
    };
    let Some(exit_ret): Option<Expr> = loop_exit_leading_return(code, stream, region, hi) else {
        return false;
    };
    if *last_val != exit_ret {
        return false;
    }
    let exit: usize = region.exit.min(stream.ops.len());
    let Some(prev): Option<usize> = last_significant_back(stream, region.body_start, exit) else {
        return false;
    };
    is_back_edge(&stream.ops[prev])
        && resolve_jump_target(stream, prev, &stream.ops[prev])
            .is_some_and(|t: usize| t <= region.header)
}

fn structure_while_body_absorbing_break_handler(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Result<Vec<Stmt>> {
    if let Some(region_try) = while_break_handler_try(stream, region, hi) {
        if absorb_hoists_nested_try(stream, region, &region_try) {
            let body_hi: usize = region_try.region_end().min(hi);
            return structure_stmts(code, stream, region.body_start, body_hi);
        }
        let try_hi: usize = region_try.region_end().min(hi);
        let mut body: Vec<Stmt> =
            structure_try(code, stream, region.body_start, try_hi, &region_try)?;
        if loop_exit_return_absorbed(code, stream, region, hi, &body) {
            body.pop();
        }
        return Ok(body);
    }
    structure_stmts(code, stream, region.body_start, region.body_end)
}

pub(super) fn structure_loop(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &LoopRegion,
) -> Result<Vec<Stmt>> {
    let while_test: Option<Expr> = if matches!(region.kind, LoopKind::While) && !region.infinite {
        Some(recover_while_test(code, stream, region))
    } else {
        None
    };
    let head_end: usize = while_test
        .as_ref()
        .and_then(|t: &Expr| redundant_entry_guard_start(code, stream, lo, region, t))
        .unwrap_or(region.header);
    let head: Vec<Stmt> = structure_stmts(code, stream, lo, head_end)?;
    let exit_return: Option<Expr> = loop_shared_exit_return(code, stream, region, hi);
    push_loop_frame(LoopFrame {
        header: region.header,
        exit: region.exit,
        exit_return,
        exit_tail_range: loop_exit_tail_range(stream, region, hi),
    });
    let mut cold_handler_exit_tail: Vec<Stmt> = Vec::new();
    let result: Result<Stmt> = (|| -> Result<Stmt> {
        let loop_stmt: Stmt = match region.kind {
            LoopKind::For => {
                let iter: Expr = recover_for_iter(code, stream, region, lo);
                let (target, body_start): (Expr, usize) = recover_for_target(code, stream, region)
                    .unwrap_or_else(|| (placeholder_target(), region.body_start));
                let (body, epilogue): (Vec<Stmt>, Vec<Stmt>) =
                    structure_for_body(code, stream, region, body_start)?;
                cold_handler_exit_tail = epilogue;
                let orelse: Vec<Stmt> = loop_orelse(code, stream, region, hi)?;
                Stmt::For {
                    target,
                    iter,
                    body: non_empty(body),
                    orelse,
                    is_async: false,
                    line: None,
                }
            }
            LoopKind::AsyncFor => {
                let iter: Expr = recover_async_for_iter(code, stream, region, lo);
                let store_idx: usize =
                    async_for_store_idx(stream, region.header + 1, region.body_end);
                let (target, after_store): (Expr, usize) =
                    recover_async_for_target(code, stream, store_idx, region.body_end);
                let body_start: usize = if region.body_start > store_idx {
                    region.body_start
                } else {
                    after_store
                };
                let body: Vec<Stmt> = structure_stmts(code, stream, body_start, region.body_end)?;
                let body: Vec<Stmt> =
                    rewrite_legacy_async_for_body(stream, body, body_start, region);
                let orelse: Vec<Stmt> = loop_orelse(code, stream, region, hi)?;
                Stmt::For {
                    target,
                    iter,
                    body: non_empty(body),
                    orelse,
                    is_async: true,
                    line: None,
                }
            }
            LoopKind::While => {
                let test: Expr = while_test
                    .clone()
                    .unwrap_or_else(|| recover_while_test(code, stream, region));
                let body: Vec<Stmt> = if region.infinite {
                    structure_infinite_while_body(code, stream, region)?
                } else {
                    structure_while_body_absorbing_break_handler(code, stream, region, hi)?
                };
                let orelse: Vec<Stmt> = if region.infinite {
                    Vec::new()
                } else {
                    loop_orelse(code, stream, region, hi)?
                };
                Stmt::While {
                    test,
                    body: non_empty(body),
                    orelse,
                    line: None,
                }
            }
        };
        Ok(loop_stmt)
    })();
    pop_loop_frame();
    let loop_stmt: Stmt = result?;
    let mut out: Vec<Stmt> = head;
    out.push(loop_stmt);
    out.extend(cold_handler_exit_tail);
    let tail_start: usize = if region.infinite {
        skip_loop_epilogue(stream, infinite_tail_start(stream, region).min(hi), hi)
    } else {
        loop_tail_start(stream, region, hi)
    };
    if tail_start < hi {
        out.extend(structure_stmts(code, stream, tail_start, hi)?);
    }
    Ok(out)
}

pub(super) fn structure_for_loop_with_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    iter: Expr,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(get_iter): Option<usize> = first_significant(stream, lo, hi)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter))
    else {
        return Ok(None);
    };
    let Some(header): Option<usize> = first_significant(stream, get_iter + 1, hi)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::ForIter(_)))
    else {
        return Ok(None);
    };
    let Some(region): Option<LoopRegion> = find_loop(stream, get_iter, hi) else {
        return Ok(None);
    };
    if !matches!(region.kind, LoopKind::For) || region.header != header {
        return Ok(None);
    }
    let exit_return: Option<Expr> = loop_shared_exit_return(code, stream, &region, hi);
    push_loop_frame(LoopFrame {
        header: region.header,
        exit: region.exit,
        exit_return,
        exit_tail_range: loop_exit_tail_range(stream, &region, hi),
    });
    let mut cold_handler_exit_tail: Vec<Stmt> = Vec::new();
    let result: Result<Stmt> = (|| -> Result<Stmt> {
        let (target, body_start): (Expr, usize) = recover_for_target(code, stream, &region)
            .unwrap_or_else(|| (placeholder_target(), region.body_start));
        let (body, epilogue): (Vec<Stmt>, Vec<Stmt>) =
            structure_for_body(code, stream, &region, body_start)?;
        cold_handler_exit_tail = epilogue;
        let orelse: Vec<Stmt> = loop_orelse(code, stream, &region, hi)?;
        Ok(Stmt::For {
            target,
            iter,
            body: non_empty(body),
            orelse,
            is_async: false,
            line: None,
        })
    })();
    pop_loop_frame();
    let loop_stmt: Stmt = result?;
    let mut out: Vec<Stmt> = vec![loop_stmt];
    out.extend(cold_handler_exit_tail);
    let tail_start: usize = loop_tail_start(stream, &region, hi);
    if tail_start < hi {
        out.extend(structure_stmts(code, stream, tail_start, hi)?);
    }
    Ok(Some(out))
}

fn infinite_exit_block(stream: &DecodedStream, region: &LoopRegion) -> Option<(usize, usize)> {
    if !region.infinite {
        return None;
    }
    let first_cond: usize = (region.header..region.back_edge).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    let body_label: usize = resolve_jump_target(stream, first_cond, &stream.ops[first_cond])
        .filter(|t: &usize| *t > first_cond && *t < region.back_edge)?;
    let block_start: usize = first_significant(stream, first_cond + 1, body_label)?;
    if block_start >= body_label {
        return None;
    }
    if !block_breaks_loop(
        stream,
        block_start,
        body_label,
        region.back_edge,
        stream.ops.len(),
    ) {
        return None;
    }
    if (block_start..body_label)
        .any(|k: usize| is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k))
    {
        return None;
    }
    Some((block_start, body_label))
}

fn structure_infinite_while_body(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
) -> Result<Vec<Stmt>> {
    let body_end: usize = infinite_body_end(stream, region);
    let body_entry: usize = infinite_body_entry(stream, region, body_end);
    let Some((_, body_label)): Option<(usize, usize)> = infinite_exit_block(stream, region) else {
        return structure_stmts(code, stream, body_entry, body_end);
    };
    let first_cond: usize = infinite_first_cond(stream, region);
    if inline_exit_splits_try(stream, region, first_cond, body_end) {
        return structure_stmts(code, stream, body_entry, body_end);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[region.header..first_cond])?;
    let test: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::True,
        line: None,
    });
    let keeps_body_when_true: bool =
        matches!(stream.ops[first_cond], CanonicalOp::PopJumpIfTrue(_));
    let break_test: Expr = if keeps_body_when_true {
        Expr::UnaryOp {
            op: crate::bytecode::opcode::UnaryOp::Not,
            operand: Box::new(test),
        }
    } else {
        test
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test: break_test,
        body: vec![Stmt::Break],
        orelse: Vec::new(),
        line: None,
    });
    out.extend(structure_stmts(code, stream, body_label, body_end)?);
    Ok(out)
}

fn infinite_body_entry(stream: &DecodedStream, region: &LoopRegion, body_end: usize) -> usize {
    first_significant(stream, region.header, body_end).unwrap_or(region.body_start)
}

fn infinite_first_cond(stream: &DecodedStream, region: &LoopRegion) -> usize {
    (region.header..region.back_edge)
        .find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        .unwrap_or(region.header)
}

fn infinite_tail_start(stream: &DecodedStream, region: &LoopRegion) -> usize {
    let body_end: usize = infinite_body_end(stream, region);
    let first_cond: usize = infinite_first_cond(stream, region);
    if inline_exit_splits_try(stream, region, first_cond, body_end) {
        body_end
    } else {
        region.exit
    }
}

fn inline_exit_splits_try(
    stream: &DecodedStream,
    region: &LoopRegion,
    first_cond: usize,
    body_end: usize,
) -> bool {
    stream
        .exception_table
        .iter()
        .any(|entry: &crate::bytecode::flow::ExceptionTableEntry| {
            let (Some(try_start), Some(handler_start)): (Option<usize>, Option<usize>) = (
                stream.index_for_offset(entry.start),
                stream.index_for_offset(entry.target),
            ) else {
                return false;
            };
            try_start >= region.header && try_start <= first_cond && handler_start < body_end
        })
}

fn loop_cfg_successors(
    stream: &DecodedStream,
    idx: usize,
    lo: usize,
    cap: usize,
    out: &mut Vec<usize>,
) -> bool {
    out.clear();
    let op: &CanonicalOp = &stream.ops[idx];
    if matches!(
        op,
        CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
    ) {
        return false;
    }
    let mut leaves: bool = false;
    let uncond: bool = matches!(
        op,
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
    );
    let two_way: bool = is_forward_cond_jump(op)
        || is_cond_back_edge(op)
        || is_cond_jump_with_backward_target(stream, idx)
        || matches!(
            op,
            CanonicalOp::JumpIfTrueOrPop(_)
                | CanonicalOp::JumpIfFalseOrPop(_)
                | CanonicalOp::ForIter(_)
                | CanonicalOp::ForLoopLegacy(_)
        );
    if (uncond || two_way)
        && let Some(target) = resolve_jump_target(stream, idx, op)
    {
        if target >= lo && target < cap {
            out.push(target);
        } else {
            leaves = true;
        }
    }
    if !uncond {
        let next: usize = idx + 1;
        if next < cap {
            out.push(next);
        } else {
            leaves = true;
        }
    }
    leaves
}

fn reachable_in_loop(stream: &DecodedStream, header: usize, lo: usize, cap: usize) -> Vec<bool> {
    let exc: Vec<(usize, usize, usize)> = stream
        .exception_table
        .iter()
        .filter_map(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            let ts: usize = stream.index_for_offset(e.start)?;
            let hs: usize = stream.index_for_offset(e.target)?;
            let te: usize = stream.index_for_offset_ceil(e.end()).unwrap_or(cap);
            (ts >= lo && ts < cap).then_some((ts, te, hs))
        })
        .collect();
    let mut seen: Vec<bool> = vec![false; cap];
    let mut stack: Vec<usize> = vec![header];
    let mut succ: Vec<usize> = Vec::new();
    while let Some(n) = stack.pop() {
        if n >= cap || seen[n] {
            continue;
        }
        seen[n] = true;
        let _: bool = loop_cfg_successors(stream, n, lo, cap, &mut succ);
        for &s in &succ {
            if s < cap && !seen[s] {
                stack.push(s);
            }
        }
        for &(ts, te, hs) in &exc {
            if n >= ts && n < te && hs < cap && !seen[hs] {
                stack.push(hs);
            }
        }
    }
    seen
}

fn trailing_block_absorbable(
    stream: &DecodedStream,
    reach: &[bool],
    legacy_exit: usize,
    lo: usize,
    cap: usize,
) -> bool {
    let mut succ: Vec<usize> = Vec::new();
    for (i, &reachable) in reach.iter().enumerate().take(cap).skip(legacy_exit) {
        if !reachable {
            continue;
        }
        if (is_back_edge(&stream.ops[i])
            && !is_async_send_back_edge(stream, i)
            && !is_async_cleanup_throw_back_edge(stream, i))
            || is_cond_back_edge(&stream.ops[i])
            || is_cond_jump_with_backward_target(stream, i)
        {
            return false;
        }
        if loop_cfg_successors(stream, i, lo, cap, &mut succ) {
            return false;
        }
    }
    true
}

fn exit_follows_bottom_back_edge(
    stream: &DecodedStream,
    legacy_exit: usize,
    header: usize,
) -> bool {
    let Some(prev): Option<usize> = (header..legacy_exit).rev().find(|&k: &usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    }) else {
        return false;
    };
    (is_back_edge(&stream.ops[prev])
        || is_cond_back_edge(&stream.ops[prev])
        || is_cond_jump_with_backward_target(stream, prev))
        && resolve_jump_target(stream, prev, &stream.ops[prev]).is_some_and(|t: usize| t <= header)
}

fn infinite_loop_reach_exit(
    stream: &DecodedStream,
    header: usize,
    legacy_exit: usize,
    lo: usize,
    hi: usize,
) -> usize {
    let cap: usize = hi.min(stream.ops.len());
    if header >= cap || legacy_exit >= cap {
        return legacy_exit;
    }
    if exit_follows_bottom_back_edge(stream, legacy_exit, header) {
        return legacy_exit;
    }
    let reach: Vec<bool> = reachable_in_loop(stream, header, lo, cap);
    if !trailing_block_absorbable(stream, &reach, legacy_exit, lo, cap) {
        return legacy_exit;
    }
    (lo..cap)
        .rev()
        .find(|&i: &usize| reach[i])
        .map_or(legacy_exit, |m: usize| (m + 1).min(cap).max(legacy_exit))
}

fn infinite_body_end(stream: &DecodedStream, region: &LoopRegion) -> usize {
    let len: usize = stream.ops.len();
    let mut end: usize =
        infinite_while_body_end(stream, region.header, region.back_edge, len).max(region.back_edge);
    loop {
        let guard_target: Option<usize> = (region.body_start..end)
            .filter(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .filter_map(|k: usize| {
                resolve_jump_target(stream, k, &stream.ops[k]).filter(|t: &usize| {
                    *t >= region.back_edge && *t > end && *t <= len && *t != region.exit
                })
            })
            .max();
        let Some(target): Option<usize> = guard_target else {
            break;
        };
        let block_end: usize = (target..len)
            .find(|&k: &usize| {
                matches!(
                    stream.ops[k],
                    CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_)
                )
            })
            .map_or(len, |r: usize| r + 1);
        if block_end <= end {
            break;
        }
        end = block_end;
    }
    end
}

pub(super) fn non_empty(body: Vec<Stmt>) -> Vec<Stmt> {
    if body.is_empty() {
        vec![Stmt::Pass]
    } else {
        body
    }
}

fn skip_loop_epilogue(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi
        && matches!(
            stream.ops[i],
            CanonicalOp::Pop | CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::EndAsyncFor
        )
    {
        if matches!(stream.ops[i], CanonicalOp::Nop) && opens_protected_region(stream, i) {
            break;
        }
        i += 1;
    }
    i
}

fn opens_protected_region(stream: &DecodedStream, idx: usize) -> bool {
    let (maj, min): (u8, u8) = (stream.version.major(), stream.version.minor());
    if maj != 3 || min > 7 {
        return false;
    }
    let Some(next_off): Option<u32> = stream.offsets.get(idx + 1).copied() else {
        return false;
    };
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start == next_off)
}

fn loop_shared_exit_return(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Option<Expr> {
    let tail_start: usize = if region.infinite {
        skip_loop_epilogue(stream, infinite_tail_start(stream, region).min(hi), hi)
    } else {
        loop_tail_start(stream, region, hi)
    };
    if tail_start >= hi {
        return None;
    }
    let tail: Vec<Stmt> = structure_stmts(code, stream, tail_start, hi).ok()?;
    match tail.as_slice() {
        [Stmt::Return(Some(value))] => Some(value.clone()),
        _ => None,
    }
}

fn loop_exit_tail_range(
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Option<(usize, usize)> {
    if region.infinite {
        return None;
    }
    let start: usize = loop_tail_start(stream, region, hi);
    (start < hi).then_some((start, hi))
}

fn loop_tail_start(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> usize {
    if let Some(end_idx) = legacy_loop_orelse_end(stream, region, hi) {
        return skip_loop_epilogue(stream, end_idx.min(hi), hi);
    }
    if let Some(break_target) = find_break_target(stream, region, hi)
        && break_target > region.exit
        && break_target <= hi
    {
        return skip_loop_epilogue(stream, break_target, hi);
    }
    let after_exit: usize = region.exit.max(region.back_edge + 1);
    skip_loop_epilogue(stream, after_exit.min(hi), hi)
}

fn loop_orelse(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    hi: usize,
) -> Result<Vec<Stmt>> {
    if let Some(else_end) = legacy_loop_orelse_end(stream, region, hi) {
        let else_start: usize = skip_loop_epilogue(stream, region.exit.min(hi), hi);
        if else_end > else_start {
            return structure_stmts(code, stream, else_start, else_end);
        }
        return Ok(Vec::new());
    }
    let else_start: usize = skip_loop_epilogue(stream, region.exit.min(hi), hi);
    let else_end: usize = find_break_target(stream, region, hi).unwrap_or(else_start);
    if else_end > else_start {
        structure_stmts(code, stream, else_start, else_end)
    } else {
        Ok(Vec::new())
    }
}

fn legacy_loop_orelse_end(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> Option<usize> {
    if stream.setup_loop_end.is_empty() {
        return None;
    }
    let (&_setup_idx, &end_idx): (&usize, &usize) = stream
        .setup_loop_end
        .range(..=region.header)
        .rev()
        .find(|&(&s, &e): &(&usize, &usize)| s < region.header && e >= region.exit)?;
    Some(end_idx.min(hi))
}

fn find_break_target(stream: &DecodedStream, region: &LoopRegion, hi: usize) -> Option<usize> {
    let mut target: Option<usize> = None;
    for k in region.body_start..region.body_end {
        if matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
        ) && let Some(t) = resolve_jump_target(stream, k, &stream.ops[k])
            && t > region.exit
            && t <= hi
        {
            target = Some(target.map_or(t, |prev: usize| prev.max(t)));
        }
        if matches!(
            stream.ops[k],
            CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::JumpAbsolute(_)
        ) && resolve_jump_target(stream, k, &stream.ops[k])
            .is_some_and(|t: usize| t < region.header)
        {
            target = Some(target.map_or(hi, |prev: usize| prev.max(hi)));
        }
    }
    target
}

fn is_iter_setup_boundary(stream: &DecodedStream, k: usize) -> bool {
    match stream.ops[k] {
        CanonicalOp::StoreFast(_)
        | CanonicalOp::StoreName(_)
        | CanonicalOp::StoreGlobal(_)
        | CanonicalOp::ForIter(_)
        | CanonicalOp::JumpBackward(_) => true,
        CanonicalOp::Pop => !is_shortcircuit_cleanup_pop(stream, k),
        _ => false,
    }
}

fn iter_region_residual(
    code: &CodeObject,
    stream: &DecodedStream,
    setup_start: usize,
    setup_end: usize,
) -> Vec<Expr> {
    let region: &[CanonicalOp] = &stream.ops[setup_start..setup_end];
    let merges: Vec<usize> = collect_value_boolop_merges(stream, setup_start, setup_end);
    let sc: Vec<ScDesc> = collect_value_boolop_sc(stream, setup_start, setup_end);
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        with_boolop_context(region, merges, sc, || build_linear_stmts_sim(code, region))
            .unwrap_or_default();
    residual
}

fn recover_for_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    if matches!(
        stream.ops.get(region.header),
        Some(CanonicalOp::ForLoopLegacy(_))
    ) {
        return recover_for_loop_legacy_iter(code, stream, region, lo);
    }
    let get_iter: Option<usize> = (lo..region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetIter | CanonicalOp::GetAiter));
    let setup_end: usize = get_iter.unwrap_or(region.header);
    let setup_start: usize = (lo..setup_end)
        .rev()
        .take_while(|&k: &usize| !is_iter_setup_boundary(stream, k))
        .last()
        .unwrap_or(setup_end);
    let residual: Vec<Expr> = iter_region_residual(code, stream, setup_start, setup_end);
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

fn recover_for_loop_legacy_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    let setup_start: usize = (lo..region.header)
        .rev()
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::ForLoopLegacy(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::JumpBackward(_)
            )
        })
        .last()
        .unwrap_or(region.header);
    let mut residual: Vec<Expr> = iter_region_residual(code, stream, setup_start, region.header);
    let _index: Option<Expr> = residual.pop();
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

pub(super) fn recover_for_target(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
) -> Option<(Expr, usize)> {
    let after: usize = region.header + 1;
    match stream.ops.get(after)? {
        CanonicalOp::StoreFast(i) => Some((local_target(code, *i, after).ok()?, after + 1)),
        CanonicalOp::StoreName(i) | CanonicalOp::StoreGlobal(i) => Some((
            Expr::Name {
                id: name_at(&code.names, *i, after, "name").ok()?,
                ctx: ExprCtx::Store,
                line: None,
            },
            after + 1,
        )),
        CanonicalOp::UnpackSequence(0) => Some((
            Expr::Tuple {
                elts: Vec::new(),
                ctx: ExprCtx::Store,
            },
            after + 1,
        )),
        CanonicalOp::UnpackSequence(n) => {
            let (targets, skip): (Vec<Expr>, usize) =
                collect_unpack_targets(code, &stream.ops, after + 1, *n as usize)?;
            Some((
                Expr::Tuple {
                    elts: targets,
                    ctx: ExprCtx::Store,
                },
                after + 1 + skip,
            ))
        }
        CanonicalOp::BuildTuple(n) => {
            let count: usize = *n as usize;
            let mut elts: Vec<Expr> = Vec::with_capacity(count.min(MAX_SYNTH_OPERANDS));
            let mut k: usize = after + 1;
            while elts.len() < count && k < region.body_end {
                match &stream.ops[k] {
                    CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {
                        k += 1;
                    }
                    CanonicalOp::StoreFastStoreFast(a, b) => {
                        elts.push(local_target(code, *a, k).ok()?);
                        elts.push(local_target(code, *b, k).ok()?);
                        k += 1;
                    }
                    _ => {
                        let (elt, next): (Expr, usize) = single_store_target(code, &stream.ops, k)?;
                        elts.push(elt);
                        k = next;
                    }
                }
            }
            if elts.len() != count {
                return None;
            }
            Some((
                Expr::Tuple {
                    elts,
                    ctx: ExprCtx::Store,
                },
                k,
            ))
        }
        _ => single_store_target(code, &stream.ops, after),
    }
}

fn recover_async_for_iter(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
    lo: usize,
) -> Expr {
    let aiter: usize = (lo..region.header)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAiter))
        .unwrap_or(region.header);
    let setup_start: usize = (lo..aiter)
        .rev()
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::EndAsyncFor
                    | CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpAbsolute(_)
            )
        })
        .last()
        .unwrap_or(aiter);
    let residual: Vec<Expr> = iter_region_residual(code, stream, setup_start, aiter);
    residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    })
}

fn recover_async_for_target(
    code: &CodeObject,
    stream: &DecodedStream,
    store_idx: usize,
    hi: usize,
) -> (Expr, usize) {
    match stream.ops.get(store_idx) {
        Some(
            CanonicalOp::UnpackSequence(_) | CanonicalOp::UnpackEx(_) | CanonicalOp::BuildTuple(_),
        ) => recover_tuple_target(code, stream, store_idx, hi),
        _ => single_store_target(code, &stream.ops, store_idx)
            .unwrap_or_else(|| (placeholder_target(), store_idx + 1)),
    }
}

#[derive(Debug, Clone, Copy)]
struct WhileConjunct {
    start: usize,
    cond_idx: usize,
    negate: bool,

    reentry: bool,
}

fn fold_while_conjuncts(
    code: &CodeObject,
    stream: &DecodedStream,
    conjuncts: &[WhileConjunct],
) -> Expr {
    let mut values: Vec<Expr> = Vec::with_capacity(conjuncts.len());
    for c in conjuncts {
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[c.start..c.cond_idx]).unwrap_or_default();
        let operand: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        });
        if let Some(none_test) = none_jump_test(stream, c.cond_idx, operand.clone()) {
            values.push(if c.reentry {
                negate_cond_expr(none_test)
            } else {
                none_test
            });
        } else {
            values.push(if c.negate {
                Expr::UnaryOp {
                    op: crate::bytecode::opcode::UnaryOp::Not,
                    operand: Box::new(operand),
                }
            } else {
                operand
            });
        }
    }
    match values.len() {
        0 => Expr::Constant {
            value: ConstValue::True,
            line: None,
        },
        1 => values.into_iter().next().unwrap_or(Expr::Constant {
            value: ConstValue::True,
            line: None,
        }),
        _ => Expr::BoolOp {
            op: crate::ast::node::BoolOpKind::And,
            values,
        },
    }
}

fn collect_while_conjuncts(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    header: usize,
    exit: usize,
) -> Vec<WhileConjunct> {
    let mut conjuncts: Vec<WhileConjunct> = Vec::new();
    let mut start: usize = lo;
    let mut k: usize = lo;
    while k <= hi {
        let is_cond: bool = matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::PopJumpIfFalse(_)
                    | CanonicalOp::PopJumpIfTrue(_)
                    | CanonicalOp::PopJumpIfFalseRel(_)
                    | CanonicalOp::PopJumpIfTrueRel(_)
                    | CanonicalOp::PopJumpIfFalseBackward(_)
                    | CanonicalOp::PopJumpIfTrueBackward(_)
            )
        ) && !is_chain_cond_jump(&stream.ops, k);
        if is_cond {
            let target: Option<usize> = resolve_jump_target(stream, k, &stream.ops[k]);
            let reentry: bool = target.is_some_and(|t: usize| t <= header || t < exit && t < k);
            conjuncts.push(WhileConjunct {
                start,
                cond_idx: k,
                negate: while_conjunct_negation(stream, k, header, exit),
                reentry,
            });
            start = k + 1;
        }
        k += 1;
    }
    conjuncts
}

fn while_conjunct_negation(
    stream: &DecodedStream,
    cond_idx: usize,
    header: usize,
    exit: usize,
) -> bool {
    let is_if_true: bool = matches!(
        stream.ops[cond_idx],
        CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
    );
    let target: Option<usize> = resolve_jump_target(stream, cond_idx, &stream.ops[cond_idx]);
    let is_reentry: bool = target.is_some_and(|t: usize| t <= header || t < exit && t < cond_idx);
    is_if_true ^ is_reentry
}

fn recover_while_test(code: &CodeObject, stream: &DecodedStream, region: &LoopRegion) -> Expr {
    if region.infinite {
        return Expr::Constant {
            value: ConstValue::True,
            line: None,
        };
    }
    if let Some(test) = recover_while_bottom_test_compound(code, stream, region) {
        return test;
    }
    let back_op: &CanonicalOp = &stream.ops[region.back_edge];
    let cond_back: bool =
        is_cond_back_edge(back_op) || is_cond_jump_with_backward_target(stream, region.back_edge);
    if cond_back {
        let test_start: usize =
            bottom_test_start(stream, region.back_edge, region.header, region.exit);
        let conjuncts: Vec<WhileConjunct> = collect_while_conjuncts(
            stream,
            test_start,
            region.back_edge,
            region.header,
            region.exit,
        );
        return fold_while_conjuncts(code, stream, &conjuncts);
    }
    let has_bottom_test: bool = (region.body_end..region.back_edge).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    });
    let (expr_start, last_cond): (usize, usize) = if has_bottom_test {
        let start: usize = bottom_test_start(stream, region.back_edge, region.header, region.exit);
        let last: usize = (start..region.back_edge)
            .rev()
            .find(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .unwrap_or(start);
        (start, last)
    } else {
        let top_end: usize = region.body_start.max(region.header + 1);
        let last: usize = (region.header..top_end)
            .rev()
            .find(|&k: &usize| {
                is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
            })
            .unwrap_or(region.header);
        (region.header, last)
    };
    if !has_bottom_test
        && let Some(test) = recover_while_compound_test(code, stream, expr_start, last_cond, region)
    {
        return test;
    }
    let conjuncts: Vec<WhileConjunct> =
        collect_while_conjuncts(stream, expr_start, last_cond, region.header, region.exit);
    fold_while_conjuncts(code, stream, &conjuncts)
}

fn recover_while_compound_test(
    code: &CodeObject,
    stream: &DecodedStream,
    expr_start: usize,
    last_cond: usize,
    region: &LoopRegion,
) -> Option<Expr> {
    let jumps: Vec<usize> = (expr_start..=last_cond)
        .filter(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        .collect();
    if jumps.len() < 2 {
        return None;
    }
    let body: usize = first_significant(stream, last_cond + 1, region.back_edge)?;
    let exit: usize = region.exit;
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jumps.len());
    let mut value_lo: usize = expr_start;
    for &jump in &jumps {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump]).ok()?;
        if !stmts.is_empty() {
            return None;
        }
        let value: Expr = residual.into_iter().next_back()?;
        let is_jump_if_true: bool = matches!(
            stream.ops[jump],
            CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfTrueRel(_)
        );
        let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])
            .filter(|t: &usize| *t == body || *t == exit || (*t > jump && *t < body))?;
        operands.push(CondOperand {
            expr: none_jump_test(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true,
            target,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, last_cond + 1).unwrap_or(jump + 1);
    }
    parse_cond_range(&operands, body, exit)
}

fn is_pop_cond_jump(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
    )
}

fn is_pop_cond_jump_if_true(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
    )
}

fn is_stmt_terminator(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
    )
}

fn terminator_floor(stream: &DecodedStream, floor: usize, back_edge: usize) -> usize {
    (floor..back_edge.min(stream.ops.len()))
        .rev()
        .find(|&k: &usize| is_stmt_terminator(&stream.ops[k]))
        .map_or(floor, |t: usize| t + 1)
}

fn bottom_test_span_start(stream: &DecodedStream, floor: usize, back_edge: usize) -> usize {
    let mut start: usize = back_edge;
    while start > floor {
        let prev: usize = start - 1;
        if completes_body_stmt(stream, prev) || is_stmt_terminator(&stream.ops[prev]) {
            break;
        }
        start = prev;
    }
    start
}

fn last_cond_back_edge_in_run(
    stream: &DecodedStream,
    first: usize,
    header: usize,
    hi: usize,
) -> usize {
    let mut back_edge: usize = first;
    let mut k: usize = first + 1;
    while k < hi {
        if completes_body_stmt(stream, k) {
            break;
        }
        let to_header: bool = resolve_jump_target(stream, k, &stream.ops[k]) == Some(header);
        if to_header && is_back_edge(&stream.ops[k]) && !is_cond_back_edge(&stream.ops[k]) {
            break;
        }
        if to_header
            && (is_cond_back_edge(&stream.ops[k]) || is_cond_jump_with_backward_target(stream, k))
        {
            back_edge = k;
        }
        k += 1;
    }
    back_edge
}

fn collect_bottom_cond_operands(
    code: &CodeObject,
    stream: &DecodedStream,
    test_start: usize,
    back_edge: usize,
    reentry: usize,
    exit: usize,
) -> Option<Vec<CondOperand>> {
    let mut operands: Vec<CondOperand> = Vec::new();
    let mut value_lo: usize = test_start;
    let mut k: usize = test_start;
    while k <= back_edge {
        if !is_pop_cond_jump(&stream.ops[k]) || is_chain_cond_jump(&stream.ops, k) {
            k += 1;
            continue;
        }
        let jump: usize = k;
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump]).ok()?;
        if !stmts.is_empty() {
            return None;
        }
        let value: Expr = residual.into_iter().next_back()?;
        let cond_if_true: bool = is_pop_cond_jump_if_true(&stream.ops[jump]);
        let follower: Option<usize> = first_significant(stream, jump + 1, back_edge + 1);
        let reloops_on_fallthrough: bool = follower.is_some_and(|f: usize| {
            f <= back_edge
                && is_back_edge(&stream.ops[f])
                && resolve_jump_target(stream, f, &stream.ops[f]) == Some(reentry)
        });
        let (is_jump_if_true, target, consumed_end): (bool, usize, usize) =
            if reloops_on_fallthrough {
                (!cond_if_true, reentry, follower?)
            } else {
                let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])?;
                (cond_if_true, target, jump)
            };
        let valid: bool = target == reentry
            || target == exit
            || (target > jump && target <= back_edge && target >= test_start);
        if !valid {
            return None;
        }
        operands.push(CondOperand {
            expr: none_jump_test(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true,
            target,
            value_lo,
        });
        value_lo = first_significant(stream, consumed_end + 1, back_edge + 1).unwrap_or(back_edge);
        k = consumed_end + 1;
    }
    Some(operands)
}

fn recover_while_bottom_test_compound(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &LoopRegion,
) -> Option<Expr> {
    let back_op: &CanonicalOp = &stream.ops[region.back_edge];
    let bottom_tested: bool = is_cond_back_edge(back_op)
        || is_cond_jump_with_backward_target(stream, region.back_edge)
        || (is_back_edge(back_op)
            && first_significant(stream, region.body_start, region.back_edge).is_some());
    if !bottom_tested {
        return None;
    }
    let reentry: usize =
        resolve_jump_target(stream, region.back_edge, &stream.ops[region.back_edge])?;
    let exit: usize = region.exit;
    let floor: usize = region.body_start.min(region.header);
    let test_start: usize = bottom_test_span_start(stream, floor, region.back_edge);
    if test_start >= region.back_edge {
        return None;
    }
    let operands: Vec<CondOperand> =
        collect_bottom_cond_operands(code, stream, test_start, region.back_edge, reentry, exit)?;
    if operands.len() < 2 || operands.last()?.target != reentry {
        return None;
    }
    parse_cond_range(&operands, reentry, exit)
}

fn recover_entry_guard_test(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    region: &LoopRegion,
) -> Option<(usize, Expr)> {
    let body: usize = region.header;
    let exit: usize = region.exit;
    let last: usize = last_significant_back(stream, lo, region.header)?;
    if !is_forward_cond_jump(&stream.ops[last])
        || is_chain_cond_jump(&stream.ops, last)
        || is_value_form_shortcircuit(&stream.ops, last)
    {
        return None;
    }
    let mut jump_idxs: Vec<usize> = vec![last];
    let mut boundary: usize = cond_expr_start(stream, last, lo);
    while boundary > lo {
        let Some(prev): Option<usize> = last_significant_back(stream, lo, boundary) else {
            break;
        };
        if !is_forward_cond_jump(&stream.ops[prev])
            || is_chain_cond_jump(&stream.ops, prev)
            || is_value_form_shortcircuit(&stream.ops, prev)
        {
            break;
        }
        let Some(target): Option<usize> = resolve_jump_target(stream, prev, &stream.ops[prev])
        else {
            break;
        };
        if target != body && target != exit && !(target > prev && target <= region.header) {
            break;
        }
        jump_idxs.push(prev);
        boundary = cond_expr_start(stream, prev, lo);
    }
    if jump_idxs.len() < 2 {
        return None;
    }
    jump_idxs.reverse();
    let entry_start: usize = cond_expr_start(stream, jump_idxs[0], lo);
    let mut operands: Vec<CondOperand> = Vec::with_capacity(jump_idxs.len());
    let mut value_lo: usize = entry_start;
    for &jump in &jump_idxs {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[value_lo..jump]).ok()?;
        if !stmts.is_empty() {
            return None;
        }
        let value: Expr = residual.into_iter().next_back()?;
        let is_jump_if_true: bool = is_pop_cond_jump_if_true(&stream.ops[jump]);
        let target: usize = resolve_jump_target(stream, jump, &stream.ops[jump])
            .filter(|t: &usize| *t == body || *t == exit || (*t > jump && *t <= region.header))?;
        operands.push(CondOperand {
            expr: none_jump_test(stream, jump, value.clone()).unwrap_or(value),
            is_jump_if_true,
            target,
            value_lo,
        });
        value_lo = first_significant(stream, jump + 1, region.header).unwrap_or(jump + 1);
    }
    let test: Expr = parse_cond_range(&operands, body, exit)?;
    Some((entry_start, test))
}

fn redundant_entry_guard_start(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    region: &LoopRegion,
    loop_test: &Expr,
) -> Option<usize> {
    let (start, guard_test): (usize, Expr) = recover_entry_guard_test(code, stream, lo, region)?;
    exprs_equal_ignoring_lines(&guard_test, loop_test).then_some(start)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod for_target_bounds {
    use super::super::DecodedStream;
    use super::super::try_with::{LoopKind, LoopRegion};
    use super::recover_for_target;
    use crate::ast::node::Expr;
    use crate::bytecode::opcode::CanonicalOp;
    use crate::bytecode::version::PyVersion;
    use disrobe_py_marshal::{CodeEra, CodeObject, Object};

    fn code_with_names(names: &[&str]) -> CodeObject {
        let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        code.names = names
            .iter()
            .map(|n: &&str| Object::Unicode {
                value: (*n).to_owned(),
                interned: false,
            })
            .collect();
        code
    }

    fn stream_from(ops: Vec<CanonicalOp>) -> DecodedStream {
        let n: usize = ops.len();
        DecodedStream {
            ops,
            offsets: (0..n).map(|i: usize| (i as u32) * 2).collect(),
            next_offsets: (0..n).map(|i: usize| (i as u32 + 1) * 2).collect(),
            code_len: (n as u32) * 2,
            lines: vec![None; n],
            wordcode: true,
            instr_unit_jumps: true,
            relative_cond_jumps: true,
            exception_table: Vec::new(),
            pre311_end_finally_idx: std::collections::BTreeSet::new(),
            pre311_pop_block_idx: std::collections::BTreeSet::new(),
            pre311_break_loop_idx: std::collections::BTreeSet::new(),
            setup_loop_end: std::collections::BTreeMap::new(),
            none_jump_kind: std::collections::BTreeMap::new(),
            version: PyVersion::V3_12,
        }
    }

    fn for_region(header: usize, body_end: usize) -> LoopRegion {
        LoopRegion {
            kind: LoopKind::For,
            header,
            body_start: header + 1,
            body_end,
            back_edge: body_end,
            exit: body_end,
            infinite: false,
        }
    }

    #[test]
    fn build_tuple_target_huge_operand_declines_without_eager_alloc() {
        let code: CodeObject = code_with_names(&["x", "y"]);
        let stream: DecodedStream = stream_from(vec![
            CanonicalOp::ForIter(0),
            CanonicalOp::BuildTuple(u32::MAX),
            CanonicalOp::StoreName(0),
            CanonicalOp::StoreName(1),
        ]);
        let region: LoopRegion = for_region(0, 4);
        let recovered: Option<(Expr, usize)> = recover_for_target(&code, &stream, &region);
        assert!(
            recovered.is_none(),
            "a build-tuple count far exceeding the loop body must decline, not reserve gigabytes"
        );
    }

    #[test]
    fn build_tuple_target_valid_pair_recovers_both_names() {
        let code: CodeObject = code_with_names(&["x", "y"]);
        let stream: DecodedStream = stream_from(vec![
            CanonicalOp::ForIter(0),
            CanonicalOp::BuildTuple(2),
            CanonicalOp::StoreName(0),
            CanonicalOp::StoreName(1),
        ]);
        let region: LoopRegion = for_region(0, 4);
        let (target, next): (Expr, usize) =
            recover_for_target(&code, &stream, &region).expect("valid tuple target recovers");
        assert_eq!(next, 4);
        let Expr::Tuple { elts, .. } = target else {
            panic!("expected a tuple for target, found {target:?}");
        };
        let names: Vec<String> = elts
            .iter()
            .map(|e: &Expr| match e {
                Expr::Name { id, .. } => id.clone(),
                other => panic!("expected a name element, found {other:?}"),
            })
            .collect();
        assert_eq!(names, vec!["x".to_owned(), "y".to_owned()]);
    }
}
