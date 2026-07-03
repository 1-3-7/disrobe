use super::branches::{CompoundIf, jump_taken_if_true, try_recover_compound_if};
use super::exprs::{
    build_linear_stmts_sim, inner_short_circuit_polarity, is_chain_compare_jump,
    is_chain_cond_jump, local_name_at, local_target, name_at,
};
use super::function_meta::load_const;
use super::loops::non_empty;
use super::postprocess::is_implicit_none_return;
use super::stmts::{
    append_handler_loop_jump, detect_inline_comprehension, first_significant,
    last_significant_back, loads_none, resolve_jump_target, structure_stmts,
    test_is_polarity_sensitive, then_continues_to_loop, then_terminating_jump,
};
use super::{
    DecodedStream, PY_CO_FLAG_FUNCTION_SCOPE, StructureHiCapGuard, active_version,
    loop_continue_target, loop_frame_depth, none_jump_test, structure_hi_cap,
};
use crate::ast::node::{ConstValue, ExceptHandler, Expr, ExprCtx, Stmt, WithItem};
use crate::bytecode::opcode::CanonicalOp;
use crate::bytecode::version::PyVersion;
use crate::error::Result;
use disrobe_py_marshal::{CodeObject, Object};

#[allow(clippy::trivially_copy_pass_by_ref)]
pub(super) fn is_value_form_shortcircuit(ops: &[CanonicalOp], idx: usize) -> bool {
    if is_chain_compare_jump(ops, idx) {
        return false;
    }
    match ops[idx] {
        CanonicalOp::JumpIfTrueOrPop(_) | CanonicalOp::JumpIfFalseOrPop(_) => true,
        CanonicalOp::PopJumpIfTrue(_) | CanonicalOp::PopJumpIfFalse(_) => {
            let mut j: usize = idx;
            while j > 0 {
                j -= 1;
                match ops[j] {
                    CanonicalOp::ToBool | CanonicalOp::Cache | CanonicalOp::Nop => {}
                    CanonicalOp::Copy(1) => return true,
                    _ => {
                        return inner_short_circuit_polarity(ops, idx).is_some();
                    }
                }
            }
            inner_short_circuit_polarity(ops, idx).is_some()
        }
        _ => false,
    }
}

pub(super) fn is_forward_cond_jump(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
    )
}

#[derive(Debug, Clone, Copy)]
pub(super) enum LoopKind {
    For,
    AsyncFor,
    While,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct LoopRegion {
    pub(super) kind: LoopKind,
    pub(super) header: usize,
    pub(super) body_start: usize,
    pub(super) body_end: usize,
    pub(super) back_edge: usize,
    pub(super) exit: usize,

    pub(super) infinite: bool,
}

pub(super) fn is_back_edge(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::JumpAbsolute(_)
    )
}

pub(super) fn is_async_send_back_edge(stream: &DecodedStream, jump_idx: usize) -> bool {
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, jump_idx, &stream.ops[jump_idx])
    else {
        return false;
    };
    if target >= jump_idx {
        return false;
    }
    let scan_lo: usize = target.saturating_sub(2);
    (scan_lo..jump_idx).any(|k: usize| matches!(stream.ops[k], CanonicalOp::Send(_)))
}

pub(super) fn is_async_cleanup_throw_back_edge(stream: &DecodedStream, jump_idx: usize) -> bool {
    if !matches!(
        stream.ops[jump_idx],
        CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return false;
    }
    (0..jump_idx)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::CleanupThrow))
}

pub(super) fn is_cond_back_edge(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PopJumpIfFalseBackward(_) | CanonicalOp::PopJumpIfTrueBackward(_)
    )
}

pub(super) fn is_cond_jump_with_backward_target(stream: &DecodedStream, idx: usize) -> bool {
    if !matches!(
        stream.ops[idx],
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)
    ) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, idx, &stream.ops[idx]) else {
        return false;
    };
    target < idx
}

#[derive(Debug, Clone)]
pub(super) struct TryRegion {
    pub(super) try_start: usize,

    protected_end: usize,
    try_end: usize,
    pub(super) handler_start: usize,
    region_end: usize,
    is_with: bool,

    is_finally: bool,
}

impl TryRegion {
    pub(super) fn protected_end(&self) -> usize {
        self.protected_end
    }

    pub(super) fn region_end(&self) -> usize {
        self.region_end
    }

    pub(super) fn is_with(&self) -> bool {
        self.is_with
    }

    pub(super) fn is_finally(&self) -> bool {
        self.is_finally
    }
}

fn is_async_for_poll_guard(stream: &DecodedStream, try_start: usize) -> bool {
    let mut probe: usize = try_start;
    while probe < stream.ops.len()
        && matches!(
            stream.ops.get(probe),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        probe += 1;
    }
    matches!(stream.ops.get(probe), Some(CanonicalOp::GetAnext))
}

pub(super) fn extend_window_over_split_handler(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> usize {
    if stream.exception_table.is_empty() {
        return hi;
    }
    let cap: usize = structure_hi_cap();
    if cap != 0 && hi >= cap {
        return hi;
    }
    let mut end: usize = hi;
    loop {
        let mut grew: bool = false;
        for entry in &stream.exception_table {
            let Some(handler_start): Option<usize> = stream.index_for_offset(entry.target) else {
                continue;
            };
            if handler_start < lo
                || handler_start >= end
                || !matches!(
                    stream.ops.get(handler_start),
                    Some(CanonicalOp::PushExcInfo)
                )
            {
                continue;
            }
            let cold_end: Option<usize> = stream
                .exception_table
                .iter()
                .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| e.start == entry.target)
                .filter_map(|e: &crate::bytecode::flow::ExceptionTableEntry| {
                    stream.index_for_offset(e.target)
                })
                .max();
            if let Some(cold) = cold_end {
                let needed: usize = (handler_join(stream, cold, stream.ops.len())).max(cold + 1);
                if needed > end {
                    end = needed;
                    grew = true;
                }
            }
        }
        if !grew {
            break;
        }
    }
    let bounded: usize = if cap != 0 { end.min(cap) } else { end };
    bounded.min(stream.ops.len())
}

fn merged_protected_end(stream: &DecodedStream, start: u32, end: u32, target: u32) -> u32 {
    let _ = start;
    let mut body_end: u32 = end;
    while let Some(next) = stream
        .exception_table
        .iter()
        .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| {
            e.target == target && e.start >= body_end && e.start < target
        })
        .map(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start)
        .min()
    {
        if !gap_is_protected_body_join(stream, body_end, next) {
            break;
        }
        let extended: u32 = stream
            .exception_table
            .iter()
            .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| {
                e.target == target && e.start == next
            })
            .map(|e: &crate::bytecode::flow::ExceptionTableEntry| e.end())
            .max()
            .unwrap_or(body_end);
        if extended <= body_end {
            break;
        }
        body_end = extended;
    }
    body_end
}

fn gap_is_protected_body_join(stream: &DecodedStream, lo_off: u32, hi_off: u32) -> bool {
    let Some(lo): Option<usize> = stream.index_for_offset_ceil(lo_off) else {
        return false;
    };
    let Some(hi): Option<usize> = stream.index_for_offset_ceil(hi_off) else {
        return false;
    };
    if lo >= hi {
        return true;
    }
    let all_benign: bool = (lo..hi).all(|k: usize| gap_op_is_exit_arm(&stream.ops[k]));
    if !all_benign {
        return false;
    }
    let Some(last): Option<usize> = last_significant_back(stream, lo, hi) else {
        return true;
    };
    matches!(
        stream.ops[last],
        CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
    )
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn gap_op_is_exit_arm(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
            | CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadFastLoadFast(_, _)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::Pop
            | CanonicalOp::Copy(_)
            | CanonicalOp::Swap(_)
            | CanonicalOp::RotN(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
    )
}

fn with_protected_body_end(stream: &DecodedStream, start: u32, end: u32, target: u32) -> u32 {
    let _ = start;
    let mut body_end: u32 = end;
    while let Some(next) = stream
        .exception_table
        .iter()
        .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| {
            e.target == target && e.start >= body_end && e.start < target
        })
        .map(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start)
        .min()
    {
        if !gap_is_with_early_exit(stream, body_end, next) {
            break;
        }
        let extended: u32 = stream
            .exception_table
            .iter()
            .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| {
                e.target == target && e.start == next
            })
            .map(|e: &crate::bytecode::flow::ExceptionTableEntry| e.end())
            .max()
            .unwrap_or(body_end);
        if extended <= body_end {
            break;
        }
        body_end = extended;
    }
    body_end
}

fn gap_is_with_early_exit(stream: &DecodedStream, lo_off: u32, hi_off: u32) -> bool {
    let Some(lo): Option<usize> = stream.index_for_offset_ceil(lo_off) else {
        return false;
    };
    let Some(hi): Option<usize> = stream.index_for_offset_ceil(hi_off) else {
        return false;
    };
    if lo >= hi {
        return false;
    }
    let Some(after_cleanup): Option<usize> = skip_with_cleanup_block(stream, lo, hi) else {
        return false;
    };
    (after_cleanup..hi).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::LoadConst(_)
                | CanonicalOp::LoadSmallInt(_)
                | CanonicalOp::LoadCommonConst(_)
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_)
        )
    })
}

fn with_terminal_cleanup_within(stream: &DecodedStream, try_start: usize, hi: usize) -> bool {
    (try_start..hi).any(|i: usize| {
        is_none_const_push(&stream.ops[i])
            && is_exit_none_triple(stream, i, hi)
            && (with_cleanup_tail_is_pure(stream, i, hi)
                || skip_with_cleanup_block(stream, i, hi).is_some())
    })
}

pub(super) fn find_try_region(stream: &DecodedStream, lo: usize, hi: usize) -> Option<TryRegion> {
    if stream.exception_table.is_empty() {
        return None;
    }
    let mut best: Option<TryRegion> = None;
    for entry in &stream.exception_table {
        let Some(try_start): Option<usize> = stream.index_for_offset(entry.start) else {
            continue;
        };
        let Some(handler_start): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        let is_modern: bool = matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        );
        let is_with: bool = is_modern
            && matches!(
                stream.ops.get(handler_start + 1),
                Some(CanonicalOp::WithExceptStart)
            );
        let with_handler_escapes: bool = is_with
            && handler_start >= hi
            && with_setup_start(stream, try_start, lo) < try_start
            && with_terminal_cleanup_within(stream, try_start, hi);
        if !(lo..hi).contains(&try_start) || (handler_start >= hi && !with_handler_escapes) {
            continue;
        }
        if matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::EndAsyncFor)
        ) {
            continue;
        }
        if is_async_for_poll_guard(stream, try_start) {
            continue;
        }
        let is_pre311_handler: bool = !is_modern
            && stream.is_pre_311()
            && is_pre311_except_or_finally_handler(stream, handler_start, hi);
        if !is_modern && !is_pre311_handler {
            continue;
        }
        let setup_start: usize = if is_with {
            let raw: usize = with_setup_start(stream, try_start, lo);
            clamp_with_setup_to_enclosing_except_star(stream, raw, try_start, hi)
        } else {
            try_start
        };
        let body_end_off: u32 = if is_modern && !is_with {
            merged_protected_end(stream, entry.start, entry.end(), entry.target)
        } else if is_with {
            with_protected_body_end(stream, entry.start, entry.end(), entry.target)
        } else {
            entry.end()
        };
        let body_bound: usize = handler_start.min(hi);
        let protected_end: usize = stream
            .index_for_offset_ceil(body_end_off)
            .unwrap_or(body_bound)
            .min(body_bound);
        let try_end: usize = stream
            .index_for_offset(body_end_off)
            .unwrap_or(body_bound)
            .min(body_bound);
        let finally_probe_end: usize = if is_pre311_handler {
            pre311_handler_region_end(stream, handler_start, hi)
        } else {
            handler_join(stream, handler_start, hi)
        };
        let is_finally: bool = !is_with
            && is_pure_finally_handler_shape(
                stream,
                handler_start,
                finally_probe_end.min(hi),
                is_pre311_handler,
            );
        let region_end: usize = if with_handler_escapes {
            hi
        } else if is_pre311_handler {
            finally_probe_end
        } else if !is_with && !is_finally {
            let join_end: usize = finally_probe_end;
            handler_region_end_named(stream, handler_start, hi)
                .filter(|&chain_end: &usize| {
                    !sibling_handler_between(stream, handler_start, chain_end, join_end)
                })
                .unwrap_or(join_end)
        } else {
            finally_probe_end
        };
        let candidate: TryRegion = TryRegion {
            try_start: setup_start,
            protected_end,
            try_end,
            handler_start: handler_start.min(hi),
            region_end: region_end.min(hi),
            is_with,
            is_finally,
        };
        if best
            .as_ref()
            .is_none_or(|b: &TryRegion| candidate.try_start < b.try_start)
        {
            best = Some(candidate);
        }
    }
    best
}

fn find_protected_try_with_outer_handler(
    stream: &DecodedStream,
    lo: usize,
    body_hi: usize,
    outer_hi: usize,
) -> Option<TryRegion> {
    if stream.exception_table.is_empty() {
        return None;
    }
    let mut best: Option<TryRegion> = None;
    for entry in &stream.exception_table {
        let try_start: usize = stream.index_for_offset(entry.start)?;
        let handler_start: usize = stream.index_for_offset(entry.target)?;
        if !(lo..body_hi).contains(&try_start)
            || handler_start < body_hi
            || handler_start >= outer_hi
        {
            continue;
        }
        if !matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        ) {
            continue;
        }
        if matches!(
            stream.ops.get(handler_start + 1),
            Some(CanonicalOp::WithExceptStart)
        ) {
            continue;
        }
        let body_end_off: u32 =
            merged_protected_end(stream, entry.start, entry.end(), entry.target);
        let protected_end: usize = stream
            .index_for_offset_ceil(body_end_off)
            .unwrap_or(handler_start)
            .min(handler_start);
        let try_end: usize = stream
            .index_for_offset(body_end_off)
            .unwrap_or(handler_start)
            .min(handler_start);
        let region_end: usize = handler_join(stream, handler_start, outer_hi).min(outer_hi);
        let is_finally: bool =
            is_pure_finally_handler_shape(stream, handler_start, region_end, false);
        let candidate: TryRegion = TryRegion {
            try_start,
            protected_end,
            try_end,
            handler_start,
            region_end,
            is_with: false,
            is_finally,
        };
        if best
            .as_ref()
            .is_none_or(|b: &TryRegion| candidate.try_start < b.try_start)
        {
            best = Some(candidate);
        }
    }
    best
}

fn is_handler_target(stream: &DecodedStream, byte_off: u32) -> bool {
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| e.target == byte_off)
}

fn leading_ops_are_stmt_setup(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).all(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Push(_)
                | CanonicalOp::LoadGlobal(_)
                | CanonicalOp::LoadFast(_)
                | CanonicalOp::LoadFastLoadFast(_, _)
                | CanonicalOp::LoadName(_)
                | CanonicalOp::LoadConst(_)
                | CanonicalOp::Nop
                | CanonicalOp::Cache
                | CanonicalOp::ExtendedArg(_)
        )
    })
}

fn stmt_boundary_at_or_before(stream: &DecodedStream, lo: usize, try_start: usize) -> usize {
    let mut head_end: usize = try_start;
    let mut k: usize = try_start;
    while k > lo && leading_ops_are_stmt_setup(stream, k - 1, try_start) {
        k -= 1;
        let mut prev: usize = k;
        while prev > lo
            && matches!(
                stream.ops[prev - 1],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        {
            prev -= 1;
        }
        if prev == lo || is_value_boundary_at(stream, prev - 1) {
            head_end = k;
        }
    }
    head_end
}

pub(super) fn try_structure_cold_sibling_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if stream.is_pre_311() || stream.exception_table.is_empty() {
        return Ok(None);
    }
    let cap: usize = structure_hi_cap();
    let outer_hi: usize = if cap == 0 {
        stream.ops.len()
    } else {
        cap.min(stream.ops.len())
    };
    let Some(region): Option<TryRegion> =
        find_protected_try_with_outer_handler(stream, lo, hi, outer_hi)
    else {
        return Ok(None);
    };
    let Some(body_start): Option<usize> = first_significant(stream, lo, hi) else {
        return Ok(None);
    };
    let head_end: usize = stmt_boundary_at_or_before(stream, body_start, region.try_start);
    let intervening_sibling_handler: bool = (hi..region.handler_start).any(|k: usize| {
        matches!(stream.ops.get(k), Some(CanonicalOp::PushExcInfo))
            && stream
                .offsets
                .get(k)
                .copied()
                .is_some_and(|off: u32| is_handler_target(stream, off))
    });
    if region.is_with
        || region.is_finally
        || head_end > region.try_start
        || head_end < body_start
        || !leading_ops_are_stmt_setup(stream, head_end, region.try_start)
        || region.handler_start < hi
        || region.protected_end <= region.try_start
        || region.protected_end > hi
        || !intervening_sibling_handler
    {
        return Ok(None);
    }
    let region_end: usize = handler_join(stream, region.handler_start, outer_hi);
    let body_end: usize = protected_body_end_with_return(
        stream,
        region.try_start,
        region.protected_end,
        region.handler_start.min(hi),
    );
    let head: Vec<Stmt> = if head_end > body_start {
        structure_stmts(code, stream, body_start, head_end)?
    } else {
        Vec::new()
    };
    let body: Vec<Stmt> = {
        let _body_cap: StructureHiCapGuard = StructureHiCapGuard::enter(body_end);
        structure_stmts(code, stream, region.try_start, body_end)?
    };
    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, region_end)?;
    if handlers.is_empty() {
        return Ok(None);
    }
    let tail: Vec<Stmt> = structure_stmts(code, stream, body_end, hi)?;
    let handlers: Vec<ExceptHandler> = match tail.last() {
        Some(last) => strip_shared_exit_return(handlers, std::slice::from_ref(last)),
        None => handlers,
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::Try {
        body: non_empty(body),
        handlers,
        orelse: Vec::new(),
        finalbody: Vec::new(),
        line: None,
    });
    out.extend(tail);
    Ok(Some(out))
}

fn empty_try_handler_start(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    for k in lo..hi {
        if !matches!(stream.ops.get(k), Some(CanonicalOp::PushExcInfo)) {
            continue;
        }
        let handler_off: u32 = stream.offsets.get(k).copied()?;
        let is_self_protecting: bool = stream
            .exception_table
            .iter()
            .any(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start == handler_off);
        if is_self_protecting && !is_handler_target(stream, handler_off) {
            return Some(k);
        }
    }
    None
}

pub(super) fn try_structure_empty_body_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if stream.is_pre_311() || stream.exception_table.is_empty() {
        return Ok(None);
    }
    let Some(handler_start): Option<usize> = empty_try_handler_start(stream, lo, hi) else {
        return Ok(None);
    };
    let body_term: usize = stmt_boundary_at_or_before(stream, lo, handler_start);
    if body_term > handler_start {
        return Ok(None);
    }
    let is_star: bool = (handler_start..hi)
        .take_while(|&k: &usize| k < handler_start + 64)
        .any(|k: usize| matches!(stream.ops.get(k), Some(CanonicalOp::CheckEgMatch)));
    let region_end: usize = handler_chain_end(stream, handler_start, hi).unwrap_or(hi);
    let continuation: Vec<Stmt> = structure_stmts(code, stream, lo, body_term)?;
    let handlers: Vec<ExceptHandler> = if is_star {
        parse_except_star_handlers(code, stream, handler_start, region_end)?
    } else {
        parse_except_handlers(code, stream, handler_start, region_end)?
    };
    if handlers.is_empty() {
        return Ok(None);
    }
    let tail: Vec<Stmt> = structure_stmts(code, stream, region_end, hi)?;
    let shared_exit: Vec<Stmt> = if continuation.is_empty() {
        tail.clone()
    } else {
        continuation.clone()
    };
    let handlers: Vec<ExceptHandler> = strip_shared_exit_suffix(handlers, &shared_exit);
    let mut out: Vec<Stmt> = Vec::new();
    let try_stmt: Stmt = if is_star {
        Stmt::TryStar {
            body: vec![Stmt::Pass],
            handlers,
            orelse: Vec::new(),
            finalbody: Vec::new(),
            line: None,
        }
    } else {
        Stmt::Try {
            body: vec![Stmt::Pass],
            handlers,
            orelse: Vec::new(),
            finalbody: Vec::new(),
            line: None,
        }
    };
    out.push(try_stmt);
    out.extend(continuation);
    out.extend(tail);
    Ok(Some(out))
}

fn is_pre311_except_or_finally_handler(
    stream: &DecodedStream,
    handler_start: usize,
    hi: usize,
) -> bool {
    if handler_start >= hi {
        return false;
    }
    let mut probe: usize = handler_start;
    while probe < hi
        && matches!(
            stream.ops.get(probe),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        probe += 1;
    }
    if matches!(
        stream.ops.get(probe),
        Some(CanonicalOp::Dup | CanonicalOp::Pop)
    ) {
        return true;
    }
    is_pre311_finally_handler_shape(stream, handler_start, hi)
}

fn clamp_with_setup_to_enclosing_except_star(
    stream: &DecodedStream,
    raw_setup_start: usize,
    with_try_start: usize,
    hi: usize,
) -> usize {
    let mut clamped: usize = raw_setup_start;
    for entry in &stream.exception_table {
        let Some(enclosing_start): Option<usize> = stream.index_for_offset(entry.start) else {
            continue;
        };
        if enclosing_start <= raw_setup_start || enclosing_start > with_try_start {
            continue;
        }
        let Some(handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if handler >= hi {
            continue;
        }
        if !matches!(stream.ops.get(handler), Some(CanonicalOp::PushExcInfo)) {
            continue;
        }
        if !handler_is_except_star(stream, handler) {
            continue;
        }
        if enclosing_start > clamped {
            clamped = enclosing_start;
        }
    }
    clamped
}

fn handler_is_except_star(stream: &DecodedStream, handler: usize) -> bool {
    if first_significant(stream, handler + 1, stream.ops.len())
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))
    {
        return false;
    }
    let block_end: usize = (handler + 1..stream.ops.len())
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
        .unwrap_or(stream.ops.len());
    (handler..block_end).any(|k: usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch))
}

fn pre311_reraise_inside_nested(
    stream: &DecodedStream,
    handler_start: usize,
    reraise: usize,
    hi: usize,
) -> bool {
    stream.exception_table.iter().any(|entry| {
        let Some(nested_try): Option<usize> = stream.index_for_offset(entry.start) else {
            return false;
        };
        let Some(nested_handler): Option<usize> = stream.index_for_offset(entry.target) else {
            return false;
        };
        if nested_handler <= handler_start
            || nested_handler > reraise
            || nested_try <= handler_start
        {
            return false;
        }
        let nested_end: usize = pre311_handler_region_end(stream, nested_handler, hi);
        nested_try <= reraise && reraise < nested_end
    })
}

fn pre311_handler_region_end(stream: &DecodedStream, handler_start: usize, hi: usize) -> usize {
    let mut i: usize = handler_start;
    let mut last_end: usize = handler_start;
    let mut last_raise: usize = handler_start;
    while i < hi {
        let is_terminator: bool = matches!(stream.ops[i], CanonicalOp::Reraise(_))
            || stream.pre311_end_finally_idx.contains(&i);
        if is_terminator && !pre311_reraise_inside_nested(stream, handler_start, i, hi) {
            last_end = i + 1;
            break;
        }
        if matches!(stream.ops[i], CanonicalOp::Raise(_)) {
            last_raise = i + 1;
        }
        i += 1;
    }
    let prefer_raise: bool = last_end == handler_start
        || (last_raise > last_end && pre311_trailing_bare_except(stream, last_end, last_raise));
    if prefer_raise {
        last_raise.min(hi)
    } else {
        last_end.min(hi)
    }
}

fn pre311_trailing_bare_except(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let Some(first): Option<usize> = first_significant(stream, lo, hi) else {
        return false;
    };
    if !matches!(stream.ops[first], CanonicalOp::Pop) {
        return false;
    }
    let mut pops: u32 = 0;
    let mut k: usize = first;
    while k < hi && matches!(stream.ops[k], CanonicalOp::Pop) {
        pops += 1;
        k += 1;
    }
    pops >= 3
}

fn with_setup_start(stream: &DecodedStream, try_start: usize, lo: usize) -> usize {
    let mut i: usize = try_start;
    while i > lo
        && matches!(
            stream.ops.get(i - 1),
            Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_) | CanonicalOp::Pop)
        )
    {
        i -= 1;
    }
    if i > lo && matches!(stream.ops.get(i - 1), Some(CanonicalOp::BeforeWith)) {
        let mut j: usize = i - 1;
        while j > lo && !is_value_boundary_at(stream, j - 1) {
            j -= 1;
        }
        return j;
    }
    if let Some(prologue_start) = async_with_prologue_start(stream, try_start, lo) {
        return prologue_start;
    }
    if let Some(prologue_start) = modern_with_prologue_start(stream, i, lo) {
        return prologue_start;
    }
    try_start
}

fn async_with_prologue_start(stream: &DecodedStream, try_start: usize, lo: usize) -> Option<usize> {
    let awaitable: usize = (lo..try_start)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))?;
    let before: usize = (lo..awaitable).rev().find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::BeforeAsyncWith | CanonicalOp::Copy(1)
        )
    })?;
    match stream.ops.get(before) {
        Some(CanonicalOp::BeforeAsyncWith) => {
            let mut j: usize = before;
            while j > lo && !is_value_boundary_at(stream, j - 1) {
                j -= 1;
            }
            Some(j)
        }
        Some(CanonicalOp::Copy(1))
            if first_significant(stream, before + 1, awaitable)
                .is_some_and(|s: usize| matches!(stream.ops[s], CanonicalOp::LoadSpecial(_))) =>
        {
            let mut j: usize = before;
            while j > lo && !is_value_boundary_at(stream, j - 1) {
                j -= 1;
            }
            Some(j)
        }
        _ => None,
    }
}

fn modern_with_prologue_start(stream: &DecodedStream, store_at: usize, lo: usize) -> Option<usize> {
    let call: usize = (lo..store_at)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !matches!(stream.ops[call], CanonicalOp::CallFunction(0)) {
        return None;
    }
    let enter: usize = (lo..call)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !matches!(stream.ops[enter], CanonicalOp::LoadSpecial(0)) {
        return None;
    }
    let copy: usize = (lo..enter)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Copy(1)))?;
    let mut j: usize = copy;
    while j > lo && !is_value_boundary_at(stream, j - 1) {
        j -= 1;
    }
    Some(j)
}

pub(super) fn is_comprehension_expr(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::ListComp { .. }
            | Expr::SetComp { .. }
            | Expr::DictComp { .. }
            | Expr::GeneratorExp { .. }
    )
}

pub(super) fn is_value_boundary(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::Pop
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::BeforeWith
    )
}

fn is_value_boundary_at(stream: &DecodedStream, idx: usize) -> bool {
    match stream.ops[idx] {
        CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_)
            if is_value_form_shortcircuit(&stream.ops, idx) =>
        {
            false
        }
        CanonicalOp::Pop if is_shortcircuit_cleanup_pop(stream, idx) => false,
        CanonicalOp::Raise(_) | CanonicalOp::Reraise(_) => true,
        _ => is_value_boundary(&stream.ops[idx]),
    }
}

pub(super) fn is_shortcircuit_cleanup_pop(stream: &DecodedStream, idx: usize) -> bool {
    let mut j: usize = idx;
    while j > 0 {
        j -= 1;
        match stream.ops[j] {
            CanonicalOp::Nop | CanonicalOp::Cache => {}
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_) => {
                return is_value_form_shortcircuit(&stream.ops, j);
            }
            _ => return false,
        }
    }
    false
}

pub(super) fn handler_join(stream: &DecodedStream, handler_start: usize, hi: usize) -> usize {
    let mut last_reraise: usize = handler_start;
    let mut i: usize = handler_start;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Reraise(_)) {
            last_reraise = i;
        }
        i += 1;
    }
    (last_reraise + 1).min(hi)
}

pub(super) fn handler_chain_end(
    stream: &DecodedStream,
    handler_start: usize,
    hi: usize,
) -> Option<usize> {
    let handler_off: u32 = stream.offsets.get(handler_start).copied()?;
    let handler_depth: u8 = stream
        .exception_table
        .iter()
        .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| e.target == handler_off)
        .map(|e: &crate::bytecode::flow::ExceptionTableEntry| e.depth)
        .max()
        .map(|d: u8| d.saturating_add(1))?;
    let mut region_end_off: u32 = handler_off;
    loop {
        let mut grew: bool = false;
        for entry in &stream.exception_table {
            if entry.start < handler_off
                || entry.start > region_end_off
                || entry.depth < handler_depth
            {
                continue;
            }
            let reach: u32 = entry.end().max(entry.target);
            if reach > region_end_off {
                region_end_off = reach;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    let from: usize = stream.index_for_offset_ceil(region_end_off)?;
    Some(handler_cold_cleanup_end(stream, from, hi).clamp(handler_start + 1, hi))
}

fn handler_region_end_named(
    stream: &DecodedStream,
    handler_start: usize,
    hi: usize,
) -> Option<usize> {
    let chain_end: usize = handler_chain_end(stream, handler_start, hi)?;
    let after_cleanup: usize = skip_handler_name_cleanup(stream, chain_end, hi);
    if after_cleanup == chain_end {
        return Some(chain_end);
    }
    Some(handler_cold_cleanup_end(stream, after_cleanup, hi).max(chain_end))
}

fn sibling_handler_between(
    stream: &DecodedStream,
    handler_start: usize,
    chain_end: usize,
    join_end: usize,
) -> bool {
    let own_off: u32 = match stream.offsets.get(handler_start) {
        Some(&o) => o,
        None => return false,
    };
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            if e.target == own_off || e.start >= own_off {
                return false;
            }
            stream
                .index_for_offset(e.target)
                .is_some_and(|t: usize| (chain_end..join_end).contains(&t))
        })
}

fn handler_cold_cleanup_end(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut k: usize = from;
    let mut last: usize = from;
    while k < hi {
        match stream.ops[k] {
            CanonicalOp::Reraise(_) => {
                last = k;
                break;
            }
            CanonicalOp::Copy(_)
            | CanonicalOp::Swap(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {
                k += 1;
            }
            _ => break,
        }
    }
    (last + 1).max(from).min(hi)
}

fn except_star_body_end(stream: &DecodedStream, region: &TryRegion, truncated_end: usize) -> usize {
    let has_nested_with: bool = (region.try_start..region.handler_start)
        .any(|k: usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart));
    if !has_nested_with || truncated_end >= region.handler_start {
        return truncated_end;
    }
    trim_try_body_jump(stream, region.try_start, region.handler_start)
}

fn except_star_normal_exit_span(
    stream: &DecodedStream,
    region: &TryRegion,
) -> Option<(usize, usize)> {
    let intrinsic: usize = (region.handler_start..region.region_end)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallIntrinsic2(_)))?;
    let guard_jump: usize = (intrinsic + 1..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopJumpIfTrue(_)))?;
    let pop_except: usize = (guard_jump + 1..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopExcept))?;
    let tail_start: usize = first_significant(stream, pop_except + 1, region.region_end)?;
    let cold_start: usize = (tail_start..region.region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Swap(_) | CanonicalOp::Reraise(_)
        )
    })?;
    if tail_start >= cold_start || !slice_has_real_stmt(stream, tail_start, cold_start) {
        return None;
    }
    Some((tail_start, cold_start))
}

fn except_star_nested_with_epilogue_span(
    stream: &DecodedStream,
    region: &TryRegion,
) -> Option<(usize, usize)> {
    let with_except: usize = (region.try_start..region.handler_start)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))?;
    let with_handler_start: usize = (region.try_start..with_except)
        .rev()
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))?;
    let cleanup_triple: usize =
        (region.try_start..with_handler_start)
            .rev()
            .find(|&k: &usize| {
                is_none_const_push(&stream.ops[k])
                    && is_exit_none_triple(stream, k, with_handler_start)
            })?;
    let epilogue_start: usize = async_with_cleanup_end(stream, cleanup_triple, with_handler_start)?;
    if !async_with_exit_guarded_by_branch(stream, epilogue_start, with_handler_start) {
        return None;
    }
    let epilogue_end: usize = except_star_epilogue_end(stream, epilogue_start, with_handler_start)?;
    if epilogue_start >= epilogue_end || !slice_has_real_stmt(stream, epilogue_start, epilogue_end)
    {
        return None;
    }
    Some((epilogue_start, epilogue_end))
}

fn except_star_epilogue_end(
    stream: &DecodedStream,
    epilogue_start: usize,
    with_handler_start: usize,
) -> Option<usize> {
    (epilogue_start..with_handler_start)
        .rev()
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return | CanonicalOp::ReturnConst(_)
            )
        })
        .map(|last_return: usize| last_return + 1)
}

fn extend_protected_end_over_comp(
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
) -> usize {
    let mut end: usize = protected_end.max(try_start);
    while let Some(comp) = detect_inline_comprehension(stream, try_start, handler_start) {
        if comp.clear_idx >= end || comp.end_for <= end {
            break;
        }
        let mut new_end: usize = comp.end_for;
        while new_end < handler_start
            && matches!(
                stream.ops[new_end],
                CanonicalOp::Pop
                    | CanonicalOp::Swap(_)
                    | CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::StoreFast(_)
            )
        {
            new_end += 1;
        }
        if new_end <= end {
            break;
        }
        end = new_end;
    }
    end.min(handler_start)
}

fn guard_is_inside_protected_try_with_continuation(
    stream: &DecodedStream,
    guard: usize,
    false_target: usize,
    region: &TryRegion,
) -> bool {
    let Some(&handler_off): Option<&u32> = stream.offsets.get(region.handler_start) else {
        return false;
    };
    let Some(&guard_off): Option<&u32> = stream.offsets.get(guard) else {
        return false;
    };
    let guard_protected_by_handler: bool =
        stream
            .exception_table
            .iter()
            .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
                e.start <= guard_off && guard_off < e.end() && e.target == handler_off
            });
    if !guard_protected_by_handler {
        return false;
    }
    handler_normal_exit_is_backjump_at_or_after(
        stream,
        region.handler_start,
        region.region_end,
        false_target,
    )
}

fn handler_normal_exit_is_backjump_at_or_after(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
    floor: usize,
) -> bool {
    let Some(pop_except): Option<usize> = handler_pop_except_idx(stream, handler_start, region_end)
    else {
        return false;
    };
    let scan_hi: usize = region_end.min(stream.ops.len());
    let after_teardown: usize = skip_except_name_teardown(stream, pop_except + 1, scan_hi);
    let Some(next): Option<usize> = first_significant(stream, after_teardown, scan_hi) else {
        return false;
    };
    if !matches!(
        stream.ops[next],
        CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
    ) {
        return false;
    }
    resolve_jump_target(stream, next, &stream.ops[next]).is_some_and(|t: usize| t >= floor)
}

fn guarded_span_is_try_else(
    stream: &DecodedStream,
    try_start: usize,
    body_end: usize,
    false_target: usize,
    handler_start: usize,
    region_end: usize,
) -> bool {
    if body_end >= false_target {
        return false;
    }
    if first_significant(stream, body_end, false_target).is_none() {
        return false;
    }
    let body_completes_into_span: bool = last_significant_back(stream, try_start, body_end)
        .is_none_or(|k: usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Return
                    | CanonicalOp::ReturnConst(_)
                    | CanonicalOp::Raise(_)
                    | CanonicalOp::Reraise(_)
                    | CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpBackwardNoInterrupt(_)
            )
        });
    if !body_completes_into_span {
        return false;
    }
    if (body_end..false_target).any(|k: usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo)) {
        return false;
    }
    handler_normal_exit_backjumps_to(stream, handler_start, region_end, false_target)
        && !handler_normal_exit_backjumps_to(stream, handler_start, region_end, body_end)
}

fn guarded_body_falls_through_to(
    stream: &DecodedStream,
    try_start: usize,
    false_target: usize,
    continuation_end: usize,
) -> bool {
    if try_start >= false_target {
        return false;
    }
    let skips_else: bool = (try_start..false_target).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
        ) && resolve_jump_target(stream, k, &stream.ops[k])
            .is_some_and(|t: usize| t >= continuation_end)
    });
    if skips_else {
        return false;
    }
    let Some(last): Option<usize> = last_significant_back(stream, try_start, false_target) else {
        return true;
    };
    if !matches!(
        stream.ops[last],
        CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
    ) {
        return true;
    }
    trailing_terminator_is_conditional(stream, try_start, last, false_target)
}

fn trailing_terminator_is_conditional(
    stream: &DecodedStream,
    lo: usize,
    terminator: usize,
    false_target: usize,
) -> bool {
    let mut k: usize = terminator;
    while k > lo {
        let Some(prev): Option<usize> = last_significant_back(stream, lo, k) else {
            return false;
        };
        match stream.ops[prev] {
            CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadSmallInt(_)
            | CanonicalOp::LoadCommonConst(_)
            | CanonicalOp::LoadFast(_)
            | CanonicalOp::LoadFastLoadFast(_, _)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadGlobal(_) => k = prev,
            _ if is_forward_cond_jump(&stream.ops[prev])
                && !is_chain_cond_jump(&stream.ops, prev) =>
            {
                return resolve_jump_target(stream, prev, &stream.ops[prev])
                    .is_some_and(|t: usize| t > terminator && t <= false_target);
            }
            _ => return false,
        }
    }
    false
}

fn handler_return_idiom_duplicates_continuation(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
    false_target: usize,
    continuation_end: usize,
) -> Option<usize> {
    if false_target >= continuation_end {
        return None;
    }
    let pop_except: usize = handler_pop_except_idx(stream, handler_start, region_end)?;
    let handler_tail_lo: usize = skip_handler_name_cleanup(stream, pop_except + 1, region_end);
    let cont_ops: Vec<&CanonicalOp> = significant_ops(stream, false_target, continuation_end);
    let tail_ops: Vec<&CanonicalOp> = significant_ops(stream, handler_tail_lo, region_end);
    if cont_ops.is_empty() || !tail_ops.starts_with(cont_ops.as_slice()) {
        return None;
    }
    Some(pop_except)
}

pub(super) fn try_structure_guarded_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    let Some(first_cond): Option<usize> = (lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    let compound: Option<CompoundIf> = try_recover_compound_if(code, stream, lo, hi)?;
    let conjunct_guard: Option<usize> = compound
        .as_ref()
        .map(|c: &CompoundIf| c.last_jump)
        .filter(|&last: &usize| last >= first_cond)
        .filter(|&last: &usize| {
            let Some(exit): Option<usize> = resolve_jump_target(stream, last, &stream.ops[last])
            else {
                return false;
            };
            (first_cond..=last)
                .filter(|&k: &usize| {
                    is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
                })
                .all(|k: usize| resolve_jump_target(stream, k, &stream.ops[k]) == Some(exit))
        });
    let guard: usize = conjunct_guard.unwrap_or(first_cond);
    if conjunct_guard.is_none()
        && (lo..guard).any(|k: usize| {
            is_forward_cond_jump(&stream.ops[k])
                && !is_chain_cond_jump(&stream.ops, k)
                && !is_value_form_shortcircuit(&stream.ops, k)
                && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
        })
    {
        return Ok(None);
    }
    let Some(false_target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|t: &usize| *t > guard && *t < hi)
    else {
        return Ok(None);
    };
    let Some(region): Option<TryRegion> =
        find_protected_try_with_outer_handler(stream, guard + 1, false_target, hi)
    else {
        return Ok(None);
    };
    if region.is_finally
        || region.try_start <= guard
        || region.try_start >= false_target
        || region.handler_start < false_target
        || guard_is_inside_protected_try_with_continuation(stream, guard, false_target, &region)
        || first_significant(stream, false_target, region.handler_start).is_none()
    {
        return Ok(None);
    }
    let inner_guard_before_try: bool = (guard + 1..region.try_start).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    });
    let (head, test): (Vec<Stmt>, Expr) = if let Some(c) = compound {
        (c.head, c.test)
    } else {
        let (head, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
        if !head.is_empty() {
            return Ok(None);
        }
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
        (head, test)
    };
    let comp_end: usize = extend_protected_end_over_comp(
        stream,
        region.try_start,
        region.protected_end,
        false_target,
    );
    let body_end: usize =
        protected_body_end_with_return(stream, region.try_start, comp_end, region.handler_start);
    let body_end: usize =
        extend_body_over_trailing_guard(stream, region.try_start, body_end, false_target);
    let continuation_end: usize =
        trim_trailing_comp_cleanup(stream, false_target, region.handler_start);
    let dup_pop_except: Option<usize> = handler_return_idiom_duplicates_continuation(
        stream,
        region.handler_start,
        region.region_end,
        false_target,
        continuation_end,
    );
    let handler_region_end: usize = dup_pop_except.map_or(region.region_end, |pop: usize| pop + 1);
    let if_body: Vec<Stmt> = if inner_guard_before_try {
        let body_start: usize =
            first_significant(stream, guard + 1, false_target).unwrap_or(guard + 1);
        structure_stmts(code, stream, body_start, region.region_end)?
    } else {
        let try_body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
        let handlers: Vec<ExceptHandler> =
            parse_except_handlers(code, stream, region.handler_start, handler_region_end)?;
        let span_is_else: bool = guarded_span_is_try_else(
            stream,
            region.try_start,
            body_end,
            false_target,
            region.handler_start,
            region.region_end,
        );
        let try_orelse: Vec<Stmt> = if span_is_else {
            structure_stmts(code, stream, body_end, false_target)?
        } else {
            Vec::new()
        };
        let try_stmt: Stmt = Stmt::Try {
            body: non_empty(try_body),
            handlers,
            orelse: try_orelse,
            finalbody: Vec::new(),
            line: None,
        };
        let mut body: Vec<Stmt> = vec![try_stmt];
        if !span_is_else {
            body.extend(structure_stmts(code, stream, body_end, false_target)?);
        }
        body
    };

    let else_join: Option<usize> = then_terminating_jump(stream, region.try_start, false_target)
        .and_then(|j: usize| resolve_jump_target(stream, j, &stream.ops[j]))
        .filter(|t: &usize| *t > false_target && *t < region.handler_start);
    let trailing_is_continuation: bool = else_join.is_none()
        && (dup_pop_except.is_some()
            || handler_normal_exit_backjumps_to(
                stream,
                region.handler_start,
                region.region_end,
                false_target,
            )
            || guarded_body_falls_through_to(
                stream,
                region.try_start,
                false_target,
                continuation_end,
            ));
    let loop_elif_end: Option<usize> = if trailing_is_continuation {
        loop_elif_arm_end(stream, false_target, continuation_end)
    } else {
        None
    };
    let orelse: Vec<Stmt> = if let Some(elif_end) = loop_elif_end {
        structure_stmts(code, stream, false_target, elif_end)?
    } else if trailing_is_continuation {
        Vec::new()
    } else if let Some(join) = else_join {
        structure_stmts(code, stream, false_target, join)?
    } else {
        structure_stmts(code, stream, false_target, continuation_end)?
    };
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(if_body),
        orelse,
        line: None,
    });
    if let Some(elif_end) = loop_elif_end {
        out.extend(structure_stmts(code, stream, elif_end, continuation_end)?);
    } else if trailing_is_continuation {
        out.extend(structure_stmts(
            code,
            stream,
            false_target,
            continuation_end,
        )?);
    }
    if let Some(join) = else_join
        && join < region.handler_start
    {
        out.extend(structure_stmts(code, stream, join, region.handler_start)?);
    }
    out.extend(structure_stmts(code, stream, region.region_end, hi)?);
    Ok(Some(out))
}

fn loop_elif_arm_end(
    stream: &DecodedStream,
    false_target: usize,
    continuation_end: usize,
) -> Option<usize> {
    if false_target >= continuation_end {
        return None;
    }
    let elif_guard: usize = (false_target..continuation_end).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    })?;
    if (false_target..elif_guard).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    }) {
        return None;
    }
    let region: TryRegion = find_try_region(stream, elif_guard + 1, stream.ops.len())?;
    if region.is_with
        || region.is_finally
        || region.try_start <= elif_guard
        || region.try_start >= continuation_end
        || region.handler_start < continuation_end
    {
        return None;
    }
    let scan_end: usize = continuation_end.min(stream.ops.len());
    let elif_loopback: usize = (region.try_start..scan_end).rev().find(|&k: &usize| {
        is_back_edge(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| t < false_target)
    })?;
    Some(elif_loopback + 1)
}

pub(super) fn is_simple_guard_prelude_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { .. }
        | Stmt::AugAssign { .. }
        | Stmt::AnnAssign { .. }
        | Stmt::Expr(_)
        | Stmt::Delete(_)
        | Stmt::Import(_)
        | Stmt::ImportFrom { .. }
        | Stmt::Raise { .. }
        | Stmt::Assert { .. }
        | Stmt::Pass => true,
        Stmt::If { body, orelse, .. } => {
            orelse.is_empty() && body.iter().all(is_simple_guard_prelude_stmt)
        }
        _ => false,
    }
}

pub(super) fn leading_guard_prelude_split(
    stream: &DecodedStream,
    lo: usize,
    guard: usize,
) -> Option<usize> {
    let mut split: usize = lo;
    for k in lo..guard {
        if !is_forward_cond_jump(&stream.ops[k])
            || is_chain_cond_jump(&stream.ops, k)
            || is_value_form_shortcircuit(&stream.ops, k)
        {
            continue;
        }
        let target: usize =
            resolve_jump_target(stream, k, &stream.ops[k]).filter(|t: &usize| *t > k)?;
        if target > guard {
            return None;
        }
        split = split.max(target);
    }
    if (split..guard)
        .any(|k: usize| is_forward_cond_jump(&stream.ops[k]) || is_chain_cond_jump(&stream.ops, k))
    {
        return None;
    }
    if (lo..split).any(|k: usize| {
        resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > split)
    }) {
        return None;
    }
    Some(split)
}

pub(super) fn try_structure_multibranch_guarded_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) != PY_CO_FLAG_FUNCTION_SCOPE {
        return Ok(None);
    }
    let mut guard_lo: usize = lo;
    let mut chosen: Option<(usize, usize, usize, TryRegion)> = None;
    while let Some(guard) = (guard_lo..hi).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) {
        let guard: usize = guard;
        guard_lo = guard + 1;
        let Some(prior_split): Option<usize> = leading_guard_prelude_split(stream, lo, guard)
        else {
            return Ok(None);
        };
        if prior_split <= lo {
            continue;
        }
        let Some(false_target): Option<usize> =
            resolve_jump_target(stream, guard, &stream.ops[guard])
                .filter(|t: &usize| *t > guard && *t < hi)
        else {
            continue;
        };
        let Some(region): Option<TryRegion> =
            find_protected_try_with_outer_handler(stream, guard + 1, false_target, hi)
        else {
            continue;
        };
        let guard_is_loop_test: bool = (guard + 1..region.region_end).any(|k: usize| {
            resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t <= guard)
        });
        let guard_unprotected: bool = stream
            .offsets
            .get(guard)
            .copied()
            .is_some_and(|off: u32| offset_is_unprotected(stream, off));
        if region.is_finally
            || region.try_start <= guard
            || region.try_start >= false_target
            || region.handler_start < false_target
            || region.region_end != hi
            || guard_is_loop_test
            || !guard_unprotected
            || first_significant(stream, guard + 1, region.try_start).is_some()
            || first_significant(stream, false_target, region.handler_start).is_none()
        {
            continue;
        }
        chosen = Some((guard, prior_split, false_target, region));
        break;
    }
    let Some((guard, prior_split, false_target, region)): Option<(usize, usize, usize, TryRegion)> =
        chosen
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
    let comp_end: usize = extend_protected_end_over_comp(
        stream,
        region.try_start,
        region.protected_end,
        false_target,
    );
    let body_end: usize =
        protected_body_end_with_return(stream, region.try_start, comp_end, region.handler_start);
    let body_end: usize =
        extend_body_over_trailing_guard(stream, region.try_start, body_end, false_target);
    let continuation_end: usize =
        trim_trailing_comp_cleanup(stream, false_target, region.handler_start);
    let dup_pop_except: Option<usize> = handler_return_idiom_duplicates_continuation(
        stream,
        region.handler_start,
        region.region_end,
        false_target,
        continuation_end,
    );
    let handler_region_end: usize = dup_pop_except.map_or(region.region_end, |pop: usize| pop + 1);
    let try_body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, handler_region_end)?;
    let span_is_else: bool = guarded_span_is_try_else(
        stream,
        region.try_start,
        body_end,
        false_target,
        region.handler_start,
        region.region_end,
    );
    let try_orelse: Vec<Stmt> = if span_is_else {
        structure_stmts(code, stream, body_end, false_target)?
    } else {
        Vec::new()
    };
    let try_stmt: Stmt = Stmt::Try {
        body: non_empty(try_body),
        handlers,
        orelse: try_orelse,
        finalbody: Vec::new(),
        line: None,
    };
    let mut if_body: Vec<Stmt> = vec![try_stmt];
    if !span_is_else {
        if_body.extend(structure_stmts(code, stream, body_end, false_target)?);
    }

    let else_join: Option<usize> = then_terminating_jump(stream, region.try_start, false_target)
        .and_then(|j: usize| resolve_jump_target(stream, j, &stream.ops[j]))
        .filter(|t: &usize| *t > false_target && *t < region.handler_start);
    let trailing_is_continuation: bool = else_join.is_none()
        && (dup_pop_except.is_some()
            || handler_normal_exit_backjumps_to(
                stream,
                region.handler_start,
                region.region_end,
                false_target,
            )
            || guarded_body_falls_through_to(
                stream,
                region.try_start,
                false_target,
                continuation_end,
            ));
    let orelse: Vec<Stmt> = if trailing_is_continuation {
        Vec::new()
    } else if let Some(join) = else_join {
        structure_stmts(code, stream, false_target, join)?
    } else {
        structure_stmts(code, stream, false_target, continuation_end)?
    };
    let mut out: Vec<Stmt> = prior;
    out.push(Stmt::If {
        test,
        body: non_empty(if_body),
        orelse,
        line: None,
    });
    if trailing_is_continuation {
        out.extend(structure_stmts(
            code,
            stream,
            false_target,
            continuation_end,
        )?);
    }
    if let Some(join) = else_join
        && join < region.handler_start
    {
        out.extend(structure_stmts(code, stream, join, region.handler_start)?);
    }
    out.extend(structure_stmts(code, stream, region.region_end, hi)?);
    Ok(Some(out))
}

fn else_try_first_guard(stream: &DecodedStream, lo: usize, hi: usize) -> Option<usize> {
    (lo..hi).find(|&k: &usize| {
        (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
            && !is_chain_cond_jump(&stream.ops, k)
    })
}

fn span_is_self_contained_validation(
    stream: &DecodedStream,
    lo: usize,
    guard: usize,
    rejoin: usize,
) -> bool {
    if rejoin <= guard || rejoin > stream.ops.len() {
        return false;
    }
    if (lo..rejoin).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::MakeFunction(_) | CanonicalOp::MakeFunctionLegacy(_)
        )
    }) {
        return false;
    }
    if find_try_region(stream, lo, rejoin).is_some() {
        return false;
    }
    (lo..rejoin).all(|k: usize| {
        resolve_jump_target(stream, k, &stream.ops[k]).is_none_or(|t: usize| t <= rejoin)
    })
}

fn else_try_skip_leading_self_contained(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<usize> {
    let mut start: usize = lo;
    loop {
        let guard: usize = else_try_first_guard(stream, start, hi)?;
        let false_target: usize = resolve_jump_target(stream, guard, &stream.ops[guard])
            .filter(|t: &usize| *t > guard && *t < hi)?;
        if find_try_region(stream, false_target, hi)
            .is_some_and(|region: TryRegion| region.try_start >= false_target)
            && then_terminating_jump(stream, guard + 1, false_target).is_some()
        {
            return if start > lo { Some(start) } else { None };
        }
        if !span_is_self_contained_validation(stream, start, guard, false_target) {
            return None;
        }
        start = false_target;
    }
}

pub(super) fn try_structure_else_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Result<Option<Vec<Stmt>>> {
    if stream.exception_table.is_empty() {
        return Ok(None);
    }
    if let Some(real_lo) = else_try_skip_leading_self_contained(stream, lo, hi)
        && real_lo > lo
    {
        let Some(inner): Option<Vec<Stmt>> = try_structure_else_try(code, stream, real_lo, hi)?
        else {
            return Ok(None);
        };
        let mut out: Vec<Stmt> = structure_stmts(code, stream, lo, real_lo)?;
        out.extend(inner);
        return Ok(Some(out));
    }
    let Some(guard): Option<usize> = else_try_first_guard(stream, lo, hi) else {
        return Ok(None);
    };
    if (lo..guard).any(|k: usize| {
        (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    }) {
        return Ok(None);
    }
    let Some(else_start): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|t: &usize| *t > guard && *t < hi)
    else {
        return Ok(None);
    };
    let Some(then_jump): Option<usize> = then_terminating_jump(stream, guard + 1, else_start)
    else {
        return Ok(None);
    };
    let Some(join): Option<usize> = resolve_jump_target(stream, then_jump, &stream.ops[then_jump])
        .filter(|t: &usize| *t > else_start && *t <= hi)
    else {
        return Ok(None);
    };
    let Some(region): Option<TryRegion> = find_try_region(stream, else_start, hi) else {
        return Ok(None);
    };
    if region.is_with
        || region.is_finally
        || region.try_start < else_start
        || region.try_start >= join
        || region.handler_start < join
        || region.protected_end > join + 1
    {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
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
    let then_body: Vec<Stmt> = structure_stmts(code, stream, guard + 1, then_jump)?;
    let mut else_pack: Vec<Stmt> = structure_try(code, stream, else_start, hi, &region)?;
    if else_pack.is_empty() {
        return Ok(None);
    }
    let cont_tail: Vec<Stmt> = else_pack.split_off(1);
    let orelse: Vec<Stmt> = else_pack;
    if !matches!(orelse.first(), Some(Stmt::Try { .. })) {
        return Ok(None);
    }
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(then_body),
        orelse,
        line: None,
    });
    out.extend(cont_tail);
    Ok(Some(out))
}

pub(super) fn try_enclosed_by_leading_guard(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> bool {
    if region.is_finally {
        return false;
    }
    let _ = hi;
    let Some(guard): Option<usize> = (lo..region.try_start).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return false;
    };
    if (lo..guard).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > k)
    }) {
        return false;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard]) else {
        return false;
    };
    if region.is_with {
        return target > region.try_end && target <= region.handler_start;
    }
    target >= region.region_end && target > region.handler_start
}

fn guard_test_split_after_stmts(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    guard: usize,
) -> Option<usize> {
    let mut test_start: usize = guard;
    while test_start > lo && !is_value_boundary_at(stream, test_start - 1) {
        test_start -= 1;
    }
    if (lo..test_start).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > test_start)
    }) {
        return None;
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[test_start..guard]).ok()?;
    (head.is_empty() && residual.len() == 1).then_some(test_start)
}

fn guard_test_expr_start(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    guard: usize,
) -> Option<usize> {
    let mut leaders: std::collections::BTreeSet<usize> = std::collections::BTreeSet::new();
    leaders.insert(lo);
    for k in lo..guard {
        if let Some(t) = resolve_jump_target(stream, k, &stream.ops[k])
            && (lo..=guard).contains(&t)
        {
            leaders.insert(t);
        }
    }
    leaders.into_iter().rev().find(|&b: &usize| {
        if (lo..b).any(|k: usize| {
            is_forward_cond_jump(&stream.ops[k])
                && !is_chain_cond_jump(&stream.ops, k)
                && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > b)
        }) {
            return false;
        }
        let Ok((head, residual)): Result<(Vec<Stmt>, Vec<Expr>)> =
            build_linear_stmts_sim(code, &stream.ops[b..guard])
        else {
            return false;
        };
        head.is_empty() && residual.len() == 1
    })
}

fn try_structure_leading_else_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Option<Vec<Stmt>>> {
    let Some(guard): Option<usize> = (lo..region.try_start).rev().find(|&k: &usize| {
        (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
            && !is_chain_cond_jump(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    let Some(else_start): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|t: &usize| *t > guard && *t <= region.try_start)
    else {
        return Ok(None);
    };
    if (else_start..region.try_start).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
        )
    }) {
        return Ok(None);
    }
    let Some(then_jump): Option<usize> = then_terminating_jump(stream, guard + 1, else_start)
    else {
        return Ok(None);
    };
    let then_skips_else: bool = resolve_jump_target(stream, then_jump, &stream.ops[then_jump])
        .is_some_and(|t: usize| t > region.try_start && t <= hi);
    if !then_skips_else {
        return Ok(None);
    }
    if (guard..region.region_end).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::MakeFunction(_) | CanonicalOp::MakeFunctionLegacy(_)
        )
    }) {
        return Ok(None);
    }
    let Some(test_start): Option<usize> = guard_test_expr_start(code, stream, lo, guard) else {
        return Ok(None);
    };
    let head: Vec<Stmt> = structure_stmts(code, stream, lo, test_start)?;
    let (test_head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[test_start..guard])?;
    if !test_head.is_empty() {
        return Ok(None);
    }
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
    let then_body: Vec<Stmt> = structure_stmts(code, stream, guard + 1, then_jump)?;
    let mut else_pack: Vec<Stmt> = structure_try(code, stream, else_start, hi, region)?;
    if else_pack.is_empty() || !matches!(else_pack.first(), Some(Stmt::Try { .. })) {
        return Ok(None);
    }
    let cont_tail: Vec<Stmt> = else_pack.split_off(1);
    let orelse: Vec<Stmt> = else_pack;
    let mut out: Vec<Stmt> = head;
    out.push(Stmt::If {
        test,
        body: non_empty(then_body),
        orelse,
        line: None,
    });
    out.extend(cont_tail);
    Ok(Some(out))
}

fn try_structure_loop_continue_guard_over_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Option<Vec<Stmt>>> {
    if region.is_with || region.is_finally || stream.is_pre_311() {
        return Ok(None);
    }
    if loop_continue_target().is_none() {
        return Ok(None);
    }
    let Some(guard): Option<usize> = (lo..region.try_start).find(|&k: &usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    if stream.none_jump_kind.contains_key(&guard) || !jump_taken_if_true(stream, guard) {
        return Ok(None);
    }
    let Some(raw_target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|&t: &usize| t > guard && t <= hi)
    else {
        return Ok(None);
    };
    let body_entry: usize = first_significant(stream, raw_target, hi).unwrap_or(raw_target);
    if body_entry < region.try_start {
        return Ok(None);
    }
    if then_continues_to_loop(stream, guard + 1, raw_target).is_none() {
        return Ok(None);
    }
    if (lo..guard).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && !is_chain_cond_jump(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > guard)
    }) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[lo..guard])?;
    if !head.is_empty() {
        return Ok(None);
    }
    let Some(positive_test): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    if !test_is_polarity_sensitive(&positive_test) {
        return Ok(None);
    }
    let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, hi)?;
    if body.is_empty() {
        return Ok(None);
    }
    Ok(Some(vec![Stmt::If {
        test: positive_test,
        body,
        orelse: Vec::new(),
        line: None,
    }]))
}

pub(super) fn structure_try(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Vec<Stmt>> {
    if let Some(stmts) = try_structure_loop_continue_guard_over_try(code, stream, lo, hi, region)? {
        return Ok(stmts);
    }
    if region.is_finally
        && !region.is_with
        && !stream.is_pre_311()
        && let Some(stmts) = try_structure_guard_over_finally(code, stream, lo, hi, region)?
    {
        return Ok(stmts);
    }
    if !region.is_with
        && !region.is_finally
        && !stream.is_pre_311()
        && let Some(guard) = (lo..region.try_start).rev().find(|&k: &usize| {
            (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
                && !is_chain_cond_jump(&stream.ops, k)
        })
        && guard > lo
        && let Some(false_target) = resolve_jump_target(stream, guard, &stream.ops[guard])
            .filter(|&t: &usize| t >= region.region_end && t < hi)
        && let Some(body_jmp) =
            first_significant(stream, region.protected_end, region.handler_start)
        && matches!(
            stream.ops.get(body_jmp),
            Some(CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_))
        )
        && let Some(continuation_start) =
            resolve_jump_target(stream, body_jmp, &stream.ops[body_jmp])
                .filter(|&c: &usize| c > false_target && c <= hi)
        && let Some(test_start) = guard_test_expr_start(code, stream, lo, guard)
    {
        let (test_stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[test_start..guard])?;
        if test_stmts.is_empty()
            && let Some(raw_test) = residual.into_iter().next_back()
        {
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
            let pre_head: Vec<Stmt> = structure_stmts(code, stream, lo, test_start)?;
            let true_body: Vec<Stmt> =
                structure_try(code, stream, guard + 1, false_target, region)?;
            let else_body: Vec<Stmt> =
                structure_stmts(code, stream, false_target, continuation_start)?;
            let cont: Vec<Stmt> = structure_stmts(code, stream, continuation_start, hi)?;
            let mut out: Vec<Stmt> = pre_head;
            out.push(Stmt::If {
                test,
                body: non_empty(true_body),
                orelse: else_body,
                line: None,
            });
            out.extend(cont);
            return Ok(out);
        }
    }
    if !region.is_with
        && !region.is_finally
        && let Some(guard) = (lo..region.try_start).rev().find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        && guard > lo
        && resolve_jump_target(stream, guard, &stream.ops[guard])
            .is_some_and(|t: usize| t > region.try_start && t <= region.handler_start)
        && let Some(test_start) = guard_test_expr_start(code, stream, lo, guard)
    {
        let guarded_opt: Option<Vec<Stmt>> =
            try_structure_guarded_try(code, stream, test_start, hi)?;
        if let Some(guarded) = guarded_opt {
            let mut out: Vec<Stmt> = structure_stmts(code, stream, lo, test_start)?;
            out.extend(guarded);
            return Ok(out);
        }
    }
    if !region.is_with
        && !region.is_finally
        && let Some(guard) = (lo..region.try_start).rev().find(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k]) && !is_chain_cond_jump(&stream.ops, k)
        })
        && guard > lo
        && let Some(false_target) = resolve_jump_target(stream, guard, &stream.ops[guard])
            .filter(|&t: &usize| t > region.try_start && t <= region.handler_start)
        && !(guard + 1..false_target).any(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
            ) && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t <= guard)
        })
        && let Some(last_stmt) = (lo..guard).rev().find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::StoreAttr(_)
                    | CanonicalOp::StoreSubscr
                    | CanonicalOp::StoreFastLoadFast(_, _)
                    | CanonicalOp::StoreFastStoreFast(_, _)
                    | CanonicalOp::Pop
                    | CanonicalOp::DeleteFast(_)
                    | CanonicalOp::DeleteName(_)
            )
        })
    {
        let candidate: usize = last_stmt + 1;
        let no_prior_jump: bool = !(lo..candidate).any(|k: usize| {
            is_forward_cond_jump(&stream.ops[k])
                && !is_chain_cond_jump(&stream.ops, k)
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| t > candidate)
        });
        if candidate < guard
            && no_prior_jump
            && let Ok((head, residual)) =
                build_linear_stmts_sim(code, &stream.ops[candidate..guard])
            && head.is_empty()
            && residual.len() == 1
            && let Some(guarded) = try_structure_guarded_try(code, stream, candidate, hi)?
        {
            let mut out: Vec<Stmt> = structure_stmts(code, stream, lo, candidate)?;
            out.extend(guarded);
            return Ok(out);
        }
    }
    if !region.is_with
        && !region.is_finally
        && let Some(stmts) = try_structure_leading_else_try(code, stream, lo, hi, region)?
    {
        return Ok(stmts);
    }
    let head: Vec<Stmt> = structure_stmts(code, stream, lo, region.try_start)?;
    let (stmt, consumed_end, gap_succ): (Stmt, usize, Vec<Stmt>) = if region.is_with {
        if let Some(enclosing) = with_enclosing_try_region(stream, region, hi) {
            let enclosing: TryRegion = enclosing;
            let (with_stmt, with_tail): (Stmt, Vec<Stmt>) = structure_with(code, stream, region)?;
            let mut try_body: Vec<Stmt> = vec![with_stmt];
            try_body.extend(with_tail);
            let handlers: Vec<ExceptHandler> =
                parse_except_handlers(code, stream, enclosing.handler_start, enclosing.region_end)?;
            (
                Stmt::Try {
                    body: non_empty(try_body),
                    handlers,
                    orelse: Vec::new(),
                    finalbody: Vec::new(),
                    line: None,
                },
                enclosing.region_end,
                Vec::new(),
            )
        } else {
            let (with_stmt, with_tail): (Stmt, Vec<Stmt>) = structure_with(code, stream, region)?;
            (with_stmt, region.region_end, with_tail)
        }
    } else if let Some((outer_handler_start, outer_region_end, inner_body_end)) =
        try_enclosing_except_region(stream, region, hi)
    {
        let inner_body: Vec<Stmt> = {
            let _body_cap: StructureHiCapGuard = StructureHiCapGuard::enter(inner_body_end);
            structure_stmts(code, stream, region.try_start, inner_body_end)?
        };
        let handlers: Vec<ExceptHandler> =
            parse_except_handlers(code, stream, outer_handler_start, outer_region_end)?;
        (
            Stmt::Try {
                body: non_empty(inner_body),
                handlers,
                orelse: Vec::new(),
                finalbody: Vec::new(),
                line: None,
            },
            outer_region_end,
            Vec::new(),
        )
    } else {
        let sc_end: usize =
            extend_end_past_shortcircuit_stmt(stream, region.try_end, region.handler_start);
        let extended_end: usize = extend_try_body(code, stream, sc_end, region.handler_start);
        let body_real_end: usize = trim_try_body_jump(stream, region.try_start, extended_end);
        let is_star: bool = (region.handler_start..region.region_end)
            .any(|k: usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch));
        if region.is_finally && !is_star {
            let (stmt, tail): (Stmt, Vec<Stmt>) =
                structure_pure_finally(code, stream, region, body_real_end)?;
            (stmt, region.region_end, tail)
        } else if is_star {
            let star_body_end: usize = except_star_body_end(stream, region, body_real_end);
            let body: Vec<Stmt> = {
                let _hi_cap: StructureHiCapGuard = StructureHiCapGuard::enter(star_body_end);
                structure_stmts(code, stream, region.try_start, star_body_end)?
            };
            let handlers: Vec<ExceptHandler> =
                parse_except_star_handlers(code, stream, region.handler_start, region.region_end)?;
            let inline_epilogue: Option<(usize, usize)> =
                except_star_nested_with_epilogue_span(stream, region)
                    .or_else(|| except_star_normal_exit_span(stream, region));
            let (succ_scan_start, succ_end): (usize, usize) =
                if let Some((start, end)) = inline_epilogue {
                    (start, end)
                } else {
                    let scan_start: usize = extended_end.max(star_body_end);
                    (
                        scan_start,
                        trim_try_body_jump(stream, scan_start, region.handler_start),
                    )
                };
            let succ: Vec<Stmt> = if succ_scan_start < succ_end
                && slice_has_real_stmt(stream, succ_scan_start, succ_end)
            {
                structure_stmts(code, stream, succ_scan_start, succ_end)?
            } else {
                Vec::new()
            };
            (
                Stmt::TryStar {
                    body: non_empty(body),
                    handlers,
                    orelse: Vec::new(),
                    finalbody: Vec::new(),
                    line: None,
                },
                region.region_end,
                succ,
            )
        } else {
            let (stmt, consumed_end, construct_tail): (Stmt, usize, Vec<Stmt>) =
                structure_try_except_family(code, stream, region, body_real_end, hi)?;
            (stmt, consumed_end, construct_tail)
        }
    };
    let mut out: Vec<Stmt> = head;
    out.push(stmt);
    out.extend(gap_succ);
    if consumed_end < hi {
        out.extend(structure_stmts(code, stream, consumed_end, hi)?);
    }
    Ok(out)
}

fn slice_has_real_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Nop
                | CanonicalOp::Cache
                | CanonicalOp::ExtendedArg(_)
        )
    })
}

#[derive(Debug, Clone)]
struct ComboFinally {
    finally_body_start: usize,
    finally_body_end: usize,
    inline_copy_len: usize,
    except_region_end: usize,
    region_end: usize,
}

fn find_combo_finally(
    stream: &DecodedStream,
    region: &TryRegion,
    hi: usize,
) -> Option<ComboFinally> {
    if stream.is_pre_311() || region.is_with {
        return None;
    }
    let mut best_handler: Option<usize> = None;
    for entry in &stream.exception_table {
        let handler_start: usize = match stream.index_for_offset(entry.target) {
            Some(h) => h,
            None => continue,
        };
        if handler_start <= region.handler_start || handler_start >= hi {
            continue;
        }
        if !matches!(
            stream.ops.get(handler_start),
            Some(CanonicalOp::PushExcInfo)
        ) {
            continue;
        }
        let cold_region_end: usize = handler_join(stream, handler_start, hi);
        if !is_pure_finally_handler_shape(stream, handler_start, cold_region_end, false) {
            continue;
        }
        best_handler =
            Some(best_handler.map_or(handler_start, |prev: usize| prev.min(handler_start)));
    }
    let handler_start: usize = best_handler?;
    let cold_region_end: usize = handler_join(stream, handler_start, hi);
    let fin_start: usize = handler_body_first(stream, handler_start);
    let fin_end: usize = finally_body_end(stream, fin_start, cold_region_end);
    let inline_copy_len: usize = fin_end.saturating_sub(fin_start);
    if inline_copy_len == 0 {
        return None;
    }
    let except_region_end: usize =
        combo_except_region_end(stream, region.handler_start, handler_start);
    Some(ComboFinally {
        finally_body_start: fin_start,
        finally_body_end: fin_end,
        inline_copy_len,
        except_region_end,
        region_end: cold_region_end.min(hi),
    })
}

fn combo_except_region_end(
    stream: &DecodedStream,
    except_handler: usize,
    finally_handler: usize,
) -> usize {
    let _ = except_handler;
    let mut end: usize = finally_handler;
    while end > 0
        && matches!(
            stream.ops.get(end - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        end -= 1;
    }
    end
}

fn bare_except_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = lo;
    while end < hi {
        match stream.ops[end] {
            CanonicalOp::Copy(_) | CanonicalOp::PopExcept => break,
            _ => end += 1,
        }
    }
    let mut trimmed: usize = end;
    while trimmed > lo
        && matches!(
            stream.ops.get(trimmed - 1),
            Some(
                CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
            )
        )
    {
        trimmed -= 1;
    }
    trimmed
}

fn modern_try_construct_tail_present(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
) -> bool {
    if protected_end >= region.handler_start {
        return false;
    }
    first_significant(stream, protected_end, region.handler_start).is_some_and(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    })
}

fn else_span_is_sequential_sibling(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
) -> bool {
    let Some(&handler_off): Option<&u32> = stream.offsets.get(region.handler_start) else {
        return false;
    };
    let Some(&span_lo): Option<&u32> = stream.offsets.get(protected_end) else {
        return false;
    };
    stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            e.start >= span_lo && e.start < handler_off && e.target >= handler_off
        })
}

fn try_else_split(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    except_region_end: usize,
    has_combo: bool,
) -> Option<(usize, usize)> {
    if stream.is_pre_311() {
        return None;
    }
    let else_start: usize = protected_end;
    if protected_end_splits_shortcircuit(stream, protected_end) {
        return None;
    }
    let else_end: usize = trim_trailing_comp_cleanup(stream, else_start, region.handler_start);
    if else_start >= else_end {
        return None;
    }
    let first_idx: usize = (else_start..else_end)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !else_entry_is_fallthrough(&stream.ops[first_idx]) {
        return None;
    }
    if else_entry_is_loop_continuation(stream, region, first_idx) {
        return None;
    }
    if !has_combo && else_span_is_sequential_sibling(stream, region, else_start) {
        return None;
    }
    if !has_combo
        && handler_normal_exit_reaches(stream, region, except_region_end, else_start, else_end)
    {
        return None;
    }
    Some((else_start, else_end))
}

fn try_continuation_split(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    except_region_end: usize,
) -> Option<(usize, usize)> {
    if stream.is_pre_311() || protected_end_splits_shortcircuit(stream, protected_end) {
        return None;
    }
    let start: usize = protected_end;
    let end: usize = trim_trailing_comp_cleanup(stream, start, region.handler_start);
    if start >= end {
        return None;
    }
    let first_idx: usize = (start..end)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !else_entry_is_fallthrough(&stream.ops[first_idx]) {
        return None;
    }
    let handler_reaches: bool =
        handler_normal_exit_reaches(stream, region, except_region_end, start, end);
    let sibling: bool = else_span_is_sequential_sibling(stream, region, start);
    if !handler_reaches && !sibling {
        return None;
    }
    Some((start, end))
}

fn skip_except_name_teardown(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let Some(load): Option<usize> = first_significant(stream, from, hi)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadConst(_)))
    else {
        return from;
    };
    let Some(store): Option<usize> =
        first_significant(stream, load + 1, hi).filter(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::StoreName(_) | CanonicalOp::StoreFast(_)
            )
        })
    else {
        return from;
    };
    let Some(delete): Option<usize> =
        first_significant(stream, store + 1, hi).filter(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::DeleteName(_) | CanonicalOp::DeleteFast(_)
            )
        })
    else {
        return from;
    };
    delete + 1
}

fn handler_normal_exit_reaches(
    stream: &DecodedStream,
    region: &TryRegion,
    except_region_end: usize,
    else_start: usize,
    else_end: usize,
) -> bool {
    let scan_end: usize = except_region_end.min(stream.ops.len());
    (region.handler_start..scan_end)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopExcept))
        .filter_map(|pop: usize| {
            let after_teardown: usize = skip_except_name_teardown(stream, pop + 1, scan_end);
            first_significant(stream, after_teardown, scan_end)
        })
        .any(|exit: usize| match &stream.ops[exit] {
            CanonicalOp::Reraise(_) => false,
            CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_) => resolve_jump_target(stream, exit, &stream.ops[exit])
                .is_some_and(|target: usize| (else_start..else_end).contains(&target)),
            _ => exit < else_end,
        })
}

fn handler_normal_exit_jump_target(
    stream: &DecodedStream,
    region: &TryRegion,
    except_region_end: usize,
    else_start: usize,
    else_end: usize,
) -> Option<usize> {
    let scan_end: usize = except_region_end.min(stream.ops.len());
    (region.handler_start..scan_end)
        .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopExcept))
        .filter_map(|pop: usize| {
            let after_teardown: usize = skip_except_name_teardown(stream, pop + 1, scan_end);
            first_significant(stream, after_teardown, scan_end)
        })
        .filter(|&exit: &usize| {
            matches!(
                stream.ops[exit],
                CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpBackwardNoInterrupt(_)
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
            )
        })
        .find_map(|exit: usize| {
            resolve_jump_target(stream, exit, &stream.ops[exit])
                .filter(|target: &usize| (else_start..else_end).contains(target))
        })
}

fn try_else_handler_continuation_split(
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    except_region_end: usize,
    has_combo: bool,
) -> Option<(usize, usize, usize)> {
    if has_combo || stream.is_pre_311() {
        return None;
    }
    if protected_end_splits_shortcircuit(stream, protected_end) {
        return None;
    }
    let else_start: usize = protected_end;
    let else_end_full: usize = trim_trailing_comp_cleanup(stream, else_start, region.handler_start);
    if else_start >= else_end_full {
        return None;
    }
    let first_idx: usize = (else_start..else_end_full)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))?;
    if !else_entry_is_fallthrough(&stream.ops[first_idx]) {
        return None;
    }
    if else_entry_is_loop_continuation(stream, region, first_idx) {
        return None;
    }
    let cont_start: usize = handler_normal_exit_jump_target(
        stream,
        region,
        except_region_end,
        else_start,
        else_end_full,
    )?;
    if cont_start <= else_start || cont_start >= else_end_full {
        return None;
    }
    if !first_significant(stream, cont_start, else_end_full)
        .is_some_and(|k: usize| else_entry_is_fallthrough(&stream.ops[k]))
    {
        return None;
    }
    if !slice_has_real_stmt(stream, else_start, cont_start)
        || !slice_has_real_stmt(stream, cont_start, else_end_full)
    {
        return None;
    }
    let cont_end: usize = continuation_span_end(stream, cont_start, else_end_full);
    if cont_start >= cont_end || !slice_has_real_stmt(stream, cont_start, cont_end) {
        return None;
    }
    Some((else_start, cont_start, cont_end))
}

fn continuation_span_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi {
        match stream.ops[k] {
            CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_) => return k,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return k + 1,
            _ => k += 1,
        }
    }
    trim_trailing_comp_cleanup(stream, lo, hi)
}

fn protected_end_splits_shortcircuit(stream: &DecodedStream, protected_end: usize) -> bool {
    let Some(prev): Option<usize> = protected_end.checked_sub(1) else {
        return false;
    };
    matches!(
        stream.ops.get(prev),
        Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_))
    ) && is_value_form_shortcircuit(&stream.ops, prev)
}

pub(super) fn trim_trailing_comp_cleanup(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let last: usize = match (lo..hi)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    {
        Some(k) => k,
        None => return hi,
    };
    if !matches!(stream.ops[last], CanonicalOp::Reraise(_)) {
        return hi;
    }
    let mut k: usize = last;
    while k > lo {
        match stream.ops[k - 1] {
            CanonicalOp::Swap(_)
            | CanonicalOp::Pop
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
            | CanonicalOp::StoreFast(_)
            | CanonicalOp::Copy(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::Reraise(_) => k -= 1,
            _ => break,
        }
    }
    k
}

fn else_entry_is_loop_continuation(
    stream: &DecodedStream,
    region: &TryRegion,
    first_idx: usize,
) -> bool {
    matches!(
        stream.ops[first_idx],
        CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::JumpAbsolute(_)
    ) && resolve_jump_target(stream, first_idx, &stream.ops[first_idx])
        .is_some_and(|t: usize| t <= region.try_start)
}

fn else_entry_is_fallthrough(op: &CanonicalOp) -> bool {
    !matches!(
        op,
        CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::Nop
            | CanonicalOp::Cache
            | CanonicalOp::Reraise(_)
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::Raise(_)
    )
}

fn trim_inline_finally_from_handlers(
    handlers: Vec<ExceptHandler>,
    finalbody: &[Stmt],
) -> Vec<ExceptHandler> {
    if finalbody.is_empty() {
        return handlers;
    }
    handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            strip_trailing_stmts(&mut h.body, finalbody);
            strip_leading_stmts(&mut h.body, finalbody);
            if h.body.is_empty() {
                h.body = vec![Stmt::Pass];
            }
            h
        })
        .collect()
}

fn strip_trailing_stmts(body: &mut Vec<Stmt>, suffix: &[Stmt]) {
    if suffix.is_empty() || body.len() < suffix.len() {
        return;
    }
    let split: usize = body.len() - suffix.len();
    let tail_matches: bool = body[split..]
        .iter()
        .zip(suffix.iter())
        .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
    if tail_matches {
        body.truncate(split);
    }
}

fn strip_leading_stmts(body: &mut Vec<Stmt>, prefix: &[Stmt]) {
    if prefix.is_empty() || body.len() < prefix.len() {
        return;
    }
    let head_matches: bool = body[..prefix.len()]
        .iter()
        .zip(prefix.iter())
        .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
    if head_matches {
        body.drain(..prefix.len());
    }
}

fn shared_construct_exit_return(raw: &[Stmt], handlers: &[ExceptHandler]) -> Option<Vec<Stmt>> {
    let [exit @ Stmt::Return(_)]: &[Stmt] = raw else {
        return None;
    };
    if handlers.is_empty() {
        return None;
    }
    let exit_repr: String = format!("{exit:?}");
    let all_share: bool = handlers.iter().all(|h: &ExceptHandler| {
        h.body
            .last()
            .is_some_and(|s: &Stmt| format!("{s:?}") == exit_repr)
    });
    all_share.then(|| vec![exit.clone()])
}

fn strip_shared_exit_suffix(
    handlers: Vec<ExceptHandler>,
    continuation: &[Stmt],
) -> Vec<ExceptHandler> {
    if continuation.is_empty() {
        return handlers;
    }
    let cont_reprs: Vec<String> = continuation
        .iter()
        .map(|s: &Stmt| format!("{s:?}"))
        .collect();
    handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            let mut match_len: usize = 0;
            while match_len < cont_reprs.len() && match_len < h.body.len() {
                let body_idx: usize = h.body.len() - 1 - match_len;
                let cont_idx: usize = cont_reprs.len() - 1 - match_len;
                if format!("{:?}", h.body[body_idx]) == cont_reprs[cont_idx] {
                    match_len += 1;
                } else {
                    break;
                }
            }
            if match_len > 0 {
                h.body.truncate(h.body.len() - match_len);
                h.body = non_empty(h.body);
            }
            h
        })
        .collect()
}

fn strip_shared_exit_return(
    handlers: Vec<ExceptHandler>,
    construct_tail: &[Stmt],
) -> Vec<ExceptHandler> {
    let [tail]: &[Stmt] = construct_tail else {
        return handlers;
    };
    let tail_repr: String = format!("{tail:?}");
    handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            if h.body
                .last()
                .is_some_and(|s: &Stmt| format!("{s:?}") == tail_repr)
            {
                h.body.pop();
                h.body = non_empty(h.body);
            }
            h
        })
        .collect()
}

fn handler_pop_except_idx(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Option<usize> {
    let hi: usize = region_end.min(stream.ops.len());
    let scan_start: usize = handler_body_first(stream, handler_start);
    let mut depth: u32 = 0;
    for k in scan_start..hi {
        match stream.ops[k] {
            CanonicalOp::PushExcInfo => depth += 1,
            CanonicalOp::PopExcept if depth == 0 => return Some(k),
            CanonicalOp::PopExcept => depth -= 1,
            _ => {}
        }
    }
    None
}

fn handler_normal_exit_backjumps_to(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
    target: usize,
) -> bool {
    let Some(pop_except): Option<usize> = handler_pop_except_idx(stream, handler_start, region_end)
    else {
        return false;
    };
    let scan_hi: usize = region_end.min(stream.ops.len());
    let after_teardown: usize = skip_except_name_teardown(stream, pop_except + 1, scan_hi);
    let Some(next): Option<usize> = first_significant(stream, after_teardown, scan_hi) else {
        return false;
    };
    if !matches!(stream.ops[next], CanonicalOp::JumpBackwardNoInterrupt(_)) {
        return false;
    }
    resolve_jump_target(stream, next, &stream.ops[next]).is_some_and(|t: usize| t == target)
}

fn significant_ops(stream: &DecodedStream, lo: usize, hi: usize) -> Vec<&CanonicalOp> {
    (lo..hi)
        .map(|k: usize| &stream.ops[k])
        .filter(|op: &&CanonicalOp| {
            !matches!(
                op,
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .collect()
}

fn op_spans_match(
    stream: &DecodedStream,
    a_lo: usize,
    a_hi: usize,
    b_lo: usize,
    b_hi: usize,
) -> bool {
    let lhs: Vec<&CanonicalOp> = significant_ops(stream, a_lo, a_hi);
    let rhs: Vec<&CanonicalOp> = significant_ops(stream, b_lo, b_hi);
    !lhs.is_empty() && lhs == rhs
}

fn modern_continuation_start(
    stream: &DecodedStream,
    gap_start: usize,
    handler_start: usize,
    tail_lo: usize,
    tail_hi: usize,
) -> usize {
    if gap_start >= handler_start || tail_lo >= tail_hi {
        return handler_start;
    }
    let mut best: usize = handler_start;
    for cont_start in (gap_start..handler_start).rev() {
        if !starts_at_statement_boundary(stream, gap_start, cont_start) {
            continue;
        }
        if op_spans_match(stream, cont_start, handler_start, tail_lo, tail_hi) {
            best = cont_start;
        }
    }
    best
}

fn starts_at_statement_boundary(
    stream: &DecodedStream,
    gap_start: usize,
    cont_start: usize,
) -> bool {
    cont_start == gap_start
        || last_significant_back(stream, gap_start, cont_start)
            .is_none_or(|k: usize| !op_leaves_value(&stream.ops[k]))
}

fn handler_continuation_tail_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi {
        match stream.ops[k] {
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_)
                if skip_handler_name_cleanup(stream, k + 1, hi) > k + 1 =>
            {
                return k + 1;
            }
            CanonicalOp::Reraise(_)
            | CanonicalOp::Copy(_)
            | CanonicalOp::Swap(_)
            | CanonicalOp::PushExcInfo
            | CanonicalOp::PopExcept => break,
            _ => k += 1,
        }
    }
    k
}

fn tail_is_implicit_none_return(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> bool {
    let ops: Vec<&CanonicalOp> = significant_ops(stream, lo, hi);
    match ops.as_slice() {
        [CanonicalOp::ReturnConst(idx)] => {
            matches!(code.consts.get(*idx as usize), Some(Object::None))
        }
        [load, CanonicalOp::Return] => loads_none(code, load),
        _ => false,
    }
}

fn structure_try_except_family(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    extended_body_end: usize,
    hi: usize,
) -> Result<(Stmt, usize, Vec<Stmt>)> {
    let combo: Option<ComboFinally> = find_combo_finally(stream, region, hi);
    let except_region_end: usize = combo
        .as_ref()
        .map_or(region.region_end, |c: &ComboFinally| c.except_region_end);

    let finalbody: Vec<Stmt> = match &combo {
        Some(c) => {
            let fin_body: Vec<Stmt> =
                structure_stmts(code, stream, c.finally_body_start, c.finally_body_end)?;
            non_empty(fin_body)
        }
        None => Vec::new(),
    };

    let inline_copy_len: usize = combo
        .as_ref()
        .map_or(0, |c: &ComboFinally| c.inline_copy_len);
    let has_combo: bool = combo.is_some();
    let comp_end: usize = extend_protected_end_over_comp(
        stream,
        region.try_start,
        region.protected_end,
        region.handler_start,
    );
    let await_end: usize = skip_await_send_loop(stream, comp_end, region.handler_start);
    let sc_end: usize = extend_end_past_shortcircuit_stmt(stream, await_end, region.handler_start);
    let protected_end: usize = if stream.is_pre_311() || has_combo {
        sc_end
    } else {
        let with_return: usize =
            protected_body_end_with_return(stream, region.try_start, sc_end, region.handler_start);
        extend_protected_end_over_guard_return(
            stream,
            region.try_start,
            with_return,
            region.handler_start,
        )
    };

    if stream.is_pre_311() && !has_combo {
        let (stmt, consumed): (Stmt, usize) =
            structure_pre311_try_except(code, stream, region, extended_body_end, hi)?;
        return Ok((stmt, consumed, Vec::new()));
    }

    if !has_combo
        && let Some(result) = structure_modern_try_with_continuation(
            code,
            stream,
            region,
            protected_end,
            except_region_end,
        )?
    {
        return Ok(result);
    }

    if !has_combo
        && let Some(result) = structure_modern_try_with_forward_continuation(
            code,
            stream,
            region,
            protected_end,
            extended_body_end,
        )?
    {
        return Ok(result);
    }

    let plain_normal_region: Option<(usize, usize)> =
        try_else_split(stream, region, protected_end, except_region_end, has_combo);

    let handler_cont_split: Option<(usize, usize, usize)> = if plain_normal_region.is_none() {
        try_else_handler_continuation_split(
            stream,
            region,
            protected_end,
            except_region_end,
            has_combo,
        )
    } else {
        None
    };

    let normal_region: Option<(usize, usize)> = plain_normal_region.or_else(|| {
        handler_cont_split
            .map(|(else_start, cont_start, _): (usize, usize, usize)| (else_start, cont_start))
    });

    let continuation_region: Option<(usize, usize)> = if has_combo || normal_region.is_some() {
        None
    } else {
        try_continuation_split(stream, region, protected_end, except_region_end)
    };

    let lift_modern_tail: bool = normal_region.is_none()
        && continuation_region.is_none()
        && !has_combo
        && modern_try_construct_tail_present(stream, region, protected_end);

    let mut body: Vec<Stmt> = if has_combo {
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            protected_end,
            region.handler_start,
            inline_copy_len,
        )?
    } else if normal_region.is_some() || continuation_region.is_some() {
        structure_stmts(code, stream, region.try_start, protected_end)?
    } else {
        structure_stmts(code, stream, region.try_start, extended_body_end)?
    };
    let lifted_tail: Vec<Stmt> =
        if lift_modern_tail && body.len() >= 2 && matches!(body.last(), Some(Stmt::Return(_))) {
            body.pop().into_iter().collect()
        } else {
            Vec::new()
        };

    let else_fallthrough_tail: Option<(usize, usize, usize)> =
        if !has_combo && normal_region.is_some() && handler_cont_split.is_none() {
            else_construct_fallthrough_tail(code, stream, region, except_region_end)
        } else {
            None
        };
    let handler_bound: usize = else_fallthrough_tail.map_or(
        except_region_end,
        |(pop_except, _, _): (usize, usize, usize)| pop_except + 1,
    );
    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, handler_bound)?;
    let handlers: Vec<ExceptHandler> = if has_combo {
        trim_inline_finally_from_handlers(handlers, &finalbody)
    } else {
        handlers
    };

    let body_had_comp: bool = protected_end > region.protected_end;
    let (orelse, construct_tail): (Vec<Stmt>, Vec<Stmt>) = match normal_region {
        Some((s, e)) => {
            let mut raw: Vec<Stmt> = structure_stmts(code, stream, s, e)?;
            if let Some((_, cont_start, cont_end)) = handler_cont_split {
                let mut tail: Vec<Stmt> = structure_stmts(code, stream, cont_start, cont_end)?;
                while tail.last().is_some_and(is_implicit_none_return) {
                    tail.pop();
                }
                (raw, tail)
            } else if has_combo {
                strip_leading_stmts(&mut raw, &finalbody);
                let tail: Vec<Stmt> = split_construct_tail_after_finally(&mut raw, &finalbody);
                while matches!(raw.last(), Some(Stmt::Return(_))) {
                    raw.pop();
                }
                (raw, tail)
            } else if let Some((_, tail_start, tail_end)) = else_fallthrough_tail {
                let mut tail: Vec<Stmt> = structure_stmts(code, stream, tail_start, tail_end)?;
                while tail.last().is_some_and(is_implicit_none_return) {
                    tail.pop();
                }
                (raw, tail)
            } else if body_had_comp {
                (Vec::new(), raw)
            } else if let Some(shared) = shared_construct_exit_return(&raw, &handlers) {
                (Vec::new(), shared)
            } else {
                (raw, Vec::new())
            }
        }
        None => match continuation_region {
            Some((s, e)) => {
                let mut tail: Vec<Stmt> = structure_stmts(code, stream, s, e)?;
                while tail.last().is_some_and(is_implicit_none_return) {
                    tail.pop();
                }
                (Vec::new(), tail)
            }
            None => (Vec::new(), lifted_tail),
        },
    };
    let handlers: Vec<ExceptHandler> = if construct_tail.is_empty() {
        handlers
    } else {
        strip_shared_exit_return(handlers, &construct_tail)
    };

    let consumed: usize = combo
        .as_ref()
        .map_or(except_region_end, |c: &ComboFinally| c.region_end);
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse,
            finalbody,
            line: None,
        },
        consumed,
        construct_tail,
    ))
}

fn is_bare_handler_scaffolding(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::PushExcInfo
            | CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::LoadGlobal(_)
            | CanonicalOp::LoadName(_)
            | CanonicalOp::LoadFromDictOrGlobals(_)
            | CanonicalOp::LoadAttr(_)
            | CanonicalOp::BuildTuple(_)
            | CanonicalOp::Pop
            | CanonicalOp::Copy(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
    )
}

fn bare_handler_is_sole_clause(
    stream: &DecodedStream,
    handler_start: usize,
    pop_except: usize,
    except_region_end: usize,
) -> bool {
    let Some(dispatch): Option<usize> = (handler_start..pop_except).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfFalseRel(_)
        )
    }) else {
        return false;
    };
    resolve_jump_target(stream, dispatch, &stream.ops[dispatch])
        .and_then(|t: usize| first_significant(stream, t, except_region_end))
        .is_some_and(|t: usize| matches!(stream.ops.get(t), Some(CanonicalOp::Reraise(_))))
}

fn else_construct_fallthrough_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    except_region_end: usize,
) -> Option<(usize, usize, usize)> {
    if active_version().is_none_or(|v: PyVersion| (v.major(), v.minor()) < (3, 12)) {
        return None;
    }
    let pop_except: usize =
        handler_pop_except_idx(stream, region.handler_start, except_region_end)?;
    if !(region.handler_start..pop_except)
        .all(|k: usize| is_bare_handler_scaffolding(&stream.ops[k]))
    {
        return None;
    }
    if !bare_handler_is_sole_clause(stream, region.handler_start, pop_except, except_region_end) {
        return None;
    }
    let after_teardown: usize =
        skip_except_name_teardown(stream, pop_except + 1, except_region_end);
    let tail_start: usize =
        first_significant(stream, after_teardown, except_region_end).unwrap_or(except_region_end);
    if !stream
        .ops
        .get(tail_start)
        .is_some_and(else_entry_is_fallthrough)
    {
        return None;
    }
    let tail_end: usize = handler_continuation_tail_end(stream, tail_start, except_region_end);
    if tail_start >= tail_end
        || !slice_has_real_stmt(stream, tail_start, tail_end)
        || tail_is_implicit_none_return(code, stream, tail_start, tail_end)
        || (tail_start..tail_end).any(|k: usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
    {
        return None;
    }
    Some((pop_except, tail_start, tail_end))
}

fn structure_modern_try_with_continuation(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    except_region_end: usize,
) -> Result<Option<(Stmt, usize, Vec<Stmt>)>> {
    let Some(pop_except): Option<usize> =
        handler_pop_except_idx(stream, region.handler_start, except_region_end)
    else {
        return Ok(None);
    };
    let tail_start: usize = skip_handler_name_cleanup(
        stream,
        first_significant(stream, pop_except + 1, except_region_end).unwrap_or(except_region_end),
        except_region_end,
    );
    let tail_end: usize = handler_continuation_tail_end(stream, tail_start, except_region_end);
    if tail_start >= tail_end
        || !slice_has_real_stmt(stream, tail_start, tail_end)
        || tail_is_implicit_none_return(code, stream, tail_start, tail_end)
    {
        return Ok(None);
    }
    let cont_start: usize = modern_continuation_start(
        stream,
        protected_end,
        region.handler_start,
        tail_start,
        tail_end,
    );
    if cont_start >= region.handler_start {
        return Ok(None);
    }

    let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, protected_end)?;

    let else_end: usize = trim_try_body_jump(stream, protected_end, cont_start);
    let orelse: Vec<Stmt> = if protected_end < else_end
        && first_significant(stream, protected_end, else_end)
            .is_some_and(|k: usize| else_entry_is_fallthrough(&stream.ops[k]))
    {
        structure_stmts(code, stream, protected_end, else_end)?
    } else {
        Vec::new()
    };

    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, pop_except + 1)?;

    let mut continuation: Vec<Stmt> =
        structure_stmts(code, stream, cont_start, region.handler_start)?;
    while continuation.last().is_some_and(is_implicit_none_return) {
        continuation.pop();
    }

    Ok(Some((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse,
            finalbody: Vec::new(),
            line: None,
        },
        except_region_end,
        continuation,
    )))
}

fn has_back_edge_into(stream: &DecodedStream, lo: usize, hi: usize, target_floor: usize) -> bool {
    (lo..hi.min(stream.ops.len())).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
        ) && resolve_jump_target(stream, k, &stream.ops[k])
            .is_some_and(|t: usize| t <= target_floor)
    })
}

fn structure_modern_try_with_forward_continuation(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    protected_end: usize,
    extended_body_end: usize,
) -> Result<Option<(Stmt, usize, Vec<Stmt>)>> {
    let Some(pop_except): Option<usize> =
        handler_pop_except_idx(stream, region.handler_start, region.region_end)
    else {
        return Ok(None);
    };
    let after_pop: usize =
        first_significant(stream, pop_except + 1, region.region_end).unwrap_or(region.region_end);
    if !matches!(stream.ops.get(after_pop), Some(CanonicalOp::JumpForward(_))) {
        return Ok(None);
    }
    let Some(jump_target): Option<usize> =
        resolve_jump_target(stream, after_pop, &stream.ops[after_pop])
            .filter(|t: &usize| *t > after_pop)
    else {
        return Ok(None);
    };
    let Some(chain_end): Option<usize> =
        handler_chain_end(stream, region.handler_start, region.region_end)
    else {
        return Ok(None);
    };
    if jump_target < chain_end
        || jump_target >= region.region_end
        || chain_end >= region.region_end
        || !slice_has_real_stmt(stream, jump_target, region.region_end)
        || has_back_edge_into(
            stream,
            region.handler_start,
            region.region_end,
            region.try_start,
        )
        || (region.handler_start + 1..chain_end)
            .any(|k: usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
        || (region.try_start..protected_end)
            .any(|k: usize| matches!(stream.ops[k], CanonicalOp::PushExcInfo))
    {
        return Ok(None);
    }

    if try_else_split(stream, region, protected_end, chain_end, true).is_some() {
        return Ok(None);
    }
    let body_end: usize = trim_try_body_jump(stream, region.try_start, extended_body_end);
    let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
    let handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, chain_end)?;

    Ok(Some((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse: Vec::new(),
            finalbody: Vec::new(),
            line: None,
        },
        chain_end,
        Vec::new(),
    )))
}

fn split_construct_tail_after_finally(raw: &mut Vec<Stmt>, finalbody: &[Stmt]) -> Vec<Stmt> {
    if finalbody.is_empty() || finalbody.len() > raw.len() {
        return Vec::new();
    }
    let mut copy_at: Option<usize> = None;
    let limit: usize = raw.len() - finalbody.len();
    for start in (0..=limit).rev() {
        let window_matches: bool = raw[start..start + finalbody.len()]
            .iter()
            .zip(finalbody.iter())
            .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
        if window_matches {
            copy_at = Some(start);
            break;
        }
    }
    let Some(copy_at): Option<usize> = copy_at else {
        strip_trailing_stmts(raw, finalbody);
        return Vec::new();
    };
    let tail_start: usize = copy_at + finalbody.len();
    let tail: Vec<Stmt> = raw.split_off(tail_start);
    raw.truncate(copy_at);
    tail.into_iter()
        .filter(|s: &Stmt| matches!(s, Stmt::Return(_)))
        .collect()
}

fn pre311_else_is_real(
    code: &CodeObject,
    stream: &DecodedStream,
    else_start: usize,
    else_end: usize,
) -> bool {
    let Some(last): Option<usize> = (else_start..else_end)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return false;
    };
    if !matches!(stream.ops[last], CanonicalOp::Return) {
        return false;
    }
    let Some(prev): Option<usize> = (else_start..last)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return false;
    };
    if !loads_none(code, &stream.ops[prev]) {
        return false;
    }
    (else_start..prev)
        .rev()
        .find_map(|k: usize| match stream.ops[k] {
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_) => Some(true),
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => None,
            _ => Some(false),
        })
        .unwrap_or(false)
}

fn structure_pre311_try_except(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    extended_body_end: usize,
    hi: usize,
) -> Result<(Stmt, usize)> {
    let region_bound: usize = hi.min(stream.ops.len());
    let pop_block: Option<usize> = stream
        .pre311_pop_block_idx
        .range(region.try_start..region.handler_start)
        .next_back()
        .copied();

    let mut body_end: usize = extended_body_end;
    let mut else_region: Option<(usize, usize)> = None;
    let mut handler_region_end: usize = region.region_end;
    let mut consumed: usize = region.region_end;

    if let Some(pb) = pop_block {
        let after: usize = pre311_skip_pop_except(stream, pb + 1, region.handler_start);
        if let Some(jt) = pre311_body_exit_jump_target(stream, pb, region.handler_start)
            && jt > region.handler_start
        {
            let else_start: usize = pre311_skip_jumps(stream, jt, region_bound);
            let else_end: usize = pre311_else_end(stream, else_start, region_bound);
            let shared_with_handler: bool =
                pre311_handler_swallow_target(stream, region.handler_start, jt).is_some_and(
                    |t: usize| pre311_skip_jumps(stream, t, region_bound) == else_start,
                );
            let real_else: bool = !pre311_enclosed_by_finally(stream, region)
                && pre311_else_is_real(code, stream, else_start, else_end);
            if pre311_region_has_real_stmt(stream, else_start, else_end)
                && !shared_with_handler
                && (real_else || pre311_enclosed_by_finally(stream, region))
            {
                body_end = pb;
                handler_region_end = jt;
                else_region = Some((else_start, else_end));
                consumed = consumed.max(else_end);
            } else if pre311_region_has_real_stmt(stream, else_start, else_end)
                && !shared_with_handler
            {
                body_end = pb;
                handler_region_end = jt;
                consumed = else_start;
            } else if shared_with_handler {
                body_end = pb;
                handler_region_end = jt;
                consumed = consumed.max(jt);
            }
        } else if matches!(stream.ops.get(region.handler_start), Some(CanonicalOp::Dup)) {
            let else_start: usize = pre311_skip_jumps(stream, after, region.handler_start);
            let else_end: usize = pre311_else_end(stream, else_start, region.handler_start);
            let first_real: Option<usize> = (else_start..else_end)
                .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop));
            let ends_in_return: bool = (else_start..else_end)
                .rev()
                .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
                .is_some_and(|k: usize| {
                    matches!(
                        stream.ops[k],
                        CanonicalOp::Return | CanonicalOp::ReturnConst(_)
                    )
                });
            let body_return_via_finally: bool =
                ends_in_return && pre311_enclosed_by_finally(stream, region);
            if !body_return_via_finally
                && !pre311_span_is_implicit_none_exit(stream, else_start, else_end)
                && first_real.is_some_and(|k: usize| else_entry_is_fallthrough(&stream.ops[k]))
            {
                body_end = pb;
                else_region = Some((else_start, else_end));
            }
        }
    }

    let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, body_end)?;
    let mut handlers: Vec<ExceptHandler> =
        parse_except_handlers(code, stream, region.handler_start, handler_region_end)?;
    let mut orelse: Vec<Stmt> = match else_region {
        Some((s, e)) => structure_stmts(code, stream, s, e)?,
        None => Vec::new(),
    };
    if let Some((else_start, _)) = else_region
        && let Some(shared) = shared_construct_exit_return(&orelse, &handlers)
    {
        orelse.clear();
        handlers = strip_shared_exit_return(handlers, &shared);
        consumed = else_start;
    }
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers,
            orelse,
            finalbody: Vec::new(),
            line: None,
        },
        consumed,
    ))
}

fn pre311_enclosed_by_finally(stream: &DecodedStream, region: &TryRegion) -> bool {
    let Some(try_off): Option<u32> = stream.offsets.get(region.try_start).copied() else {
        return false;
    };
    let Some(handler_off): Option<u32> = stream.offsets.get(region.handler_start).copied() else {
        return false;
    };
    for entry in &stream.exception_table {
        let Some(enc_handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if enc_handler <= region.handler_start {
            continue;
        }
        if entry.start > try_off || entry.end() < handler_off {
            continue;
        }
        let enc_end: usize = pre311_handler_region_end(stream, enc_handler, stream.ops.len());
        if is_pre311_finally_handler_shape(stream, enc_handler, enc_end.min(stream.ops.len())) {
            return true;
        }
    }
    false
}

fn pre311_skip_pop_except(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::PopExcept | CanonicalOp::Nop | CanonicalOp::Cache)
        )
    {
        k += 1;
    }
    k
}

fn pre311_body_exit_jump_target(
    stream: &DecodedStream,
    pop_block: usize,
    handler_start: usize,
) -> Option<usize> {
    let k: usize = pre311_skip_pop_except(stream, pop_block + 1, handler_start);
    if k >= handler_start {
        return None;
    }
    if matches!(
        stream.ops.get(k),
        Some(CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_))
    ) {
        return resolve_jump_target(stream, k, &stream.ops[k]);
    }
    None
}

fn pre311_handler_swallow_target(
    stream: &DecodedStream,
    handler_start: usize,
    body_exit: usize,
) -> Option<usize> {
    (handler_start..body_exit)
        .rev()
        .filter(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpForward(_) | CanonicalOp::JumpAbsolute(_)
            )
        })
        .find_map(|k: usize| {
            resolve_jump_target(stream, k, &stream.ops[k]).filter(|t: &usize| *t >= body_exit)
        })
}

fn pre311_region_has_real_stmt(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    (lo..hi).any(|k: usize| {
        !matches!(
            stream.ops[k],
            CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::Reraise(_)
                | CanonicalOp::PopExcept
        )
    })
}

fn pre311_skip_jumps(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        )
    {
        k += 1;
    }
    k
}

fn pre311_span_is_implicit_none_exit(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    let significant: Vec<usize> = (lo..hi)
        .filter(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        })
        .collect();
    match significant.as_slice() {
        [only] => matches!(stream.ops[*only], CanonicalOp::ReturnConst(_)),
        [load, ret] => {
            is_none_const_push(&stream.ops[*load])
                && matches!(stream.ops[*ret], CanonicalOp::Return)
        }
        _ => false,
    }
}

fn pre311_else_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        )
    {
        end -= 1;
    }
    end
}

pub(super) fn is_pure_finally_handler_shape(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
    is_pre311: bool,
) -> bool {
    if is_pre311 {
        return is_pre311_finally_handler_shape(stream, handler_start, region_end);
    }
    let mut i: usize = handler_start;
    if !matches!(stream.ops.get(i), Some(CanonicalOp::PushExcInfo)) {
        return false;
    }
    i += 1;
    if matches!(
        first_significant(stream, i, region_end).map(|k: usize| &stream.ops[k]),
        Some(CanonicalOp::WithExceptStart)
    ) {
        return false;
    }
    if matches!(stream.ops.get(i), Some(CanonicalOp::Pop)) {
        return false;
    }
    for k in i..region_end {
        match stream.ops[k] {
            CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
            | CanonicalOp::Other(121, _)
            | CanonicalOp::PopExcept
            | CanonicalOp::Dup => return false,
            CanonicalOp::Reraise(_) => return true,
            _ => {}
        }
    }
    false
}

fn is_pre311_finally_handler_shape(
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> bool {
    let mut i: usize = handler_start;
    while i < region_end
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        i += 1;
    }
    if matches!(stream.ops.get(i), Some(CanonicalOp::Pop | CanonicalOp::Dup)) {
        return false;
    }
    for k in i..region_end {
        match stream.ops[k] {
            CanonicalOp::CheckExcMatch
            | CanonicalOp::CheckEgMatch
            | CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
            | CanonicalOp::Other(121, _)
            | CanonicalOp::PopExcept => return false,
            CanonicalOp::Dup if dup_is_exc_match_probe(stream, k, region_end) => return false,
            CanonicalOp::Reraise(_) => return true,
            _ if stream.pre311_end_finally_idx.contains(&k) => return true,
            _ => {}
        }
    }
    false
}

fn dup_is_exc_match_probe(stream: &DecodedStream, dup_idx: usize, region_end: usize) -> bool {
    let probe_end: usize = (dup_idx + 8).min(region_end);
    (dup_idx + 1..probe_end).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::CheckExcMatch
                | CanonicalOp::CheckEgMatch
                | CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch)
                | CanonicalOp::Other(121, _)
        )
    })
}

fn handler_body_first(stream: &DecodedStream, handler_start: usize) -> usize {
    if matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::PushExcInfo)
    ) {
        handler_start + 1
    } else {
        handler_start
    }
}

fn finally_body_end(stream: &DecodedStream, fin_start: usize, region_end: usize) -> usize {
    (fin_start..region_end)
        .find(|&k: &usize| {
            matches!(stream.ops[k], CanonicalOp::Reraise(_))
                || stream.pre311_end_finally_idx.contains(&k)
        })
        .unwrap_or(region_end)
}

fn pre311_inner_except_region_end(stream: &DecodedStream, region: &TryRegion) -> Option<usize> {
    let mut end: Option<usize> = None;
    for entry in &stream.exception_table {
        let Some(inner_handler): Option<usize> = stream.index_for_offset(entry.target) else {
            continue;
        };
        if inner_handler <= region.try_start || inner_handler >= region.handler_start {
            continue;
        }
        let inner_end: usize =
            pre311_handler_region_end(stream, inner_handler, region.handler_start);
        let bounded: usize = inner_end.min(region.handler_start);
        if !is_pre311_finally_handler_shape(stream, inner_handler, bounded) {
            end = Some(end.map_or(bounded, |prev: usize| prev.max(bounded)));
        }
    }
    end
}

fn try_structure_guard_over_finally(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
    region: &TryRegion,
) -> Result<Option<Vec<Stmt>>> {
    let Some(guard): Option<usize> = (lo..region.try_start).rev().find(|&k: &usize| {
        (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
    }) else {
        return Ok(None);
    };
    if guard <= lo {
        return Ok(None);
    }
    let Some(false_target): Option<usize> = resolve_jump_target(stream, guard, &stream.ops[guard])
        .filter(|&t: &usize| t > region.protected_end && t <= region.region_end && t <= hi)
    else {
        return Ok(None);
    };
    if false_target > region.handler_start && false_target < region.region_end {
        return Ok(None);
    }
    if (lo..guard).any(|k: usize| {
        (is_forward_cond_jump(&stream.ops[k]) || stream.none_jump_kind.contains_key(&k))
            && !is_chain_cond_jump(&stream.ops, k)
            && !is_value_form_shortcircuit(&stream.ops, k)
            && resolve_jump_target(stream, k, &stream.ops[k]).is_some_and(|t: usize| t > guard)
    }) {
        return Ok(None);
    }
    let body_lo: usize = (guard + 1..region.try_start)
        .find(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Nop | CanonicalOp::Cache | CanonicalOp::ExtendedArg(_)
            )
        })
        .unwrap_or(region.try_start);
    if body_lo < region.try_start
        && (body_lo..region.try_start).any(|k: usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Push(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        })
    {
        return Ok(None);
    }
    let Some(test_start): Option<usize> = guard_test_split_after_stmts(code, stream, lo, guard)
    else {
        return Ok(None);
    };
    let (test_head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[test_start..guard])?;
    if !test_head.is_empty() {
        return Ok(None);
    }
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
    let (finally_stmt, fin_tail): (Stmt, Vec<Stmt>) =
        structure_pure_finally(code, stream, region, region.protected_end)?;
    if !matches!(finally_stmt, Stmt::Try { .. }) {
        return Ok(None);
    }
    let fin_start: usize = handler_body_first(stream, region.handler_start);
    let fin_end: usize = finally_body_end(stream, fin_start, region.region_end);
    let finally_len: usize = fin_end.saturating_sub(fin_start);
    let cont_start: usize = (region.protected_end + finally_len).min(region.handler_start);
    let normal_cont_end: usize = false_target.max(cont_start).min(region.handler_start);
    let mut normal_cont: Vec<Stmt> = if cont_start < normal_cont_end {
        structure_stmts(code, stream, cont_start, normal_cont_end)?
    } else {
        Vec::new()
    };
    normal_cont.extend(fin_tail);
    while normal_cont.last().is_some_and(is_implicit_none_return) {
        normal_cont.pop();
    }
    let guard_exit: Vec<Stmt> = if false_target < region.handler_start {
        let mut gx: Vec<Stmt> = structure_stmts(code, stream, false_target, region.handler_start)?;
        while gx.last().is_some_and(is_implicit_none_return) {
            gx.pop();
        }
        gx
    } else {
        Vec::new()
    };
    let threaded: bool = !normal_cont.is_empty()
        && !guard_exit.is_empty()
        && stmts_textually_equal(&normal_cont, &guard_exit);
    let (inside_if, after_if): (Vec<Stmt>, Vec<Stmt>) = if threaded {
        (Vec::new(), normal_cont)
    } else {
        (normal_cont, guard_exit)
    };
    let mut if_body: Vec<Stmt> = vec![finally_stmt];
    if_body.extend(inside_if);
    let pre_head: Vec<Stmt> = structure_stmts(code, stream, lo, test_start)?;
    let mut out: Vec<Stmt> = pre_head;
    out.push(Stmt::If {
        test,
        body: non_empty(if_body),
        orelse: Vec::new(),
        line: None,
    });
    out.extend(after_if);
    if region.region_end < hi {
        out.extend(structure_stmts(code, stream, region.region_end, hi)?);
    }
    Ok(Some(out))
}

fn stmts_textually_equal(a: &[Stmt], b: &[Stmt]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|(x, y): (&Stmt, &Stmt)| format!("{x:?}") == format!("{y:?}"))
}

fn structure_pure_finally(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
    body_real_end: usize,
) -> Result<(Stmt, Vec<Stmt>)> {
    let _ = body_real_end;
    let fin_start: usize = handler_body_first(stream, region.handler_start);
    let fin_end: usize = finally_body_end(stream, fin_start, region.region_end);
    let finalbody: Vec<Stmt> = structure_stmts(code, stream, fin_start, fin_end)?;
    let finally_len: usize = fin_end.saturating_sub(fin_start);

    let protected_end: usize = region.protected_end.max(region.try_start);
    let body: Vec<Stmt> = if stream.is_pre_311() {
        let peeled: usize = pre311_inline_finally_start(
            stream,
            region.try_start,
            region.handler_start,
            finally_len,
        );
        let inline_start: usize = match pre311_inner_except_region_end(stream, region) {
            Some(inner_end) if peeled < inner_end => region.handler_start,
            _ => peeled,
        };
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            inline_start,
            region.handler_start,
            finally_len,
        )?
    } else {
        structure_finally_protected_body(
            code,
            stream,
            region.try_start,
            protected_end,
            region.handler_start,
            finally_len,
        )?
    };
    let (mut body, tail, merged_finally): (Vec<Stmt>, Vec<Stmt>, bool) = if stream.is_pre_311() {
        fold_pre311_combo_inner(body, &finalbody)
    } else {
        (body, Vec::new(), false)
    };
    if merged_finally && body.len() == 1 {
        let single: Stmt = body.remove(0);
        return Ok((single, tail));
    }
    Ok((
        Stmt::Try {
            body: non_empty(body),
            handlers: Vec::new(),
            orelse: Vec::new(),
            finalbody: non_empty(finalbody),
            line: None,
        },
        tail,
    ))
}

fn fold_pre311_combo_inner(body: Vec<Stmt>, finalbody: &[Stmt]) -> (Vec<Stmt>, Vec<Stmt>, bool) {
    if finalbody.is_empty() || body.len() != 1 || !matches!(body.first(), Some(Stmt::Try { .. })) {
        return (body, Vec::new(), false);
    }
    let Some(Stmt::Try {
        body: inner_body,
        handlers,
        orelse,
        finalbody: inner_final,
        line,
    }): Option<Stmt> = body.into_iter().next()
    else {
        return (Vec::new(), Vec::new(), false);
    };
    if !inner_final.is_empty() || handlers.is_empty() {
        return (
            vec![Stmt::Try {
                body: inner_body,
                handlers,
                orelse,
                finalbody: inner_final,
                line,
            }],
            Vec::new(),
            false,
        );
    }
    let mut inner_body: Vec<Stmt> = inner_body;
    strip_clause_inline_finally(&mut inner_body, finalbody, false);
    let handlers: Vec<ExceptHandler> = handlers
        .into_iter()
        .map(|mut h: ExceptHandler| {
            strip_clause_inline_finally(&mut h.body, finalbody, false);
            if h.body.is_empty() {
                h.body = vec![Stmt::Pass];
            }
            h
        })
        .collect();
    let mut orelse: Vec<Stmt> = orelse;
    let tail: Vec<Stmt> = strip_clause_inline_finally(&mut orelse, finalbody, true);
    (
        vec![Stmt::Try {
            body: non_empty(inner_body),
            handlers,
            orelse,
            finalbody: finalbody.to_vec(),
            line,
        }],
        tail,
        true,
    )
}

fn strip_clause_inline_finally(
    clause: &mut Vec<Stmt>,
    finalbody: &[Stmt],
    lift_tail: bool,
) -> Vec<Stmt> {
    if finalbody.is_empty() || clause.len() < finalbody.len() {
        return Vec::new();
    }
    let limit: usize = clause.len() - finalbody.len();
    let mut copy_at: Option<usize> = None;
    for start in (0..=limit).rev() {
        let window_matches: bool = clause[start..start + finalbody.len()]
            .iter()
            .zip(finalbody.iter())
            .all(|(a, b): (&Stmt, &Stmt)| format!("{a:?}") == format!("{b:?}"));
        if window_matches {
            copy_at = Some(start);
            break;
        }
    }
    let Some(copy_at): Option<usize> = copy_at else {
        return Vec::new();
    };
    if lift_tail {
        let tail: Vec<Stmt> = clause.split_off(copy_at + finalbody.len());
        clause.truncate(copy_at);
        return tail
            .into_iter()
            .filter(|s: &Stmt| matches!(s, Stmt::Return(_)))
            .collect();
    }
    clause.drain(copy_at..copy_at + finalbody.len());
    Vec::new()
}

fn pre311_inline_finally_start(
    stream: &DecodedStream,
    try_start: usize,
    handler_start: usize,
    finally_len: usize,
) -> usize {
    if finally_len == 0 {
        return handler_start;
    }
    let fin_body_start: usize = handler_start;
    let mut candidate: usize = handler_start.saturating_sub(finally_len);
    while candidate > try_start {
        if finally_runs_match(stream, fin_body_start, candidate, finally_len) {
            return candidate;
        }
        candidate -= 1;
    }
    if candidate >= try_start && finally_runs_match(stream, fin_body_start, candidate, finally_len)
    {
        return candidate;
    }
    handler_start
}

fn finally_runs_match(stream: &DecodedStream, a: usize, b: usize, len: usize) -> bool {
    if a + len > stream.ops.len() || b + len > stream.ops.len() {
        return false;
    }
    (0..len).all(|k: usize| {
        std::mem::discriminant(&stream.ops[a + k]) == std::mem::discriminant(&stream.ops[b + k])
    })
}

fn loop_spanning_finally_body_end(
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
    finally_len: usize,
) -> Option<usize> {
    let back_edge: usize = (protected_end..handler_start).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpBackward(_) | CanonicalOp::JumpBackwardNoInterrupt(_)
        ) && resolve_jump_target(stream, k, &stream.ops[k])
            .is_some_and(|t: usize| t >= try_start && t < protected_end)
    })?;
    if finally_len == 0 {
        return None;
    }
    let fin_body_start: usize = handler_body_first(stream, handler_start);
    let mut candidate: usize = handler_start.saturating_sub(finally_len);
    while candidate > back_edge {
        if finally_runs_match(stream, fin_body_start, candidate, finally_len) {
            return Some(candidate);
        }
        candidate -= 1;
    }
    None
}

fn structure_finally_protected_body(
    code: &CodeObject,
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
    finally_len: usize,
) -> Result<Vec<Stmt>> {
    if let Some(body_end) =
        loop_spanning_finally_body_end(stream, try_start, protected_end, handler_start, finally_len)
    {
        return structure_stmts(code, stream, try_start, body_end);
    }
    let inline_start: usize = protected_end;
    let inline_end: usize = (inline_start + finally_len).min(handler_start);
    let trailing_return: bool = (inline_end..handler_start)
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
        .is_some_and(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return | CanonicalOp::ReturnConst(_)
            )
        });
    if trailing_return && region_is_linear(stream, try_start, protected_end) {
        let (head, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[try_start..protected_end])?;
        let mut out: Vec<Stmt> = head;
        if let Some(value) = residual.into_iter().next_back() {
            out.push(Stmt::Return(Some(value)));
        }
        return Ok(out);
    }
    if trailing_return {
        let value_start: usize = trailing_value_run_start(stream, try_start, protected_end);
        if value_start > try_start
            && region_is_linear(stream, value_start, protected_end)
            && let Ok((tail_head, tail_residual)) =
                build_linear_stmts_sim(code, &stream.ops[value_start..protected_end])
            && tail_head.is_empty()
            && let Some(value) = tail_residual.into_iter().next_back()
        {
            let mut out: Vec<Stmt> = structure_stmts(code, stream, try_start, value_start)?;
            out.push(Stmt::Return(Some(value)));
            return Ok(out);
        }
    }
    structure_stmts(code, stream, try_start, protected_end)
}

fn trailing_value_run_start(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut start: usize = hi;
    while start > lo {
        let prev: usize = start - 1;
        if matches!(
            stream.ops[prev],
            CanonicalOp::Pop
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreAttr(_)
                | CanonicalOp::StoreSubscr
                | CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
        ) {
            break;
        }
        start = prev;
    }
    start
}

pub(super) fn region_is_linear(stream: &DecodedStream, lo: usize, hi: usize) -> bool {
    !(lo..hi).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::PopJumpIfFalse(_)
                | CanonicalOp::PopJumpIfTrue(_)
                | CanonicalOp::ForIter(_)
                | CanonicalOp::GetIter
                | CanonicalOp::BeforeWith
        )
    })
}

pub(super) fn special_method_name(slot: u32) -> &'static str {
    match slot {
        0 => "__enter__",
        1 => "__exit__",
        2 => "__aenter__",
        _ => "__aexit__",
    }
}

fn find_async_with_setup_end(
    stream: &DecodedStream,
    lo: usize,
    hi: usize,
) -> Option<(usize, usize)> {
    let mut i: usize = lo;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Copy(1))
            && let Some(special) = first_significant(stream, i + 1, hi)
            && matches!(stream.ops[special], CanonicalOp::LoadSpecial(_))
        {
            let enter: usize = (special + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadSpecial(2)))?;
            let call: usize = (enter + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
            return Some((i, call + 1));
        }
        i += 1;
    }
    None
}

fn find_with_setup_end(stream: &DecodedStream, lo: usize, hi: usize) -> Option<(usize, usize)> {
    let mut i: usize = lo;
    while i < hi {
        if matches!(stream.ops[i], CanonicalOp::Copy(1))
            && let Some(special) = first_significant(stream, i + 1, hi)
            && matches!(stream.ops[special], CanonicalOp::LoadSpecial(_))
        {
            let enter: usize = (special + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::LoadSpecial(0)))?;
            let call: usize = (enter + 1..hi)
                .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
            return Some((i, call + 1));
        }
        i += 1;
    }
    None
}

fn structure_async_with(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<Option<(Stmt, Vec<Stmt>)>> {
    let with_except: usize = match (region.handler_start..region.region_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::WithExceptStart))
    {
        Some(idx) => idx,
        None => return Ok(None),
    };
    if !first_significant(stream, with_except + 1, region.region_end)
        .is_some_and(|k: usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
    {
        return Ok(None);
    }
    let before_idx: Option<usize> = (region.try_start..region.try_end)
        .find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::BeforeAsyncWith));
    let (context_end, setup_end): (usize, usize) = if let Some(idx) = before_idx {
        (idx, idx + 1)
    } else {
        let Some((copy_idx, setup_end)): Option<(usize, usize)> =
            find_async_with_setup_end(stream, region.try_start, region.try_end)
        else {
            return Ok(None);
        };
        (copy_idx, setup_end)
    };
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[region.try_start..context_end])?;
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let enter_await: usize = (setup_end..region.try_end)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .unwrap_or(setup_end);
    let after_poll: usize = skip_await_poll(stream, enter_await + 1, region.try_end);
    let mut body_start: usize = after_poll;
    let mut optional_vars: Option<Expr> = None;
    match stream.ops.get(after_poll) {
        Some(CanonicalOp::StoreFast(slot)) => {
            optional_vars = local_target(code, *slot, after_poll).ok();
            body_start += 1;
        }
        Some(CanonicalOp::StoreName(slot)) => {
            optional_vars =
                name_at(&code.names, *slot, after_poll, "name")
                    .ok()
                    .map(|id: String| Expr::Name {
                        id,
                        ctx: ExprCtx::Store,
                        line: None,
                    });
            body_start += 1;
        }
        Some(CanonicalOp::Pop) => body_start += 1,
        _ => {}
    }
    let search_end: usize = region.region_end.max(region.try_end);
    let body_end: usize = with_body_end(code, stream, body_start, search_end);
    if let Some(ret) = async_with_stashed_return(code, stream, body_start, body_end)? {
        return Ok(Some((
            Stmt::With {
                items: vec![WithItem {
                    context_expr,
                    optional_vars,
                }],
                body: vec![ret],
                is_async: true,
                line: None,
            },
            Vec::new(),
        )));
    }
    let mut body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
    let owned_by_enclosing_try: bool =
        async_with_return_owned_by_enclosing_try(stream, body_end, search_end, stream.ops.len());
    let trailing: Option<Stmt> = async_with_trailing_return(code, stream, body_end, search_end)?;
    let post_with: Vec<Stmt> = if trailing.is_some() || owned_by_enclosing_try {
        Vec::new()
    } else {
        async_with_post_tail(code, stream, body_end, region.handler_start)?
    };
    if let Some(ret) = trailing {
        body.push(ret);
    }
    Ok(Some((
        Stmt::With {
            items: vec![WithItem {
                context_expr,
                optional_vars,
            }],
            body: non_empty(body),
            is_async: true,
            line: None,
        },
        post_with,
    )))
}

fn async_with_stashed_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> Result<Option<Stmt>> {
    let Some(swap): Option<usize> = (body_start..body_end)
        .rev()
        .find(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Cache | CanonicalOp::Nop))
    else {
        return Ok(None);
    };
    if !matches!(stream.ops[swap], CanonicalOp::Swap(2)) {
        return Ok(None);
    }
    let (head, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[body_start..swap])?;
    if !head.is_empty() {
        return Ok(None);
    }
    let Some(value): Option<Expr> = residual.into_iter().next_back() else {
        return Ok(None);
    };
    Ok(Some(Stmt::Return(Some(value))))
}

fn async_with_post_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    handler_start: usize,
) -> Result<Vec<Stmt>> {
    let Some(tail_start): Option<usize> = async_with_cleanup_end(stream, body_end, handler_start)
    else {
        return Ok(Vec::new());
    };
    if tail_start >= handler_start || !slice_has_real_stmt(stream, tail_start, handler_start) {
        return Ok(Vec::new());
    }
    structure_stmts(code, stream, tail_start, handler_start)
}

fn async_with_cleanup_end(stream: &DecodedStream, body_end: usize, hi: usize) -> Option<usize> {
    let mut i: usize = body_end;
    let mut loads: usize = 0;
    while i < hi && loads < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                loads += 1;
            }
            CanonicalOp::Push(0)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => {}
            _ => return None,
        }
        i += 1;
    }
    if loads < 3 {
        return None;
    }
    let call: usize =
        (i..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CallFunction(_)))?;
    let after_await: usize = (call + 1..hi)
        .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::GetAwaitable))
        .map_or(call + 1, |g: usize| skip_await_poll(stream, g + 1, hi));
    Some(
        first_significant(stream, after_await, hi)
            .filter(|&k: &usize| matches!(stream.ops[k], CanonicalOp::Pop))
            .map_or(after_await, |p: usize| p + 1),
    )
}

fn async_with_return_owned_by_enclosing_try(
    stream: &DecodedStream,
    ret_start: usize,
    hi: usize,
    scan_end: usize,
) -> bool {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return false;
    };
    (ret_idx + 1..scan_end).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::CheckEgMatch | CanonicalOp::CheckExcMatch
        )
    })
}

fn async_with_trailing_return(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    let Some(ret_start): Option<usize> = async_with_cleanup_end(stream, body_end, hi) else {
        return Ok(None);
    };
    if async_with_exit_guarded_by_branch(stream, ret_start, hi) {
        return Ok(None);
    }
    if async_with_return_owned_by_enclosing_try(stream, ret_start, hi, stream.ops.len()) {
        return Ok(None);
    }
    recover_return_at(code, stream, ret_start, hi)
}

fn async_with_exit_guarded_by_branch(stream: &DecodedStream, ret_start: usize, hi: usize) -> bool {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return false;
    };
    (ret_start..ret_idx).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            || matches!(
                stream.ops[k],
                CanonicalOp::ForIter(_)
                    | CanonicalOp::GetAnext
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::JumpBackward(_)
            )
    })
}

pub(super) fn recover_return_at(
    code: &CodeObject,
    stream: &DecodedStream,
    ret_start: usize,
    hi: usize,
) -> Result<Option<Stmt>> {
    let Some(ret_idx): Option<usize> = (ret_start..hi).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(None);
    };
    if let CanonicalOp::ReturnConst(c) = &stream.ops[ret_idx] {
        let value: Expr = load_const(code, *c, ret_idx)?;
        return Ok(Some(Stmt::Return(Some(value))));
    }
    let (_, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[ret_start..ret_idx])?;
    Ok(Some(Stmt::Return(residual.into_iter().next_back())))
}

pub(super) fn skip_await_poll(stream: &DecodedStream, from: usize, hi: usize) -> usize {
    let mut i: usize = from;
    while i < hi {
        match &stream.ops[i] {
            CanonicalOp::YieldFrom => return i + 1,
            CanonicalOp::LoadConst(_)
            | CanonicalOp::LoadCommonConst(7)
            | CanonicalOp::Push(0)
            | CanonicalOp::Send(_)
            | CanonicalOp::Yield
            | CanonicalOp::Resume(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::EndSend
            | CanonicalOp::CleanupThrow
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_) => i += 1,
            _ => break,
        }
    }
    i
}

#[derive(Debug)]
struct WithSetup {
    item: WithItem,
    setup_line: Option<u32>,
    next_start: usize,
}

type WithChainEntry = (WithItem, Option<u32>);

fn recover_with_setup(
    code: &CodeObject,
    stream: &DecodedStream,
    ctx_start: usize,
    hi: usize,
) -> Result<Option<WithSetup>> {
    let before_idx: Option<usize> =
        (ctx_start..hi).find(|&i: &usize| matches!(stream.ops[i], CanonicalOp::BeforeWith));
    let modern: Option<(usize, usize)> = find_with_setup_end(stream, ctx_start, hi);
    let (ctx_end, setup_end): (usize, usize) = match (before_idx, modern) {
        (Some(before_idx), Some((copy_idx, _))) if before_idx <= copy_idx => {
            (before_idx, before_idx + 1)
        }
        (Some(before_idx), None) => (before_idx, before_idx + 1),
        (_, Some((copy_idx, modern_end))) => (copy_idx, modern_end),
        (None, None) => return Ok(None),
    };
    let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[ctx_start..ctx_end])?;
    let carried_fused_store: usize = usize::from(matches!(
        stream.ops.get(ctx_start),
        Some(CanonicalOp::StoreFastLoadFast(_, _))
    ));
    if stmts.len() > carried_fused_store {
        return Ok(None);
    }
    let context_expr: Expr = residual.into_iter().next_back().unwrap_or(Expr::Constant {
        value: ConstValue::None,
        line: None,
    });
    let (optional_vars, next_start): (Option<Expr>, usize) = match stream.ops.get(setup_end) {
        Some(CanonicalOp::StoreFast(slot)) => {
            (local_target(code, *slot, setup_end).ok(), setup_end + 1)
        }
        Some(CanonicalOp::StoreName(slot)) => (
            name_at(&code.names, *slot, setup_end, "name")
                .ok()
                .map(|id: String| Expr::Name {
                    id,
                    ctx: ExprCtx::Store,
                    line: None,
                }),
            setup_end + 1,
        ),
        Some(CanonicalOp::StoreFastLoadFast(slot, _)) => {
            (local_target(code, *slot, setup_end).ok(), setup_end)
        }
        Some(CanonicalOp::Pop) => (None, setup_end + 1),
        _ => (None, setup_end),
    };
    Ok(Some(WithSetup {
        item: WithItem {
            context_expr,
            optional_vars,
        },
        setup_line: stream.line_at(ctx_end),
        next_start,
    }))
}

fn collect_with_chain(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<(Vec<WithChainEntry>, usize)> {
    let search_end: usize = region.region_end.max(region.try_end);
    let mut items: Vec<WithChainEntry> = Vec::new();
    let mut cursor: usize = region.try_start;
    let mut pending: Option<WithSetup> = recover_with_setup(code, stream, cursor, search_end)?;
    while let Some(setup) = pending {
        let next_start: usize = setup.next_start;
        items.push((setup.item, setup.setup_line));
        if next_start <= cursor {
            break;
        }
        cursor = next_start;
        pending = recover_with_setup(code, stream, cursor, search_end)?;
    }
    Ok((items, cursor))
}

fn structure_with(
    code: &CodeObject,
    stream: &DecodedStream,
    region: &TryRegion,
) -> Result<(Stmt, Vec<Stmt>)> {
    if let Some(stmt_and_tail) = structure_async_with(code, stream, region)? {
        return Ok(stmt_and_tail);
    }
    let (chain, body_start): (Vec<WithChainEntry>, usize) =
        collect_with_chain(code, stream, region)?;
    if chain.is_empty() {
        let body: Vec<Stmt> = structure_stmts(code, stream, region.try_start, region.try_end)?;
        return Ok((
            Stmt::With {
                items: vec![WithItem {
                    context_expr: Expr::Constant {
                        value: ConstValue::None,
                        line: None,
                    },
                    optional_vars: None,
                }],
                body: non_empty(body),
                is_async: false,
                line: None,
            },
            Vec::new(),
        ));
    }
    let search_end: usize = region.region_end.max(region.try_end);
    let scanned_end: usize = with_body_end(code, stream, body_start, search_end);
    let body_end: usize =
        clamp_with_body_to_protected(stream, region, body_start, scanned_end, search_end);
    if body_end < scanned_end
        && let Some(cont_start) = skip_with_cleanup_block(stream, body_end, search_end)
        && cont_start < region.handler_start
        && slice_has_real_stmt(stream, cont_start, region.handler_start)
    {
        let (body, _tail): (Vec<Stmt>, Vec<Stmt>) =
            structure_with_body(code, stream, body_start, body_end, search_end)?;
        let continuation: Vec<Stmt> =
            structure_stmts(code, stream, cont_start, region.handler_start)?;
        return Ok((assemble_with_chain(chain, body), continuation));
    }
    let (body, mut tail): (Vec<Stmt>, Vec<Stmt>) =
        structure_with_body(code, stream, body_start, body_end, search_end)?;
    if tail.is_empty()
        && let Some(cont_start) = with_handler_backjump_continuation(stream, region, body_end)
    {
        tail = structure_stmts(code, stream, cont_start, region.handler_start)?;
    }
    Ok((assemble_with_chain(chain, body), tail))
}

fn clamp_with_body_to_protected(
    stream: &DecodedStream,
    region: &TryRegion,
    body_start: usize,
    scanned_end: usize,
    search_end: usize,
) -> usize {
    if stream.is_pre_311() || region.try_end <= body_start || region.try_end >= scanned_end {
        return scanned_end;
    }
    let protected: usize = region.try_end;
    let is_own_exit_cleanup: bool = matches!(
        stream.ops.get(protected),
        Some(CanonicalOp::Swap(_) | CanonicalOp::RotN(_))
    ) || (is_none_const_push(&stream.ops[protected])
        && is_exit_none_triple(stream, protected, search_end));
    if !is_own_exit_cleanup {
        return scanned_end;
    }
    let Some(after_cleanup): Option<usize> = skip_with_cleanup_block(stream, protected, search_end)
    else {
        return scanned_end;
    };
    let continues: bool = after_cleanup < search_end
        && slice_has_real_stmt(stream, after_cleanup, search_end.min(scanned_end));
    if continues { protected } else { scanned_end }
}

fn with_handler_backjump_continuation(
    stream: &DecodedStream,
    region: &TryRegion,
    body_end: usize,
) -> Option<usize> {
    if region.handler_start <= body_end {
        return None;
    }
    let pop_except: usize =
        handler_pop_except_idx(stream, region.handler_start, region.region_end)?;
    let mut exit: usize = pop_except + 1;
    while exit < region.region_end
        && matches!(
            stream.ops[exit],
            CanonicalOp::Pop | CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
        )
    {
        exit += 1;
    }
    if exit >= region.region_end
        || !matches!(stream.ops[exit], CanonicalOp::JumpBackwardNoInterrupt(_))
    {
        return None;
    }
    let cont_start: usize = resolve_jump_target(stream, exit, &stream.ops[exit])
        .filter(|t: &usize| (body_end..region.handler_start).contains(t))?;
    slice_has_real_stmt(stream, cont_start, region.handler_start).then_some(cont_start)
}

fn with_enclosing_try_region(
    stream: &DecodedStream,
    region: &TryRegion,
    hi: usize,
) -> Option<TryRegion> {
    if !region.is_with || stream.is_pre_311() || region.handler_start >= hi {
        return None;
    }
    let with_cleanup_end: usize = handler_chain_end(stream, region.handler_start, hi)?;
    let enclosing: TryRegion =
        find_protected_try_with_outer_handler(stream, region.try_start, with_cleanup_end, hi)?;
    let body_starts_in_with: bool =
        (region.try_start..region.protected_end).contains(&enclosing.try_start);
    let handler_after_with: bool = enclosing.handler_start >= with_cleanup_end;
    let real_except: bool = matches!(
        stream.ops.get(enclosing.handler_start),
        Some(CanonicalOp::PushExcInfo)
    ) && !matches!(
        stream.ops.get(enclosing.handler_start + 1),
        Some(CanonicalOp::WithExceptStart)
    );
    (body_starts_in_with && handler_after_with && real_except).then_some(enclosing)
}

fn try_enclosing_except_region(
    stream: &DecodedStream,
    region: &TryRegion,
    hi: usize,
) -> Option<(usize, usize, usize)> {
    if region.is_with || region.is_finally || stream.is_pre_311() || region.handler_start >= hi {
        return None;
    }
    if (region.handler_start..region.region_end)
        .any(|k: usize| matches!(stream.ops.get(k), Some(CanonicalOp::CheckEgMatch)))
    {
        return None;
    }
    let inner_handler_off: u32 = stream.offsets.get(region.handler_start).copied()?;
    let inner_end: usize =
        handler_chain_end(stream, region.handler_start, hi)?.max(region.region_end);
    let inner_end_off: u32 = stream.offsets.get(inner_end).copied().unwrap_or(u32::MAX);
    let outer_handler_start: usize = stream
        .exception_table
        .iter()
        .filter(|e: &&crate::bytecode::flow::ExceptionTableEntry| {
            (inner_handler_off..inner_end_off).contains(&e.start)
        })
        .filter_map(|e: &crate::bytecode::flow::ExceptionTableEntry| {
            let hs: usize = stream.index_for_offset(e.target)?;
            ((inner_end..hi).contains(&hs)
                && matches!(stream.ops.get(hs), Some(CanonicalOp::PushExcInfo))
                && !matches!(stream.ops.get(hs + 1), Some(CanonicalOp::WithExceptStart)))
            .then_some(hs)
        })
        .min()?;
    let outer_region_end: usize = handler_chain_end(stream, outer_handler_start, hi)?.min(hi);
    if is_pure_finally_handler_shape(stream, outer_handler_start, outer_region_end, false) {
        return None;
    }
    Some((outer_handler_start, outer_region_end, inner_end))
}

fn assemble_with_chain(chain: Vec<WithChainEntry>, body: Vec<Stmt>) -> Stmt {
    let mut groups: Vec<Vec<WithItem>> = Vec::new();
    let mut last_line: Option<u32> = None;
    for (item, item_line) in chain {
        let same_line: bool = matches!((item_line, last_line), (Some(l), Some(p)) if l == p);
        if same_line && let Some(group) = groups.last_mut() {
            group.push(item);
        } else {
            groups.push(vec![item]);
        }
        last_line = item_line.or(last_line);
    }
    let mut inner_body: Vec<Stmt> = non_empty(body);
    for items in groups.into_iter().rev() {
        inner_body = vec![Stmt::With {
            items,
            body: inner_body,
            is_async: false,
            line: None,
        }];
    }
    inner_body.into_iter().next().unwrap_or(Stmt::Pass)
}

fn structure_with_body(
    code: &CodeObject,
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
    region_end: usize,
) -> Result<(Vec<Stmt>, Vec<Stmt>)> {
    let mut trim_end: usize = body_end;
    while trim_end > body_start
        && matches!(
            stream.ops[trim_end - 1],
            CanonicalOp::Swap(_) | CanonicalOp::RotN(_)
        )
    {
        trim_end -= 1;
    }
    let swap_present: bool = trim_end < body_end;
    let trailing_return: bool = is_with_trailing_return(stream, body_end, region_end);
    let has_internal_control_flow: bool =
        with_body_has_internal_control_flow(stream, body_start, trim_end);
    if swap_present && trailing_return && !has_internal_control_flow {
        let (stmts, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[body_start..trim_end])?;
        let mut out: Vec<Stmt> = stmts;
        if let Some(value) = residual.into_iter().next_back() {
            out.push(Stmt::Return(Some(value)));
        }
        return Ok((out, Vec::new()));
    }
    let body: Vec<Stmt> = if has_internal_control_flow
        && let Some(folded) = elide_inline_with_exits(stream, body_start, body_end)
    {
        structure_stmts(code, &folded, body_start, body_end)?
    } else {
        structure_stmts(code, stream, body_start, body_end)?
    };
    let tail: Vec<Stmt> = if swap_present {
        Vec::new()
    } else {
        with_post_cleanup_tail(code, stream, body_end, region_end)?
    };
    Ok((body, tail))
}

pub(super) fn offset_is_unprotected(stream: &DecodedStream, off: u32) -> bool {
    !stream
        .exception_table
        .iter()
        .any(|e: &crate::bytecode::flow::ExceptionTableEntry| e.start <= off && off < e.end())
}

fn no_swap_inline_with_exit(stream: &DecodedStream, i: usize, body_end: usize) -> Option<usize> {
    if !(is_none_const_push(&stream.ops[i]) && is_exit_none_triple(stream, i, body_end)) {
        return None;
    }
    let call: usize = {
        let mut seen: usize = 0;
        let mut k: usize = i;
        while k < body_end && seen < 3 {
            if matches!(
                stream.ops[k],
                CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup
            ) {
                seen += 1;
            }
            k += 1;
        }
        first_significant(stream, k, body_end)?
    };
    let call_off: u32 = *stream.offsets.get(call)?;
    if !offset_is_unprotected(stream, call_off) {
        return None;
    }
    let after: usize = skip_with_cleanup_block(stream, i, body_end)?;
    let term: usize = {
        let mut k: usize = first_significant(stream, after, body_end)?;
        while k < body_end
            && matches!(
                stream.ops[k],
                CanonicalOp::LoadConst(_)
                    | CanonicalOp::LoadSmallInt(_)
                    | CanonicalOp::LoadCommonConst(_)
                    | CanonicalOp::LoadFast(_)
                    | CanonicalOp::LoadFastLoadFast(_, _)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
            )
        {
            k += 1;
        }
        k
    };
    matches!(
        stream.ops.get(term),
        Some(
            CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::Raise(_)
                | CanonicalOp::JumpForward(_)
                | CanonicalOp::JumpAbsolute(_)
                | CanonicalOp::JumpBackward(_)
                | CanonicalOp::JumpBackwardNoInterrupt(_)
        )
    )
    .then_some(after)
}

fn elide_inline_with_exits(
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> Option<DecodedStream> {
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut i: usize = body_start;
    while i < body_end {
        if matches!(stream.ops[i], CanonicalOp::Swap(_) | CanonicalOp::RotN(_))
            && let Some(after) = skip_with_cleanup_block(stream, i, body_end)
            && first_significant(stream, after, body_end).is_some_and(|t: usize| {
                matches!(
                    stream.ops[t],
                    CanonicalOp::Return
                        | CanonicalOp::ReturnConst(_)
                        | CanonicalOp::Raise(_)
                        | CanonicalOp::JumpForward(_)
                        | CanonicalOp::JumpAbsolute(_)
                        | CanonicalOp::JumpBackward(_)
                        | CanonicalOp::JumpBackwardNoInterrupt(_)
                )
            })
        {
            spans.push((i, after));
            i = after;
        } else if let Some(after) = no_swap_inline_with_exit(stream, i, body_end) {
            spans.push((i, after));
            i = after;
        } else {
            i += 1;
        }
    }
    if spans.is_empty() {
        return None;
    }
    let mut ops: Vec<CanonicalOp> = stream.ops.clone();
    for (lo, hi) in spans {
        for op in &mut ops[lo..hi] {
            *op = CanonicalOp::Nop;
        }
    }
    Some(DecodedStream {
        ops,
        offsets: stream.offsets.clone(),
        next_offsets: stream.next_offsets.clone(),
        code_len: stream.code_len,
        lines: stream.lines.clone(),
        wordcode: stream.wordcode,
        instr_unit_jumps: stream.instr_unit_jumps,
        relative_cond_jumps: stream.relative_cond_jumps,
        exception_table: stream.exception_table.clone(),
        pre311_end_finally_idx: stream.pre311_end_finally_idx.clone(),
        pre311_pop_block_idx: stream.pre311_pop_block_idx.clone(),
        pre311_break_loop_idx: stream.pre311_break_loop_idx.clone(),
        setup_loop_end: stream.setup_loop_end.clone(),
        none_jump_kind: stream.none_jump_kind.clone(),
        version: stream.version.clone(),
    })
}

fn with_body_has_internal_control_flow(
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
) -> bool {
    (body_start..body_end).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            || matches!(
                stream.ops[k],
                CanonicalOp::Return | CanonicalOp::ReturnConst(_)
            )
    })
}

fn with_post_cleanup_tail(
    code: &CodeObject,
    stream: &DecodedStream,
    body_end: usize,
    region_end: usize,
) -> Result<Vec<Stmt>> {
    let mut ret_start: usize = body_end;
    let mut cleanups: usize = 0;
    while let Some(next) = skip_with_cleanup_block(stream, ret_start, region_end) {
        ret_start = next;
        cleanups += 1;
    }
    if cleanups == 0 {
        return Ok(Vec::new());
    }
    let Some(ret_idx): Option<usize> = (ret_start..region_end).find(|&k: &usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::Return | CanonicalOp::ReturnConst(_)
        )
    }) else {
        return Ok(Vec::new());
    };
    let has_exc_scaffold: bool = (ret_start..ret_idx).any(|k: usize| {
        matches!(
            stream.ops[k],
            CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
        )
    });
    if has_exc_scaffold {
        return Ok(Vec::new());
    }
    let tail_end: usize = (ret_start..region_end)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
            )
        })
        .unwrap_or(region_end);
    let branched: bool = (ret_start..tail_end).any(|k: usize| {
        is_forward_cond_jump(&stream.ops[k])
            && resolve_jump_target(stream, k, &stream.ops[k])
                .is_some_and(|t: usize| (ret_start..=tail_end).contains(&t))
    });
    if branched && slice_has_real_stmt(stream, ret_start, tail_end) {
        return structure_stmts(code, stream, ret_start, tail_end);
    }
    let (mut stmts, residual): (Vec<Stmt>, Vec<Expr>) =
        build_linear_stmts_sim(code, &stream.ops[ret_start..ret_idx])?;
    let return_value: Option<Expr> = if let CanonicalOp::ReturnConst(c) = &stream.ops[ret_idx] {
        Some(load_const(code, *c, ret_idx)?)
    } else {
        residual.into_iter().next_back()
    };
    stmts.push(Stmt::Return(return_value));
    Ok(stmts)
}

fn is_with_trailing_return(stream: &DecodedStream, body_end: usize, region_end: usize) -> bool {
    let mut i: usize = body_end;
    while let Some(next) = skip_with_cleanup_block(stream, i, region_end) {
        i = next;
    }
    while i < region_end {
        match &stream.ops[i] {
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => i += 1,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) => return true,
            _ => return false,
        }
    }
    false
}

fn skip_with_cleanup_block(
    stream: &DecodedStream,
    start: usize,
    region_end: usize,
) -> Option<usize> {
    let mut i: usize = first_significant(stream, start, region_end)?;
    while matches!(stream.ops[i], CanonicalOp::Swap(_) | CanonicalOp::RotN(_)) {
        i = first_significant(stream, i + 1, region_end)?;
    }
    let mut loads: usize = 0;
    while i < region_end && loads < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                loads += 1;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => return None,
        }
        i += 1;
    }
    if loads < 3 {
        return None;
    }
    i = first_significant(stream, i, region_end)?;
    if !matches!(
        stream.ops[i],
        CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
    ) {
        return None;
    }
    i = first_significant(stream, i + 1, region_end)?;
    if !matches!(stream.ops[i], CanonicalOp::Pop) {
        return None;
    }
    Some(i + 1)
}

fn with_body_exit_count(
    code: &CodeObject,
    stream: &DecodedStream,
    lo: usize,
    handler_bound: usize,
) -> usize {
    let mut exits: Vec<bool> = Vec::new();
    let mut i: usize = lo;
    while i < handler_bound {
        let cleanup_start: bool =
            matches!(stream.ops[i], CanonicalOp::Swap(_) | CanonicalOp::RotN(_))
                || (is_none_const_push(&stream.ops[i])
                    && is_exit_none_triple(stream, i, handler_bound));
        if cleanup_start && let Some(after) = skip_with_cleanup_block(stream, i, handler_bound) {
            let value_at: Option<usize> = (after < handler_bound
                && matches!(
                    stream.ops[after],
                    CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(_)
                ))
            .then_some(after);
            let mut k: usize = after;
            while k < handler_bound
                && matches!(
                    stream.ops[k],
                    CanonicalOp::LoadConst(_)
                        | CanonicalOp::LoadSmallInt(_)
                        | CanonicalOp::LoadCommonConst(_)
                        | CanonicalOp::LoadFast(_)
                        | CanonicalOp::LoadFastLoadFast(_, _)
                        | CanonicalOp::Nop
                        | CanonicalOp::Cache
                        | CanonicalOp::ExtendedArg(_)
                )
            {
                k += 1;
            }
            if matches!(
                stream.ops.get(k),
                Some(
                    CanonicalOp::Return
                        | CanonicalOp::ReturnConst(_)
                        | CanonicalOp::Raise(_)
                        | CanonicalOp::JumpForward(_)
                        | CanonicalOp::JumpAbsolute(_)
                        | CanonicalOp::JumpBackward(_)
                        | CanonicalOp::JumpBackwardNoInterrupt(_)
                )
            ) {
                let returns_none: bool = matches!(stream.ops.get(k), Some(CanonicalOp::Return))
                    && value_at.is_some_and(|v: usize| loads_none(code, &stream.ops[v]));
                exits.push(returns_none);
            }
            i = after;
        } else {
            i += 1;
        }
    }
    if exits.last() == Some(&true) {
        exits.pop();
    }
    exits.len()
}

fn with_body_end(code: &CodeObject, stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let handler_bound: usize = (lo..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
            )
        })
        .unwrap_or(hi);
    if with_body_exit_count(code, stream, lo, handler_bound) >= 2 {
        return handler_bound;
    }
    for i in lo..hi {
        if is_none_const_push(&stream.ops[i])
            && is_exit_none_triple(stream, i, hi)
            && with_cleanup_tail_is_pure(stream, i, hi)
        {
            return i;
        }
    }
    for i in lo..hi {
        if is_none_const_push(&stream.ops[i]) && is_exit_none_triple(stream, i, hi) {
            return i;
        }
    }
    hi
}

fn with_cleanup_tail_is_pure(stream: &DecodedStream, triple_start: usize, hi: usize) -> bool {
    let mut i: usize = triple_start;
    while let Some(next) = skip_with_cleanup_block(stream, i, hi) {
        i = next;
    }
    (i..hi)
        .take_while(|&k: &usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::PushExcInfo | CanonicalOp::WithExceptStart
            )
        })
        .all(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return
                    | CanonicalOp::ReturnConst(_)
                    | CanonicalOp::Raise(_)
                    | CanonicalOp::Reraise(_)
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpBackwardNoInterrupt(_)
                    | CanonicalOp::LoadConst(_)
                    | CanonicalOp::LoadSmallInt(_)
                    | CanonicalOp::LoadCommonConst(_)
                    | CanonicalOp::LoadFast(_)
                    | CanonicalOp::Cache
                    | CanonicalOp::Nop
                    | CanonicalOp::ExtendedArg(_)
            )
        })
}

#[inline]
fn is_none_const_push(op: &CanonicalOp) -> bool {
    matches!(
        op,
        CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7)
    )
}

fn is_exit_none_triple(stream: &DecodedStream, start: usize, hi: usize) -> bool {
    let mut seen: usize = 0;
    let mut i: usize = start;
    while i < hi && seen < 3 {
        match &stream.ops[i] {
            CanonicalOp::LoadConst(_) | CanonicalOp::LoadCommonConst(7) | CanonicalOp::Dup => {
                seen += 1;
            }
            CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_) => {}
            _ => return false,
        }
        i += 1;
    }
    if seen < 3 {
        return false;
    }
    first_significant(stream, i, hi).is_some_and(|call: usize| {
        matches!(
            stream.ops[call],
            CanonicalOp::CallFunction(_) | CanonicalOp::CallFunctionKw(_)
        )
    })
}

fn skip_await_send_loop(stream: &DecodedStream, end: usize, handler_start: usize) -> usize {
    if !matches!(
        stream.ops.get(end),
        Some(CanonicalOp::Yield | CanonicalOp::Send(_))
    ) {
        return end;
    }
    let mut k: usize = end;
    while k < handler_start {
        match stream.ops.get(k) {
            Some(CanonicalOp::EndSend) => {
                let mut after: usize = k + 1;
                while after < handler_start
                    && matches!(
                        stream.ops.get(after),
                        Some(CanonicalOp::Cache | CanonicalOp::Nop)
                    )
                {
                    after += 1;
                }
                if matches!(stream.ops.get(after), Some(CanonicalOp::Pop)) {
                    after += 1;
                }
                return after;
            }
            Some(
                CanonicalOp::Yield
                | CanonicalOp::Send(_)
                | CanonicalOp::Resume(_)
                | CanonicalOp::CleanupThrow
                | CanonicalOp::JumpBackwardNoInterrupt(_)
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_),
            ) => k += 1,
            _ => return end,
        }
    }
    end
}

fn extend_try_body(
    code: &CodeObject,
    stream: &DecodedStream,
    try_end: usize,
    handler_start: usize,
) -> usize {
    let mut end: usize = try_end;
    let mut balanced: bool = try_end
        .checked_sub(1)
        .and_then(|p: usize| stream.ops.get(p))
        .is_some_and(|op: &CanonicalOp| {
            matches!(
                op,
                CanonicalOp::Pop
                    | CanonicalOp::StoreFast(_)
                    | CanonicalOp::StoreName(_)
                    | CanonicalOp::StoreGlobal(_)
                    | CanonicalOp::StoreAttr(_)
                    | CanonicalOp::StoreSubscr
            )
        });
    while end < handler_start {
        let after_await: usize = skip_await_send_loop(stream, end, handler_start);
        if after_await > end {
            end = after_await;
            continue;
        }
        match stream.ops.get(end) {
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)) => {
                end += 1;
            }
            Some(CanonicalOp::ReturnConst(slot)) if balanced && is_const_none(code, *slot) => {
                break;
            }
            Some(
                CanonicalOp::Return
                | CanonicalOp::ReturnConst(_)
                | CanonicalOp::StoreFast(_)
                | CanonicalOp::StoreName(_)
                | CanonicalOp::StoreGlobal(_)
                | CanonicalOp::StoreAttr(_)
                | CanonicalOp::StoreSubscr
                | CanonicalOp::Pop,
            ) => {
                end += 1;
                balanced = true;
            }
            _ => break,
        }
    }
    end
}

fn is_const_none(code: &CodeObject, slot: crate::bytecode::opcode::ConstIndex) -> bool {
    matches!(
        load_const(code, slot, 0),
        Ok(Expr::Constant {
            value: ConstValue::None,
            ..
        })
    )
}

fn extend_end_past_shortcircuit_stmt(stream: &DecodedStream, end: usize, hi: usize) -> usize {
    let mut end: usize = end;
    while protected_end_splits_shortcircuit(stream, end) {
        let Some(terminator): Option<usize> = (end..hi).find(|&k: &usize| match stream.ops[k] {
            CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreFastLoadFast(_, _)
            | CanonicalOp::StoreFastStoreFast(_, _)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_) => true,
            CanonicalOp::Pop => !is_shortcircuit_cleanup_pop(stream, k),
            _ => false,
        }) else {
            return end;
        };
        let next: usize = (terminator + 1).min(hi);
        if next <= end {
            return end;
        }
        end = next;
    }
    end
}

fn op_leaves_value(op: &CanonicalOp) -> bool {
    !matches!(
        op,
        CanonicalOp::StoreFast(_)
            | CanonicalOp::StoreName(_)
            | CanonicalOp::StoreGlobal(_)
            | CanonicalOp::StoreAttr(_)
            | CanonicalOp::StoreSubscr
            | CanonicalOp::StoreFastLoadFast(_, _)
            | CanonicalOp::StoreFastStoreFast(_, _)
            | CanonicalOp::Pop
            | CanonicalOp::DiscardTop
            | CanonicalOp::Return
            | CanonicalOp::ReturnConst(_)
            | CanonicalOp::Raise(_)
            | CanonicalOp::Reraise(_)
            | CanonicalOp::PopExcept
            | CanonicalOp::PushExcInfo
            | CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::JumpBackward(_)
            | CanonicalOp::JumpBackwardNoInterrupt(_)
            | CanonicalOp::PopJumpIfFalse(_)
            | CanonicalOp::PopJumpIfTrue(_)
            | CanonicalOp::PopJumpIfFalseRel(_)
            | CanonicalOp::PopJumpIfTrueRel(_)
            | CanonicalOp::PopJumpIfFalseBackward(_)
            | CanonicalOp::PopJumpIfTrueBackward(_)
            | CanonicalOp::Cache
            | CanonicalOp::Nop
            | CanonicalOp::ExtendedArg(_)
    )
}

fn extend_body_over_trailing_guard(
    stream: &DecodedStream,
    try_start: usize,
    body_end: usize,
    false_target: usize,
) -> usize {
    if body_end == 0 || body_end >= false_target {
        return body_end;
    }
    let Some(last): Option<usize> = last_significant_back(stream, try_start, body_end) else {
        return body_end;
    };
    if !is_forward_cond_jump(&stream.ops[last]) || is_chain_cond_jump(&stream.ops, last) {
        return body_end;
    }
    let Some(target): Option<usize> = resolve_jump_target(stream, last, &stream.ops[last])
        .filter(|t: &usize| *t > body_end && *t <= false_target)
    else {
        return body_end;
    };
    let tail_terminates: bool =
        last_significant_back(stream, body_end, target).is_some_and(|k: usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::Return
                    | CanonicalOp::ReturnConst(_)
                    | CanonicalOp::Raise(_)
                    | CanonicalOp::Reraise(_)
            )
        });
    let tail_has_no_handler_boundary: bool = (body_end..target).all(|k: usize| {
        stream
            .offsets
            .get(k)
            .copied()
            .is_none_or(|off: u32| !is_handler_target(stream, off))
    });
    if tail_terminates && tail_has_no_handler_boundary {
        target
    } else {
        body_end
    }
}

fn protected_body_end_with_return(
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
) -> usize {
    if protected_end >= handler_start {
        return protected_end;
    }
    let Some(first): Option<usize> = first_significant(stream, protected_end, handler_start) else {
        return protected_end;
    };
    let ret: usize = match stream.ops.get(first) {
        Some(CanonicalOp::Return) => first,
        Some(
            CanonicalOp::Swap(_) | CanonicalOp::Copy(_) | CanonicalOp::RotN(_) | CanonicalOp::Pop,
        ) if loop_frame_depth() > 0 => {
            match return_after_iter_cleanup(stream, first, handler_start) {
                Some(k) => k,
                None => return protected_end,
            }
        }
        _ => return protected_end,
    };
    let leaves_value: bool = last_significant_back(stream, try_start, protected_end)
        .is_some_and(|k: usize| op_leaves_value(&stream.ops[k]));
    if leaves_value { ret + 1 } else { protected_end }
}

fn single_const_return_tail_end(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    let mut k: usize = from;
    let mut returns: usize = 0;
    while k < hi {
        match stream.ops.get(k) {
            Some(
                CanonicalOp::LoadConst(_)
                | CanonicalOp::LoadSmallInt(_)
                | CanonicalOp::LoadCommonConst(_)
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_),
            ) => k += 1,
            Some(CanonicalOp::Return | CanonicalOp::ReturnConst(_)) => {
                returns += 1;
                k += 1;
            }
            _ => break,
        }
    }
    (returns == 1 && k > from).then_some(k)
}

fn extend_protected_end_over_guard_return(
    stream: &DecodedStream,
    try_start: usize,
    protected_end: usize,
    handler_start: usize,
) -> usize {
    if protected_end >= handler_start {
        return protected_end;
    }
    let body_falls_through: bool = last_significant_back(stream, try_start, protected_end)
        .is_some_and(|k: usize| {
            !matches!(
                stream.ops[k],
                CanonicalOp::Return
                    | CanonicalOp::ReturnConst(_)
                    | CanonicalOp::Raise(_)
                    | CanonicalOp::Reraise(_)
                    | CanonicalOp::JumpBackward(_)
                    | CanonicalOp::JumpBackwardNoInterrupt(_)
            )
        });
    if !body_falls_through {
        return protected_end;
    }
    let Some(tail_end): Option<usize> =
        single_const_return_tail_end(stream, protected_end, handler_start)
    else {
        return protected_end;
    };
    let guards_targeting_tail: usize = (try_start..protected_end)
        .filter(|&k: &usize| {
            is_forward_cond_jump(&stream.ops[k])
                && !is_chain_cond_jump(&stream.ops, k)
                && !is_value_form_shortcircuit(&stream.ops, k)
                && resolve_jump_target(stream, k, &stream.ops[k])
                    .is_some_and(|t: usize| (protected_end..tail_end).contains(&t))
        })
        .count();
    if guards_targeting_tail == 1 {
        tail_end
    } else {
        protected_end
    }
}

fn return_after_iter_cleanup(stream: &DecodedStream, from: usize, hi: usize) -> Option<usize> {
    let mut k: usize = from;
    while k < hi {
        match stream.ops.get(k) {
            Some(
                CanonicalOp::Swap(_)
                | CanonicalOp::Copy(_)
                | CanonicalOp::RotN(_)
                | CanonicalOp::Pop
                | CanonicalOp::Cache
                | CanonicalOp::Nop
                | CanonicalOp::ExtendedArg(_),
            ) => k += 1,
            Some(CanonicalOp::Return) => return Some(k),
            _ => return None,
        }
    }
    None
}

fn trim_try_body_jump(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
            )
        )
    {
        end -= 1;
    }
    end
}

fn handler_tail_returns_through_pop_except(
    stream: &DecodedStream,
    body_start: usize,
    next_handler: usize,
) -> bool {
    if next_handler <= body_start || next_handler >= stream.ops.len() {
        return false;
    }
    if !matches!(stream.ops.get(next_handler), Some(CanonicalOp::Return)) {
        return false;
    }
    let mut k: usize = next_handler;
    while k > body_start
        && matches!(
            stream.ops.get(k - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        k -= 1;
    }
    if k == body_start || !matches!(stream.ops.get(k - 1), Some(CanonicalOp::PopExcept)) {
        return false;
    }
    k -= 1;
    while k > body_start
        && matches!(
            stream.ops.get(k - 1),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        k -= 1;
    }
    k > body_start && matches!(stream.ops.get(k - 1), Some(CanonicalOp::Swap(2)))
}

fn handler_return_idiom_body_end(stream: &DecodedStream, next_handler: usize) -> usize {
    (next_handler + 1).min(stream.ops.len())
}

fn bare_handler_return_idiom_end(
    stream: &DecodedStream,
    bare_start: usize,
    region_end: usize,
) -> Option<usize> {
    let hi: usize = region_end.min(stream.ops.len());
    let pop_except: usize =
        (bare_start..hi).find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::PopExcept))?;
    if pop_except <= bare_start
        || !matches!(stream.ops.get(pop_except - 1), Some(CanonicalOp::Swap(2)))
    {
        return None;
    }
    let mut ret: usize = pop_except + 1;
    while matches!(
        stream.ops.get(ret),
        Some(CanonicalOp::Cache | CanonicalOp::Nop)
    ) {
        ret += 1;
    }
    matches!(stream.ops.get(ret), Some(CanonicalOp::Return)).then_some(ret + 1)
}

fn parse_except_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    if !matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::PushExcInfo)
    ) && matches!(
        stream.ops.get(handler_start),
        Some(CanonicalOp::Dup | CanonicalOp::Pop)
    ) {
        return parse_pre311_except_handlers(code, stream, handler_start, region_end);
    }
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    if matches!(stream.ops.get(i), Some(CanonicalOp::PushExcInfo)) {
        i += 1;
    }
    while i < region_end {
        while i < region_end && matches!(stream.ops[i], CanonicalOp::Nop | CanonicalOp::Cache) {
            i += 1;
        }
        if i >= region_end {
            break;
        }
        let clause_start: usize = i;
        let mut check_at: Option<usize> = None;
        for k in clause_start..region_end {
            if matches!(
                stream.ops[k],
                CanonicalOp::CheckExcMatch | CanonicalOp::CheckEgMatch
            ) {
                check_at = Some(k);
                break;
            }
            if matches!(stream.ops[k], CanonicalOp::Reraise(_)) {
                break;
            }
        }
        let Some(check_idx): Option<usize> = check_at else {
            let bare_start: usize =
                if matches!(stream.ops.get(clause_start), Some(CanonicalOp::Pop)) {
                    clause_start + 1
                } else {
                    clause_start
                };
            let bare_is_function_scope: bool =
                (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) == PY_CO_FLAG_FUNCTION_SCOPE;
            let bare_end: usize = bare_is_function_scope
                .then(|| bare_handler_return_idiom_end(stream, bare_start, region_end))
                .flatten()
                .unwrap_or_else(|| bare_except_body_end(stream, bare_start, region_end));
            let bare_body: Vec<Stmt> = structure_stmts(code, stream, bare_start, bare_end)?;
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: non_empty(bare_body),
                line: None,
            });
            break;
        };
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[clause_start..check_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let dispatch_idx: usize = check_idx + 1;
        let next_handler: usize = if matches!(
            stream.ops.get(dispatch_idx),
            Some(CanonicalOp::PopJumpIfFalse(_) | CanonicalOp::PopJumpIfTrue(_))
        ) {
            resolve_jump_target(stream, dispatch_idx, &stream.ops[dispatch_idx])
                .filter(|t: &usize| *t > dispatch_idx && *t <= region_end)
                .unwrap_or(region_end)
        } else {
            region_end
        };
        let mut body_start: usize =
            first_significant(stream, dispatch_idx + 1, next_handler).unwrap_or(dispatch_idx + 1);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
            }
            _ => {}
        }
        let is_function_scope: bool =
            (code.flags & PY_CO_FLAG_FUNCTION_SCOPE) == PY_CO_FLAG_FUNCTION_SCOPE;
        let is_return_idiom: bool = is_function_scope
            && handler_tail_returns_through_pop_except(stream, body_start, next_handler);
        let raw_body_end: usize = if is_return_idiom {
            handler_return_idiom_body_end(stream, next_handler)
        } else if name.is_some() {
            handler_body_end_at_pop_except(stream, body_start, next_handler)
        } else {
            handler_body_end(stream, body_start, next_handler)
        };
        let body_end: usize = if is_return_idiom {
            raw_body_end
        } else {
            extend_over_nested_cold_handler(stream, body_start, raw_body_end, region_end)
        };
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        let handler_body: Vec<Stmt> =
            append_handler_loop_jump(stream, handler_body, body_start, body_end);
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_handler;
        if matches!(stream.ops.get(i), Some(CanonicalOp::Reraise(_))) {
            break;
        }
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

fn parse_pre311_except_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    while i < region_end {
        while i < region_end
            && matches!(
                stream.ops[i],
                CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)
            )
        {
            i += 1;
        }
        if i >= region_end {
            break;
        }
        let clause_start: usize = i;
        if is_pre311_reraise_epilogue(stream, clause_start, region_end) {
            break;
        }
        let is_bare: bool = matches!(stream.ops[clause_start], CanonicalOp::Pop);
        if is_bare {
            let body_start: usize = pre311_skip_three_pops(stream, clause_start, region_end);
            let body_end: usize = pre311_handler_body_end(stream, body_start, region_end);
            let next: usize = pre311_advance_after_handler(stream, body_end, region_end);
            let body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
            handlers.push(ExceptHandler {
                typ: None,
                name: None,
                body: non_empty(body),
                line: None,
            });
            i = next;
            continue;
        }
        if !matches!(stream.ops[clause_start], CanonicalOp::Dup) {
            break;
        }
        let mut j: usize = clause_start + 1;
        let type_start: usize = j;
        let mut type_end: Option<usize> = None;
        let mut next_handler: usize = region_end;
        while j < region_end {
            match &stream.ops[j] {
                CanonicalOp::Compare(crate::bytecode::opcode::CmpOp::ExcMatch) => {
                    type_end = Some(j);
                    let dispatch: usize = j + 1;
                    next_handler = resolve_jump_target(stream, dispatch, &stream.ops[dispatch])
                        .filter(|t: &usize| *t > dispatch && *t <= region_end)
                        .unwrap_or(region_end);
                    j = dispatch + 1;
                    break;
                }
                CanonicalOp::Other(121, _) => {
                    type_end = Some(j);
                    next_handler = resolve_jump_target(stream, j, &stream.ops[j])
                        .filter(|t: &usize| *t > j && *t <= region_end)
                        .unwrap_or(region_end);
                    j += 1;
                    break;
                }
                _ => j += 1,
            }
        }
        let Some(type_end_idx): Option<usize> = type_end else {
            break;
        };
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[type_start..type_end_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let after_dispatch: usize = j;
        let mut body_start: usize = pre311_skip_first_pop(stream, after_dispatch, next_handler);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Nop)) {
                    body_start += 1;
                }
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Nop)) {
                    body_start += 1;
                }
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
                if matches!(stream.ops.get(body_start), Some(CanonicalOp::Pop)) {
                    body_start += 1;
                }
            }
            _ => {}
        }
        let body_end: usize = pre311_handler_body_end(stream, body_start, next_handler);
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_handler;
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

fn is_pre311_reraise_epilogue(stream: &DecodedStream, clause_start: usize, hi: usize) -> bool {
    if !matches!(stream.ops.get(clause_start), Some(CanonicalOp::Pop)) {
        return false;
    }
    let mut k: usize = clause_start + 1;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::ExtendedArg(_))
        )
    {
        k += 1;
    }
    stream.pre311_end_finally_idx.contains(&k)
}

fn pre311_skip_three_pops(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    let mut pops: u32 = 0;
    while k < hi && pops < 3 {
        match stream.ops.get(k) {
            Some(CanonicalOp::Pop) => {
                pops += 1;
                k += 1;
            }
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_)) => k += 1,
            _ => break,
        }
    }
    k
}

fn pre311_skip_first_pop(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::Nop | CanonicalOp::ExtendedArg(_))
        )
    {
        k += 1;
    }
    if matches!(stream.ops.get(k), Some(CanonicalOp::Pop)) {
        k += 1;
    }
    k
}

fn pre311_handler_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PopExcept
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::Reraise(_)
            )
        )
    {
        end -= 1;
    }
    end
}

fn pre311_advance_after_handler(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PopExcept
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
                    | CanonicalOp::ExtendedArg(_)
                    | CanonicalOp::Reraise(_)
            )
        )
    {
        k += 1;
    }
    k
}

fn parse_except_star_handlers(
    code: &CodeObject,
    stream: &DecodedStream,
    handler_start: usize,
    region_end: usize,
) -> Result<Vec<ExceptHandler>> {
    let mut handlers: Vec<ExceptHandler> = Vec::new();
    let mut i: usize = handler_start;
    while i < region_end {
        let check_at: Option<usize> = (i..region_end)
            .take_while(|&k: &usize| !matches!(stream.ops[k], CanonicalOp::Reraise(_)))
            .find(|&k: &usize| matches!(stream.ops[k], CanonicalOp::CheckEgMatch));
        let Some(check_idx): Option<usize> = check_at else {
            break;
        };
        let type_start: usize = eg_clause_type_start(stream, check_idx, i);
        let (_, residual): (Vec<Stmt>, Vec<Expr>) =
            build_linear_stmts_sim(code, &stream.ops[type_start..check_idx])?;
        let exc_type: Option<Expr> = residual.into_iter().next_back();
        let dispatch_idx: usize =
            first_significant(stream, check_idx + 1, region_end).unwrap_or(check_idx + 1);
        let dispatch_idx: usize =
            if matches!(stream.ops.get(dispatch_idx), Some(CanonicalOp::Copy(1))) {
                first_significant(stream, dispatch_idx + 1, region_end).unwrap_or(dispatch_idx + 1)
            } else {
                dispatch_idx
            };
        let next_clause: usize =
            resolve_jump_target(stream, dispatch_idx, &stream.ops[dispatch_idx])
                .filter(|t: &usize| *t > dispatch_idx && *t <= region_end)
                .unwrap_or(region_end);
        let mut body_start: usize =
            first_significant(stream, dispatch_idx + 1, next_clause).unwrap_or(dispatch_idx + 1);
        let mut name: Option<String> = None;
        match stream.ops.get(body_start) {
            Some(CanonicalOp::StoreFast(slot)) => {
                name = local_name_at(code, *slot, body_start).ok();
                body_start += 1;
            }
            Some(CanonicalOp::StoreName(slot)) => {
                name = name_at(&code.names, *slot, body_start, "name").ok();
                body_start += 1;
            }
            Some(CanonicalOp::Pop) => {
                body_start += 1;
            }
            _ => {}
        }
        let body_end: usize = eg_body_end(stream, body_start, next_clause);
        let mut handler_body: Vec<Stmt> = structure_stmts(code, stream, body_start, body_end)?;
        if let Some(bound) = name.as_deref() {
            strip_named_exc_cleanup(&mut handler_body, bound);
        }
        handlers.push(ExceptHandler {
            typ: exc_type,
            name,
            body: non_empty(handler_body),
            line: None,
        });
        i = next_clause;
    }
    if handlers.is_empty() {
        handlers.push(ExceptHandler {
            typ: None,
            name: None,
            body: vec![Stmt::Pass],
            line: None,
        });
    }
    Ok(handlers)
}

fn eg_clause_type_start(stream: &DecodedStream, check_idx: usize, lo: usize) -> usize {
    let mut i: usize = check_idx;
    while i > lo
        && !matches!(
            stream.ops.get(i - 1),
            Some(
                CanonicalOp::Pop
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::PushExcInfo
                    | CanonicalOp::Copy(_)
                    | CanonicalOp::ListAppend
            )
        )
    {
        i -= 1;
    }
    i
}

fn eg_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    (lo..hi)
        .find(|&k: &usize| {
            matches!(
                stream.ops[k],
                CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::ListAppend
                    | CanonicalOp::PopExcept
            )
        })
        .unwrap_or(hi)
}

fn strip_named_exc_cleanup(body: &mut Vec<Stmt>, bound: &str) {
    body.retain(|s: &Stmt| !is_bound_clear_stmt(s, bound));
    strip_trailing_bound_clear(body, bound);
}

fn strip_trailing_bound_clear(body: &mut Vec<Stmt>, bound: &str) {
    if pop_trailing_bound_clear_pair(body, bound) {
        return;
    }
    match body.last_mut() {
        Some(
            Stmt::If {
                body: b, orelse, ..
            }
            | Stmt::For {
                body: b, orelse, ..
            }
            | Stmt::While {
                body: b, orelse, ..
            },
        ) => {
            strip_trailing_bound_clear(b, bound);
            strip_trailing_bound_clear(orelse, bound);
        }
        Some(Stmt::With { body: b, .. }) => strip_trailing_bound_clear(b, bound),
        Some(
            Stmt::Try {
                body: b,
                handlers,
                orelse,
                finalbody,
                ..
            }
            | Stmt::TryStar {
                body: b,
                handlers,
                orelse,
                finalbody,
                ..
            },
        ) => {
            strip_trailing_bound_clear(b, bound);
            strip_trailing_bound_clear(orelse, bound);
            strip_trailing_bound_clear(finalbody, bound);
            for handler in handlers.iter_mut() {
                strip_trailing_bound_clear(&mut handler.body, bound);
            }
        }
        _ => {}
    }
}

fn pop_trailing_bound_clear_pair(body: &mut Vec<Stmt>, bound: &str) -> bool {
    let n: usize = body.len();
    let del_at: Option<usize> = if n >= 1 && is_bound_del_stmt(&body[n - 1], bound) {
        Some(n - 1)
    } else if n >= 2
        && is_bound_del_stmt(&body[n - 2], bound)
        && is_implicit_none_return(&body[n - 1])
    {
        Some(n - 2)
    } else {
        None
    };
    let Some(del_idx): Option<usize> = del_at else {
        return false;
    };
    if del_idx == 0 || !is_bound_assign_none_stmt(&body[del_idx - 1], bound) {
        return false;
    }
    body.remove(del_idx);
    body.remove(del_idx - 1);
    true
}

fn is_bound_assign_none_stmt(stmt: &Stmt, bound: &str) -> bool {
    matches!(
        stmt,
        Stmt::Assign { targets, value, .. }
            if targets.len() == 1
                && matches!(&targets[0], Expr::Name { id, .. } if id == bound)
                && matches!(value, Expr::Constant { value: ConstValue::None, .. })
    )
}

fn is_bound_del_stmt(stmt: &Stmt, bound: &str) -> bool {
    matches!(
        stmt,
        Stmt::Delete(targets)
            if targets.iter().all(|e: &Expr| matches!(e, Expr::Name { id, .. } if id == bound))
    )
}

fn is_bound_clear_stmt(stmt: &Stmt, bound: &str) -> bool {
    match stmt {
        Stmt::Assign { targets, value, .. } => {
            targets.len() == 1
                && matches!(&targets[0], Expr::Name { id, .. } if id == bound)
                && matches!(
                    value,
                    Expr::Constant {
                        value: ConstValue::None,
                        ..
                    }
                )
        }
        Stmt::Delete(targets) => targets
            .iter()
            .all(|e: &Expr| matches!(e, Expr::Name { id, .. } if id == bound)),
        _ => false,
    }
}

fn extend_over_nested_cold_handler(
    stream: &DecodedStream,
    body_start: usize,
    body_end: usize,
    limit: usize,
) -> usize {
    if stream.is_pre_311() || stream.exception_table.is_empty() {
        return body_end;
    }
    let Some(start_off): Option<u32> = stream.offsets.get(body_start).copied() else {
        return body_end;
    };
    let mut end: usize = body_end;
    while let Some(end_off) = stream.offsets.get(end).copied() {
        let mut grew: bool = false;
        for entry in &stream.exception_table {
            if entry.start < start_off || entry.start >= end_off {
                continue;
            }
            let Some(handler_idx): Option<usize> = stream.index_for_offset(entry.target) else {
                continue;
            };
            if handler_idx < end
                || handler_idx >= limit
                || !matches!(stream.ops.get(handler_idx), Some(CanonicalOp::PushExcInfo))
            {
                continue;
            }
            let nested_end: usize = handler_join(stream, handler_idx, limit);
            if nested_end > end {
                end = nested_end;
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    end.min(limit)
}

fn handler_body_end_at_pop_except(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut depth: u32 = 0;
    let mut pop_at: Option<usize> = None;
    for k in lo..hi {
        match stream.ops[k] {
            CanonicalOp::PushExcInfo => depth += 1,
            CanonicalOp::PopExcept if depth == 0 => {
                pop_at = Some(k);
                break;
            }
            CanonicalOp::PopExcept => depth -= 1,
            _ => {}
        }
    }
    let Some(pop): Option<usize> = pop_at else {
        return handler_body_end(stream, lo, hi);
    };
    let after_cleanup: usize = skip_handler_name_cleanup(stream, pop + 1, hi);
    let trailing: usize = handler_trailing_terminator_end(stream, after_cleanup, hi);
    if trailing > pop { trailing } else { pop }
}

fn skip_handler_name_cleanup(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut i: usize = lo;
    while i < hi
        && matches!(
            stream.ops.get(i),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        i += 1;
    }
    let load_const: Option<&CanonicalOp> = stream.ops.get(i);
    let store: Option<&CanonicalOp> = stream.ops.get(i + 1);
    let delete: Option<&CanonicalOp> = stream.ops.get(i + 2);
    let cleared: bool = matches!(load_const, Some(CanonicalOp::LoadConst(_)))
        && matches!(
            store,
            Some(CanonicalOp::StoreFast(_) | CanonicalOp::StoreName(_))
        )
        && matches!(
            delete,
            Some(CanonicalOp::DeleteFast(_) | CanonicalOp::DeleteName(_))
        );
    if cleared { i + 3 } else { lo }
}

fn handler_trailing_terminator_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut k: usize = lo;
    while k < hi
        && matches!(
            stream.ops.get(k),
            Some(CanonicalOp::Cache | CanonicalOp::Nop)
        )
    {
        k += 1;
    }
    let mut last_significant: usize = k;
    while k < hi {
        match stream.ops[k] {
            CanonicalOp::JumpForward(_)
            | CanonicalOp::JumpAbsolute(_)
            | CanonicalOp::Reraise(_) => return last_significant,
            CanonicalOp::Return | CanonicalOp::ReturnConst(_) | CanonicalOp::Raise(_) => {
                last_significant = k + 1;
                k += 1;
                while k < hi
                    && matches!(
                        stream.ops.get(k),
                        Some(CanonicalOp::Cache | CanonicalOp::Nop)
                    )
                {
                    k += 1;
                }
                return last_significant;
            }
            CanonicalOp::Cache | CanonicalOp::Nop => {}
            _ => {
                last_significant = k + 1;
            }
        }
        k += 1;
    }
    last_significant
}

fn handler_body_end(stream: &DecodedStream, lo: usize, hi: usize) -> usize {
    let mut end: usize = hi;
    while end > lo
        && matches!(
            stream.ops.get(end - 1),
            Some(
                CanonicalOp::PopExcept
                    | CanonicalOp::JumpForward(_)
                    | CanonicalOp::JumpAbsolute(_)
                    | CanonicalOp::Reraise(_)
                    | CanonicalOp::Nop
                    | CanonicalOp::Cache
            )
        )
    {
        end -= 1;
    }
    end
}
