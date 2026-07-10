use crate::ast::node::{ExceptHandler, Stmt};

use super::ast_facts::{self, AstFacts};
use super::input_facts::InputFacts;

const MAX_HOIST_CANDIDATES: usize = 64;

#[must_use]
pub(crate) fn has_repair_candidate(body: &[Stmt]) -> bool {
    body.iter()
        .enumerate()
        .any(|(idx, stmt): (usize, &Stmt)| else_tail_site(stmt) || loop_tail_site(body, idx))
        || body.iter().any(nested_scan_worth_it)
}

#[must_use]
fn nested_scan_worth_it(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::If { body, orelse, .. }
        | Stmt::For { body, orelse, .. }
        | Stmt::While { body, orelse, .. } => {
            has_repair_candidate(body) || has_repair_candidate(orelse)
        }
        Stmt::With { body, .. } => has_repair_candidate(body),
        Stmt::Try {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        }
        | Stmt::TryStar {
            body,
            handlers,
            orelse,
            finalbody,
            ..
        } => {
            has_repair_candidate(body)
                || has_repair_candidate(orelse)
                || has_repair_candidate(finalbody)
                || handlers
                    .iter()
                    .any(|h: &ExceptHandler| has_repair_candidate(&h.body))
        }
        _ => false,
    }
}

#[must_use]
fn else_tail_site(stmt: &Stmt) -> bool {
    let (Stmt::Try { orelse, .. } | Stmt::TryStar { orelse, .. }) = stmt else {
        return false;
    };
    !orelse.is_empty() && orelse.iter().any(contains_try)
}

#[must_use]
fn loop_tail_site(body: &[Stmt], idx: usize) -> bool {
    let Some(Stmt::For { body: lbody, .. } | Stmt::While { body: lbody, .. }) = body.get(idx)
    else {
        return false;
    };
    let followed_by_return: bool = matches!(body.get(idx + 1), Some(Stmt::Return(_)));
    followed_by_return && loop_last_try_returns(lbody)
}

#[must_use]
fn loop_last_try_returns(lbody: &[Stmt]) -> bool {
    matches!(
        lbody.last(),
        Some(Stmt::Try { orelse, handlers, finalbody, .. })
            if finalbody.is_empty()
                && !orelse.is_empty()
                && is_terminator(orelse.last())
                && handlers.iter().all(|h: &ExceptHandler| !is_terminator(h.body.last()))
    )
}

#[must_use]
fn contains_try(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Try { .. } | Stmt::TryStar { .. } => true,
        Stmt::If { body, orelse, .. }
        | Stmt::For { body, orelse, .. }
        | Stmt::While { body, orelse, .. } => {
            body.iter().any(contains_try) || orelse.iter().any(contains_try)
        }
        Stmt::With { body, .. } => body.iter().any(contains_try),
        _ => false,
    }
}

#[must_use]
fn is_terminator(stmt: Option<&Stmt>) -> bool {
    matches!(
        stmt,
        Some(Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Continue | Stmt::Break)
    )
}

pub(crate) fn repair_body(body: Vec<Stmt>, input: &InputFacts) -> Vec<Stmt> {
    let mut current: Vec<Stmt> = body;
    if let Some(order) = input.handler_order.as_deref()
        && let Some(next) = repair_else_tail(&current, order)
    {
        current = next;
    }
    if !input.loop_inner_return
        && let Some(next) = repair_loop_tail(&current)
    {
        current = next;
    }
    current
}

#[must_use]
fn repair_else_tail(body: &[Stmt], input_order: &[usize]) -> Option<Vec<Stmt>> {
    let primary: AstFacts = ast_facts::extract(body);
    if primary.has_with || primary.has_finally {
        return None;
    }
    if primary.try_count != input_order.len() {
        return None;
    }
    if primary.handler_order == input_order {
        return None;
    }
    for (t, stmt) in body.iter().enumerate() {
        let (Stmt::Try { orelse, .. } | Stmt::TryStar { orelse, .. }) = stmt else {
            continue;
        };
        if orelse.is_empty() || !orelse.iter().any(contains_try) {
            continue;
        }
        let orelse_len: usize = orelse.len();
        for split in (0..orelse_len).rev().take(MAX_HOIST_CANDIDATES) {
            if !orelse[split..].iter().any(contains_try) {
                continue;
            }
            let Some(candidate): Option<Vec<Stmt>> = build_hoist_candidate(body, t, split) else {
                continue;
            };
            let facts: AstFacts = ast_facts::extract(&candidate);
            if facts.try_count == input_order.len() && facts.handler_order == input_order {
                return Some(candidate);
            }
        }
    }
    None
}

#[must_use]
fn build_hoist_candidate(body: &[Stmt], try_index: usize, split: usize) -> Option<Vec<Stmt>> {
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len() + 4);
    for (idx, stmt) in body.iter().enumerate() {
        if idx != try_index {
            out.push(stmt.clone());
            continue;
        }
        let mut owned: Stmt = stmt.clone();
        let hoisted: Vec<Stmt> = split_try_orelse(&mut owned, split)?;
        out.push(owned);
        out.extend(hoisted);
    }
    Some(out)
}

#[must_use]
fn split_try_orelse(stmt: &mut Stmt, split: usize) -> Option<Vec<Stmt>> {
    let (Stmt::Try { orelse, .. } | Stmt::TryStar { orelse, .. }) = stmt else {
        return None;
    };
    if split > orelse.len() {
        return None;
    }
    let hoisted: Vec<Stmt> = orelse.split_off(split);
    Some(hoisted)
}

#[must_use]
fn repair_loop_tail(body: &[Stmt]) -> Option<Vec<Stmt>> {
    let primary: AstFacts = ast_facts::extract(body);
    if !primary.loop_inner_return {
        return None;
    }
    for l in 0..body.len() {
        if !matches!(body.get(l + 1), Some(Stmt::Return(_))) {
            continue;
        }
        let Some(next): Option<Vec<Stmt>> = transform_loop_tail(body, l) else {
            continue;
        };
        let facts: AstFacts = ast_facts::extract(&next);
        if !facts.loop_inner_return {
            return Some(next);
        }
    }
    None
}

#[must_use]
fn transform_loop_tail(body: &[Stmt], l: usize) -> Option<Vec<Stmt>> {
    let loop_stmt: &Stmt = body.get(l)?;
    let mut owned: Stmt = loop_stmt.clone();
    let lbody: &mut Vec<Stmt> = match &mut owned {
        Stmt::For { body: b, .. } | Stmt::While { body: b, .. } => b,
        _ => return None,
    };
    let last: Stmt = lbody.pop()?;
    let Stmt::Try {
        body: tbody,
        mut handlers,
        mut orelse,
        finalbody,
        line,
    } = last
    else {
        return None;
    };
    if !finalbody.is_empty() || orelse.is_empty() || !is_terminator(orelse.last()) {
        return None;
    }
    if handlers
        .iter()
        .any(|h: &ExceptHandler| is_terminator(h.body.last()))
    {
        return None;
    }
    let _dropped: Option<Stmt> = orelse.pop();
    let tail: Vec<Stmt> = std::mem::take(&mut orelse);
    for handler in &mut handlers {
        continue_handler(handler);
    }
    let rebuilt: Stmt = Stmt::Try {
        body: tbody,
        handlers,
        orelse: Vec::new(),
        finalbody,
        line,
    };
    lbody.push(rebuilt);
    lbody.extend(tail);
    let mut out: Vec<Stmt> = Vec::with_capacity(body.len());
    out.extend_from_slice(&body[..l]);
    out.push(owned);
    out.extend_from_slice(&body[l + 1..]);
    Some(out)
}

fn continue_handler(handler: &mut ExceptHandler) {
    if matches!(handler.body.last(), Some(Stmt::Pass)) {
        handler.body.pop();
    }
    if !is_terminator(handler.body.last()) {
        handler.body.push(Stmt::Continue);
    }
}
