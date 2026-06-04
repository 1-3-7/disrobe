//! Structured control-flow recovery from a basic-block CFG.
//!
//! Turns a basic-block [`Cfg`] plus per-block lifted statements into nested
//! `while`/`if`-`else`/`switch`/`try` constructs, emitting labeled `goto` only for the residual
//! irreducible edges that cannot be expressed structurally.
//!
//! Clean-room reimplementation of the dominance / natural-loop structuring approach used by `ILSpy`
//! (MIT): natural loops drive `while` bodies, conditional terminators drive `if`/`else` with the
//! join recovered from immediate post-dominance, and the dominator tree bounds each region so a
//! block is inlined into a region only when that region dominates it (single-entry). No `ILSpy`
//! source is copied; the structuring traversal is reimplemented from understanding of the algorithm.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::cfg::{BlockId, Cfg, NaturalLoop, Terminator};
use crate::cil::{ExceptionClause, ExceptionClauseKind, MethodBody};
use crate::structurize::{BlockCode, LinearStmt, TargetLang, TokenNamer, lift_block};

/// A node in the recovered structured-control-flow tree.
#[derive(Debug, Clone)]
pub(crate) enum Structured {
    /// A run of structured nodes emitted in order.
    Seq(Vec<Self>),
    /// The linear statements of one basic block.
    Block(Vec<LinearStmt>),
    /// `while (cond) { body }`; `cond == None` renders `while (true)`.
    While {
        cond: Option<String>,
        body: Box<Self>,
    },
    /// `if (cond) { then } [else { els }]`.
    If {
        cond: String,
        then: Box<Self>,
        els: Option<Box<Self>>,
    },
    /// `switch (sel) { case i: ... }`.
    Switch {
        selector: String,
        cases: Vec<(Vec<usize>, Self)>,
        default: Option<Box<Self>>,
    },
    /// `try { body } <handlers>`.
    Try {
        body: Box<Self>,
        handlers: Vec<Handler>,
    },
    Return(Option<String>),
    Throw(Option<String>),
    Break,
    Continue,
    /// `goto IL_xxxx;` - residual unstructured edge.
    Goto(u32),
    /// `IL_xxxx:` - jump label kept for a residual goto target.
    Label(u32),
    /// Renders nothing (used to prune empty branches).
    Empty,
}

/// One recovered exception handler region.
#[derive(Debug, Clone)]
pub(crate) struct Handler {
    pub kind: ExceptionClauseKind,
    pub catch_type: Option<String>,
    pub body: Box<Structured>,
}

/// Loop context threaded through structuring so `break`/`continue` resolve to the innermost loop.
#[derive(Debug, Clone, Copy)]
struct LoopFrame {
    header: BlockId,
    exit: Option<BlockId>,
    /// In-loop "continue block" (e.g. a `for` increment) whose sole successor is the header; a jump
    /// to it is a `continue` that first runs its statements. `None` when the header is the only
    /// continue point.
    continue_block: Option<BlockId>,
}

struct Structurer<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    namer: &'a N,
    lang: TargetLang,
    ipdom: Vec<BlockId>,
    block_code: Vec<BlockCode>,
    loop_header: Vec<bool>,
    visited: Vec<bool>,
    loop_stack: Vec<LoopFrame>,
    goto_targets: BTreeSet<u32>,
    locals_used: BTreeSet<u32>,
    try_starts: BTreeMap<u32, Vec<&'a ExceptionClause>>,
}

impl<'a, N: TokenNamer> Structurer<'a, N> {
    fn new(cfg: &'a Cfg, body: &'a MethodBody, namer: &'a N, lang: TargetLang) -> Self {
        let count: usize = cfg.blocks.len();
        let ipdom: Vec<BlockId> = cfg.immediate_post_dominators();
        let block_code: Vec<BlockCode> = (0..count)
            .map(|b: usize| {
                lift_block(
                    namer,
                    lang,
                    &body.instructions,
                    cfg.blocks[b].first,
                    cfg.blocks[b].last,
                )
            })
            .collect();
        let mut loop_header: Vec<bool> = vec![false; count];
        for lp in &cfg.loops {
            loop_header[lp.header] = true;
        }
        let mut try_starts: BTreeMap<u32, Vec<&ExceptionClause>> = BTreeMap::new();
        for c in &body.exception_clauses {
            try_starts.entry(c.try_offset).or_default().push(c);
        }
        let mut locals_used: BTreeSet<u32> = BTreeSet::new();
        for bc in &block_code {
            locals_used.extend(bc.locals_used.iter().copied());
        }
        Self {
            cfg,
            namer,
            lang,
            ipdom,
            block_code,
            loop_header,
            visited: vec![false; count],
            loop_stack: Vec::new(),
            goto_targets: BTreeSet::new(),
            locals_used,
            try_starts,
        }
    }

    /// Emit the region beginning at `start` and ending before `stop` (exclusive follow). A `stop` of
    /// `None` means "run to the end of the method".
    fn emit_region(&mut self, start: BlockId, stop: Option<BlockId>) -> Structured {
        let mut seq: Vec<Structured> = Vec::new();
        let mut cur: Option<BlockId> = Some(start);
        while let Some(bid) = cur {
            if Some(bid) == stop || !self.cfg.is_reachable(bid) {
                break;
            }
            if self.visited[bid] {
                seq.push(self.goto(bid));
                break;
            }
            cur = self.emit_block_into(bid, stop, &mut seq);
        }
        finish_seq(seq)
    }

    /// Emit a single block (and any structure it heads) into `seq`, returning the next block to
    /// continue the region with, or `None` to stop.
    fn emit_block_into(
        &mut self,
        bid: BlockId,
        stop: Option<BlockId>,
        seq: &mut Vec<Structured>,
    ) -> Option<BlockId> {
        if self.loop_header[bid]
            && !self.in_current_loop(bid)
            && let Some(lp_idx) = self
                .cfg
                .loops
                .iter()
                .position(|l: &NaturalLoop| l.header == bid)
        {
            return self.emit_loop(lp_idx, seq);
        }

        if self.try_starts.contains_key(&self.cfg.blocks[bid].start) {
            let follow: Option<BlockId> = self.emit_try(bid, seq);
            return follow.filter(|&b: &BlockId| self.cfg.is_reachable(b) && !self.visited[b]);
        }

        self.visited[bid] = true;
        self.maybe_label(bid, seq);
        push_block_stmts(seq, &self.block_code[bid].stmts);

        let term: Terminator = self.cfg.terminators[bid].clone();
        match term {
            Terminator::Return => {
                seq.push(self.return_stmt(bid));
                None
            }
            Terminator::Throw => {
                seq.push(self.throw_stmt(bid));
                None
            }
            Terminator::EndFinally => None,
            Terminator::FallThrough(next) | Terminator::Goto(next) => self.flow_to(next, stop, seq),
            Terminator::Cond { taken, fallthrough } => {
                self.emit_if(bid, taken, fallthrough, stop, seq)
            }
            Terminator::Switch { cases, fallthrough } => {
                self.emit_switch(bid, &cases, fallthrough, stop, seq)
            }
        }
    }

    /// Resolve where control should go after a block whose only exit is `next`: continue the region
    /// inline if `next` is still owned by it, else emit `break`/`continue`/`goto`.
    fn flow_to(
        &mut self,
        next: BlockId,
        stop: Option<BlockId>,
        seq: &mut Vec<Structured>,
    ) -> Option<BlockId> {
        if let Some(frame) = self.loop_stack.last().copied() {
            if next == frame.header {
                seq.push(Structured::Continue);
                return None;
            }
            if Some(next) == frame.continue_block {
                self.push_continue_via(next, seq);
                return None;
            }
            if Some(next) == frame.exit {
                seq.push(Structured::Break);
                return None;
            }
        }
        if Some(next) == stop {
            return None;
        }
        if self.visited[next] {
            seq.push(self.goto(next));
            return None;
        }
        Some(next)
    }

    /// Emit a `continue` that targets the loop's continue block: run the continue block's statements
    /// (the increment) then loop back. Safe to duplicate because continue blocks are side-effect
    /// local (`i++`, re-test setup).
    fn push_continue_via(&self, cont: BlockId, seq: &mut Vec<Structured>) {
        push_block_stmts(seq, &self.block_code[cont].stmts);
        seq.push(Structured::Continue);
    }

    fn emit_loop(&mut self, lp_idx: usize, seq: &mut Vec<Structured>) -> Option<BlockId> {
        let header: BlockId = self.cfg.loops[lp_idx].header;
        let exit: Option<BlockId> = self.loop_exit(lp_idx);
        self.visited[header] = true;
        self.maybe_label(header, seq);

        let header_term: Terminator = self.cfg.terminators[header].clone();
        let header_stmts_empty: bool = self.block_code[header].stmts.is_empty();
        let continue_block: Option<BlockId> = self.loop_continue_block(lp_idx);
        self.loop_stack.push(LoopFrame {
            header,
            exit,
            continue_block,
        });

        let while_node: Structured = match (&header_term, header_stmts_empty) {
            (Terminator::Cond { taken, fallthrough }, true)
                if self.is_loop_guard(lp_idx, *taken, *fallthrough, exit) =>
            {
                let (cond, body_start): (String, BlockId) =
                    self.loop_guard_cond(header, *taken, *fallthrough, exit);
                let body: Structured = self.emit_region(body_start, Some(header));
                Structured::While {
                    cond: Some(cond),
                    body: Box::new(body),
                }
            }
            _ => {
                let mut body_seq: Vec<Structured> = Vec::new();
                push_block_stmts(&mut body_seq, &self.block_code[header].stmts);
                self.emit_loop_header_tail(header, &header_term, &mut body_seq);
                Structured::While {
                    cond: None,
                    body: Box::new(finish_seq(body_seq)),
                }
            }
        };
        self.loop_stack.pop();
        seq.push(while_node);
        exit.filter(|&e: &BlockId| self.cfg.is_reachable(e) && !self.visited[e])
    }

    /// Emit the body following an infinite-loop header's terminator (the header's own control flow,
    /// re-entered each iteration).
    fn emit_loop_header_tail(
        &mut self,
        header: BlockId,
        term: &Terminator,
        body_seq: &mut Vec<Structured>,
    ) {
        match term {
            Terminator::Cond { taken, fallthrough } => {
                let _: Option<BlockId> =
                    self.emit_if(header, *taken, *fallthrough, Some(header), body_seq);
            }
            Terminator::Switch { cases, fallthrough } => {
                let cases_v: Vec<BlockId> = cases.clone();
                let _: Option<BlockId> =
                    self.emit_switch(header, &cases_v, *fallthrough, Some(header), body_seq);
            }
            Terminator::FallThrough(next) | Terminator::Goto(next) => {
                let _: Option<BlockId> = self.flow_to(*next, Some(header), body_seq);
            }
            Terminator::Return => body_seq.push(self.return_stmt(header)),
            Terminator::Throw => body_seq.push(self.throw_stmt(header)),
            Terminator::EndFinally => {}
        }
    }

    /// Whether `bid` is a "pure condition" block: no side-effecting statements, exactly two
    /// predecessors-agnostic conditional edges, and reachable from exactly one place (so inlining it
    /// into a compound condition is sound). Such blocks are the building blocks of `&&`/`||`.
    fn is_pure_cond_block(&self, bid: BlockId) -> bool {
        self.block_code[bid].stmts.is_empty()
            && self.block_code[bid].condition.is_some()
            && matches!(self.cfg.terminators[bid], Terminator::Cond { .. })
            && self.cfg.blocks[bid].preds.len() == 1
            && !self.loop_header[bid]
            && !self.visited[bid]
    }

    /// Greedily fold short-circuit `&&`/`||` chains rooted at a conditional block, following pure
    /// condition blocks that share an outgoing target with the root. Returns the combined condition
    /// text plus the effective taken/fallthrough block ids after folding, and marks every folded
    /// intermediate block visited so it is not re-emitted.
    ///
    /// Clean-room port of the short-circuit recovery in `ILSpy`'s `ConditionDetection` (MIT),
    /// reimplemented from understanding of the `&&`/`||` join structure.
    fn fold_condition(
        &mut self,
        bid: BlockId,
        taken: BlockId,
        fallthrough: BlockId,
    ) -> (String, BlockId, BlockId) {
        let mut cond: String = self.block_code[bid]
            .condition
            .clone()
            .unwrap_or_else(|| "true".to_owned());
        let mut cur_taken: BlockId = taken;
        let mut cur_ft: BlockId = fallthrough;
        loop {
            if self.is_pure_cond_block(cur_ft)
                && let Terminator::Cond {
                    taken: pt,
                    fallthrough: pf,
                } = self.cfg.terminators[cur_ft].clone()
            {
                let pcond: String = self.block_code[cur_ft]
                    .condition
                    .clone()
                    .unwrap_or_else(|| "true".to_owned());
                if pt == cur_taken {
                    self.visited[cur_ft] = true;
                    cond = join_or(&cond, &pcond, self.lang);
                    cur_ft = pf;
                    continue;
                }
                if pf == cur_taken {
                    self.visited[cur_ft] = true;
                    cond = join_or(&cond, &negate(&pcond, self.lang), self.lang);
                    cur_ft = pt;
                    continue;
                }
            }
            if self.is_pure_cond_block(cur_taken)
                && let Terminator::Cond {
                    taken: pt,
                    fallthrough: pf,
                } = self.cfg.terminators[cur_taken].clone()
            {
                let pcond: String = self.block_code[cur_taken]
                    .condition
                    .clone()
                    .unwrap_or_else(|| "true".to_owned());
                if pf == cur_ft {
                    self.visited[cur_taken] = true;
                    cond = join_and(&cond, &pcond, self.lang);
                    cur_taken = pt;
                    continue;
                }
                if pt == cur_ft {
                    self.visited[cur_taken] = true;
                    cond = join_and(&cond, &negate(&pcond, self.lang), self.lang);
                    cur_taken = pf;
                    continue;
                }
            }
            break;
        }
        (cond, cur_taken, cur_ft)
    }

    fn emit_if(
        &mut self,
        bid: BlockId,
        taken: BlockId,
        fallthrough: BlockId,
        stop: Option<BlockId>,
        seq: &mut Vec<Structured>,
    ) -> Option<BlockId> {
        let (cond, taken, fallthrough): (String, BlockId, BlockId) =
            self.fold_condition(bid, taken, fallthrough);
        let join: Option<BlockId> = self.if_join(bid, taken, fallthrough);
        let then_stop: Option<BlockId> = join.or(stop);

        let then_branch: Structured = self.branch_region(taken, then_stop, stop);
        let else_branch: Structured = self.branch_region(fallthrough, then_stop, stop);

        let (cond, then_branch, else_branch): (String, Structured, Structured) =
            if is_empty(&then_branch) && !is_empty(&else_branch) {
                (negate(&cond, self.lang), else_branch, then_branch)
            } else {
                (cond, then_branch, else_branch)
            };

        let els: Option<Box<Structured>> = if is_empty(&else_branch) {
            None
        } else {
            Some(Box::new(else_branch))
        };
        seq.push(Structured::If {
            cond,
            then: Box::new(then_branch),
            els,
        });
        match join {
            Some(j) if Some(j) != stop && self.cfg.is_reachable(j) && !self.visited[j] => Some(j),
            Some(j) if !self.visited[j] => self.flow_to(j, stop, seq),
            _ => None,
        }
    }

    /// Emit one branch of an `if`: if the branch target is the join itself, the branch is empty; if
    /// it escapes the region (break/continue/goto), emit that; otherwise recurse up to the join.
    fn branch_region(
        &mut self,
        target: BlockId,
        join: Option<BlockId>,
        outer_stop: Option<BlockId>,
    ) -> Structured {
        if Some(target) == join {
            return Structured::Empty;
        }
        if let Some(frame) = self.loop_stack.last().copied() {
            if target == frame.header {
                return Structured::Continue;
            }
            if Some(target) == frame.continue_block {
                let mut s: Vec<Structured> = Vec::new();
                self.push_continue_via(target, &mut s);
                return finish_seq(s);
            }
            if Some(target) == frame.exit {
                return Structured::Break;
            }
        }
        if Some(target) == outer_stop {
            return Structured::Empty;
        }
        if self.visited[target] {
            return self.goto(target);
        }
        self.emit_region(target, join.or(outer_stop))
    }

    fn emit_switch(
        &mut self,
        bid: BlockId,
        cases: &[BlockId],
        fallthrough: BlockId,
        stop: Option<BlockId>,
        seq: &mut Vec<Structured>,
    ) -> Option<BlockId> {
        let selector: String = self.block_code[bid]
            .switch_selector
            .clone()
            .unwrap_or_else(|| "selector".to_owned());
        let join: Option<BlockId> = self.switch_join(bid, cases, fallthrough);
        let mut case_nodes: Vec<(Vec<usize>, Structured)> = Vec::new();
        for (i, &t) in cases.iter().enumerate() {
            if Some(t) == join {
                case_nodes.push((vec![i], Structured::Break));
                continue;
            }
            let region: Structured = self.branch_region(t, join, stop);
            case_nodes.push((vec![i], with_trailing_break(region)));
        }
        let default: Option<Box<Structured>> =
            if Some(fallthrough) == join || Some(fallthrough) == stop {
                None
            } else if self.visited[fallthrough] {
                Some(Box::new(self.goto(fallthrough)))
            } else {
                Some(Box::new(with_trailing_break(self.branch_region(
                    fallthrough,
                    join,
                    stop,
                ))))
            };
        seq.push(Structured::Switch {
            selector,
            cases: case_nodes,
            default,
        });
        match join {
            Some(j) if Some(j) != stop && self.cfg.is_reachable(j) && !self.visited[j] => {
                self.flow_to(j, stop, seq)
            }
            _ => None,
        }
    }

    /// Emit a `try`/handler region. The caller guarantees `bid` starts an EH-protected region, so
    /// the follow block (first block after the try and all its handlers) is returned directly.
    fn emit_try(&mut self, bid: BlockId, seq: &mut Vec<Structured>) -> Option<BlockId> {
        let start: u32 = self.cfg.blocks[bid].start;
        let clauses: Vec<&ExceptionClause> =
            self.try_starts.get(&start).cloned().unwrap_or_default();
        if clauses.is_empty() {
            return None;
        }
        let try_end: u32 = clauses[0].try_offset.saturating_add(clauses[0].try_length);
        let try_stop: Option<BlockId> = self.cfg.start_to_block.get(&try_end).copied();
        self.visited[bid] = true;
        let body: Structured = {
            let mut s: Vec<Structured> = Vec::new();
            self.maybe_label(bid, &mut s);
            push_block_stmts(&mut s, &self.block_code[bid].stmts);
            let term: Terminator = self.cfg.terminators[bid].clone();
            self.emit_try_body_tail(bid, &term, try_stop, &mut s);
            finish_seq(s)
        };
        let mut handlers: Vec<Handler> = Vec::new();
        let mut max_end: u32 = try_end;
        for c in &clauses {
            let h_start: Option<BlockId> = self.cfg.start_to_block.get(&c.handler_offset).copied();
            let h_end: u32 = c.handler_offset.saturating_add(c.handler_length);
            max_end = max_end.max(h_end);
            let h_stop: Option<BlockId> = self.cfg.start_to_block.get(&h_end).copied();
            let h_body: Structured = match h_start {
                Some(hb) if !self.visited[hb] => self.emit_region(hb, h_stop),
                _ => Structured::Empty,
            };
            handlers.push(Handler {
                kind: c.kind,
                catch_type: catch_type_name(self.namer, c),
                body: Box::new(h_body),
            });
        }
        seq.push(Structured::Try {
            body: Box::new(body),
            handlers,
        });
        self.cfg.start_to_block.get(&max_end).copied()
    }

    fn emit_try_body_tail(
        &mut self,
        bid: BlockId,
        term: &Terminator,
        try_stop: Option<BlockId>,
        s: &mut Vec<Structured>,
    ) {
        match term {
            Terminator::Cond { taken, fallthrough } => {
                let _: Option<BlockId> = self.emit_if(bid, *taken, *fallthrough, try_stop, s);
            }
            Terminator::Switch { cases, fallthrough } => {
                let cases_v: Vec<BlockId> = cases.clone();
                let _: Option<BlockId> = self.emit_switch(bid, &cases_v, *fallthrough, try_stop, s);
            }
            Terminator::FallThrough(next) | Terminator::Goto(next) => {
                if Some(*next) != try_stop && !self.visited[*next] {
                    let region: Structured = self.emit_region(*next, try_stop);
                    if !is_empty(&region) {
                        s.push(region);
                    }
                }
            }
            Terminator::Return => s.push(self.return_stmt(bid)),
            Terminator::Throw => s.push(self.throw_stmt(bid)),
            Terminator::EndFinally => {}
        }
    }

    fn return_stmt(&self, bid: BlockId) -> Structured {
        Structured::Return(last_return_value(&self.block_code[bid].stmts))
    }

    fn throw_stmt(&self, bid: BlockId) -> Structured {
        Structured::Throw(last_throw_value(&self.block_code[bid].stmts))
    }

    fn maybe_label(&self, bid: BlockId, seq: &mut Vec<Structured>) {
        let off: u32 = self.cfg.blocks[bid].start;
        if self.goto_targets.contains(&off) {
            seq.push(Structured::Label(off));
        }
    }

    /// Emit a jump to `bid`. When the target is a small terminal block (`return`/`throw` with no
    /// side-effecting statements), inline a duplicate of it instead of a `goto` - this mirrors
    /// `ILSpy`'s return-block duplication and removes the most common residual jumps. Otherwise fall
    /// back to a real labeled `goto`.
    fn goto(&mut self, bid: BlockId) -> Structured {
        if let Some(dup) = self.duplicable_terminal(bid) {
            return dup;
        }
        let off: u32 = self.cfg.blocks[bid].start;
        self.goto_targets.insert(off);
        Structured::Goto(off)
    }

    /// If `bid` is a small block whose tail is a control transfer that can be safely duplicated,
    /// produce an inline copy of it for a jump site instead of a `goto`:
    /// * `return`/`throw` blocks (return-block duplication, as in `ILSpy`);
    /// * a "continue tail": a short block (few statements) that falls through to the innermost loop
    ///   header, duplicated as `stmts; continue;`.
    fn duplicable_terminal(&self, bid: BlockId) -> Option<Structured> {
        match self.cfg.terminators[bid] {
            Terminator::Return if self.is_small_duplicable(bid) => {
                let mut s: Vec<Structured> = Vec::new();
                push_block_stmts(&mut s, &self.block_code[bid].stmts);
                s.push(self.return_stmt(bid));
                Some(finish_seq(s))
            }
            Terminator::Throw if self.is_small_duplicable(bid) => {
                let mut s: Vec<Structured> = Vec::new();
                push_block_stmts(&mut s, &self.block_code[bid].stmts);
                s.push(self.throw_stmt(bid));
                Some(finish_seq(s))
            }
            Terminator::FallThrough(next) | Terminator::Goto(next)
                if self.is_continue_tail(bid, next) =>
            {
                let mut s: Vec<Structured> = Vec::new();
                push_block_stmts(&mut s, &self.block_code[bid].stmts);
                if self
                    .loop_stack
                    .last()
                    .is_some_and(|f: &LoopFrame| f.continue_block == Some(next))
                {
                    push_block_stmts(&mut s, &self.block_code[next].stmts);
                }
                s.push(Structured::Continue);
                Some(finish_seq(s))
            }
            _ => None,
        }
    }

    /// Whether `bid`'s statements are a short, side-effect-local sequence safe to duplicate at a jump
    /// site: only local/field assignments and the trailing `return`/`throw`, at most a few lines.
    fn is_small_duplicable(&self, bid: BlockId) -> bool {
        const MAX_DUP_STMTS: usize = 3;
        let stmts: &[LinearStmt] = &self.block_code[bid].stmts;
        stmts.len() <= MAX_DUP_STMTS
            && stmts.iter().all(|s: &LinearStmt| {
                matches!(
                    s,
                    LinearStmt::Assign { .. } | LinearStmt::Return(_) | LinearStmt::Throw(_)
                )
            })
    }

    /// Whether `bid` is a short block (at most a few statements) whose successor `next` is the
    /// current loop's header or continue block, making it a duplicable `continue` tail.
    fn is_continue_tail(&self, bid: BlockId, next: BlockId) -> bool {
        const MAX_DUP_STMTS: usize = 4;
        self.loop_stack
            .last()
            .is_some_and(|f: &LoopFrame| f.header == next || f.continue_block == Some(next))
            && self.block_code[bid].stmts.len() <= MAX_DUP_STMTS
    }

    fn in_current_loop(&self, header: BlockId) -> bool {
        self.loop_stack
            .iter()
            .any(|f: &LoopFrame| f.header == header)
    }

    /// The join point of an `if`: the structured merge point both arms reach.
    ///
    /// Uses the immediate post-dominator when it is a real block. When that is the virtual exit (one
    /// or both arms return/throw), falls back to the lowest-offset block reachable from *both* arms
    /// (the convergence point), so shared tail code after the `if` is emitted inline rather than via
    /// a `goto`.
    fn if_join(&self, bid: BlockId, taken: BlockId, fallthrough: BlockId) -> Option<BlockId> {
        let pd: BlockId = *self.ipdom.get(bid)?;
        if pd != usize::MAX {
            return Some(pd);
        }
        let from_taken: BTreeSet<BlockId> = self.forward_reachable(taken);
        let from_ft: BTreeSet<BlockId> = self.forward_reachable(fallthrough);
        let shared: Option<BlockId> = from_taken
            .intersection(&from_ft)
            .copied()
            .min_by_key(|&b: &BlockId| self.cfg.blocks[b].start);
        if shared.is_some() {
            return shared;
        }
        // No shared merge: one arm exits via `return`/`throw`. The textual continuation is whichever
        // arm does not immediately dead-end in a terminal block, so the tail code emits after the
        // `if` with no `else`.
        let taken_terminal: bool = self.block_is_terminal(taken);
        let ft_terminal: bool = self.block_is_terminal(fallthrough);
        match (taken_terminal, ft_terminal) {
            (true, false) => Some(fallthrough),
            (false, true) => Some(taken),
            _ => None,
        }
    }

    /// Whether a block ends the method directly via `return`/`throw`/`endfinally`.
    fn block_is_terminal(&self, b: BlockId) -> bool {
        matches!(
            self.cfg.terminators[b],
            Terminator::Return | Terminator::Throw | Terminator::EndFinally
        )
    }

    /// Blocks reachable forward from `start` (inclusive), bounded by the dominator subtree of the
    /// containing region so the search stays local.
    fn forward_reachable(&self, start: BlockId) -> BTreeSet<BlockId> {
        let mut seen: BTreeSet<BlockId> = BTreeSet::new();
        let mut stack: Vec<BlockId> = vec![start];
        while let Some(b) = stack.pop() {
            if !seen.insert(b) {
                continue;
            }
            for &s in &self.cfg.blocks[b].succs {
                if !seen.contains(&s) {
                    stack.push(s);
                }
            }
        }
        seen
    }

    fn switch_join(&self, bid: BlockId, _cases: &[BlockId], _ft: BlockId) -> Option<BlockId> {
        let pd: BlockId = *self.ipdom.get(bid)?;
        (pd != usize::MAX).then_some(pd)
    }

    /// Whether the loop header is a pure `while (cond)` guard: its conditional sends one edge into
    /// the loop body and the other to the loop exit.
    fn is_loop_guard(
        &self,
        lp_idx: usize,
        taken: BlockId,
        fallthrough: BlockId,
        exit: Option<BlockId>,
    ) -> bool {
        let lp: &NaturalLoop = &self.cfg.loops[lp_idx];
        let taken_in: bool = lp.body.contains(&taken);
        let ft_in: bool = lp.body.contains(&fallthrough);
        exit.map_or(taken_in ^ ft_in, |e: BlockId| {
            (taken_in && fallthrough == e) || (ft_in && taken == e)
        })
    }

    fn loop_guard_cond(
        &self,
        header: BlockId,
        taken: BlockId,
        fallthrough: BlockId,
        exit: Option<BlockId>,
    ) -> (String, BlockId) {
        let raw: String = self.block_code[header]
            .condition
            .clone()
            .unwrap_or_else(|| "true".to_owned());
        let taken_in_loop: bool = self
            .cfg
            .loop_at_header(header)
            .is_some_and(|lp: &NaturalLoop| lp.body.contains(&taken));
        if taken_in_loop && Some(fallthrough) == exit.or(Some(fallthrough)) {
            (raw, taken)
        } else {
            (negate(&raw, self.lang), fallthrough)
        }
    }

    /// The loop's "continue block": an in-loop block, distinct from the header, whose only successor
    /// is the header and that is the target of a back-edge (a `for` increment / `while` re-test
    /// pre-block). Jumps to it are `continue` statements that first run its statements. Returns
    /// `None` when no such single block exists (then only the header serves as the continue point).
    fn loop_continue_block(&self, lp_idx: usize) -> Option<BlockId> {
        let lp: &NaturalLoop = &self.cfg.loops[lp_idx];
        let header: BlockId = lp.header;
        let mut candidate: Option<BlockId> = None;
        for &b in &lp.body {
            if b == header {
                continue;
            }
            if self.cfg.blocks[b].succs == [header] {
                if candidate.is_some() {
                    return None;
                }
                candidate = Some(b);
            }
        }
        candidate.filter(|&b: &BlockId| self.cfg.blocks[b].preds.len() >= 2)
    }

    /// The loop's single exit block: a successor of some loop block that is itself outside the loop
    /// body. Prefers the lowest IL offset (the textual fall-out point).
    fn loop_exit(&self, lp_idx: usize) -> Option<BlockId> {
        let lp: &NaturalLoop = &self.cfg.loops[lp_idx];
        let mut best: Option<(u32, BlockId)> = None;
        for &b in &lp.body {
            for &s in &self.cfg.blocks[b].succs {
                if !lp.body.contains(&s) {
                    let off: u32 = self.cfg.blocks[s].start;
                    if best.is_none_or(|(bo, _): (u32, BlockId)| off < bo) {
                        best = Some((off, s));
                    }
                }
            }
        }
        best.map(|(_, b): (u32, BlockId)| b)
    }
}

/// Recover structured pseudo-source for a method body. Returns the rendered body text and the set
/// of locals referenced (for declaration emission), plus a count of residual gotos for metrics.
#[must_use]
pub(crate) fn structure_method<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    lang: TargetLang,
) -> StructuredOutput {
    let cfg: Cfg = Cfg::build(body);
    if cfg.blocks.is_empty() {
        return StructuredOutput::default();
    }
    let mut st: Structurer<'_, N> = Structurer::new(&cfg, body, namer, lang);
    let tree: Structured = st.emit_region(cfg.entry, None);
    let residual_gotos: u32 = u32::try_from(st.goto_targets.len()).unwrap_or(u32::MAX);
    let locals_used: BTreeSet<u32> = st.locals_used.clone();
    let mut text: String = String::with_capacity(256);
    render(&mut text, &tree, 1, lang);
    StructuredOutput {
        body: text,
        locals_used,
        residual_gotos,
    }
}

/// Result of structured recovery.
#[derive(Debug, Clone, Default)]
pub(crate) struct StructuredOutput {
    pub body: String,
    pub locals_used: BTreeSet<u32>,
    pub residual_gotos: u32,
}

/// Push a block's linear statements, dropping any trailing `return`/`throw`: those are reissued by
/// the block's terminator handler so we never emit them twice.
fn push_block_stmts(seq: &mut Vec<Structured>, stmts: &[LinearStmt]) {
    let mut end: usize = stmts.len();
    while end > 0 && matches!(stmts[end - 1], LinearStmt::Return(_) | LinearStmt::Throw(_)) {
        end -= 1;
    }
    if end > 0 {
        seq.push(Structured::Block(stmts[..end].to_vec()));
    }
}

fn finish_seq(mut seq: Vec<Structured>) -> Structured {
    seq.retain(|s: &Structured| !is_empty(s));
    if seq.len() > 1 {
        return Structured::Seq(seq);
    }
    seq.pop().unwrap_or(Structured::Empty)
}

fn is_empty(s: &Structured) -> bool {
    match s {
        Structured::Empty => true,
        Structured::Seq(v) => v.iter().all(is_empty),
        Structured::Block(b) => b.is_empty(),
        _ => false,
    }
}

fn with_trailing_break(region: Structured) -> Structured {
    if ends_in_control_transfer(&region) {
        return region;
    }
    match region {
        Structured::Empty => Structured::Break,
        Structured::Seq(mut v) => {
            v.push(Structured::Break);
            Structured::Seq(v)
        }
        other => Structured::Seq(vec![other, Structured::Break]),
    }
}

fn ends_in_control_transfer(s: &Structured) -> bool {
    match s {
        Structured::Return(_)
        | Structured::Throw(_)
        | Structured::Break
        | Structured::Continue
        | Structured::Goto(_) => true,
        Structured::Seq(v) => v.last().is_some_and(ends_in_control_transfer),
        _ => false,
    }
}

fn last_return_value(stmts: &[LinearStmt]) -> Option<String> {
    None.or_else(|| {
        stmts.iter().rev().find_map(|s: &LinearStmt| match s {
            LinearStmt::Return(v) => Some(v.clone()),
            _ => None,
        })
    })
    .flatten()
}

fn last_throw_value(stmts: &[LinearStmt]) -> Option<String> {
    stmts
        .iter()
        .rev()
        .find_map(|s: &LinearStmt| match s {
            LinearStmt::Throw(v) => Some(v.clone()),
            _ => None,
        })
        .flatten()
}

fn join_and(a: &str, b: &str, lang: TargetLang) -> String {
    let op: &str = match lang {
        TargetLang::VbNet => "AndAlso",
        _ => "&&",
    };
    format!("{} {op} {}", wrap_operand(a), wrap_operand(b))
}

fn join_or(a: &str, b: &str, lang: TargetLang) -> String {
    let op: &str = match lang {
        TargetLang::VbNet => "OrElse",
        _ => "||",
    };
    format!("{} {op} {}", wrap_operand(a), wrap_operand(b))
}

/// Parenthesize a sub-condition when it already contains a lower-precedence boolean operator, so
/// short-circuit folding preserves evaluation order.
fn wrap_operand(c: &str) -> String {
    if c.contains("&&") || c.contains("||") || c.contains("AndAlso") || c.contains("OrElse") {
        format!("({c})")
    } else {
        c.to_owned()
    }
}

fn negate(cond: &str, lang: TargetLang) -> String {
    if let Some(inner) = cond
        .strip_prefix("!(")
        .and_then(|s: &str| s.strip_suffix(')'))
    {
        return inner.to_owned();
    }
    if let Some(flipped) = flip_relational(cond, lang) {
        return flipped;
    }
    match lang {
        TargetLang::CSharp => format!("!({cond})"),
        TargetLang::FSharp => format!("not ({cond})"),
        TargetLang::VbNet => format!("Not ({cond})"),
    }
}

/// Rewrite a single top-level relational comparison to its negation (`a <= b` -> `a > b`), so
/// inverted branch conditions read naturally instead of `!(a <= b)`. Only fires when the condition
/// contains exactly one comparison operator and no boolean connective (keeping precedence trivially
/// correct).
fn flip_relational(cond: &str, lang: TargetLang) -> Option<String> {
    if cond.contains("&&")
        || cond.contains("||")
        || cond.contains("AndAlso")
        || cond.contains("OrElse")
    {
        return None;
    }
    let pairs: &[(&str, &str)] = match lang {
        TargetLang::VbNet => &[
            (" <= ", " > "),
            (" >= ", " < "),
            (" <> ", " = "),
            (" < ", " >= "),
            (" > ", " <= "),
        ],
        _ => &[
            (" <= ", " > "),
            (" >= ", " < "),
            (" == ", " != "),
            (" != ", " == "),
            (" < ", " >= "),
            (" > ", " <= "),
        ],
    };
    let present: Vec<&(&str, &str)> = pairs
        .iter()
        .filter(|(from, _): &&(&str, &str)| cond.contains(*from))
        .collect();
    let (from, to): &(&str, &str) = present.first()?;
    let comparator_count: usize = pairs
        .iter()
        .map(|(f, _): &(&str, &str)| cond.matches(f).count())
        .sum();
    (comparator_count == 1).then(|| cond.replacen(from, to, 1))
}

fn catch_type_name<N: TokenNamer>(namer: &N, c: &ExceptionClause) -> Option<String> {
    matches!(c.kind, ExceptionClauseKind::Catch)
        .then(|| short_type(&namer.name(c.class_token_or_filter)))
}

fn short_type(name: &str) -> String {
    name.rsplit("::")
        .next()
        .unwrap_or(name)
        .rsplit('.')
        .next()
        .unwrap_or(name)
        .to_owned()
}

fn indent(text: &mut String, depth: usize) {
    for _ in 0..depth {
        text.push_str("    ");
    }
}

/// Render the structured tree to language-faithful source at the given indentation `depth`.
fn render(text: &mut String, node: &Structured, depth: usize, lang: TargetLang) {
    match node {
        Structured::Empty => {}
        Structured::Seq(v) => {
            for n in v {
                render(text, n, depth, lang);
            }
        }
        Structured::Block(stmts) => {
            for s in stmts {
                render_linear(text, s, depth, lang);
            }
        }
        Structured::While { cond, body } => render_while(text, cond.as_deref(), body, depth, lang),
        Structured::If { cond, then, els } => {
            render_if(text, cond, then, els.as_deref(), depth, lang);
        }
        Structured::Switch {
            selector,
            cases,
            default,
        } => render_switch(text, selector, cases, default.as_deref(), depth, lang),
        Structured::Try { body, handlers } => render_try(text, body, handlers, depth, lang),
        Structured::Return(v) => render_return(text, v.as_deref(), depth, lang),
        Structured::Throw(v) => render_throw(text, v.as_deref(), depth, lang),
        Structured::Break => render_kw(text, depth, lang, "break;", "()", "Exit While"),
        Structured::Continue => render_kw(text, depth, lang, "continue;", "()", "Continue While"),
        Structured::Goto(off) => render_goto(text, *off, depth, lang),
        Structured::Label(off) => render_label(text, *off, depth, lang),
    }
}

fn render_linear(text: &mut String, s: &LinearStmt, depth: usize, lang: TargetLang) {
    let term: &str = stmt_terminator(lang);
    match s {
        LinearStmt::Assign { target, value } => {
            indent(text, depth);
            let op: &str = if matches!(lang, TargetLang::FSharp) {
                "<-"
            } else {
                "="
            };
            let _ = writeln!(text, "{target} {op} {value}{term}");
        }
        LinearStmt::Expr(e) => {
            indent(text, depth);
            match lang {
                TargetLang::FSharp => {
                    let _ = writeln!(text, "{e} |> ignore");
                }
                _ => {
                    let _ = writeln!(text, "{e}{term}");
                }
            }
        }
        LinearStmt::Return(v) => render_return(text, v.as_deref(), depth, lang),
        LinearStmt::Throw(v) => render_throw(text, v.as_deref(), depth, lang),
        LinearStmt::Comment(c) => render_comment(text, c, depth, lang),
    }
}

const fn stmt_terminator(lang: TargetLang) -> &'static str {
    match lang {
        TargetLang::CSharp => ";",
        TargetLang::FSharp | TargetLang::VbNet => "",
    }
}

fn render_while(
    text: &mut String,
    cond: Option<&str>,
    body: &Structured,
    depth: usize,
    lang: TargetLang,
) {
    let cond: &str = cond.unwrap_or(match lang {
        TargetLang::VbNet => "True",
        _ => "true",
    });
    indent(text, depth);
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "while ({cond})");
            indent(text, depth);
            let _ = writeln!(text, "{{");
            render(text, body, depth + 1, lang);
            indent(text, depth);
            let _ = writeln!(text, "}}");
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "while {cond} do");
            render(text, body, depth + 1, lang);
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "While {cond}");
            render(text, body, depth + 1, lang);
            indent(text, depth);
            let _ = writeln!(text, "End While");
        }
    }
}

fn render_if(
    text: &mut String,
    cond: &str,
    then: &Structured,
    els: Option<&Structured>,
    depth: usize,
    lang: TargetLang,
) {
    indent(text, depth);
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "if ({cond})");
            indent(text, depth);
            let _ = writeln!(text, "{{");
            render(text, then, depth + 1, lang);
            indent(text, depth);
            let _ = writeln!(text, "}}");
            if let Some(e) = els {
                indent(text, depth);
                let _ = writeln!(text, "else");
                indent(text, depth);
                let _ = writeln!(text, "{{");
                render(text, e, depth + 1, lang);
                indent(text, depth);
                let _ = writeln!(text, "}}");
            }
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "if {cond} then");
            render(text, then, depth + 1, lang);
            if let Some(e) = els {
                indent(text, depth);
                let _ = writeln!(text, "else");
                render(text, e, depth + 1, lang);
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "If {cond} Then");
            render(text, then, depth + 1, lang);
            if let Some(e) = els {
                indent(text, depth);
                let _ = writeln!(text, "Else");
                render(text, e, depth + 1, lang);
            }
            indent(text, depth);
            let _ = writeln!(text, "End If");
        }
    }
}

fn render_switch(
    text: &mut String,
    selector: &str,
    cases: &[(Vec<usize>, Structured)],
    default: Option<&Structured>,
    depth: usize,
    lang: TargetLang,
) {
    indent(text, depth);
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "switch ({selector})");
            indent(text, depth);
            let _ = writeln!(text, "{{");
            for (labels, region) in cases {
                for l in labels {
                    indent(text, depth + 1);
                    let _ = writeln!(text, "case {l}:");
                }
                render(text, region, depth + 2, lang);
            }
            if let Some(d) = default {
                indent(text, depth + 1);
                let _ = writeln!(text, "default:");
                render(text, &with_trailing_break(d.clone()), depth + 2, lang);
            }
            indent(text, depth);
            let _ = writeln!(text, "}}");
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "match {selector} with");
            for (labels, region) in cases {
                indent(text, depth);
                let pats: String = labels
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<String>>()
                    .join(" | ");
                let _ = writeln!(text, "| {pats} ->");
                render(text, region, depth + 1, lang);
            }
            if let Some(d) = default {
                indent(text, depth);
                let _ = writeln!(text, "| _ ->");
                render(text, d, depth + 1, lang);
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "Select Case {selector}");
            for (labels, region) in cases {
                for l in labels {
                    indent(text, depth + 1);
                    let _ = writeln!(text, "Case {l}");
                }
                render(text, region, depth + 2, lang);
            }
            if let Some(d) = default {
                indent(text, depth + 1);
                let _ = writeln!(text, "Case Else");
                render(text, d, depth + 2, lang);
            }
            indent(text, depth);
            let _ = writeln!(text, "End Select");
        }
    }
}

fn render_try(
    text: &mut String,
    body: &Structured,
    handlers: &[Handler],
    depth: usize,
    lang: TargetLang,
) {
    indent(text, depth);
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "try");
            indent(text, depth);
            let _ = writeln!(text, "{{");
            render(text, body, depth + 1, lang);
            indent(text, depth);
            let _ = writeln!(text, "}}");
            for h in handlers {
                indent(text, depth);
                let _ = writeln!(text, "{}", csharp_handler_head(h));
                indent(text, depth);
                let _ = writeln!(text, "{{");
                render(text, &h.body, depth + 1, lang);
                indent(text, depth);
                let _ = writeln!(text, "}}");
            }
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "try");
            render(text, body, depth + 1, lang);
            for h in handlers {
                indent(text, depth);
                let head: &str = match h.kind {
                    ExceptionClauseKind::Finally => "finally",
                    _ => "with _ ->",
                };
                let _ = writeln!(text, "{head}");
                render(text, &h.body, depth + 1, lang);
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "Try");
            render(text, body, depth + 1, lang);
            for h in handlers {
                indent(text, depth);
                let head: String = match h.kind {
                    ExceptionClauseKind::Finally => "Finally".to_owned(),
                    _ => h.catch_type.as_ref().map_or_else(
                        || "Catch".to_owned(),
                        |t: &String| format!("Catch ex As {t}"),
                    ),
                };
                let _ = writeln!(text, "{head}");
                render(text, &h.body, depth + 1, lang);
            }
            indent(text, depth);
            let _ = writeln!(text, "End Try");
        }
    }
}

fn csharp_handler_head(h: &Handler) -> String {
    match h.kind {
        ExceptionClauseKind::Finally => "finally".to_owned(),
        ExceptionClauseKind::Fault => "catch /* fault */".to_owned(),
        ExceptionClauseKind::Filter => "catch when (/* filter */ true)".to_owned(),
        ExceptionClauseKind::Catch => h.catch_type.as_ref().map_or_else(
            || "catch".to_owned(),
            |t: &String| format!("catch ({t} ex)"),
        ),
    }
}

fn render_return(text: &mut String, v: Option<&str>, depth: usize, lang: TargetLang) {
    indent(text, depth);
    match (lang, v) {
        (TargetLang::CSharp, Some(v)) => {
            let _ = writeln!(text, "return {v};");
        }
        (TargetLang::CSharp, None) => {
            let _ = writeln!(text, "return;");
        }
        (TargetLang::FSharp, Some(v)) => {
            let _ = writeln!(text, "{v}");
        }
        (TargetLang::FSharp, None) => {
            let _ = writeln!(text, "()");
        }
        (TargetLang::VbNet, Some(v)) => {
            let _ = writeln!(text, "Return {v}");
        }
        (TargetLang::VbNet, None) => {
            let _ = writeln!(text, "Return");
        }
    }
}

fn render_throw(text: &mut String, v: Option<&str>, depth: usize, lang: TargetLang) {
    indent(text, depth);
    match (lang, v) {
        (TargetLang::CSharp, Some(v)) => {
            let _ = writeln!(text, "throw {v};");
        }
        (TargetLang::CSharp, None) => {
            let _ = writeln!(text, "throw;");
        }
        (TargetLang::FSharp, Some(v)) => {
            let _ = writeln!(text, "raise {v}");
        }
        (TargetLang::FSharp, None) => {
            let _ = writeln!(text, "reraise()");
        }
        (TargetLang::VbNet, Some(v)) => {
            let _ = writeln!(text, "Throw {v}");
        }
        (TargetLang::VbNet, None) => {
            let _ = writeln!(text, "Throw");
        }
    }
}

fn render_kw(text: &mut String, depth: usize, lang: TargetLang, cs: &str, fs: &str, vb: &str) {
    indent(text, depth);
    let _ = match lang {
        TargetLang::CSharp => writeln!(text, "{cs}"),
        TargetLang::FSharp => writeln!(text, "{fs}"),
        TargetLang::VbNet => writeln!(text, "{vb}"),
    };
}

fn render_goto(text: &mut String, off: u32, depth: usize, lang: TargetLang) {
    indent(text, depth);
    let _ = match lang {
        TargetLang::CSharp => writeln!(text, "goto IL_{off:04X};"),
        TargetLang::FSharp => writeln!(text, "// goto IL_{off:04X}"),
        TargetLang::VbNet => writeln!(text, "GoTo IL_{off:04X}"),
    };
}

fn render_label(text: &mut String, off: u32, depth: usize, lang: TargetLang) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "IL_{off:04X}:;");
        }
        TargetLang::FSharp => {
            indent(text, depth);
            let _ = writeln!(text, "// IL_{off:04X}:");
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "IL_{off:04X}:");
        }
    }
}

fn render_comment(text: &mut String, c: &str, depth: usize, lang: TargetLang) {
    indent(text, depth);
    let _ = match lang {
        TargetLang::VbNet => writeln!(text, "' {c}"),
        _ => writeln!(text, "// {c}"),
    };
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::disassemble;
    use crate::structurize::HexNamer;

    fn structure(code: &[u8], lang: TargetLang) -> StructuredOutput {
        let body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        };
        structure_method(&body, &HexNamer, lang)
    }

    #[test]
    fn straight_line_has_no_goto() {
        let out: StructuredOutput = structure(&[0x16, 0x17, 0x58, 0x2A], TargetLang::CSharp);
        assert_eq!(out.residual_gotos, 0);
        assert!(out.body.contains("return"), "got:\n{}", out.body);
    }

    #[test]
    fn backward_branch_becomes_while_loop() {
        let code: [u8; 6] = [0x16, 0x0A, 0x06, 0x2D, 0xFD, 0x2A];
        let out: StructuredOutput = structure(&code, TargetLang::CSharp);
        assert!(
            out.body.contains("while ("),
            "backward branch must become a while loop; got:\n{}",
            out.body
        );
    }
}
