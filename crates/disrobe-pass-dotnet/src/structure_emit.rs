use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use crate::cfg::{BlockId, Cfg, NaturalLoop, Terminator};
use crate::cil::{ExceptionClause, ExceptionClauseKind, Instruction, MethodBody};
use crate::names::NameTable;
use crate::structurize::{
    BlockCode, LinearStmt, TargetLang, TokenNamer, lift_block, lift_filter_condition,
};

#[derive(Debug, Clone)]
pub(crate) enum Structured {
    Seq(Vec<Self>),

    Block(Vec<LinearStmt>),

    While {
        cond: Option<String>,
        body: Box<Self>,
    },

    If {
        cond: String,
        then: Box<Self>,
        els: Option<Box<Self>>,
    },

    Switch {
        selector: String,
        cases: Vec<(Vec<usize>, Self)>,
        default: Option<Box<Self>>,
    },

    Try {
        body: Box<Self>,
        handlers: Vec<Handler>,
    },
    Return(Option<String>),
    Throw(Option<String>),
    Break,
    Continue,

    Goto(u32),

    Label(u32),

    Empty,
}

#[derive(Debug, Clone)]
pub(crate) struct Handler {
    pub kind: ExceptionClauseKind,
    pub catch_type: Option<String>,
    pub filter: Option<String>,
    pub body: Box<Structured>,
}

#[derive(Debug, Clone, Copy)]
struct LoopFrame {
    header: BlockId,
    exit: Option<BlockId>,

    continue_block: Option<BlockId>,
}

const MAX_STRUCTURE_DEPTH: usize = 256;

struct Structurer<'a, N: TokenNamer> {
    cfg: &'a Cfg,
    namer: &'a N,
    names: &'a NameTable,
    lang: TargetLang,
    instrs: &'a [Instruction],
    ipdom: Vec<BlockId>,
    block_code: Vec<BlockCode>,
    loop_header: Vec<bool>,
    visited: Vec<bool>,
    depth: usize,
    loop_stack: Vec<LoopFrame>,
    goto_targets: BTreeSet<u32>,
    locals_used: BTreeSet<u32>,
    try_starts: BTreeMap<u32, Vec<&'a ExceptionClause>>,
    async_state_machine: bool,
}

impl<'a, N: TokenNamer> Structurer<'a, N> {
    fn new(
        cfg: &'a Cfg,
        body: &'a MethodBody,
        namer: &'a N,
        names: &'a NameTable,
        lang: TargetLang,
        async_state_machine: bool,
    ) -> Self {
        let count: usize = cfg.blocks.len();
        let ipdom: Vec<BlockId> = cfg.immediate_post_dominators();
        let block_code: Vec<BlockCode> = (0..count)
            .map(|b: usize| {
                lift_block(
                    namer,
                    names,
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
            names,
            lang,
            instrs: &body.instructions,
            ipdom,
            block_code,
            loop_header,
            visited: vec![false; count],
            depth: 0,
            loop_stack: Vec::new(),
            goto_targets: BTreeSet::new(),
            locals_used,
            try_starts,
            async_state_machine,
        }
    }

    fn emit_region(&mut self, start: BlockId, stop: Option<BlockId>) -> Structured {
        self.depth += 1;
        if self.depth > MAX_STRUCTURE_DEPTH {
            self.depth -= 1;
            return self.goto(start);
        }
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
        self.depth -= 1;
        finish_seq(seq)
    }

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

    fn is_pure_cond_block(&self, bid: BlockId) -> bool {
        self.block_code[bid].stmts.is_empty()
            && self.block_code[bid].condition.is_some()
            && matches!(self.cfg.terminators[bid], Terminator::Cond { .. })
            && self.cfg.blocks[bid].preds.len() == 1
            && !self.loop_header[bid]
            && !self.visited[bid]
    }

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

        if join.is_none()
            && ends_in_return_or_throw(&then_branch)
            && ends_in_return_or_throw(&else_branch)
        {
            seq.push(Structured::If {
                cond: negate(&cond, self.lang),
                then: Box::new(else_branch),
                els: None,
            });
            seq.push(then_branch);
            return None;
        }

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
            let (catch_type, filter): (Option<String>, Option<String>) =
                if matches!(c.kind, ExceptionClauseKind::Filter) {
                    self.recover_filter(c)
                } else {
                    (catch_type_name(self.namer, c), None)
                };
            handlers.push(Handler {
                kind: c.kind,
                catch_type,
                filter,
                body: Box::new(h_body),
            });
        }
        seq.push(Structured::Try {
            body: Box::new(body),
            handlers,
        });
        self.cfg.start_to_block.get(&max_end).copied()
    }

    fn recover_filter(&mut self, c: &ExceptionClause) -> (Option<String>, Option<String>) {
        let filter_start: u32 = c.class_token_or_filter;
        let filter_end: u32 = c.handler_offset;
        let first: Option<usize> = self
            .instrs
            .iter()
            .position(|i: &Instruction| i.offset >= filter_start && i.offset < filter_end);
        let Some(first): Option<usize> = first else {
            return (None, None);
        };
        let last: usize = self
            .instrs
            .iter()
            .enumerate()
            .rev()
            .find(|(_, i): &(usize, &Instruction)| {
                i.offset >= filter_start && i.offset < filter_end
            })
            .map_or(first, |(idx, _): (usize, &Instruction)| idx);
        for b in 0..self.cfg.blocks.len() {
            let start: u32 = self.cfg.blocks[b].start;
            if start >= filter_start && start < filter_end {
                self.visited[b] = true;
            }
        }
        let recovered: Option<(Option<String>, String)> =
            lift_filter_condition(self.namer, self.names, self.lang, self.instrs, first, last);
        match recovered {
            Some((catch_type, cond)) => (catch_type, Some(cond)),
            None => (None, None),
        }
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

    fn reemit_with_known_labels(&mut self) -> Structured {
        let entry: BlockId = self.cfg.entry;
        self.visited.iter_mut().for_each(|v: &mut bool| *v = false);
        self.loop_stack.clear();
        self.emit_region(entry, None)
    }

    fn maybe_label(&self, bid: BlockId, seq: &mut Vec<Structured>) {
        let off: u32 = self.cfg.blocks[bid].start;
        if self.goto_targets.contains(&off) {
            seq.push(Structured::Label(off));
        }
    }

    fn goto(&mut self, bid: BlockId) -> Structured {
        if let Some(dup) = self.duplicable_terminal(bid) {
            return dup;
        }
        let off: u32 = self.cfg.blocks[bid].start;
        self.goto_targets.insert(off);
        Structured::Goto(off)
    }

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
        let taken_terminal: bool = self.block_is_terminal(taken);
        let ft_terminal: bool = self.block_is_terminal(fallthrough);
        match (taken_terminal, ft_terminal) {
            (true, false) => Some(fallthrough),
            (false, true) => Some(taken),
            _ => None,
        }
    }

    fn block_is_terminal(&self, b: BlockId) -> bool {
        matches!(
            self.cfg.terminators[b],
            Terminator::Return | Terminator::Throw | Terminator::EndFinally
        )
    }

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

    fn loop_exit(&self, lp_idx: usize) -> Option<BlockId> {
        let lp: &NaturalLoop = &self.cfg.loops[lp_idx];
        let mut exits: Vec<(u32, BlockId)> = Vec::new();
        for &b in &lp.body {
            for &s in &self.cfg.blocks[b].succs {
                if !lp.body.contains(&s) && !exits.iter().any(|(_, e): &(u32, BlockId)| *e == s) {
                    exits.push((self.cfg.blocks[s].start, s));
                }
            }
        }
        if self.async_state_machine && exits.len() > 1 {
            return self.async_loop_done_exit(&exits);
        }
        exits
            .into_iter()
            .min_by_key(|(off, _): &(u32, BlockId)| *off)
            .map(|(_, b): (u32, BlockId)| b)
    }

    fn async_loop_done_exit(&self, exits: &[(u32, BlockId)]) -> Option<BlockId> {
        exits
            .iter()
            .filter(|(_, b): &&(u32, BlockId)| !self.is_async_suspend_exit(*b))
            .max_by_key(|(off, _): &&(u32, BlockId)| *off)
            .or_else(|| exits.iter().min_by_key(|(off, _): &&(u32, BlockId)| *off))
            .map(|&(_, b): &(u32, BlockId)| b)
    }

    fn is_async_suspend_exit(&self, bid: BlockId) -> bool {
        self.block_code[bid].stmts.iter().any(|s: &LinearStmt| {
            stmt_text(s)
                .is_some_and(|t: &str| t.contains("AwaitUnsafeOnCompleted") || t.contains("<>u__"))
        })
    }
}

#[must_use]
pub(crate) fn structure_method<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> StructuredOutput {
    structure_method_core(body, namer, names, lang, false, false)
}

#[must_use]
pub(crate) fn structure_move_next<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    is_async: bool,
) -> StructuredOutput {
    structure_method_core(body, namer, names, lang, true, is_async)
}

#[must_use]
fn structure_method_core<N: TokenNamer>(
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    is_state_machine_move_next: bool,
    is_async: bool,
) -> StructuredOutput {
    let mut cfg: Cfg = Cfg::build(body);
    if cfg.blocks.is_empty() {
        return StructuredOutput::default();
    }
    if is_state_machine_move_next {
        let _ = crate::state_machine_cfg::normalize_move_next(&mut cfg, body);
    }
    let mut st: Structurer<'_, N> = Structurer::new(&cfg, body, namer, names, lang, is_async);
    let first: Structured = st.emit_region(cfg.entry, None);
    let had_back_gotos: bool = !st.goto_targets.is_empty();
    let mut tree: Structured = if had_back_gotos {
        st.reemit_with_known_labels()
    } else {
        first
    };
    prune_orphan_labels(&mut tree);
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

#[derive(Debug, Clone, Default)]
pub(crate) struct StructuredOutput {
    pub body: String,
    pub locals_used: BTreeSet<u32>,
    pub residual_gotos: u32,
}

fn stmt_text(stmt: &LinearStmt) -> Option<&str> {
    match stmt {
        LinearStmt::Expr(t) | LinearStmt::Comment(t) => Some(t),
        LinearStmt::Assign { value, .. } => Some(value),
        LinearStmt::Return(_) | LinearStmt::Throw(_) => None,
    }
}

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

fn prune_orphan_labels(tree: &mut Structured) {
    let mut referenced: BTreeSet<u32> = BTreeSet::new();
    collect_gotos(tree, &mut referenced);
    drop_unreferenced_labels(tree, &referenced);
}

fn collect_gotos(node: &Structured, out: &mut BTreeSet<u32>) {
    match node {
        Structured::Goto(off) => {
            out.insert(*off);
        }
        Structured::Seq(v) => v.iter().for_each(|n: &Structured| collect_gotos(n, out)),
        Structured::While { body, .. } => collect_gotos(body, out),
        Structured::If { then, els, .. } => {
            collect_gotos(then, out);
            if let Some(e) = els {
                collect_gotos(e, out);
            }
        }
        Structured::Switch { cases, default, .. } => {
            for (_, c) in cases {
                collect_gotos(c, out);
            }
            if let Some(d) = default {
                collect_gotos(d, out);
            }
        }
        Structured::Try { body, handlers } => {
            collect_gotos(body, out);
            for h in handlers {
                collect_gotos(&h.body, out);
            }
        }
        _ => {}
    }
}

fn drop_unreferenced_labels(node: &mut Structured, referenced: &BTreeSet<u32>) {
    match node {
        Structured::Seq(v) => {
            v.retain(
                |n: &Structured| !matches!(n, Structured::Label(off) if !referenced.contains(off)),
            );
            for n in v.iter_mut() {
                drop_unreferenced_labels(n, referenced);
            }
        }
        Structured::While { body, .. } => drop_unreferenced_labels(body, referenced),
        Structured::If { then, els, .. } => {
            drop_unreferenced_labels(then, referenced);
            if let Some(e) = els {
                drop_unreferenced_labels(e, referenced);
            }
        }
        Structured::Switch { cases, default, .. } => {
            for (_, c) in cases {
                drop_unreferenced_labels(c, referenced);
            }
            if let Some(d) = default {
                drop_unreferenced_labels(d, referenced);
            }
        }
        Structured::Try { body, handlers } => {
            drop_unreferenced_labels(body, referenced);
            for h in handlers {
                drop_unreferenced_labels(&mut h.body, referenced);
            }
        }
        _ => {}
    }
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

fn ends_in_return_or_throw(s: &Structured) -> bool {
    match s {
        Structured::Return(_) | Structured::Throw(_) => true,
        Structured::Seq(v) => v.last().is_some_and(ends_in_return_or_throw),
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
                let head: String = vbnet_handler_head(h);
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
        ExceptionClauseKind::Finally | ExceptionClauseKind::Fault => "finally".to_owned(),
        ExceptionClauseKind::Filter => csharp_filter_head(h),
        ExceptionClauseKind::Catch => h.catch_type.as_ref().map_or_else(
            || "catch".to_owned(),
            |t: &String| format!("catch ({t} ex)"),
        ),
    }
}

fn csharp_filter_head(h: &Handler) -> String {
    match (&h.catch_type, &h.filter) {
        (Some(t), Some(f)) => format!("catch ({t} ex) when ({f})"),
        (Some(t), None) => format!("catch ({t} ex)"),
        (None, Some(f)) => format!("catch when ({f})"),
        (None, None) => "catch".to_owned(),
    }
}

fn vbnet_handler_head(h: &Handler) -> String {
    if matches!(h.kind, ExceptionClauseKind::Finally) {
        return "Finally".to_owned();
    }
    let base: String = h.catch_type.as_ref().map_or_else(
        || "Catch".to_owned(),
        |t: &String| format!("Catch ex As {t}"),
    );
    match &h.filter {
        Some(f) => format!("{base} When {f}"),
        None => base,
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
        structure_method(&body, &HexNamer, &NameTable::default(), lang)
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

    fn deep_conditional_chain(n: u32) -> Vec<u8> {
        let mut code: Vec<u8> = Vec::with_capacity(9 * n as usize + 1);
        let tail_start: u32 = 6 * n + 1;
        for i in 0..n {
            let next_off: u32 = 6 * i + 6;
            let s_off: u32 = tail_start + 3 * i;
            let disp: i32 = (i64::from(s_off) - i64::from(next_off)) as i32;
            code.push(0x02);
            code.push(0x3A);
            code.extend_from_slice(&disp.to_le_bytes());
        }
        code.push(0x2A);
        for _ in 0..n {
            code.push(0x2B);
            code.push(0x00);
            code.push(0x2A);
        }
        code
    }

    fn decompile_chain(n: u32) -> String {
        let code: Vec<u8> = deep_conditional_chain(n);
        let body: MethodBody = MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: disassemble(&code).expect("disasm"),
            exception_clauses: Vec::new(),
        };
        crate::structurize::decompile_method_named(
            "void M()",
            &body,
            &HexNamer,
            &NameTable::default(),
            TargetLang::CSharp,
        )
        .body
    }

    #[test]
    fn deep_conditional_chain_recursion_is_depth_bounded() {
        let shallow: String = decompile_chain(8);
        assert_eq!(
            shallow.matches("if (").count(),
            8,
            "a chain shorter than the depth budget structures fully; got:\n{shallow}"
        );
        assert_eq!(shallow.matches("goto ").count(), 0);

        let cap: u32 = MAX_STRUCTURE_DEPTH as u32;
        let deep: String = decompile_chain(cap * 2);
        assert_eq!(
            deep.matches("if (").count(),
            MAX_STRUCTURE_DEPTH,
            "the recovered nesting is capped at the depth budget rather than the chain length"
        );
        assert!(
            deep.matches("goto ").count() > 0,
            "the depth cap degrades to a goto instead of recursing"
        );
        assert_eq!(
            decompile_chain(cap * 3).matches("if (").count(),
            MAX_STRUCTURE_DEPTH,
            "a longer chain still caps at the depth budget, so nesting is bounded regardless of chain length"
        );
    }
}
