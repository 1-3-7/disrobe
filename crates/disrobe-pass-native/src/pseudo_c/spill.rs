use std::collections::BTreeMap;

use super::{
    Block, Cond, CondKind, ExtSource, Flags, FpOperand, IndexOperand, LoopCond, MemRef, MemRmwOp,
    Node, PackedOp, Reg, RegRef, Source, Stmt, SwitchCase, VecStmt, Width, may_alias,
};

const MAX_INLINED_DEFINITIONS: usize = 128;

const MAX_RECORDED_DECISIONS: usize = 128;

const LOOP_USE_WEIGHT: u32 = 8;
const MAX_LOOP_WEIGHT_DEPTH: u32 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum InlineBarrier {
    Call,
    Store,
    Atomic,
    OperandWrite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum SpillReason {
    Crosses(InlineBarrier),
    MultipleUses,
    NoSubstitutableUse,
    LoopDepth,
    LiveAfterUse,
    EffectfulDefinition,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct UseFacts {
    pub(super) textual: u32,
    pub(super) loop_weighted: u32,
}

impl UseFacts {
    fn observe(self, extra_depth: u32) -> Self {
        let weight: u32 = LOOP_USE_WEIGHT.saturating_pow(extra_depth.min(MAX_LOOP_WEIGHT_DEPTH));
        Self {
            textual: self.textual.saturating_add(1),
            loop_weighted: self.loop_weighted.saturating_add(weight),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SpillFacts {
    pub(super) uses: UseFacts,
    pub(super) reason: Option<SpillReason>,
}

impl SpillFacts {
    pub(super) const fn inlinable(self) -> bool {
        self.reason.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SpillDecision {
    pub(super) dest: Reg,
    pub(super) facts: SpillFacts,
}

#[derive(Debug, Default)]
pub(super) struct SpillOutcome {
    pub(super) inlined: usize,
    pub(super) decisions: Vec<SpillDecision>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UseSite {
    Value,
    Register,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    Read(UseSite),
    Write,
}

const PROTECTED: [Reg; 3] = [Reg::Rsp, Reg::Rbp, Reg::Rax];

pub(super) fn inline_single_use_definitions(body: &mut Block, live_out: &[Reg]) -> SpillOutcome {
    let mut outcome: SpillOutcome = SpillOutcome::default();
    let unstructured: bool = has_unstructured_flow(body);
    for _ in 0..=MAX_INLINED_DEFINITIONS {
        let totals: BTreeMap<Reg, u32> = function_read_totals(body);
        let mut context: Context<'_> = Context {
            totals: &totals,
            live_out,
            unstructured,
            outcome: &mut outcome,
        };
        if !apply_once(body, &mut context, false) {
            return outcome;
        }
    }
    outcome
}

struct Context<'facts> {
    totals: &'facts BTreeMap<Reg, u32>,
    live_out: &'facts [Reg],
    unstructured: bool,
    outcome: &'facts mut SpillOutcome,
}

fn has_unstructured_flow(block: &Block) -> bool {
    block.iter().any(|node: &Node| match node {
        Node::Label(_)
        | Node::Goto(_)
        | Node::ResumeAt(_)
        | Node::OuterResume(_)
        | Node::BreakLoop(_)
        | Node::ContinueLoop(_) => true,
        Node::If {
            then_body,
            else_body,
            ..
        } => {
            has_unstructured_flow(then_body)
                || else_body
                    .as_ref()
                    .is_some_and(|body: &Block| has_unstructured_flow(body))
        }
        Node::DoWhile { body, .. } | Node::While { body, .. } => has_unstructured_flow(body),
        Node::Switch { cases, default, .. } => {
            cases
                .iter()
                .any(|case: &SwitchCase| has_unstructured_flow(&case.body))
                || has_unstructured_flow(default)
        }
        Node::Stmt(_) | Node::CondSnapshot { .. } | Node::Break | Node::Continue | Node::Return => {
            false
        }
    })
}

fn apply_once(block: &mut Block, context: &mut Context<'_>, inside_loop: bool) -> bool {
    if rewrite_runs(block, context, inside_loop) {
        return true;
    }
    for node in block.iter_mut() {
        let applied: bool = match node {
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                apply_once(then_body, context, inside_loop)
                    || else_body
                        .as_mut()
                        .is_some_and(|body: &mut Block| apply_once(body, context, inside_loop))
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                apply_once(body, context, true)
            }
            Node::Switch { cases, default, .. } => {
                cases
                    .iter_mut()
                    .any(|case: &mut SwitchCase| apply_once(&mut case.body, context, inside_loop))
                    || apply_once(default, context, inside_loop)
            }
            Node::Stmt(_)
            | Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::BreakLoop(_)
            | Node::ContinueLoop(_)
            | Node::ResumeAt(_)
            | Node::OuterResume(_)
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => false,
        };
        if applied {
            return true;
        }
    }
    false
}

fn rewrite_runs(block: &mut Block, context: &mut Context<'_>, inside_loop: bool) -> bool {
    let mut start: usize = 0;
    while start < block.len() {
        if !is_stmt(&block[start]) {
            start += 1;
            continue;
        }
        let end: usize = (start..block.len())
            .find(|&index: &usize| !is_stmt(&block[index]))
            .unwrap_or(block.len());
        for def_index in start..end {
            if try_inline(block, context, inside_loop, start, end, def_index) {
                return true;
            }
        }
        start = end;
    }
    false
}

const fn is_stmt(node: &Node) -> bool {
    matches!(node, Node::Stmt(_))
}

fn try_inline(
    block: &mut Block,
    context: &mut Context<'_>,
    inside_loop: bool,
    run_start: usize,
    run_end: usize,
    def_index: usize,
) -> bool {
    let Some(Node::Stmt(Stmt::Assign { dest, src })) = block.get(def_index) else {
        return false;
    };
    let (dest, src): (RegRef, Source) = (*dest, src.clone());
    if dest.width != Width::W64
        || PROTECTED.contains(&dest.reg)
        || context.live_out.contains(&dest.reg)
    {
        return false;
    }
    if !source_is_substitutable(&src) {
        record(context, block, dest.reg, SpillReason::EffectfulDefinition);
        return false;
    }
    let in_run: u32 = range_reads(block, run_start, run_end, dest.reg);
    let total: u32 = context.totals.get(&dest.reg).copied().unwrap_or(u32::MAX);
    if total != in_run {
        let reason: SpillReason = escape_reason(block, dest.reg);
        record(context, block, dest.reg, reason);
        return false;
    }
    if in_run == 0 {
        record(context, block, dest.reg, SpillReason::NoSubstitutableUse);
        return false;
    }
    let before: u32 = range_reads(block, run_start, def_index, dest.reg);
    if (inside_loop || context.unstructured) && before > 0 {
        record(context, block, dest.reg, SpillReason::LiveAfterUse);
        return false;
    }
    let after: u32 = range_reads(block, def_index + 1, run_end, dest.reg);
    if after != 1 {
        let reason: SpillReason = if after == 0 {
            SpillReason::NoSubstitutableUse
        } else {
            SpillReason::MultipleUses
        };
        record(context, block, dest.reg, reason);
        return false;
    }
    let Some(use_index): Option<usize> = (def_index + 1..run_end).find(|&index: &usize| {
        stmt_at(block, index).is_some_and(|stmt: &Stmt| reads(stmt, dest.reg) > 0)
    }) else {
        record(context, block, dest.reg, SpillReason::NoSubstitutableUse);
        return false;
    };
    let Some(site): Option<UseSite> =
        stmt_at(block, use_index).and_then(|stmt: &Stmt| sole_read_site(stmt, dest.reg))
    else {
        record(context, block, dest.reg, SpillReason::NoSubstitutableUse);
        return false;
    };
    if !site_accepts(site, &src) {
        record(context, block, dest.reg, SpillReason::NoSubstitutableUse);
        return false;
    }
    if let Some(barrier) = first_barrier(block, def_index + 1, use_index, &src, dest.reg) {
        record(context, block, dest.reg, SpillReason::Crosses(barrier));
        return false;
    }
    let facts: UseFacts = local_use_facts(block, dest.reg);
    let Some(Node::Stmt(target)) = block.get_mut(use_index) else {
        return false;
    };
    if !substitute(target, dest.reg, &src) {
        record(context, block, dest.reg, SpillReason::NoSubstitutableUse);
        return false;
    }
    if stmt_at(block, use_index).is_some_and(is_self_assignment) {
        block.remove(use_index);
    }
    block.remove(def_index);
    context.outcome.inlined = context.outcome.inlined.saturating_add(1);
    context.outcome.decisions.push(SpillDecision {
        dest: dest.reg,
        facts: SpillFacts {
            uses: facts,
            reason: None,
        },
    });
    true
}

fn is_self_assignment(stmt: &Stmt) -> bool {
    matches!(
        stmt,
        Stmt::Assign {
            dest: RegRef { reg: dest, width: Width::W64 },
            src: Source::Reg(RegRef { reg: source, width: Width::W64 }),
        } if dest == source
    )
}

fn escape_reason(block: &Block, reg: Reg) -> SpillReason {
    let local: UseFacts = local_use_facts(block, reg);
    if local.loop_weighted > local.textual {
        SpillReason::LoopDepth
    } else {
        SpillReason::LiveAfterUse
    }
}

fn record(context: &mut Context<'_>, block: &Block, dest: Reg, reason: SpillReason) {
    if context.outcome.decisions.len() >= MAX_RECORDED_DECISIONS {
        return;
    }
    let uses: UseFacts = local_use_facts(block, dest);
    context.outcome.decisions.push(SpillDecision {
        dest,
        facts: SpillFacts {
            uses,
            reason: Some(reason),
        },
    });
}

fn stmt_at(block: &Block, index: usize) -> Option<&Stmt> {
    match block.get(index) {
        Some(Node::Stmt(stmt)) => Some(stmt),
        _ => None,
    }
}

const fn source_is_substitutable(src: &Source) -> bool {
    match src {
        Source::Reg(RegRef {
            width: Width::W64, ..
        })
        | Source::Imm(_)
        | Source::Lea { .. }
        | Source::Mem(_) => true,
        Source::Reg(_) => false,
    }
}

const fn site_accepts(site: UseSite, src: &Source) -> bool {
    match site {
        UseSite::Value => true,
        UseSite::Register => matches!(src, Source::Reg(_)),
        UseSite::Opaque => false,
    }
}

fn function_read_totals(body: &Block) -> BTreeMap<Reg, u32> {
    let mut totals: BTreeMap<Reg, u32> = BTreeMap::new();
    for reg in mentioned_registers(body) {
        totals.insert(reg, block_use_facts(body, reg, 0).textual);
    }
    totals
}

fn mentioned_registers(body: &Block) -> Vec<Reg> {
    let mut seen: Vec<Reg> = Vec::new();
    collect_assign_dests(body, &mut seen);
    seen
}

fn collect_assign_dests(block: &Block, out: &mut Vec<Reg>) {
    for node in block {
        match node {
            Node::Stmt(Stmt::Assign { dest, .. }) => {
                if !out.contains(&dest.reg) {
                    out.push(dest.reg);
                }
            }
            Node::If {
                then_body,
                else_body,
                ..
            } => {
                collect_assign_dests(then_body, out);
                if let Some(else_body) = else_body {
                    collect_assign_dests(else_body, out);
                }
            }
            Node::DoWhile { body, .. } | Node::While { body, .. } => {
                collect_assign_dests(body, out);
            }
            Node::Switch { cases, default, .. } => {
                for case in cases {
                    collect_assign_dests(&case.body, out);
                }
                collect_assign_dests(default, out);
            }
            Node::Stmt(_)
            | Node::CondSnapshot { .. }
            | Node::Break
            | Node::Continue
            | Node::BreakLoop(_)
            | Node::ContinueLoop(_)
            | Node::ResumeAt(_)
            | Node::OuterResume(_)
            | Node::Return
            | Node::Label(_)
            | Node::Goto(_) => {}
        }
    }
}

fn local_use_facts(block: &Block, reg: Reg) -> UseFacts {
    block_use_facts(block, reg, 0)
}

fn block_use_facts(block: &Block, reg: Reg, depth: u32) -> UseFacts {
    let mut facts: UseFacts = UseFacts::default();
    for node in block {
        node_use_facts(node, reg, depth, &mut facts);
    }
    facts
}

fn range_reads(block: &Block, from: usize, to: usize, reg: Reg) -> u32 {
    let upper: usize = to.min(block.len());
    let lower: usize = from.min(upper);
    let mut facts: UseFacts = UseFacts::default();
    for node in &block[lower..upper] {
        node_use_facts(node, reg, 0, &mut facts);
    }
    facts.textual
}

fn node_use_facts(node: &Node, reg: Reg, depth: u32, facts: &mut UseFacts) {
    let deeper: u32 = depth.saturating_add(1);
    match node {
        Node::Stmt(stmt) => observe(facts, reads(stmt, reg), depth),
        Node::If {
            cond,
            then_body,
            else_body,
        } => {
            observe(facts, cond_reads(cond, reg), depth);
            *facts = merge(*facts, block_use_facts(then_body, reg, depth));
            if let Some(else_body) = else_body {
                *facts = merge(*facts, block_use_facts(else_body, reg, depth));
            }
        }
        Node::DoWhile { body, cond } => {
            observe(facts, loop_cond_reads(cond, reg), deeper);
            *facts = merge(*facts, block_use_facts(body, reg, deeper));
        }
        Node::While { body, cond } => {
            if let Some(cond) = cond {
                observe(facts, loop_cond_reads(cond, reg), deeper);
            }
            *facts = merge(*facts, block_use_facts(body, reg, deeper));
        }
        Node::Switch {
            disc,
            cases,
            default,
        } => {
            observe(facts, u32::from(disc.reg == reg), depth);
            for case in cases {
                *facts = merge(*facts, block_use_facts(&case.body, reg, depth));
            }
            *facts = merge(*facts, block_use_facts(default, reg, depth));
        }
        Node::CondSnapshot { flags, .. } => observe(facts, flag_reads(flags, reg), depth),
        Node::ResumeAt(_) | Node::OuterResume(_) => observe(facts, 1, deeper),
        Node::Break
        | Node::Continue
        | Node::BreakLoop(_)
        | Node::ContinueLoop(_)
        | Node::Return
        | Node::Label(_)
        | Node::Goto(_) => {}
    }
}

fn observe(facts: &mut UseFacts, count: u32, depth: u32) {
    for _ in 0..count {
        *facts = facts.observe(depth);
    }
}

const fn merge(left: UseFacts, right: UseFacts) -> UseFacts {
    UseFacts {
        textual: left.textual.saturating_add(right.textual),
        loop_weighted: left.loop_weighted.saturating_add(right.loop_weighted),
    }
}

fn cond_reads(cond: &Cond, reg: Reg) -> u32 {
    let mut total: u32 = 0;
    cond.visit_leaves(&mut |_: CondKind, flags: &Flags| {
        total = total.saturating_add(flag_reads(flags, reg));
    });
    total
}

fn loop_cond_reads(cond: &LoopCond, reg: Reg) -> u32 {
    match cond {
        LoopCond::Direct { flags, .. } => flag_reads(flags, reg),
        LoopCond::Snapshot { .. } => 0,
    }
}

fn flag_reads(flags: &Flags, reg: Reg) -> u32 {
    match flags {
        Flags::Cmp { lhs, rhs } | Flags::Add { lhs, rhs } => {
            u32::from(lhs.reg == reg).saturating_add(source_reads(rhs, reg))
        }
        Flags::CmpMem { lhs, rhs } => mem_reads(lhs, reg).saturating_add(source_reads(rhs, reg)),
        Flags::Test { operand } | Flags::TestImm { operand, .. } => u32::from(operand.reg == reg),
        Flags::Sign { result } => u32::from(result.reg == reg),
        Flags::FpCmp { rhs, .. } => fp_operand_reads(rhs, reg),
        Flags::Snapshot { .. } => 0,
        Flags::CondCmp { prior, taken, .. } => {
            flag_reads(prior, reg).saturating_add(flag_reads(taken, reg))
        }
    }
}

fn source_reads(src: &Source, reg: Reg) -> u32 {
    match src {
        Source::Reg(r) => u32::from(r.reg == reg),
        Source::Imm(_) => 0,
        Source::Lea { base, index, .. } => u32::from(*base == Some(reg))
            .saturating_add(u32::from(index.is_some_and(|i: IndexOperand| i.reg == reg))),
        Source::Mem(mem) => mem_reads(mem, reg),
    }
}

fn mem_reads(mem: &MemRef, reg: Reg) -> u32 {
    u32::from(mem.base == Some(reg)).saturating_add(u32::from(
        mem.index.is_some_and(|i: IndexOperand| i.reg == reg),
    ))
}

fn ext_reads(src: &ExtSource, reg: Reg) -> u32 {
    match src {
        ExtSource::Reg(r) => u32::from(r.reg == reg),
        ExtSource::Mem(mem) => mem_reads(mem, reg),
    }
}

fn fp_operand_reads(operand: &FpOperand, reg: Reg) -> u32 {
    match operand {
        FpOperand::Mem(mem) => mem_reads(mem, reg),
        FpOperand::Xmm(_) | FpOperand::Const { .. } => 0,
    }
}

fn reads(stmt: &Stmt, reg: Reg) -> u32 {
    let count: usize = accesses(stmt, reg)
        .iter()
        .filter(|access: &&Access| matches!(access, Access::Read(_)))
        .count();
    u32::try_from(count).unwrap_or(u32::MAX)
}

fn sole_read_site(stmt: &Stmt, reg: Reg) -> Option<UseSite> {
    let sites: Vec<UseSite> = accesses(stmt, reg)
        .into_iter()
        .filter_map(|access: Access| match access {
            Access::Read(site) => Some(site),
            Access::Write => None,
        })
        .collect();
    match sites.as_slice() {
        [only] => Some(*only),
        _ => None,
    }
}

fn writes(stmt: &Stmt, reg: Reg) -> bool {
    accesses(stmt, reg)
        .iter()
        .any(|access: &Access| matches!(access, Access::Write))
}

fn push_reads(out: &mut Vec<Access>, count: u32, site: UseSite) {
    for _ in 0..count {
        out.push(Access::Read(site));
    }
}

fn narrow_dest_access(out: &mut Vec<Access>, dest: RegRef, reg: Reg) {
    if dest.reg != reg {
        return;
    }
    if dest.width != Width::W64 {
        out.push(Access::Read(UseSite::Opaque));
    }
    out.push(Access::Write);
}

const fn value_site(src: &Source) -> UseSite {
    match src {
        Source::Reg(_) => UseSite::Value,
        Source::Imm(_) | Source::Lea { .. } | Source::Mem(_) => UseSite::Opaque,
    }
}

fn accesses(stmt: &Stmt, reg: Reg) -> Vec<Access> {
    let mut out: Vec<Access> = Vec::new();
    match stmt {
        Stmt::Assign { dest, src } => {
            push_reads(&mut out, source_reads(src, reg), value_site(src));
            narrow_dest_access(&mut out, *dest, reg);
        }
        Stmt::BinAssign { dest, src, .. } => {
            push_reads(&mut out, source_reads(src, reg), value_site(src));
            if dest.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::UnAssign { dest, .. } => {
            if dest.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::Cond {
            dest, src, flags, ..
        } => {
            push_reads(&mut out, source_reads(src, reg), UseSite::Opaque);
            push_reads(&mut out, flag_reads(flags, reg), UseSite::Opaque);
            if dest.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::SetCc { dest, flags, .. } => {
            push_reads(&mut out, flag_reads(flags, reg), UseSite::Opaque);
            narrow_dest_access(&mut out, *dest, reg);
        }
        Stmt::Store { addr, src } => {
            push_reads(&mut out, mem_reads(addr, reg), UseSite::Opaque);
            push_reads(&mut out, source_reads(src, reg), value_site(src));
        }
        Stmt::MemRmw { addr, op } => {
            push_reads(&mut out, mem_reads(addr, reg), UseSite::Opaque);
            if let Some(src) = memrmw_source(op) {
                push_reads(&mut out, source_reads(src, reg), UseSite::Opaque);
            }
        }
        Stmt::Extend { dest, src, .. } | Stmt::MulImm { dest, src, .. } => {
            push_reads(&mut out, ext_reads(src, reg), UseSite::Opaque);
            narrow_dest_access(&mut out, *dest, reg);
        }
        Stmt::WideMul { src, .. } => {
            if src.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
            }
            if reg == Reg::Rax {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
            if reg == Reg::Rdx {
                out.push(Access::Write);
            }
        }
        Stmt::Divide { divisor, .. } => {
            if divisor.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
            }
            if reg == Reg::Rax || reg == Reg::Rdx {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::FpBin { lhs, rhs, .. } | Stmt::FpMinMax { lhs, rhs, .. } => {
            push_reads(&mut out, fp_operand_reads(lhs, reg), UseSite::Opaque);
            push_reads(&mut out, fp_operand_reads(rhs, reg), UseSite::Opaque);
        }
        Stmt::FpMov { src, .. }
        | Stmt::FpSqrt { src, .. }
        | Stmt::FpUnary { src, .. }
        | Stmt::FpRound { src, .. } => {
            push_reads(&mut out, fp_operand_reads(src, reg), UseSite::Opaque);
        }
        Stmt::FpStore { addr, .. } => {
            push_reads(&mut out, mem_reads(addr, reg), UseSite::Opaque);
        }
        Stmt::IntToFp { src, .. } | Stmt::GprToXmm { src, .. } => {
            if src.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
            }
        }
        Stmt::FpToInt { dest, .. }
        | Stmt::XmmToGpr { dest, .. }
        | Stmt::PackedToGpr { dest, .. } => narrow_dest_access(&mut out, *dest, reg),
        Stmt::FpConvert { .. } => {}
        Stmt::FpFma {
            mul_lhs,
            mul_rhs,
            addend,
            ..
        } => {
            push_reads(&mut out, fp_operand_reads(mul_lhs, reg), UseSite::Opaque);
            push_reads(&mut out, fp_operand_reads(mul_rhs, reg), UseSite::Opaque);
            push_reads(&mut out, fp_operand_reads(addend, reg), UseSite::Opaque);
        }
        Stmt::FpCsel {
            if_true,
            if_false,
            flags,
            ..
        } => {
            push_reads(&mut out, fp_operand_reads(if_true, reg), UseSite::Opaque);
            push_reads(&mut out, fp_operand_reads(if_false, reg), UseSite::Opaque);
            push_reads(&mut out, flag_reads(flags, reg), UseSite::Opaque);
        }
        Stmt::DoubleShift { dest, src, .. } => {
            if src.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
            }
            if dest.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::BlockMove { .. } => {
            if matches!(reg, Reg::Rsi | Reg::Rdi | Reg::Rcx) {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
        }
        Stmt::BlockFill { .. } => {
            if matches!(reg, Reg::Rdi | Reg::Rcx) {
                out.push(Access::Read(UseSite::Opaque));
                out.push(Access::Write);
            }
            if reg == Reg::Rax {
                out.push(Access::Read(UseSite::Opaque));
            }
        }
        Stmt::Call { args, .. } => {
            for arg in args {
                if *arg == reg {
                    out.push(Access::Read(UseSite::Register));
                }
            }
            if reg == Reg::Rax {
                out.push(Access::Write);
            }
        }
        Stmt::FlagSnapshot { flags, .. } => {
            push_reads(&mut out, flag_reads(flags, reg), UseSite::Opaque);
        }
        Stmt::Packed { op, .. } => {
            if let PackedOp::FromGpr { src } = op
                && src.reg == reg
            {
                out.push(Access::Read(UseSite::Opaque));
            }
        }
        Stmt::Vector(vec_stmt) => vector_accesses(vec_stmt, reg, &mut out),
    }
    out
}

const fn memrmw_source(op: &MemRmwOp) -> Option<&Source> {
    match op {
        MemRmwOp::Bin { src, .. } => Some(src),
        MemRmwOp::Un(_) => None,
    }
}

fn vector_accesses(stmt: &VecStmt, reg: Reg, out: &mut Vec<Access>) {
    match stmt {
        VecStmt::Load { addr, .. } | VecStmt::Store { addr, .. } => {
            push_reads(out, mem_reads(addr, reg), UseSite::Opaque);
        }
        VecStmt::Dup { src, .. } | VecStmt::LaneInsert { src, .. } => {
            if src.reg == reg {
                out.push(Access::Read(UseSite::Opaque));
            }
        }
        VecStmt::ExtractToGpr { dest, .. } => narrow_dest_access(out, *dest, reg),
        VecStmt::Bin { .. }
        | VecStmt::Compare { .. }
        | VecStmt::MoveImm { .. }
        | VecStmt::Reduce { .. }
        | VecStmt::WidenExtend { .. }
        | VecStmt::WidenAdd { .. } => {}
    }
}

fn first_barrier(
    block: &Block,
    from: usize,
    to: usize,
    src: &Source,
    dest: Reg,
) -> Option<InlineBarrier> {
    let loaded: Option<MemRef> = match src {
        Source::Mem(mem) => Some(*mem),
        Source::Reg(_) | Source::Imm(_) | Source::Lea { .. } => None,
    };
    let operands: Vec<Reg> = operand_regs(src);
    for index in from..to.min(block.len()) {
        let Some(stmt): Option<&Stmt> = stmt_at(block, index) else {
            return Some(InlineBarrier::Call);
        };
        if writes(stmt, dest) || operands.iter().any(|reg: &Reg| writes(stmt, *reg)) {
            return Some(InlineBarrier::OperandWrite);
        }
        if let Some(mem) = loaded
            && let Some(barrier) = memory_barrier(stmt, &mem)
        {
            return Some(barrier);
        }
    }
    None
}

fn operand_regs(src: &Source) -> Vec<Reg> {
    match src {
        Source::Reg(r) => vec![r.reg],
        Source::Imm(_) => Vec::new(),
        Source::Lea { base, index, .. } => base
            .iter()
            .copied()
            .chain(index.map(|i: IndexOperand| i.reg))
            .collect(),
        Source::Mem(mem) => mem
            .base
            .iter()
            .copied()
            .chain(mem.index.map(|i: IndexOperand| i.reg))
            .collect(),
    }
}

fn memory_barrier(stmt: &Stmt, loaded: &MemRef) -> Option<InlineBarrier> {
    match stmt {
        Stmt::Store { addr, .. } => may_alias(addr, loaded).then_some(InlineBarrier::Store),
        Stmt::MemRmw { addr, .. } => may_alias(addr, loaded).then_some(InlineBarrier::Atomic),
        Stmt::Call { .. } => Some(InlineBarrier::Call),
        Stmt::FpStore { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::Vector(VecStmt::Store { .. }) => Some(InlineBarrier::Store),
        Stmt::Assign { .. }
        | Stmt::BinAssign { .. }
        | Stmt::UnAssign { .. }
        | Stmt::Cond { .. }
        | Stmt::SetCc { .. }
        | Stmt::Extend { .. }
        | Stmt::MulImm { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpToInt { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Packed { .. }
        | Stmt::PackedToGpr { .. }
        | Stmt::Vector(
            VecStmt::Load { .. }
            | VecStmt::Bin { .. }
            | VecStmt::Dup { .. }
            | VecStmt::LaneInsert { .. }
            | VecStmt::Compare { .. }
            | VecStmt::MoveImm { .. }
            | VecStmt::Reduce { .. }
            | VecStmt::ExtractToGpr { .. }
            | VecStmt::WidenExtend { .. }
            | VecStmt::WidenAdd { .. },
        ) => None,
    }
}

fn substitute(stmt: &mut Stmt, reg: Reg, src: &Source) -> bool {
    match stmt {
        Stmt::Assign {
            src: target_src, ..
        }
        | Stmt::BinAssign {
            src: target_src, ..
        }
        | Stmt::Store {
            src: target_src, ..
        } => replace_source(target_src, reg, src),
        Stmt::Call { args, .. } => {
            let Source::Reg(replacement) = src else {
                return false;
            };
            let mut replaced: bool = false;
            for arg in args.iter_mut() {
                if *arg == reg {
                    *arg = replacement.reg;
                    replaced = true;
                }
            }
            replaced
        }
        Stmt::UnAssign { .. }
        | Stmt::Cond { .. }
        | Stmt::SetCc { .. }
        | Stmt::MemRmw { .. }
        | Stmt::Extend { .. }
        | Stmt::MulImm { .. }
        | Stmt::WideMul { .. }
        | Stmt::Divide { .. }
        | Stmt::FpBin { .. }
        | Stmt::FpMov { .. }
        | Stmt::FpStore { .. }
        | Stmt::IntToFp { .. }
        | Stmt::FpToInt { .. }
        | Stmt::FpConvert { .. }
        | Stmt::FpMinMax { .. }
        | Stmt::FpFma { .. }
        | Stmt::FpCsel { .. }
        | Stmt::FpSqrt { .. }
        | Stmt::FpUnary { .. }
        | Stmt::FpRound { .. }
        | Stmt::GprToXmm { .. }
        | Stmt::XmmToGpr { .. }
        | Stmt::DoubleShift { .. }
        | Stmt::BlockMove { .. }
        | Stmt::BlockFill { .. }
        | Stmt::FlagSnapshot { .. }
        | Stmt::Packed { .. }
        | Stmt::PackedToGpr { .. }
        | Stmt::Vector(_) => false,
    }
}

fn replace_source(target: &mut Source, reg: Reg, src: &Source) -> bool {
    match target {
        Source::Reg(existing) if existing.reg == reg && existing.width == Width::W64 => {
            *target = src.clone();
            true
        }
        Source::Reg(_) | Source::Imm(_) | Source::Lea { .. } | Source::Mem(_) => false,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests;
