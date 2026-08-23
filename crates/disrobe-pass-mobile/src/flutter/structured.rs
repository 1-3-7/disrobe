use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_cfg::{Flow, FlowError, FlowGraph};
use disrobe_nir::{
    HirCond, HirCondExpr, HirCondTest, HirExpr, HirFunction, HirStmt, NirBlock, NirFunction,
    NirInstr, NirOp, SourceLang, SourceRef, basic_blocks, structurize_function,
};

use super::aot_lift::{
    DartCheckKind, bcond, classify_guard, is_arm64_trap, subs_imm, subs_shifted_reg, tbz_tbnz,
};
use super::call_args::{DartCallArguments, recover_boolean_return, recover_call_arguments};
use super::disasm::{Arm64FlowKind, Arm64Function, Arm64Instruction};
use super::pool_table::DartPoolTable;

const ARM64_INSN_BYTES: u64 = 4;

const OPAQUE_ARGUMENTS: &str = "...";

const CBZ_CBNZ_MASK: u32 = 0x7E00_0000;

const CBZ_CBNZ_MATCH: u32 = 0x3400_0000;

const CBNZ_BIT: u32 = 0x0100_0000;

const COMPARE_LOOKBACK: usize = 8;

pub(crate) struct DartAbi<'a> {
    pub(crate) fn_start: u64,
    pub(crate) fn_end: u64,
    pub(crate) label: &'a str,
    pub(crate) arg_registers: u8,
    pub(crate) resolve: &'a dyn Fn(u64) -> Option<String>,
    pub(crate) pool: Option<&'a DartPoolTable>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct DartCallArgumentCounts {
    pub(crate) recovered_sites: usize,
    pub(crate) opaque_sites: usize,
    pub(crate) lifted_statements: usize,
    pub(crate) unlifted_statements: usize,
    pub(crate) recovered_conditions: usize,
    pub(crate) recovered_returns: usize,
    pub(crate) recovered_field_stores: usize,
}

const UNLIFTED_MARKER: &str = "unliftedArm64(";

pub(crate) struct DartStructuredBody {
    pub(crate) text: String,
    pub(crate) parameter_count: Option<u8>,
    pub(crate) lifted_statements: usize,
    pub(crate) unlifted_statements: usize,
}

#[must_use]
pub(crate) fn structure_dart_function(
    func: &Arm64Function,
    abi: &DartAbi<'_>,
    counts: &mut DartCallArgumentCounts,
) -> Option<DartStructuredBody> {
    if let Some((expression, parameter_count)) = recover_boolean_return(func, abi.pool) {
        return Some(DartStructuredBody {
            text: emit_boolean_return(abi, &expression, parameter_count),
            parameter_count: Some(parameter_count),
            lifted_statements: 0,
            unlifted_statements: 0,
        });
    }
    let nir: NirFunction = build_nir(func, abi, None)?;
    let blocks: Vec<NirBlock> = basic_blocks(&nir);
    if blocks.len() < 2 {
        return None;
    }
    let hir: HirFunction = structurize_function(&nir);
    if !hir.structured {
        return None;
    }
    if !round_trip_ok(&blocks, &hir) {
        return None;
    }
    let reachable: BTreeSet<u64> = reachable_from(&blocks);
    let tail_calls: BTreeSet<u64> = tail_call_addresses(&nir);
    let parameter_count: Option<u8> = abi
        .pool
        .and_then(|pool: &DartPoolTable| pool.function_parameter_count(abi.label));
    let arguments: DartCallArguments = recover_call_arguments(
        func,
        &blocks,
        &reachable,
        &tail_calls,
        abi.pool,
        parameter_count,
    );
    let baseline: String = emit_dart(&hir, abi, &reachable, &arguments, parameter_count);
    let text: String = match returned_expression_pass(func, abi, &arguments, &blocks) {
        Some(relabelled) => {
            let candidate: String =
                emit_dart(&relabelled, abi, &reachable, &arguments, parameter_count);
            if relabelled_only(&baseline, &candidate) {
                candidate
            } else {
                baseline
            }
        }
        None => baseline,
    };
    counts.recovered_sites = counts
        .recovered_sites
        .saturating_add(arguments.recovered_sites);
    counts.opaque_sites = counts.opaque_sites.saturating_add(arguments.opaque_sites);
    counts.lifted_statements = counts
        .lifted_statements
        .saturating_add(arguments.lifted_statements);
    counts.recovered_returns = counts
        .recovered_returns
        .saturating_add(rendered_return_expressions(&text));
    counts.recovered_conditions = counts
        .recovered_conditions
        .saturating_add(arguments.recovered_conditions());
    counts.recovered_field_stores = counts
        .recovered_field_stores
        .saturating_add(arguments.recovered_field_stores);
    let unlifted_statements: usize = text.matches(UNLIFTED_MARKER).count();
    counts.unlifted_statements = counts
        .unlifted_statements
        .saturating_add(unlifted_statements);
    Some(DartStructuredBody {
        text,
        parameter_count,
        lifted_statements: arguments.lifted_statements,
        unlifted_statements,
    })
}

fn emit_boolean_return(abi: &DartAbi<'_>, expression: &str, parameter_count: u8) -> String {
    let params: String = (0..parameter_count)
        .map(|index: u8| format!("arg{index}"))
        .collect::<Vec<String>>()
        .join(", ");
    format!("{}({params}) {{\n  return {expression};\n}}", abi.label)
}

fn returned_expression_pass(
    func: &Arm64Function,
    abi: &DartAbi<'_>,
    arguments: &DartCallArguments,
    blocks: &[NirBlock],
) -> Option<HirFunction> {
    if arguments.recovered_returns == 0 && arguments.recovered_conditions() == 0 {
        return None;
    }
    let nir: NirFunction = build_nir(func, abi, Some(arguments))?;
    let rebuilt: Vec<NirBlock> = basic_blocks(&nir);
    if !same_block_layout(&rebuilt, blocks) {
        return None;
    }
    let hir: HirFunction = structurize_function(&nir);
    (hir.structured && round_trip_ok(&rebuilt, &hir)).then_some(hir)
}

const OPAQUE_INVOCATION: &str = "(...)";

fn relabelled_only(before: &str, after: &str) -> bool {
    if before.matches(OPAQUE_INVOCATION).count() != after.matches(OPAQUE_INVOCATION).count() {
        return false;
    }
    if before.matches(UNLIFTED_MARKER).count() != after.matches(UNLIFTED_MARKER).count() {
        return false;
    }
    let structural = |line: &&str| {
        let trimmed: &str = line.trim_start();
        !(trimmed.starts_with("return") || trimmed.contains("if ("))
    };
    before
        .lines()
        .filter(structural)
        .eq(after.lines().filter(structural))
}

fn rendered_return_expressions(text: &str) -> usize {
    text.lines()
        .filter(|line: &&str| {
            let trimmed: &str = line.trim();
            trimmed.starts_with("return ") && trimmed != "return;"
        })
        .count()
}

fn same_block_layout(left: &[NirBlock], right: &[NirBlock]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(a, b): (&NirBlock, &NirBlock)| {
                a.start == b.start && a.end == b.end && a.successors == b.successors
            })
}

fn build_nir(
    func: &Arm64Function,
    abi: &DartAbi<'_>,
    returns: Option<&DartCallArguments>,
) -> Option<NirFunction> {
    let insns: &[Arm64Instruction] = &func.instructions;
    if insns.is_empty() {
        return None;
    }
    let counts: BTreeMap<u64, usize> = branch_target_counts(insns, abi);
    let mut lowered: Vec<NirInstr> = Vec::with_capacity(insns.len());
    for (i, insn) in insns.iter().enumerate() {
        let op: NirOp;
        let mnemonic: String;
        let mut operands: Vec<String> = Vec::new();
        match insn.flow {
            Arm64FlowKind::Return => {
                op = NirOp::Return;
                mnemonic = "ret".to_owned();
                if let Some(expression) = returns
                    .and_then(|found: &DartCallArguments| found.return_expression(insn.address))
                {
                    operands.push(expression.to_owned());
                }
            }
            Arm64FlowKind::DirectCall => {
                op = NirOp::Call { target: None };
                mnemonic = "call".to_owned();
                operands.push(call_display(insn.branch_target, abi));
            }
            Arm64FlowKind::IndirectCall => {
                op = NirOp::IndirectCall;
                mnemonic = "invoke".to_owned();
            }
            Arm64FlowKind::DirectBranch => {
                let target: Option<u64> = insn.branch_target;
                if in_function(target, abi) {
                    op = NirOp::Branch { target };
                    mnemonic = "b".to_owned();
                } else {
                    op = NirOp::TailCall { target };
                    mnemonic = "tail".to_owned();
                    operands.push(call_display(target, abi));
                }
            }
            Arm64FlowKind::ConditionalBranch => {
                let guard: Option<DartCheckKind> = classify_guard(insns, i);
                if droppable_guard(guard)
                    && safe_to_drop(insn.branch_target, i, insns, &counts, abi)
                {
                    op = NirOp::Nop;
                    mnemonic = String::new();
                } else {
                    let target: Option<u64> = insn.branch_target;
                    if !in_function(target, abi) {
                        return None;
                    }
                    op = NirOp::CondBranch { target };
                    mnemonic = recovered_condition_text(insn, returns)
                        .unwrap_or_else(|| condition_text(insns, i));
                }
            }
            Arm64FlowKind::IndirectBranch | Arm64FlowKind::DecodeError => {
                return None;
            }
            Arm64FlowKind::Sequential => {
                if is_arm64_trap(insn.bytes) {
                    op = NirOp::NoReturnCall { target: None };
                    mnemonic = "trap".to_owned();
                } else {
                    op = NirOp::Nop;
                    mnemonic = super::aot_lift::DartUnliftedArm64 {
                        address: insn.address,
                        bytes: insn.bytes,
                        text: insn.text.clone(),
                    }
                    .to_pseudo_dart();
                }
            }
        }
        let reads_memory: bool = arm64_reads_memory(&insn.text);
        let writes_memory: bool = arm64_writes_memory(&insn.text)
            || (insn.flow == Arm64FlowKind::Sequential
                && !arm64_sequential_is_foldable(&insn.text));
        lowered.push(NirInstr {
            address: insn.address,
            op,
            mnemonic,
            operands,
            reads_memory,
            writes_memory,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeArm, insn.address),
        });
    }
    Some(NirFunction {
        name: abi.label.to_owned(),
        address: abi.fn_start,
        end: abi.fn_end,
        is_export: false,
        instructions: lowered,
        source: SourceRef::new(SourceLang::NativeArm, abi.fn_start),
    })
}

fn arm64_reads_memory(text: &str) -> bool {
    let Some(mnemonic): Option<&str> = text.split_ascii_whitespace().next() else {
        return false;
    };
    mnemonic.starts_with("ld") || mnemonic.starts_with("cas") || mnemonic.starts_with("swp")
}

fn arm64_writes_memory(text: &str) -> bool {
    let Some(mnemonic): Option<&str> = text.split_ascii_whitespace().next() else {
        return false;
    };
    mnemonic.starts_with("st")
        || mnemonic.starts_with("cas")
        || mnemonic.starts_with("swp")
        || [
            "cpy", "ldadd", "ldclr", "ldeor", "ldset", "ldsmax", "ldsmin", "ldumax", "ldumin",
            "set",
        ]
        .iter()
        .any(|prefix: &&str| mnemonic.starts_with(prefix))
}

fn arm64_sequential_is_foldable(text: &str) -> bool {
    let Some(mnemonic): Option<&str> = text.split_ascii_whitespace().next() else {
        return false;
    };
    arm64_reads_memory(text)
        || [
            "adc", "add", "adr", "and", "asr", "aut", "bfi", "bfm", "bfx", "ccm", "cinc", "cinv",
            "cls", "clz", "cmn", "cmp", "cneg", "csel", "csinc", "csinv", "csneg", "eon", "eor",
            "extr", "f", "lsl", "lsr", "madd", "mneg", "mov", "mrs", "msub", "mul", "mvn", "neg",
            "ngc", "nop", "orn", "orr", "pac", "rbit", "rev", "ror", "sbc", "sbf", "scvt", "sdiv",
            "smadd", "smne", "smsub", "sub", "tst", "ubf", "ucvt", "udiv", "umadd", "umne",
            "umsub", "xpac",
        ]
        .iter()
        .any(|prefix: &&str| mnemonic.starts_with(prefix))
}

fn tail_call_addresses(nir: &NirFunction) -> BTreeSet<u64> {
    nir.instructions
        .iter()
        .filter(|instr: &&NirInstr| matches!(instr.op, NirOp::TailCall { .. }))
        .map(|instr: &NirInstr| instr.address)
        .collect::<BTreeSet<u64>>()
}

fn branch_target_counts(insns: &[Arm64Instruction], abi: &DartAbi<'_>) -> BTreeMap<u64, usize> {
    let mut counts: BTreeMap<u64, usize> = BTreeMap::new();
    for insn in insns {
        if matches!(
            insn.flow,
            Arm64FlowKind::ConditionalBranch | Arm64FlowKind::DirectBranch
        ) && in_function(insn.branch_target, abi)
            && let Some(target) = insn.branch_target
        {
            *counts.entry(target).or_default() += 1;
        }
    }
    counts
}

const fn droppable_guard(guard: Option<DartCheckKind>) -> bool {
    matches!(
        guard,
        Some(DartCheckKind::StackOverflow | DartCheckKind::NullCheck | DartCheckKind::BoundsCheck)
    )
}

fn safe_to_drop(
    target: Option<u64>,
    at: usize,
    insns: &[Arm64Instruction],
    counts: &BTreeMap<u64, usize>,
    abi: &DartAbi<'_>,
) -> bool {
    let Some(t): Option<u64> = target else {
        return true;
    };
    if !in_function(Some(t), abi) {
        return true;
    }
    if counts.get(&t).copied().unwrap_or(0) != 1 {
        return false;
    }
    predecessor_is_terminator(t, at, insns)
}

fn predecessor_is_terminator(target: u64, at: usize, insns: &[Arm64Instruction]) -> bool {
    let Some(prev_addr): Option<u64> = target.checked_sub(ARM64_INSN_BYTES) else {
        return false;
    };
    let mut index: usize = at;
    if insns.get(index).map(|i: &Arm64Instruction| i.address) != Some(prev_addr) {
        let Some(found): Option<usize> = insns
            .iter()
            .position(|i: &Arm64Instruction| i.address == prev_addr)
        else {
            return false;
        };
        index = found;
    }
    let Some(prev): Option<&Arm64Instruction> = insns.get(index) else {
        return false;
    };
    matches!(
        prev.flow,
        Arm64FlowKind::Return
            | Arm64FlowKind::DirectBranch
            | Arm64FlowKind::ConditionalBranch
            | Arm64FlowKind::IndirectBranch
    ) || is_arm64_trap(prev.bytes)
}

const fn in_function(target: Option<u64>, abi: &DartAbi<'_>) -> bool {
    match target {
        Some(t) => t >= abi.fn_start && t < abi.fn_end,
        None => false,
    }
}

fn call_display(target: Option<u64>, abi: &DartAbi<'_>) -> String {
    match target {
        Some(t) if t >= abi.fn_start && t < abi.fn_end => abi.label.to_owned(),
        Some(t) => (abi.resolve)(t).unwrap_or_else(|| format!("sub_{t:#x}")),
        None => "invoke".to_owned(),
    }
}

fn recovered_condition_text(
    insn: &Arm64Instruction,
    recovered: Option<&DartCallArguments>,
) -> Option<String> {
    let (left, right): (&str, &str) = recovered?.comparison(insn.address)?;
    let operator: &str = match bcond(insn.bytes) {
        Some(condition) => cond_operator(condition),
        None if insn.bytes & CBZ_CBNZ_MASK == CBZ_CBNZ_MATCH => {
            if insn.bytes & CBNZ_BIT == 0 {
                "=="
            } else {
                "!="
            }
        }
        None => return None,
    };
    Some(format!("{left} {operator} {right}"))
}

fn condition_text(insns: &[Arm64Instruction], at: usize) -> String {
    let raw: u32 = insns[at].bytes;
    if let Some(cond) = bcond(raw) {
        return flags_condition(insns, at, cond);
    }
    if raw & CBZ_CBNZ_MASK == CBZ_CBNZ_MATCH {
        let reg: u8 = (raw & 0x1F) as u8;
        let rel: &str = if raw & CBNZ_BIT != 0 { "!=" } else { "==" };
        return format!("x{reg} {rel} 0");
    }
    if let Some((rt, bit, is_tbnz)) = tbz_tbnz(raw) {
        let rel: &str = if is_tbnz { "!=" } else { "==" };
        return format!("(x{rt} & (1 << {bit})) {rel} 0");
    }
    format!("cond@{:#x}", insns[at].address)
}

fn flags_condition(insns: &[Arm64Instruction], at: usize, cond: u8) -> String {
    let op: &str = cond_operator(cond);
    let start: usize = at.saturating_sub(COMPARE_LOOKBACK);
    for prior in (start..at).rev() {
        let raw: u32 = insns[prior].bytes;
        if let Some((rd, rn, imm)) = subs_imm(raw)
            && rd == 31
        {
            return format!("x{rn} {op} {imm}");
        }
        if let Some((rd, rn, rm)) = subs_shifted_reg(raw)
            && rd == 31
        {
            return format!("x{rn} {op} x{rm}");
        }
    }
    format!("cond_{cond}@{:#x}", insns[at].address)
}

const fn cond_operator(cond: u8) -> &'static str {
    match cond {
        0 => "==",
        1 => "!=",
        2 | 10 => ">=",
        3 | 11 => "<",
        8 | 12 => ">",
        9 | 13 => "<=",
        _ => "?",
    }
}

fn reachable_from(blocks: &[NirBlock]) -> BTreeSet<u64> {
    let starts: BTreeSet<u64> = blocks.iter().map(|b: &NirBlock| b.start).collect();
    let by_start: BTreeMap<u64, &NirBlock> =
        blocks.iter().map(|b: &NirBlock| (b.start, b)).collect();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let Some(entry): Option<u64> = blocks.first().map(|b: &NirBlock| b.start) else {
        return seen;
    };
    let mut stack: Vec<u64> = vec![entry];
    while let Some(current) = stack.pop() {
        if !seen.insert(current) {
            continue;
        }
        if let Some(block) = by_start.get(&current) {
            for succ in &block.successors {
                if starts.contains(succ) {
                    stack.push(*succ);
                }
            }
        }
    }
    seen
}

fn round_trip_ok(blocks: &[NirBlock], hir: &HirFunction) -> bool {
    let reachable: BTreeSet<u64> = reachable_from(blocks);
    if reachable.is_empty() {
        return false;
    }
    let mut input_edges: BTreeSet<(u64, u64)> = BTreeSet::new();
    let starts: BTreeSet<u64> = blocks.iter().map(|b: &NirBlock| b.start).collect();
    for block in blocks {
        if !reachable.contains(&block.start) {
            continue;
        }
        for succ in &block.successors {
            if starts.contains(succ) {
                input_edges.insert((block.start, *succ));
            }
        }
    }
    let mut flattener: Flattener<'_> = Flattener::new(&reachable);
    flattener.link(&hir.body, None);
    if !flattener.valid || flattener.edges != input_edges {
        return false;
    }
    let hir_blocks: BTreeSet<u64> = hir.block_starts();
    if !reachable.iter().all(|b: &u64| hir_blocks.contains(b)) {
        return false;
    }
    let input_headers: BTreeSet<u64> = natural_loop_headers(blocks, &reachable);
    let mut hir_loops: BTreeSet<u64> = BTreeSet::new();
    collect_loop_labels(&hir.body, &mut hir_loops);
    input_headers == hir_loops
}

struct Flattener<'a> {
    reachable: &'a BTreeSet<u64>,
    edges: BTreeSet<(u64, u64)>,
    loops: Vec<(u64, Option<u64>)>,
    valid: bool,
}

impl<'a> Flattener<'a> {
    fn new(reachable: &'a BTreeSet<u64>) -> Self {
        Self {
            reachable,
            edges: BTreeSet::new(),
            loops: Vec::new(),
            valid: true,
        }
    }

    fn loop_follow(&self, label: u64) -> Option<u64> {
        self.loops
            .iter()
            .rev()
            .find(|(l, _f): &&(u64, Option<u64>)| *l == label)
            .and_then(|(_l, f): &(u64, Option<u64>)| *f)
    }

    fn link(&mut self, stmt: &HirStmt, cont: Option<u64>) -> Option<u64> {
        match stmt {
            HirStmt::Empty | HirStmt::Return { .. } => cont_of_terminal(stmt, cont),
            HirStmt::Break { label } => self.loop_follow(*label),
            HirStmt::Continue { label } => Some(*label),
            HirStmt::Leaf { block_start, .. } => {
                if !self.reachable.contains(block_start) {
                    return cont;
                }
                if let Some(next) = cont {
                    self.edges.insert((*block_start, next));
                }
                Some(*block_start)
            }
            HirStmt::Loop { label, body } => {
                self.loops.push((*label, cont));
                let entry: Option<u64> = self.link(body, Some(*label));
                self.loops.pop();
                entry.or(Some(*label))
            }
            HirStmt::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let then_target: Option<u64> = self.arm(then_branch, cont);
                let else_target: Option<u64> = self.arm(else_branch, cont);
                if then_target != cond.taken_target || else_target != cond.fallthrough_target {
                    self.valid = false;
                }
                self.link_condition(&cond.expression)
            }
            HirStmt::Seq { body } => self.link_seq(body, cont),
            HirStmt::Dispatch { .. } | HirStmt::GotoGraph { .. } => cont,
        }
    }

    fn link_seq(&mut self, items: &[HirStmt], cont: Option<u64>) -> Option<u64> {
        let Some((head, rest)): Option<(&HirStmt, &[HirStmt])> = items.split_first() else {
            return cont;
        };
        if let HirStmt::Leaf { block_start, .. } = head
            && self.reachable.contains(block_start)
        {
            let source: u64 = *block_start;
            return Some(self.link_branch_block(source, rest, cont));
        }
        if let HirStmt::Leaf { .. } = head {
            return self.link_seq(rest, cont);
        }
        let rest_entry: Option<u64> = self.link_seq(rest, cont);
        self.link(head, rest_entry).or(rest_entry)
    }

    fn link_branch_block(&mut self, source: u64, rest: &[HirStmt], cont: Option<u64>) -> u64 {
        match rest.first() {
            Some(condition @ HirStmt::If { .. }) => {
                let after: Option<u64> = self.link_seq(&rest[1..], cont);
                if let Some(condition_entry) = self.link(condition, after)
                    && condition_entry != source
                {
                    self.edges.insert((source, condition_entry));
                }
            }
            Some(HirStmt::Return { .. }) => {}
            Some(HirStmt::Break { label }) => {
                if let Some(f) = self.loop_follow(*label) {
                    self.edges.insert((source, f));
                }
            }
            Some(HirStmt::Continue { label }) => {
                self.edges.insert((source, *label));
            }
            _ => {
                let rest_entry: Option<u64> = self.link_seq(rest, cont);
                if let Some(next) = rest_entry {
                    self.edges.insert((source, next));
                }
            }
        }
        source
    }

    fn arm(&mut self, stmt: &HirStmt, cont: Option<u64>) -> Option<u64> {
        match stmt {
            HirStmt::Empty => cont,
            HirStmt::Break { label } => self.loop_follow(*label),
            HirStmt::Continue { label } => Some(*label),
            HirStmt::Return { .. } => None,
            other => self.link(other, cont),
        }
    }

    fn link_condition(&mut self, expression: &HirCondExpr) -> Option<u64> {
        let mut entry: Option<u64> = None;
        let mut pending: Vec<&HirCondExpr> = vec![expression];
        while let Some(current) = pending.pop() {
            match current {
                HirCondExpr::Test { test, .. } => {
                    entry.get_or_insert(test.block_start);
                    for target in [test.taken_target, test.fallthrough_target]
                        .into_iter()
                        .flatten()
                    {
                        if self.reachable.contains(&target) {
                            self.edges.insert((test.block_start, target));
                        }
                    }
                    for route in test.taken_route.iter().chain(&test.fallthrough_route) {
                        if self.reachable.contains(&route.successor) {
                            self.edges.insert((route.block_start, route.successor));
                        }
                    }
                }
                HirCondExpr::All { terms } | HirCondExpr::Any { terms } => {
                    pending.extend(terms.iter().rev());
                }
            }
        }
        entry
    }
}

fn cont_of_terminal(stmt: &HirStmt, cont: Option<u64>) -> Option<u64> {
    match stmt {
        HirStmt::Return { .. } => None,
        _ => cont,
    }
}

fn collect_loop_labels(stmt: &HirStmt, out: &mut BTreeSet<u64>) {
    match stmt {
        HirStmt::Loop { label, body } => {
            out.insert(*label);
            collect_loop_labels(body, out);
        }
        HirStmt::Seq { body } => {
            for child in body {
                collect_loop_labels(child, out);
            }
        }
        HirStmt::If {
            then_branch,
            else_branch,
            ..
        } => {
            collect_loop_labels(then_branch, out);
            collect_loop_labels(else_branch, out);
        }
        _ => {}
    }
}

fn natural_loop_headers(blocks: &[NirBlock], reachable: &BTreeSet<u64>) -> BTreeSet<u64> {
    let order: Vec<u64> = reachable.iter().copied().collect();
    if order.is_empty() {
        return BTreeSet::new();
    }
    let by_start: BTreeMap<u64, &NirBlock> =
        blocks.iter().map(|b: &NirBlock| (b.start, b)).collect();
    let entry: u64 = blocks
        .first()
        .map(|b: &NirBlock| b.start)
        .unwrap_or(order[0]);
    let entry: u64 = if reachable.contains(&entry) {
        entry
    } else {
        order[0]
    };
    let Ok(graph): Result<FlowGraph<u64>, FlowError> = FlowGraph::build(
        order.iter().copied(),
        entry,
        |start: u64, emit: &mut dyn FnMut(Flow<u64>)| {
            let Some(block): Option<&&NirBlock> = by_start.get(&start) else {
                emit(Flow::Exit);
                return;
            };
            let mut sinks: bool = true;
            for successor in &block.successors {
                if reachable.contains(successor) {
                    sinks = false;
                    emit(Flow::To(*successor));
                }
            }
            if sinks {
                emit(Flow::Exit);
            }
        },
    ) else {
        return BTreeSet::new();
    };
    graph
        .back_edges()
        .into_iter()
        .map(|(_, header): (u64, u64)| header)
        .collect()
}

fn emit_dart(
    hir: &HirFunction,
    abi: &DartAbi<'_>,
    reachable: &BTreeSet<u64>,
    arguments: &DartCallArguments,
    parameter_count: Option<u8>,
) -> String {
    let inferred: usize = usize::from(abi.arg_registers).max(
        arguments
            .max_parameter
            .map_or(0, |highest: usize| highest.saturating_add(1)),
    );
    let declared: usize = parameter_count.map_or(inferred, usize::from);
    let params: String = (0..declared)
        .map(|i: usize| format!("arg{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut out: String = String::new();
    let _ = writeln!(out, "{}({params}) {{", abi.label);
    let mut body: String = String::new();
    emit_stmt(&hir.body, 1, reachable, arguments, &mut body);
    if body.trim().is_empty() {
        let _ = writeln!(out, "  return;");
    } else {
        out.push_str(&body);
    }
    out.push('}');
    out
}

fn emit_stmt(
    stmt: &HirStmt,
    indent: usize,
    reachable: &BTreeSet<u64>,
    arguments: &DartCallArguments,
    out: &mut String,
) {
    match stmt {
        HirStmt::Seq { body } => {
            for child in body {
                emit_stmt(child, indent, reachable, arguments, out);
            }
        }
        HirStmt::Leaf { block_start, stmts } => {
            if !reachable.contains(block_start) {
                return;
            }
            for leaf in stmts {
                if let Some(line) = render_leaf(&leaf.instr, arguments) {
                    push_indented(out, indent, &line);
                }
            }
        }
        HirStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            let root: Option<&HirCondTest> = first_condition_test(&cond.expression);
            if let Some(test) = root {
                emit_condition_prelude(test, indent, arguments, out);
            }
            push_indented(
                out,
                indent,
                &format!(
                    "if ({}) {{",
                    condition_of(
                        cond,
                        root.map(|test: &HirCondTest| test.block_start),
                        indent,
                        arguments,
                    )
                ),
            );
            emit_stmt(then_branch, indent + 1, reachable, arguments, out);
            if has_content(else_branch, reachable, arguments) {
                push_indented(out, indent, "} else {");
                emit_stmt(else_branch, indent + 1, reachable, arguments, out);
            }
            push_indented(out, indent, "}");
        }
        HirStmt::Loop { body, .. } => {
            push_indented(out, indent, "while (true) {");
            emit_stmt(body, indent + 1, reachable, arguments, out);
            push_indented(out, indent, "}");
        }
        HirStmt::Break { .. } => push_indented(out, indent, "break;"),
        HirStmt::Continue { .. } => push_indented(out, indent, "continue;"),
        HirStmt::Return { value } => {
            let line: String = match value.as_ref().and_then(return_expression_text) {
                Some(text) => format!("return {text};"),
                None => "return;".to_owned(),
            };
            push_indented(out, indent, &line);
        }
        HirStmt::Empty | HirStmt::Dispatch { .. } | HirStmt::GotoGraph { .. } => {}
    }
}

fn return_expression_text(value: &HirExpr) -> Option<String> {
    let text: String = match value {
        HirExpr::Const { value } => value.render(),
        HirExpr::Unknown { text } => text.clone(),
        HirExpr::Var { name } => name.clone(),
        HirExpr::Mem { cell, width } => match width {
            Some(bits) => format!("{cell}:u{bits}"),
            None => cell.clone(),
        },
        HirExpr::Unary { .. } | HirExpr::Binary { .. } | HirExpr::Call { .. } => return None,
    };
    (!text.is_empty()).then_some(text)
}

fn first_condition_test(expression: &HirCondExpr) -> Option<&HirCondTest> {
    match expression {
        HirCondExpr::Test { test, .. } => Some(test),
        HirCondExpr::All { terms } | HirCondExpr::Any { terms } => {
            terms.iter().find_map(first_condition_test)
        }
    }
}

fn condition_prelude(test: &HirCondTest) -> &[disrobe_nir::HirLeafStmt] {
    match test.stmts.split_last() {
        Some((last, preceding)) if last.instr.class() == disrobe_nir::NirClass::ConditionalJump => {
            preceding
        }
        _ => &test.stmts,
    }
}

fn emit_condition_prelude(
    test: &HirCondTest,
    indent: usize,
    arguments: &DartCallArguments,
    out: &mut String,
) {
    for statement in condition_prelude(test) {
        if let Some(line) = render_leaf(&statement.instr, arguments) {
            push_indented(out, indent, &line);
        }
    }
}

fn condition_of(
    cond: &HirCond,
    root_block: Option<u64>,
    indent: usize,
    arguments: &DartCallArguments,
) -> String {
    condition_expression_of(&cond.expression, root_block, indent, arguments, 0)
}

fn condition_expression_of(
    expression: &HirCondExpr,
    root_block: Option<u64>,
    indent: usize,
    arguments: &DartCallArguments,
    parent_precedence: u8,
) -> String {
    let precedence: u8 = match expression {
        HirCondExpr::Test { .. } => 3,
        HirCondExpr::All { .. } => 2,
        HirCondExpr::Any { .. } => 1,
    };
    let rendered: String = match expression {
        HirCondExpr::Test { test, negated } => {
            let predicate: String = if test.mnemonic.is_empty() {
                format!("cond@{:#x}", test.at)
            } else {
                test.mnemonic.clone()
            };
            let prelude: &[disrobe_nir::HirLeafStmt] = condition_prelude(test);
            let expression: String = if prelude.is_empty() || root_block == Some(test.block_start) {
                predicate
            } else {
                let mut closure: String = String::from("(() {\n");
                for statement in prelude {
                    if let Some(line) = render_leaf(&statement.instr, arguments) {
                        push_indented(&mut closure, indent.saturating_add(1), &line);
                    }
                }
                push_indented(
                    &mut closure,
                    indent.saturating_add(1),
                    &format!("return {predicate};"),
                );
                for _ in 0..indent {
                    closure.push_str("  ");
                }
                closure.push_str("})()");
                closure
            };
            if *negated {
                format!("!({expression})")
            } else {
                expression
            }
        }
        HirCondExpr::All { terms } | HirCondExpr::Any { terms } => {
            let separator: &str = if matches!(expression, HirCondExpr::All { .. }) {
                " && "
            } else {
                " || "
            };
            if terms.is_empty() {
                "condition".to_owned()
            } else {
                terms
                    .iter()
                    .map(|term: &HirCondExpr| {
                        condition_expression_of(term, root_block, indent, arguments, precedence)
                    })
                    .collect::<Vec<String>>()
                    .join(separator)
            }
        }
    };
    if precedence < parent_precedence {
        format!("({rendered})")
    } else {
        rendered
    }
}

fn has_content(stmt: &HirStmt, reachable: &BTreeSet<u64>, arguments: &DartCallArguments) -> bool {
    match stmt {
        HirStmt::Leaf { block_start, stmts } => {
            reachable.contains(block_start)
                && stmts
                    .iter()
                    .any(|leaf| render_leaf(&leaf.instr, arguments).is_some())
        }
        HirStmt::Seq { body } => body
            .iter()
            .any(|s: &HirStmt| has_content(s, reachable, arguments)),
        HirStmt::If { .. }
        | HirStmt::Loop { .. }
        | HirStmt::Break { .. }
        | HirStmt::Continue { .. }
        | HirStmt::Return { .. } => true,
        HirStmt::Empty | HirStmt::Dispatch { .. } | HirStmt::GotoGraph { .. } => false,
    }
}

fn render_leaf(instr: &NirInstr, arguments: &DartCallArguments) -> Option<String> {
    match &instr.op {
        NirOp::Call { .. } => {
            let callee: &str = instr
                .operands
                .first()
                .map_or("sub", |s: &String| s.as_str());
            Some(render_invocation(callee, instr.address, arguments))
        }
        NirOp::IndirectCall => Some(render_invocation("invoke", instr.address, arguments)),
        NirOp::TailCall { .. } => {
            let callee: &str = instr
                .operands
                .first()
                .map_or("sub", |s: &String| s.as_str());
            let list: String = arguments
                .arguments(instr.address)
                .map_or_else(|| OPAQUE_ARGUMENTS.to_owned(), |values| values.join(", "));
            Some(format!("return {callee}({list});"))
        }
        NirOp::NoReturnCall { .. } if instr.mnemonic == "trap" => Some("trap();".to_owned()),
        NirOp::Nop if !instr.mnemonic.is_empty() => {
            if let Some(store) = arguments.field_store(instr.address) {
                return Some(store.to_owned());
            }
            if let Some(definition) = arguments.definition(instr.address) {
                return Some(definition.to_owned());
            }
            if arguments.is_bookkeeping(instr.address) {
                return None;
            }
            Some(instr.mnemonic.clone())
        }
        _ => None,
    }
}

fn render_invocation(callee: &str, address: u64, arguments: &DartCallArguments) -> String {
    let list: String = arguments
        .arguments(address)
        .map_or_else(|| OPAQUE_ARGUMENTS.to_owned(), |values| values.join(", "));
    match arguments.result_binding(address) {
        Some(index) => format!("var v{index} = {callee}({list});"),
        None => format!("{callee}({list});"),
    }
}

fn push_indented(out: &mut String, indent: usize, line: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(line);
    out.push('\n');
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use disrobe_nir::HirStmt;

    use super::*;
    use crate::flutter::disasm::disassemble_range;

    fn words(ws: &[u32]) -> Vec<u8> {
        let mut v: Vec<u8> = Vec::with_capacity(ws.len() * 4);
        for w in ws {
            v.extend_from_slice(&w.to_le_bytes());
        }
        v
    }

    fn ret() -> u32 {
        0xD65F_03C0
    }

    fn cmp_imm(rn: u32, imm: u32) -> u32 {
        0xF100_0000 | (imm << 10) | (rn << 5) | 31
    }

    fn bcc(cond: u32, from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x5400_0000 | (((imm as u32) & 0x7_FFFF) << 5) | cond
    }

    fn b(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x1400_0000 | ((imm as u32) & 0x03FF_FFFF)
    }

    fn no_names(_t: u64) -> Option<String> {
        None
    }

    fn abi<'a>(func: &Arm64Function, resolve: &'a dyn Fn(u64) -> Option<String>) -> DartAbi<'a> {
        let start: u64 = func.instructions.first().map_or(0, |i| i.address);
        let end: u64 = func
            .instructions
            .last()
            .map_or(start, |i| i.address + ARM64_INSN_BYTES);
        DartAbi {
            fn_start: start,
            fn_end: end,
            label: "probe",
            arg_registers: 1,
            resolve,
            pool: None,
        }
    }

    fn structure(func: &Arm64Function, abi: &DartAbi<'_>) -> Option<String> {
        let mut counts: DartCallArgumentCounts = DartCallArgumentCounts::default();
        structure_dart_function(func, abi, &mut counts)
            .map(|structured: DartStructuredBody| structured.text)
    }

    fn movz_imm(rd: u32, imm: u32) -> u32 {
        0xD280_0000 | (imm << 5) | rd
    }

    fn mov_from(rd: u32, rm: u32) -> u32 {
        0xAA00_03E0 | (rm << 16) | rd
    }

    fn bl(from: u64, to: u64) -> u32 {
        let imm: i64 = ((to as i64) - (from as i64)) >> 2;
        0x9400_0000 | ((imm as u32) & 0x03FF_FFFF)
    }

    fn str_stack(rt: u32, byte_offset: u32) -> u32 {
        0xF900_0000 | ((byte_offset / 8) << 10) | (15 << 5) | rt
    }

    fn ldr_pool(rt: u32, byte_offset: u32) -> u32 {
        0xF940_0000 | ((byte_offset / 8) << 10) | (27 << 5) | rt
    }

    fn ldr_unsigned(rt: u32, rn: u32) -> u32 {
        0xF940_0000 | (rn << 5) | rt
    }

    fn str_unsigned(rt: u32, rn: u32) -> u32 {
        0xF900_0000 | (rn << 5) | rt
    }

    fn blr(reg: u32) -> u32 {
        0xD63F_0000 | (reg << 5)
    }

    #[test]
    fn argument_set_in_both_arms_renders_as_the_placeholder() {
        let base: u64 = 0x5000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 0),
            bcc(0, base + 0x4, base + 0x10),
            movz_imm(1, 7),
            b(base + 0xC, base + 0x14),
            movz_imm(1, 9),
            mov_from(2, 22),
            bl(base + 0x18, base + 0x100),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("merge".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("(?, null);"),
            "an argument register written on both sides of a merge must render as the placeholder, never one arm's value, got:\n{rendered}"
        );
        assert!(
            !rendered.contains("(7,") && !rendered.contains("(9,"),
            "no branch-local value may leak through the merge, got:\n{rendered}"
        );
    }

    #[test]
    fn dart_argument_registers_are_read_in_the_engine_order() {
        let base: u64 = 0x7000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x2C),
            movz_imm(1, 11),
            movz_imm(2, 22),
            movz_imm(3, 33),
            movz_imm(4, 99),
            movz_imm(5, 55),
            movz_imm(6, 66),
            movz_imm(7, 77),
            bl(base + 0x20, base + 0x400),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("order".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("(11, 22, 33, 55, 66, 77);"),
            "the Dart argument sequence is R1 R2 R3 R5 R6 R7; R4 carries the arguments descriptor and never an argument, got:\n{rendered}"
        );
        let invocation: &str = rendered
            .lines()
            .find(|line: &&str| line.contains("sub_0x"))
            .expect("the call must render");
        assert!(
            !invocation.contains("99"),
            "a value parked in R4 must never enter the argument list, got:\n{rendered}"
        );
    }

    #[test]
    fn stack_slots_extend_the_argument_list_past_the_register_file() {
        let base: u64 = 0x7400;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x30),
            movz_imm(9, 88),
            str_stack(9, 0),
            movz_imm(1, 11),
            movz_imm(2, 22),
            movz_imm(3, 33),
            movz_imm(5, 55),
            movz_imm(6, 66),
            movz_imm(7, 77),
            bl(base + 0x28, base + 0x500),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("spill".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("(11, 22, 33, 55, 66, 77, 88);"),
            "an argument written to a Dart stack slot must extend the list past the register file, got:\n{rendered}"
        );
    }

    #[test]
    fn a_non_contiguous_stack_area_yields_no_stack_arguments() {
        let base: u64 = 0x7800;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x1C),
            movz_imm(9, 88),
            str_stack(9, 0x10),
            movz_imm(1, 11),
            bl(base + 0x14, base + 0x600),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("gap".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("(11);"),
            "a store that does not start the outgoing area at slot zero must not become an argument, got:\n{rendered}"
        );
        let invocation: &str = rendered
            .lines()
            .find(|line: &&str| line.contains("sub_0x"))
            .expect("the call must render");
        assert!(
            !invocation.contains("88"),
            "a non-contiguous stack store must not inflate the argument count, got:\n{rendered}"
        );
    }

    #[test]
    fn a_tail_call_renders_its_recovered_arguments() {
        let base: u64 = 0x7C00;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x14),
            movz_imm(2, 42),
            b(base + 0xC, base + 0x9000),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("tail".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("return sub_0x10c00(arg0, 42);"),
            "a tail call leaves the function and must render its recovered arguments, got:\n{rendered}"
        );
    }

    #[test]
    fn an_instance_dispatch_selector_is_not_an_argument() {
        let base: u64 = 0x8000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x18),
            movz_imm(1, 11),
            ldr_pool(5, 0x40),
            blr(9),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("dispatch".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("invoke(11);"),
            "an instance dispatch loads its selector into R5 from the pool; that selector is not an argument, got:\n{rendered}"
        );
    }

    #[test]
    fn straight_line_argument_setup_is_recovered() {
        let base: u64 = 0x6000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 1),
            bcc(0, base + 0x4, base + 0x18),
            movz_imm(1, 7),
            mov_from(2, 22),
            bl(base + 0x10, base + 0x200),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("straight".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(
            rendered.contains("(7, null);"),
            "a single-predecessor argument setup must recover both argument registers, got:\n{rendered}"
        );
    }

    #[test]
    fn if_else_diamond_structures_and_round_trips() {
        let base: u64 = 0x1000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 2),
            bcc(10, base + 0x4, base + 0x10),
            cmp_imm(1, 0),
            ret(),
            cmp_imm(2, 0),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("probe".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(rendered.contains("if (x0 >= 2)"), "got:\n{rendered}");
        assert!(rendered.contains('}'), "got:\n{rendered}");
    }

    #[test]
    fn compound_condition_emits_a_lazy_guarded_load_with_exact_grouping() {
        let base: u64 = 0x9000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 0),
            bcc(0, base + 0x4, base + 0x1C),
            cmp_imm(1, 0),
            bcc(1, base + 0xC, base + 0x20),
            ldr_unsigned(2, 3),
            cmp_imm(2, 0),
            bcc(1, base + 0x18, base + 0x20),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("compound".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(rendered.contains("&& ("), "got:\n{rendered}");
        assert!(rendered.contains(" || "), "got:\n{rendered}");
        assert!(rendered.contains("!("), "got:\n{rendered}");
        assert!(rendered.contains("(() {"), "got:\n{rendered}");
        assert_eq!(
            rendered.matches("arg2.field@0x0").count(),
            1,
            "the guarded load must occur exactly once inside its lazy closure:\n{rendered}",
        );
        let condition: usize = rendered.find("if (").expect("compound condition");
        let closure: usize = rendered.find("(() {").expect("lazy closure");
        let load: usize = rendered.find("arg2.field@0x0").expect("guarded load");
        assert!(condition < closure && closure < load, "got:\n{rendered}");
    }

    #[test]
    fn compound_condition_refuses_a_guarded_store() {
        let base: u64 = 0x9400;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 0),
            bcc(0, base + 0x4, base + 0x18),
            str_unsigned(2, 3),
            cmp_imm(1, 0),
            bcc(1, base + 0x10, base + 0x1C),
            ret(),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("store".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(!rendered.contains("&&"), "got:\n{rendered}");
        assert!(!rendered.contains("(() {"), "got:\n{rendered}");
    }

    #[test]
    fn compound_condition_refuses_a_guarded_supervisor_call() {
        let base: u64 = 0x9800;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 0),
            bcc(0, base + 0x4, base + 0x18),
            0xD400_0001,
            cmp_imm(1, 0),
            bcc(1, base + 0x10, base + 0x1C),
            ret(),
            ret(),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("svc".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let rendered: String = structure(&func, &abi(&func, resolve)).expect("must structure");
        assert!(!rendered.contains("&&"), "got:\n{rendered}");
        assert!(!rendered.contains("(() {"), "got:\n{rendered}");
    }

    #[test]
    fn gate_accepts_faithful_structure_and_rejects_tampered() {
        let base: u64 = 0x2000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 2),
            bcc(10, base + 0x4, base + 0x10),
            cmp_imm(1, 0),
            ret(),
            cmp_imm(2, 0),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("probe".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let nir: NirFunction = build_nir(&func, &abi(&func, resolve), None).expect("nir");
        let blocks: Vec<NirBlock> = basic_blocks(&nir);
        let hir: HirFunction = structurize_function(&nir);
        assert!(hir.structured);
        assert!(
            round_trip_ok(&blocks, &hir),
            "the faithful structurer output must pass the round-trip gate"
        );

        let tampered: HirFunction = tamper_first_if(&hir);
        assert!(
            !round_trip_ok(&blocks, &tampered),
            "a structure whose branch targets a wrong block must be rejected"
        );
    }

    fn tamper_first_if(hir: &HirFunction) -> HirFunction {
        let mut clone: HirFunction = hir.clone();
        clone.body = rewrite_if(&clone.body);
        clone
    }

    fn rewrite_if(stmt: &HirStmt) -> HirStmt {
        match stmt {
            HirStmt::Seq { body } => HirStmt::Seq {
                body: body.iter().map(rewrite_if).collect(),
            },
            HirStmt::If {
                cond, else_branch, ..
            } => {
                let bogus: HirStmt = HirStmt::Leaf {
                    block_start: 0xDEAD_BEEF,
                    stmts: Vec::new(),
                };
                HirStmt::If {
                    cond: cond.clone(),
                    then_branch: Box::new(bogus),
                    else_branch: else_branch.clone(),
                }
            }
            other => other.clone(),
        }
    }

    #[test]
    fn indirect_branch_falls_back_to_none() {
        let base: u64 = 0x3000;
        let bytes: Vec<u8> = words(&[cmp_imm(0, 1), 0xD61F_0000, ret()]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("probe".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        assert!(
            structure(&func, &abi(&func, resolve)).is_none(),
            "an indirect (computed) branch is not soundly structurable and must fall back"
        );
    }

    #[test]
    fn reducible_loop_structures_with_matching_header() {
        let base: u64 = 0x4000;
        let bytes: Vec<u8> = words(&[
            cmp_imm(0, 0),
            cmp_imm(1, 0),
            bcc(0, base + 0x8, base + 0x14),
            cmp_imm(2, 0),
            b(base + 0x10, base + 0x4),
            ret(),
        ]);
        let func: Arm64Function =
            disassemble_range(&bytes, base, 0, bytes.len(), Some("loop".to_owned()));
        let resolve: &dyn Fn(u64) -> Option<String> = &no_names;
        let nir: NirFunction = build_nir(&func, &abi(&func, resolve), None).expect("nir");
        let blocks: Vec<NirBlock> = basic_blocks(&nir);
        let hir: HirFunction = structurize_function(&nir);
        if hir.structured {
            assert!(
                round_trip_ok(&blocks, &hir),
                "a structured reducible loop must pass the gate"
            );
        }
    }
}
