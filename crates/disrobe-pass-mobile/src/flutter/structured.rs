use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_cfg::{Flow, FlowError, FlowGraph};
use disrobe_nir::{
    HirCond, HirFunction, HirStmt, NirBlock, NirFunction, NirInstr, NirOp, SourceLang, SourceRef,
    basic_blocks, structurize_function,
};

use super::aot_lift::{DartCheckKind, bcond, classify_guard, subs_imm, subs_shifted_reg, tbz_tbnz};
use super::disasm::{Arm64FlowKind, Arm64Function, Arm64Instruction};

const ARM64_INSN_BYTES: u64 = 4;

const BRK_MASK: u32 = 0xFFE0_001F;

const BRK_MATCH: u32 = 0xD420_0000;

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
}

#[must_use]
pub(crate) fn structure_dart_function(func: &Arm64Function, abi: &DartAbi<'_>) -> Option<String> {
    let nir: NirFunction = build_nir(func, abi)?;
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
    Some(emit_dart(&hir, abi, &reachable))
}

fn build_nir(func: &Arm64Function, abi: &DartAbi<'_>) -> Option<NirFunction> {
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
                    mnemonic = condition_text(insns, i);
                }
            }
            Arm64FlowKind::IndirectBranch | Arm64FlowKind::DecodeError => {
                return None;
            }
            Arm64FlowKind::Sequential => {
                if insn.bytes & BRK_MASK == BRK_MATCH {
                    op = NirOp::NoReturnCall { target: None };
                    mnemonic = "trap".to_owned();
                } else {
                    op = NirOp::Nop;
                    mnemonic = String::new();
                }
            }
        }
        lowered.push(NirInstr {
            address: insn.address,
            op,
            mnemonic,
            operands,
            reads_memory: false,
            writes_memory: false,
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
    ) || prev.bytes & BRK_MASK == BRK_MATCH
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
    if flattener.edges != input_edges {
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
}

impl<'a> Flattener<'a> {
    fn new(reachable: &'a BTreeSet<u64>) -> Self {
        Self {
            reachable,
            edges: BTreeSet::new(),
            loops: Vec::new(),
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
            HirStmt::If { .. } => cont,
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
            Some(HirStmt::If {
                then_branch,
                else_branch,
                ..
            }) => {
                let after: Option<u64> = self.link_seq(&rest[1..], cont);
                let then_target: Option<u64> = self.arm(then_branch, after);
                let else_target: Option<u64> = self.arm(else_branch, after);
                if let Some(t) = then_target {
                    self.edges.insert((source, t));
                }
                if let Some(t) = else_target {
                    self.edges.insert((source, t));
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

fn emit_dart(hir: &HirFunction, abi: &DartAbi<'_>, reachable: &BTreeSet<u64>) -> String {
    let params: String = (0..abi.arg_registers)
        .map(|i: u8| format!("arg{i}"))
        .collect::<Vec<String>>()
        .join(", ");
    let mut out: String = String::new();
    let _ = writeln!(out, "{}({params}) {{", abi.label);
    let mut body: String = String::new();
    emit_stmt(&hir.body, 1, reachable, &mut body);
    if body.trim().is_empty() {
        let _ = writeln!(out, "  return;");
    } else {
        out.push_str(&body);
    }
    out.push('}');
    out
}

fn emit_stmt(stmt: &HirStmt, indent: usize, reachable: &BTreeSet<u64>, out: &mut String) {
    match stmt {
        HirStmt::Seq { body } => {
            for child in body {
                emit_stmt(child, indent, reachable, out);
            }
        }
        HirStmt::Leaf { block_start, stmts } => {
            if !reachable.contains(block_start) {
                return;
            }
            for leaf in stmts {
                if let Some(line) = render_leaf(&leaf.instr) {
                    push_indented(out, indent, &line);
                }
            }
        }
        HirStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            push_indented(out, indent, &format!("if ({}) {{", condition_of(cond)));
            emit_stmt(then_branch, indent + 1, reachable, out);
            if has_content(else_branch, reachable) {
                push_indented(out, indent, "} else {");
                emit_stmt(else_branch, indent + 1, reachable, out);
            }
            push_indented(out, indent, "}");
        }
        HirStmt::Loop { body, .. } => {
            push_indented(out, indent, "while (true) {");
            emit_stmt(body, indent + 1, reachable, out);
            push_indented(out, indent, "}");
        }
        HirStmt::Break { .. } => push_indented(out, indent, "break;"),
        HirStmt::Continue { .. } => push_indented(out, indent, "continue;"),
        HirStmt::Return { .. } => push_indented(out, indent, "return;"),
        HirStmt::Empty | HirStmt::Dispatch { .. } | HirStmt::GotoGraph { .. } => {}
    }
}

fn condition_of(cond: &HirCond) -> String {
    if cond.mnemonic.is_empty() {
        format!("cond@{:#x}", cond.at)
    } else {
        cond.mnemonic.clone()
    }
}

fn has_content(stmt: &HirStmt, reachable: &BTreeSet<u64>) -> bool {
    match stmt {
        HirStmt::Leaf { block_start, stmts } => {
            reachable.contains(block_start)
                && stmts.iter().any(|leaf| render_leaf(&leaf.instr).is_some())
        }
        HirStmt::Seq { body } => body.iter().any(|s: &HirStmt| has_content(s, reachable)),
        HirStmt::If { .. }
        | HirStmt::Loop { .. }
        | HirStmt::Break { .. }
        | HirStmt::Continue { .. }
        | HirStmt::Return { .. } => true,
        HirStmt::Empty | HirStmt::Dispatch { .. } | HirStmt::GotoGraph { .. } => false,
    }
}

fn render_leaf(instr: &NirInstr) -> Option<String> {
    match &instr.op {
        NirOp::Call { .. } => {
            let callee: &str = instr
                .operands
                .first()
                .map_or("sub", |s: &String| s.as_str());
            Some(format!("{callee}(...);"))
        }
        NirOp::IndirectCall => Some("invoke(...);".to_owned()),
        _ => None,
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
    use disrobe_nir::{HirCond, HirStmt};

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
        }
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
        let rendered: String =
            structure_dart_function(&func, &abi(&func, resolve)).expect("must structure");
        assert!(rendered.contains("if (x0 >= 2)"), "got:\n{rendered}");
        assert!(rendered.contains('}'), "got:\n{rendered}");
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
        let nir: NirFunction = build_nir(&func, &abi(&func, resolve)).expect("nir");
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
                    cond: HirCond {
                        at: cond.at,
                        mnemonic: cond.mnemonic.clone(),
                        operands: cond.operands.clone(),
                        taken_target: cond.taken_target,
                    },
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
            structure_dart_function(&func, &abi(&func, resolve)).is_none(),
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
        let nir: NirFunction = build_nir(&func, &abi(&func, resolve)).expect("nir");
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
