use std::collections::{BTreeMap, BTreeSet};

use disrobe_nir::{BlockKind, NirBlock, NirInstr, NirOp, ValueOp};

use crate::jumptable::ValueSet;

use super::detect::{MAX_REGION_NODES, Plan, block_defs, dest_is, parse_immediate};
use super::types::DegradeReason;

const TRACE_DEPTH: u32 = 64;

const fn width_mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

const fn bits_from_bytes(bytes: u32) -> Option<u32> {
    match bytes {
        1..=8 => Some(bytes * 8),
        _ => None,
    }
}

const fn sign_extend(value: u64, bits: u32) -> u64 {
    if bits == 0 || bits >= 64 {
        return value;
    }
    let shift: u32 = 64 - bits;
    (((value << shift) as i64) >> shift) as u64
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Abstract {
    Known { set: ValueSet, bits: u32 },
    Free(u32),
    Opaque,
}

impl Abstract {
    const fn known(value: u64, bits: u32) -> Self {
        Self::Known {
            set: ValueSet::singleton(value & width_mask(bits)),
            bits,
        }
    }

    const fn constant(self) -> Option<u64> {
        match self {
            Self::Known { set, .. } => set.as_constant(),
            Self::Free(_) | Self::Opaque => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AluKind {
    Add,
    Sub,
    Mul,
    And,
    Or,
    Xor,
    Shl,
    Lshr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpKind {
    Eq,
    Ne,
    Ult,
    Ule,
    Slt,
    Sle,
}

fn fold_alu(op: AluKind, lhs: u64, rhs: u64, bits: u32) -> u64 {
    let mask: u64 = width_mask(bits);
    let lhs: u64 = lhs & mask;
    let rhs: u64 = rhs & mask;
    let wide: u64 = u64::from(bits);
    let value: u64 = match op {
        AluKind::Add => lhs.wrapping_add(rhs),
        AluKind::Sub => lhs.wrapping_sub(rhs),
        AluKind::Mul => lhs.wrapping_mul(rhs),
        AluKind::And => lhs & rhs,
        AluKind::Or => lhs | rhs,
        AluKind::Xor => lhs ^ rhs,
        AluKind::Shl | AluKind::Lshr if rhs >= wide => 0,
        AluKind::Shl => lhs.wrapping_shl(rhs as u32),
        AluKind::Lshr => lhs >> rhs,
    };
    value & mask
}

fn fold_cmp(op: CmpKind, lhs: u64, rhs: u64, bits: u32) -> u64 {
    let mask: u64 = width_mask(bits);
    let lhs: u64 = lhs & mask;
    let rhs: u64 = rhs & mask;
    let result: bool = match op {
        CmpKind::Eq => lhs == rhs,
        CmpKind::Ne => lhs != rhs,
        CmpKind::Ult => lhs < rhs,
        CmpKind::Ule => lhs <= rhs,
        CmpKind::Slt => (sign_extend(lhs, bits) as i64) < (sign_extend(rhs, bits) as i64),
        CmpKind::Sle => (sign_extend(lhs, bits) as i64) <= (sign_extend(rhs, bits) as i64),
    };
    u64::from(result)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheapAbstain {
    Degrade(DegradeReason),
    NeedsSolver,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CheapEnd {
    sv: Option<u64>,
    wrote: bool,
    terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Path {
    block: u64,
    env: BTreeMap<String, Abstract>,
    wrote: bool,
    forks: u32,
    loops: BTreeMap<u64, u32>,
}

impl Path {
    fn child(&self, block: u64) -> Self {
        Self {
            block,
            env: self.env.clone(),
            wrote: self.wrote,
            forks: self.forks,
            loops: self.loops.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BranchKind {
    TakenOnly,
    FallthroughOnly,
    Both,
    NeedsSolver,
}

struct Cheap<'a> {
    blocks: &'a BTreeMap<u64, NirBlock>,
    stop: u64,
    start: u64,
    case_heads: &'a BTreeSet<u64>,
    state_var: &'a str,
    loop_cap: u32,
    nodes: u32,
    fresh: u32,
    abstain: Option<CheapAbstain>,
    ends: Vec<CheapEnd>,
}

impl std::fmt::Debug for Cheap<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Cheap")
            .field("stop", &self.stop)
            .field("start", &self.start)
            .field("nodes", &self.nodes)
            .field("abstain", &self.abstain)
            .finish_non_exhaustive()
    }
}

impl<'a> Cheap<'a> {
    const fn new(
        blocks: &'a BTreeMap<u64, NirBlock>,
        stop: u64,
        start: u64,
        case_heads: &'a BTreeSet<u64>,
        state_var: &'a str,
        loop_cap: u32,
    ) -> Self {
        Self {
            blocks,
            stop,
            start,
            case_heads,
            state_var,
            loop_cap,
            nodes: 0,
            fresh: 0,
            abstain: None,
            ends: Vec::new(),
        }
    }

    const fn next_id(&mut self) -> u32 {
        let id: u32 = self.fresh;
        self.fresh = self.fresh.wrapping_add(1);
        id
    }

    fn run(&mut self, start: u64, seed: Option<(u64, u32)>) {
        let mut env: BTreeMap<String, Abstract> = BTreeMap::new();
        if let Some((value, bits)) = seed {
            env.insert(self.state_var.to_owned(), Abstract::known(value, bits));
        }
        let mut work: Vec<Path> = vec![Path {
            block: start,
            env,
            wrote: false,
            forks: 0,
            loops: BTreeMap::new(),
        }];
        while let Some(mut path) = work.pop() {
            if self.abstain.is_some() {
                return;
            }
            self.nodes = self.nodes.saturating_add(1);
            if self.nodes > MAX_REGION_NODES {
                self.abstain = Some(CheapAbstain::Degrade(DegradeReason::RegionUnbounded));
                return;
            }
            let Some(block): Option<NirBlock> = self.blocks.get(&path.block).cloned() else {
                continue;
            };
            let defs: BTreeMap<&str, &NirInstr> = block_defs(&block);
            for instr in &block.instructions {
                if dest_is(instr, self.state_var) {
                    path.wrote = true;
                }
                self.step(&mut path.env, instr);
            }
            self.transition(&block, &defs, &path, &mut work);
        }
    }

    fn transition(
        &mut self,
        block: &NirBlock,
        defs: &BTreeMap<&str, &NirInstr>,
        path: &Path,
        work: &mut Vec<Path>,
    ) {
        if block.successors.is_empty() {
            self.ends.push(CheapEnd {
                sv: None,
                wrote: path.wrote,
                terminal: true,
            });
            return;
        }
        let terminator: Option<&NirInstr> = block.instructions.last();
        if block.kind == BlockKind::Conditional
            && block.successors.len() == 2
            && let Some(instr) = terminator
            && let Some(taken) = instr.direct_target()
            && block.successors.contains(&taken)
            && let Some(fallthrough) = block.successors.iter().copied().find(|s: &u64| *s != taken)
        {
            self.fork(defs, &path.env, instr, taken, fallthrough, path, work);
            return;
        }
        for successor in &block.successors {
            let child: Path = path.child(*successor);
            self.enqueue(child, work);
        }
    }

    fn fork(
        &mut self,
        defs: &BTreeMap<&str, &NirInstr>,
        env: &BTreeMap<String, Abstract>,
        terminator: &NirInstr,
        taken: u64,
        fallthrough: u64,
        path: &Path,
        work: &mut Vec<Path>,
    ) {
        match self.classify_branch(defs, env, terminator.operands.first()) {
            BranchKind::TakenOnly => {
                let child: Path = path.child(taken);
                self.enqueue(child, work);
            }
            BranchKind::FallthroughOnly => {
                let child: Path = path.child(fallthrough);
                self.enqueue(child, work);
            }
            BranchKind::Both => {
                if path.forks >= 1 {
                    self.abstain = Some(CheapAbstain::NeedsSolver);
                    return;
                }
                let mut taken_path: Path = path.child(taken);
                taken_path.forks = taken_path.forks.saturating_add(1);
                self.enqueue(taken_path, work);
                let mut fall_path: Path = path.child(fallthrough);
                fall_path.forks = fall_path.forks.saturating_add(1);
                self.enqueue(fall_path, work);
            }
            BranchKind::NeedsSolver => {
                self.abstain = Some(CheapAbstain::NeedsSolver);
            }
        }
    }

    fn classify_branch(
        &mut self,
        defs: &BTreeMap<&str, &NirInstr>,
        env: &BTreeMap<String, Abstract>,
        cond: Option<&String>,
    ) -> BranchKind {
        let Some(name): Option<&String> = cond else {
            return BranchKind::Both;
        };
        let trimmed: &str = name.trim();
        if let Some(literal) = parse_immediate(trimmed, 0xff) {
            return if literal == 0 {
                BranchKind::FallthroughOnly
            } else {
                BranchKind::TakenOnly
            };
        }
        match self.peek(env, trimmed) {
            Abstract::Known { set, .. } => match set.as_constant() {
                Some(0) => BranchKind::FallthroughOnly,
                Some(_) => BranchKind::TakenOnly,
                None => BranchKind::NeedsSolver,
            },
            Abstract::Free(_) => BranchKind::Both,
            Abstract::Opaque => {
                if self.trace_two_valued(defs, env, trimmed, 0) {
                    BranchKind::Both
                } else {
                    BranchKind::NeedsSolver
                }
            }
        }
    }

    fn trace_two_valued(
        &mut self,
        defs: &BTreeMap<&str, &NirInstr>,
        env: &BTreeMap<String, Abstract>,
        name: &str,
        depth: u32,
    ) -> bool {
        if depth > TRACE_DEPTH {
            return false;
        }
        let Some(instr): Option<&&NirInstr> = defs.get(name.trim()) else {
            return false;
        };
        match &instr.op {
            NirOp::Value {
                op: ValueOp::IntEqual | ValueOp::IntNotEqual,
                inputs,
                ..
            } if inputs.len() == 2 => self.two_valued(env, &inputs[0], &inputs[1]),
            NirOp::Copy { src, .. } => self.trace_two_valued(defs, env, src.trim(), depth + 1),
            NirOp::Value {
                op: ValueOp::BoolNegate,
                inputs,
                ..
            } if inputs.len() == 1 => self.trace_two_valued(defs, env, inputs[0].trim(), depth + 1),
            _ => false,
        }
    }

    fn two_valued(&mut self, env: &BTreeMap<String, Abstract>, lhs: &str, rhs: &str) -> bool {
        let lhs: &str = lhs.trim();
        let rhs: &str = rhs.trim();
        if lhs == rhs {
            return false;
        }
        match (self.peek(env, lhs), self.peek(env, rhs)) {
            (Abstract::Opaque, _)
            | (_, Abstract::Opaque)
            | (Abstract::Known { .. }, Abstract::Known { .. }) => false,
            (Abstract::Free(a), Abstract::Free(b)) => a != b,
            (Abstract::Free(_), Abstract::Known { .. })
            | (Abstract::Known { .. }, Abstract::Free(_)) => true,
        }
    }

    fn peek(&mut self, env: &BTreeMap<String, Abstract>, name: &str) -> Abstract {
        let trimmed: &str = name.trim();
        if let Some(value) = parse_immediate(trimmed, u64::MAX) {
            return Abstract::known(value, 64);
        }
        if let Some(existing) = env.get(trimmed) {
            return *existing;
        }
        Abstract::Free(self.next_id())
    }

    fn enqueue(&mut self, child: Path, work: &mut Vec<Path>) {
        if child.block == self.stop {
            let sv: Option<u64> = child
                .env
                .get(self.state_var)
                .and_then(|value: &Abstract| value.constant());
            self.ends.push(CheapEnd {
                sv,
                wrote: child.wrote,
                terminal: false,
            });
            return;
        }
        if child.block != self.start && self.case_heads.contains(&child.block) {
            self.abstain = Some(CheapAbstain::Degrade(DegradeReason::FellIntoCase));
            return;
        }
        let count: u32 = child
            .loops
            .get(&child.block)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if count > self.loop_cap {
            self.abstain = Some(CheapAbstain::Degrade(DegradeReason::RegionUnbounded));
            return;
        }
        let mut child: Path = child;
        child.loops.insert(child.block, count);
        work.push(child);
    }

    fn step(&mut self, env: &mut BTreeMap<String, Abstract>, instr: &NirInstr) {
        match &instr.op {
            NirOp::Nop
            | NirOp::Branch { .. }
            | NirOp::CondBranch { .. }
            | NirOp::Return
            | NirOp::Store
            | NirOp::RawStore { .. } => {}
            NirOp::Interrupt
            | NirOp::Unmodeled { .. }
            | NirOp::Call { .. }
            | NirOp::NoReturnCall { .. }
            | NirOp::TailCall { .. }
            | NirOp::ExternCall { .. }
            | NirOp::IndirectCall => env.clear(),
            NirOp::Const => {
                let bits: u32 = if instr.byte_width { 8 } else { 64 };
                let value: Abstract = instr
                    .operands
                    .get(1)
                    .and_then(|imm: &String| parse_immediate(imm, width_mask(bits)))
                    .map_or_else(|| self.fresh_free(), |raw: u64| Abstract::known(raw, bits));
                bind(env, instr.operands.first(), value);
            }
            NirOp::BinOp { .. }
            | NirOp::RawLoad { .. }
            | NirOp::Load
            | NirOp::Phi
            | NirOp::Piece { .. } => {
                let value: Abstract = self.fresh_free();
                bind(env, instr.operands.first(), value);
            }
            NirOp::Copy { src, size } => {
                let bits: u32 = bits_from_bytes(*size).unwrap_or(64);
                let source: Abstract = self.resolve(env, src, bits);
                let value: Abstract = match source {
                    Abstract::Known {
                        bits: source_bits, ..
                    } if source_bits == bits => source,
                    Abstract::Known { .. } => self.fresh_free(),
                    Abstract::Free(_) | Abstract::Opaque => source,
                };
                bind(env, instr.operands.first(), value);
            }
            NirOp::Subpiece { src, offset, size } => {
                let bits: u32 = bits_from_bytes(*size).unwrap_or(64);
                let shift: u32 = offset.saturating_mul(8);
                let source: Abstract = self.resolve(env, src, 64);
                let value: Abstract = match source.constant() {
                    Some(raw) if shift < 64 => Abstract::known(raw >> shift, bits),
                    Some(_) | None => Abstract::Opaque,
                };
                bind(env, instr.operands.first(), value);
            }
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                size,
            } => {
                let bits: u32 = bits_from_bytes(*size).unwrap_or(64);
                let value: Abstract = self.eval_value(env, *op, inputs, input_sizes, bits);
                bind(env, instr.operands.first(), value);
            }
            NirOp::Deposit { cell, .. } => {
                let value: Abstract = self.fresh_free();
                env.insert(cell.trim().to_owned(), value);
            }
            NirOp::CallOther { effect } => {
                if effect.unknown_registers {
                    env.clear();
                } else {
                    for written in &effect.writes {
                        env.remove(written.trim());
                    }
                }
            }
        }
    }

    fn eval_value(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        op: ValueOp,
        inputs: &[String],
        sizes: &[u32],
        out_bits: u32,
    ) -> Abstract {
        match op {
            ValueOp::IntAdd => self.alu(env, AluKind::Add, inputs, out_bits),
            ValueOp::IntSub => self.alu(env, AluKind::Sub, inputs, out_bits),
            ValueOp::IntMult => self.alu(env, AluKind::Mul, inputs, out_bits),
            ValueOp::IntAnd => self.alu(env, AluKind::And, inputs, out_bits),
            ValueOp::IntOr => self.alu(env, AluKind::Or, inputs, out_bits),
            ValueOp::IntXor => self.alu(env, AluKind::Xor, inputs, out_bits),
            ValueOp::IntLeft => self.alu(env, AluKind::Shl, inputs, out_bits),
            ValueOp::IntRight => self.alu(env, AluKind::Lshr, inputs, out_bits),
            ValueOp::IntEqual => self.cmp(env, CmpKind::Eq, inputs, sizes, out_bits),
            ValueOp::IntNotEqual => self.cmp(env, CmpKind::Ne, inputs, sizes, out_bits),
            ValueOp::IntLess => self.cmp(env, CmpKind::Ult, inputs, sizes, out_bits),
            ValueOp::IntLessEqual => self.cmp(env, CmpKind::Ule, inputs, sizes, out_bits),
            ValueOp::IntSignedLess => self.cmp(env, CmpKind::Slt, inputs, sizes, out_bits),
            ValueOp::IntSignedLessEqual => self.cmp(env, CmpKind::Sle, inputs, sizes, out_bits),
            ValueOp::IntNegate => self.unary_not(env, inputs, out_bits),
            ValueOp::IntZext => self.zero_extend(env, inputs, sizes, out_bits),
            ValueOp::BoolNegate => self.bool_negate(env, inputs, out_bits),
            ValueOp::IntDiv
            | ValueOp::IntSignedDiv
            | ValueOp::IntRem
            | ValueOp::IntSignedRem
            | ValueOp::IntSignedRight => Abstract::Opaque,
            _ => self.fresh_free(),
        }
    }

    fn alu(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        op: AluKind,
        inputs: &[String],
        out_bits: u32,
    ) -> Abstract {
        let (Some(lhs_name), Some(rhs_name)): (Option<&String>, Option<&String>) =
            (inputs.first(), inputs.get(1))
        else {
            return self.fresh_free();
        };
        let lhs: Abstract = self.resolve(env, lhs_name, out_bits);
        let rhs: Abstract = self.resolve(env, rhs_name, out_bits);
        match (known_at(lhs, out_bits), known_at(rhs, out_bits)) {
            (Some(a), Some(b)) => Abstract::known(fold_alu(op, a, b, out_bits), out_bits),
            _ => Abstract::Opaque,
        }
    }

    fn cmp(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        op: CmpKind,
        inputs: &[String],
        sizes: &[u32],
        out_bits: u32,
    ) -> Abstract {
        let (Some(lhs_name), Some(rhs_name)): (Option<&String>, Option<&String>) =
            (inputs.first(), inputs.get(1))
        else {
            return self.fresh_free();
        };
        let (Some(lhs_bits), Some(rhs_bits)): (Option<u32>, Option<u32>) = (
            sizes.first().copied().and_then(bits_from_bytes),
            sizes.get(1).copied().and_then(bits_from_bytes),
        ) else {
            return Abstract::Opaque;
        };
        if lhs_bits != rhs_bits {
            return Abstract::Opaque;
        }
        let lhs: Abstract = self.resolve(env, lhs_name, lhs_bits);
        let rhs: Abstract = self.resolve(env, rhs_name, rhs_bits);
        match (known_at(lhs, lhs_bits), known_at(rhs, rhs_bits)) {
            (Some(a), Some(b)) => Abstract::known(fold_cmp(op, a, b, lhs_bits), out_bits),
            _ => Abstract::Opaque,
        }
    }

    fn unary_not(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        inputs: &[String],
        out_bits: u32,
    ) -> Abstract {
        let Some(name): Option<&String> = inputs.first() else {
            return self.fresh_free();
        };
        let operand: Abstract = self.resolve(env, name, out_bits);
        known_at(operand, out_bits).map_or(Abstract::Opaque, |value: u64| {
            Abstract::known(!value, out_bits)
        })
    }

    fn zero_extend(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        inputs: &[String],
        sizes: &[u32],
        out_bits: u32,
    ) -> Abstract {
        let Some(name): Option<&String> = inputs.first() else {
            return self.fresh_free();
        };
        let Some(source_bits): Option<u32> = sizes.first().copied().and_then(bits_from_bytes)
        else {
            return Abstract::Opaque;
        };
        let operand: Abstract = self.resolve(env, name, source_bits);
        known_at(operand, source_bits).map_or(Abstract::Opaque, |value: u64| {
            Abstract::known(value, out_bits)
        })
    }

    fn bool_negate(
        &mut self,
        env: &mut BTreeMap<String, Abstract>,
        inputs: &[String],
        out_bits: u32,
    ) -> Abstract {
        let Some(name): Option<&String> = inputs.first() else {
            return self.fresh_free();
        };
        let operand: Abstract = self.resolve(env, name, out_bits);
        operand.constant().map_or(Abstract::Opaque, |value: u64| {
            Abstract::known(u64::from(value == 0), out_bits)
        })
    }

    fn resolve(&mut self, env: &mut BTreeMap<String, Abstract>, name: &str, bits: u32) -> Abstract {
        let trimmed: &str = name.trim();
        if let Some(value) = parse_immediate(trimmed, width_mask(bits)) {
            return Abstract::known(value, bits);
        }
        if let Some(existing) = env.get(trimmed) {
            return *existing;
        }
        let value: Abstract = Abstract::Free(self.next_id());
        env.insert(trimmed.to_owned(), value);
        value
    }

    const fn fresh_free(&mut self) -> Abstract {
        Abstract::Free(self.next_id())
    }
}

fn bind(env: &mut BTreeMap<String, Abstract>, dest: Option<&String>, value: Abstract) {
    let Some(name): Option<&String> = dest else {
        return;
    };
    let trimmed: &str = name.trim();
    if trimmed.is_empty() || parse_immediate(trimmed, u64::MAX).is_some() {
        return;
    }
    env.insert(trimmed.to_owned(), value);
}

const fn known_at(value: Abstract, bits: u32) -> Option<u64> {
    match value {
        Abstract::Known {
            set,
            bits: value_bits,
        } if value_bits == bits => set.as_constant(),
        Abstract::Known { .. } | Abstract::Free(_) | Abstract::Opaque => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheapResolution {
    Resolved { targets: Vec<u64> },
    Terminal,
    Degrade(DegradeReason),
    NeedsSolver,
}

pub(crate) fn cheap_initial(
    blocks: &BTreeMap<u64, NirBlock>,
    plan: &Plan,
    case_heads: &BTreeSet<u64>,
    loop_cap: u32,
) -> Option<u64> {
    let mut walker: Cheap<'_> = Cheap::new(
        blocks,
        plan.head,
        plan.entry_block,
        case_heads,
        &plan.state_var,
        loop_cap,
    );
    walker.run(plan.entry_block, None);
    if walker.abstain.is_some() {
        return None;
    }
    let mut constants: BTreeSet<u64> = BTreeSet::new();
    for end in &walker.ends {
        if end.terminal {
            continue;
        }
        constants.insert(end.sv?);
    }
    let mut iter = constants.into_iter();
    let first: u64 = iter.next()?;
    if iter.next().is_some() {
        return None;
    }
    plan.casemap.get(&first).copied()
}

pub(crate) fn cheap_resolve_block(
    blocks: &BTreeMap<u64, NirBlock>,
    plan: &Plan,
    case_heads: &BTreeSet<u64>,
    case_value: u64,
    block: u64,
    loop_cap: u32,
) -> CheapResolution {
    let mut walker: Cheap<'_> = Cheap::new(
        blocks,
        plan.head,
        block,
        case_heads,
        &plan.state_var,
        loop_cap,
    );
    walker.run(block, Some((case_value, plan.sv_width.bits())));
    if let Some(abstain) = walker.abstain {
        return match abstain {
            CheapAbstain::Degrade(reason) => CheapResolution::Degrade(reason),
            CheapAbstain::NeedsSolver => CheapResolution::NeedsSolver,
        };
    }
    let back: Vec<&CheapEnd> = walker
        .ends
        .iter()
        .filter(|end: &&CheapEnd| !end.terminal)
        .collect();
    if back.is_empty() {
        return CheapResolution::Terminal;
    }
    if back.iter().any(|end: &&CheapEnd| !end.wrote) {
        return CheapResolution::Degrade(DegradeReason::StateVarNotAssigned);
    }
    let mut targets: BTreeSet<u64> = BTreeSet::new();
    for end in &back {
        let Some(value): Option<u64> = end.sv else {
            return CheapResolution::Degrade(DegradeReason::NextStateNotConstant);
        };
        let Some(&target): Option<&u64> = plan.casemap.get(&value) else {
            return CheapResolution::Degrade(DegradeReason::NextStateOutsideCaseMap);
        };
        targets.insert(target);
    }
    CheapResolution::Resolved {
        targets: targets.into_iter().collect(),
    }
}
