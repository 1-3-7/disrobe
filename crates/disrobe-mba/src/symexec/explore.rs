use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use disrobe_nir::{BlockKind, NirBlock, NirFunction, NirInstr, NirOp, ValueOp, basic_blocks};

use super::memory::load_or_havoc;
use super::solver::{Feasible, Guard, SolverBudget, SymSolver};
use super::state::State;
use super::value::{AluOp, BitWidth, CmpOp, Sym, UnaryOp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SymexecBudget {
    pub max_blocks: usize,
    pub max_states: u64,
    pub max_paths: u64,
    pub max_retired: u64,
    pub loop_cap: u32,
    pub memory_ceiling: usize,
    pub solver_query_timeout: Duration,
    pub solver_max_conflicts: u64,
    pub solver_max_decisions: u64,
    pub solver_cumulative: Duration,
    pub solver_max_queries: u64,
}

impl SymexecBudget {
    #[must_use]
    pub const fn bounded_default() -> Self {
        Self {
            max_blocks: 4_096,
            max_states: 20_000,
            max_paths: 8_192,
            max_retired: 200_000,
            loop_cap: 8,
            memory_ceiling: 4_096,
            solver_query_timeout: Duration::from_millis(250),
            solver_max_conflicts: 20_000,
            solver_max_decisions: 100_000,
            solver_cumulative: Duration::from_secs(5),
            solver_max_queries: 4_096,
        }
    }

    pub(crate) const fn solver(self) -> SolverBudget {
        SolverBudget {
            per_query_timeout: self.solver_query_timeout,
            max_conflicts: self.solver_max_conflicts,
            max_decisions: self.solver_max_decisions,
            cumulative: self.solver_cumulative,
            max_queries: self.solver_max_queries,
        }
    }
}

impl Default for SymexecBudget {
    fn default() -> Self {
        Self::bounded_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbstainReason {
    StateCap,
    PathCap,
    RetiredCap,
    LoopCap,
    SolverBudget,
    SolverUnknown,
    TooManyBlocks,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Outcome {
    pub(crate) live: BTreeSet<(u64, u64)>,
    pub(crate) dead: BTreeSet<(u64, u64)>,
    pub(crate) abstain: Option<AbstainReason>,
}

#[derive(Debug)]
pub(crate) struct Explore {
    blocks: BTreeMap<u64, NirBlock>,
    solver: SymSolver,
    budget: SymexecBudget,
    live: BTreeSet<(u64, u64)>,
    dead: BTreeSet<(u64, u64)>,
    states_seen: u64,
    paths: u64,
    retired: u64,
    abstain: Option<AbstainReason>,
}

impl Explore {
    pub(crate) fn run(function: &NirFunction, budget: SymexecBudget) -> Outcome {
        let blocks_list: Vec<NirBlock> = basic_blocks(function);
        if blocks_list.is_empty() {
            return Outcome {
                live: BTreeSet::new(),
                dead: BTreeSet::new(),
                abstain: None,
            };
        }
        if blocks_list.len() > budget.max_blocks {
            return Outcome {
                live: BTreeSet::new(),
                dead: BTreeSet::new(),
                abstain: Some(AbstainReason::TooManyBlocks),
            };
        }
        let entry: u64 = function.address;
        let blocks: BTreeMap<u64, NirBlock> = blocks_list
            .into_iter()
            .map(|block: NirBlock| (block.start, block))
            .collect();
        let entry: u64 = if blocks.contains_key(&entry) {
            entry
        } else {
            blocks.keys().next().copied().unwrap_or(entry)
        };
        let mut engine: Self = Self {
            blocks,
            solver: SymSolver::new(budget.solver()),
            budget,
            live: BTreeSet::new(),
            dead: BTreeSet::new(),
            states_seen: 0,
            paths: 0,
            retired: 0,
            abstain: None,
        };
        engine.explore(entry);
        Outcome {
            live: engine.live,
            dead: engine.dead,
            abstain: engine.abstain,
        }
    }

    fn explore(&mut self, entry: u64) {
        let mut worklist: Vec<State> = vec![State::entry(entry, self.budget.memory_ceiling)];
        while let Some(mut state) = worklist.pop() {
            if self.abstain.is_some() {
                return;
            }
            self.states_seen = self.states_seen.saturating_add(1);
            if self.states_seen > self.budget.max_states {
                self.abstain = Some(AbstainReason::StateCap);
                return;
            }
            let Some(block): Option<NirBlock> = self.blocks.get(&state.block).cloned() else {
                continue;
            };
            if self.execute_block(&mut state, &block).is_none() {
                return;
            }
            self.transition(&state, &block, &mut worklist);
        }
    }

    fn execute_block(&mut self, state: &mut State, block: &NirBlock) -> Option<()> {
        for instr in &block.instructions {
            self.retired = self.retired.saturating_add(1);
            if self.retired > self.budget.max_retired {
                self.abstain = Some(AbstainReason::RetiredCap);
                return None;
            }
            self.execute_instr(state, instr);
        }
        Some(())
    }

    fn transition(&mut self, state: &State, block: &NirBlock, worklist: &mut Vec<State>) {
        if block.successors.is_empty() {
            self.paths = self.paths.saturating_add(1);
            if self.paths > self.budget.max_paths {
                self.abstain = Some(AbstainReason::PathCap);
            }
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
            self.branch(state, block.start, instr, taken, fallthrough, worklist);
            return;
        }
        for successor in &block.successors {
            self.live.insert((block.start, *successor));
            let child: State = state.fork(*successor);
            self.enqueue(child, worklist);
        }
    }

    fn branch(
        &mut self,
        state: &State,
        source: u64,
        terminator: &NirInstr,
        taken: u64,
        fallthrough: u64,
        worklist: &mut Vec<State>,
    ) {
        if self.solver.cumulative_exhausted() {
            self.abstain = Some(AbstainReason::SolverBudget);
            return;
        }
        let mut probe: State = state.clone();
        let condition: Sym = match terminator.operands.first() {
            Some(name) => self.eval_operand(&mut probe, name, BitWidth::BYTE),
            None => self.solver.fresh_havoc(BitWidth::BYTE),
        };
        let nonzero: Guard = self.solver.nonzero_guard(condition);
        let zero: Guard = self.solver.zero_guard(condition);
        let taken_feasible: Feasible = self.solver.feasible(&probe.path, nonzero);
        let fallthrough_feasible: Feasible = self.solver.feasible(&probe.path, zero);
        if taken_feasible == Feasible::Unknown || fallthrough_feasible == Feasible::Unknown {
            self.abstain = Some(AbstainReason::SolverUnknown);
            return;
        }
        self.arm(&probe, source, taken, nonzero, taken_feasible, worklist);
        self.arm(
            &probe,
            source,
            fallthrough,
            zero,
            fallthrough_feasible,
            worklist,
        );
    }

    fn arm(
        &mut self,
        state: &State,
        source: u64,
        target: u64,
        guard: Guard,
        feasible: Feasible,
        worklist: &mut Vec<State>,
    ) {
        match feasible {
            Feasible::Sat => {
                self.live.insert((source, target));
                let mut child: State = state.fork(target);
                if let Guard::Term(term) = guard {
                    child.path.push(term);
                }
                self.enqueue(child, worklist);
            }
            Feasible::Unsat => {
                self.dead.insert((source, target));
            }
            Feasible::Unknown => {
                self.abstain = Some(AbstainReason::SolverUnknown);
            }
        }
    }

    fn enqueue(&mut self, mut child: State, worklist: &mut Vec<State>) {
        let count: u32 = child
            .loop_counts
            .get(&child.block)
            .copied()
            .unwrap_or(0)
            .saturating_add(1);
        if count > self.budget.loop_cap {
            self.abstain = Some(AbstainReason::LoopCap);
            return;
        }
        child.loop_counts.insert(child.block, count);
        worklist.push(child);
    }

    fn execute_instr(&mut self, state: &mut State, instr: &NirInstr) {
        match &instr.op {
            NirOp::Nop
            | NirOp::Branch { .. }
            | NirOp::CondBranch { .. }
            | NirOp::Return
            | NirOp::Interrupt
            | NirOp::Unmodeled { .. } => Self::effect_only(state, instr),
            NirOp::Const => self.exec_const(state, instr),
            NirOp::BinOp { .. } => self.exec_binop(state, instr),
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                size,
            } => {
                let width: BitWidth = BitWidth::from_bytes(*size).unwrap_or(BitWidth::QWORD);
                let value: Sym = self.interp_value(state, *op, inputs, input_sizes, width);
                bind(state, instr.operands.first(), value);
            }
            NirOp::Copy { src, size } => {
                let width: BitWidth = BitWidth::from_bytes(*size).unwrap_or(BitWidth::QWORD);
                let source: Sym = self.eval_operand(state, src, width);
                let value: Sym = if source.width() == width {
                    source
                } else {
                    self.solver.fresh_havoc(width)
                };
                bind(state, instr.operands.first(), value);
            }
            NirOp::Subpiece { src, offset, size } => {
                let width: BitWidth = BitWidth::from_bytes(*size).unwrap_or(BitWidth::QWORD);
                let source: Sym = self.eval_operand(state, src, BitWidth::QWORD);
                let value: Sym = self
                    .solver
                    .extract_low(source, offset.saturating_mul(8), width);
                bind(state, instr.operands.first(), value);
            }
            NirOp::RawLoad { addr, size } => {
                let width: BitWidth = BitWidth::from_bytes(*size).unwrap_or(BitWidth::BYTE);
                let pointer: Sym = self.eval_operand(state, addr, BitWidth::QWORD);
                let value: Sym = load_or_havoc(&state.memory, &mut self.solver, pointer, width);
                bind(state, instr.operands.first(), value);
            }
            NirOp::RawStore { addr, value, size } => {
                let width: BitWidth = BitWidth::from_bytes(*size).unwrap_or(BitWidth::BYTE);
                let pointer: Sym = self.eval_operand(state, addr, BitWidth::QWORD);
                let stored: Sym = self.eval_operand(state, value, width);
                state.memory.store(pointer, stored, width);
            }
            NirOp::Store => state.memory.invalidate_all(),
            NirOp::Deposit { cell, .. } => {
                let value: Sym = self.solver.fresh_havoc(BitWidth::QWORD);
                state.env.insert(cell.trim().to_owned(), value);
            }
            NirOp::Load | NirOp::Piece { .. } | NirOp::Phi => {
                let value: Sym = self.solver.fresh_havoc(BitWidth::QWORD);
                bind(state, instr.operands.first(), value);
            }
            NirOp::Call { .. }
            | NirOp::NoReturnCall { .. }
            | NirOp::TailCall { .. }
            | NirOp::ExternCall { .. }
            | NirOp::IndirectCall => {
                state.clobber_registers();
                state.memory.invalidate_all();
            }
            NirOp::CallOther { effect } => {
                if effect.unknown_registers {
                    state.clobber_registers();
                } else {
                    for written in &effect.writes {
                        state.env.remove(written.trim());
                    }
                }
                if effect.writes_memory {
                    state.memory.invalidate_all();
                }
            }
        }
    }

    fn effect_only(state: &mut State, instr: &NirInstr) {
        if matches!(instr.op, NirOp::Interrupt | NirOp::Unmodeled { .. }) {
            state.clobber_registers();
            state.memory.invalidate_all();
        }
    }

    fn exec_const(&mut self, state: &mut State, instr: &NirInstr) {
        let width: BitWidth = if instr.byte_width {
            BitWidth::BYTE
        } else {
            BitWidth::QWORD
        };
        let value: Sym = instr
            .operands
            .get(1)
            .and_then(|imm: &String| parse_immediate(imm, width))
            .map_or_else(
                || self.solver.fresh_havoc(width),
                |raw: u64| Sym::constant(width, raw),
            );
        bind(state, instr.operands.first(), value);
    }

    fn exec_binop(&mut self, state: &mut State, instr: &NirInstr) {
        let width: BitWidth = if instr.byte_width {
            BitWidth::BYTE
        } else {
            BitWidth::QWORD
        };
        let value: Sym = self.solver.fresh_havoc(width);
        bind(state, instr.operands.first(), value);
    }

    fn interp_value(
        &mut self,
        state: &mut State,
        op: ValueOp,
        inputs: &[String],
        sizes: &[u32],
        out: BitWidth,
    ) -> Sym {
        match op {
            ValueOp::IntAdd => self.binary_alu(state, AluOp::Add, inputs, out),
            ValueOp::IntSub => self.binary_alu(state, AluOp::Sub, inputs, out),
            ValueOp::IntMult => self.binary_alu(state, AluOp::Mul, inputs, out),
            ValueOp::IntAnd => self.binary_alu(state, AluOp::And, inputs, out),
            ValueOp::IntOr => self.binary_alu(state, AluOp::Or, inputs, out),
            ValueOp::IntXor => self.binary_alu(state, AluOp::Xor, inputs, out),
            ValueOp::IntLeft => self.binary_alu(state, AluOp::Shl, inputs, out),
            ValueOp::IntRight => self.binary_alu(state, AluOp::Lshr, inputs, out),
            ValueOp::IntSignedRight => self.binary_alu(state, AluOp::Ashr, inputs, out),
            ValueOp::IntDiv => self.binary_alu(state, AluOp::Udiv, inputs, out),
            ValueOp::IntSignedDiv => self.binary_alu(state, AluOp::Sdiv, inputs, out),
            ValueOp::IntRem => self.binary_alu(state, AluOp::Urem, inputs, out),
            ValueOp::IntSignedRem => self.binary_alu(state, AluOp::Srem, inputs, out),
            ValueOp::IntNegate => self.unary_alu(state, UnaryOp::Not, inputs, out),
            ValueOp::IntEqual => self.compare(state, CmpOp::Eq, inputs, sizes, out),
            ValueOp::IntNotEqual => self.compare(state, CmpOp::Ne, inputs, sizes, out),
            ValueOp::IntLess => self.compare(state, CmpOp::Ult, inputs, sizes, out),
            ValueOp::IntLessEqual => self.compare(state, CmpOp::Ule, inputs, sizes, out),
            ValueOp::IntSignedLess => self.compare(state, CmpOp::Slt, inputs, sizes, out),
            ValueOp::IntSignedLessEqual => self.compare(state, CmpOp::Sle, inputs, sizes, out),
            ValueOp::IntZext => self.extend(state, inputs, sizes, out),
            ValueOp::BoolNegate => self.bool_negate(state, inputs, sizes, out),
            _ => self.solver.fresh_havoc(out),
        }
    }

    fn binary_alu(
        &mut self,
        state: &mut State,
        op: AluOp,
        inputs: &[String],
        out: BitWidth,
    ) -> Sym {
        let (Some(lhs_name), Some(rhs_name)): (Option<&String>, Option<&String>) =
            (inputs.first(), inputs.get(1))
        else {
            return self.solver.fresh_havoc(out);
        };
        let lhs: Sym = self.eval_operand(state, lhs_name, out);
        let rhs: Sym = self.eval_operand(state, rhs_name, out);
        self.solver.alu(op, lhs, rhs, out)
    }

    fn unary_alu(
        &mut self,
        state: &mut State,
        op: UnaryOp,
        inputs: &[String],
        out: BitWidth,
    ) -> Sym {
        let Some(name): Option<&String> = inputs.first() else {
            return self.solver.fresh_havoc(out);
        };
        let operand: Sym = self.eval_operand(state, name, out);
        self.solver.unary(op, operand, out)
    }

    fn compare(
        &mut self,
        state: &mut State,
        op: CmpOp,
        inputs: &[String],
        sizes: &[u32],
        out: BitWidth,
    ) -> Sym {
        let (Some(lhs_name), Some(rhs_name)): (Option<&String>, Option<&String>) =
            (inputs.first(), inputs.get(1))
        else {
            return self.solver.fresh_havoc(out);
        };
        let (Some(lhs_width), Some(rhs_width)): (Option<BitWidth>, Option<BitWidth>) =
            (width_of(sizes, 0), width_of(sizes, 1))
        else {
            return self.solver.fresh_havoc(out);
        };
        if lhs_width != rhs_width {
            return self.solver.fresh_havoc(out);
        }
        let lhs: Sym = self.eval_operand(state, lhs_name, lhs_width);
        let rhs: Sym = self.eval_operand(state, rhs_name, rhs_width);
        self.solver.compare(op, lhs, rhs, out)
    }

    fn extend(
        &mut self,
        state: &mut State,
        inputs: &[String],
        sizes: &[u32],
        out: BitWidth,
    ) -> Sym {
        let Some(name): Option<&String> = inputs.first() else {
            return self.solver.fresh_havoc(out);
        };
        let Some(source_width): Option<BitWidth> = width_of(sizes, 0) else {
            return self.solver.fresh_havoc(out);
        };
        let operand: Sym = self.eval_operand(state, name, source_width);
        self.solver.zero_extend(operand, out)
    }

    fn bool_negate(
        &mut self,
        state: &mut State,
        inputs: &[String],
        sizes: &[u32],
        out: BitWidth,
    ) -> Sym {
        let Some(name): Option<&String> = inputs.first() else {
            return self.solver.fresh_havoc(out);
        };
        let width: BitWidth = width_of(sizes, 0).unwrap_or(out);
        let operand: Sym = self.eval_operand(state, name, width);
        let zero: Sym = Sym::constant(width, 0);
        self.solver.compare(CmpOp::Eq, operand, zero, out)
    }

    fn eval_operand(&mut self, state: &mut State, name: &str, hint: BitWidth) -> Sym {
        let trimmed: &str = name.trim();
        if let Some(value) = parse_immediate(trimmed, hint) {
            return Sym::constant(hint, value);
        }
        if let Some(existing) = state.env.get(trimmed) {
            return *existing;
        }
        let fresh: Sym = self.solver.fresh_havoc(hint);
        state.env.insert(trimmed.to_owned(), fresh);
        fresh
    }
}

fn bind(state: &mut State, dest: Option<&String>, value: Sym) {
    let Some(name): Option<&String> = dest else {
        return;
    };
    let trimmed: &str = name.trim();
    if trimmed.is_empty() || parse_immediate(trimmed, BitWidth::QWORD).is_some() {
        return;
    }
    state.env.insert(trimmed.to_owned(), value);
}

fn width_of(sizes: &[u32], index: usize) -> Option<BitWidth> {
    sizes.get(index).copied().and_then(BitWidth::from_bytes)
}

fn parse_immediate(operand: &str, width: BitWidth) -> Option<u64> {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return None;
    }
    let (negative, body): (bool, &str) = trimmed
        .strip_prefix('-')
        .map_or((false, trimmed), |rest: &str| (true, rest));
    let hex: Option<&str> = body.strip_prefix("0x").or_else(|| body.strip_prefix("0X"));
    let (radix, digits): (u32, &str) = hex.map_or((10, body), |rest: &str| (16, rest));
    let magnitude: u64 = u64::from_str_radix(digits, radix).ok()?;
    let value: u64 = if negative {
        magnitude.wrapping_neg()
    } else {
        magnitude
    };
    Some(value & width.mask())
}
