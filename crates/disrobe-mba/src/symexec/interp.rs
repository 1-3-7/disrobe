use disrobe_nir::{NirInstr, NirOp, ValueOp};

use super::memory::load_or_havoc;
use super::solver::SymSolver;
use super::state::State;
use super::value::{AluOp, BitWidth, CmpOp, Sym, UnaryOp};

#[derive(Debug)]
pub(crate) struct Interp<'a> {
    solver: &'a mut SymSolver,
}

impl<'a> Interp<'a> {
    pub(crate) const fn new(solver: &'a mut SymSolver) -> Self {
        Self { solver }
    }

    pub(crate) fn step(&mut self, state: &mut State, instr: &NirInstr) {
        match &instr.op {
            NirOp::Nop
            | NirOp::Branch { .. }
            | NirOp::CondBranch { .. }
            | NirOp::Return
            | NirOp::Interrupt
            | NirOp::Unmodeled { .. } => effect_only(state, instr),
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
                let value: Sym = load_or_havoc(&state.memory, self.solver, pointer, width);
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

    pub(crate) fn eval_operand(&mut self, state: &mut State, name: &str, hint: BitWidth) -> Sym {
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

fn effect_only(state: &mut State, instr: &NirInstr) {
    if matches!(instr.op, NirOp::Interrupt | NirOp::Unmodeled { .. }) {
        state.clobber_registers();
        state.memory.invalidate_all();
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

pub(crate) fn parse_immediate(operand: &str, width: BitWidth) -> Option<u64> {
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
