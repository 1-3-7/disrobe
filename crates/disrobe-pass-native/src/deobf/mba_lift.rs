use std::collections::BTreeMap;

use disrobe_mba::{BinOp, Expr, UnOp, Width};
use iced_x86::{Instruction, Mnemonic, OpKind, Register};

const MAX_EXPR_NODES: usize = 4096;
const MAX_LIFT_INSNS: usize = 8192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Slot {
    Reg(Register),
    Imm(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct StackCell {
    pub base: Register,
    pub disp: i64,
}

#[derive(Debug, Default, Clone)]
pub struct RegFile {
    bindings: BTreeMap<Register, Expr>,
    stack: BTreeMap<StackCell, Expr>,
    sym_mem: BTreeMap<(String, Width), Expr>,
    next_var: u32,
    seeds: BTreeMap<Register, u32>,
    stack_seeds: BTreeMap<StackCell, u32>,
    capped: bool,
}

impl RegFile {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn full_reg(reg: Register) -> Register {
        let full: Register = reg.full_register();
        if full == Register::None { reg } else { full }
    }

    fn seed(&mut self, reg: Register) -> Expr {
        let full: Register = Self::full_reg(reg);
        if let Some(existing) = self.seeds.get(&full) {
            return Expr::var(*existing);
        }
        let index: u32 = self.next_var;
        self.next_var += 1;
        self.seeds.insert(full, index);
        Expr::var(index)
    }

    fn read_reg(&mut self, reg: Register) -> Expr {
        let full: Register = Self::full_reg(reg);
        if let Some(expr) = self.bindings.get(&full) {
            return expr.clone();
        }
        self.seed(full)
    }

    fn write_reg(&mut self, reg: Register, value: Expr) {
        let full: Register = Self::full_reg(reg);
        if value.node_count() > MAX_EXPR_NODES {
            self.capped = true;
            let replacement: Expr = self.seed(full);
            self.bindings.insert(full, replacement);
            return;
        }
        self.bindings.insert(full, value);
    }

    #[must_use]
    pub fn current(&mut self, reg: Register) -> Expr {
        self.read_reg(reg)
    }

    #[must_use]
    pub fn seed_index(&self, reg: Register) -> Option<u32> {
        self.seeds.get(&Self::full_reg(reg)).copied()
    }

    #[must_use]
    pub const fn is_capped(&self) -> bool {
        self.capped
    }

    #[must_use]
    pub fn bound_registers(&self) -> Vec<Register> {
        self.bindings.keys().copied().collect()
    }

    #[must_use]
    pub fn binding(&self, reg: Register) -> Option<&Expr> {
        self.bindings.get(&Self::full_reg(reg))
    }

    #[must_use]
    pub const fn next_var(&self) -> u32 {
        self.next_var
    }

    pub fn apply_insn(&mut self, insn: &Instruction) -> bool {
        apply_arith(self, insn)
    }

    #[must_use]
    pub fn bound_stack_cells(&self) -> Vec<StackCell> {
        self.stack.keys().copied().collect()
    }

    #[must_use]
    pub fn stack_binding(&self, cell: StackCell) -> Option<&Expr> {
        self.stack.get(&cell)
    }

    pub fn set_reg_binding(&mut self, reg: Register, value: Expr) {
        self.bindings.insert(Self::full_reg(reg), value);
    }

    pub fn set_stack_binding(&mut self, cell: StackCell, value: Expr) {
        self.stack.insert(cell, value);
    }

    pub fn seed_or_create(&mut self, reg: Register) -> u32 {
        let full: Register = Self::full_reg(reg);
        if let Some(existing) = self.seeds.get(&full) {
            return *existing;
        }
        let index: u32 = self.next_var;
        self.next_var += 1;
        self.seeds.insert(full, index);
        index
    }

    pub fn fresh_var(&mut self) -> u32 {
        let index: u32 = self.next_var;
        self.next_var += 1;
        index
    }

    pub fn adopt_next_var(&mut self, floor: u32) {
        if floor > self.next_var {
            self.next_var = floor;
        }
    }

    fn read_mem(&mut self, cell: StackCell) -> Expr {
        if let Some(expr) = self.stack.get(&cell) {
            return expr.clone();
        }
        if let Some(existing) = self.stack_seeds.get(&cell) {
            return Expr::var(*existing);
        }
        let index: u32 = self.next_var;
        self.next_var += 1;
        self.stack_seeds.insert(cell, index);
        Expr::var(index)
    }

    fn write_mem(&mut self, cell: StackCell, value: Expr) {
        if value.node_count() > MAX_EXPR_NODES {
            self.capped = true;
            self.stack.remove(&cell);
            self.stack_seeds.remove(&cell);
            return;
        }
        self.stack.insert(cell, value);
    }

    fn read_general_mem(&self, addr: Expr, width: Width) -> Expr {
        let key: (String, Width) = (format!("{addr}"), width);
        if let Some(stored) = self.sym_mem.get(&key) {
            return stored.clone();
        }
        Expr::mem(addr, width)
    }

    fn write_general_mem(&mut self, addr: Expr, width: Width, value: Expr) {
        if value.node_count() > MAX_EXPR_NODES || addr.node_count() > MAX_EXPR_NODES {
            self.capped = true;
            self.sym_mem.remove(&(format!("{addr}"), width));
            return;
        }
        self.sym_mem.insert((format!("{addr}"), width), value);
    }
}

fn stack_cell(insn: &Instruction) -> Option<StackCell> {
    if insn.memory_index() != Register::None {
        return None;
    }
    let base: Register = insn.memory_base();
    if !matches!(
        base,
        Register::RSP | Register::RBP | Register::ESP | Register::EBP
    ) {
        return None;
    }
    Some(StackCell {
        base: base.full_register(),
        disp: insn.memory_displacement64().cast_signed(),
    })
}

fn mem_addr_expr(regs: &mut RegFile, insn: &Instruction) -> Expr {
    let base: Register = insn.memory_base();
    let index: Register = insn.memory_index();
    let scale: u64 = u64::from(insn.memory_index_scale());
    let disp: u64 = insn.memory_displacement64();
    let base_term: Option<Expr> = (base != Register::None).then(|| regs.current(base));
    let index_term: Option<Expr> = (index != Register::None).then(|| {
        if scale <= 1 {
            regs.current(index)
        } else {
            Expr::mul(Expr::konst(scale), regs.current(index))
        }
    });
    let acc: Option<Expr> = match (base_term, index_term) {
        (Some(b), Some(i)) => Some(Expr::add(b, i)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    };
    match acc {
        Some(existing) if disp == 0 => existing,
        Some(existing) => Expr::add(existing, Expr::konst(disp)),
        None => Expr::konst(disp),
    }
}

#[must_use]
pub fn mem_access_width(insn: &Instruction) -> Width {
    match insn.memory_size().size() {
        1 => Width::W8,
        2 => Width::W16,
        4 => Width::W32,
        _ => Width::W64,
    }
}

fn width_for_register(reg: Register) -> Width {
    match reg.size() {
        1 => Width::W8,
        2 => Width::W16,
        4 => Width::W32,
        _ => Width::W64,
    }
}

fn read_immediate(insn: &Instruction, operand: u32) -> Option<u64> {
    match insn.op_kind(operand) {
        OpKind::Immediate8 => Some(u64::from(insn.immediate8())),
        OpKind::Immediate16 => Some(u64::from(insn.immediate16())),
        OpKind::Immediate32 => Some(u64::from(insn.immediate32())),
        OpKind::Immediate64 => Some(insn.immediate64()),
        OpKind::Immediate8to16 => Some(insn.immediate8to16().cast_unsigned().into()),
        OpKind::Immediate8to32 => Some(insn.immediate8to32().cast_unsigned().into()),
        OpKind::Immediate8to64 => Some(insn.immediate8to64().cast_unsigned()),
        OpKind::Immediate32to64 => Some(insn.immediate32to64().cast_unsigned()),
        _ => None,
    }
}

fn source_expr(regs: &mut RegFile, insn: &Instruction) -> Option<Expr> {
    match insn.op1_kind() {
        OpKind::Register => Some(regs.current(insn.op1_register())),
        OpKind::Memory => Some(match stack_cell(insn) {
            Some(cell) => regs.read_mem(cell),
            None => {
                let addr: Expr = mem_addr_expr(regs, insn);
                regs.read_general_mem(addr, mem_access_width(insn))
            }
        }),
        _ => read_immediate(insn, 1).map(Expr::konst),
    }
}

fn source_width(insn: &Instruction) -> Width {
    match insn.op1_kind() {
        OpKind::Register => width_for_register(insn.op1_register()),
        OpKind::Memory => mem_access_width(insn),
        _ => Width::W64,
    }
}

#[must_use]
pub fn operand_expr(regs: &mut RegFile, insn: &Instruction, operand: u32) -> Option<Expr> {
    match insn.op_kind(operand) {
        OpKind::Register => Some(regs.current(insn.op_register(operand))),
        OpKind::Memory => Some(match stack_cell(insn) {
            Some(cell) => regs.read_mem(cell),
            None => {
                let addr: Expr = mem_addr_expr(regs, insn);
                regs.read_general_mem(addr, mem_access_width(insn))
            }
        }),
        _ => read_immediate(insn, operand).map(Expr::konst),
    }
}

#[must_use]
pub fn lift_operand_pair(prefix: &[Instruction], insn: &Instruction) -> Option<(Expr, Expr)> {
    if prefix.len() > MAX_LIFT_INSNS {
        return None;
    }
    let mut regs: RegFile = RegFile::new();
    for step in prefix {
        if !apply_arith(&mut regs, step) {
            return None;
        }
    }
    let left: Expr = operand_expr(&mut regs, insn, 0)?;
    let right: Expr = operand_expr(&mut regs, insn, 1)?;
    if regs.capped {
        return None;
    }
    Some((left, right))
}

#[must_use]
pub fn lift_arith_value(insns: &[Instruction], dest: Register) -> Option<(Expr, Width)> {
    if insns.is_empty() || insns.len() > MAX_LIFT_INSNS {
        return None;
    }
    let mut regs: RegFile = RegFile::new();
    let mut width: Width = width_for_register(dest);
    for insn in insns {
        if !apply_arith(&mut regs, insn) {
            return None;
        }
        if insn.op_count() >= 1 && insn.op0_kind() == OpKind::Register {
            width = width_for_register(insn.op0_register());
        }
    }
    if regs.capped {
        return None;
    }
    let value: Expr = regs.current(dest);
    Some((value, width))
}

const fn is_flag_only(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Nop
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Ret
            | Mnemonic::Cmp
            | Mnemonic::Test
            | Mnemonic::Sete
            | Mnemonic::Setne
            | Mnemonic::Setl
            | Mnemonic::Setle
            | Mnemonic::Setg
            | Mnemonic::Setge
            | Mnemonic::Setb
            | Mnemonic::Setbe
            | Mnemonic::Seta
            | Mnemonic::Setae
    )
}

fn apply_arith(regs: &mut RegFile, insn: &Instruction) -> bool {
    let mnemonic: Mnemonic = insn.mnemonic();
    if is_flag_only(mnemonic) {
        return true;
    }
    if mnemonic == Mnemonic::Mov && insn.op0_kind() == OpKind::Memory {
        let Some(src): Option<Expr> = source_expr(regs, insn) else {
            return false;
        };
        match stack_cell(insn) {
            Some(cell) => regs.write_mem(cell, src),
            None => {
                let addr: Expr = mem_addr_expr(regs, insn);
                regs.write_general_mem(addr, mem_access_width(insn), src);
            }
        }
        return true;
    }
    if insn.op0_kind() != OpKind::Register {
        return false;
    }
    let dest: Register = insn.op0_register();
    match mnemonic {
        Mnemonic::Mov => {
            let Some(src): Option<Expr> = source_expr(regs, insn) else {
                return false;
            };
            regs.write_reg(dest, src);
            true
        }
        Mnemonic::Movzx => {
            let Some(src): Option<Expr> = source_expr(regs, insn) else {
                return false;
            };
            let mask: u64 = source_width(insn).mask();
            regs.write_reg(dest, Expr::and(src, Expr::konst(mask)));
            true
        }
        Mnemonic::Xchg => {
            if insn.op1_kind() != OpKind::Register {
                return false;
            }
            let other: Register = insn.op1_register();
            let dest_value: Expr = regs.current(dest);
            let other_value: Expr = regs.current(other);
            regs.write_reg(dest, other_value);
            regs.write_reg(other, dest_value);
            true
        }
        Mnemonic::Add => binary(regs, insn, dest, BinOp::Add),
        Mnemonic::Sub => binary(regs, insn, dest, BinOp::Sub),
        Mnemonic::Imul | Mnemonic::Mul => binary(regs, insn, dest, BinOp::Mul),
        Mnemonic::And => binary(regs, insn, dest, BinOp::And),
        Mnemonic::Or => binary(regs, insn, dest, BinOp::Or),
        Mnemonic::Xor => binary(regs, insn, dest, BinOp::Xor),
        Mnemonic::Shl => binary(regs, insn, dest, BinOp::Shl),
        Mnemonic::Shr => binary(regs, insn, dest, BinOp::Shr),
        Mnemonic::Lea => lift_lea(regs, insn, dest),
        Mnemonic::Neg => {
            let current: Expr = regs.current(dest);
            regs.write_reg(dest, Expr::Unary(UnOp::Neg, Box::new(current)));
            true
        }
        Mnemonic::Not => {
            let current: Expr = regs.current(dest);
            regs.write_reg(dest, Expr::Unary(UnOp::Not, Box::new(current)));
            true
        }
        Mnemonic::Inc => {
            let current: Expr = regs.current(dest);
            regs.write_reg(dest, Expr::add(current, Expr::konst(1)));
            true
        }
        Mnemonic::Dec => {
            let current: Expr = regs.current(dest);
            regs.write_reg(dest, Expr::sub(current, Expr::konst(1)));
            true
        }
        _ => false,
    }
}

fn binary(regs: &mut RegFile, insn: &Instruction, dest: Register, op: BinOp) -> bool {
    let lhs: Expr = regs.current(dest);
    let Some(rhs): Option<Expr> = source_expr(regs, insn) else {
        return false;
    };
    regs.write_reg(dest, Expr::Binary(op, Box::new(lhs), Box::new(rhs)));
    true
}

fn lift_lea(regs: &mut RegFile, insn: &Instruction, dest: Register) -> bool {
    if insn.op1_kind() != OpKind::Memory {
        return false;
    }
    let base: Register = insn.memory_base();
    let index: Register = insn.memory_index();
    let scale: u64 = u64::from(insn.memory_index_scale());
    let disp: u64 = insn.memory_displacement64();
    let base_term: Option<Expr> = (base != Register::None).then(|| regs.current(base));
    let index_term: Option<Expr> = (index != Register::None).then(|| {
        if scale <= 1 {
            regs.current(index)
        } else {
            Expr::mul(Expr::konst(scale), regs.current(index))
        }
    });
    let acc: Option<Expr> = match (base_term, index_term) {
        (Some(b), Some(i)) => Some(Expr::add(b, i)),
        (Some(only), None) | (None, Some(only)) => Some(only),
        (None, None) => None,
    };
    let value: Expr = match acc {
        Some(existing) if disp == 0 => existing,
        Some(existing) => Expr::add(existing, Expr::konst(disp)),
        None => Expr::konst(disp),
    };
    regs.write_reg(dest, value);
    true
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_mba::equivalent_exhaustive;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder: Decoder<'_> = Decoder::with_ip(64, bytes, 0x1000, DecoderOptions::NONE);
        let mut out: Vec<Instruction> = Vec::new();
        while decoder.can_decode() {
            let mut insn: Instruction = Instruction::default();
            decoder.decode_out(&mut insn);
            out.push(insn);
        }
        out
    }

    #[test]
    fn lifts_add_chain_to_expr() {
        let bytes: [u8; 6] = [0x89, 0xF8, 0x01, 0xD8, 0x83, 0xC0];
        let mut full: Vec<u8> = bytes[..4].to_vec();
        full.extend_from_slice(&[0x83, 0xC0, 0x05]);
        let insns: Vec<Instruction> = decode(&full);
        let (expr, width): (Expr, Width) =
            lift_arith_value(&insns, Register::EAX).expect("lifted eax");
        assert_eq!(width, Width::W32);
        assert!(expr.node_count() >= 3);
    }

    #[test]
    fn xor_self_lifts_to_zero_under_simplify() {
        let bytes: [u8; 2] = [0x31, 0xC0];
        let insns: Vec<Instruction> = decode(&bytes);
        let (expr, width): (Expr, Width) =
            lift_arith_value(&insns, Register::EAX).expect("lifted eax");
        let simplified: disrobe_mba::Simplification = disrobe_mba::simplify(&expr, width);
        assert!(
            equivalent_exhaustive(&simplified.simplified, &Expr::konst(0), Width::W8, 1),
            "xor eax,eax must lift to a value equal to 0, got {expr}"
        );
    }

    #[test]
    fn movzx_zero_extends_and_masks_source_width() {
        let bytes: [u8; 3] = [0x0F, 0xB6, 0xC1];
        let insns: Vec<Instruction> = decode(&bytes);
        let (expr, _width): (Expr, Width) =
            lift_arith_value(&insns, Register::EAX).expect("movzx lifts");
        assert_eq!(expr.eval(&[0x1234], Width::W32), 0x34);
    }

    #[test]
    fn xchg_swaps_register_bindings() {
        let mut prep: Vec<u8> = vec![0xB8, 0x07, 0x00, 0x00, 0x00];
        prep.extend_from_slice(&[0xBA, 0x09, 0x00, 0x00, 0x00]);
        prep.extend_from_slice(&[0x92]);
        let insns: Vec<Instruction> = decode(&prep);
        let (eax_expr, _w0): (Expr, Width) =
            lift_arith_value(&insns, Register::EAX).expect("eax after xchg");
        let (edx_expr, _w1): (Expr, Width) =
            lift_arith_value(&insns, Register::EDX).expect("edx after xchg");
        assert_eq!(eax_expr.eval(&[], Width::W32), 9);
        assert_eq!(edx_expr.eval(&[], Width::W32), 7);
    }

    #[test]
    fn add_self_chain_is_capped_not_exponential() {
        let bytes: Vec<u8> = (0..200u32).flat_map(|_| [0x01u8, 0xC0]).collect();
        let insns: Vec<Instruction> = decode(&bytes);
        assert!(
            lift_arith_value(&insns, Register::EAX).is_none(),
            "a long add-self chain must hit the node cap and bail, not blow up"
        );
    }
}
