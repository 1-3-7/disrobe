use std::collections::{BTreeMap, BTreeSet};

use disrobe_mba::{BinOp, Expr, Width};

use crate::llvmir::{ARG_ID_BASE, llvm_int_ty};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Operand {
    Literal(u64),
    Value(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnaryKind {
    Neg,
    Not,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IcmpKind {
    Eq,
    Ne,
    UnsignedLt,
    UnsignedLe,
    UnsignedGt,
    UnsignedGe,
    SignedLt,
    SignedLe,
    SignedGt,
    SignedGe,
}

impl IcmpKind {
    const fn mnemonic(self) -> &'static str {
        match self {
            Self::Eq => "eq",
            Self::Ne => "ne",
            Self::UnsignedLt => "ult",
            Self::UnsignedLe => "ule",
            Self::UnsignedGt => "ugt",
            Self::UnsignedGe => "uge",
            Self::SignedLt => "slt",
            Self::SignedLe => "sle",
            Self::SignedGt => "sgt",
            Self::SignedGe => "sge",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Inst {
    Bin {
        op: BinOp,
        lhs: Operand,
        rhs: Operand,
    },
    Unary {
        op: UnaryKind,
        value: Operand,
    },
    Icmp {
        op: IcmpKind,
        lhs: Operand,
        rhs: Operand,
    },
    BoolBin {
        is_and: bool,
        lhs: Operand,
        rhs: Operand,
    },
    Select {
        cond: Operand,
        then: Operand,
        otherwise: Operand,
    },
    Trunc {
        source: Operand,
        from_bits: u32,
        to_bits: u32,
    },
    Zext {
        source: Operand,
        from_bits: u32,
        to_bits: u32,
    },
    IntToPtr {
        address: Operand,
    },
    Load {
        pointer: Operand,
        load_bits: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueGraph {
    pub(crate) insts: BTreeMap<u32, Inst>,
    pub(crate) order: Vec<u32>,
    pub(crate) replacements: BTreeMap<u32, Operand>,
    pub(crate) root: Operand,
    pub(crate) width: Width,
    pub(crate) argument_count: usize,
}

impl ValueGraph {
    #[must_use]
    pub(crate) fn resolve(&self, operand: Operand) -> Operand {
        let mut current: Operand = operand;
        let mut guard: usize = 0;
        while let Operand::Value(id) = current {
            let Some(next): Option<&Operand> = self.replacements.get(&id) else {
                break;
            };
            if *next == current {
                break;
            }
            current = *next;
            guard += 1;
            if guard > self.replacements.len() + 1 {
                break;
            }
        }
        current
    }

    #[must_use]
    pub(crate) fn live_values(&self) -> BTreeSet<u32> {
        let mut live: BTreeSet<u32> = BTreeSet::new();
        let mut stack: Vec<u32> = Vec::new();
        if let Operand::Value(id) = self.resolve(self.root) {
            stack.push(id);
        }
        while let Some(id) = stack.pop() {
            if !live.insert(id) {
                continue;
            }
            if let Some(inst) = self.insts.get(&id) {
                for operand in inst_operands(inst) {
                    if let Operand::Value(next) = self.resolve(operand) {
                        stack.push(next);
                    }
                }
            }
        }
        live
    }

    #[must_use]
    pub(crate) fn operand_expr(&self, operand: Operand) -> Option<Expr> {
        let mut seen: BTreeSet<u32> = BTreeSet::new();
        self.operand_expr_inner(operand, &mut seen)
    }

    fn operand_expr_inner(&self, operand: Operand, seen: &mut BTreeSet<u32>) -> Option<Expr> {
        match self.resolve(operand) {
            Operand::Literal(value) => Some(Expr::konst(value)),
            Operand::Value(id) => {
                if let Some(slot) = arg_slot(id, self.argument_count) {
                    return Some(Expr::var(slot));
                }
                if !seen.insert(id) {
                    return None;
                }
                let inst: &Inst = self.insts.get(&id)?;
                let built: Option<Expr> = self.inst_expr(inst, seen);
                seen.remove(&id);
                built
            }
        }
    }

    fn inst_expr(&self, inst: &Inst, seen: &mut BTreeSet<u32>) -> Option<Expr> {
        match inst {
            Inst::Bin { op, lhs, rhs } => {
                let left: Expr = self.operand_expr_inner(*lhs, seen)?;
                let right: Expr = self.operand_expr_inner(*rhs, seen)?;
                Some(Expr::Binary(*op, Box::new(left), Box::new(right)))
            }
            Inst::Unary { op, value } => {
                let inner: Expr = self.operand_expr_inner(*value, seen)?;
                Some(match op {
                    UnaryKind::Neg => Expr::neg(inner),
                    UnaryKind::Not => Expr::not(inner),
                })
            }
            Inst::Trunc {
                source, to_bits, ..
            } => {
                let inner: Expr = self.operand_expr_inner(*source, seen)?;
                Some(Expr::slice(inner, 0, (*to_bits).min(self.width.bits())))
            }
            Inst::Zext {
                source, from_bits, ..
            } => {
                let inner: Expr = self.operand_expr_inner(*source, seen)?;
                Some(Expr::slice(inner, 0, (*from_bits).min(self.width.bits())))
            }
            Inst::Select {
                cond,
                then,
                otherwise,
            } => {
                let cond_expr: Expr = self.operand_expr_inner(*cond, seen)?;
                let then_expr: Expr = self.operand_expr_inner(*then, seen)?;
                let else_expr: Expr = self.operand_expr_inner(*otherwise, seen)?;
                Some(Expr::ite(cond_expr, then_expr, else_expr))
            }
            Inst::IntToPtr { address } => self.operand_expr_inner(*address, seen),
            Inst::Load { pointer, load_bits } => {
                let address: Expr = self.pointer_address_expr(*pointer, seen)?;
                let load_width: Width = Width::from_bits(*load_bits)?;
                Some(Expr::mem(address, load_width))
            }
            Inst::Icmp { .. } | Inst::BoolBin { .. } => None,
        }
    }

    fn pointer_address_expr(&self, pointer: Operand, seen: &mut BTreeSet<u32>) -> Option<Expr> {
        if let Operand::Value(id) = self.resolve(pointer)
            && let Some(Inst::IntToPtr { address }) = self.insts.get(&id)
        {
            return self.operand_expr_inner(*address, seen);
        }
        None
    }

    #[must_use]
    pub(crate) fn instruction_count(&self) -> usize {
        self.order
            .iter()
            .filter(|id: &&u32| self.insts.contains_key(id))
            .count()
    }

    #[must_use]
    pub(crate) fn render(&self, name: &str, parameters: &str) -> String {
        let ty: &'static str = llvm_int_ty(self.width);
        let mut text: String = String::new();
        text.push_str("define ");
        text.push_str(ty);
        text.push_str(" @");
        text.push_str(name);
        text.push('(');
        text.push_str(parameters);
        text.push_str(") {\n");
        text.push_str("entry:\n");
        for id in &self.order {
            let Some(inst): Option<&Inst> = self.insts.get(id) else {
                continue;
            };
            let rhs: String = self.render_inst(inst);
            text.push_str("  %v");
            text.push_str(&id.to_string());
            text.push_str(" = ");
            text.push_str(&rhs);
            text.push('\n');
        }
        text.push_str("  ret ");
        text.push_str(ty);
        text.push(' ');
        text.push_str(&self.render_operand(self.resolve(self.root)));
        text.push('\n');
        text.push_str("}\n");
        text
    }

    fn render_operand(&self, operand: Operand) -> String {
        match self.resolve(operand) {
            Operand::Literal(value) => (value & self.width.mask()).to_string(),
            Operand::Value(id) => format!("%v{id}"),
        }
    }

    fn render_inst(&self, inst: &Inst) -> String {
        let ty: &'static str = llvm_int_ty(self.width);
        match inst {
            Inst::Bin { op, lhs, rhs } => {
                let mnemonic: &'static str = bin_mnemonic(*op);
                format!(
                    "{mnemonic} {ty} {}, {}",
                    self.render_operand(*lhs),
                    self.render_operand(*rhs)
                )
            }
            Inst::Unary { op, value } => match op {
                UnaryKind::Neg => format!("sub {ty} 0, {}", self.render_operand(*value)),
                UnaryKind::Not => format!("xor {ty} {}, -1", self.render_operand(*value)),
            },
            Inst::Icmp { op, lhs, rhs } => format!(
                "icmp {} {ty} {}, {}",
                op.mnemonic(),
                self.render_operand(*lhs),
                self.render_operand(*rhs)
            ),
            Inst::BoolBin { is_and, lhs, rhs } => {
                let mnemonic: &'static str = if *is_and { "and" } else { "or" };
                format!(
                    "{mnemonic} i1 {}, {}",
                    self.render_operand(*lhs),
                    self.render_operand(*rhs)
                )
            }
            Inst::Select {
                cond,
                then,
                otherwise,
            } => format!(
                "select i1 {}, {ty} {}, {ty} {}",
                self.render_operand(*cond),
                self.render_operand(*then),
                self.render_operand(*otherwise)
            ),
            Inst::Trunc {
                source,
                from_bits,
                to_bits,
            } => format!(
                "trunc i{from_bits} {} to i{to_bits}",
                self.render_operand(*source)
            ),
            Inst::Zext {
                source,
                from_bits,
                to_bits,
            } => format!(
                "zext i{from_bits} {} to i{to_bits}",
                self.render_operand(*source)
            ),
            Inst::IntToPtr { address } => {
                format!("inttoptr {ty} {} to ptr", self.render_operand(*address))
            }
            Inst::Load { pointer, load_bits } => {
                format!("load i{load_bits}, ptr {}", self.render_operand(*pointer))
            }
        }
    }
}

fn arg_slot(id: u32, argument_count: usize) -> Option<u32> {
    if id < ARG_ID_BASE {
        return None;
    }
    let slot: u32 = id - ARG_ID_BASE;
    let limit: u32 = u32::try_from(argument_count).ok()?;
    (slot < limit).then_some(slot)
}

const fn bin_mnemonic(op: BinOp) -> &'static str {
    match op {
        BinOp::Add => "add",
        BinOp::Sub => "sub",
        BinOp::Mul => "mul",
        BinOp::And => "and",
        BinOp::Or => "or",
        BinOp::Xor => "xor",
        BinOp::Shl => "shl",
        BinOp::Shr => "lshr",
    }
}

fn inst_operands(inst: &Inst) -> Vec<Operand> {
    match inst {
        Inst::Bin { lhs, rhs, .. }
        | Inst::Icmp { lhs, rhs, .. }
        | Inst::BoolBin { lhs, rhs, .. } => vec![*lhs, *rhs],
        Inst::Unary { value, .. } => vec![*value],
        Inst::Select {
            cond,
            then,
            otherwise,
        } => vec![*cond, *then, *otherwise],
        Inst::Trunc { source, .. } | Inst::Zext { source, .. } => vec![*source],
        Inst::IntToPtr { address } => vec![*address],
        Inst::Load { pointer, .. } => vec![*pointer],
    }
}
