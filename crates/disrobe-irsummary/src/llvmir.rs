use std::collections::BTreeMap;
use std::fmt;

use disrobe_mba::{BinOp, CmpOp, Expr, Predicate, UnOp, Width};

use crate::optimize::optimize_graph;
use crate::symexec::{Location, NirSummary};
use crate::valuegraph::{IcmpKind, Inst, Operand, UnaryKind, ValueGraph};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlvmModule {
    text: String,
    function_name: String,
    argument_count: usize,
    instruction_count: usize,
    graph: ValueGraph,
    parameters: String,
}

impl LlvmModule {
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    #[must_use]
    pub fn function_name(&self) -> &str {
        &self.function_name
    }

    #[must_use]
    pub const fn argument_count(&self) -> usize {
        self.argument_count
    }

    #[must_use]
    pub const fn instruction_count(&self) -> usize {
        self.instruction_count
    }

    #[must_use]
    pub fn optimized(&self) -> Self {
        let graph: ValueGraph = optimize_graph(&self.graph);
        let text: String = graph.render(&self.function_name, &self.parameters);
        let instruction_count: usize = graph.instruction_count();
        Self {
            text,
            function_name: self.function_name.clone(),
            argument_count: self.argument_count,
            instruction_count,
            graph,
            parameters: self.parameters.clone(),
        }
    }
}

impl fmt::Display for LlvmModule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LlvmEmitError {
    NoOutputs,
    UnboundVariable(u32),
    UnsupportedNode(&'static str),
    SliceOutOfRange { lo: u32, hi: u32 },
    TooManyArguments(usize),
    Format,
}

impl fmt::Display for LlvmEmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOutputs => f.write_str("summary has no output expressions to emit"),
            Self::UnboundVariable(index) => {
                write!(f, "variable v{index} is not bound to a function argument")
            }
            Self::UnsupportedNode(kind) => write!(f, "unsupported expression node: {kind}"),
            Self::SliceOutOfRange { lo, hi } => {
                write!(f, "slice bounds out of range: lo={lo} hi={hi}")
            }
            Self::TooManyArguments(count) => {
                write!(f, "too many function arguments to encode: {count}")
            }
            Self::Format => f.write_str("failed to format the emitted module text"),
        }
    }
}

impl std::error::Error for LlvmEmitError {}

#[must_use]
pub const fn llvm_int_ty(width: Width) -> &'static str {
    match width {
        Width::W1 => "i1",
        Width::W2 => "i2",
        Width::W4 => "i4",
        Width::W8 => "i8",
        Width::W16 => "i16",
        Width::W32 => "i32",
        Width::W64 => "i64",
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Hash {
    Const(u64),
    Arg(u32),
    Unary(UnOp, Box<Self>),
    Binary(BinOp, Box<Self>, Box<Self>),
    Select(Box<Self>, Box<Self>, Box<Self>),
    Slice(Box<Self>, u32, u32),
    Compose(Box<Self>, Box<Self>, u32),
    Load(Box<Self>, u32),
}

#[derive(Debug)]
struct Emitter<'ctx> {
    arg_index: &'ctx BTreeMap<u32, usize>,
    conditions: &'ctx BTreeMap<u32, Predicate>,
    width_bits: u32,
    insts: BTreeMap<u32, Inst>,
    order: Vec<u32>,
    cache: BTreeMap<Hash, Operand>,
    next_id: u32,
}

impl Emitter<'_> {
    const fn fresh(&mut self) -> u32 {
        let id: u32 = self.next_id;
        self.next_id += 1;
        id
    }

    fn structural_hash(expr: &Expr) -> Hash {
        match expr {
            Expr::Const(value) => Hash::Const(*value),
            Expr::Var(index) => Hash::Arg(*index),
            Expr::Unary(op, inner) => Hash::Unary(*op, Box::new(Self::structural_hash(inner))),
            Expr::Binary(op, left, right) => Hash::Binary(
                *op,
                Box::new(Self::structural_hash(left)),
                Box::new(Self::structural_hash(right)),
            ),
            Expr::Ite(cond, then, otherwise) => Hash::Select(
                Box::new(Self::structural_hash(cond)),
                Box::new(Self::structural_hash(then)),
                Box::new(Self::structural_hash(otherwise)),
            ),
            Expr::Slice(inner, lo, hi) => {
                Hash::Slice(Box::new(Self::structural_hash(inner)), *lo, *hi)
            }
            Expr::Compose(low, high, low_bits) => Hash::Compose(
                Box::new(Self::structural_hash(low)),
                Box::new(Self::structural_hash(high)),
                *low_bits,
            ),
            Expr::Mem(addr, load_width) => {
                Hash::Load(Box::new(Self::structural_hash(addr)), load_width.bits())
            }
        }
    }

    fn push(&mut self, inst: Inst) -> Operand {
        let id: u32 = self.fresh();
        self.insts.insert(id, inst);
        self.order.push(id);
        Operand::Value(id)
    }

    fn lower(&mut self, expr: &Expr) -> Result<Operand, LlvmEmitError> {
        if let Expr::Const(value) = expr {
            return Ok(Operand::Literal(*value));
        }
        let key: Hash = Self::structural_hash(expr);
        if let Some(cached) = self.cache.get(&key) {
            return Ok(*cached);
        }
        let operand: Operand = self.lower_uncached(expr)?;
        self.cache.insert(key, operand);
        Ok(operand)
    }

    fn lower_uncached(&mut self, expr: &Expr) -> Result<Operand, LlvmEmitError> {
        match expr {
            Expr::Const(value) => Ok(Operand::Literal(*value)),
            Expr::Var(index) => {
                if let Some(arg) = self.arg_index.get(index) {
                    return Ok(Operand::Value(arg_value_id(*arg)?));
                }
                if let Some(predicate) = self.conditions.get(index) {
                    let cloned: Predicate = predicate.clone();
                    let truth: Operand = self.lower_predicate(&cloned)?;
                    return Ok(self.push(Inst::Zext {
                        source: truth,
                        from_bits: 1,
                        to_bits: self.width_bits,
                    }));
                }
                Err(LlvmEmitError::UnboundVariable(*index))
            }
            Expr::Unary(op, inner) => self.lower_unary(*op, inner),
            Expr::Binary(op, left, right) => self.lower_binary(*op, left, right),
            Expr::Ite(cond, then, otherwise) => self.lower_select(cond, then, otherwise),
            Expr::Slice(inner, lo, hi) => self.lower_slice(inner, *lo, *hi),
            Expr::Compose(low, high, low_bits) => self.lower_compose(low, high, *low_bits),
            Expr::Mem(addr, load_width) => self.lower_load(addr, *load_width),
        }
    }

    fn lower_unary(&mut self, op: UnOp, inner: &Expr) -> Result<Operand, LlvmEmitError> {
        let value: Operand = self.lower(inner)?;
        let kind: UnaryKind = match op {
            UnOp::Neg => UnaryKind::Neg,
            UnOp::Not => UnaryKind::Not,
        };
        Ok(self.push(Inst::Unary { op: kind, value }))
    }

    fn lower_binary(
        &mut self,
        op: BinOp,
        left: &Expr,
        right: &Expr,
    ) -> Result<Operand, LlvmEmitError> {
        let lhs: Operand = self.lower(left)?;
        let rhs: Operand = self.lower(right)?;
        Ok(self.push(Inst::Bin { op, lhs, rhs }))
    }

    fn lower_select(
        &mut self,
        cond: &Expr,
        then: &Expr,
        otherwise: &Expr,
    ) -> Result<Operand, LlvmEmitError> {
        let cond_value: Operand = self.lower(cond)?;
        let then_value: Operand = self.lower(then)?;
        let else_value: Operand = self.lower(otherwise)?;
        let predicate: Operand = self.push(Inst::Icmp {
            op: IcmpKind::Ne,
            lhs: cond_value,
            rhs: Operand::Literal(0),
        });
        Ok(self.push(Inst::Select {
            cond: predicate,
            then: then_value,
            otherwise: else_value,
        }))
    }

    fn lower_predicate(&mut self, predicate: &Predicate) -> Result<Operand, LlvmEmitError> {
        match predicate {
            Predicate::Compare { op, left, right } => {
                let lhs: Operand = self.lower(left)?;
                let rhs: Operand = self.lower(right)?;
                Ok(self.push(Inst::Icmp {
                    op: cmp_to_icmp(*op),
                    lhs,
                    rhs,
                }))
            }
            Predicate::Nonzero(inner) => {
                let value: Operand = self.lower(inner)?;
                Ok(self.push(Inst::Icmp {
                    op: IcmpKind::Ne,
                    lhs: value,
                    rhs: Operand::Literal(0),
                }))
            }
            Predicate::Or(left, right) => {
                let l: Operand = self.lower_predicate(left)?;
                let r: Operand = self.lower_predicate(right)?;
                Ok(self.push(Inst::BoolBin {
                    is_and: false,
                    lhs: l,
                    rhs: r,
                }))
            }
            Predicate::And(left, right) => {
                let l: Operand = self.lower_predicate(left)?;
                let r: Operand = self.lower_predicate(right)?;
                Ok(self.push(Inst::BoolBin {
                    is_and: true,
                    lhs: l,
                    rhs: r,
                }))
            }
        }
    }

    fn lower_slice(&mut self, inner: &Expr, lo: u32, hi: u32) -> Result<Operand, LlvmEmitError> {
        if hi <= lo || hi > self.width_bits {
            return Err(LlvmEmitError::SliceOutOfRange { lo, hi });
        }
        let value: Operand = self.lower(inner)?;
        let shifted: Operand = if lo == 0 {
            value
        } else {
            self.push(Inst::Bin {
                op: BinOp::Shr,
                lhs: value,
                rhs: Operand::Literal(u64::from(lo)),
            })
        };
        let field_bits: u32 = hi - lo;
        if field_bits >= self.width_bits {
            return Ok(shifted);
        }
        let truncated: Operand = self.push(Inst::Trunc {
            source: shifted,
            from_bits: self.width_bits,
            to_bits: field_bits,
        });
        Ok(self.push(Inst::Zext {
            source: truncated,
            from_bits: field_bits,
            to_bits: self.width_bits,
        }))
    }

    fn lower_compose(
        &mut self,
        low: &Expr,
        high: &Expr,
        low_bits: u32,
    ) -> Result<Operand, LlvmEmitError> {
        let low_value: Operand = self.lower(low)?;
        let high_value: Operand = self.lower(high)?;
        let low_mask: u64 = if low_bits == 0 {
            0
        } else if low_bits >= 64 {
            u64::MAX
        } else {
            (1u64 << low_bits) - 1
        };
        let masked_low: Operand = self.push(Inst::Bin {
            op: BinOp::And,
            lhs: low_value,
            rhs: Operand::Literal(low_mask),
        });
        let shifted_high: Operand = self.push(Inst::Bin {
            op: BinOp::Shl,
            lhs: high_value,
            rhs: Operand::Literal(u64::from(low_bits)),
        });
        Ok(self.push(Inst::Bin {
            op: BinOp::Or,
            lhs: masked_low,
            rhs: shifted_high,
        }))
    }

    fn lower_load(&mut self, addr: &Expr, load_width: Width) -> Result<Operand, LlvmEmitError> {
        let address: Operand = self.lower(addr)?;
        let pointer: Operand = self.push(Inst::IntToPtr { address });
        let loaded: Operand = self.push(Inst::Load {
            pointer,
            load_bits: load_width.bits(),
        });
        if load_width.bits() == self.width_bits {
            return Ok(loaded);
        }
        Ok(self.push(Inst::Zext {
            source: loaded,
            from_bits: load_width.bits(),
            to_bits: self.width_bits,
        }))
    }
}

pub(crate) fn arg_value_id(arg: usize) -> Result<u32, LlvmEmitError> {
    let offset: u32 = u32::try_from(arg).map_err(|_| LlvmEmitError::TooManyArguments(arg))?;
    ARG_ID_BASE
        .checked_add(offset)
        .ok_or(LlvmEmitError::TooManyArguments(arg))
}

pub(crate) const ARG_ID_BASE: u32 = 0xF000_0000;

const fn cmp_to_icmp(op: CmpOp) -> IcmpKind {
    match op {
        CmpOp::Eq => IcmpKind::Eq,
        CmpOp::Ne => IcmpKind::Ne,
        CmpOp::UnsignedLt => IcmpKind::UnsignedLt,
        CmpOp::UnsignedLe => IcmpKind::UnsignedLe,
        CmpOp::UnsignedGt => IcmpKind::UnsignedGt,
        CmpOp::UnsignedGe => IcmpKind::UnsignedGe,
        CmpOp::SignedLt => IcmpKind::SignedLt,
        CmpOp::SignedLe => IcmpKind::SignedLe,
        CmpOp::SignedGt => IcmpKind::SignedGt,
        CmpOp::SignedGe => IcmpKind::SignedGe,
    }
}

fn primary_output(summary: &NirSummary) -> Option<(&Location, &Expr)> {
    summary
        .outputs
        .iter()
        .find(|(loc, _): &(&Location, &Expr)| matches!(loc, Location::Register(_)))
        .or_else(|| summary.outputs.iter().next())
}

fn build_module(name: &str, summary: &NirSummary) -> Result<LlvmModule, LlvmEmitError> {
    let (_, output): (&Location, &Expr) =
        primary_output(summary).ok_or(LlvmEmitError::NoOutputs)?;

    let ordered_vars: std::collections::BTreeSet<u32> =
        summary.input_seeds.values().copied().collect();
    let arg_index: BTreeMap<u32, usize> = ordered_vars
        .iter()
        .enumerate()
        .map(|(slot, var): (usize, &u32)| (*var, slot))
        .collect();

    let conditions: BTreeMap<u32, Predicate> = summary
        .branches
        .iter()
        .map(|branch: &crate::symexec::BranchFact| (branch.condition_var, branch.predicate.clone()))
        .collect();

    let width: Width = summary.width;
    let width_bits: u32 = width.bits();
    let ty: &'static str = llvm_int_ty(width);

    let mut emitter: Emitter<'_> = Emitter {
        arg_index: &arg_index,
        conditions: &conditions,
        width_bits,
        insts: BTreeMap::new(),
        order: Vec::new(),
        cache: BTreeMap::new(),
        next_id: 0,
    };

    let result: Operand = emitter.lower(output)?;

    let argument_count: usize = arg_index.len();
    let parameters: String = (0..argument_count)
        .map(|slot: usize| arg_value_id(slot).map(|id: u32| format!("{ty} %v{id}")))
        .collect::<Result<Vec<String>, LlvmEmitError>>()?
        .join(", ");

    let sanitized_name: String = sanitize_symbol(name);

    let graph: ValueGraph = ValueGraph {
        insts: emitter.insts,
        order: emitter.order,
        replacements: BTreeMap::new(),
        root: result,
        width,
        argument_count,
    };

    let text: String = graph.render(&sanitized_name, &parameters);
    let instruction_count: usize = graph.instruction_count();

    Ok(LlvmModule {
        text,
        function_name: sanitized_name,
        argument_count,
        instruction_count,
        graph,
        parameters,
    })
}

pub fn emit_llvm_function(name: &str, summary: &NirSummary) -> Result<LlvmModule, LlvmEmitError> {
    build_module(name, summary)
}

pub fn emit_optimized_llvm_function(
    name: &str,
    summary: &NirSummary,
) -> Result<LlvmModule, LlvmEmitError> {
    Ok(build_module(name, summary)?.optimized())
}

fn sanitize_symbol(name: &str) -> String {
    let mut out: String = String::with_capacity(name.len());
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '.' || ch == '$' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("anon");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_value_id_rejects_ids_outside_encoding_range() {
        let first_outside: usize =
            usize::try_from(u32::MAX - ARG_ID_BASE).map_or(usize::MAX, |last: usize| last + 1);
        assert_eq!(arg_value_id(0), Ok(ARG_ID_BASE));
        assert!(matches!(
            arg_value_id(first_outside),
            Err(LlvmEmitError::TooManyArguments(_))
        ));
    }
}
