use indexmap::IndexMap;
use serde::Serialize;
use smallvec::{SmallVec, smallvec};
use wasmparser::{MemArg, Operator, ValType};

use crate::cfg::{BlockId, CfgBlock, FunctionCfg};
use crate::error::{Error, Result};
use crate::signature::MAX_FUNCTION_LOCALS;
use crate::types::{LoadKind, StoreKind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct ValueId(pub u32);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum ConstVal {
    I32(i32),
    I64(i64),
    F32Bits(u32),
    F64Bits(u64),
    Bytes(Vec<u8>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum OpKind {
    I32Add,
    I32Sub,
    I32Mul,
    I32And,
    I32Or,
    I32Xor,
    I32Shl,
    I32ShrU,
    I32ShrS,
    I32Eq,
    I32Ne,
    I32LtS,
    I32LtU,
    I32GtS,
    I32GtU,
    I32LeS,
    I32LeU,
    I32GeS,
    I32GeU,
    I32DivS,
    I32DivU,
    I32RemS,
    I32RemU,
    I32Rotl,
    I32Rotr,
    I64Add,
    I64Sub,
    I64Mul,
    I64DivS,
    I64DivU,
    I64RemS,
    I64RemU,
    I64And,
    I64Or,
    I64Xor,
    I64Shl,
    I64ShrU,
    I64ShrS,
    I64Rotl,
    I64Rotr,
    I64Eq,
    I64Ne,
    I64LtS,
    I64LtU,
    I64GtS,
    I64GtU,
    I64LeS,
    I64LeU,
    I64GeS,
    I64GeU,
    F32Add,
    F32Sub,
    F32Mul,
    F32Div,
    F32Min,
    F32Max,
    F32Copysign,
    F32Eq,
    F32Ne,
    F32Lt,
    F32Gt,
    F32Le,
    F32Ge,
    F64Add,
    F64Sub,
    F64Mul,
    F64Div,
    F64Min,
    F64Max,
    F64Copysign,
    F64Eq,
    F64Ne,
    F64Lt,
    F64Gt,
    F64Le,
    F64Ge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum UnOp {
    I32Eqz,
    I64Eqz,
    I32Clz,
    I32Ctz,
    I32Popcnt,
    I64Clz,
    I64Ctz,
    I64Popcnt,
    F32Abs,
    F32Neg,
    F32Ceil,
    F32Floor,
    F32Trunc,
    F32Nearest,
    F32Sqrt,
    F64Abs,
    F64Neg,
    F64Ceil,
    F64Floor,
    F64Trunc,
    F64Nearest,
    F64Sqrt,
    I32WrapI64,
    I64ExtendI32S,
    I64ExtendI32U,
    I32Extend8S,
    I32Extend16S,
    I64Extend8S,
    I64Extend16S,
    I64Extend32S,
    I32TruncF32S,
    I32TruncF32U,
    I32TruncF64S,
    I32TruncF64U,
    I64TruncF32S,
    I64TruncF32U,
    I64TruncF64S,
    I64TruncF64U,
    I32TruncSatF32S,
    I32TruncSatF32U,
    I32TruncSatF64S,
    I32TruncSatF64U,
    I64TruncSatF32S,
    I64TruncSatF32U,
    I64TruncSatF64S,
    I64TruncSatF64U,
    F32ConvertI32S,
    F32ConvertI32U,
    F32ConvertI64S,
    F32ConvertI64U,
    F64ConvertI32S,
    F64ConvertI32U,
    F64ConvertI64S,
    F64ConvertI64U,
    F32DemoteF64,
    F64PromoteF32,
    I32ReinterpretF32,
    I64ReinterpretF64,
    F32ReinterpretI32,
    F64ReinterpretI64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct SsaMemArg {
    pub align: u8,
    pub offset: u64,
    pub memory: u32,
}

impl From<MemArg> for SsaMemArg {
    fn from(m: MemArg) -> Self {
        Self {
            align: m.align,
            offset: m.offset,
            memory: m.memory,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub enum ValueDef {
    Param(BlockId, u16),
    Phi {
        block: BlockId,
        operands: SmallVec<[ValueId; 4]>,
    },
    Const(ConstVal),
    Op {
        kind: OpKind,
        args: SmallVec<[ValueId; 3]>,
        #[serde(skip)]
        ty: ValType,
    },
    Unary {
        op: UnOp,
        arg: ValueId,
        #[serde(skip)]
        ty: ValType,
    },
    Select {
        cond: ValueId,
        if_true: ValueId,
        if_false: ValueId,
        #[serde(skip)]
        ty: ValType,
    },
    Load {
        addr: ValueId,
        memarg: SsaMemArg,
        kind: LoadKind,
        #[serde(skip)]
        ty: ValType,
    },
    GlobalGet {
        global: u32,
        #[serde(skip)]
        ty: ValType,
    },
    Call {
        func: u32,
        args: SmallVec<[ValueId; 4]>,
        #[serde(skip)]
        ty: Option<ValType>,
    },
    CallIndirect {
        type_index: u32,
        table: u32,
        callee: ValueId,
        args: SmallVec<[ValueId; 4]>,
        #[serde(skip)]
        ty: Option<ValType>,
    },
    MemorySize {
        mem: u32,
    },
    MemoryGrow {
        mem: u32,
        delta: ValueId,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct BlockTarget {
    pub block: BlockId,
    pub args: SmallVec<[ValueId; 2]>,
}

#[derive(Debug, Clone, Serialize)]
pub enum SsaTerm {
    Return(SmallVec<[ValueId; 1]>),
    Br(BlockTarget),
    BrIf {
        cond: ValueId,
        then_t: BlockTarget,
        else_t: BlockTarget,
    },
    BrTable {
        idx: ValueId,
        targets: Vec<BlockTarget>,
        default: BlockTarget,
    },
    Unreachable,
    Fallthrough(BlockTarget),
}

#[derive(Debug, Clone, Serialize)]
pub struct SideEffect {
    pub addr: ValueId,
    pub val: ValueId,
    pub memarg: SsaMemArg,
    pub kind: StoreKind,
}

#[derive(Debug, Clone, Serialize)]
pub struct GlobalSet {
    pub global: u32,
    pub val: ValueId,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsaBlock {
    pub id: BlockId,
    #[serde(skip)]
    pub params: SmallVec<[ValType; 4]>,
    pub instrs: Vec<ValueId>,
    pub stores: Vec<SideEffect>,
    #[serde(default)]
    pub global_sets: Vec<GlobalSet>,
    pub terminator: SsaTerm,
    pub preds: Vec<BlockId>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsaFunction {
    pub values: Vec<ValueDef>,
    pub blocks: Vec<SsaBlock>,
    pub entry: BlockId,
}

impl SsaFunction {
    pub fn value_def(&self, v: ValueId) -> Option<&ValueDef> {
        self.values.get(v.0 as usize)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct LocalId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct SsaValue {
    pub local: LocalId,
    pub version: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LegacySsaBlock {
    pub block: BlockId,
    pub locals_in: IndexMap<LocalId, SsaValue>,
    pub locals_out: IndexMap<LocalId, SsaValue>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LegacySsaFunction {
    pub blocks: Vec<LegacySsaBlock>,
    pub next_version: u32,
}

#[must_use]
pub fn promote_locals_to_ssa(cfg: &FunctionCfg, local_count: u32) -> LegacySsaFunction {
    let cap: u32 = u32::try_from(MAX_FUNCTION_LOCALS).unwrap_or(u32::MAX);
    let bounded_count: u32 = local_count.min(cap);
    let mut next_version: u32 = 0u32;
    let mut current_versions: IndexMap<LocalId, SsaValue> = IndexMap::new();
    for local in 0..bounded_count {
        let lid: LocalId = LocalId(local);
        current_versions.insert(
            lid,
            SsaValue {
                local: lid,
                version: next_version,
            },
        );
        next_version = next_version.saturating_add(1);
    }

    let blocks: Vec<LegacySsaBlock> = cfg
        .blocks
        .iter()
        .map(|b| LegacySsaBlock {
            block: b.id,
            locals_in: current_versions.clone(),
            locals_out: current_versions.clone(),
        })
        .collect();

    LegacySsaFunction {
        blocks,
        next_version,
    }
}

#[derive(Debug, Default)]
struct Builder {
    values: Vec<ValueDef>,
    blocks: Vec<SsaBlock>,
    current_def: IndexMap<(u32, BlockId), ValueId>,
    incomplete_phis: IndexMap<BlockId, Vec<(u32, ValueId)>>,
    sealed: Vec<bool>,
    preds_of: Vec<Vec<BlockId>>,
}

impl Builder {
    fn new(block_count: usize) -> Self {
        Self {
            values: Vec::with_capacity(block_count * 8),
            blocks: Vec::with_capacity(block_count),
            current_def: IndexMap::new(),
            incomplete_phis: IndexMap::new(),
            sealed: vec![false; block_count],
            preds_of: vec![Vec::new(); block_count],
        }
    }

    fn alloc(&mut self, def: ValueDef) -> ValueId {
        let id: ValueId = ValueId(u32::try_from(self.values.len()).unwrap_or(u32::MAX));
        self.values.push(def);
        id
    }

    fn write_variable(&mut self, var: u32, block: BlockId, value: ValueId) {
        self.current_def.insert((var, block), value);
    }

    fn read_variable(&mut self, var: u32, block: BlockId) -> ValueId {
        if let Some(v) = self.current_def.get(&(var, block)).copied() {
            return v;
        }
        self.read_recursive(var, block)
    }

    fn read_recursive(&mut self, var: u32, block: BlockId) -> ValueId {
        let bidx: usize = block.0 as usize;
        let sealed: bool = self.sealed.get(bidx).copied().unwrap_or(true);
        if !sealed {
            let phi: ValueId = self.alloc(ValueDef::Phi {
                block,
                operands: SmallVec::new(),
            });
            self.incomplete_phis
                .entry(block)
                .or_default()
                .push((var, phi));
            self.write_variable(var, block, phi);
            return phi;
        }
        let preds: Vec<BlockId> = self.preds_of.get(bidx).cloned().unwrap_or_default();
        if preds.len() == 1 {
            let p: BlockId = preds[0];
            let v: ValueId = self.read_variable(var, p);
            self.write_variable(var, block, v);
            return v;
        }
        let phi: ValueId = self.alloc(ValueDef::Phi {
            block,
            operands: SmallVec::new(),
        });
        self.write_variable(var, block, phi);
        self.add_phi_operands(var, phi);
        phi
    }

    fn add_phi_operands(&mut self, var: u32, phi: ValueId) {
        let phi_block: BlockId = match self.values.get(phi.0 as usize) {
            Some(ValueDef::Phi { block, .. }) => *block,
            _ => return,
        };
        let preds: Vec<BlockId> = self
            .preds_of
            .get(phi_block.0 as usize)
            .cloned()
            .unwrap_or_default();
        let mut ops: SmallVec<[ValueId; 4]> = SmallVec::new();
        for p in preds {
            ops.push(self.read_variable(var, p));
        }
        if let Some(ValueDef::Phi { operands, .. }) = self.values.get_mut(phi.0 as usize) {
            *operands = ops;
        }
        self.try_remove_trivial_phi(phi);
    }

    fn try_remove_trivial_phi(&mut self, phi: ValueId) -> ValueId {
        let operands: SmallVec<[ValueId; 4]> = match self.values.get(phi.0 as usize) {
            Some(ValueDef::Phi { operands, .. }) => operands.clone(),
            _ => return phi,
        };
        let mut same: Option<ValueId> = None;
        for op in &operands {
            if *op == phi {
                continue;
            }
            if let Some(s) = same {
                if s != *op {
                    return phi;
                }
            } else {
                same = Some(*op);
            }
        }
        let replacement: ValueId = same.unwrap_or(phi);
        for slot in &mut self.values {
            replace_value(slot, phi, replacement);
        }
        for v in self.current_def.values_mut() {
            if *v == phi {
                *v = replacement;
            }
        }
        replacement
    }

    fn seal_block(&mut self, block: BlockId) {
        let bidx: usize = block.0 as usize;
        if let Some(slot) = self.sealed.get_mut(bidx) {
            if *slot {
                return;
            }
            *slot = true;
        }
        if let Some(phis) = self.incomplete_phis.shift_remove(&block) {
            for (var, phi) in phis {
                self.add_phi_operands(var, phi);
            }
        }
    }
}

fn replace_value(def: &mut ValueDef, from: ValueId, to: ValueId) {
    match def {
        ValueDef::Phi { operands, .. } => {
            for op in operands.iter_mut() {
                if *op == from {
                    *op = to;
                }
            }
        }
        ValueDef::Op { args, .. } => {
            for a in args.iter_mut() {
                if *a == from {
                    *a = to;
                }
            }
        }
        ValueDef::Unary { arg, .. } => {
            if *arg == from {
                *arg = to;
            }
        }
        ValueDef::Select {
            cond,
            if_true,
            if_false,
            ..
        } => {
            for slot in [cond, if_true, if_false] {
                if *slot == from {
                    *slot = to;
                }
            }
        }
        ValueDef::Load { addr, .. } => {
            if *addr == from {
                *addr = to;
            }
        }
        ValueDef::Call { args, .. } => {
            for a in args.iter_mut() {
                if *a == from {
                    *a = to;
                }
            }
        }
        ValueDef::CallIndirect { callee, args, .. } => {
            if *callee == from {
                *callee = to;
            }
            for a in args.iter_mut() {
                if *a == from {
                    *a = to;
                }
            }
        }
        ValueDef::MemoryGrow { delta, .. } => {
            if *delta == from {
                *delta = to;
            }
        }
        ValueDef::Param(..)
        | ValueDef::Const(_)
        | ValueDef::GlobalGet { .. }
        | ValueDef::MemorySize { .. } => {}
    }
}

fn expand_locals(locals_iter: &[(u32, ValType)], params: &[ValType]) -> Vec<ValType> {
    let mut out: Vec<ValType> = params.to_vec();
    for (count, ty) in locals_iter {
        let remaining: usize = MAX_FUNCTION_LOCALS.saturating_sub(out.len());
        let take: usize = (*count as usize).min(remaining);
        out.extend(std::iter::repeat_n(*ty, take));
        if out.len() >= MAX_FUNCTION_LOCALS {
            break;
        }
    }
    out
}

fn build_preds(cfg: &FunctionCfg) -> Vec<Vec<BlockId>> {
    let mut preds: Vec<Vec<BlockId>> = vec![Vec::new(); cfg.blocks.len()];
    for edge in &cfg.edges {
        let tidx: usize = edge.to.0 as usize;
        if let Some(v) = preds.get_mut(tidx) {
            v.push(edge.from);
        }
    }
    preds
}

fn block_for_offset(blocks: &[CfgBlock], offset: usize, cursor: &mut usize) -> Option<BlockId> {
    let last: usize = blocks.len().checked_sub(1)?;
    while *cursor < last {
        let Some(end): Option<usize> = blocks.get(*cursor).map(|b| b.end_offset) else {
            break;
        };
        if offset <= end {
            break;
        }
        *cursor += 1;
    }
    blocks.get(*cursor).map(|b| b.id)
}

type CallSig = (SmallVec<[ValType; 4]>, SmallVec<[ValType; 1]>);

#[derive(Debug, Clone, Default)]
pub struct CallSignatures {
    sigs: Vec<CallSig>,
}

impl CallSignatures {
    #[must_use]
    pub fn new(sigs: Vec<(Vec<ValType>, Vec<ValType>)>) -> Self {
        Self {
            sigs: sigs
                .into_iter()
                .map(|(p, r)| (SmallVec::from_vec(p), SmallVec::from_vec(r)))
                .collect(),
        }
    }

    fn param_count(&self, function_index: u32) -> Option<usize> {
        self.sigs.get(function_index as usize).map(|(p, _)| p.len())
    }

    fn result_type(&self, function_index: u32) -> Option<ValType> {
        self.sigs
            .get(function_index as usize)
            .and_then(|(_, r)| r.first().copied())
    }

    fn type_result(&self, type_index: u32) -> Option<ValType> {
        self.sigs
            .get(type_index as usize)
            .and_then(|(_, r)| r.first().copied())
    }
}

pub fn build_ssa(
    cfg: &FunctionCfg,
    body: &wasmparser::FunctionBody<'_>,
    params: &[ValType],
) -> Result<SsaFunction> {
    build_ssa_with_calls(cfg, body, params, &CallSignatures::default())
}

pub fn build_ssa_with_calls(
    cfg: &FunctionCfg,
    body: &wasmparser::FunctionBody<'_>,
    params: &[ValType],
    call_sigs: &CallSignatures,
) -> Result<SsaFunction> {
    if cfg.blocks.is_empty() {
        return Ok(SsaFunction {
            values: Vec::new(),
            blocks: Vec::new(),
            entry: BlockId(0),
        });
    }

    let locals_reader: wasmparser::LocalsReader<'_> = body
        .get_locals_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;
    let mut locals_pairs: Vec<(u32, ValType)> = Vec::new();
    for item in locals_reader {
        let pair: (u32, ValType) = item.map_err(|e| Error::Parse(e.to_string()))?;
        locals_pairs.push(pair);
    }
    let all_locals: Vec<ValType> = expand_locals(&locals_pairs, params);

    let mut builder: Builder = Builder::new(cfg.blocks.len());
    builder.preds_of = build_preds(cfg);

    for b in &cfg.blocks {
        builder.blocks.push(SsaBlock {
            id: b.id,
            params: SmallVec::new(),
            instrs: Vec::new(),
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Unreachable,
            preds: builder
                .preds_of
                .get(b.id.0 as usize)
                .cloned()
                .unwrap_or_default(),
        });
    }

    for (i, ty) in all_locals.iter().enumerate() {
        let var: u32 = u32::try_from(i).unwrap_or(u32::MAX);
        if i < params.len() {
            let param_idx: u16 = u16::try_from(i).unwrap_or(u16::MAX);
            let param: ValueId = builder.alloc(ValueDef::Param(cfg.entry, param_idx));
            builder.write_variable(var, cfg.entry, param);
            if let Some(entry_block) = builder.blocks.get_mut(cfg.entry.0 as usize) {
                entry_block.params.push(*ty);
                entry_block.instrs.push(param);
            }
        } else {
            let zero: ValueId = match ty {
                ValType::I64 => builder.alloc(ValueDef::Const(ConstVal::I64(0))),
                ValType::F32 => builder.alloc(ValueDef::Const(ConstVal::F32Bits(0))),
                ValType::F64 => builder.alloc(ValueDef::Const(ConstVal::F64Bits(0))),
                _ => builder.alloc(ValueDef::Const(ConstVal::I32(0))),
            };
            builder.write_variable(var, cfg.entry, zero);
            if let Some(entry_block) = builder.blocks.get_mut(cfg.entry.0 as usize) {
                entry_block.instrs.push(zero);
            }
        }
    }

    let mut stack: Vec<ValueId> = Vec::new();
    let ops_reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .map_err(|e| Error::Parse(e.to_string()))?;

    let mut current_block: BlockId = cfg.entry;
    let mut produced_terminator: bool = false;
    let mut block_cursor: usize = 0;

    for op_result in ops_reader.into_iter_with_offsets() {
        let (op, offset): (Operator<'_>, usize) =
            op_result.map_err(|e| Error::Parse(e.to_string()))?;
        if let Some(b) = block_for_offset(&cfg.blocks, offset, &mut block_cursor) {
            if b != current_block {
                if !produced_terminator {
                    if let Some(prev) = builder.blocks.get_mut(current_block.0 as usize) {
                        prev.terminator = SsaTerm::Fallthrough(BlockTarget {
                            block: b,
                            args: SmallVec::from_vec(stack.clone()),
                        });
                    }
                }
                builder.seal_block(current_block);
                current_block = b;
                produced_terminator = false;
            }
        }

        lift_op(
            &op,
            &mut stack,
            &mut builder,
            current_block,
            &mut produced_terminator,
            call_sigs,
        )?;
    }

    if !produced_terminator {
        if let Some(last) = builder.blocks.get_mut(current_block.0 as usize) {
            last.terminator = SsaTerm::Return(SmallVec::from_vec(stack.clone()));
        }
    }

    for bidx in 0..builder.blocks.len() {
        builder.seal_block(BlockId(u32::try_from(bidx).unwrap_or(u32::MAX)));
    }

    Ok(SsaFunction {
        values: builder.values,
        blocks: builder.blocks,
        entry: cfg.entry,
    })
}

fn lift_op(
    op: &Operator<'_>,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
    produced_terminator: &mut bool,
    call_sigs: &CallSignatures,
) -> Result<()> {
    if lift_control(op, stack, b, block, produced_terminator)? {
        return Ok(());
    }
    if lift_locals_consts(op, stack, b, block)? {
        return Ok(());
    }
    if let Some((kind, ty)) = binop_kind(op) {
        lift_binop(kind, ty, stack, b, block)?;
        return Ok(());
    }
    if let Some((unop, ty)) = unop_kind(op) {
        lift_unop(unop, ty, stack, b, block)?;
        return Ok(());
    }
    if lift_call_and_memory(op, stack, b, block, call_sigs)? {
        return Ok(());
    }
    if let Some((kind, ty, memarg)) = load_descriptor(op) {
        lift_load(kind, ty, memarg, stack, b, block)?;
        return Ok(());
    }
    if let Some((kind, memarg)) = store_descriptor(op) {
        lift_store(kind, memarg, stack, b, block)?;
        return Ok(());
    }
    Err(Error::Parse(format!(
        "DR-WASMDEOB-SSA: unsupported operator ({:?})",
        core::mem::discriminant(op)
    )))
}

fn lift_control(
    op: &Operator<'_>,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
    produced_terminator: &mut bool,
) -> Result<bool> {
    match op {
        Operator::Nop
        | Operator::Block { .. }
        | Operator::Loop { .. }
        | Operator::Else
        | Operator::End => Ok(true),
        Operator::If { .. } => {
            let cond: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at if".into()))?;
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.terminator = SsaTerm::BrIf {
                    cond,
                    then_t: BlockTarget {
                        block,
                        args: SmallVec::new(),
                    },
                    else_t: BlockTarget {
                        block,
                        args: SmallVec::new(),
                    },
                };
            }
            *produced_terminator = true;
            Ok(true)
        }
        Operator::Return => {
            let vals: SmallVec<[ValueId; 1]> = SmallVec::from_vec(core::mem::take(stack));
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.terminator = SsaTerm::Return(vals);
            }
            *produced_terminator = true;
            Ok(true)
        }
        Operator::Unreachable => {
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.terminator = SsaTerm::Unreachable;
            }
            *produced_terminator = true;
            Ok(true)
        }
        Operator::Br { relative_depth } => {
            let target: BlockId = BlockId(*relative_depth);
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.terminator = SsaTerm::Br(BlockTarget {
                    block: target,
                    args: SmallVec::from_vec(stack.clone()),
                });
            }
            *produced_terminator = true;
            Ok(true)
        }
        Operator::BrIf { relative_depth } => {
            let cond: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at br_if".into()))?;
            let target: BlockId = BlockId(*relative_depth);
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.terminator = SsaTerm::BrIf {
                    cond,
                    then_t: BlockTarget {
                        block: target,
                        args: SmallVec::from_vec(stack.clone()),
                    },
                    else_t: BlockTarget {
                        block,
                        args: SmallVec::new(),
                    },
                };
            }
            *produced_terminator = true;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn lift_locals_consts(
    op: &Operator<'_>,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<bool> {
    match op {
        Operator::Drop => {
            stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at drop".into()))?;
            Ok(true)
        }
        Operator::Select | Operator::TypedSelect { .. } | Operator::TypedSelectMulti { .. } => {
            let cond: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let if_false: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let if_true: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let v: ValueId = b.alloc(ValueDef::Select {
                cond,
                if_true,
                if_false,
                ty: ValType::I32,
            });
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::LocalGet { local_index } => {
            let v: ValueId = b.read_variable(*local_index, block);
            stack.push(v);
            Ok(true)
        }
        Operator::LocalSet { local_index } => {
            let v: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at local.set".into()))?;
            b.write_variable(*local_index, block, v);
            Ok(true)
        }
        Operator::LocalTee { local_index } => {
            let v: ValueId = *stack
                .last()
                .ok_or_else(|| Error::Parse("stack underflow at local.tee".into()))?;
            b.write_variable(*local_index, block, v);
            Ok(true)
        }
        Operator::GlobalGet { global_index } => {
            let v: ValueId = b.alloc(ValueDef::GlobalGet {
                global: *global_index,
                ty: ValType::I32,
            });
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::GlobalSet { global_index } => {
            let val: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at global.set".into()))?;
            if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.global_sets.push(GlobalSet {
                    global: *global_index,
                    val,
                });
            }
            Ok(true)
        }
        Operator::I32Const { value } => {
            let v: ValueId = b.alloc(ValueDef::Const(ConstVal::I32(*value)));
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::I64Const { value } => {
            let v: ValueId = b.alloc(ValueDef::Const(ConstVal::I64(*value)));
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::F32Const { value } => {
            let v: ValueId = b.alloc(ValueDef::Const(ConstVal::F32Bits(value.bits())));
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::F64Const { value } => {
            let v: ValueId = b.alloc(ValueDef::Const(ConstVal::F64Bits(value.bits())));
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn push_to_block(stack: &mut Vec<ValueId>, b: &mut Builder, block: BlockId, v: ValueId) {
    stack.push(v);
    if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
        blk.instrs.push(v);
    }
}

pub(crate) const fn binop_kind(op: &Operator<'_>) -> Option<(OpKind, ValType)> {
    Some(match op {
        Operator::I32Add => (OpKind::I32Add, ValType::I32),
        Operator::I32Sub => (OpKind::I32Sub, ValType::I32),
        Operator::I32Mul => (OpKind::I32Mul, ValType::I32),
        Operator::I32DivS => (OpKind::I32DivS, ValType::I32),
        Operator::I32DivU => (OpKind::I32DivU, ValType::I32),
        Operator::I32RemS => (OpKind::I32RemS, ValType::I32),
        Operator::I32RemU => (OpKind::I32RemU, ValType::I32),
        Operator::I32And => (OpKind::I32And, ValType::I32),
        Operator::I32Or => (OpKind::I32Or, ValType::I32),
        Operator::I32Xor => (OpKind::I32Xor, ValType::I32),
        Operator::I32Shl => (OpKind::I32Shl, ValType::I32),
        Operator::I32ShrU => (OpKind::I32ShrU, ValType::I32),
        Operator::I32ShrS => (OpKind::I32ShrS, ValType::I32),
        Operator::I32Rotl => (OpKind::I32Rotl, ValType::I32),
        Operator::I32Rotr => (OpKind::I32Rotr, ValType::I32),
        Operator::I32Eq => (OpKind::I32Eq, ValType::I32),
        Operator::I32Ne => (OpKind::I32Ne, ValType::I32),
        Operator::I32LtS => (OpKind::I32LtS, ValType::I32),
        Operator::I32LtU => (OpKind::I32LtU, ValType::I32),
        Operator::I32GtS => (OpKind::I32GtS, ValType::I32),
        Operator::I32GtU => (OpKind::I32GtU, ValType::I32),
        Operator::I32LeS => (OpKind::I32LeS, ValType::I32),
        Operator::I32LeU => (OpKind::I32LeU, ValType::I32),
        Operator::I32GeS => (OpKind::I32GeS, ValType::I32),
        Operator::I32GeU => (OpKind::I32GeU, ValType::I32),
        Operator::I64Add => (OpKind::I64Add, ValType::I64),
        Operator::I64Sub => (OpKind::I64Sub, ValType::I64),
        Operator::I64Mul => (OpKind::I64Mul, ValType::I64),
        Operator::I64DivS => (OpKind::I64DivS, ValType::I64),
        Operator::I64DivU => (OpKind::I64DivU, ValType::I64),
        Operator::I64RemS => (OpKind::I64RemS, ValType::I64),
        Operator::I64RemU => (OpKind::I64RemU, ValType::I64),
        Operator::I64And => (OpKind::I64And, ValType::I64),
        Operator::I64Or => (OpKind::I64Or, ValType::I64),
        Operator::I64Xor => (OpKind::I64Xor, ValType::I64),
        Operator::I64Shl => (OpKind::I64Shl, ValType::I64),
        Operator::I64ShrU => (OpKind::I64ShrU, ValType::I64),
        Operator::I64ShrS => (OpKind::I64ShrS, ValType::I64),
        Operator::I64Rotl => (OpKind::I64Rotl, ValType::I64),
        Operator::I64Rotr => (OpKind::I64Rotr, ValType::I64),
        Operator::I64Eq => (OpKind::I64Eq, ValType::I32),
        Operator::I64Ne => (OpKind::I64Ne, ValType::I32),
        Operator::I64LtS => (OpKind::I64LtS, ValType::I32),
        Operator::I64LtU => (OpKind::I64LtU, ValType::I32),
        Operator::I64GtS => (OpKind::I64GtS, ValType::I32),
        Operator::I64GtU => (OpKind::I64GtU, ValType::I32),
        Operator::I64LeS => (OpKind::I64LeS, ValType::I32),
        Operator::I64LeU => (OpKind::I64LeU, ValType::I32),
        Operator::I64GeS => (OpKind::I64GeS, ValType::I32),
        Operator::I64GeU => (OpKind::I64GeU, ValType::I32),
        Operator::F32Add => (OpKind::F32Add, ValType::F32),
        Operator::F32Sub => (OpKind::F32Sub, ValType::F32),
        Operator::F32Mul => (OpKind::F32Mul, ValType::F32),
        Operator::F32Div => (OpKind::F32Div, ValType::F32),
        Operator::F32Min => (OpKind::F32Min, ValType::F32),
        Operator::F32Max => (OpKind::F32Max, ValType::F32),
        Operator::F32Copysign => (OpKind::F32Copysign, ValType::F32),
        Operator::F32Eq => (OpKind::F32Eq, ValType::I32),
        Operator::F32Ne => (OpKind::F32Ne, ValType::I32),
        Operator::F32Lt => (OpKind::F32Lt, ValType::I32),
        Operator::F32Gt => (OpKind::F32Gt, ValType::I32),
        Operator::F32Le => (OpKind::F32Le, ValType::I32),
        Operator::F32Ge => (OpKind::F32Ge, ValType::I32),
        Operator::F64Add => (OpKind::F64Add, ValType::F64),
        Operator::F64Sub => (OpKind::F64Sub, ValType::F64),
        Operator::F64Mul => (OpKind::F64Mul, ValType::F64),
        Operator::F64Div => (OpKind::F64Div, ValType::F64),
        Operator::F64Min => (OpKind::F64Min, ValType::F64),
        Operator::F64Max => (OpKind::F64Max, ValType::F64),
        Operator::F64Copysign => (OpKind::F64Copysign, ValType::F64),
        Operator::F64Eq => (OpKind::F64Eq, ValType::I32),
        Operator::F64Ne => (OpKind::F64Ne, ValType::I32),
        Operator::F64Lt => (OpKind::F64Lt, ValType::I32),
        Operator::F64Gt => (OpKind::F64Gt, ValType::I32),
        Operator::F64Le => (OpKind::F64Le, ValType::I32),
        Operator::F64Ge => (OpKind::F64Ge, ValType::I32),
        _ => return None,
    })
}

fn lift_binop(
    kind: OpKind,
    ty: ValType,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<()> {
    let rhs: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at binop".into()))?;
    let lhs: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at binop".into()))?;
    let v: ValueId = b.alloc(ValueDef::Op {
        kind,
        args: smallvec![lhs, rhs],
        ty,
    });
    push_to_block(stack, b, block, v);
    Ok(())
}

pub(crate) const fn unop_kind(op: &Operator<'_>) -> Option<(UnOp, ValType)> {
    Some(match op {
        Operator::I32Eqz => (UnOp::I32Eqz, ValType::I32),
        Operator::I64Eqz => (UnOp::I64Eqz, ValType::I32),
        Operator::I32Clz => (UnOp::I32Clz, ValType::I32),
        Operator::I32Ctz => (UnOp::I32Ctz, ValType::I32),
        Operator::I32Popcnt => (UnOp::I32Popcnt, ValType::I32),
        Operator::I64Clz => (UnOp::I64Clz, ValType::I64),
        Operator::I64Ctz => (UnOp::I64Ctz, ValType::I64),
        Operator::I64Popcnt => (UnOp::I64Popcnt, ValType::I64),
        Operator::F32Abs => (UnOp::F32Abs, ValType::F32),
        Operator::F32Neg => (UnOp::F32Neg, ValType::F32),
        Operator::F32Ceil => (UnOp::F32Ceil, ValType::F32),
        Operator::F32Floor => (UnOp::F32Floor, ValType::F32),
        Operator::F32Trunc => (UnOp::F32Trunc, ValType::F32),
        Operator::F32Nearest => (UnOp::F32Nearest, ValType::F32),
        Operator::F32Sqrt => (UnOp::F32Sqrt, ValType::F32),
        Operator::F64Abs => (UnOp::F64Abs, ValType::F64),
        Operator::F64Neg => (UnOp::F64Neg, ValType::F64),
        Operator::F64Ceil => (UnOp::F64Ceil, ValType::F64),
        Operator::F64Floor => (UnOp::F64Floor, ValType::F64),
        Operator::F64Trunc => (UnOp::F64Trunc, ValType::F64),
        Operator::F64Nearest => (UnOp::F64Nearest, ValType::F64),
        Operator::F64Sqrt => (UnOp::F64Sqrt, ValType::F64),
        Operator::I32WrapI64 => (UnOp::I32WrapI64, ValType::I32),
        Operator::I64ExtendI32S => (UnOp::I64ExtendI32S, ValType::I64),
        Operator::I64ExtendI32U => (UnOp::I64ExtendI32U, ValType::I64),
        Operator::I32Extend8S => (UnOp::I32Extend8S, ValType::I32),
        Operator::I32Extend16S => (UnOp::I32Extend16S, ValType::I32),
        Operator::I64Extend8S => (UnOp::I64Extend8S, ValType::I64),
        Operator::I64Extend16S => (UnOp::I64Extend16S, ValType::I64),
        Operator::I64Extend32S => (UnOp::I64Extend32S, ValType::I64),
        Operator::I32TruncF32S => (UnOp::I32TruncF32S, ValType::I32),
        Operator::I32TruncF32U => (UnOp::I32TruncF32U, ValType::I32),
        Operator::I32TruncF64S => (UnOp::I32TruncF64S, ValType::I32),
        Operator::I32TruncF64U => (UnOp::I32TruncF64U, ValType::I32),
        Operator::I64TruncF32S => (UnOp::I64TruncF32S, ValType::I64),
        Operator::I64TruncF32U => (UnOp::I64TruncF32U, ValType::I64),
        Operator::I64TruncF64S => (UnOp::I64TruncF64S, ValType::I64),
        Operator::I64TruncF64U => (UnOp::I64TruncF64U, ValType::I64),
        Operator::I32TruncSatF32S => (UnOp::I32TruncSatF32S, ValType::I32),
        Operator::I32TruncSatF32U => (UnOp::I32TruncSatF32U, ValType::I32),
        Operator::I32TruncSatF64S => (UnOp::I32TruncSatF64S, ValType::I32),
        Operator::I32TruncSatF64U => (UnOp::I32TruncSatF64U, ValType::I32),
        Operator::I64TruncSatF32S => (UnOp::I64TruncSatF32S, ValType::I64),
        Operator::I64TruncSatF32U => (UnOp::I64TruncSatF32U, ValType::I64),
        Operator::I64TruncSatF64S => (UnOp::I64TruncSatF64S, ValType::I64),
        Operator::I64TruncSatF64U => (UnOp::I64TruncSatF64U, ValType::I64),
        Operator::F32ConvertI32S => (UnOp::F32ConvertI32S, ValType::F32),
        Operator::F32ConvertI32U => (UnOp::F32ConvertI32U, ValType::F32),
        Operator::F32ConvertI64S => (UnOp::F32ConvertI64S, ValType::F32),
        Operator::F32ConvertI64U => (UnOp::F32ConvertI64U, ValType::F32),
        Operator::F64ConvertI32S => (UnOp::F64ConvertI32S, ValType::F64),
        Operator::F64ConvertI32U => (UnOp::F64ConvertI32U, ValType::F64),
        Operator::F64ConvertI64S => (UnOp::F64ConvertI64S, ValType::F64),
        Operator::F64ConvertI64U => (UnOp::F64ConvertI64U, ValType::F64),
        Operator::F32DemoteF64 => (UnOp::F32DemoteF64, ValType::F32),
        Operator::F64PromoteF32 => (UnOp::F64PromoteF32, ValType::F64),
        Operator::I32ReinterpretF32 => (UnOp::I32ReinterpretF32, ValType::I32),
        Operator::I64ReinterpretF64 => (UnOp::I64ReinterpretF64, ValType::I64),
        Operator::F32ReinterpretI32 => (UnOp::F32ReinterpretI32, ValType::F32),
        Operator::F64ReinterpretI64 => (UnOp::F64ReinterpretI64, ValType::F64),
        _ => return None,
    })
}

fn lift_unop(
    op: UnOp,
    ty: ValType,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<()> {
    let arg: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at unop".into()))?;
    let v: ValueId = b.alloc(ValueDef::Unary { op, arg, ty });
    push_to_block(stack, b, block, v);
    Ok(())
}

fn pop_args(
    stack: &mut Vec<ValueId>,
    arity: Option<usize>,
    site: &str,
) -> Result<SmallVec<[ValueId; 4]>> {
    match arity {
        Some(n) => {
            if stack.len() < n {
                return Err(Error::Parse(format!("stack underflow at {site}")));
            }
            let split: usize = stack.len() - n;
            Ok(SmallVec::from_vec(stack.split_off(split)))
        }
        None => Ok(SmallVec::from_vec(core::mem::take(stack))),
    }
}

fn lift_call_and_memory(
    op: &Operator<'_>,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
    call_sigs: &CallSignatures,
) -> Result<bool> {
    match op {
        Operator::Call { function_index } => {
            let arity: Option<usize> = call_sigs.param_count(*function_index);
            let result_ty: Option<ValType> = call_sigs.result_type(*function_index);
            let has_result: bool = arity.is_none() || result_ty.is_some();
            let args: SmallVec<[ValueId; 4]> = pop_args(stack, arity, "call")?;
            let v: ValueId = b.alloc(ValueDef::Call {
                func: *function_index,
                args,
                ty: result_ty.or(Some(ValType::I32)),
            });
            if has_result {
                push_to_block(stack, b, block, v);
            } else if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
                blk.instrs.push(v);
            }
            Ok(true)
        }
        Operator::CallIndirect {
            type_index,
            table_index,
        } => {
            let callee: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at call_indirect".into()))?;
            let arity: Option<usize> = call_sigs.param_count(*type_index);
            let result_ty: Option<ValType> = call_sigs.type_result(*type_index);
            let args: SmallVec<[ValueId; 4]> = pop_args(stack, arity, "call_indirect")?;
            let v: ValueId = b.alloc(ValueDef::CallIndirect {
                type_index: *type_index,
                table: *table_index,
                callee,
                args,
                ty: result_ty.or(Some(ValType::I32)),
            });
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::MemorySize { mem } => {
            let v: ValueId = b.alloc(ValueDef::MemorySize { mem: *mem });
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        Operator::MemoryGrow { mem } => {
            let delta: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at memory.grow".into()))?;
            let v: ValueId = b.alloc(ValueDef::MemoryGrow { mem: *mem, delta });
            push_to_block(stack, b, block, v);
            Ok(true)
        }
        _ => Ok(false),
    }
}

pub(crate) const fn load_descriptor(op: &Operator<'_>) -> Option<(LoadKind, ValType, MemArg)> {
    let (kind, ty, memarg): (LoadKind, ValType, MemArg) = match op {
        Operator::I32Load { memarg } => (LoadKind::I32, ValType::I32, *memarg),
        Operator::I64Load { memarg } => (LoadKind::I64, ValType::I64, *memarg),
        Operator::F32Load { memarg } => (LoadKind::F32, ValType::F32, *memarg),
        Operator::F64Load { memarg } => (LoadKind::F64, ValType::F64, *memarg),
        Operator::I32Load8S { memarg } => (LoadKind::I32_8S, ValType::I32, *memarg),
        Operator::I32Load8U { memarg } => (LoadKind::I32_8U, ValType::I32, *memarg),
        Operator::I32Load16S { memarg } => (LoadKind::I32_16S, ValType::I32, *memarg),
        Operator::I32Load16U { memarg } => (LoadKind::I32_16U, ValType::I32, *memarg),
        Operator::I64Load8S { memarg } => (LoadKind::I64_8S, ValType::I64, *memarg),
        Operator::I64Load8U { memarg } => (LoadKind::I64_8U, ValType::I64, *memarg),
        Operator::I64Load16S { memarg } => (LoadKind::I64_16S, ValType::I64, *memarg),
        Operator::I64Load16U { memarg } => (LoadKind::I64_16U, ValType::I64, *memarg),
        Operator::I64Load32S { memarg } => (LoadKind::I64_32S, ValType::I64, *memarg),
        Operator::I64Load32U { memarg } => (LoadKind::I64_32U, ValType::I64, *memarg),
        _ => return None,
    };
    Some((kind, ty, memarg))
}

fn lift_load(
    kind: LoadKind,
    ty: ValType,
    memarg: MemArg,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<()> {
    let addr: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at load".into()))?;
    let v: ValueId = b.alloc(ValueDef::Load {
        addr,
        memarg: memarg.into(),
        kind,
        ty,
    });
    push_to_block(stack, b, block, v);
    Ok(())
}

pub(crate) const fn store_descriptor(op: &Operator<'_>) -> Option<(StoreKind, MemArg)> {
    let (kind, memarg): (StoreKind, MemArg) = match op {
        Operator::I32Store { memarg } => (StoreKind::I32, *memarg),
        Operator::I64Store { memarg } => (StoreKind::I64, *memarg),
        Operator::F32Store { memarg } => (StoreKind::F32, *memarg),
        Operator::F64Store { memarg } => (StoreKind::F64, *memarg),
        Operator::I32Store8 { memarg } => (StoreKind::I32_8, *memarg),
        Operator::I32Store16 { memarg } => (StoreKind::I32_16, *memarg),
        Operator::I64Store8 { memarg } => (StoreKind::I64_8, *memarg),
        Operator::I64Store16 { memarg } => (StoreKind::I64_16, *memarg),
        Operator::I64Store32 { memarg } => (StoreKind::I64_32, *memarg),
        _ => return None,
    };
    Some((kind, memarg))
}

fn lift_store(
    kind: StoreKind,
    memarg: MemArg,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<()> {
    let val: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at store val".into()))?;
    let addr: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at store addr".into()))?;
    if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
        blk.stores.push(SideEffect {
            addr,
            val,
            memarg: memarg.into(),
            kind,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::cfg::CfgBlock;

    #[test]
    fn promotes_empty_cfg_to_empty_ssa() {
        let cfg: FunctionCfg = FunctionCfg::default();
        let ssa: LegacySsaFunction = promote_locals_to_ssa(&cfg, 0);
        assert_eq!(ssa.blocks.len(), 0);
        assert_eq!(ssa.next_version, 0);
    }

    #[test]
    fn assigns_v0_to_each_local_at_entry() {
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![CfgBlock {
                id: BlockId(0),
                ..Default::default()
            }],
            edges: Vec::new(),
            entry: BlockId(0),
        };
        let ssa: LegacySsaFunction = promote_locals_to_ssa(&cfg, 3);
        assert_eq!(ssa.blocks.len(), 1);
        assert_eq!(ssa.next_version, 3);
        let block0: &LegacySsaBlock = &ssa.blocks[0];
        assert_eq!(block0.locals_in.len(), 3);
        assert_eq!(block0.locals_in[&LocalId(0)].version, 0);
        assert_eq!(block0.locals_in[&LocalId(1)].version, 1);
        assert_eq!(block0.locals_in[&LocalId(2)].version, 2);
    }

    #[test]
    fn promote_locals_caps_hostile_local_count() {
        let cfg: FunctionCfg = FunctionCfg {
            blocks: vec![CfgBlock {
                id: BlockId(0),
                ..Default::default()
            }],
            edges: Vec::new(),
            entry: BlockId(0),
        };
        let cap: u32 = u32::try_from(MAX_FUNCTION_LOCALS).unwrap_or(u32::MAX);

        let under: LegacySsaFunction = promote_locals_to_ssa(&cfg, cap - 1);
        assert_eq!(under.next_version, cap - 1);
        assert_eq!(under.blocks[0].locals_in.len(), (cap - 1) as usize);

        let over: LegacySsaFunction = promote_locals_to_ssa(&cfg, u32::MAX);
        assert_eq!(over.next_version, cap);
        assert_eq!(over.blocks[0].locals_in.len(), MAX_FUNCTION_LOCALS);
    }

    #[test]
    fn trivial_single_pred_read_reuses_predecessor_value() {
        let mut b: Builder = Builder::new(2);
        b.preds_of[1] = vec![BlockId(0)];
        let c0: ValueId = b.alloc(ValueDef::Const(ConstVal::I32(42)));
        b.write_variable(0, BlockId(0), c0);
        b.sealed[0] = true;
        b.sealed[1] = true;
        let v: ValueId = b.read_variable(0, BlockId(1));
        assert_eq!(v, c0, "single-pred read must reuse predecessor value");
    }

    #[test]
    fn try_remove_trivial_phi_collapses_self_referential_phi() {
        let mut b: Builder = Builder::new(1);
        let v0: ValueId = b.alloc(ValueDef::Const(ConstVal::I32(1)));
        let phi: ValueId = b.alloc(ValueDef::Phi {
            block: BlockId(0),
            operands: smallvec![ValueId(u32::MAX), v0],
        });
        if let Some(ValueDef::Phi { operands, .. }) = b.values.get_mut(phi.0 as usize) {
            operands[0] = phi;
        }
        let replacement: ValueId = b.try_remove_trivial_phi(phi);
        assert_eq!(replacement, v0);
    }

    fn synthetic_load_store_module() -> Vec<u8> {
        let mut buf: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        buf.extend_from_slice(&[0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f]);
        buf.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
        buf.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
        let body: [u8; 12] = [
            0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x41, 0x01, 0x6a, 0x0f, 0x0b, 0x00,
        ];
        let _ = body[10];
        let body_bytes: &[u8] = &[
            0x00, 0x41, 0x00, 0x28, 0x02, 0x00, 0x41, 0x01, 0x6a, 0x0f, 0x0b,
        ];
        let body_len: u8 = u8::try_from(body_bytes.len()).expect("fixture body fits u8");
        buf.push(0x0a);
        buf.push(body_len + 2);
        buf.push(0x01);
        buf.push(body_len);
        buf.extend_from_slice(body_bytes);
        buf
    }

    fn linear_block_for_offset(blocks: &[CfgBlock], offset: usize) -> Option<BlockId> {
        for b in blocks {
            if offset >= b.start_offset && offset <= b.end_offset {
                return Some(b.id);
            }
        }
        blocks.last().map(|b| b.id)
    }

    fn contiguous_blocks(count: u32, span: usize) -> Vec<CfgBlock> {
        let mut blocks: Vec<CfgBlock> = Vec::with_capacity(count as usize);
        let mut start: usize = 0;
        for i in 0..count {
            let end: usize = start + span;
            blocks.push(CfgBlock {
                id: BlockId(i),
                start_offset: start,
                end_offset: end,
                ..Default::default()
            });
            start = end;
        }
        blocks
    }

    #[test]
    fn cursor_block_resolution_matches_linear_scan_over_monotonic_offsets() {
        let blocks: Vec<CfgBlock> = contiguous_blocks(400, 3);
        let top: usize = blocks.last().map_or(0, |b| b.end_offset);
        let mut cursor: usize = 0;
        for offset in 0..=top {
            let expected: Option<BlockId> = linear_block_for_offset(&blocks, offset);
            let got: Option<BlockId> = block_for_offset(&blocks, offset, &mut cursor);
            assert_eq!(got, expected, "resolution diverged at offset {offset}");
        }
        let beyond: usize = top + 64;
        assert_eq!(
            block_for_offset(&blocks, beyond, &mut cursor),
            linear_block_for_offset(&blocks, beyond),
            "resolution diverged past the final block"
        );
    }

    #[test]
    fn cursor_block_resolution_handles_empty_and_single() {
        let mut cursor: usize = 0;
        assert_eq!(block_for_offset(&[], 0, &mut cursor), None);
        let single: Vec<CfgBlock> = contiguous_blocks(1, 5);
        let mut c2: usize = 0;
        assert_eq!(block_for_offset(&single, 0, &mut c2), Some(BlockId(0)));
        assert_eq!(block_for_offset(&single, 3, &mut c2), Some(BlockId(0)));
        assert_eq!(block_for_offset(&single, 999, &mut c2), Some(BlockId(0)));
    }

    fn many_op_block_module(blocks: usize, ops_per_block: usize) -> Vec<u8> {
        let mut body: String = String::with_capacity(blocks * (ops_per_block + 1) * 18);
        for _ in 0..blocks {
            for _ in 0..ops_per_block {
                body.push_str("i32.const 0 drop ");
            }
            body.push_str("i32.const 0 br_if 0 ");
        }
        let source: String = format!("(module (func {body}))");
        wat::parse_str(&source).expect("many-op module parses")
    }

    #[test]
    fn build_ssa_scales_for_many_ops_and_blocks() {
        let bytes: Vec<u8> = many_op_block_module(3000, 30);
        let start: std::time::Instant = std::time::Instant::now();
        let mut found: bool = false;
        for payload in wasmparser::Parser::new(0).parse_all(&bytes) {
            if let Ok(wasmparser::Payload::CodeSectionEntry(body)) = payload {
                let cfg: FunctionCfg = crate::cfg::build_function_cfg(&body).expect("cfg build");
                let ssa: SsaFunction = build_ssa(&cfg, &body, &[]).expect("ssa build");
                assert_eq!(
                    ssa.blocks.len(),
                    cfg.blocks.len(),
                    "one ssa block per cfg block"
                );
                assert!(
                    matches!(
                        ssa.blocks.last().map(|b| &b.terminator),
                        Some(SsaTerm::Return(_) | SsaTerm::Fallthrough(_) | SsaTerm::Unreachable)
                    ),
                    "final block must carry a terminator"
                );
                found = true;
            }
        }
        assert!(found, "module must contain a code body");
        assert!(
            start.elapsed() < std::time::Duration::from_secs(20),
            "ssa build must scale, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn builds_ssa_for_load_add_return() {
        use wasmparser::Parser;
        let bytes: Vec<u8> = synthetic_load_store_module();
        let mut found: bool = false;
        for payload in Parser::new(0).parse_all(&bytes) {
            if let Ok(wasmparser::Payload::CodeSectionEntry(body)) = payload {
                let cfg: FunctionCfg = crate::cfg::build_function_cfg(&body).expect("cfg build");
                let ssa: SsaFunction = build_ssa(&cfg, &body, &[]).expect("ssa build");
                assert!(!ssa.blocks.is_empty());
                let has_load: bool = ssa
                    .values
                    .iter()
                    .any(|v| matches!(v, ValueDef::Load { .. }));
                let has_add: bool = ssa.values.iter().any(|v| {
                    matches!(
                        v,
                        ValueDef::Op {
                            kind: OpKind::I32Add,
                            ..
                        }
                    )
                });
                assert!(has_load, "must lift i32.load to ValueDef::Load");
                assert!(has_add, "must lift i32.add to ValueDef::Op(I32Add)");
                let last: &SsaBlock = ssa.blocks.last().expect("at least one block");
                assert!(
                    matches!(last.terminator, SsaTerm::Return(_)),
                    "last block must terminate with Return, got {:?}",
                    last.terminator
                );
                found = true;
            }
        }
        assert!(found, "synthetic module must contain a code body");
    }
}
