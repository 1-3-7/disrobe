use indexmap::IndexMap;
use serde::Serialize;
use smallvec::{SmallVec, smallvec};
use wasmparser::{MemArg, Operator, ValType};

use crate::cfg::{BlockId, CfgBlock, FunctionCfg};
use crate::error::{Error, Result};
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
    Load {
        addr: ValueId,
        memarg: SsaMemArg,
        kind: LoadKind,
        #[serde(skip)]
        ty: ValType,
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
pub struct SsaBlock {
    pub id: BlockId,
    #[serde(skip)]
    pub params: SmallVec<[ValType; 4]>,
    pub instrs: Vec<ValueId>,
    pub stores: Vec<SideEffect>,
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

pub fn promote_locals_to_ssa(cfg: &FunctionCfg, local_count: u32) -> LegacySsaFunction {
    let mut next_version: u32 = 0u32;
    let mut current_versions: IndexMap<LocalId, SsaValue> = IndexMap::new();
    for local in 0..local_count {
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
        ValueDef::Load { addr, .. } => {
            if *addr == from {
                *addr = to;
            }
        }
        ValueDef::Param(..) | ValueDef::Const(_) => {}
    }
}

fn expand_locals(locals_iter: &[(u32, ValType)], params: &[ValType]) -> Vec<ValType> {
    let mut out: Vec<ValType> = params.to_vec();
    for (count, ty) in locals_iter {
        for _ in 0..*count {
            out.push(*ty);
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

fn block_for_offset(blocks: &[CfgBlock], offset: usize) -> Option<BlockId> {
    for b in blocks {
        if offset >= b.start_offset && offset <= b.end_offset {
            return Some(b.id);
        }
    }
    blocks.last().map(|b| b.id)
}

pub fn build_ssa(
    cfg: &FunctionCfg,
    body: &wasmparser::FunctionBody<'_>,
    params: &[ValType],
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

    for op_result in ops_reader.into_iter_with_offsets() {
        let (op, offset): (Operator<'_>, usize) =
            op_result.map_err(|e| Error::Parse(e.to_string()))?;
        if let Some(b) = block_for_offset(&cfg.blocks, offset) {
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
) -> Result<()> {
    if lift_control(op, stack, b, block, produced_terminator)? {
        return Ok(());
    }
    if lift_locals_consts(op, stack, b, block)? {
        return Ok(());
    }
    if let Some(kind) = i32_binop_kind(op) {
        lift_i32_binop(kind, stack, b, block)?;
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
        "DR-WASMDEOB-SSA: unsupported operator in MVP slice ({:?})",
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
        Operator::Select => {
            let cond: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let b_val: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let a_val: ValueId = stack
                .pop()
                .ok_or_else(|| Error::Parse("stack underflow at select".into()))?;
            let v: ValueId = b.alloc(ValueDef::Op {
                kind: OpKind::I32Or,
                args: smallvec![a_val, b_val, cond],
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
        _ => Ok(false),
    }
}

fn push_to_block(stack: &mut Vec<ValueId>, b: &mut Builder, block: BlockId, v: ValueId) {
    stack.push(v);
    if let Some(blk) = b.blocks.get_mut(block.0 as usize) {
        blk.instrs.push(v);
    }
}

const fn i32_binop_kind(op: &Operator<'_>) -> Option<OpKind> {
    Some(match op {
        Operator::I32Add => OpKind::I32Add,
        Operator::I32Sub => OpKind::I32Sub,
        Operator::I32Mul => OpKind::I32Mul,
        Operator::I32And => OpKind::I32And,
        Operator::I32Or => OpKind::I32Or,
        Operator::I32Xor => OpKind::I32Xor,
        Operator::I32Shl => OpKind::I32Shl,
        Operator::I32ShrU => OpKind::I32ShrU,
        Operator::I32ShrS => OpKind::I32ShrS,
        Operator::I32Eq => OpKind::I32Eq,
        Operator::I32Ne => OpKind::I32Ne,
        Operator::I32LtS => OpKind::I32LtS,
        Operator::I32LtU => OpKind::I32LtU,
        Operator::I32GtS => OpKind::I32GtS,
        Operator::I32GtU => OpKind::I32GtU,
        Operator::I32LeS => OpKind::I32LeS,
        Operator::I32LeU => OpKind::I32LeU,
        Operator::I32GeS => OpKind::I32GeS,
        Operator::I32GeU => OpKind::I32GeU,
        _ => return None,
    })
}

fn lift_i32_binop(
    kind: OpKind,
    stack: &mut Vec<ValueId>,
    b: &mut Builder,
    block: BlockId,
) -> Result<()> {
    let rhs: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at i32 binop".into()))?;
    let lhs: ValueId = stack
        .pop()
        .ok_or_else(|| Error::Parse("stack underflow at i32 binop".into()))?;
    let v: ValueId = b.alloc(ValueDef::Op {
        kind,
        args: smallvec![lhs, rhs],
        ty: ValType::I32,
    });
    push_to_block(stack, b, block, v);
    Ok(())
}

const fn load_descriptor(op: &Operator<'_>) -> Option<(LoadKind, ValType, MemArg)> {
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

const fn store_descriptor(op: &Operator<'_>) -> Option<(StoreKind, MemArg)> {
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
