use std::collections::BTreeMap;

use walrus::ir::{BinaryOp, ExtendedLoad, Instr, InstrSeqId, LoadKind, StoreKind, UnaryOp, Value};
use walrus::{
    ConstExpr, FunctionId, GlobalId, GlobalKind, LocalFunction, LocalId, Module, ValType,
};

const MAX_STEPS: u64 = 2_000_000;
const MAX_CALL_DEPTH: u32 = 8;
const MAX_MEMORY_BYTES: usize = 1 << 20;
const MAX_VALUE_STACK: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scalar {
    I32(i32),
    I64(i64),
}

impl Scalar {
    const fn as_i32(self) -> Option<i32> {
        match self {
            Self::I32(v) => Some(v),
            Self::I64(_) => None,
        }
    }

    const fn truthy(self) -> bool {
        match self {
            Self::I32(v) => v != 0,
            Self::I64(v) => v != 0,
        }
    }
}

#[derive(Debug)]
struct FnSnapshot {
    args: Vec<LocalId>,
    result: Option<ValType>,
    entry: InstrSeqId,
    seqs: BTreeMap<InstrSeqId, Vec<Instr>>,
    locals: Vec<(LocalId, ValType)>,
}

#[derive(Debug)]
pub(super) struct PureModule {
    functions: BTreeMap<FunctionId, FnSnapshot>,
    globals: BTreeMap<GlobalId, Scalar>,
}

impl PureModule {
    pub(super) fn snapshot(module: &Module) -> Self {
        let mut functions: BTreeMap<FunctionId, FnSnapshot> = BTreeMap::new();
        for (fid, func) in module.funcs.iter_local() {
            functions.insert(fid, snapshot_function(module, func));
        }
        let mut globals: BTreeMap<GlobalId, Scalar> = BTreeMap::new();
        for global in module.globals.iter() {
            if let GlobalKind::Local(ConstExpr::Value(value)) = &global.kind {
                if let Some(scalar) = scalar_of_value(*value) {
                    globals.insert(global.id(), scalar);
                }
            }
        }
        Self { functions, globals }
    }

    pub(super) fn eval_guard(&self, guard: &[Instr]) -> Option<Scalar> {
        let mut machine: Machine<'_> = Machine {
            module: self,
            memory: BTreeMap::new(),
            globals: self.globals.clone(),
            steps: 0,
        };
        let mut stack: Vec<Scalar> = Vec::new();
        for instr in guard {
            machine.steps += 1;
            if machine.steps > MAX_STEPS {
                return None;
            }
            match instr {
                Instr::Const(c) => stack.push(scalar_of_value(c.value)?),
                Instr::Binop(b) => {
                    let rhs: Scalar = stack.pop()?;
                    let lhs: Scalar = stack.pop()?;
                    stack.push(eval_binop(b.op, lhs, rhs)?);
                }
                Instr::Unop(u) => {
                    let value: Scalar = stack.pop()?;
                    stack.push(eval_unop(u.op, value)?);
                }
                Instr::Select(_) => {
                    let cond: Scalar = stack.pop()?;
                    let rhs: Scalar = stack.pop()?;
                    let lhs: Scalar = stack.pop()?;
                    stack.push(if cond.truthy() { lhs } else { rhs });
                }
                Instr::Drop(_) => {
                    stack.pop()?;
                }
                Instr::Call(call) => {
                    let arity: usize = self.functions.get(&call.func)?.args.len();
                    if stack.len() < arity {
                        return None;
                    }
                    let split: usize = stack.len() - arity;
                    let call_args: Vec<Scalar> = stack.split_off(split);
                    let result: Scalar = machine.invoke(call.func, &call_args, 1)?;
                    stack.push(result);
                }
                _ => return None,
            }
        }
        match stack.as_slice() {
            [single] => Some(*single),
            _ => None,
        }
    }
}

fn snapshot_function(module: &Module, func: &LocalFunction) -> FnSnapshot {
    let mut seqs: BTreeMap<InstrSeqId, Vec<Instr>> = BTreeMap::new();
    let mut stack: Vec<InstrSeqId> = vec![func.entry_block()];
    while let Some(id) = stack.pop() {
        if seqs.contains_key(&id) {
            continue;
        }
        let instrs: Vec<Instr> = func
            .block(id)
            .instrs
            .iter()
            .map(|(instr, _): &(Instr, walrus::ir::InstrLocId)| instr.clone())
            .collect();
        for instr in &instrs {
            match instr {
                Instr::Block(b) => stack.push(b.seq),
                Instr::Loop(l) => stack.push(l.seq),
                Instr::IfElse(ie) => {
                    stack.push(ie.consequent);
                    stack.push(ie.alternative);
                }
                _ => {}
            }
        }
        seqs.insert(id, instrs);
    }
    let result: Option<ValType> = module.types.results(func.ty()).first().copied();
    let mut locals: Vec<(LocalId, ValType)> = Vec::new();
    let mut seen: std::collections::BTreeSet<LocalId> = std::collections::BTreeSet::new();
    for instrs in seqs.values() {
        for instr in instrs {
            if let Some(lid) = local_ref(instr) {
                if seen.insert(lid) {
                    let local: &walrus::ir::Local = module.locals.get(lid);
                    locals.push((lid, local.ty()));
                }
            }
        }
    }
    FnSnapshot {
        args: func.args.clone(),
        result,
        entry: func.entry_block(),
        seqs,
        locals,
    }
}

const fn local_ref(instr: &Instr) -> Option<LocalId> {
    match instr {
        Instr::LocalGet(g) => Some(g.local),
        Instr::LocalSet(s) => Some(s.local),
        Instr::LocalTee(t) => Some(t.local),
        _ => None,
    }
}

const fn scalar_of_value(value: Value) -> Option<Scalar> {
    match value {
        Value::I32(v) => Some(Scalar::I32(v)),
        Value::I64(v) => Some(Scalar::I64(v)),
        _ => None,
    }
}

const fn zero_for(ty: ValType) -> Option<Scalar> {
    match ty {
        ValType::I32 => Some(Scalar::I32(0)),
        ValType::I64 => Some(Scalar::I64(0)),
        _ => None,
    }
}

enum Flow {
    Normal,
    Branch(InstrSeqId),
    Return(Option<Scalar>),
}

struct Machine<'a> {
    module: &'a PureModule,
    memory: BTreeMap<u32, u8>,
    globals: BTreeMap<GlobalId, Scalar>,
    steps: u64,
}

impl Machine<'_> {
    fn invoke(&mut self, callee: FunctionId, args: &[Scalar], depth: u32) -> Option<Scalar> {
        if depth > MAX_CALL_DEPTH {
            return None;
        }
        let snapshot: &FnSnapshot = self.module.functions.get(&callee)?;
        if args.len() != snapshot.args.len() {
            return None;
        }
        let mut locals: BTreeMap<LocalId, Scalar> = BTreeMap::new();
        for (slot, value) in snapshot.args.iter().zip(args.iter()) {
            locals.insert(*slot, *value);
        }
        for (lid, ty) in &snapshot.locals {
            if locals.contains_key(lid) {
                continue;
            }
            locals.insert(*lid, zero_for(*ty)?);
        }
        let mut stack: Vec<Scalar> = Vec::new();
        let flow: Flow = self.run_seq(snapshot, snapshot.entry, &mut locals, &mut stack, depth)?;
        match (flow, snapshot.result) {
            (Flow::Return(Some(value)), Some(_)) => Some(value),
            (Flow::Return(None), None) => Some(Scalar::I32(0)),
            (Flow::Normal, Some(_)) => stack.pop(),
            (Flow::Normal, None) => Some(Scalar::I32(0)),
            _ => None,
        }
    }

    fn run_seq(
        &mut self,
        snapshot: &FnSnapshot,
        seq_id: InstrSeqId,
        locals: &mut BTreeMap<LocalId, Scalar>,
        stack: &mut Vec<Scalar>,
        depth: u32,
    ) -> Option<Flow> {
        let instrs: &[Instr] = snapshot.seqs.get(&seq_id)?;
        for instr in instrs {
            self.steps += 1;
            if self.steps > MAX_STEPS || stack.len() > MAX_VALUE_STACK {
                return None;
            }
            match instr {
                Instr::Const(c) => stack.push(scalar_of_value(c.value)?),
                Instr::LocalGet(g) => stack.push(*locals.get(&g.local)?),
                Instr::LocalSet(s) => {
                    let value: Scalar = stack.pop()?;
                    locals.insert(s.local, value);
                }
                Instr::LocalTee(t) => {
                    let value: Scalar = *stack.last()?;
                    locals.insert(t.local, value);
                }
                Instr::GlobalGet(g) => stack.push(*self.globals.get(&g.global)?),
                Instr::GlobalSet(g) => {
                    let value: Scalar = stack.pop()?;
                    self.globals.insert(g.global, value);
                }
                Instr::Drop(_) => {
                    stack.pop()?;
                }
                Instr::Binop(b) => {
                    let rhs: Scalar = stack.pop()?;
                    let lhs: Scalar = stack.pop()?;
                    stack.push(eval_binop(b.op, lhs, rhs)?);
                }
                Instr::Unop(u) => {
                    let value: Scalar = stack.pop()?;
                    stack.push(eval_unop(u.op, value)?);
                }
                Instr::Select(_) => {
                    let cond: Scalar = stack.pop()?;
                    let rhs: Scalar = stack.pop()?;
                    let lhs: Scalar = stack.pop()?;
                    stack.push(if cond.truthy() { lhs } else { rhs });
                }
                Instr::Load(load) => {
                    let addr: Scalar = stack.pop()?;
                    stack.push(self.load(load.kind, addr, load.arg.offset)?);
                }
                Instr::Store(store) => {
                    let value: Scalar = stack.pop()?;
                    let addr: Scalar = stack.pop()?;
                    self.store(store.kind, addr, store.arg.offset, value)?;
                }
                Instr::Call(call) => {
                    let arity: usize = self.module.functions.get(&call.func)?.args.len();
                    if stack.len() < arity {
                        return None;
                    }
                    let split: usize = stack.len() - arity;
                    let call_args: Vec<Scalar> = stack.split_off(split);
                    let result: Option<Scalar> = self.invoke(call.func, &call_args, depth + 1);
                    if let Some(value) = result {
                        stack.push(value);
                    }
                }
                Instr::Block(b) => match self.run_seq(snapshot, b.seq, locals, stack, depth)? {
                    Flow::Branch(target) if target == b.seq => {}
                    Flow::Branch(target) => return Some(Flow::Branch(target)),
                    Flow::Return(value) => return Some(Flow::Return(value)),
                    Flow::Normal => {}
                },
                Instr::Loop(l) => loop {
                    match self.run_seq(snapshot, l.seq, locals, stack, depth)? {
                        Flow::Branch(target) if target == l.seq => {}
                        Flow::Branch(target) => return Some(Flow::Branch(target)),
                        Flow::Return(value) => return Some(Flow::Return(value)),
                        Flow::Normal => break,
                    }
                },
                Instr::IfElse(ie) => {
                    let cond: Scalar = stack.pop()?;
                    let branch: InstrSeqId = if cond.truthy() {
                        ie.consequent
                    } else {
                        ie.alternative
                    };
                    match self.run_seq(snapshot, branch, locals, stack, depth)? {
                        Flow::Branch(target) if target == branch => {}
                        Flow::Branch(target) => return Some(Flow::Branch(target)),
                        Flow::Return(value) => return Some(Flow::Return(value)),
                        Flow::Normal => {}
                    }
                }
                Instr::Br(br) => return Some(Flow::Branch(br.block)),
                Instr::BrIf(br) => {
                    let cond: Scalar = stack.pop()?;
                    if cond.truthy() {
                        return Some(Flow::Branch(br.block));
                    }
                }
                Instr::Return(_) => {
                    let value: Option<Scalar> = match snapshot.result {
                        Some(_) => Some(stack.pop()?),
                        None => None,
                    };
                    return Some(Flow::Return(value));
                }
                _ => return None,
            }
        }
        Some(Flow::Normal)
    }

    fn load(&self, kind: LoadKind, addr: Scalar, offset: u32) -> Option<Scalar> {
        let base: u32 = addr.as_i32()?.cast_unsigned();
        let effective: u32 = base.checked_add(offset)?;
        match kind {
            LoadKind::I32 { atomic: false } => Some(Scalar::I32(i32::from_le_bytes(
                self.read_bytes::<4>(effective)?,
            ))),
            LoadKind::I64 { atomic: false } => Some(Scalar::I64(i64::from_le_bytes(
                self.read_bytes::<8>(effective)?,
            ))),
            LoadKind::I32_8 { kind: ext } => {
                let bytes: [u8; 1] = self.read_bytes::<1>(effective)?;
                Some(Scalar::I32(extend8_i32(bytes[0], ext)))
            }
            LoadKind::I32_16 { kind: ext } => {
                let bytes: [u8; 2] = self.read_bytes::<2>(effective)?;
                Some(Scalar::I32(extend16_i32(u16::from_le_bytes(bytes), ext)))
            }
            LoadKind::I64_8 { kind: ext } => {
                let bytes: [u8; 1] = self.read_bytes::<1>(effective)?;
                Some(Scalar::I64(i64::from(extend8_i32(bytes[0], ext))))
            }
            LoadKind::I64_16 { kind: ext } => {
                let bytes: [u8; 2] = self.read_bytes::<2>(effective)?;
                Some(Scalar::I64(i64::from(extend16_i32(
                    u16::from_le_bytes(bytes),
                    ext,
                ))))
            }
            LoadKind::I64_32 { kind: ext } => {
                let raw: i32 = i32::from_le_bytes(self.read_bytes::<4>(effective)?);
                Some(Scalar::I64(match ext {
                    ExtendedLoad::SignExtend => i64::from(raw),
                    ExtendedLoad::ZeroExtend | ExtendedLoad::ZeroExtendAtomic => {
                        i64::from(raw.cast_unsigned())
                    }
                }))
            }
            _ => None,
        }
    }

    fn store(&mut self, kind: StoreKind, addr: Scalar, offset: u32, value: Scalar) -> Option<()> {
        let base: u32 = addr.as_i32()?.cast_unsigned();
        let effective: u32 = base.checked_add(offset)?;
        match kind {
            StoreKind::I32 { atomic: false } => {
                self.write_bytes(effective, &value_i32(value)?.to_le_bytes())
            }
            StoreKind::I64 { atomic: false } => {
                self.write_bytes(effective, &value_i64(value)?.to_le_bytes())
            }
            StoreKind::I32_8 { atomic: false } => {
                self.write_bytes(effective, &[value_i32(value)?.cast_unsigned() as u8])
            }
            StoreKind::I32_16 { atomic: false } => {
                let half: u16 = value_i32(value)?.cast_unsigned() as u16;
                self.write_bytes(effective, &half.to_le_bytes())
            }
            StoreKind::I64_8 { atomic: false } => {
                self.write_bytes(effective, &[value_i64(value)?.cast_unsigned() as u8])
            }
            StoreKind::I64_16 { atomic: false } => {
                let half: u16 = value_i64(value)?.cast_unsigned() as u16;
                self.write_bytes(effective, &half.to_le_bytes())
            }
            StoreKind::I64_32 { atomic: false } => {
                let word: u32 = value_i64(value)?.cast_unsigned() as u32;
                self.write_bytes(effective, &word.to_le_bytes())
            }
            _ => None,
        }
    }

    fn read_bytes<const N: usize>(&self, address: u32) -> Option<[u8; N]> {
        let mut out: [u8; N] = [0; N];
        for (i, slot) in out.iter_mut().enumerate() {
            let at: u32 = address.checked_add(i as u32)?;
            *slot = self.memory.get(&at).copied().unwrap_or(0);
        }
        Some(out)
    }

    fn write_bytes(&mut self, address: u32, bytes: &[u8]) -> Option<()> {
        if self.memory.len().saturating_add(bytes.len()) > MAX_MEMORY_BYTES {
            return None;
        }
        for (i, byte) in bytes.iter().enumerate() {
            let at: u32 = address.checked_add(i as u32)?;
            self.memory.insert(at, *byte);
        }
        Some(())
    }
}

const fn value_i32(value: Scalar) -> Option<i32> {
    match value {
        Scalar::I32(v) => Some(v),
        Scalar::I64(_) => None,
    }
}

const fn value_i64(value: Scalar) -> Option<i64> {
    match value {
        Scalar::I64(v) => Some(v),
        Scalar::I32(_) => None,
    }
}

const fn extend8_i32(byte: u8, ext: ExtendedLoad) -> i32 {
    match ext {
        ExtendedLoad::SignExtend => byte.cast_signed() as i32,
        ExtendedLoad::ZeroExtend | ExtendedLoad::ZeroExtendAtomic => byte as i32,
    }
}

const fn extend16_i32(half: u16, ext: ExtendedLoad) -> i32 {
    match ext {
        ExtendedLoad::SignExtend => half.cast_signed() as i32,
        ExtendedLoad::ZeroExtend | ExtendedLoad::ZeroExtendAtomic => half as i32,
    }
}

fn eval_unop(op: UnaryOp, value: Scalar) -> Option<Scalar> {
    Some(match (op, value) {
        (UnaryOp::I32Eqz, Scalar::I32(v)) => Scalar::I32(i32::from(v == 0)),
        (UnaryOp::I32Clz, Scalar::I32(v)) => Scalar::I32(v.cast_unsigned().leading_zeros() as i32),
        (UnaryOp::I32Ctz, Scalar::I32(v)) => Scalar::I32(v.cast_unsigned().trailing_zeros() as i32),
        (UnaryOp::I32Popcnt, Scalar::I32(v)) => Scalar::I32(v.cast_unsigned().count_ones() as i32),
        (UnaryOp::I32Extend8S, Scalar::I32(v)) => Scalar::I32(i32::from(v as i8)),
        (UnaryOp::I32Extend16S, Scalar::I32(v)) => Scalar::I32(i32::from(v as i16)),
        (UnaryOp::I64Eqz, Scalar::I64(v)) => Scalar::I32(i32::from(v == 0)),
        (UnaryOp::I64Clz, Scalar::I64(v)) => {
            Scalar::I64(i64::from(v.cast_unsigned().leading_zeros()))
        }
        (UnaryOp::I64Ctz, Scalar::I64(v)) => {
            Scalar::I64(i64::from(v.cast_unsigned().trailing_zeros()))
        }
        (UnaryOp::I64Popcnt, Scalar::I64(v)) => {
            Scalar::I64(i64::from(v.cast_unsigned().count_ones()))
        }
        (UnaryOp::I64Extend8S, Scalar::I64(v)) => Scalar::I64(i64::from(v as i8)),
        (UnaryOp::I64Extend16S, Scalar::I64(v)) => Scalar::I64(i64::from(v as i16)),
        (UnaryOp::I64Extend32S, Scalar::I64(v)) => Scalar::I64(i64::from(v as i32)),
        (UnaryOp::I32WrapI64, Scalar::I64(v)) => Scalar::I32(v as i32),
        (UnaryOp::I64ExtendSI32, Scalar::I32(v)) => Scalar::I64(i64::from(v)),
        (UnaryOp::I64ExtendUI32, Scalar::I32(v)) => Scalar::I64(i64::from(v.cast_unsigned())),
        _ => return None,
    })
}

fn eval_binop(op: BinaryOp, lhs: Scalar, rhs: Scalar) -> Option<Scalar> {
    match (lhs, rhs) {
        (Scalar::I32(a), Scalar::I32(b)) => eval_binop_i32(op, a, b),
        (Scalar::I64(a), Scalar::I64(b)) => eval_binop_i64(op, a, b),
        _ => None,
    }
}

fn eval_binop_i32(op: BinaryOp, a: i32, b: i32) -> Option<Scalar> {
    let ua: u32 = a.cast_unsigned();
    let ub: u32 = b.cast_unsigned();
    Some(Scalar::I32(match op {
        BinaryOp::I32Add => a.wrapping_add(b),
        BinaryOp::I32Sub => a.wrapping_sub(b),
        BinaryOp::I32Mul => a.wrapping_mul(b),
        BinaryOp::I32DivS => a.checked_div(b).filter(|_| !(a == i32::MIN && b == -1))?,
        BinaryOp::I32DivU => ua.checked_div(ub)?.cast_signed(),
        BinaryOp::I32RemS => {
            if b == -1 {
                0
            } else {
                a.checked_rem(b)?
            }
        }
        BinaryOp::I32RemU => ua.checked_rem(ub)?.cast_signed(),
        BinaryOp::I32And => a & b,
        BinaryOp::I32Or => a | b,
        BinaryOp::I32Xor => a ^ b,
        BinaryOp::I32Shl => a.wrapping_shl(ub & 31),
        BinaryOp::I32ShrU => ua.wrapping_shr(ub & 31).cast_signed(),
        BinaryOp::I32ShrS => a.wrapping_shr(ub & 31),
        BinaryOp::I32Rotl => a.rotate_left(ub & 31),
        BinaryOp::I32Rotr => a.rotate_right(ub & 31),
        BinaryOp::I32Eq => i32::from(a == b),
        BinaryOp::I32Ne => i32::from(a != b),
        BinaryOp::I32LtS => i32::from(a < b),
        BinaryOp::I32LtU => i32::from(ua < ub),
        BinaryOp::I32GtS => i32::from(a > b),
        BinaryOp::I32GtU => i32::from(ua > ub),
        BinaryOp::I32LeS => i32::from(a <= b),
        BinaryOp::I32LeU => i32::from(ua <= ub),
        BinaryOp::I32GeS => i32::from(a >= b),
        BinaryOp::I32GeU => i32::from(ua >= ub),
        _ => return None,
    }))
}

fn eval_binop_i64(op: BinaryOp, a: i64, b: i64) -> Option<Scalar> {
    let ua: u64 = a.cast_unsigned();
    let ub: u64 = b.cast_unsigned();
    let wide: i64 = match op {
        BinaryOp::I64Add => a.wrapping_add(b),
        BinaryOp::I64Sub => a.wrapping_sub(b),
        BinaryOp::I64Mul => a.wrapping_mul(b),
        BinaryOp::I64DivS => a.checked_div(b).filter(|_| !(a == i64::MIN && b == -1))?,
        BinaryOp::I64DivU => ua.checked_div(ub)?.cast_signed(),
        BinaryOp::I64RemS => {
            if b == -1 {
                0
            } else {
                a.checked_rem(b)?
            }
        }
        BinaryOp::I64RemU => ua.checked_rem(ub)?.cast_signed(),
        BinaryOp::I64And => a & b,
        BinaryOp::I64Or => a | b,
        BinaryOp::I64Xor => a ^ b,
        BinaryOp::I64Shl => a.wrapping_shl((ub & 63) as u32),
        BinaryOp::I64ShrU => ua.wrapping_shr((ub & 63) as u32).cast_signed(),
        BinaryOp::I64ShrS => a.wrapping_shr((ub & 63) as u32),
        BinaryOp::I64Rotl => a.rotate_left((ub & 63) as u32),
        BinaryOp::I64Rotr => a.rotate_right((ub & 63) as u32),
        BinaryOp::I64Eq => return Some(Scalar::I32(i32::from(a == b))),
        BinaryOp::I64Ne => return Some(Scalar::I32(i32::from(a != b))),
        BinaryOp::I64LtS => return Some(Scalar::I32(i32::from(a < b))),
        BinaryOp::I64LtU => return Some(Scalar::I32(i32::from(ua < ub))),
        BinaryOp::I64GtS => return Some(Scalar::I32(i32::from(a > b))),
        BinaryOp::I64GtU => return Some(Scalar::I32(i32::from(ua > ub))),
        BinaryOp::I64LeS => return Some(Scalar::I32(i32::from(a <= b))),
        BinaryOp::I64LeU => return Some(Scalar::I32(i32::from(ua <= ub))),
        BinaryOp::I64GeS => return Some(Scalar::I32(i32::from(a >= b))),
        BinaryOp::I64GeU => return Some(Scalar::I32(i32::from(ua >= ub))),
        _ => return None,
    };
    Some(Scalar::I64(wide))
}
