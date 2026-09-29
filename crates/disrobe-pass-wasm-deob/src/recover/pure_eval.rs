use std::collections::BTreeMap;

use walrus::ir::{BinaryOp, Instr, InstrSeqId, UnaryOp, Value};
use walrus::{
    ConstExpr, FunctionId, GlobalId, GlobalKind, LocalFunction, LocalId, Module, ValType,
};

const MAX_STEPS: u64 = 2_000_000;
const MAX_MODULE_STEPS: u64 = 50_000_000;
const MAX_CALL_DEPTH: u32 = 8;
const MAX_VALUE_STACK: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Scalar {
    I32(i32),
    I64(i64),
}

impl Scalar {
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
    spent: std::cell::Cell<u64>,
}

impl PureModule {
    pub(super) fn snapshot(module: &Module) -> Self {
        let mut functions: BTreeMap<FunctionId, FnSnapshot> = BTreeMap::new();
        for (fid, func) in module.funcs.iter_local() {
            functions.insert(fid, snapshot_function(module, func));
        }
        let mut globals: BTreeMap<GlobalId, Scalar> = BTreeMap::new();
        for global in module.globals.iter() {
            if !global.mutable
                && let GlobalKind::Local(ConstExpr::Value(value)) = &global.kind
            {
                if let Some(scalar) = scalar_of_value(*value) {
                    globals.insert(global.id(), scalar);
                }
            }
        }
        Self {
            functions,
            globals,
            spent: std::cell::Cell::new(0),
        }
    }

    fn charge_step(&self) -> bool {
        let spent: u64 = self.spent.get().saturating_add(1);
        self.spent.set(spent);
        spent <= MAX_MODULE_STEPS
    }

    pub(super) const fn budget_exhausted(&self) -> bool {
        self.spent.get() > MAX_MODULE_STEPS
    }

    pub(super) fn eval_guard(&self, guard: &[Instr]) -> Option<Scalar> {
        let mut machine: Machine<'_> = Machine {
            module: self,
            steps: 0,
        };
        let mut stack: Vec<Scalar> = Vec::new();
        for instr in guard {
            machine.steps += 1;
            if machine.steps > MAX_STEPS || !self.charge_step() {
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
                    if let Returned::Value(result) = machine.invoke(call.func, &call_args, 1)? {
                        stack.push(result);
                    }
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

#[derive(Debug, Clone, Copy)]
enum Returned {
    Value(Scalar),
    Void,
}

struct Machine<'a> {
    module: &'a PureModule,
    steps: u64,
}

impl Machine<'_> {
    fn invoke(&mut self, callee: FunctionId, args: &[Scalar], depth: u32) -> Option<Returned> {
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
            (Flow::Return(Some(value)), Some(_)) => Some(Returned::Value(value)),
            (Flow::Return(None) | Flow::Normal, None) => Some(Returned::Void),
            (Flow::Normal, Some(_)) => stack.pop().map(Returned::Value),
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
            if self.steps > MAX_STEPS || stack.len() > MAX_VALUE_STACK || !self.module.charge_step()
            {
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
                Instr::GlobalGet(g) => stack.push(*self.module.globals.get(&g.global)?),
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
                Instr::Call(call) => {
                    let arity: usize = self.module.functions.get(&call.func)?.args.len();
                    if stack.len() < arity {
                        return None;
                    }
                    let split: usize = stack.len() - arity;
                    let call_args: Vec<Scalar> = stack.split_off(split);
                    if let Returned::Value(value) = self.invoke(call.func, &call_args, depth + 1)? {
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{MAX_MODULE_STEPS, MAX_STEPS, PureModule};
    use walrus::ir::{Call, Instr};
    use walrus::{FunctionId, LocalFunction, Module};

    #[test]
    fn guards_that_never_return_share_one_module_step_budget() {
        let bytes: Vec<u8> =
            wat::parse_str("(module (func (result i32) (loop $l (br $l)) (i32.const 0)))")
                .expect("assemble");
        let module: Module = Module::from_buffer(&bytes).expect("walrus reads the module");
        let spin: FunctionId = module
            .funcs
            .iter_local()
            .next()
            .map(|(id, _): (FunctionId, &LocalFunction)| id)
            .expect("one local function");
        let pure: PureModule = PureModule::snapshot(&module);
        let guard: [Instr; 1] = [Instr::Call(Call { func: spin })];
        let guards: u64 = MAX_MODULE_STEPS / MAX_STEPS + 2;
        for _ in 0..guards {
            assert_eq!(pure.eval_guard(&guard), None);
        }
        assert!(pure.budget_exhausted());
        assert!(
            pure.spent.get() <= MAX_MODULE_STEPS + guards,
            "every guard after the module budget is spent must stop at its first step, spent {}",
            pure.spent.get()
        );
    }
}
