use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use disrobe_nir::{NirBlock, NirClass, NirFunction, NirInstr, NirOp, ValueOp, basic_blocks};

use super::dispatch_recover::binop_selector;
use super::recover::{PyExpr, RecoverOptions};

const SLOT_BINOP: u64 = 0x20;
const SLOT_COMPARE: u64 = 0x40;
const SLOT_ISTRUE: u64 = 0x198;
const MAX_STEPS: usize = 4096;

#[must_use]
pub(crate) const fn richcompare_selector(selector: u64) -> Option<&'static str> {
    match selector {
        0 => Some("<"),
        1 => Some("<="),
        2 => Some("=="),
        3 => Some("!="),
        4 => Some(">"),
        5 => Some(">="),
        _ => None,
    }
}

const fn invert_compare(op: &str) -> Option<&'static str> {
    match op.as_bytes() {
        b"<" => Some(">="),
        b"<=" => Some(">"),
        b">" => Some("<="),
        b">=" => Some("<"),
        b"==" => Some("!="),
        b"!=" => Some("=="),
        _ => None,
    }
}

#[derive(Clone)]
enum Cond {
    Cmp(PyExpr, &'static str, PyExpr),
    Opaque,
}

impl Cond {
    fn negate(self) -> Option<Self> {
        match self {
            Self::Cmp(left, op, right) => {
                invert_compare(op).map(|inv: &'static str| Self::Cmp(left, inv, right))
            }
            Self::Opaque => None,
        }
    }

    fn to_expr(&self) -> Option<PyExpr> {
        match self {
            Self::Cmp(left, op, right) => Some(PyExpr::Compare(
                Box::new(left.clone()),
                op,
                Box::new(right.clone()),
            )),
            Self::Opaque => None,
        }
    }
}

#[derive(Clone)]
enum Val {
    Param(usize),
    Expr(PyExpr),
    Local,
    CompareObj(Cond),
    Bool { cond: Cond, negated: bool },
    Rsp(i64),
    FramePtr(i64),
    RuntimeTable,
    RuntimeSlotAddr(u64),
    RuntimeSlot(u64),
    Machine(u64),
    Unknown,
}

struct Machine<'a> {
    options: &'a RecoverOptions,
    abi_args: &'static [&'static str],
    regs: BTreeMap<String, Val>,
    frame: BTreeMap<i64, Val>,
    local_slot: Option<i64>,
    local_name: String,
    body: Vec<String>,
    steps: usize,
}

impl<'a> Machine<'a> {
    fn new(options: &'a RecoverOptions) -> Self {
        let abi_args: &'static [&'static str] = options.abi.arg_registers();
        let mut regs: BTreeMap<String, Val> = BTreeMap::new();
        for (index, name) in abi_args.iter().enumerate().take(options.argcount) {
            regs.insert((*name).to_owned(), Val::Param(index));
        }
        regs.insert("rsp".to_owned(), Val::Rsp(0));
        Self {
            options,
            abi_args,
            regs,
            frame: BTreeMap::new(),
            local_slot: None,
            local_name: local_identifier(options),
            body: Vec::new(),
            steps: 0,
        }
    }

    fn eval(&self, name: &str) -> Val {
        if let Some(value) = parse_immediate(name) {
            return Val::Machine(value);
        }
        self.regs.get(name).cloned().unwrap_or(Val::Unknown)
    }

    fn assign(&mut self, name: &str, value: Val) {
        self.regs.insert(name.to_owned(), value);
    }

    fn to_expr(&self, value: &Val) -> Option<PyExpr> {
        match value {
            Val::Param(index) => Some(PyExpr::Name(self.options.param(*index))),
            Val::Expr(expr) => Some(expr.clone()),
            Val::Local => Some(PyExpr::Name(self.local_name.clone())),
            _ => None,
        }
    }

    fn load(&self, address: &Val) -> Val {
        match address {
            Val::Machine(_) => Val::RuntimeTable,
            Val::RuntimeSlotAddr(offset) => Val::RuntimeSlot(*offset),
            Val::FramePtr(offset) => self.frame.get(offset).cloned().unwrap_or(Val::Unknown),
            _ => Val::Unknown,
        }
    }

    fn step_dataflow(&mut self, instruction: &NirInstr) {
        match &instruction.op {
            NirOp::Copy { src, .. } => {
                let value: Val = self.eval(src);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, value);
                }
            }
            NirOp::Value {
                op, inputs, size, ..
            } => {
                let folded: Val = self.fold_value(*op, inputs, *size);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, folded);
                }
            }
            NirOp::RawLoad { addr, .. } => {
                let address: Val = self.eval(addr);
                let value: Val = self.load(&address);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, value);
                }
            }
            NirOp::RawStore { addr, value, .. } => {
                let address: Val = self.eval(addr);
                let stored: Val = self.eval(value);
                if let Val::FramePtr(offset) = address {
                    self.frame.insert(offset, stored);
                }
            }
            NirOp::Subpiece { src, offset, .. } if *offset == 0 => {
                let value: Val = self.eval(src);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, passthrough(value));
                }
            }
            NirOp::Deposit {
                cell,
                value,
                offset,
                zero_upper,
                ..
            } if *zero_upper && *offset == 0 => {
                let evaluated: Val = self.eval(value);
                self.assign(cell, passthrough(evaluated));
            }
            _ => {
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, Val::Unknown);
                }
            }
        }
    }

    fn fold_value(&self, op: ValueOp, inputs: &[String], size: u32) -> Val {
        let first: Val = inputs
            .first()
            .map_or(Val::Unknown, |n: &String| self.eval(n));
        let second: Val = inputs
            .get(1)
            .map_or(Val::Unknown, |n: &String| self.eval(n));
        match op {
            ValueOp::IntZext | ValueOp::IntSext => passthrough(first),
            ValueOp::BoolNegate => match first {
                Val::Bool { cond, negated } => Val::Bool {
                    cond,
                    negated: !negated,
                },
                _ => Val::Unknown,
            },
            ValueOp::IntAdd => match (&first, &second) {
                (Val::Rsp(delta), Val::Machine(value)) | (Val::Machine(value), Val::Rsp(delta)) => {
                    Val::FramePtr(delta.saturating_add(i64_of(*value)))
                }
                (Val::RuntimeTable, Val::Machine(value))
                | (Val::Machine(value), Val::RuntimeTable) => Val::RuntimeSlotAddr(*value),
                _ => Val::Unknown,
            },
            ValueOp::IntSub => match (&first, &second) {
                (Val::Rsp(delta), Val::Machine(value)) => {
                    Val::Rsp(delta.saturating_sub(i64_of(*value)))
                }
                (Val::Machine(a), Val::Machine(b)) => {
                    Val::Machine(a.wrapping_sub(*b) & mask_for(size))
                }
                _ => Val::Unknown,
            },
            _ => Val::Unknown,
        }
    }

    fn step_call(&mut self, instruction: &NirInstr) {
        let called: Val = match &instruction.op {
            NirOp::IndirectCall => instruction
                .operands
                .first()
                .map_or(Val::Unknown, |name: &String| self.eval(name)),
            _ => Val::Unknown,
        };
        let result: Val = match called {
            Val::RuntimeSlot(SLOT_BINOP) => self.dispatch_binop(),
            Val::RuntimeSlot(SLOT_COMPARE) => self.dispatch_compare(),
            Val::RuntimeSlot(SLOT_ISTRUE) => self.dispatch_istrue(),
            _ => Val::Unknown,
        };
        self.clobber_after_call();
        self.assign("rax", result);
    }

    fn arg(&self, index: usize) -> Val {
        self.abi_args
            .get(index)
            .map_or(Val::Unknown, |name: &&str| self.eval(name))
    }

    fn dispatch_binop(&self) -> Val {
        let left: Val = self.arg(0);
        let right: Val = self.arg(1);
        let selector: Option<u64> = match self.arg(2) {
            Val::Machine(value) => Some(value),
            _ => None,
        };
        let Some((operator, _)): Option<(&str, &str)> = selector.and_then(binop_selector) else {
            return Val::Unknown;
        };
        match (self.to_expr(&left), self.to_expr(&right)) {
            (Some(left_expr), Some(right_expr)) => Val::Expr(PyExpr::Binary(
                Box::new(left_expr),
                operator,
                Box::new(right_expr),
            )),
            _ => Val::Unknown,
        }
    }

    fn dispatch_compare(&self) -> Val {
        let left: Val = self.arg(0);
        let right: Val = self.arg(1);
        let (Some(left_expr), Some(right_expr)): (Option<PyExpr>, Option<PyExpr>) =
            (self.to_expr(&left), self.to_expr(&right))
        else {
            return Val::Unknown;
        };
        match self.arg(2) {
            Val::Machine(selector) => richcompare_selector(selector).map_or_else(
                || Val::CompareObj(Cond::Opaque),
                |operator: &'static str| {
                    Val::CompareObj(Cond::Cmp(left_expr, operator, right_expr))
                },
            ),
            _ => Val::CompareObj(Cond::Opaque),
        }
    }

    fn dispatch_istrue(&self) -> Val {
        match self.arg(0) {
            Val::CompareObj(cond) => Val::Bool {
                cond,
                negated: false,
            },
            _ => Val::Unknown,
        }
    }

    fn clobber_after_call(&mut self) {
        for register in self.options.abi.volatile_registers() {
            self.regs.remove(*register);
        }
    }

    fn establish_local(&mut self, offset: i64) {
        self.local_slot = Some(offset);
        self.frame.insert(offset, Val::Local);
    }
}

fn passthrough(value: Val) -> Val {
    match value {
        Val::Machine(_)
        | Val::Param(_)
        | Val::Expr(_)
        | Val::Local
        | Val::CompareObj(_)
        | Val::Bool { .. } => value,
        _ => Val::Unknown,
    }
}

fn local_identifier(options: &RecoverOptions) -> String {
    let params: BTreeSet<String> = (0..options.argcount)
        .map(|index: usize| options.param(index))
        .collect();
    for candidate in ["result", "value", "acc", "local"] {
        if !params.contains(candidate) {
            return candidate.to_owned();
        }
    }
    let mut name: String = "local0".to_owned();
    let mut index: usize = 0;
    while params.contains(&name) {
        index = index.saturating_add(1);
        name = format!("local{index}");
    }
    name
}

fn parse_immediate(name: &str) -> Option<u64> {
    let body: &str = name
        .strip_prefix("0x")
        .or_else(|| name.strip_prefix("0X"))?;
    u64::from_str_radix(body, 16).ok()
}

const fn mask_for(size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    if bits >= 64 {
        u64::MAX
    } else {
        match 1_u64.checked_shl(bits) {
            Some(shifted) => shifted - 1,
            None => u64::MAX,
        }
    }
}

const fn i64_of(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

struct BlockView<'a> {
    by_start: BTreeMap<u64, &'a NirBlock>,
}

impl<'a> BlockView<'a> {
    fn new(blocks: &'a [NirBlock]) -> Self {
        let mut by_start: BTreeMap<u64, &'a NirBlock> = BTreeMap::new();
        for block in blocks {
            by_start.entry(block.start).or_insert(block);
        }
        Self { by_start }
    }

    fn block(&self, start: u64) -> Option<&'a NirBlock> {
        self.by_start.get(&start).copied()
    }
}

#[must_use]
pub(crate) fn recover_structured(
    nir: &NirFunction,
    options: &RecoverOptions,
    notes: &mut Vec<String>,
) -> Option<String> {
    let blocks: Vec<NirBlock> = basic_blocks(nir);
    let entry: &NirBlock = blocks.first()?;
    let view: BlockView<'_> = BlockView::new(&blocks);
    let mut machine: Machine<'_> = Machine::new(options);
    let mut visited: BTreeSet<u64> = BTreeSet::new();
    let mut current: u64 = entry.start;

    loop {
        machine.steps = machine.steps.saturating_add(1);
        if machine.steps > MAX_STEPS {
            return None;
        }
        if !visited.insert(current) {
            return None;
        }
        let block: &NirBlock = view.block(current)?;
        match walk_block(&mut machine, block, &view, notes)? {
            Flow::Return(expr) => {
                return Some(finish(options, &machine, &expr));
            }
            Flow::Goto(target) => current = target,
        }
    }
}

enum Flow {
    Return(PyExpr),
    Goto(u64),
}

fn walk_block(
    machine: &mut Machine<'_>,
    block: &NirBlock,
    view: &BlockView<'_>,
    notes: &mut Vec<String>,
) -> Option<Flow> {
    let count: usize = block.instructions.len();
    for (index, instruction) in block.instructions.iter().enumerate() {
        let is_last: bool = index + 1 == count;
        match instruction.class() {
            NirClass::Other => {
                machine.step_dataflow(instruction);
                record_store(machine, instruction);
            }
            NirClass::Call => machine.step_call(instruction),
            NirClass::Return => {
                let expr: PyExpr = return_expression(machine, instruction)?;
                return Some(Flow::Return(expr));
            }
            NirClass::ConditionalJump if is_last => {
                return conditional_region(machine, block, instruction, view, notes);
            }
            NirClass::UnconditionalJump if is_last => {
                let target: u64 = instruction.direct_target()?;
                return Some(Flow::Goto(target));
            }
            NirClass::ConditionalJump | NirClass::UnconditionalJump => return None,
        }
    }
    let fallthrough: u64 = block.successors.first().copied()?;
    Some(Flow::Goto(fallthrough))
}

fn record_store(machine: &mut Machine<'_>, instruction: &NirInstr) {
    let NirOp::RawStore { addr, value, .. } = &instruction.op else {
        return;
    };
    let address: Val = machine.eval(addr);
    let Val::FramePtr(offset): Val = address else {
        return;
    };
    let stored: Val = machine.eval(value);
    let Some(expr): Option<PyExpr> = machine.to_expr(&stored) else {
        return;
    };
    let is_local: bool = machine.local_slot == Some(offset);
    let first_local: bool = machine.local_slot.is_none();
    if is_local || first_local {
        machine
            .body
            .push(format!("    {} = {}", machine.local_name, expr.render()));
        machine.establish_local(offset);
    }
}

fn return_expression(machine: &Machine<'_>, instruction: &NirInstr) -> Option<PyExpr> {
    let operand: &String = instruction.operands.first()?;
    let value: Val = machine.eval(operand);
    machine.to_expr(&value)
}

fn conditional_region(
    machine: &mut Machine<'_>,
    block: &NirBlock,
    branch: &NirInstr,
    view: &BlockView<'_>,
    notes: &mut Vec<String>,
) -> Option<Flow> {
    let tested: &String = branch.operands.first()?;
    let Val::Bool { cond, negated }: Val = machine.eval(tested) else {
        notes.push(
            "branch predicate did not reduce to a recovered compare truth-test; body left native"
                .to_owned(),
        );
        return None;
    };
    let taken: u64 = branch.direct_target()?;
    let fallthrough: u64 = block
        .successors
        .iter()
        .copied()
        .find(|s: &u64| *s != taken)?;

    let taken_arm: Option<(i64, PyExpr)> = assign_arm(machine, view, taken, fallthrough);
    let fall_arm: Option<(i64, PyExpr)> = assign_arm(machine, view, fallthrough, taken);

    let (assign_when_taken, merge, offset, value): (bool, u64, i64, PyExpr) =
        match (taken_arm, fall_arm) {
            (Some((offset, value)), None) => (true, fallthrough, offset, value),
            (None, Some((offset, value))) => (false, taken, offset, value),
            _ => {
                notes.push(
                    "conditional did not form a single guarded local assignment; body left native"
                        .to_owned(),
                );
                return None;
            }
        };

    if machine.local_slot != Some(offset) {
        notes.push("guarded assignment targets a slot other than the tracked local".to_owned());
        return None;
    }

    let taken_cond: Cond = if negated { cond.negate()? } else { cond };
    let guard: Cond = if assign_when_taken {
        taken_cond
    } else {
        taken_cond.negate()?
    };
    let Some(guard_expr): Option<PyExpr> = guard.to_expr() else {
        notes.push(
            "compare selector is runtime-determined (operator-unverified); structural recovery gated"
                .to_owned(),
        );
        return None;
    };

    machine
        .body
        .push(format!("    if {}:", guard_expr.render()));
    machine.body.push(format!(
        "        {} = {}",
        machine.local_name,
        value.render()
    ));
    Some(Flow::Goto(merge))
}

fn assign_arm(
    machine: &Machine<'_>,
    view: &BlockView<'_>,
    arm: u64,
    merge: u64,
) -> Option<(i64, PyExpr)> {
    if arm == merge {
        return None;
    }
    let block: &NirBlock = view.block(arm)?;
    let mut probe: Machine<'_> = clone_state(machine);
    let mut assignment: Option<(i64, PyExpr)> = None;
    let count: usize = block.instructions.len();
    for (index, instruction) in block.instructions.iter().enumerate() {
        let is_last: bool = index + 1 == count;
        match instruction.class() {
            NirClass::Other => {
                if let NirOp::RawStore { addr, value, .. } = &instruction.op {
                    let address: Val = probe.eval(addr);
                    if let Val::FramePtr(offset) = address {
                        let stored: Val = probe.eval(value);
                        if let Some(expr) = probe.to_expr(&stored) {
                            if assignment.is_some() {
                                return None;
                            }
                            assignment = Some((offset, expr));
                        } else {
                            return None;
                        }
                    }
                }
                probe.step_dataflow(instruction);
            }
            NirClass::UnconditionalJump if is_last => {
                let target: u64 = instruction.direct_target()?;
                return (target == merge).then_some(assignment).flatten();
            }
            NirClass::Call
            | NirClass::Return
            | NirClass::ConditionalJump
            | NirClass::UnconditionalJump => return None,
        }
    }
    let fallthrough: u64 = block.successors.first().copied()?;
    (fallthrough == merge).then_some(assignment).flatten()
}

fn clone_state<'a>(machine: &Machine<'a>) -> Machine<'a> {
    Machine {
        options: machine.options,
        abi_args: machine.abi_args,
        regs: machine.regs.clone(),
        frame: machine.frame.clone(),
        local_slot: machine.local_slot,
        local_name: machine.local_name.clone(),
        body: Vec::new(),
        steps: machine.steps,
    }
}

fn finish(options: &RecoverOptions, machine: &Machine<'_>, ret: &PyExpr) -> String {
    let params: Vec<String> = (0..options.argcount)
        .map(|index: usize| options.param(index))
        .collect();
    let mut out: String = format!("def {}({}):\n", options.func_name, params.join(", "));
    for line in &machine.body {
        out.push_str(line);
        out.push('\n');
    }
    let _ = writeln!(out, "    return {}", ret.render());
    out
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::vec_init_then_push
)]
mod tests {
    use std::process::Command;

    use disrobe_nir::{SourceLang, SourceRef};

    use super::*;
    use crate::PyAbi;

    fn value(address: u64, dest: &str, op: ValueOp, a: &str, b: &str) -> NirInstr {
        instr(
            address,
            NirOp::Value {
                op,
                inputs: vec![a.to_owned(), b.to_owned()],
                input_sizes: vec![8, 8],
                size: 8,
            },
            &[dest, a, b],
        )
    }

    fn frame_ptr(address: u64, dest: &str, offset: &str) -> NirInstr {
        value(address, dest, ValueOp::IntAdd, "rsp", offset)
    }

    fn raw_load(address: u64, dest: &str, addr: &str) -> NirInstr {
        instr(
            address,
            NirOp::RawLoad {
                addr: addr.to_owned(),
                size: 8,
            },
            &[dest, addr],
        )
    }

    fn raw_store(address: u64, addr: &str, val: &str) -> NirInstr {
        instr(
            address,
            NirOp::RawStore {
                addr: addr.to_owned(),
                value: val.to_owned(),
                size: 8,
            },
            &[addr, val],
        )
    }

    fn indirect(address: u64, target: &str) -> NirInstr {
        instr(address, NirOp::IndirectCall, &[target])
    }

    fn cond_branch(address: u64, target: u64, flag: &str) -> NirInstr {
        instr(
            address,
            NirOp::CondBranch {
                target: Some(target),
            },
            &[flag],
        )
    }

    fn branch(address: u64, target: u64) -> NirInstr {
        instr(
            address,
            NirOp::Branch {
                target: Some(target),
            },
            &[],
        )
    }

    fn guard(
        program: &mut Vec<NirInstr>,
        start: u64,
        right: &str,
        selector: &str,
        arm: u64,
        flag: &str,
    ) {
        let a = |offset: u64| -> u64 { start.saturating_add(offset.saturating_mul(2)) };
        program.push(frame_ptr(a(0), "t_left", "0x20"));
        program.push(raw_load(a(1), "rcx", "t_left"));
        program.push(frame_ptr(a(2), "t_right", right));
        program.push(raw_load(a(3), "rdx", "t_right"));
        program.push(copy(a(4), "r8", selector));
        program.push(raw_load(a(5), "rax", "0xf90"));
        program.push(value(a(6), "t_cmp", ValueOp::IntAdd, "rax", "0x40"));
        program.push(raw_load(a(7), "t_cmp_fn", "t_cmp"));
        program.push(indirect(a(8), "t_cmp_fn"));
        program.push(copy(a(9), "rcx", "rax"));
        program.push(raw_load(a(10), "rax", "0xf90"));
        program.push(value(a(11), "t_truth", ValueOp::IntAdd, "rax", "0x198"));
        program.push(raw_load(a(12), "t_truth_fn", "t_truth"));
        program.push(indirect(a(13), "t_truth_fn"));
        program.push(copy(a(14), flag, "rax"));
        program.push(cond_branch(a(15), arm, flag));
    }

    fn arm(program: &mut Vec<NirInstr>, start: u64, source: &str, target: u64) {
        program.push(frame_ptr(start, "t_src", source));
        program.push(raw_load(start + 2, "t_val", "t_src"));
        program.push(frame_ptr(start + 4, "t_dst", "0x20"));
        program.push(raw_store(start + 6, "t_dst", "t_val"));
        program.push(branch(start + 8, target));
    }

    fn clamp_nir() -> NirFunction {
        const GUARD2: u64 = 0x200;
        const RETURN: u64 = 0x280;
        const ARM1: u64 = 0x300;
        const ARM2: u64 = 0x380;
        let mut program: Vec<NirInstr> = Vec::new();
        program.push(frame_ptr(0x100, "t_r", "0x20"));
        program.push(raw_store(0x102, "t_r", "rcx"));
        program.push(frame_ptr(0x104, "t_lo", "0x28"));
        program.push(raw_store(0x106, "t_lo", "rdx"));
        program.push(frame_ptr(0x108, "t_hi", "0x30"));
        program.push(raw_store(0x10a, "t_hi", "r8"));
        guard(&mut program, 0x10c, "0x28", "0x0", ARM1, "f_low");
        guard(&mut program, GUARD2, "0x30", "0x4", ARM2, "f_high");
        program.push(frame_ptr(RETURN, "t_ret", "0x20"));
        program.push(raw_load(RETURN + 2, "rax", "t_ret"));
        program.push(instr(RETURN + 4, NirOp::Return, &["rax"]));
        arm(&mut program, ARM1, "0x28", GUARD2);
        arm(&mut program, ARM2, "0x30", RETURN);
        NirFunction {
            name: "clamp".to_owned(),
            address: 0x100,
            end: 0x400,
            is_export: false,
            instructions: program,
            source: SourceRef::new(SourceLang::NativeX86, 0x100),
        }
    }

    fn clamp_options() -> RecoverOptions {
        let mut options: RecoverOptions = RecoverOptions::new("clamp", PyAbi::Win64, 3);
        options.param_names = vec!["value".to_owned(), "low".to_owned(), "high".to_owned()];
        options
    }

    fn interpreter() -> Option<String> {
        for candidate in ["python", "python3", "py"] {
            if Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|o: std::process::Output| o.status.success())
            {
                return Some(candidate.to_owned());
            }
        }
        None
    }

    fn instr(address: u64, op: NirOp, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: String::new(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn copy(address: u64, dest: &str, src: &str) -> NirInstr {
        instr(
            address,
            NirOp::Copy {
                src: src.to_owned(),
                size: 8,
            },
            &[dest],
        )
    }

    #[test]
    fn copy_and_branch_helpers_are_available() {
        let node: NirInstr = copy(0, "rax", "rcx");
        assert!(matches!(node.op, NirOp::Copy { .. }));
    }

    #[test]
    fn richcompare_selectors_follow_cpython_op_ids() {
        assert_eq!(richcompare_selector(0), Some("<"));
        assert_eq!(richcompare_selector(1), Some("<="));
        assert_eq!(richcompare_selector(2), Some("=="));
        assert_eq!(richcompare_selector(3), Some("!="));
        assert_eq!(richcompare_selector(4), Some(">"));
        assert_eq!(richcompare_selector(5), Some(">="));
        assert_eq!(richcompare_selector(6), None);
    }

    #[test]
    fn compare_operator_inversion_is_total_on_the_six_ops() {
        assert_eq!(invert_compare("<"), Some(">="));
        assert_eq!(invert_compare("<="), Some(">"));
        assert_eq!(invert_compare(">"), Some("<="));
        assert_eq!(invert_compare(">="), Some("<"));
        assert_eq!(invert_compare("=="), Some("!="));
        assert_eq!(invert_compare("!="), Some("=="));
        assert_eq!(invert_compare("+"), None);
    }

    #[test]
    fn irreducible_or_unrecognized_body_degrades_to_none() {
        let function: NirFunction = NirFunction {
            name: "weird".to_owned(),
            address: 0,
            end: 0x4,
            is_export: false,
            instructions: vec![
                copy(0x0, "rax", "rcx"),
                instr(0x2, NirOp::Branch { target: None }, &["rax"]),
            ],
            source: SourceRef::new(SourceLang::NativeX86, 0),
        };
        let options: RecoverOptions = RecoverOptions::new("weird", PyAbi::Win64, 1);
        let mut notes: Vec<String> = Vec::new();
        assert!(recover_structured(&function, &options, &mut notes).is_none());
    }

    #[test]
    fn local_identifier_avoids_parameter_collisions() {
        let mut options: RecoverOptions = RecoverOptions::new("f", PyAbi::Win64, 2);
        options.param_names = vec!["result".to_owned(), "value".to_owned()];
        assert_eq!(local_identifier(&options), "acc");
    }

    #[test]
    fn guarded_local_reassignment_body_recovers_to_python() {
        let function: NirFunction = clamp_nir();
        let options: RecoverOptions = clamp_options();
        let mut notes: Vec<String> = Vec::new();
        let body: String = recover_structured(&function, &options, &mut notes)
            .expect("clean guarded-local body must structure");
        assert_eq!(
            body,
            "def clamp(value, low, high):\n    result = value\n    if result < low:\n        result = low\n    if result > high:\n        result = high\n    return result\n",
            "recovered body: {body}"
        );
    }

    #[test]
    fn recovered_body_matches_cpython_over_fuzzed_inputs() {
        let function: NirFunction = clamp_nir();
        let options: RecoverOptions = clamp_options();
        let mut notes: Vec<String> = Vec::new();
        let body: String = recover_structured(&function, &options, &mut notes)
            .expect("clean guarded-local body must structure");
        let Some(python): Option<String> = interpreter() else {
            eprintln!("no python interpreter present; skipping behavioral differential");
            return;
        };
        let script: String = format!(
            "import itertools, sys\n\
             def reference(value, low, high):\n\
             \x20   r = value\n\
             \x20   if r < low: r = low\n\
             \x20   if r > high: r = high\n\
             \x20   return r\n\
             {body}\n\
             vals = [-9, -4, -1, 0, 1, 3, 8, 40, 100, 250]\n\
             for combo in itertools.product(vals, repeat=3):\n\
             \x20   want = reference(combo[0], combo[1], combo[2])\n\
             \x20   got = clamp(combo[0], combo[1], combo[2])\n\
             \x20   if want != got:\n\
             \x20       print('MISMATCH', combo, want, got); sys.exit(1)\n\
             print('OK')\n",
        );
        let dir: std::path::PathBuf =
            std::env::temp_dir().join(format!("disrobe-bcc-structure-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("scratch dir");
        let path: std::path::PathBuf = dir.join("check_clamp.py");
        std::fs::write(&path, script).expect("write script");
        let output: std::process::Output = Command::new(python)
            .arg(&path)
            .output()
            .expect("run python");
        let stdout: std::borrow::Cow<'_, str> = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("OK"),
            "recovered clamp diverges from CPython: {stdout}\nstderr: {}\nbody:\n{body}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
