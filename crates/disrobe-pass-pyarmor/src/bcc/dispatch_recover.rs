use std::collections::BTreeMap;
use std::fmt::Write as _;

use disrobe_nir::{NirClass, NirFunction, NirInstr, NirOp, ValueOp};
use disrobe_nir_lift::lower_x86_64;

use super::recover::{PyExpr, RecognizedCall, RecoverOptions, RecoveredBody};

const MAX_BODY_BYTES: usize = 256 * 1024;
const SLOT_BINOP: u64 = 0x20;
const SLOT_COMPARE: u64 = 0x40;
const SLOT_ISTRUE: u64 = 0x198;
const SLOT_UNPACK: u64 = 0x98;
const TUPLE_ITEM0: u64 = 0x18;
const PTR: u64 = 8;
const FUNC_CONSTS_ROW: u64 = 0x10;
const IGNORED_SLOTS: &[u64] = &[0x8, 0x38, 0x138];

#[must_use]
pub const fn binop_selector(selector: u64) -> Option<(&'static str, &'static str)> {
    let entry: (&'static str, &'static str) = match selector {
        0x07 => ("+", "PyNumber_Add"),
        0x08 => ("&", "PyNumber_And"),
        0x0c => ("//", "PyNumber_FloorDivide"),
        0x1c => ("<<", "PyNumber_Lshift"),
        0x1d => ("*", "PyNumber_Multiply"),
        0x1f => ("|", "PyNumber_Or"),
        0x21 => ("**", "PyNumber_Power"),
        0x22 => ("%", "PyNumber_Remainder"),
        0x23 => (">>", "PyNumber_Rshift"),
        0x24 => ("-", "PyNumber_Subtract"),
        0x25 => ("/", "PyNumber_TrueDivide"),
        0x26 => ("^", "PyNumber_Xor"),
        0x4b => ("@", "PyNumber_MatrixMultiply"),
        _ => return None,
    };
    Some(entry)
}

#[derive(Debug, Clone)]
enum BccVal {
    Param(usize),
    PyConst(i128),
    Call(usize),
    Machine(u64),
    Frame(i64),
    RuntimeTable,
    RuntimeSlotAddr(u64),
    RuntimeSlot(u64),
    FuncObj,
    FuncConstsCountAddr,
    FuncConstsCount,
    FuncConstsScaled,
    FuncConstsRowAddr,
    FuncConstsItemAddr,
    ConstsTuple,
    ConstsItemAddr(u64),
    Unknown,
}

const EXECUTION_BUDGET: usize = 200_000;

struct PathState {
    index: usize,
    registers: BTreeMap<String, BccVal>,
    frame: BTreeMap<i64, BccVal>,
}

struct BccMachine<'a> {
    options: &'a RecoverOptions,
    consts: &'a [Option<i128>],
    abi_args: &'static [&'static str],
    registers: BTreeMap<String, BccVal>,
    frame: BTreeMap<i64, BccVal>,
    call_exprs: Vec<Option<PyExpr>>,
    dispatch_calls: Vec<RecognizedCall>,
    dispatch_index: BTreeMap<u64, usize>,
    returns: Vec<BccVal>,
    saw_branch: bool,
    bail: Option<String>,
}

impl<'a> BccMachine<'a> {
    fn new(options: &'a RecoverOptions, consts: &'a [Option<i128>]) -> Self {
        let abi_args: &'static [&'static str] = options.abi.arg_registers();
        let mut registers: BTreeMap<String, BccVal> = BTreeMap::new();
        if let Some(first) = abi_args.first() {
            registers.insert((*first).to_owned(), BccVal::FuncObj);
        }
        registers.insert("rsp".to_owned(), BccVal::Frame(0));
        Self {
            options,
            consts,
            abi_args,
            registers,
            frame: BTreeMap::new(),
            call_exprs: Vec::new(),
            dispatch_calls: Vec::new(),
            dispatch_index: BTreeMap::new(),
            returns: Vec::new(),
            saw_branch: false,
            bail: None,
        }
    }

    fn eval(&self, name: &str) -> BccVal {
        if let Some(value) = parse_immediate(name) {
            return BccVal::Machine(value);
        }
        self.registers.get(name).cloned().unwrap_or(BccVal::Unknown)
    }

    fn arg(&self, index: usize) -> BccVal {
        self.abi_args
            .get(index)
            .map_or(BccVal::Unknown, |name: &&str| self.eval(name))
    }

    fn assign(&mut self, name: &str, value: BccVal) {
        self.registers.insert(name.to_owned(), value);
    }

    fn run(&mut self, nir: &NirFunction) {
        let addr_to_index: BTreeMap<u64, usize> = index_by_address(nir);
        let mut visited: std::collections::BTreeSet<u64> = std::collections::BTreeSet::new();
        let mut worklist: Vec<PathState> = vec![PathState {
            index: 0,
            registers: self.registers.clone(),
            frame: self.frame.clone(),
        }];
        let mut steps: usize = 0;
        while let Some(path) = worklist.pop() {
            self.registers = path.registers;
            self.frame = path.frame;
            let mut pc: usize = path.index;
            while pc < nir.instructions.len() {
                steps += 1;
                if steps > EXECUTION_BUDGET {
                    self.bail = Some("execution budget exceeded before a return".to_owned());
                    return;
                }
                let instruction: &NirInstr = &nir.instructions[pc];
                match instruction.class() {
                    NirClass::Return => {
                        let value: BccVal = instruction
                            .operands
                            .first()
                            .map_or(BccVal::Unknown, |name: &String| self.eval(name));
                        self.returns.push(value);
                        break;
                    }
                    NirClass::UnconditionalJump => {
                        let Some(target): Option<u64> = instruction.direct_target() else {
                            break;
                        };
                        if !visited.insert(target) {
                            break;
                        }
                        let Some(next): Option<&usize> = addr_to_index.get(&target) else {
                            break;
                        };
                        pc = *next;
                    }
                    NirClass::ConditionalJump => {
                        self.saw_branch = true;
                        if let Some(dest) = instruction.direct_target()
                            && visited.insert(dest)
                            && let Some(next) = addr_to_index.get(&dest)
                        {
                            worklist.push(PathState {
                                index: *next,
                                registers: self.registers.clone(),
                                frame: self.frame.clone(),
                            });
                        }
                        pc += 1;
                    }
                    NirClass::Call => {
                        self.step_call(instruction);
                        pc += 1;
                    }
                    NirClass::Other => {
                        self.step_dataflow(instruction);
                        pc += 1;
                    }
                }
            }
        }
    }

    fn step_call(&mut self, instruction: &NirInstr) {
        let called: BccVal = match &instruction.op {
            NirOp::IndirectCall => instruction
                .operands
                .first()
                .map_or(BccVal::Unknown, |name: &String| self.eval(name)),
            _ => BccVal::Unknown,
        };
        let result: BccVal = match called {
            BccVal::RuntimeSlot(SLOT_BINOP) => self.step_dispatch(instruction.address),
            BccVal::RuntimeSlot(SLOT_UNPACK) => {
                self.step_unpack();
                BccVal::Unknown
            }
            BccVal::RuntimeSlot(SLOT_COMPARE) => {
                self.record_opaque_dispatch(instruction.address, "PyObject_RichCompare");
                BccVal::Unknown
            }
            BccVal::RuntimeSlot(SLOT_ISTRUE) => {
                self.record_opaque_dispatch(instruction.address, "PyObject_IsTrue");
                BccVal::Unknown
            }
            BccVal::RuntimeSlot(slot) if IGNORED_SLOTS.contains(&slot) => BccVal::Unknown,
            BccVal::RuntimeSlot(slot) => {
                self.bail = Some(format!(
                    "indirect call through unmodeled runtime dispatch slot {slot:#x}"
                ));
                BccVal::Unknown
            }
            _ => BccVal::Unknown,
        };
        self.clobber_after_call();
        self.assign("rax", result);
    }

    fn step_dispatch(&mut self, address: u64) -> BccVal {
        if let Some(existing) = self.dispatch_index.get(&address) {
            let index: usize = *existing;
            return if self
                .call_exprs
                .get(index)
                .and_then(Option::as_ref)
                .is_some()
            {
                BccVal::Call(index)
            } else {
                BccVal::Unknown
            };
        }
        let index: usize = self.call_exprs.len();
        self.dispatch_index.insert(address, index);
        let selector: Option<u64> = match self.arg(2) {
            BccVal::Machine(value) => Some(value),
            _ => None,
        };
        let left: BccVal = self.arg(0);
        let right: BccVal = self.arg(1);
        let resolved: Option<(&'static str, &'static str)> = selector.and_then(binop_selector);
        let expr: Option<PyExpr> = match resolved {
            Some((operator, _)) => match (self.to_expr(&left), self.to_expr(&right)) {
                (Some(l), Some(r)) => Some(PyExpr::Binary(Box::new(l), operator, Box::new(r))),
                _ => None,
            },
            None => None,
        };
        let symbol: Option<String> = resolved.map(|(_, name): (&str, &str)| name.to_owned());
        let python: Option<String> = expr.as_ref().map(PyExpr::render);
        self.dispatch_calls.push(RecognizedCall {
            call_site: address,
            symbol,
            python,
        });
        let result: BccVal = if expr.is_some() {
            BccVal::Call(index)
        } else {
            BccVal::Unknown
        };
        self.call_exprs.push(expr);
        result
    }

    fn record_opaque_dispatch(&mut self, address: u64, symbol: &str) {
        if self.dispatch_index.contains_key(&address) {
            return;
        }
        let index: usize = self.call_exprs.len();
        self.dispatch_index.insert(address, index);
        self.dispatch_calls.push(RecognizedCall {
            call_site: address,
            symbol: Some(symbol.to_owned()),
            python: None,
        });
        self.call_exprs.push(None);
    }

    fn step_unpack(&mut self) {
        let base: Option<i64> = match self.arg(3) {
            BccVal::Frame(offset) => Some(offset),
            _ => None,
        };
        let count: usize = match self.arg(2) {
            BccVal::Machine(value) => usize::try_from(value).unwrap_or(self.options.argcount),
            _ => self.options.argcount,
        };
        let Some(anchor): Option<i64> = base else {
            return;
        };
        let bound: usize = count.min(self.options.argcount);
        for index in 0..bound {
            let stride: i64 = i64::try_from(index)
                .unwrap_or(0)
                .saturating_mul(i64::try_from(PTR).unwrap_or(8));
            let offset: i64 = anchor.saturating_add(stride);
            self.frame.insert(offset, BccVal::Param(index));
        }
    }

    fn clobber_after_call(&mut self) {
        for register in self.options.abi.volatile_registers() {
            self.registers.remove(*register);
        }
        if let BccVal::Frame(offset) = self.eval("rsp") {
            let restored: i64 = offset.saturating_add(i64::try_from(PTR).unwrap_or(8));
            self.registers
                .insert("rsp".to_owned(), BccVal::Frame(restored));
        }
    }

    fn step_dataflow(&mut self, instruction: &NirInstr) {
        match &instruction.op {
            NirOp::Copy { src, .. } => {
                let value: BccVal = self.eval(src);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, value);
                }
            }
            NirOp::Subpiece { src, offset, size } => {
                let value: BccVal = self.eval(src);
                let folded: BccVal = fold_subpiece(&value, *offset, *size);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, folded);
                }
            }
            NirOp::Deposit {
                cell,
                value,
                offset,
                size,
                zero_upper,
                ..
            } => {
                let evaluated: BccVal = self.eval(value);
                let folded: BccVal = if *zero_upper && *offset == 0 {
                    mask(&evaluated, *size)
                } else {
                    BccVal::Unknown
                };
                self.assign(cell, folded);
            }
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                size,
            } => {
                let folded: BccVal = self.fold_value(*op, inputs, input_sizes, *size);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, folded);
                }
            }
            NirOp::RawLoad { addr, .. } => {
                let address: BccVal = self.eval(addr);
                let value: BccVal = self.load(&address);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, value);
                }
            }
            NirOp::RawStore { addr, value, .. } => {
                let address: BccVal = self.eval(addr);
                let stored: BccVal = self.eval(value);
                if let BccVal::Frame(offset) = address {
                    self.frame.insert(offset, stored);
                }
            }
            NirOp::Piece { .. } => {
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, BccVal::Unknown);
                }
            }
            _ => {}
        }
    }

    fn load(&self, address: &BccVal) -> BccVal {
        match address {
            BccVal::Machine(_) => BccVal::RuntimeTable,
            BccVal::RuntimeSlotAddr(offset) => BccVal::RuntimeSlot(*offset),
            BccVal::Frame(offset) => self.frame.get(offset).cloned().unwrap_or(BccVal::Unknown),
            BccVal::ConstsItemAddr(offset) => {
                let index: u64 = offset.saturating_sub(TUPLE_ITEM0) / PTR;
                usize::try_from(index)
                    .ok()
                    .and_then(|i: usize| self.consts.get(i).copied())
                    .flatten()
                    .map_or(BccVal::Unknown, BccVal::PyConst)
            }
            BccVal::FuncConstsCountAddr => BccVal::FuncConstsCount,
            BccVal::FuncConstsItemAddr => BccVal::ConstsTuple,
            _ => BccVal::Unknown,
        }
    }

    fn fold_value(&self, op: ValueOp, inputs: &[String], input_sizes: &[u32], size: u32) -> BccVal {
        let first: BccVal = inputs
            .first()
            .map_or(BccVal::Unknown, |n: &String| self.eval(n));
        let second: BccVal = inputs
            .get(1)
            .map_or(BccVal::Unknown, |n: &String| self.eval(n));
        match op {
            ValueOp::IntAdd => fold_add(&first, &second),
            ValueOp::IntSub => match (&first, &second) {
                (BccVal::Frame(offset), BccVal::Machine(value)) => {
                    BccVal::Frame(offset.saturating_sub(i64_of(*value)))
                }
                (BccVal::Machine(a), BccVal::Machine(b)) => {
                    BccVal::Machine(mask_to_size(a.wrapping_sub(*b), size))
                }
                _ => BccVal::Unknown,
            },
            ValueOp::IntMult => match (&first, &second) {
                (BccVal::FuncConstsCount, BccVal::Machine(PTR))
                | (BccVal::Machine(PTR), BccVal::FuncConstsCount) => BccVal::FuncConstsScaled,
                (BccVal::Machine(a), BccVal::Machine(b)) => {
                    BccVal::Machine(mask_to_size(a.wrapping_mul(*b), size))
                }
                _ => BccVal::Unknown,
            },
            ValueOp::IntZext => match &first {
                BccVal::Machine(value) => BccVal::Machine(*value),
                other => other.clone(),
            },
            ValueOp::IntSext => match &first {
                BccVal::Machine(value) => {
                    let source_width: u32 = input_sizes.first().copied().unwrap_or(size);
                    BccVal::Machine(sign_extend(*value, source_width))
                }
                other => other.clone(),
            },
            _ => match (&first, &second) {
                (BccVal::Machine(a), BccVal::Machine(b)) => fold_binary_machine(op, *a, *b)
                    .map_or(BccVal::Unknown, |value: u64| {
                        BccVal::Machine(mask_to_size(value, size))
                    }),
                _ => BccVal::Unknown,
            },
        }
    }

    fn to_expr(&self, value: &BccVal) -> Option<PyExpr> {
        match value {
            BccVal::Param(index) => Some(PyExpr::Name(self.options.param(*index))),
            BccVal::PyConst(constant) => Some(PyExpr::Num(*constant)),
            BccVal::Call(index) => self.call_exprs.get(*index).and_then(Clone::clone),
            _ => None,
        }
    }

    fn resolved_return(&self) -> Option<&PyExpr> {
        let mut best: Option<usize> = None;
        for value in &self.returns {
            if let BccVal::Call(index) = value
                && self
                    .call_exprs
                    .get(*index)
                    .and_then(Option::as_ref)
                    .is_some()
            {
                best = Some(best.map_or(*index, |prev: usize| prev.max(*index)));
            }
        }
        best.and_then(|index: usize| self.call_exprs.get(index).and_then(Option::as_ref))
    }

    fn resolved_returns_render_identically(&self) -> bool {
        let mut rendered: Option<String> = None;
        for value in &self.returns {
            let Some(expr): Option<PyExpr> = self.to_expr(value) else {
                continue;
            };
            let text: String = expr.render();
            match &rendered {
                Some(existing) if *existing != text => return false,
                _ => rendered = Some(text),
            }
        }
        rendered.is_some()
    }

    fn recovered_body(&self, notes: &mut Vec<String>) -> Option<String> {
        let total: usize = self.dispatch_calls.len();
        let recognized: usize = self
            .dispatch_calls
            .iter()
            .filter(|call: &&RecognizedCall| call.python.is_some())
            .count();
        if total == 0 {
            notes.push("no binary-op dispatcher call site present in the body".to_owned());
            return None;
        }
        if recognized != total {
            notes
                .push("not every dispatcher selector resolved to a supported binary op".to_owned());
            return None;
        }
        if self.saw_branch && !self.resolved_returns_render_identically() {
            notes.push(
                "control flow present; structured recovery of branches and loops is a later increment"
                    .to_owned(),
            );
            return None;
        }
        let Some(expr): Option<&PyExpr> = self.resolved_return() else {
            notes.push(
                "the return value did not reduce to a single resolved dispatcher expression"
                    .to_owned(),
            );
            return None;
        };
        let params: Vec<String> = (0..self.options.argcount)
            .map(|index: usize| self.options.param(index))
            .collect();
        Some(format!(
            "def {}({}):\n    return {}\n",
            self.options.func_name,
            params.join(", "),
            expr.render()
        ))
    }
}

fn index_by_address(nir: &NirFunction) -> BTreeMap<u64, usize> {
    let mut map: BTreeMap<u64, usize> = BTreeMap::new();
    for (index, instruction) in nir.instructions.iter().enumerate() {
        map.entry(instruction.address).or_insert(index);
    }
    map
}

const fn fold_add(first: &BccVal, second: &BccVal) -> BccVal {
    match (first, second) {
        (BccVal::Frame(offset), BccVal::Machine(value))
        | (BccVal::Machine(value), BccVal::Frame(offset)) => {
            BccVal::Frame(offset.saturating_add(i64_of(*value)))
        }
        (BccVal::RuntimeTable, BccVal::Machine(value))
        | (BccVal::Machine(value), BccVal::RuntimeTable) => BccVal::RuntimeSlotAddr(*value),
        (BccVal::ConstsTuple, BccVal::Machine(value))
        | (BccVal::Machine(value), BccVal::ConstsTuple)
            if *value >= TUPLE_ITEM0 =>
        {
            BccVal::ConstsItemAddr(*value)
        }
        (BccVal::FuncObj, BccVal::Machine(FUNC_CONSTS_ROW))
        | (BccVal::Machine(FUNC_CONSTS_ROW), BccVal::FuncObj) => BccVal::FuncConstsCountAddr,
        (BccVal::FuncObj, BccVal::FuncConstsScaled)
        | (BccVal::FuncConstsScaled, BccVal::FuncObj) => BccVal::FuncConstsRowAddr,
        (BccVal::FuncConstsRowAddr, BccVal::Machine(FUNC_CONSTS_ROW))
        | (BccVal::Machine(FUNC_CONSTS_ROW), BccVal::FuncConstsRowAddr) => {
            BccVal::FuncConstsItemAddr
        }
        (BccVal::Machine(a), BccVal::Machine(b)) => BccVal::Machine(a.wrapping_add(*b)),
        _ => BccVal::Unknown,
    }
}

fn parse_immediate(name: &str) -> Option<u64> {
    let body: &str = name
        .strip_prefix("0x")
        .or_else(|| name.strip_prefix("0X"))?;
    u64::from_str_radix(body, 16).ok()
}

fn fold_subpiece(value: &BccVal, offset: u32, size: u32) -> BccVal {
    match value {
        BccVal::Machine(constant) => {
            let shift: u32 = offset.saturating_mul(8);
            let shifted: u64 = constant.checked_shr(shift).unwrap_or(0);
            BccVal::Machine(mask_to_size(shifted, size))
        }
        other if offset == 0 => other.clone(),
        _ => BccVal::Unknown,
    }
}

fn mask(value: &BccVal, size: u32) -> BccVal {
    match value {
        BccVal::Machine(constant) => BccVal::Machine(mask_to_size(*constant, size)),
        other => other.clone(),
    }
}

fn mask_to_size(value: u64, size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    if bits >= 64 {
        value
    } else {
        let ceiling: u64 = 1_u64
            .checked_shl(bits)
            .map_or(u64::MAX, |shifted: u64| shifted - 1);
        value & ceiling
    }
}

fn sign_extend(value: u64, size_bytes: u32) -> u64 {
    let bits: u32 = size_bytes.saturating_mul(8);
    if bits == 0 || bits >= 64 {
        return value;
    }
    let sign_bit: u64 = 1_u64 << (bits - 1);
    let masked: u64 = mask_to_size(value, size_bytes);
    if masked & sign_bit != 0 {
        masked | !mask_to_size(u64::MAX, size_bytes)
    } else {
        masked
    }
}

fn fold_binary_machine(op: ValueOp, first: u64, second: u64) -> Option<u64> {
    match op {
        ValueOp::IntAnd => Some(first & second),
        ValueOp::IntOr => Some(first | second),
        ValueOp::IntXor => Some(first ^ second),
        ValueOp::IntLeft => Some(first.wrapping_shl(u32::try_from(second).unwrap_or(0))),
        ValueOp::IntRight => Some(first.wrapping_shr(u32::try_from(second).unwrap_or(0))),
        _ => None,
    }
}

const fn i64_of(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}

fn degraded(
    options: &RecoverOptions,
    machine: &BccMachine<'_>,
    notes: Vec<String>,
) -> RecoveredBody {
    let total: usize = machine.dispatch_calls.len();
    let recognized: usize = machine
        .dispatch_calls
        .iter()
        .filter(|call: &&RecognizedCall| call.python.is_some())
        .count();
    let annotation: String = render_annotation(options, &machine.dispatch_calls, total, recognized);
    RecoveredBody {
        func_name: options.func_name.clone(),
        total_call_sites: total,
        recognized_call_sites: recognized,
        recovered_python: None,
        calls: machine.dispatch_calls.clone(),
        annotation,
        notes,
    }
}

fn render_annotation(
    options: &RecoverOptions,
    calls: &[RecognizedCall],
    total: usize,
    recognized: usize,
) -> String {
    let mut output: String = String::new();
    let percentage: f64 = if total == 0 {
        0.0
    } else {
        (recognized as f64) * 100.0 / (total as f64)
    };
    let _ = writeln!(
        output,
        "# bcc dispatch recovery {}: {}/{} binary-op dispatcher sites resolved ({:.1}% coverage)",
        options.func_name, recognized, total, percentage
    );
    for call in calls {
        let rendered: String = match (&call.symbol, &call.python) {
            (Some(symbol), Some(python)) => format!("{symbol} -> {python}"),
            (Some(symbol), None) => format!("{symbol} -> opaque_call(...)"),
            (None, _) => "unresolved selector -> opaque_call(...)".to_owned(),
        };
        let _ = writeln!(output, "#   {:#06x}: {rendered}", call.call_site);
    }
    output
}

#[must_use]
pub fn recover_bcc_arith(
    code: &[u8],
    base: u64,
    options: &RecoverOptions,
    consts: &[Option<i128>],
) -> RecoveredBody {
    let mut notes: Vec<String> = Vec::new();
    if code.is_empty() || code.len() > MAX_BODY_BYTES {
        notes.push("native body is empty or exceeds the recovery size bound".to_owned());
        let machine: BccMachine<'_> = BccMachine::new(options, consts);
        return degraded(options, &machine, notes);
    }
    let nir: NirFunction = match lower_x86_64(code, base, "bcc_body") {
        Ok(function) => function,
        Err(error) => {
            notes.push(format!("x86-64 to NIR lowering declined: {error}"));
            let machine: BccMachine<'_> = BccMachine::new(options, consts);
            return degraded(options, &machine, notes);
        }
    };
    let mut machine: BccMachine<'_> = BccMachine::new(options, consts);
    machine.run(&nir);

    let bail: Option<String> = machine.bail.clone();
    let mut recovered_python: Option<String> = if bail.is_some() {
        None
    } else {
        machine.recovered_body(&mut notes)
    };
    if recovered_python.is_none() {
        recovered_python = super::stmt_structure::recover_structured(&nir, options, &mut notes);
        if recovered_python.is_none()
            && let Some(reason) = bail
        {
            notes.push(reason);
            return degraded(options, &machine, notes);
        }
    }

    let total: usize = machine.dispatch_calls.len();
    let recognized: usize = machine
        .dispatch_calls
        .iter()
        .filter(|call: &&RecognizedCall| call.python.is_some())
        .count();
    let annotation: String = render_annotation(options, &machine.dispatch_calls, total, recognized);
    RecoveredBody {
        func_name: options.func_name.clone(),
        total_call_sites: total,
        recognized_call_sites: recognized,
        recovered_python,
        calls: machine.dispatch_calls,
        annotation,
        notes,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use disrobe_nir::{SourceLang, SourceRef};

    use super::*;

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

    fn two_arm_branch_body(selector_a: u64, selector_b: u64) -> NirFunction {
        let arm = |base: u64, selector: u64| -> Vec<NirInstr> {
            vec![
                copy(base, "rcx", "rsi"),
                copy(base + 4, "rdx", "rdi"),
                copy(base + 8, "r8", &format!("{selector:#x}")),
                copy(base + 12, "r10", "rbx"),
                instr(base + 16, NirOp::IndirectCall, &["r10"]),
                instr(base + 20, NirOp::Return, &["rax"]),
            ]
        };
        let mut instructions: Vec<NirInstr> =
            vec![instr(0x00, NirOp::CondBranch { target: Some(0x50) }, &[])];
        instructions.extend(arm(0x08, selector_a));
        instructions.extend(arm(0x50, selector_b));
        NirFunction {
            name: "f".to_owned(),
            address: 0,
            end: 0x68,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    fn seed_branch_machine<'a>(
        options: &'a RecoverOptions,
        consts: &'a [Option<i128>],
        nir: &NirFunction,
    ) -> BccMachine<'a> {
        let mut machine: BccMachine<'a> = BccMachine::new(options, consts);
        machine.registers.insert("rsi".to_owned(), BccVal::Param(0));
        machine.registers.insert("rdi".to_owned(), BccVal::Param(1));
        machine
            .registers
            .insert("rbx".to_owned(), BccVal::RuntimeSlot(SLOT_BINOP));
        machine.run(nir);
        machine
    }

    #[test]
    fn divergent_branch_arms_degrade_to_opaque() {
        let options: RecoverOptions = RecoverOptions::new("f", crate::PyAbi::Win64, 2);
        let consts: Vec<Option<i128>> = Vec::new();
        let nir: NirFunction = two_arm_branch_body(0x07, 0x24);
        let machine: BccMachine<'_> = seed_branch_machine(&options, &consts, &nir);
        assert!(machine.saw_branch, "conditional jump must record a branch");
        assert_eq!(machine.returns.len(), 2, "both arms reach a return");
        assert!(
            !machine.resolved_returns_render_identically(),
            "the two arms compute different expressions"
        );
        let mut notes: Vec<String> = Vec::new();
        let body: Option<String> = machine.recovered_body(&mut notes);
        assert!(
            body.is_none(),
            "divergent branch arms must degrade rather than emit one arm: {body:?}"
        );
    }

    #[test]
    fn identical_branch_arms_recover_shared_expression() {
        let options: RecoverOptions = RecoverOptions::new("f", crate::PyAbi::Win64, 2);
        let consts: Vec<Option<i128>> = Vec::new();
        let nir: NirFunction = two_arm_branch_body(0x07, 0x07);
        let machine: BccMachine<'_> = seed_branch_machine(&options, &consts, &nir);
        assert!(machine.saw_branch);
        assert!(machine.resolved_returns_render_identically());
        let mut notes: Vec<String> = Vec::new();
        let body: String = machine
            .recovered_body(&mut notes)
            .expect("identical arms recover the shared expression");
        assert!(body.contains("return arg_0 + arg_1"), "recovered: {body}");
    }

    #[test]
    fn selector_table_matches_runtime_dispatcher() {
        assert_eq!(binop_selector(0x07), Some(("+", "PyNumber_Add")));
        assert_eq!(binop_selector(0x08), Some(("&", "PyNumber_And")));
        assert_eq!(binop_selector(0x0c), Some(("//", "PyNumber_FloorDivide")));
        assert_eq!(binop_selector(0x1c), Some(("<<", "PyNumber_Lshift")));
        assert_eq!(binop_selector(0x1d), Some(("*", "PyNumber_Multiply")));
        assert_eq!(binop_selector(0x1f), Some(("|", "PyNumber_Or")));
        assert_eq!(binop_selector(0x21), Some(("**", "PyNumber_Power")));
        assert_eq!(binop_selector(0x22), Some(("%", "PyNumber_Remainder")));
        assert_eq!(binop_selector(0x23), Some((">>", "PyNumber_Rshift")));
        assert_eq!(binop_selector(0x24), Some(("-", "PyNumber_Subtract")));
        assert_eq!(binop_selector(0x25), Some(("/", "PyNumber_TrueDivide")));
        assert_eq!(binop_selector(0x26), Some(("^", "PyNumber_Xor")));
        assert_eq!(binop_selector(0x4b), Some(("@", "PyNumber_MatrixMultiply")));
    }

    #[test]
    fn inplace_and_invalid_selectors_are_unsupported() {
        assert_eq!(binop_selector(0x0e), None);
        assert_eq!(binop_selector(0x19), None);
        assert_eq!(binop_selector(0x09), None);
        assert_eq!(binop_selector(0x00), None);
        assert_eq!(binop_selector(0x2b), None);
    }

    #[test]
    fn empty_body_degrades_without_panic() {
        let options: RecoverOptions = RecoverOptions::new("f", crate::PyAbi::Win64, 2);
        let body: RecoveredBody = recover_bcc_arith(&[], 0, &options, &[]);
        assert!(body.recovered_python.is_none());
        assert_eq!(body.recognized_call_sites, 0);
    }

    #[test]
    fn address_folding_tags_frame_runtime_and_consts() {
        assert!(matches!(
            fold_add(&BccVal::Frame(-0x68), &BccVal::Machine(0x40)),
            BccVal::Frame(-0x28)
        ));
        assert!(matches!(
            fold_add(&BccVal::RuntimeTable, &BccVal::Machine(SLOT_BINOP)),
            BccVal::RuntimeSlotAddr(SLOT_BINOP)
        ));
        assert!(matches!(
            fold_add(&BccVal::ConstsTuple, &BccVal::Machine(TUPLE_ITEM0)),
            BccVal::ConstsItemAddr(TUPLE_ITEM0)
        ));
        assert!(matches!(
            fold_add(&BccVal::ConstsTuple, &BccVal::Machine(0x10)),
            BccVal::Unknown
        ));
    }
}
