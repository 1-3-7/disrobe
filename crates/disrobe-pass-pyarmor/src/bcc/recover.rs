use std::collections::BTreeMap;
use std::fmt::Write as _;

use disrobe_nir::{NirClass, NirFunction, NirInstr, NirOp, ValueOp};
use disrobe_nir_lift::lower_x86_64;

use crate::v8v9::BccArch;

const MAX_BODY_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PyAbi {
    SysV,
    Win64,
}

impl PyAbi {
    #[must_use]
    pub const fn from_arch(arch: BccArch) -> Self {
        match arch {
            BccArch::LinuxX64 => Self::SysV,
            BccArch::WinX64 | BccArch::DarwinArm64 | BccArch::Other(_) => Self::Win64,
        }
    }

    pub(crate) const fn arg_registers(self) -> &'static [&'static str] {
        match self {
            Self::SysV => &["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            Self::Win64 => &["rcx", "rdx", "r8", "r9"],
        }
    }

    pub(crate) const fn volatile_registers(self) -> &'static [&'static str] {
        match self {
            Self::SysV => &["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"],
            Self::Win64 => &["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"],
        }
    }
}

pub trait CallResolver {
    fn symbol(&self, call_site: u64) -> Option<&str>;
}

#[derive(Debug, Clone, Default)]
pub struct MapCallResolver {
    entries: BTreeMap<u64, String>,
}

impl MapCallResolver {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn insert(&mut self, call_site: u64, symbol: impl Into<String>) {
        self.entries.insert(call_site, symbol.into());
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CallResolver for MapCallResolver {
    fn symbol(&self, call_site: u64) -> Option<&str> {
        self.entries.get(&call_site).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct RecoverOptions {
    pub func_name: String,
    pub abi: PyAbi,
    pub argcount: usize,
    pub param_names: Vec<String>,
}

impl RecoverOptions {
    #[must_use]
    pub fn new(func_name: impl Into<String>, abi: PyAbi, argcount: usize) -> Self {
        Self {
            func_name: func_name.into(),
            abi,
            argcount,
            param_names: Vec::new(),
        }
    }

    pub(crate) fn param(&self, index: usize) -> String {
        self.param_names
            .get(index)
            .cloned()
            .unwrap_or_else(|| format!("arg_{index}"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecognizedCall {
    pub call_site: u64,
    pub symbol: Option<String>,
    pub python: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredBody {
    pub func_name: String,
    pub total_call_sites: usize,
    pub recognized_call_sites: usize,
    pub recovered_python: Option<String>,
    pub calls: Vec<RecognizedCall>,
    pub annotation: String,
    pub notes: Vec<String>,
}

impl RecoveredBody {
    #[must_use]
    pub fn coverage(&self) -> f64 {
        if self.total_call_sites == 0 {
            return 0.0;
        }
        let recognized: f64 = self.recognized_call_sites as f64;
        let total: f64 = self.total_call_sites as f64;
        recognized / total
    }

    #[must_use]
    pub const fn is_fully_recovered(&self) -> bool {
        self.recovered_python.is_some()
    }
}

#[derive(Debug, Clone)]
enum SymValue {
    Param(usize),
    Const(u64),
    CallResult(usize),
    Unknown,
}

#[derive(Debug, Clone)]
pub(crate) enum PyExpr {
    Name(String),
    Num(i128),
    Binary(Box<Self>, &'static str, Box<Self>),
    Unary(&'static str, Box<Self>),
    Compare(Box<Self>, &'static str, Box<Self>),
    Index(Box<Self>, Box<Self>),
}

impl PyExpr {
    fn precedence(&self) -> u8 {
        match self {
            Self::Name(_) | Self::Num(_) | Self::Index(..) => 100,
            Self::Unary(..) => 60,
            Self::Binary(_, op, _) => binary_precedence(op),
            Self::Compare(..) => 10,
        }
    }

    pub(crate) fn render(&self) -> String {
        match self {
            Self::Name(name) => name.clone(),
            Self::Num(value) => value.to_string(),
            Self::Index(base, key) => format!("{}[{}]", parenthesize(base, 100), key.render()),
            Self::Unary(op, inner) => format!("{op}{}", parenthesize(inner, 60)),
            Self::Binary(left, op, right) => {
                let level: u8 = binary_precedence(op);
                let (left_min, right_min): (u8, u8) = if is_right_associative(op) {
                    (level.saturating_add(1), level)
                } else {
                    (level, level.saturating_add(1))
                };
                format!(
                    "{} {op} {}",
                    parenthesize(left, left_min),
                    parenthesize(right, right_min)
                )
            }
            Self::Compare(left, op, right) => {
                format!(
                    "{} {op} {}",
                    parenthesize(left, 11),
                    parenthesize(right, 11)
                )
            }
        }
    }
}

fn parenthesize(expr: &PyExpr, minimum: u8) -> String {
    if expr.precedence() < minimum {
        format!("({})", expr.render())
    } else {
        expr.render()
    }
}

fn binary_precedence(op: &str) -> u8 {
    match op {
        "|" => 20,
        "^" => 22,
        "&" => 24,
        "<<" | ">>" => 26,
        "+" | "-" => 30,
        "*" | "/" | "//" | "%" | "@" => 40,
        "**" => 70,
        _ => 50,
    }
}

fn is_right_associative(op: &str) -> bool {
    op == "**"
}

#[derive(Debug, Clone, Copy)]
enum CApiOp {
    Binary(&'static str),
    Unary(&'static str),
    RichCompare,
    GetItem,
    Unsupported,
}

fn classify_capi(symbol: &str) -> Option<CApiOp> {
    let trimmed: &str = symbol.strip_prefix('_').unwrap_or(symbol);
    let op: CApiOp = match trimmed {
        "PyNumber_Add" => CApiOp::Binary("+"),
        "PyNumber_Subtract" => CApiOp::Binary("-"),
        "PyNumber_Multiply" => CApiOp::Binary("*"),
        "PyNumber_TrueDivide" => CApiOp::Binary("/"),
        "PyNumber_FloorDivide" => CApiOp::Binary("//"),
        "PyNumber_Remainder" => CApiOp::Binary("%"),
        "PyNumber_Lshift" => CApiOp::Binary("<<"),
        "PyNumber_Rshift" => CApiOp::Binary(">>"),
        "PyNumber_And" => CApiOp::Binary("&"),
        "PyNumber_Or" => CApiOp::Binary("|"),
        "PyNumber_Xor" => CApiOp::Binary("^"),
        "PyNumber_MatrixMultiply" => CApiOp::Binary("@"),
        "PyNumber_Negative" => CApiOp::Unary("-"),
        "PyNumber_Positive" => CApiOp::Unary("+"),
        "PyNumber_Invert" => CApiOp::Unary("~"),
        "PyObject_RichCompare" | "PyObject_RichCompareBool" => CApiOp::RichCompare,
        "PyObject_GetItem" => CApiOp::GetItem,
        "PyNumber_Power"
        | "PyNumber_InPlaceAdd"
        | "PyNumber_InPlaceSubtract"
        | "PyNumber_InPlaceMultiply"
        | "PyObject_GetAttr"
        | "PyObject_GetAttrString"
        | "PyObject_SetItem"
        | "PyObject_SetAttr"
        | "PyObject_Vectorcall"
        | "PyObject_CallFunctionObjArgs"
        | "PyObject_Call"
        | "Py_BuildValue" => CApiOp::Unsupported,
        _ => return None,
    };
    Some(op)
}

const fn richcompare_operator(selector: u64) -> Option<&'static str> {
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

struct Evaluator {
    registers: BTreeMap<String, SymValue>,
}

impl Evaluator {
    fn new(options: &RecoverOptions) -> Self {
        let mut registers: BTreeMap<String, SymValue> = BTreeMap::new();
        let arg_registers: &[&str] = options.abi.arg_registers();
        let bound: usize = options.argcount.min(arg_registers.len());
        for index in 0..bound {
            if let Some(name) = arg_registers.get(index) {
                registers.insert((*name).to_owned(), SymValue::Param(index));
            }
        }
        Self { registers }
    }

    fn eval(&self, name: &str) -> SymValue {
        if let Some(value) = parse_immediate(name) {
            return SymValue::Const(value);
        }
        self.registers
            .get(name)
            .cloned()
            .unwrap_or(SymValue::Unknown)
    }

    fn assign(&mut self, name: &str, value: SymValue) {
        self.registers.insert(name.to_owned(), value);
    }

    fn snapshot_args(&self, abi: PyAbi, arity: usize) -> Vec<SymValue> {
        let arg_registers: &[&str] = abi.arg_registers();
        (0..arity)
            .map(|index: usize| {
                arg_registers
                    .get(index)
                    .map_or(SymValue::Unknown, |name: &&str| self.eval(name))
            })
            .collect()
    }

    fn clobber(&mut self, abi: PyAbi, result: SymValue) {
        for register in abi.volatile_registers() {
            self.registers.remove(*register);
        }
        self.registers.insert("rax".to_owned(), result);
    }

    fn step(&mut self, instruction: &NirInstr) {
        match &instruction.op {
            NirOp::Copy { src, .. } => {
                let value: SymValue = self.eval(src);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, value);
                }
            }
            NirOp::Subpiece { src, offset, size } => {
                let value: SymValue = self.eval(src);
                let folded: SymValue = fold_subpiece(&value, *offset, *size);
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
                let evaluated: SymValue = self.eval(value);
                let folded: SymValue = if *zero_upper && *offset == 0 {
                    fold_mask(&evaluated, *size)
                } else {
                    SymValue::Unknown
                };
                self.assign(cell, folded);
            }
            NirOp::Value {
                op,
                inputs,
                input_sizes,
                size,
            } => {
                let folded: SymValue = self.fold_value(*op, inputs, input_sizes, *size);
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, folded);
                }
            }
            NirOp::RawLoad { .. } | NirOp::Piece { .. } => {
                if let Some(dest) = instruction.operands.first() {
                    self.assign(dest, SymValue::Unknown);
                }
            }
            _ => {}
        }
    }

    fn fold_value(
        &self,
        op: ValueOp,
        inputs: &[String],
        input_sizes: &[u32],
        size: u32,
    ) -> SymValue {
        let mut operands: Vec<u64> = Vec::with_capacity(inputs.len());
        for input in inputs {
            match self.eval(input) {
                SymValue::Const(value) => operands.push(value),
                _ => return SymValue::Unknown,
            }
        }
        let first: u64 = operands.first().copied().unwrap_or(0);
        let second: u64 = operands.get(1).copied().unwrap_or(0);
        let result: Option<u64> = match op {
            ValueOp::IntZext => Some(first),
            ValueOp::IntSext => Some(sign_extend(
                first,
                input_sizes.first().copied().unwrap_or(size),
            )),
            ValueOp::IntAdd => Some(first.wrapping_add(second)),
            ValueOp::IntSub => Some(first.wrapping_sub(second)),
            ValueOp::IntMult => Some(first.wrapping_mul(second)),
            ValueOp::IntAnd => Some(first & second),
            ValueOp::IntOr => Some(first | second),
            ValueOp::IntXor => Some(first ^ second),
            ValueOp::IntLeft => Some(first.wrapping_shl(u32::try_from(second).unwrap_or(0))),
            ValueOp::IntRight => Some(first.wrapping_shr(u32::try_from(second).unwrap_or(0))),
            _ => None,
        };
        result.map_or(SymValue::Unknown, |value: u64| {
            SymValue::Const(mask_to_size(value, size))
        })
    }
}

fn parse_immediate(name: &str) -> Option<u64> {
    let body: &str = name
        .strip_prefix("0x")
        .or_else(|| name.strip_prefix("0X"))?;
    u64::from_str_radix(body, 16).ok()
}

fn fold_subpiece(value: &SymValue, offset: u32, size: u32) -> SymValue {
    match value {
        SymValue::Const(constant) => {
            let shift: u32 = offset.saturating_mul(8);
            let shifted: u64 = constant.checked_shr(shift).unwrap_or(0);
            SymValue::Const(mask_to_size(shifted, size))
        }
        _ => SymValue::Unknown,
    }
}

fn fold_mask(value: &SymValue, size: u32) -> SymValue {
    match value {
        SymValue::Const(constant) => SymValue::Const(mask_to_size(*constant, size)),
        other => other.clone(),
    }
}

fn mask_to_size(value: u64, size: u32) -> u64 {
    let bits: u32 = size.saturating_mul(8);
    if bits >= 64 {
        value
    } else {
        let mask: u64 = 1_u64
            .checked_shl(bits)
            .map_or(u64::MAX, |shifted: u64| shifted - 1);
        value & mask
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

#[must_use]
pub fn recover_from_code(
    code: &[u8],
    base: u64,
    options: &RecoverOptions,
    resolver: &dyn CallResolver,
) -> RecoveredBody {
    let mut notes: Vec<String> = Vec::new();
    if code.is_empty() || code.len() > MAX_BODY_BYTES {
        notes.push("native body is empty or exceeds the recovery size bound".to_owned());
        return degraded(options, Vec::new(), notes);
    }
    let nir: NirFunction = match lower_x86_64(code, base, "bcc_body") {
        Ok(function) => function,
        Err(error) => {
            notes.push(format!("x86-64 to NIR lowering declined: {error}"));
            return degraded(options, Vec::new(), notes);
        }
    };
    recover_from_nir(&nir, options, resolver, notes)
}

#[must_use]
pub fn recover_from_nir(
    nir: &NirFunction,
    options: &RecoverOptions,
    resolver: &dyn CallResolver,
    mut notes: Vec<String>,
) -> RecoveredBody {
    let mut evaluator: Evaluator = Evaluator::new(options);
    let mut call_exprs: Vec<Option<PyExpr>> = Vec::new();
    let mut calls: Vec<RecognizedCall> = Vec::new();
    let mut has_branch: bool = false;
    let mut return_value: Option<SymValue> = None;
    let mut return_count: usize = 0;

    for instruction in &nir.instructions {
        match instruction.class() {
            NirClass::Call => {
                let call_index: usize = call_exprs.len();
                let symbol: Option<String> =
                    resolver.symbol(instruction.address).map(str::to_owned);
                let (expr, python): (Option<PyExpr>, Option<String>) = symbol
                    .as_deref()
                    .and_then(classify_capi)
                    .and_then(|op: CApiOp| recognize_call(op, options, &evaluator, &call_exprs))
                    .map_or((None, None), |expr: PyExpr| {
                        let rendered: String = expr.render();
                        (Some(expr), Some(rendered))
                    });
                calls.push(RecognizedCall {
                    call_site: instruction.address,
                    symbol,
                    python: python.clone(),
                });
                let result: SymValue = if expr.is_some() {
                    SymValue::CallResult(call_index)
                } else {
                    SymValue::Unknown
                };
                call_exprs.push(expr);
                evaluator.clobber(options.abi, result);
            }
            NirClass::ConditionalJump | NirClass::UnconditionalJump => {
                has_branch = true;
            }
            NirClass::Return => {
                return_count = return_count.saturating_add(1);
                let value: SymValue = instruction
                    .operands
                    .first()
                    .map_or(SymValue::Unknown, |name: &String| evaluator.eval(name));
                return_value = Some(value);
            }
            NirClass::Other => evaluator.step(instruction),
        }
    }

    let total_call_sites: usize = calls.len();
    let recognized_call_sites: usize = calls
        .iter()
        .filter(|call: &&RecognizedCall| call.python.is_some())
        .count();

    let recovered_python: Option<String> = build_python(
        options,
        &calls,
        &call_exprs,
        return_value.as_ref(),
        return_count,
        has_branch,
        &mut notes,
    );

    let annotation: String =
        render_annotation(options, &calls, total_call_sites, recognized_call_sites);

    RecoveredBody {
        func_name: options.func_name.clone(),
        total_call_sites,
        recognized_call_sites,
        recovered_python,
        calls,
        annotation,
        notes,
    }
}

fn recognize_call(
    op: CApiOp,
    options: &RecoverOptions,
    evaluator: &Evaluator,
    call_exprs: &[Option<PyExpr>],
) -> Option<PyExpr> {
    match op {
        CApiOp::Binary(operator) => {
            let args: Vec<SymValue> = evaluator.snapshot_args(options.abi, 2);
            let left: PyExpr = value_to_expr(args.first()?, options, call_exprs)?;
            let right: PyExpr = value_to_expr(args.get(1)?, options, call_exprs)?;
            Some(PyExpr::Binary(Box::new(left), operator, Box::new(right)))
        }
        CApiOp::Unary(operator) => {
            let args: Vec<SymValue> = evaluator.snapshot_args(options.abi, 1);
            let inner: PyExpr = value_to_expr(args.first()?, options, call_exprs)?;
            Some(PyExpr::Unary(operator, Box::new(inner)))
        }
        CApiOp::RichCompare => {
            let args: Vec<SymValue> = evaluator.snapshot_args(options.abi, 3);
            let left: PyExpr = value_to_expr(args.first()?, options, call_exprs)?;
            let right: PyExpr = value_to_expr(args.get(1)?, options, call_exprs)?;
            let selector: u64 = match args.get(2)? {
                SymValue::Const(value) => *value,
                _ => return None,
            };
            let operator: &'static str = richcompare_operator(selector)?;
            Some(PyExpr::Compare(Box::new(left), operator, Box::new(right)))
        }
        CApiOp::GetItem => {
            let args: Vec<SymValue> = evaluator.snapshot_args(options.abi, 2);
            let base: PyExpr = value_to_expr(args.first()?, options, call_exprs)?;
            let key: PyExpr = value_to_expr(args.get(1)?, options, call_exprs)?;
            Some(PyExpr::Index(Box::new(base), Box::new(key)))
        }
        CApiOp::Unsupported => None,
    }
}

fn value_to_expr(
    value: &SymValue,
    options: &RecoverOptions,
    call_exprs: &[Option<PyExpr>],
) -> Option<PyExpr> {
    match value {
        SymValue::Param(index) => Some(PyExpr::Name(options.param(*index))),
        SymValue::Const(constant) => Some(PyExpr::Num(i128::from(*constant))),
        SymValue::CallResult(index) => call_exprs.get(*index).and_then(Clone::clone),
        SymValue::Unknown => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn build_python(
    options: &RecoverOptions,
    calls: &[RecognizedCall],
    call_exprs: &[Option<PyExpr>],
    return_value: Option<&SymValue>,
    return_count: usize,
    has_branch: bool,
    notes: &mut Vec<String>,
) -> Option<String> {
    if calls.is_empty() {
        return None;
    }
    if calls
        .iter()
        .any(|call: &RecognizedCall| call.python.is_none())
    {
        return None;
    }
    if has_branch {
        notes.push(
            "control flow present; structured recovery of branches and loops is a later increment"
                .to_owned(),
        );
        return None;
    }
    if return_count != 1 {
        return None;
    }
    let expr: PyExpr = match return_value? {
        SymValue::CallResult(index) => call_exprs.get(*index).and_then(Clone::clone)?,
        _ => return None,
    };
    let params: Vec<String> = (0..options.argcount)
        .map(|index: usize| options.param(index))
        .collect();
    Some(format!(
        "def {}({}):\n    return {}\n",
        options.func_name,
        params.join(", "),
        expr.render()
    ))
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
    let header: String = format!(
        "# bcc recovery {}: {}/{} C-API call sites recognized ({:.1}% coverage)\n",
        options.func_name, recognized, total, percentage
    );
    output.push_str(&header);
    for call in calls {
        let rendered: String = match (&call.symbol, &call.python) {
            (Some(symbol), Some(python)) => format!("{symbol} -> {python}"),
            (Some(symbol), None) => format!("{symbol} -> opaque_call(...)"),
            (None, _) => "indirect call -> opaque_call(...)".to_owned(),
        };
        let _ = writeln!(output, "#   {:#06x}: {rendered}", call.call_site);
    }
    output
}

fn degraded(
    options: &RecoverOptions,
    calls: Vec<RecognizedCall>,
    notes: Vec<String>,
) -> RecoveredBody {
    let annotation: String = render_annotation(options, &calls, calls.len(), 0);
    RecoveredBody {
        func_name: options.func_name.clone(),
        total_call_sites: calls.len(),
        recognized_call_sites: 0,
        recovered_python: None,
        calls,
        annotation,
        notes,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn precedence_renders_without_redundant_parens() {
        let expr: PyExpr = PyExpr::Binary(
            Box::new(PyExpr::Name("a".to_owned())),
            "+",
            Box::new(PyExpr::Binary(
                Box::new(PyExpr::Name("b".to_owned())),
                "*",
                Box::new(PyExpr::Name("c".to_owned())),
            )),
        );
        assert_eq!(expr.render(), "a + b * c");
    }

    #[test]
    fn precedence_parenthesizes_lower_precedence_left() {
        let expr: PyExpr = PyExpr::Binary(
            Box::new(PyExpr::Binary(
                Box::new(PyExpr::Name("a".to_owned())),
                "+",
                Box::new(PyExpr::Name("b".to_owned())),
            )),
            "*",
            Box::new(PyExpr::Name("c".to_owned())),
        );
        assert_eq!(expr.render(), "(a + b) * c");
    }

    #[test]
    fn power_renders_right_associatively() {
        let left_nested: PyExpr = PyExpr::Binary(
            Box::new(PyExpr::Binary(
                Box::new(PyExpr::Name("a".to_owned())),
                "**",
                Box::new(PyExpr::Name("b".to_owned())),
            )),
            "**",
            Box::new(PyExpr::Name("c".to_owned())),
        );
        assert_eq!(left_nested.render(), "(a ** b) ** c");

        let right_nested: PyExpr = PyExpr::Binary(
            Box::new(PyExpr::Name("a".to_owned())),
            "**",
            Box::new(PyExpr::Binary(
                Box::new(PyExpr::Name("b".to_owned())),
                "**",
                Box::new(PyExpr::Name("c".to_owned())),
            )),
        );
        assert_eq!(right_nested.render(), "a ** b ** c");

        let left_grouped: i128 = 2_i128.pow(3).pow(2);
        let right_grouped: i128 = 2_i128.pow(3_u32.pow(2));
        assert_eq!(left_grouped, 64);
        assert_eq!(right_grouped, 512);
        assert_ne!(
            left_grouped, right_grouped,
            "left- and right-grouped power evaluate differently, so the parens change meaning"
        );
    }

    #[test]
    fn subtraction_parenthesizes_right_operand() {
        let expr: PyExpr = PyExpr::Binary(
            Box::new(PyExpr::Name("a".to_owned())),
            "-",
            Box::new(PyExpr::Binary(
                Box::new(PyExpr::Name("b".to_owned())),
                "-",
                Box::new(PyExpr::Name("c".to_owned())),
            )),
        );
        assert_eq!(expr.render(), "a - (b - c)");
    }

    #[test]
    fn classify_covers_core_arithmetic() {
        assert!(matches!(
            classify_capi("PyNumber_Add"),
            Some(CApiOp::Binary("+"))
        ));
        assert!(matches!(
            classify_capi("_PyObject_RichCompare"),
            Some(CApiOp::RichCompare)
        ));
        assert!(matches!(
            classify_capi("PyObject_Vectorcall"),
            Some(CApiOp::Unsupported)
        ));
        assert!(classify_capi("SomeOtherSymbol").is_none());
    }

    #[test]
    fn richcompare_selectors_decode() {
        assert_eq!(richcompare_operator(0), Some("<"));
        assert_eq!(richcompare_operator(5), Some(">="));
        assert_eq!(richcompare_operator(9), None);
    }

    #[test]
    fn empty_code_degrades_without_panic() {
        let options: RecoverOptions = RecoverOptions::new("f", PyAbi::Win64, 2);
        let resolver: MapCallResolver = MapCallResolver::new();
        let body: RecoveredBody = recover_from_code(&[], 0, &options, &resolver);
        assert!(body.recovered_python.is_none());
        assert_eq!(body.recognized_call_sites, 0);
    }
}
