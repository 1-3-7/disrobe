use std::collections::BTreeMap;

use disrobe_core::codec::hex::push_fixed as push_lower_hex_fixed;
use ruff_python_ast::{
    BoolOp, CmpOp, Comprehension, Expr, ExprAttribute, ExprBinOp, ExprBoolOp, ExprBooleanLiteral,
    ExprBytesLiteral, ExprCall, ExprCompare, ExprDict, ExprGenerator, ExprIf, ExprLambda, ExprList,
    ExprListComp, ExprName, ExprNoneLiteral, ExprNumberLiteral, ExprSetComp, ExprStringLiteral,
    ExprSubscript, ExprTuple, ExprUnaryOp, Number, Operator, Parameters, UnaryOp,
};

use super::methods::call_method;
use super::value::{Key, Value};

#[derive(Debug)]
pub(crate) struct Scope {
    bindings: BTreeMap<String, Value>,
    in_comprehension: bool,
}

impl Scope {
    pub(crate) const fn new() -> Self {
        Self {
            bindings: BTreeMap::new(),
            in_comprehension: false,
        }
    }

    pub(crate) fn bind(&mut self, name: String, value: Value) {
        self.bindings.insert(name, value);
    }

    pub(crate) fn get(&self, name: &str) -> Option<&Value> {
        self.bindings.get(name)
    }

    pub(crate) fn len(&self) -> usize {
        self.bindings.len()
    }

    const fn in_comprehension(&self) -> bool {
        self.in_comprehension
    }

    fn child_with(&self, name: String, value: Value) -> Self {
        let mut bindings: BTreeMap<String, Value> = self.bindings.clone();
        bindings.insert(name, value);
        Self {
            bindings,
            in_comprehension: self.in_comprehension,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum EvalError {
    Unsupported,
    DynamicCode,
    NonConstant,
    DivisionByZero,
    Overflow,
    IndexOutOfRange,
    TypeMismatch,
}

pub(crate) type EvalResult = core::result::Result<Value, EvalError>;

const FORBIDDEN: &[&str] = &[
    "exec",
    "eval",
    "compile",
    "__import__",
    "open",
    "input",
    "print",
    "globals",
    "locals",
    "vars",
    "getattr",
    "setattr",
    "delattr",
    "hasattr",
    "callable",
    "id",
    "type",
    "isinstance",
    "issubclass",
    "super",
    "object",
    "help",
    "dir",
    "memoryview",
    "breakpoint",
];

pub(crate) fn is_forbidden(name: &str) -> bool {
    FORBIDDEN.contains(&name)
}

pub(crate) fn eval_expr(expr: &Expr, scope: &Scope) -> EvalResult {
    match expr {
        Expr::NumberLiteral(ExprNumberLiteral {
            value: Number::Int(int),
            ..
        }) => {
            let s: String = int.to_string();
            s.parse::<i128>()
                .map(Value::Int)
                .map_err(|_| EvalError::Overflow)
        }
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            Ok(Value::Str(value.to_str().to_owned()))
        }
        Expr::BytesLiteral(ExprBytesLiteral { value, .. }) => Ok(Value::Bytes(
            value.iter().flat_map(|b| b.value.iter().copied()).collect(),
        )),
        Expr::BooleanLiteral(ExprBooleanLiteral { value, .. }) => Ok(Value::Bool(*value)),
        Expr::NoneLiteral(ExprNoneLiteral { .. }) => Ok(Value::None),
        Expr::Name(ExprName { id, .. }) => eval_name(id.as_str(), scope),
        Expr::UnaryOp(u) => eval_unary(u, scope),
        Expr::BinOp(b) => eval_binop(b, scope),
        Expr::BoolOp(b) => eval_boolop(b, scope),
        Expr::Compare(c) => eval_compare(c, scope),
        Expr::If(i) => eval_ifexp(i, scope),
        Expr::List(ExprList { elts, .. }) => {
            let items: Vec<Value> = eval_seq(elts, scope)?;
            Ok(Value::List(items))
        }
        Expr::Tuple(ExprTuple { elts, .. }) => {
            let items: Vec<Value> = eval_seq(elts, scope)?;
            Ok(Value::Tuple(items))
        }
        Expr::Dict(ExprDict { items, .. }) => {
            let mut out: BTreeMap<Key, Value> = BTreeMap::new();
            for item in items {
                let Some(k_expr) = item.key.as_ref() else {
                    return Err(EvalError::Unsupported);
                };
                let k_val: Value = eval_expr(k_expr, scope)?;
                let Some(k) = k_val.to_key() else {
                    return Err(EvalError::TypeMismatch);
                };
                let v: Value = eval_expr(&item.value, scope)?;
                out.insert(k, v);
            }
            Ok(Value::Dict(out))
        }
        Expr::Subscript(s) => eval_subscript(s, scope),
        Expr::Call(c) => eval_call(c, scope),
        Expr::Attribute(a) => eval_attribute(a, scope),
        Expr::ListComp(ExprListComp {
            elt, generators, ..
        })
        | Expr::SetComp(ExprSetComp {
            elt, generators, ..
        })
        | Expr::Generator(ExprGenerator {
            elt, generators, ..
        }) => {
            let items: Vec<Value> = eval_comprehension(elt, generators, scope)?;
            Ok(Value::List(items))
        }
        _ => Err(EvalError::Unsupported),
    }
}

fn eval_seq(items: &[Expr], scope: &Scope) -> core::result::Result<Vec<Value>, EvalError> {
    let mut out: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        out.push(eval_expr(item, scope)?);
    }
    Ok(out)
}

fn eval_name(id: &str, scope: &Scope) -> EvalResult {
    if is_forbidden(id) {
        return Err(EvalError::DynamicCode);
    }
    match id {
        "True" => Ok(Value::Bool(true)),
        "False" => Ok(Value::Bool(false)),
        "None" => Ok(Value::None),
        _ => scope.get(id).cloned().ok_or(EvalError::NonConstant),
    }
}

fn eval_unary(u: &ExprUnaryOp, scope: &Scope) -> EvalResult {
    let operand: Value = eval_expr(&u.operand, scope)?;
    match (u.op, operand) {
        (UnaryOp::USub, Value::Int(n)) => {
            n.checked_neg().map(Value::Int).ok_or(EvalError::Overflow)
        }
        (UnaryOp::UAdd, Value::Int(n)) => Ok(Value::Int(n)),
        (UnaryOp::Invert, Value::Int(n)) => Ok(Value::Int(!n)),
        (UnaryOp::Not, v) => Ok(Value::Bool(!v.truthy())),
        _ => Err(EvalError::TypeMismatch),
    }
}

fn eval_binop(b: &ExprBinOp, scope: &Scope) -> EvalResult {
    let lhs: Value = eval_expr(&b.left, scope)?;
    let rhs: Value = eval_expr(&b.right, scope)?;
    match (lhs, rhs, b.op) {
        (Value::Int(a), Value::Int(c), Operator::Add) => {
            a.checked_add(c).map(Value::Int).ok_or(EvalError::Overflow)
        }
        (Value::Int(a), Value::Int(c), Operator::Sub) => {
            a.checked_sub(c).map(Value::Int).ok_or(EvalError::Overflow)
        }
        (Value::Int(a), Value::Int(c), Operator::Mult) => {
            a.checked_mul(c).map(Value::Int).ok_or(EvalError::Overflow)
        }
        (Value::Int(_a), Value::Int(0), Operator::FloorDiv | Operator::Mod) => {
            Err(EvalError::DivisionByZero)
        }
        (Value::Int(a), Value::Int(c), Operator::FloorDiv) => Ok(Value::Int(a.div_euclid(c))),
        (Value::Int(a), Value::Int(c), Operator::Mod) => Ok(Value::Int(a.rem_euclid(c))),
        (Value::Int(a), Value::Int(c), Operator::BitAnd) => Ok(Value::Int(a & c)),
        (Value::Int(a), Value::Int(c), Operator::BitOr) => Ok(Value::Int(a | c)),
        (Value::Int(a), Value::Int(c), Operator::BitXor) => Ok(Value::Int(a ^ c)),
        (Value::Int(a), Value::Int(c), Operator::LShift) if (0..120).contains(&c) => {
            let shift: u32 = u32::try_from(c).map_err(|_| EvalError::Overflow)?;
            a.checked_shl(shift)
                .map(Value::Int)
                .ok_or(EvalError::Overflow)
        }
        (Value::Int(a), Value::Int(c), Operator::RShift) if (0..120).contains(&c) => {
            let shift: u32 = u32::try_from(c).map_err(|_| EvalError::Overflow)?;
            a.checked_shr(shift)
                .map(Value::Int)
                .ok_or(EvalError::Overflow)
        }
        (Value::Int(a), Value::Int(c), Operator::Pow) if (0..32).contains(&c) => {
            let exp: u32 = u32::try_from(c).map_err(|_| EvalError::Overflow)?;
            a.checked_pow(exp)
                .map(Value::Int)
                .ok_or(EvalError::Overflow)
        }
        (Value::Str(s), Value::Str(t), Operator::Add) => Ok(Value::Str(format!("{s}{t}"))),
        (Value::Str(s), Value::Int(n), Operator::Mult) if (0..=8192).contains(&n) => {
            let count: usize = usize::try_from(n).map_err(|_| EvalError::Overflow)?;
            Ok(Value::Str(s.repeat(count)))
        }
        (Value::Bytes(mut a), Value::Bytes(c), Operator::Add) => {
            a.extend_from_slice(&c);
            Ok(Value::Bytes(a))
        }
        (Value::Bytes(b), Value::Int(n), Operator::Mult) if (0..=8192).contains(&n) => {
            let count: usize = usize::try_from(n).map_err(|_| EvalError::Overflow)?;
            Ok(Value::Bytes(b.repeat(count)))
        }
        (Value::List(mut a), Value::List(c), Operator::Add) => {
            a.extend(c);
            Ok(Value::List(a))
        }
        (Value::Tuple(mut a), Value::Tuple(c), Operator::Add) => {
            a.extend(c);
            Ok(Value::Tuple(a))
        }
        _ => Err(EvalError::TypeMismatch),
    }
}

fn eval_boolop(b: &ExprBoolOp, scope: &Scope) -> EvalResult {
    let mut last: Value = Value::Bool(matches!(b.op, BoolOp::And));
    for child in &b.values {
        let v: Value = eval_expr(child, scope)?;
        match b.op {
            BoolOp::And => {
                if !v.truthy() {
                    return Ok(v);
                }
                last = v;
            }
            BoolOp::Or => {
                if v.truthy() {
                    return Ok(v);
                }
                last = v;
            }
        }
    }
    Ok(last)
}

fn eval_compare(c: &ExprCompare, scope: &Scope) -> EvalResult {
    let mut current: Value = eval_expr(&c.left, scope)?;
    for (op, rhs_expr) in c.ops.iter().zip(c.comparators.iter()) {
        let rhs: Value = eval_expr(rhs_expr, scope)?;
        let pair_ok: bool = compare_pair(&current, &rhs, *op)?;
        if !pair_ok {
            return Ok(Value::Bool(false));
        }
        current = rhs;
    }
    Ok(Value::Bool(true))
}

fn compare_pair(lhs: &Value, rhs: &Value, op: CmpOp) -> core::result::Result<bool, EvalError> {
    match (lhs, rhs, op) {
        (Value::Int(a), Value::Int(b), CmpOp::Eq) => Ok(a == b),
        (Value::Int(a), Value::Int(b), CmpOp::NotEq) => Ok(a != b),
        (Value::Int(a), Value::Int(b), CmpOp::Lt) => Ok(a < b),
        (Value::Int(a), Value::Int(b), CmpOp::LtE) => Ok(a <= b),
        (Value::Int(a), Value::Int(b), CmpOp::Gt) => Ok(a > b),
        (Value::Int(a), Value::Int(b), CmpOp::GtE) => Ok(a >= b),
        (Value::Str(a), Value::Str(b), CmpOp::Eq) => Ok(a == b),
        (Value::Str(a), Value::Str(b), CmpOp::NotEq) => Ok(a != b),
        (Value::Bool(a), Value::Bool(b), CmpOp::Eq) => Ok(a == b),
        (Value::Bool(a), Value::Bool(b), CmpOp::NotEq) => Ok(a != b),
        (Value::Bytes(a), Value::Bytes(b), CmpOp::Eq) => Ok(a == b),
        (Value::Bytes(a), Value::Bytes(b), CmpOp::NotEq) => Ok(a != b),
        (Value::None, Value::None, CmpOp::Eq | CmpOp::Is) => Ok(true),
        (Value::None, Value::None, CmpOp::NotEq | CmpOp::IsNot) => Ok(false),
        (_, container, CmpOp::In) => {
            let items: Vec<Value> = container.iter_items().ok_or(EvalError::TypeMismatch)?;
            Ok(items.iter().any(|item: &Value| item == lhs))
        }
        (_, container, CmpOp::NotIn) => {
            let items: Vec<Value> = container.iter_items().ok_or(EvalError::TypeMismatch)?;
            Ok(!items.iter().any(|item: &Value| item == lhs))
        }
        _ => Err(EvalError::TypeMismatch),
    }
}

fn eval_ifexp(i: &ExprIf, scope: &Scope) -> EvalResult {
    let test: Value = eval_expr(&i.test, scope)?;
    if test.truthy() {
        eval_expr(&i.body, scope)
    } else {
        eval_expr(&i.orelse, scope)
    }
}

fn eval_subscript(s: &ExprSubscript, scope: &Scope) -> EvalResult {
    let target: Value = eval_expr(&s.value, scope)?;
    if let Expr::Slice(slice) = &*s.slice {
        return eval_slice(&target, slice, scope);
    }
    let index_val: Value = eval_expr(&s.slice, scope)?;
    match (target, index_val) {
        (Value::Str(text), Value::Int(idx)) => {
            let chars: Vec<char> = text.chars().collect();
            let real_idx: usize = wrap_index(idx, chars.len()).ok_or(EvalError::IndexOutOfRange)?;
            Ok(Value::Str(
                chars
                    .get(real_idx)
                    .copied()
                    .ok_or(EvalError::IndexOutOfRange)?
                    .to_string(),
            ))
        }
        (Value::Bytes(bytes), Value::Int(idx)) => {
            let real_idx: usize = wrap_index(idx, bytes.len()).ok_or(EvalError::IndexOutOfRange)?;
            let byte: u8 = *bytes.get(real_idx).ok_or(EvalError::IndexOutOfRange)?;
            Ok(Value::Int(i128::from(byte)))
        }
        (Value::List(items) | Value::Tuple(items), Value::Int(idx)) => {
            let real_idx: usize = wrap_index(idx, items.len()).ok_or(EvalError::IndexOutOfRange)?;
            items
                .get(real_idx)
                .cloned()
                .ok_or(EvalError::IndexOutOfRange)
        }
        (Value::Dict(m), key_val) => {
            let key: Key = key_val.to_key().ok_or(EvalError::TypeMismatch)?;
            m.get(&key).cloned().ok_or(EvalError::IndexOutOfRange)
        }
        _ => Err(EvalError::TypeMismatch),
    }
}

fn eval_slice(target: &Value, slice: &ruff_python_ast::ExprSlice, scope: &Scope) -> EvalResult {
    let lower: Option<i128> = match &slice.lower {
        Some(e) => Some(eval_int(e, scope)?),
        None => None,
    };
    let upper: Option<i128> = match &slice.upper {
        Some(e) => Some(eval_int(e, scope)?),
        None => None,
    };
    let step: i128 = match &slice.step {
        Some(e) => eval_int(e, scope)?,
        None => 1,
    };
    if step == 0 {
        return Err(EvalError::Unsupported);
    }
    match target {
        Value::Str(s) => {
            let chars: Vec<char> = s.chars().collect();
            let sliced: Vec<char> = apply_slice(&chars, lower, upper, step);
            Ok(Value::Str(sliced.into_iter().collect::<String>()))
        }
        Value::Bytes(b) => {
            let bytes_vec: Vec<u8> = b.clone();
            let sliced: Vec<u8> = apply_slice(&bytes_vec, lower, upper, step);
            Ok(Value::Bytes(sliced))
        }
        Value::List(items) => {
            let sliced: Vec<Value> = apply_slice(items, lower, upper, step);
            Ok(Value::List(sliced))
        }
        Value::Tuple(items) => {
            let sliced: Vec<Value> = apply_slice(items, lower, upper, step);
            Ok(Value::Tuple(sliced))
        }
        _ => Err(EvalError::TypeMismatch),
    }
}

fn eval_int(expr: &Expr, scope: &Scope) -> core::result::Result<i128, EvalError> {
    match eval_expr(expr, scope)? {
        Value::Int(n) => Ok(n),
        _ => Err(EvalError::TypeMismatch),
    }
}

fn apply_slice<T: Clone>(
    items: &[T],
    lower: Option<i128>,
    upper: Option<i128>,
    step: i128,
) -> Vec<T> {
    let len: i128 = match i128::try_from(items.len()) {
        Ok(n) => n,
        Err(_) => return Vec::new(),
    };
    let (start, end, step_size): (i128, i128, i128) = if step > 0 {
        let s: i128 = lower.map_or(0, |x: i128| clamp_index(x, len, false));
        let e: i128 = upper.map_or(len, |x: i128| clamp_index(x, len, false));
        (s, e, step)
    } else {
        let s: i128 = lower.map_or(len - 1, |x: i128| clamp_index(x, len, true));
        let e: i128 = upper.map_or(-1, |x: i128| clamp_index(x, len, true));
        (s, e, step)
    };
    let mut out: Vec<T> = Vec::new();
    let mut i: i128 = start;
    while (step_size > 0 && i < end) || (step_size < 0 && i > end) {
        let Ok(idx): core::result::Result<usize, _> = usize::try_from(i) else {
            break;
        };
        let Some(item): Option<&T> = items.get(idx) else {
            break;
        };
        out.push(item.clone());
        i = match i.checked_add(step_size) {
            Some(v) => v,
            None => break,
        };
    }
    out
}

fn clamp_index(idx: i128, len: i128, negative_step: bool) -> i128 {
    let normalized: i128 = if idx < 0 { idx + len } else { idx };
    if negative_step {
        normalized.clamp(-1, len - 1)
    } else {
        normalized.clamp(0, len)
    }
}

fn wrap_index(idx: i128, len: usize) -> Option<usize> {
    let len_i: i128 = i128::try_from(len).ok()?;
    let real: i128 = if idx < 0 { idx + len_i } else { idx };
    if real < 0 || real >= len_i {
        return None;
    }
    usize::try_from(real).ok()
}

fn eval_call(c: &ExprCall, scope: &Scope) -> EvalResult {
    if let Expr::Lambda(lambda) = &*c.func {
        return eval_lambda_iife(lambda, &c.arguments.args, scope);
    }
    if !c.arguments.keywords.is_empty() {
        return Err(EvalError::Unsupported);
    }
    if let Expr::Attribute(attr) = &*c.func {
        let args: Vec<Value> = eval_seq(&c.arguments.args, scope)?;
        if let Expr::Name(name_node) = &*attr.value
            && let Some(result) = class_method(name_node.id.as_str(), attr.attr.as_str(), &args)
        {
            return result;
        }
        if attr.attr.as_str() == "__class__"
            && let Some(result) = class_constructor_from_literal(&attr.value, &args)
        {
            return result;
        }
        let receiver: Value = eval_expr(&attr.value, scope)?;
        if let Some(result) = int_dunder_method(&receiver, attr.attr.as_str(), &args) {
            return result;
        }
        return call_method(&receiver, attr.attr.as_str(), &args);
    }
    let Expr::Name(ExprName { id, .. }) = &*c.func else {
        return Err(EvalError::Unsupported);
    };
    if is_forbidden(id.as_str()) {
        return Err(EvalError::DynamicCode);
    }
    if id.as_str() == "map"
        && c.arguments.args.len() == 2
        && let Some(Expr::Name(func_name)) = c.arguments.args.first()
        && let Some(iter_expr) = c.arguments.args.get(1)
    {
        let func: &str = func_name.id.as_str();
        if is_forbidden(func) {
            return Err(EvalError::DynamicCode);
        }
        if is_pure_unary_builtin(func) {
            let iterable: Value = eval_expr(iter_expr, scope)?;
            return map_pure_builtin(func, &iterable);
        }
        return Err(EvalError::Unsupported);
    }
    let args: Vec<Value> = eval_seq(&c.arguments.args, scope)?;
    call_builtin(id.as_str(), &args)
}

fn eval_lambda_iife(lambda: &ExprLambda, call_args: &[Expr], scope: &Scope) -> EvalResult {
    if scope.in_comprehension() {
        return Err(EvalError::Unsupported);
    }
    let Some(parameters): Option<&Parameters> = lambda.parameters.as_deref() else {
        if call_args.is_empty() {
            return eval_expr(&lambda.body, scope);
        }
        return Err(EvalError::Unsupported);
    };
    if !parameters.kwonlyargs.is_empty()
        || parameters.vararg.is_some()
        || parameters.kwarg.is_some()
        || !parameters.posonlyargs.is_empty()
    {
        return Err(EvalError::Unsupported);
    }
    if parameters.args.len() != 1 || call_args.len() != 1 {
        return Err(EvalError::Unsupported);
    }
    let param_name: &str = parameters.args[0].parameter.name.as_str();
    if is_forbidden(param_name) {
        return Err(EvalError::DynamicCode);
    }
    let arg_value: Value = eval_expr(&call_args[0], scope)?;
    let inner: Scope = scope.child_with(param_name.to_owned(), arg_value);
    eval_expr(&lambda.body, &inner)
}

fn class_constructor_from_literal(receiver: &Expr, args: &[Value]) -> Option<EvalResult> {
    match receiver {
        Expr::NumberLiteral(ExprNumberLiteral {
            value: Number::Int(_),
            ..
        }) => Some(call_builtin("int", args)),
        Expr::StringLiteral(_) => Some(call_builtin("str", args)),
        Expr::BytesLiteral(_) => Some(call_builtin("bytes", args)),
        Expr::BooleanLiteral(_) => Some(call_builtin("bool", args)),
        _ => None,
    }
}

fn int_dunder_method(receiver: &Value, method: &str, args: &[Value]) -> Option<EvalResult> {
    let Value::Int(lhs) = receiver else {
        return None;
    };
    if let ("to_bytes", [Value::Int(length), Value::Str(order)]) = (method, args) {
        return Some(int_to_bytes(*lhs, *length, order));
    }
    let [Value::Int(rhs)] = args else {
        return None;
    };
    let result: Option<i128> = match method {
        "__xor__" => Some(lhs ^ rhs),
        "__and__" => Some(lhs & rhs),
        "__or__" => Some(lhs | rhs),
        "__add__" => lhs.checked_add(*rhs),
        "__sub__" => lhs.checked_sub(*rhs),
        "__mul__" => lhs.checked_mul(*rhs),
        "__lshift__" if (0..120).contains(rhs) => u32::try_from(*rhs)
            .ok()
            .and_then(|s: u32| lhs.checked_shl(s)),
        "__rshift__" if (0..120).contains(rhs) => u32::try_from(*rhs)
            .ok()
            .and_then(|s: u32| lhs.checked_shr(s)),
        _ => return None,
    };
    Some(result.map(Value::Int).ok_or(EvalError::Overflow))
}

fn int_to_bytes(value: i128, length: i128, order: &str) -> EvalResult {
    if value < 0 || !(0..=64).contains(&length) {
        return Err(EvalError::Unsupported);
    }
    let len: usize = usize::try_from(length).map_err(|_| EvalError::Overflow)?;
    let big_endian: bool = match order {
        "big" => true,
        "little" => false,
        _ => return Err(EvalError::Unsupported),
    };
    let mut out: Vec<u8> = vec![0u8; len];
    let mut remaining: u128 = u128::try_from(value).map_err(|_| EvalError::Overflow)?;
    for slot in out.iter_mut().rev() {
        *slot = u8::try_from(remaining & 0xff).map_err(|_| EvalError::Overflow)?;
        remaining >>= 8;
    }
    if remaining != 0 {
        return Err(EvalError::Overflow);
    }
    if !big_endian {
        out.reverse();
    }
    Ok(Value::Bytes(out))
}

fn is_pure_unary_builtin(name: &str) -> bool {
    matches!(
        name,
        "chr"
            | "ord"
            | "str"
            | "int"
            | "bool"
            | "abs"
            | "hex"
            | "oct"
            | "bin"
            | "len"
            | "repr"
            | "ascii"
    )
}

fn map_pure_builtin(func: &str, iterable: &Value) -> EvalResult {
    let items: Vec<Value> = iterable.iter_items().ok_or(EvalError::TypeMismatch)?;
    let mut out: Vec<Value> = Vec::with_capacity(items.len());
    for item in items {
        out.push(call_builtin(func, core::slice::from_ref(&item))?);
    }
    Ok(Value::List(out))
}

fn class_method(type_name: &str, method: &str, args: &[Value]) -> Option<EvalResult> {
    match (type_name, method, args) {
        ("bytes" | "bytearray", "fromhex", [Value::Str(hex)]) => Some(bytes_fromhex(hex)),
        ("int", "from_bytes", [Value::Bytes(b), Value::Str(order)]) => {
            Some(int_from_bytes(b, order))
        }
        ("int", _, [Value::Int(lhs), ..]) if method.starts_with("__") => {
            int_dunder_method(&Value::Int(*lhs), method, &args[1..])
        }
        _ => None,
    }
}

fn int_from_bytes(bytes: &[u8], order: &str) -> EvalResult {
    if bytes.len() > 15 {
        return Err(EvalError::Overflow);
    }
    let big_endian: bool = match order {
        "big" => true,
        "little" => false,
        _ => return Err(EvalError::Unsupported),
    };
    let mut value: i128 = 0;
    if big_endian {
        for &byte in bytes {
            value = (value << 8) | i128::from(byte);
        }
    } else {
        for &byte in bytes.iter().rev() {
            value = (value << 8) | i128::from(byte);
        }
    }
    Ok(Value::Int(value))
}

fn bytes_fromhex(hex: &str) -> EvalResult {
    let cleaned: String = hex.chars().filter(|c: &char| !c.is_whitespace()).collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(EvalError::TypeMismatch);
    }
    let bytes_in: &[u8] = cleaned.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(cleaned.len() / 2);
    let mut i: usize = 0;
    while i < bytes_in.len() {
        let pair: &str =
            core::str::from_utf8(&bytes_in[i..i + 2]).map_err(|_| EvalError::TypeMismatch)?;
        let byte: u8 = u8::from_str_radix(pair, 16).map_err(|_| EvalError::TypeMismatch)?;
        out.push(byte);
        i += 2;
    }
    Ok(Value::Bytes(out))
}

fn call_builtin(name: &str, args: &[Value]) -> EvalResult {
    match (name, args) {
        ("chr", [Value::Int(n)]) if (0..0x0011_0000).contains(n) => {
            let cp: u32 = u32::try_from(*n).map_err(|_| EvalError::Overflow)?;
            let ch: char = char::from_u32(cp).ok_or(EvalError::TypeMismatch)?;
            Ok(Value::Str(ch.to_string()))
        }
        ("ord", [Value::Str(s)]) if s.chars().count() == 1 => {
            let c: char = s.chars().next().ok_or(EvalError::TypeMismatch)?;
            Ok(Value::Int(i128::from(c as u32)))
        }
        ("ord", [Value::Bytes(b)]) if b.len() == 1 => Ok(Value::Int(i128::from(
            *b.first().ok_or(EvalError::TypeMismatch)?,
        ))),
        ("int" | "round", [Value::Int(n)]) => Ok(Value::Int(*n)),
        ("int", [Value::Bool(b)]) => Ok(Value::Int(i128::from(*b))),
        ("int", [Value::Str(s)]) => s
            .trim()
            .parse::<i128>()
            .map(Value::Int)
            .map_err(|_| EvalError::TypeMismatch),
        ("int", [Value::Str(s), Value::Int(base)]) if (2..=36).contains(base) => {
            let radix: u32 = u32::try_from(*base).map_err(|_| EvalError::Overflow)?;
            i128::from_str_radix(s.trim(), radix)
                .map(Value::Int)
                .map_err(|_| EvalError::TypeMismatch)
        }
        ("str", [Value::Int(n)]) => Ok(Value::Str(n.to_string())),
        ("str", [Value::Str(s)]) => Ok(Value::Str(s.clone())),
        ("str", [Value::Bool(b)]) => Ok(Value::Str(if *b {
            "True".to_owned()
        } else {
            "False".to_owned()
        })),
        ("str", [Value::None]) => Ok(Value::Str("None".to_owned())),
        ("bool", [v]) => Ok(Value::Bool(v.truthy())),
        ("len", [v]) => v.len().map(Value::Int).ok_or(EvalError::TypeMismatch),
        ("abs", [Value::Int(n)]) => n.checked_abs().map(Value::Int).ok_or(EvalError::Overflow),
        ("bytes" | "bytearray", [Value::Int(n)]) if (0..=4_194_304).contains(n) => {
            let count: usize = usize::try_from(*n).map_err(|_| EvalError::Overflow)?;
            Ok(Value::Bytes(vec![0_u8; count]))
        }
        ("bytes" | "bytearray", [v]) => bytes_from_iterable(v),
        ("bytes" | "bytearray", []) => Ok(Value::Bytes(Vec::new())),
        ("list", [v]) => v
            .iter_items()
            .map(Value::List)
            .ok_or(EvalError::TypeMismatch),
        ("list", []) => Ok(Value::List(Vec::new())),
        ("tuple", [v]) => v
            .iter_items()
            .map(Value::Tuple)
            .ok_or(EvalError::TypeMismatch),
        ("tuple", []) => Ok(Value::Tuple(Vec::new())),
        ("dict", []) => Ok(Value::Dict(BTreeMap::new())),
        ("hex", [Value::Int(n)]) => {
            if *n < 0 {
                Ok(Value::Str(format!("-0x{:x}", n.unsigned_abs())))
            } else {
                Ok(Value::Str(format!("0x{:x}", *n)))
            }
        }
        ("oct", [Value::Int(n)]) => {
            if *n < 0 {
                Ok(Value::Str(format!("-0o{:o}", n.unsigned_abs())))
            } else {
                Ok(Value::Str(format!("0o{:o}", *n)))
            }
        }
        ("bin", [Value::Int(n)]) => {
            if *n < 0 {
                Ok(Value::Str(format!("-0b{:b}", n.unsigned_abs())))
            } else {
                Ok(Value::Str(format!("0b{:b}", *n)))
            }
        }
        ("min", [v]) => min_max(v, true),
        ("max", [v]) => min_max(v, false),
        ("sum", [v]) => sum_iter(v, 0),
        ("sum", [v, Value::Int(start)]) => sum_iter(v, *start),
        ("reversed", [v]) => {
            let mut items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
            items.reverse();
            Ok(Value::List(items))
        }
        ("sorted", [v]) => sorted_iter(v),
        ("zip", args_zip) if !args_zip.is_empty() => zip_iters(args_zip),
        ("enumerate", [v]) => enumerate_iter(v, 0),
        ("enumerate", [v, Value::Int(start)]) => enumerate_iter(v, *start),
        ("filter", [Value::None, v]) => {
            let items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
            Ok(Value::List(
                items
                    .into_iter()
                    .filter(Value::truthy)
                    .collect::<Vec<Value>>(),
            ))
        }
        ("divmod", [Value::Int(a), Value::Int(d)]) if *d != 0 => Ok(Value::Tuple(vec![
            Value::Int(a.div_euclid(*d)),
            Value::Int(a.rem_euclid(*d)),
        ])),
        ("pow", [Value::Int(base), Value::Int(exp)]) if (0..256).contains(exp) => {
            let e: u32 = u32::try_from(*exp).map_err(|_| EvalError::Overflow)?;
            base.checked_pow(e)
                .map(Value::Int)
                .ok_or(EvalError::Overflow)
        }
        ("pow", [Value::Int(base), Value::Int(exp), Value::Int(modulus)])
            if *exp >= 0 && *modulus != 0 =>
        {
            Ok(Value::Int(pow_mod(*base, *exp, *modulus)))
        }
        ("repr" | "ascii", [v]) => Ok(Value::Str(py_repr(v, name == "ascii"))),
        ("range", [Value::Int(end_n)]) => Ok(Value::List(range_list(0, *end_n, 1)?)),
        ("range", [Value::Int(begin_n), Value::Int(end_n)]) => {
            Ok(Value::List(range_list(*begin_n, *end_n, 1)?))
        }
        ("range", [Value::Int(begin_n), Value::Int(end_n), Value::Int(stride_n)])
            if *stride_n != 0 =>
        {
            Ok(Value::List(range_list(*begin_n, *end_n, *stride_n)?))
        }
        _ => Err(EvalError::Unsupported),
    }
}

fn bytes_from_iterable(v: &Value) -> EvalResult {
    match v {
        Value::Bytes(b) => Ok(Value::Bytes(b.clone())),
        Value::List(items) | Value::Tuple(items) => {
            let mut out: Vec<u8> = Vec::with_capacity(items.len());
            for item in items {
                let Value::Int(n) = item else {
                    return Err(EvalError::TypeMismatch);
                };
                let byte: u8 = u8::try_from(*n).map_err(|_| EvalError::Overflow)?;
                out.push(byte);
            }
            Ok(Value::Bytes(out))
        }
        Value::Str(s) => Ok(Value::Bytes(s.as_bytes().to_vec())),
        _ => Err(EvalError::TypeMismatch),
    }
}

fn min_max(v: &Value, is_min: bool) -> EvalResult {
    let items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
    let mut best: Option<Value> = None;
    for item in items {
        match (&best, &item) {
            (None, _) => best = Some(item),
            (Some(Value::Int(b)), Value::Int(c)) => {
                let take: bool = if is_min { c < b } else { c > b };
                if take {
                    best = Some(item);
                }
            }
            _ => return Err(EvalError::TypeMismatch),
        }
    }
    best.ok_or(EvalError::TypeMismatch)
}

fn sum_iter(v: &Value, start: i128) -> EvalResult {
    let items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
    let mut total: i128 = start;
    for item in items {
        let Value::Int(n) = item else {
            return Err(EvalError::TypeMismatch);
        };
        total = total.checked_add(n).ok_or(EvalError::Overflow)?;
    }
    Ok(Value::Int(total))
}

fn sorted_iter(v: &Value) -> EvalResult {
    let mut items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
    let all_int: bool = items.iter().all(|x: &Value| matches!(x, Value::Int(_)));
    let all_str: bool = items.iter().all(|x: &Value| matches!(x, Value::Str(_)));
    if all_int {
        items.sort_by(|a: &Value, b: &Value| match (a, b) {
            (Value::Int(x), Value::Int(y)) => x.cmp(y),
            _ => core::cmp::Ordering::Equal,
        });
    } else if all_str {
        items.sort_by(|a: &Value, b: &Value| match (a, b) {
            (Value::Str(x), Value::Str(y)) => x.cmp(y),
            _ => core::cmp::Ordering::Equal,
        });
    } else {
        return Err(EvalError::TypeMismatch);
    }
    Ok(Value::List(items))
}

fn zip_iters(args: &[Value]) -> EvalResult {
    let mut columns: Vec<Vec<Value>> = Vec::with_capacity(args.len());
    for arg in args {
        columns.push(arg.iter_items().ok_or(EvalError::TypeMismatch)?);
    }
    let rows: usize = columns.iter().map(Vec::len).min().unwrap_or(0);
    let mut out: Vec<Value> = Vec::with_capacity(rows);
    for row in 0..rows {
        let mut tuple: Vec<Value> = Vec::with_capacity(columns.len());
        for column in &columns {
            tuple.push(column.get(row).cloned().ok_or(EvalError::IndexOutOfRange)?);
        }
        out.push(Value::Tuple(tuple));
    }
    Ok(Value::List(out))
}

fn enumerate_iter(v: &Value, start: i128) -> EvalResult {
    let items: Vec<Value> = v.iter_items().ok_or(EvalError::TypeMismatch)?;
    let mut out: Vec<Value> = Vec::with_capacity(items.len());
    let mut index: i128 = start;
    for item in items {
        out.push(Value::Tuple(vec![Value::Int(index), item]));
        index = index.checked_add(1).ok_or(EvalError::Overflow)?;
    }
    Ok(Value::List(out))
}

const fn pow_mod(base: i128, exp: i128, modulus: i128) -> i128 {
    let m: i128 = modulus.abs();
    if m == 1 {
        return 0;
    }
    let mut result: i128 = 1;
    let mut b: i128 = base.rem_euclid(m);
    let mut e: i128 = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * b).rem_euclid(m);
        }
        e >>= 1;
        b = (b * b).rem_euclid(m);
    }
    result
}

fn py_repr(v: &Value, ascii_only: bool) -> String {
    match v {
        Value::None => "None".to_owned(),
        Value::Bool(b) => if *b { "True" } else { "False" }.to_owned(),
        Value::Int(n) => n.to_string(),
        Value::Str(s) => repr_str(s, ascii_only),
        Value::Bytes(b) => repr_bytes(b),
        Value::List(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|x: &Value| py_repr(x, ascii_only))
                .collect();
            format!("[{}]", inner.join(", "))
        }
        Value::Tuple(items) => {
            let inner: Vec<String> = items
                .iter()
                .map(|x: &Value| py_repr(x, ascii_only))
                .collect();
            if items.len() == 1 {
                format!("({},)", inner[0])
            } else {
                format!("({})", inner.join(", "))
            }
        }
        Value::Dict(_) => String::new(),
    }
}

fn repr_str(s: &str, ascii_only: bool) -> String {
    let has_single: bool = s.contains('\'');
    let has_double: bool = s.contains('"');
    let quote: char = if has_single && !has_double { '"' } else { '\'' };
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if ascii_only && !c.is_ascii() => {
                let code: u32 = c as u32;
                if code <= 0xff {
                    out.push_str("\\x");
                    push_lower_hex_fixed(&mut out, code, 2);
                } else if code <= 0xffff {
                    out.push_str("\\u");
                    push_lower_hex_fixed(&mut out, code, 4);
                } else {
                    out.push_str("\\U");
                    push_lower_hex_fixed(&mut out, code, 8);
                }
            }
            c if (c as u32) < 0x20
                || c as u32 == 0x7f
                || (!ascii_only && (0x80..=0xa0).contains(&(c as u32))) =>
            {
                out.push_str("\\x");
                push_lower_hex_fixed(&mut out, c as u32, 2);
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

fn repr_bytes(b: &[u8]) -> String {
    let mut out: String = String::with_capacity(b.len() + 3);
    out.push_str("b'");
    for &byte in b {
        match byte {
            b'\\' => out.push_str("\\\\"),
            b'\'' => out.push_str("\\'"),
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b'\t' => out.push_str("\\t"),
            0x20..=0x7e => out.push(char::from(byte)),
            _ => {
                out.push_str("\\x");
                push_lower_hex_fixed(&mut out, u32::from(byte), 2);
            }
        }
    }
    out.push('\'');
    out
}

fn range_list(
    begin_n: i128,
    end_n: i128,
    stride_n: i128,
) -> core::result::Result<Vec<Value>, EvalError> {
    if stride_n == 0 {
        return Err(EvalError::Unsupported);
    }
    let mut out: Vec<Value> = Vec::new();
    let mut i: i128 = begin_n;
    let mut guard: usize = 0;
    while (stride_n > 0 && i < end_n) || (stride_n < 0 && i > end_n) {
        out.push(Value::Int(i));
        i = i.checked_add(stride_n).ok_or(EvalError::Overflow)?;
        guard += 1;
        if guard > 1_048_576 {
            return Err(EvalError::Overflow);
        }
    }
    Ok(out)
}

fn eval_attribute(a: &ExprAttribute, scope: &Scope) -> EvalResult {
    let value: Value = eval_expr(&a.value, scope)?;
    match (value, a.attr.as_str()) {
        (Value::Str(s), "upper") => Ok(Value::Str(s.to_uppercase())),
        (Value::Str(s), "lower") => Ok(Value::Str(s.to_lowercase())),
        _ => Err(EvalError::Unsupported),
    }
}

fn eval_comprehension(
    elt: &Expr,
    generators: &[Comprehension],
    outer_scope: &Scope,
) -> core::result::Result<Vec<Value>, EvalError> {
    let mut out: Vec<Value> = Vec::new();
    eval_comp_recursive(elt, generators, 0, outer_scope, &mut out)?;
    Ok(out)
}

fn eval_comp_recursive(
    elt: &Expr,
    generators: &[Comprehension],
    idx: usize,
    scope: &Scope,
    out: &mut Vec<Value>,
) -> core::result::Result<(), EvalError> {
    let Some(comp) = generators.get(idx) else {
        let item: Value = eval_expr(elt, scope)?;
        out.push(item);
        return Ok(());
    };
    if comp.is_async {
        return Err(EvalError::Unsupported);
    }
    let iter: Value = eval_expr(&comp.iter, scope)?;
    let items: Vec<Value> = iter.iter_items().ok_or(EvalError::TypeMismatch)?;
    for item in items {
        let mut inner_scope: Scope = clone_scope(scope);
        bind_target(&comp.target, &item, &mut inner_scope)?;
        let mut keep: bool = true;
        for guard_expr in &comp.ifs {
            let guard: Value = eval_expr(guard_expr, &inner_scope)?;
            if !guard.truthy() {
                keep = false;
                break;
            }
        }
        if !keep {
            continue;
        }
        eval_comp_recursive(elt, generators, idx + 1, &inner_scope, out)?;
    }
    Ok(())
}

fn clone_scope(scope: &Scope) -> Scope {
    Scope {
        bindings: scope.bindings.clone(),
        in_comprehension: true,
    }
}

fn bind_target(
    target: &Expr,
    value: &Value,
    scope: &mut Scope,
) -> core::result::Result<(), EvalError> {
    match target {
        Expr::Name(n) => {
            scope.bind(n.id.to_string(), value.clone());
            Ok(())
        }
        Expr::Tuple(t) => {
            let Some(items): Option<Vec<Value>> = value.iter_items() else {
                return Err(EvalError::TypeMismatch);
            };
            if items.len() != t.elts.len() {
                return Err(EvalError::TypeMismatch);
            }
            for (sub_target, sub_value) in t.elts.iter().zip(items.iter()) {
                bind_target(sub_target, sub_value, scope)?;
            }
            Ok(())
        }
        _ => Err(EvalError::Unsupported),
    }
}

#[cfg(test)]
mod repr_tests {
    use super::{Value, py_repr};

    fn repr_of(chars: &[char]) -> String {
        py_repr(&Value::Str(chars.iter().collect::<String>()), false)
    }

    fn ascii_of(chars: &[char]) -> String {
        py_repr(&Value::Str(chars.iter().collect::<String>()), true)
    }

    #[test]
    fn escapes_delete_control_in_repr_and_ascii() {
        let del: char = '\u{7f}';
        assert_eq!(repr_of(&[del]), "'\\x7f'");
        assert_eq!(ascii_of(&[del]), "'\\x7f'");
    }

    #[test]
    fn escapes_c1_control_range_in_repr() {
        assert_eq!(repr_of(&['\u{80}']), "'\\x80'");
        assert_eq!(repr_of(&['\u{9f}']), "'\\x9f'");
        assert_eq!(repr_of(&['\u{a0}']), "'\\xa0'");
    }

    #[test]
    fn keeps_printable_latin1_unescaped_in_repr() {
        assert_eq!(repr_of(&['\u{a1}']), "'\u{a1}'");
        assert_eq!(repr_of(&['\u{e9}']), "'\u{e9}'");
    }

    #[test]
    fn ascii_escapes_nonascii_printable() {
        assert_eq!(ascii_of(&['\u{a1}']), "'\\xa1'");
        assert_eq!(ascii_of(&['\u{e9}']), "'\\xe9'");
    }
}
