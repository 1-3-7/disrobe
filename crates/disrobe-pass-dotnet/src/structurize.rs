use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use crate::model::Resolver;
use crate::names::NameTable;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TargetLang {
    #[default]
    CSharp,
    FSharp,
    VbNet,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMethod {
    pub signature: String,
    pub body: String,
    pub statement_count: u32,
    pub recovered_locals: u32,
    pub recovered_branches: u32,
    pub typed_locals: u32,
    pub named_params: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallInfo {
    pub arg_count: usize,

    pub returns_value: bool,

    pub has_this: bool,

    pub byref_param_mask: u64,
}

impl CallInfo {
    #[must_use]
    fn arg_is_byref(&self, arg_index: usize) -> bool {
        let param_index: usize = arg_index.saturating_sub(usize::from(self.has_this));
        param_index < 64 && self.byref_param_mask & (1u64 << param_index) != 0
    }
}

pub trait TokenNamer {
    fn name(&self, token: u32) -> String;

    fn call_info(&self, _token: u32) -> Option<CallInfo> {
        None
    }

    fn enum_param_type(&self, _token: u32, _param_index: usize) -> Option<String> {
        None
    }

    fn outer_has_this(&self) -> bool {
        true
    }
}

impl TokenNamer for Resolver {
    #[inline]
    fn name(&self, token: u32) -> String {
        self.resolve_token(token)
    }

    fn call_info(&self, token: u32) -> Option<CallInfo> {
        self.callee_signature(token).map(|sig| {
            let params: usize = sig.params.len();
            let has_this: bool = sig.has_this;
            let byref_param_mask: u64 = sig
                .params
                .iter()
                .take(64)
                .enumerate()
                .filter(|(_, p): &(usize, &crate::signature::TypeSig)| {
                    matches!(p, crate::signature::TypeSig::ByRef(_))
                })
                .fold(
                    0u64,
                    |acc: u64, (idx, _): (usize, &crate::signature::TypeSig)| acc | (1u64 << idx),
                );
            CallInfo {
                arg_count: params + usize::from(has_this),
                returns_value: !matches!(sig.return_type, crate::signature::TypeSigOrVoid::Void),
                has_this,
                byref_param_mask,
            }
        })
    }

    fn enum_param_type(&self, token: u32, param_index: usize) -> Option<String> {
        self.enum_param_type_name(token, param_index)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MethodNamer<'a> {
    pub resolver: &'a Resolver,
    pub has_this: bool,
}

impl TokenNamer for MethodNamer<'_> {
    #[inline]
    fn name(&self, token: u32) -> String {
        self.resolver.resolve_token(token)
    }

    #[inline]
    fn call_info(&self, token: u32) -> Option<CallInfo> {
        self.resolver.call_info(token)
    }

    #[inline]
    fn enum_param_type(&self, token: u32, param_index: usize) -> Option<String> {
        self.resolver.enum_param_type_name(token, param_index)
    }

    #[inline]
    fn outer_has_this(&self) -> bool {
        self.has_this
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct HexNamer;

impl TokenNamer for HexNamer {
    #[inline]
    fn name(&self, token: u32) -> String {
        format!("token_{token:08X}")
    }
}

#[derive(Debug, Clone)]
enum Expr {
    Const(String),
    Local(u32),
    Arg(u32),
    Field(String),
    Unary(&'static str, Box<Self>),
    Binary(&'static str, Box<Self>, Box<Self>),
    Call {
        target: String,
        args: Vec<Self>,
    },
    NewObj {
        ctor: String,
        args: Vec<Self>,
    },
    Tuple(Vec<Self>),
    Coalesce(Box<Self>, Box<Self>),
    Cast(String, Box<Self>),
    IsInst(String, Box<Self>),
    LoadElem(Box<Self>, Box<Self>),
    LoadLen(Box<Self>),
    NewArr(String, Box<Self>),
    AddressOf(Box<Self>),
    Deref(Box<Self>),
    StringLit(String),
    Null,
    This,
    MethodPtr {
        receiver: Option<Box<Self>>,
        method: String,
    },
    Raw(String),
}

impl Expr {
    fn render(&self, lang: TargetLang, names: &NameTable) -> String {
        match self {
            Self::Const(c) | Self::Field(c) | Self::Raw(c) => c.clone(),
            Self::Local(n) => NameTable::local_name(*n),
            Self::Arg(n) => names.arg_name(*n),
            Self::Unary(op, e) => format!("{}{}", map_unary_op(op, lang), paren(e, lang, names)),
            Self::Binary(op, a, b) => {
                format!(
                    "{} {} {}",
                    paren(a, lang, names),
                    map_binary_op(op, lang),
                    paren(b, lang, names)
                )
            }
            Self::Call { target, args } => format!("{target}({})", render_args(args, lang, names)),
            Self::NewObj { ctor, args } => match lang {
                TargetLang::CSharp => format!("new {ctor}({})", render_args(args, lang, names)),
                TargetLang::FSharp => format!("{ctor}({})", render_args(args, lang, names)),
                TargetLang::VbNet => format!("New {ctor}({})", render_args(args, lang, names)),
            },
            Self::Tuple(elems) => format!("({})", render_args(elems, lang, names)),
            Self::Coalesce(a, b) => {
                let lhs: String = paren(a, lang, names);
                let rhs: String = paren(b, lang, names);
                match lang {
                    TargetLang::CSharp => format!("{lhs} ?? {rhs}"),
                    TargetLang::FSharp => {
                        format!("(if {lhs} <> null then {lhs} else {rhs})")
                    }
                    TargetLang::VbNet => format!("If({lhs}, {rhs})"),
                }
            }
            Self::Cast(ty, e) => match lang {
                TargetLang::CSharp => format!("({ty}){}", paren(e, lang, names)),
                TargetLang::FSharp => format!("({} :?> {ty})", e.render(lang, names)),
                TargetLang::VbNet => format!("CType({}, {ty})", e.render(lang, names)),
            },
            Self::IsInst(ty, e) => match lang {
                TargetLang::CSharp => format!("{} as {ty}", paren(e, lang, names)),
                TargetLang::FSharp => format!("({} :?> {ty})", e.render(lang, names)),
                TargetLang::VbNet => format!("TryCast({}, {ty})", e.render(lang, names)),
            },
            Self::LoadElem(arr, idx) => {
                format!("{}[{}]", paren(arr, lang, names), idx.render(lang, names))
            }
            Self::LoadLen(arr) => format!("{}.Length", paren(arr, lang, names)),
            Self::NewArr(ty, len) => format!("new {ty}[{}]", len.render(lang, names)),
            Self::AddressOf(e) => match lang {
                TargetLang::CSharp | TargetLang::FSharp => format!("&{}", paren(e, lang, names)),
                TargetLang::VbNet => e.render(lang, names),
            },
            Self::Deref(e) => match lang {
                TargetLang::CSharp if is_managed_byref_expr(e, names) => e.render(lang, names),
                TargetLang::CSharp => format!("*{}", paren(e, lang, names)),
                TargetLang::FSharp => format!("{}.Value", paren(e, lang, names)),
                TargetLang::VbNet => e.render(lang, names),
            },
            Self::StringLit(s) => format!("\"{}\"", escape(s)),
            Self::Null => match lang {
                TargetLang::CSharp | TargetLang::FSharp => "null".to_owned(),
                TargetLang::VbNet => "Nothing".to_owned(),
            },
            Self::This => match lang {
                TargetLang::CSharp | TargetLang::FSharp => "this".to_owned(),
                TargetLang::VbNet => "Me".to_owned(),
            },
            Self::MethodPtr { receiver, method } => receiver.as_deref().map_or_else(
                || short(method),
                |r: &Self| format!("{}.{}", paren(r, lang, names), short(method)),
            ),
        }
    }

    const fn is_atom(&self) -> bool {
        matches!(
            self,
            Self::Const(_)
                | Self::Local(_)
                | Self::Arg(_)
                | Self::Field(_)
                | Self::Raw(_)
                | Self::StringLit(_)
                | Self::Null
                | Self::This
                | Self::Call { .. }
                | Self::NewObj { .. }
                | Self::Tuple(_)
                | Self::LoadElem(_, _)
                | Self::LoadLen(_)
                | Self::MethodPtr { .. }
        )
    }
}

fn paren(e: &Expr, lang: TargetLang, names: &NameTable) -> String {
    if e.is_atom() {
        e.render(lang, names)
    } else {
        format!("({})", e.render(lang, names))
    }
}

fn call_receiver(e: &Expr, lang: TargetLang, names: &NameTable) -> String {
    match e {
        Expr::AddressOf(inner) => paren(inner, lang, names),
        other => paren(other, lang, names),
    }
}

fn deref_target(addr: &Expr, lang: TargetLang, names: &NameTable) -> String {
    match addr {
        Expr::AddressOf(inner) => inner.render(lang, names),
        other if lang == TargetLang::CSharp && is_managed_byref_expr(other, names) => {
            other.render(lang, names)
        }
        other => format!("*{}", paren(other, lang, names)),
    }
}

fn is_managed_byref_expr(e: &Expr, names: &NameTable) -> bool {
    match e {
        Expr::Arg(n) => names.arg_is_managed_byref(*n),
        Expr::Local(n) => names.local_is_managed_byref(*n),
        _ => false,
    }
}

fn is_singleton_field(name: &str) -> bool {
    let short: &str = name.rsplit("::").next().unwrap_or(name);
    short == "<>9" || short.starts_with("<>9__")
}

fn render_args(args: &[Expr], lang: TargetLang, names: &NameTable) -> String {
    args.iter()
        .map(|e: &Expr| e.render(lang, names))
        .collect::<Vec<String>>()
        .join(", ")
}

fn is_value_tuple_ctor(ctor: &str) -> bool {
    ctor == "ValueTuple" || ctor.starts_with("ValueTuple<")
}

fn is_tuple_factory_owner(raw: &str) -> bool {
    let Some((owner, _)): Option<(&str, &str)> = raw.rsplit_once("::") else {
        return false;
    };
    let owner_short: &str = owner.rsplit('.').next().unwrap_or(owner);
    let base: &str = owner_short.split('<').next().unwrap_or(owner_short);
    base == "Tuple" || base == "ValueTuple"
}

fn property_getter_name(member: &str) -> Option<&str> {
    let name: &str = member.strip_prefix("get_")?;
    if is_property_identifier(name) {
        Some(name)
    } else {
        None
    }
}

fn property_setter_name(member: &str) -> Option<&str> {
    let name: &str = member.strip_prefix("set_")?;
    if is_property_identifier(name) {
        Some(name)
    } else {
        None
    }
}

fn is_property_identifier(name: &str) -> bool {
    let mut chars: std::str::Chars<'_> = name.chars();
    let Some(first): Option<char> = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    chars.all(|c: char| c.is_ascii_alphanumeric() || c == '_')
}

fn binary_operator_special_name(member: &str) -> Option<&'static str> {
    match member {
        "op_Equality" => Some("=="),
        "op_Inequality" => Some("!="),
        "op_GreaterThan" => Some(">"),
        "op_LessThan" => Some("<"),
        "op_GreaterThanOrEqual" => Some(">="),
        "op_LessThanOrEqual" => Some("<="),
        "op_Addition" => Some("+"),
        "op_Subtraction" => Some("-"),
        "op_Multiply" => Some("*"),
        "op_Division" => Some("/"),
        "op_Modulus" => Some("%"),
        "op_BitwiseAnd" => Some("&"),
        "op_BitwiseOr" => Some("|"),
        "op_ExclusiveOr" => Some("^"),
        "op_LeftShift" => Some("<<"),
        "op_RightShift" => Some(">>"),
        _ => None,
    }
}

fn unary_operator_special_name(member: &str) -> Option<&'static str> {
    match member {
        "op_UnaryNegation" => Some("-"),
        "op_UnaryPlus" => Some("+"),
        "op_LogicalNot" => Some("!"),
        "op_OnesComplement" => Some("~"),
        _ => None,
    }
}

fn map_binary_op(op: &str, lang: TargetLang) -> &'static str {
    match (op, lang) {
        ("&&", TargetLang::VbNet) => "AndAlso",
        ("||", TargetLang::VbNet) => "OrElse",
        ("==", TargetLang::VbNet) => "=",
        ("!=", TargetLang::VbNet) => "<>",
        ("+", _) => "+",
        ("-", _) => "-",
        ("*", _) => "*",
        ("/", _) => "/",
        ("%", _) => "%",
        ("&", _) => "&",
        ("|", _) => "|",
        ("^", _) => "^",
        ("<<", _) => "<<",
        (">>", _) => ">>",
        ("==", _) => "==",
        ("!=", _) => "!=",
        (">", _) => ">",
        ("<", _) => "<",
        (">=", _) => ">=",
        ("<=", _) => "<=",
        ("&&", _) => "&&",
        ("||", _) => "||",
        _ => "?",
    }
}

fn map_unary_op(op: &str, lang: TargetLang) -> &'static str {
    match (op, lang) {
        ("!", TargetLang::FSharp) => "not ",
        ("!", TargetLang::VbNet) => "Not ",
        ("-", _) => "-",
        ("+", _) => "+",
        ("~", _) => "~",
        _ => "!",
    }
}

#[must_use]
pub(crate) fn csharp_string_literal(s: &str) -> String {
    format!("\"{}\"", escape(s))
}

fn escape(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out
}

#[derive(Debug, Clone)]
enum Stmt {
    Assign { target: String, value: String },
    Expr(String),
    Return(Option<String>),
    Throw(Option<String>),
    Comment(String),
}

struct Lifter<'a, N: TokenNamer> {
    namer: &'a N,
    names: &'a NameTable,
    lang: TargetLang,
    stack: Vec<Expr>,
    stmts: Vec<Stmt>,
    locals_used: BTreeSet<u32>,
    locals_assigned: BTreeSet<u32>,
}

impl<'a, N: TokenNamer> Lifter<'a, N> {
    const fn new(namer: &'a N, names: &'a NameTable, lang: TargetLang) -> Self {
        Self {
            namer,
            names,
            lang,
            stack: Vec::new(),
            stmts: Vec::new(),
            locals_used: BTreeSet::new(),
            locals_assigned: BTreeSet::new(),
        }
    }

    #[inline]
    fn push(&mut self, e: Expr) {
        self.stack.push(e);
    }

    #[inline]
    fn pop(&mut self) -> Expr {
        self.stack
            .pop()
            .unwrap_or_else(|| Expr::Raw("__stack_underflow".to_owned()))
    }

    fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        let mut v: Vec<Expr> = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(self.pop());
        }
        v.reverse();
        v
    }

    fn binary(&mut self, op: &'static str) {
        let b: Expr = self.pop();
        let a: Expr = self.pop();
        self.push(Expr::Binary(op, Box::new(a), Box::new(b)));
    }

    fn unary(&mut self, op: &'static str) {
        let a: Expr = self.pop();
        self.push(Expr::Unary(op, Box::new(a)));
    }

    fn token_name(&self, ins: &Instruction) -> String {
        match ins.operand {
            OperandValue::Token(t) => self.namer.name(t),
            _ => "__token".to_owned(),
        }
    }

    fn float_const(ins: &Instruction) -> String {
        match ins.operand {
            OperandValue::F32Bits(b) => format!("{}f", f32::from_bits(b)),
            OperandValue::F64Bits(b) => f64::from_bits(b).to_string(),
            _ => "0".to_owned(),
        }
    }

    fn int_const(ins: &Instruction, name: &str) -> i64 {
        if let Some(rest) = name.strip_prefix("ldc.i4.") {
            return match rest {
                "s" => match ins.operand {
                    OperandValue::U8(b) => i64::from(b.cast_signed()),
                    _ => 0,
                },
                d => d.parse::<i64>().unwrap_or(0),
            };
        }
        if name == "ldc.i4"
            && let OperandValue::I32(v) = ins.operand
        {
            return i64::from(v);
        }
        0
    }

    fn store_loc(&mut self, ins: &Instruction, name: &str) {
        let n: u32 = local_index(ins, name);
        self.locals_used.insert(n);
        let val: Expr = self.pop();
        self.locals_assigned.insert(n);
        self.stmts.push(Stmt::Assign {
            target: NameTable::local_name(n),
            value: val.render(self.lang, self.names),
        });
    }

    fn render_byref_args(
        &mut self,
        args: &[Expr],
        info: Option<CallInfo>,
        has_this: bool,
    ) -> Vec<Expr> {
        let Some(info): Option<CallInfo> = info.filter(|c: &CallInfo| c.byref_param_mask != 0)
        else {
            return args.to_vec();
        };
        args.iter()
            .enumerate()
            .map(|(idx, arg): (usize, &Expr)| {
                if idx == 0 && has_this {
                    return arg.clone();
                }
                let Expr::AddressOf(inner): &Expr = arg else {
                    return arg.clone();
                };
                if !info.arg_is_byref(idx) {
                    return arg.clone();
                }
                let keyword: &str = match inner.as_ref() {
                    Expr::Local(slot) if !self.locals_assigned.contains(slot) => {
                        self.locals_assigned.insert(*slot);
                        "out"
                    }
                    _ => "ref",
                };
                Expr::Raw(format!("{keyword} {}", inner.render(self.lang, self.names)))
            })
            .collect()
    }

    fn emit_call(&mut self, ins: &Instruction) {
        let raw: String = self.token_name(ins);
        let member: &str = raw.rsplit("::").next().unwrap_or(&raw);
        let is_ctor: bool = member == ".ctor" || member == ".cctor";
        let token: u32 = match ins.operand {
            OperandValue::Token(t) => t,
            _ => 0,
        };
        let info: Option<CallInfo> = self.namer.call_info(token);
        let arg_count: usize = info.map_or(0, |c: CallInfo| c.arg_count);
        let returns_value: bool = info.map_or(!is_ctor, |c: CallInfo| c.returns_value);
        let has_this: bool = info.map_or_else(|| raw.contains("::"), |c: CallInfo| c.has_this);

        let mut args: Vec<Expr> = self.pop_n(arg_count);
        if token != 0 {
            let recv_off: usize = usize::from(has_this);
            for (idx, arg) in args.iter_mut().enumerate() {
                if idx < recv_off {
                    continue;
                }
                if let Expr::Const(value) = arg
                    && is_bare_integer_literal(value)
                    && let Some(enum_ty) = self.namer.enum_param_type(token, idx - recv_off)
                {
                    *arg = Expr::Cast(enum_ty, Box::new(Expr::Const(value.clone())));
                }
            }
        }
        if !has_this
            && let Some(op) = binary_operator_special_name(member)
            && args.len() == 2
        {
            let b: Expr = args.pop().unwrap_or(Expr::Null);
            let a: Expr = args.pop().unwrap_or(Expr::Null);
            let folded: Expr = Expr::Binary(op, Box::new(a), Box::new(b));
            if returns_value {
                self.push(folded);
            } else {
                self.stmts
                    .push(Stmt::Expr(folded.render(self.lang, self.names)));
            }
            return;
        }
        if !has_this
            && let Some(op) = unary_operator_special_name(member)
            && args.len() == 1
        {
            let a: Expr = args.pop().unwrap_or(Expr::Null);
            let folded: Expr = Expr::Unary(op, Box::new(a));
            if returns_value {
                self.push(folded);
            } else {
                self.stmts
                    .push(Stmt::Expr(folded.render(self.lang, self.names)));
            }
            return;
        }
        if member == "GetTypeFromHandle"
            && args.len() == 1
            && let Expr::Raw(inner) = &args[0]
            && inner.starts_with("typeof(")
        {
            let typeof_expr: Expr = args.pop().unwrap_or(Expr::Null);
            self.push(typeof_expr);
            return;
        }
        if !has_this
            && member == "Create"
            && is_tuple_factory_owner(&raw)
            && (2..=8).contains(&args.len())
        {
            self.push(Expr::Tuple(args));
            return;
        }
        if let Some(prop) = property_getter_name(member)
            && returns_value
        {
            if has_this && args.len() == 1 {
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                self.push(Expr::Field(format!(
                    "{}.{prop}",
                    call_receiver(&recv, self.lang, self.names)
                )));
                return;
            }
            if !has_this && args.is_empty() {
                self.push(Expr::Field(prop.to_owned()));
                return;
            }
        }
        if let Some(prop) = property_setter_name(member)
            && !returns_value
        {
            if has_this && args.len() == 2 {
                let value: Expr = args.pop().unwrap_or(Expr::Null);
                let recv: Expr = args.pop().unwrap_or(Expr::Null);
                self.stmts.push(Stmt::Assign {
                    target: format!("{}.{prop}", call_receiver(&recv, self.lang, self.names)),
                    value: value.render(self.lang, self.names),
                });
                return;
            }
            if !has_this && args.len() == 1 {
                let value: Expr = args.pop().unwrap_or(Expr::Null);
                self.stmts.push(Stmt::Assign {
                    target: prop.to_owned(),
                    value: value.render(self.lang, self.names),
                });
                return;
            }
        }
        let rendered_args: Vec<Expr> = self.render_byref_args(&args, info, has_this);
        let call: Expr = if has_this && !rendered_args.is_empty() {
            let mut rendered_args: Vec<Expr> = rendered_args;
            let recv: Expr = rendered_args.remove(0);
            Expr::Call {
                target: format!(
                    "{}.{}",
                    call_receiver(&recv, self.lang, self.names),
                    short(&raw)
                ),
                args: rendered_args,
            }
        } else {
            Expr::Call {
                target: static_call_target(&raw, self.lang),
                args: rendered_args,
            }
        };
        if is_ctor || !returns_value {
            self.stmts
                .push(Stmt::Expr(call.render(self.lang, self.names)));
        } else {
            self.push(call);
        }
    }

    fn cmp_cond(&mut self, op: &'static str, lang: TargetLang) -> String {
        let b: Expr = self.pop();
        let a: Expr = self.pop();
        Expr::Binary(op, Box::new(a), Box::new(b)).render(lang, self.names)
    }

    fn arg_slot(&self, idx: u32) -> u32 {
        if self.namer.outer_has_this() {
            idx
        } else {
            idx.saturating_add(1)
        }
    }

    fn forwarded_arg_name(&self, raw_slot: usize, has_this: bool) -> String {
        if raw_slot == 0 && has_this {
            return match self.lang {
                TargetLang::VbNet => "Me".to_owned(),
                _ => "this".to_owned(),
            };
        }
        let raw: u32 = u32::try_from(raw_slot).unwrap_or(u32::MAX);
        let slot: u32 = if has_this { raw } else { raw.saturating_add(1) };
        self.names.arg_name(slot)
    }

    fn as_method_group(args: &[Expr]) -> Option<Expr> {
        let [target, Expr::MethodPtr { receiver, method }]: &[Expr] = args else {
            return None;
        };
        if let Some(bound) = receiver {
            return Some(Expr::MethodPtr {
                receiver: Some(bound.clone()),
                method: method.clone(),
            });
        }
        let bound: Option<Box<Expr>> = match target {
            Expr::Null => None,
            Expr::Field(f) if is_singleton_field(f) => None,
            other => Some(Box::new(other.clone())),
        };
        Some(Expr::MethodPtr {
            receiver: bound,
            method: method.clone(),
        })
    }

    #[allow(clippy::too_many_lines, clippy::match_same_arms)]
    fn lift_one(&mut self, ins: &Instruction) {
        match ins.name.as_str() {
            "nop" | "break" => {}
            "ldnull" => self.push(Expr::Null),
            "ldstr" => {
                let s: String = match ins.operand {
                    OperandValue::Token(t) => self.namer.name(t),
                    _ => String::new(),
                };
                self.push(Expr::StringLit(s));
            }
            "ldc.i4.m1" => self.push(Expr::Const("-1".to_owned())),
            "__coalesce" => {
                let alt: Expr = self.pop();
                let primary: Expr = self.pop();
                self.push(Expr::Coalesce(Box::new(primary), Box::new(alt)));
            }
            "__throw_expr" => {
                let exc: Expr = self.pop();
                let keyword: &str = match self.lang {
                    TargetLang::FSharp => "raise",
                    _ => "throw",
                };
                self.push(Expr::Raw(format!(
                    "{keyword} {}",
                    exc.render(self.lang, self.names)
                )));
            }
            "dup" => {
                let e: Expr = self.pop();
                let r: String = e.render(self.lang, self.names);
                self.push(e);
                self.push(Expr::Raw(r));
            }
            "pop" => {
                let e: Expr = self.pop();
                if matches!(e, Expr::Call { .. } | Expr::NewObj { .. }) {
                    self.stmts.push(Stmt::Expr(e.render(self.lang, self.names)));
                }
            }
            "ret" => {
                let val: Option<String> = if self.stack.is_empty() {
                    None
                } else {
                    Some(self.pop().render(self.lang, self.names))
                };
                self.stmts.push(Stmt::Return(val));
            }
            "add" | "add.ovf" | "add.ovf.un" => self.binary("+"),
            "sub" | "sub.ovf" | "sub.ovf.un" => self.binary("-"),
            "mul" | "mul.ovf" | "mul.ovf.un" => self.binary("*"),
            "div" | "div.un" => self.binary("/"),
            "rem" | "rem.un" => self.binary("%"),
            "and" => self.binary("&"),
            "or" => self.binary("|"),
            "xor" => self.binary("^"),
            "shl" => self.binary("<<"),
            "shr" | "shr.un" => self.binary(">>"),
            "neg" => self.unary("-"),
            "not" => self.unary("~"),
            "ceq" => self.binary("=="),
            "cgt" | "cgt.un" => self.binary(">"),
            "clt" | "clt.un" => self.binary("<"),
            "ldlen" => {
                let arr: Expr = self.pop();
                self.push(Expr::LoadLen(Box::new(arr)));
            }
            "throw" => {
                let e: Expr = self.pop();
                self.stmts
                    .push(Stmt::Throw(Some(e.render(self.lang, self.names))));
            }
            "rethrow" => self.stmts.push(Stmt::Throw(None)),
            "newarr" => {
                let len: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::NewArr(ty, Box::new(len)));
            }
            "newobj" => {
                let raw: String = self.token_name(ins);
                let token: u32 = match ins.operand {
                    OperandValue::Token(t) => t,
                    _ => 0,
                };
                let argc: usize = self.namer.call_info(token).map_or(0, |c: CallInfo| {
                    c.arg_count.saturating_sub(usize::from(c.has_this))
                });
                let args: Vec<Expr> = self.pop_n(argc);
                let ctor: String = short(&raw.replace("::.ctor", ""));
                if let Some(group) = Self::as_method_group(&args) {
                    self.push(group);
                } else if is_value_tuple_ctor(&ctor) && (2..=8).contains(&args.len()) {
                    self.push(Expr::Tuple(args));
                } else {
                    self.push(Expr::NewObj { ctor, args });
                }
            }
            "call" | "callvirt" | "calli" => self.emit_call(ins),
            "castclass" => {
                let e: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::Cast(ty, Box::new(e)));
            }
            "isinst" => {
                let e: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::IsInst(ty, Box::new(e)));
            }
            "box" | "unbox.any" | "unbox" | "readonly." | "volatile." | "tail."
            | "constrained." | "no." => {}
            "ldobj" => {
                let addr: Expr = self.pop();
                self.push(Expr::Deref(Box::new(addr)));
            }
            "stobj" | "cpobj" => {
                let val: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: val.render(self.lang, self.names),
                });
            }
            "initobj" => {
                let addr: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: format!("default({ty})"),
                });
            }
            "ldtoken" => self.push(Expr::Raw(format!(
                "typeof({})",
                short(&self.token_name(ins))
            ))),
            "ldftn" => {
                let method: String = self.token_name(ins);
                self.push(Expr::MethodPtr {
                    receiver: None,
                    method,
                });
            }
            "ldvirtftn" => {
                let obj: Expr = self.pop();
                let method: String = self.token_name(ins);
                self.push(Expr::MethodPtr {
                    receiver: Some(Box::new(obj)),
                    method,
                });
            }
            "sizeof" => {
                self.push(Expr::Raw(format!(
                    "sizeof({})",
                    short(&self.token_name(ins))
                )));
            }
            "localloc" => {
                let size: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "stackalloc byte[{}]",
                    size.render(self.lang, self.names)
                )));
            }
            "ldfld" => {
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj, self.lang, self.names),
                    fld
                )));
            }
            "ldflda" => {
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj, self.lang, self.names),
                    fld
                )))));
            }
            "ldsfld" => {
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::Field(fld));
            }
            "ldsflda" => {
                let fld: String = field_name(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(fld))));
            }
            "stfld" => {
                let val: Expr = self.pop();
                let obj: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: format!("{}.{}", paren(&obj, self.lang, self.names), fld),
                    value: val.render(self.lang, self.names),
                });
            }
            "stsfld" => {
                let val: Expr = self.pop();
                let fld: String = field_name(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: fld,
                    value: val.render(self.lang, self.names),
                });
            }
            "ldelema" => {
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                self.push(Expr::AddressOf(Box::new(Expr::LoadElem(
                    Box::new(arr),
                    Box::new(idx),
                ))));
            }
            n if n.starts_with("ldelem") => {
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                self.push(Expr::LoadElem(Box::new(arr), Box::new(idx)));
            }
            n if n.starts_with("stelem") => {
                let val: Expr = self.pop();
                let idx: Expr = self.pop();
                let arr: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: format!(
                        "{}[{}]",
                        paren(&arr, self.lang, self.names),
                        idx.render(self.lang, self.names)
                    ),
                    value: val.render(self.lang, self.names),
                });
            }
            n if n.starts_with("ldc.i4") => {
                self.push(Expr::Const(Self::int_const(ins, n).to_string()));
            }
            "ldc.i8" => {
                if let OperandValue::I64(v) = ins.operand {
                    self.push(Expr::Const(format!("{v}L")));
                }
            }
            "ldc.r4" | "ldc.r8" => self.push(Expr::Const(Self::float_const(ins))),
            n if n.starts_with("ldarga") => {
                let idx: u32 = local_index(ins, n);
                if idx == 0 && self.namer.outer_has_this() {
                    self.push(Expr::AddressOf(Box::new(Expr::This)));
                } else {
                    self.push(Expr::AddressOf(Box::new(Expr::Arg(self.arg_slot(idx)))));
                }
            }
            n if n.starts_with("ldarg") => {
                let idx: u32 = local_index(ins, n);
                if idx == 0 && self.namer.outer_has_this() {
                    self.push(Expr::This);
                } else {
                    self.push(Expr::Arg(self.arg_slot(idx)));
                }
            }
            n if n.starts_with("ldloca") => {
                let idx: u32 = local_index(ins, n);
                self.locals_used.insert(idx);
                self.push(Expr::AddressOf(Box::new(Expr::Local(idx))));
            }
            n if n.starts_with("ldloc") => {
                let idx: u32 = local_index(ins, n);
                self.locals_used.insert(idx);
                self.push(Expr::Local(idx));
            }
            n if n.starts_with("starg") => {
                let idx: u32 = local_index(ins, n);
                let slot: u32 = self.arg_slot(idx);
                let val: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: self.names.arg_name(slot),
                    value: val.render(self.lang, self.names),
                });
            }
            n if n.starts_with("stloc") => self.store_loc(ins, n),
            n if n.starts_with("conv.") => {}
            n if n.starts_with("ldind.") => {
                let addr: Expr = self.pop();
                self.push(Expr::Deref(Box::new(addr)));
            }
            n if n.starts_with("stind.") => {
                let val: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: deref_target(&addr, self.lang, self.names),
                    value: val.render(self.lang, self.names),
                });
            }
            "br" | "br.s" | "leave" | "leave.s" => {
                self.stack.clear();
            }
            "brtrue" | "brtrue.s" | "brfalse" | "brfalse.s" => {
                let _: Expr = self.pop();
            }
            "beq" | "beq.s" | "bne.un" | "bne.un.s" | "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s"
            | "bge" | "bge.s" | "bge.un" | "bge.un.s" | "blt" | "blt.s" | "blt.un" | "blt.un.s"
            | "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                let _: Expr = self.pop();
                let _: Expr = self.pop();
            }
            "switch" => {
                let _: Expr = self.pop();
            }
            "endfinally" | "endfilter" => self.stack.clear(),
            "ckfinite" | "unaligned." => {}
            "jmp" => {
                let raw: String = self.token_name(ins);
                let token: u32 = match ins.operand {
                    OperandValue::Token(t) => t,
                    _ => 0,
                };
                let argc: usize = self
                    .namer
                    .call_info(token)
                    .map_or(0, |c: CallInfo| c.arg_count);
                let has_this: bool = self.namer.outer_has_this();
                let forwarded: String = (0..argc)
                    .map(|i: usize| self.forwarded_arg_name(i, has_this))
                    .collect::<Vec<String>>()
                    .join(", ");
                self.stmts
                    .push(Stmt::Return(Some(format!("{}({forwarded})", short(&raw)))));
            }
            "arglist" => self.push(Expr::Raw("__arglist".to_owned())),
            "mkrefany" => {
                let addr: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "__makeref({})",
                    Expr::Deref(Box::new(addr)).render(self.lang, self.names)
                )));
            }
            "refanyval" => {
                let tr: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Raw(format!(
                    "__refvalue({}, {ty})",
                    tr.render(self.lang, self.names)
                )))));
            }
            "refanytype" => {
                let tr: Expr = self.pop();
                self.push(Expr::Raw(format!(
                    "__reftype({})",
                    tr.render(self.lang, self.names)
                )));
            }
            "cpblk" => {
                let size: Expr = self.pop();
                let src: Expr = self.pop();
                let dest: Expr = self.pop();
                self.stmts.push(Stmt::Expr(format!(
                    "Unsafe.CopyBlock({}, {}, {})",
                    dest.render(self.lang, self.names),
                    src.render(self.lang, self.names),
                    size.render(self.lang, self.names)
                )));
            }
            "initblk" => {
                let size: Expr = self.pop();
                let value: Expr = self.pop();
                let addr: Expr = self.pop();
                self.stmts.push(Stmt::Expr(format!(
                    "Unsafe.InitBlock({}, {}, {})",
                    addr.render(self.lang, self.names),
                    value.render(self.lang, self.names),
                    size.render(self.lang, self.names)
                )));
            }
            other => self.stmts.push(Stmt::Comment(format!(
                "{other} {}",
                render_operand(&ins.operand)
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) enum LinearStmt {
    Assign { target: String, value: String },
    Expr(String),
    Return(Option<String>),
    Throw(Option<String>),
    Comment(String),
}

#[derive(Debug, Clone, Default)]
pub(crate) struct BlockCode {
    pub stmts: Vec<LinearStmt>,
    pub condition: Option<String>,
    pub switch_selector: Option<String>,
    pub locals_used: BTreeSet<u32>,
}

fn branch_target(ins: &Instruction) -> Option<u32> {
    match ins.operand {
        OperandValue::BrTarget(rel) => {
            Some(u32::try_from(i64::from(ins.offset) + i64::from(rel)).unwrap_or(ins.offset))
        }
        _ => None,
    }
}

fn continue_op_for_and(branch: &str) -> Option<&'static str> {
    match branch {
        "bne.un" | "bne.un.s" => Some("=="),
        "beq" | "beq.s" => Some("!="),
        "bge" | "bge.s" | "bge.un" | "bge.un.s" => Some("<"),
        "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => Some("<="),
        "ble" | "ble.s" | "ble.un" | "ble.un.s" => Some(">"),
        "blt" | "blt.s" | "blt.un" | "blt.un.s" => Some(">="),
        _ => None,
    }
}

pub(crate) fn lift_filter_condition<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    instrs: &[Instruction],
    first: usize,
    last: usize,
) -> Option<(Option<String>, String)> {
    let region: &[Instruction] = &instrs[first..=last];
    let catch_type: Option<String> = region
        .iter()
        .find(|i: &&Instruction| matches!(i.name.as_str(), "isinst" | "castclass"))
        .map(|i: &Instruction| {
            short(&match i.operand {
                OperandValue::Token(t) => namer.name(t),
                _ => "__token".to_owned(),
            })
        });
    let entry: u32 = region
        .iter()
        .find(|i: &&Instruction| matches!(i.name.as_str(), "brtrue" | "brtrue.s"))
        .and_then(branch_target)
        .unwrap_or(region.first()?.offset);
    let end_off: u32 = region
        .iter()
        .find(|i: &&Instruction| i.name == "endfilter")
        .map(|i: &Instruction| i.offset)?;
    let full_body: Vec<&Instruction> = region
        .iter()
        .filter(|i: &&Instruction| i.offset >= entry && i.offset < end_off)
        .collect();
    let true_exit: Option<usize> = full_body
        .iter()
        .position(|i: &&Instruction| matches!(i.name.as_str(), "br" | "br.s"));
    let cond_body: &[&Instruction] =
        true_exit.map_or(full_body.as_slice(), |idx: usize| &full_body[..idx]);
    let false_sink: Option<u32> = cond_body
        .iter()
        .filter(|i: &&&Instruction| continue_op_for_and(&i.name).is_some())
        .filter_map(|i: &&Instruction| branch_target(i))
        .max();
    let conjuncts: Vec<String> = reconstruct_conjuncts(namer, names, lang, cond_body, false_sink);
    if conjuncts.is_empty() {
        return None;
    }
    let joined: String = conjuncts.join(" && ");
    if joined == "ex" || joined.is_empty() {
        return None;
    }
    Some((catch_type, joined))
}

fn reconstruct_conjuncts<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    cond_body: &[&Instruction],
    false_sink: Option<u32>,
) -> Vec<String> {
    let mut lifter: Lifter<'_, N> = Lifter::new(namer, names, lang);
    let mut conjuncts: Vec<String> = Vec::new();
    for ins in cond_body {
        let name: &str = ins.name.as_str();
        if let Some(op) = continue_op_for_and(name) {
            if branch_target(ins) == false_sink {
                let b: Expr = lifter.pop();
                let a: Expr = lifter.pop();
                conjuncts.push(Expr::Binary(op, Box::new(a), Box::new(b)).render(lang, names));
            } else {
                let _: Expr = lifter.pop();
                let _: Expr = lifter.pop();
            }
            continue;
        }
        match name {
            "brfalse" | "brfalse.s" if branch_target(ins) == false_sink => {
                conjuncts.push(lifter.pop().render(lang, names));
            }
            "brtrue" | "brtrue.s" if branch_target(ins) == false_sink => {
                let e: Expr = lifter.pop();
                conjuncts.push(Expr::Unary("!", Box::new(e)).render(lang, names));
            }
            "isinst" | "castclass" => {
                let _: Expr = lifter.pop();
                lifter.push(Expr::Raw("ex".to_owned()));
            }
            "pop" => {
                let _: Expr = lifter.pop();
            }
            "br" | "br.s" | "nop" | "endfilter" => {}
            "ldc.i4.0" if is_bool_normalize(cond_body, ins) => {}
            "cgt.un" if is_bool_normalize_consumer(cond_body, ins) => {}
            _ => lifter.lift_one(ins),
        }
    }
    if let Some(tail) = final_comparison(&mut lifter, lang) {
        conjuncts.push(tail);
    }
    conjuncts
}

fn is_bool_normalize(cond_body: &[&Instruction], cur: &Instruction) -> bool {
    cond_body
        .iter()
        .position(|i: &&Instruction| i.offset == cur.offset)
        .and_then(|idx: usize| cond_body.get(idx + 1))
        .is_some_and(|next: &&Instruction| next.name == "cgt.un")
}

fn is_bool_normalize_consumer(cond_body: &[&Instruction], cur: &Instruction) -> bool {
    cond_body
        .iter()
        .position(|i: &&Instruction| i.offset == cur.offset)
        .and_then(|idx: usize| idx.checked_sub(1).and_then(|p: usize| cond_body.get(p)))
        .is_some_and(|prev: &&Instruction| prev.name == "ldc.i4.0")
}

fn final_comparison<N: TokenNamer>(lifter: &mut Lifter<'_, N>, lang: TargetLang) -> Option<String> {
    if lifter.stack.is_empty() {
        return None;
    }
    let tail: String = lifter.pop().render(lang, lifter.names);
    (tail != "ex" && !tail.is_empty()).then_some(tail)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CondKind {
    Bool,
    Reference,
    Integral,
}

fn is_comparison_or_logical(op: &str) -> bool {
    matches!(op, "==" | "!=" | "<" | ">" | "<=" | ">=" | "&&" | "||")
}

fn is_bool_type_name(ty: &str) -> bool {
    matches!(ty, "bool" | "Boolean" | "System.Boolean")
}

fn is_reference_type_name(ty: &str) -> bool {
    ty.ends_with("[]")
        || ty.contains('<')
        || matches!(
            ty,
            "string" | "String" | "System.String" | "object" | "Object" | "System.Object"
        )
}

fn is_integral_type_name(ty: &str) -> bool {
    matches!(
        ty,
        "int"
            | "uint"
            | "long"
            | "ulong"
            | "short"
            | "ushort"
            | "byte"
            | "sbyte"
            | "char"
            | "nint"
            | "nuint"
            | "IntPtr"
            | "UIntPtr"
            | "Int32"
            | "UInt32"
            | "Int64"
            | "UInt64"
            | "Int16"
            | "UInt16"
            | "Byte"
            | "SByte"
            | "Char"
            | "System.Int32"
            | "System.UInt32"
            | "System.Int64"
            | "System.UInt64"
            | "System.Int16"
            | "System.UInt16"
            | "System.Byte"
            | "System.SByte"
            | "System.Char"
            | "System.IntPtr"
            | "System.UIntPtr"
    )
}

fn classify_type_str(ty: &str) -> CondKind {
    let t: &str = ty.trim();
    if is_bool_type_name(t) {
        CondKind::Bool
    } else if is_reference_type_name(t) {
        CondKind::Reference
    } else if is_integral_type_name(t) {
        CondKind::Integral
    } else {
        CondKind::Bool
    }
}

fn classify_cond_kind(e: &Expr, names: &NameTable) -> CondKind {
    match e {
        Expr::Binary(op, _, _) => {
            if is_comparison_or_logical(op) {
                CondKind::Bool
            } else {
                CondKind::Integral
            }
        }
        Expr::Unary(op, _) => {
            if *op == "!" {
                CondKind::Bool
            } else {
                CondKind::Integral
            }
        }
        Expr::LoadLen(_) => CondKind::Integral,
        Expr::Const(c) => {
            if is_bare_integer_literal(c) {
                CondKind::Integral
            } else {
                CondKind::Bool
            }
        }
        Expr::Null | Expr::StringLit(_) | Expr::This | Expr::NewObj { .. } | Expr::NewArr(_, _) => {
            CondKind::Reference
        }
        Expr::Local(n) => names
            .local_type(*n)
            .map_or(CondKind::Bool, classify_type_str),
        Expr::Arg(n) => names.arg_type(*n).map_or(CondKind::Bool, classify_type_str),
        Expr::Cast(ty, _) => classify_type_str(ty),
        _ => CondKind::Bool,
    }
}

fn branch_condition(e: Expr, brtrue: bool, lang: TargetLang, names: &NameTable) -> String {
    let kind: CondKind = if lang == TargetLang::CSharp {
        classify_cond_kind(&e, names)
    } else {
        CondKind::Bool
    };
    match kind {
        CondKind::Bool if brtrue => e.render(lang, names),
        CondKind::Bool => Expr::Unary("!", Box::new(e)).render(lang, names),
        CondKind::Reference => {
            let op: &'static str = if brtrue { "!=" } else { "==" };
            Expr::Binary(op, Box::new(e), Box::new(Expr::Null)).render(lang, names)
        }
        CondKind::Integral => {
            let op: &'static str = if brtrue { "!=" } else { "==" };
            Expr::Binary(op, Box::new(e), Box::new(Expr::Const("0".to_owned()))).render(lang, names)
        }
    }
}

pub(crate) fn lift_block<N: TokenNamer>(
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    instrs: &[Instruction],
    first: usize,
    last: usize,
) -> BlockCode {
    let mut lifter: Lifter<'_, N> = Lifter::new(namer, names, lang);
    let mut condition: Option<String> = None;
    let mut switch_selector: Option<String> = None;
    for ins in &instrs[first..=last] {
        match ins.flow {
            FlowControl::CondBranch => match ins.name.as_str() {
                "brtrue" | "brtrue.s" => {
                    condition = Some(branch_condition(lifter.pop(), true, lang, names));
                }
                "brfalse" | "brfalse.s" => {
                    condition = Some(branch_condition(lifter.pop(), false, lang, names));
                }
                "beq" | "beq.s" => condition = Some(lifter.cmp_cond("==", lang)),
                "bne.un" | "bne.un.s" => condition = Some(lifter.cmp_cond("!=", lang)),
                "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => {
                    condition = Some(lifter.cmp_cond(">", lang));
                }
                "bge" | "bge.s" | "bge.un" | "bge.un.s" => {
                    condition = Some(lifter.cmp_cond(">=", lang));
                }
                "blt" | "blt.s" | "blt.un" | "blt.un.s" => {
                    condition = Some(lifter.cmp_cond("<", lang));
                }
                "ble" | "ble.s" | "ble.un" | "ble.un.s" => {
                    condition = Some(lifter.cmp_cond("<=", lang));
                }
                "switch" => switch_selector = Some(lifter.pop().render(lang, names)),
                _ => lifter.lift_one(ins),
            },
            FlowControl::Branch
                if matches!(ins.name.as_str(), "br" | "br.s" | "leave" | "leave.s") => {}
            FlowControl::Return if matches!(ins.name.as_str(), "endfinally" | "endfilter") => {}
            _ => lifter.lift_one(ins),
        }
    }
    let stmts: Vec<LinearStmt> = lifter.stmts.into_iter().map(stmt_to_linear).collect();
    BlockCode {
        stmts,
        condition,
        switch_selector,
        locals_used: lifter.locals_used,
    }
}

fn stmt_to_linear(s: Stmt) -> LinearStmt {
    match s {
        Stmt::Assign { target, value } => LinearStmt::Assign { target, value },
        Stmt::Expr(e) => LinearStmt::Expr(e),
        Stmt::Return(v) => LinearStmt::Return(v),
        Stmt::Throw(v) => LinearStmt::Throw(v),
        Stmt::Comment(c) => LinearStmt::Comment(c),
    }
}

fn normalize_branches(body: &MethodBody) -> MethodBody {
    let offsets: Vec<u32> = body
        .instructions
        .iter()
        .map(|i: &Instruction| i.offset)
        .collect();
    let mut patched: MethodBody = body.clone();
    let last_size: u32 = body
        .code_size
        .checked_sub(offsets.last().copied().unwrap_or(0))
        .unwrap_or(1)
        .max(1);
    for (idx, ins) in patched.instructions.iter_mut().enumerate() {
        let next_off: u32 = offsets
            .get(idx + 1)
            .copied()
            .unwrap_or_else(|| ins.offset + last_size);
        match &mut ins.operand {
            OperandValue::BrTarget(rel) => {
                let abs: i64 = i64::from(next_off) + i64::from(*rel);
                *rel = i32::try_from(abs - i64::from(ins.offset)).unwrap_or(*rel);
            }
            OperandValue::Switch(rels) => {
                for r in rels.iter_mut() {
                    let abs: i64 = i64::from(next_off) + i64::from(*r);
                    *r = i32::try_from(abs - i64::from(ins.offset)).unwrap_or(*r);
                }
            }
            _ => {}
        }
    }
    patched
}

#[must_use]
pub fn normalize_branches_pub(body: &MethodBody) -> MethodBody {
    normalize_branches(body)
}

#[must_use]
pub fn decompile_method<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
) -> StructuredMethod {
    decompile_method_in(signature, body, namer, TargetLang::CSharp)
}

#[must_use]
pub fn decompile_method_in<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    lang: TargetLang,
) -> StructuredMethod {
    decompile_method_named(signature, body, namer, &NameTable::default(), lang)
}

#[must_use]
pub fn decompile_method_named<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
) -> StructuredMethod {
    let normalized: MethodBody = normalize_branches(body);
    let prepared: MethodBody = if lang == TargetLang::CSharp {
        crate::cil::fold_null_coalesce(&normalized)
    } else {
        normalized
    };
    let recovered: crate::structure_emit::StructuredOutput =
        crate::structure_emit::structure_method(&prepared, namer, names, lang);
    finish_structured(signature, recovered, names, lang)
}

#[must_use]
pub fn decompile_move_next_named<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    names: &NameTable,
    lang: TargetLang,
    is_async: bool,
) -> StructuredMethod {
    let prepared: MethodBody = crate::cil::fold_null_coalesce(&normalize_branches(body));
    let recovered: crate::structure_emit::StructuredOutput =
        crate::structure_emit::structure_move_next(&prepared, namer, names, lang, is_async);
    finish_structured(signature, recovered, names, lang)
}

#[must_use]
fn finish_structured(
    signature: &str,
    recovered: crate::structure_emit::StructuredOutput,
    names: &NameTable,
    lang: TargetLang,
) -> StructuredMethod {
    let recovered_body: String = if lang == TargetLang::CSharp {
        canonicalize_bool_returns(&recovered.body, signature)
    } else {
        recovered.body.clone()
    };
    let mut text: String = String::with_capacity(recovered_body.len() + 128);
    write_prologue(&mut text, signature, &recovered.locals_used, names, lang);
    text.push_str(&recovered_body);
    write_epilogue(&mut text, signature, lang);

    let statement_count: u32 = u32::try_from(recovered_body.lines().count()).unwrap_or(u32::MAX);
    let used_locals: Vec<u32> = recovered.locals_used.iter().copied().collect();
    StructuredMethod {
        signature: signature.to_owned(),
        body: text,
        statement_count,
        recovered_locals: u32::try_from(recovered.locals_used.len()).unwrap_or(u32::MAX),
        recovered_branches: recovered.residual_gotos,
        typed_locals: names.typed_locals_count(&used_locals),
        named_params: names.named_params_count(),
    }
}

fn canonicalize_bool_returns(body: &str, signature: &str) -> String {
    if !csharp_return_type_is_bool(signature) {
        return body.to_owned();
    }
    let has_target: bool = body
        .lines()
        .any(|l: &str| matches!(l.trim(), "return 0;" | "return 1;"));
    if !has_target {
        return body.to_owned();
    }
    let trailing_newline: bool = body.ends_with('\n');
    let mut lines: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed: &str = line.trim_start();
        let indent: &str = &line[..line.len() - trimmed.len()];
        match trimmed {
            "return 0;" => lines.push(format!("{indent}return false;")),
            "return 1;" => lines.push(format!("{indent}return true;")),
            _ => lines.push(line.to_owned()),
        }
    }
    let mut out: String = lines.join("\n");
    if trailing_newline {
        out.push('\n');
    }
    out
}

fn csharp_return_type_is_bool(signature: &str) -> bool {
    let header: &str = signature
        .lines()
        .find(|l: &&str| !l.trim_start().starts_with("//"))
        .unwrap_or(signature);
    let before_params: &str = header.split('(').next().unwrap_or(header).trim_end();
    let Some((qualifiers, _name)): Option<(&str, &str)> = before_params.rsplit_once(' ') else {
        return false;
    };
    matches!(
        qualifiers.rsplit(' ').next(),
        Some("bool" | "System.Boolean")
    )
}

const FSHARP_GOTO_BANNER: &str =
    "    // note: unstructured CIL jumps preserved as comments; F# has no goto";

fn write_prologue(
    text: &mut String,
    signature: &str,
    locals: &BTreeSet<u32>,
    names: &NameTable,
    lang: TargetLang,
) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "{signature}");
            let _ = writeln!(text, "{{");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "{signature} =");
            let _ = writeln!(text, "{FSHARP_GOTO_BANNER}");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "{signature}");
            for n in locals {
                let _ = writeln!(text, "    {}", names.local_decl(*n, lang));
            }
        }
    }
    if !locals.is_empty() {
        let _ = writeln!(text);
    }
}

fn write_epilogue(text: &mut String, signature: &str, lang: TargetLang) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "}}");
        }
        TargetLang::FSharp => {}
        TargetLang::VbNet => {
            let _ = writeln!(text, "{}", vb_body_terminator(signature));
        }
    }
}

fn vb_body_terminator(signature: &str) -> &'static str {
    if signature.contains(") As ") {
        "End Function"
    } else {
        "End Sub"
    }
}

fn is_bare_integer_literal(value: &str) -> bool {
    let digits: &str = value.strip_prefix('-').unwrap_or(value);
    !digits.is_empty() && digits.bytes().all(|b: u8| b.is_ascii_digit())
}

fn short(name: &str) -> String {
    let member: &str = name.rsplit("::").next().unwrap_or(name);
    let head: &str = member.split('<').next().unwrap_or(member);
    let prefix_len: usize = head.rfind('.').map_or(0, |dot: usize| dot + 1);
    member[prefix_len..].to_owned()
}

fn static_call_target(raw: &str, lang: TargetLang) -> String {
    let member: String = short(raw);
    if lang != TargetLang::CSharp {
        return member;
    }
    if crate::lambda_reverse::LINQ_EXTENSIONS.contains(&member.as_str()) {
        return member;
    }
    let Some((owner, _)): Option<(&str, &str)> = raw.rsplit_once("::") else {
        return member;
    };
    if owner.is_empty()
        || owner.contains('<')
        || owner.contains('>')
        || owner.contains('!')
        || owner.contains('[')
        || !owner
            .bytes()
            .all(|b: u8| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
    {
        return member;
    }
    let owner_head: &str = owner.rsplit('.').next().unwrap_or(owner);
    if owner_head.is_empty() || !is_simple_identifier(owner_head) {
        return member;
    }
    format!("{owner}.{member}")
}

fn field_name(name: &str) -> String {
    let raw: String = short(name);
    let recovered: Option<String> = auto_property_backing_name(&raw).map(str::to_owned);
    recovered.unwrap_or(raw)
}

fn auto_property_backing_name(short_name: &str) -> Option<&str> {
    short_name
        .strip_prefix('<')?
        .strip_suffix(">k__BackingField")
        .filter(|p: &&str| !p.is_empty() && is_simple_identifier(p))
}

fn is_simple_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c: char| c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c: char| c == '_' || c.is_ascii_alphanumeric())
}

fn render_operand(op: &OperandValue) -> String {
    match op {
        OperandValue::None => String::new(),
        OperandValue::I32(v) => v.to_string(),
        OperandValue::I64(v) => format!("{v}L"),
        OperandValue::U8(v) => v.to_string(),
        OperandValue::U16(v) => v.to_string(),
        OperandValue::F32Bits(b) => f32::from_bits(*b).to_string(),
        OperandValue::F64Bits(b) => f64::from_bits(*b).to_string(),
        OperandValue::BrTarget(t) => format!("{t:+}"),
        OperandValue::Token(t) => format!("0x{t:08X}"),
        OperandValue::Switch(t) => format!("[{} targets]", t.len()),
    }
}

fn local_index(ins: &Instruction, name: &str) -> u32 {
    if let Some(rest) = name.rsplit('.').next()
        && let Ok(n) = rest.parse::<u32>()
    {
        return n;
    }
    match ins.operand {
        OperandValue::U8(b) => u32::from(b),
        OperandValue::U16(v) => u32::from(v),
        OperandValue::I32(v) => v.cast_unsigned(),
        _ => 0,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::cil::{MethodBody, disassemble};

    fn body_from(code: &[u8]) -> MethodBody {
        MethodBody {
            max_stack: 8,
            code_size: code.len() as u32,
            local_var_sig_tok: 0,
            init_locals: false,
            instructions: disassemble(code).expect("disasm"),
            exception_clauses: Vec::new(),
        }
    }

    struct DelegateNamer;

    impl TokenNamer for DelegateNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0400_0001 => "<>c::<>9".to_owned(),
                0x0600_0010 => "<>c::<Doubled>b__1_0".to_owned(),
                0x0600_0020 => "Repository::Process".to_owned(),
                0x0A00_0030 => "System.Func`2::.ctor".to_owned(),
                0x0A00_0040 => "System.Action::.ctor".to_owned(),
                other => format!("token_{other:08X}"),
            }
        }

        fn call_info(&self, token: u32) -> Option<CallInfo> {
            matches!(token, 0x0A00_0030 | 0x0A00_0040).then_some(CallInfo {
                arg_count: 3,
                returns_value: false,
                has_this: true,
                byref_param_mask: 0,
            })
        }
    }

    #[test]
    fn lifts_addition_to_return_expression() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod =
            decompile_method("int Add(int arg1, int arg2)", &body, &HexNamer);
        assert!(
            out.body.contains("return arg1 + arg2;"),
            "got:\n{}",
            out.body
        );
    }

    #[test]
    fn lifts_local_store_and_load() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod = decompile_method("int M()", &body, &HexNamer);
        assert!(out.body.contains("local0 = 5;"), "got:\n{}", out.body);
        assert!(out.body.contains("return local0;"));
        assert_eq!(out.recovered_locals, 1);
    }

    #[test]
    fn conditional_branch_emits_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(bool arg0)", &body, &HexNamer);
        assert!(out.body.contains("if ("), "got:\n{}", out.body);
        assert!(
            !out.body.contains("goto IL_"),
            "structured if must not leave a goto; got:\n{}",
            out.body
        );
        assert_eq!(out.recovered_branches, 0, "no residual gotos");
    }

    #[test]
    fn compare_branch_recovers_canonical_guard_polarity() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x2F, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(int a, int b)", &body, &HexNamer);
        assert!(
            out.body.contains("if (arg1 < arg2)"),
            "bge taken to the tail recovers the negated fall-through guard csc emits canonically; got:\n{}",
            out.body
        );
    }

    #[test]
    fn switch_renders_switch_header() {
        let code: [u8; 14] = [
            0x03, 0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M(int arg1)", &body, &HexNamer);
        assert!(out.body.contains("switch (arg1)"), "got:\n{}", out.body);
    }

    #[test]
    fn signature_and_braces_present() {
        let body: MethodBody = body_from(&[0x2A]);
        let out: StructuredMethod = decompile_method("void Empty()", &body, &HexNamer);
        assert!(out.body.starts_with("void Empty()\n{\n"));
        assert!(out.body.trim_end().ends_with('}'));
    }

    #[test]
    fn ldstr_renders_string_literal() {
        let mut code: Vec<u8> = vec![0x72];
        code.extend_from_slice(&0x7000_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &HexNamer);
        assert!(out.body.contains('"'), "got:\n{}", out.body);
    }

    #[test]
    fn throw_renders_throw_statement() {
        let mut code: Vec<u8> = vec![0x73];
        code.extend_from_slice(&0x0A00_0001u32.to_le_bytes());
        code.push(0x7A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M()", &body, &HexNamer);
        assert!(out.body.contains("throw new"), "got:\n{}", out.body);
    }

    #[test]
    fn vbnet_lifts_addition_to_return() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "Public Function Add(arg1 As Integer, arg2 As Integer) As Integer",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(
            out.body.contains("Return arg1 + arg2"),
            "got:\n{}",
            out.body
        );
        assert!(out.body.contains("End Function"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_lifts_addition_to_return() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x58, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "member Add(arg1: int, arg2: int) : int",
            &body,
            &HexNamer,
            TargetLang::FSharp,
        );
        assert!(out.body.contains("arg1 + arg2"), "got:\n{}", out.body);
        assert!(out.body.contains(FSHARP_GOTO_BANNER), "got:\n{}", out.body);
    }

    #[test]
    fn vbnet_local_store_uses_dim_and_assign() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod =
            decompile_method_in("Public Sub M()", &body, &HexNamer, TargetLang::VbNet);
        assert!(out.body.contains("Dim local0"), "got:\n{}", out.body);
        assert!(out.body.contains("local0 = 5"), "got:\n{}", out.body);
        assert!(out.body.contains("Return local0"), "got:\n{}", out.body);
        assert!(out.body.contains("End Sub"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_local_store_uses_let_mutable_and_rebind() {
        let body: MethodBody = body_from(&[0x1B, 0x0A, 0x06, 0x2A]);
        let out: StructuredMethod =
            decompile_method_in("member M() : int", &body, &HexNamer, TargetLang::FSharp);
        assert!(
            out.body.contains("let mutable local0"),
            "got:\n{}",
            out.body
        );
        assert!(out.body.contains("local0 <- 5"), "got:\n{}", out.body);
    }

    #[test]
    fn fsharp_conditional_branch_is_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "member M(arg0: bool) : unit",
            &body,
            &HexNamer,
            TargetLang::FSharp,
        );
        assert!(out.body.contains("if "), "got:\n{}", out.body);
        assert!(
            !out.body
                .lines()
                .any(|l: &str| l.trim_start().starts_with("goto ")),
            "F# must never emit a bare goto; got:\n{}",
            out.body
        );
    }

    #[test]
    fn vbnet_conditional_branch_emits_structured_if() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method_in(
            "Public Sub M(arg0 As Boolean)",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(out.body.contains("If "), "got:\n{}", out.body);
        assert!(out.body.contains("End If"), "got:\n{}", out.body);
        assert!(
            !out.body.contains("GoTo IL_"),
            "structured if must not leave a goto; got:\n{}",
            out.body
        );
    }

    #[test]
    fn vbnet_switch_renders_select_case_header() {
        let code: [u8; 14] = [
            0x03, 0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method_in(
            "Public Sub M(arg1 As Integer)",
            &body,
            &HexNamer,
            TargetLang::VbNet,
        );
        assert!(out.body.contains("Select Case arg1"), "got:\n{}", out.body);
        assert!(out.body.contains("End Select"), "got:\n{}", out.body);
    }

    #[test]
    fn ldelema_lifts_to_element_address_not_value() {
        let mut code: Vec<u8> = vec![0x03, 0x17, 0x8F];
        code.extend_from_slice(&0x0100_0001u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M(int[] arg1)", &body, &HexNamer);
        assert!(
            out.body.contains("return &arg1[1];"),
            "ldelema must yield an element address, not a value; got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains("ldelema"),
            "no opcode comment placeholder remains; got:\n{}",
            out.body
        );
    }

    #[test]
    fn ckfinite_passes_value_through() {
        let body: MethodBody = body_from(&[0x03, 0xC3, 0x2A]);
        let out: StructuredMethod = decompile_method("double M(double arg1)", &body, &HexNamer);
        assert!(out.body.contains("return arg1;"), "got:\n{}", out.body);
        assert!(!out.body.contains("ckfinite"), "got:\n{}", out.body);
    }

    #[test]
    fn arglist_lifts_to_runtime_argument_handle() {
        let body: MethodBody = body_from(&[0xFE, 0x00, 0x2A]);
        let out: StructuredMethod = decompile_method("RuntimeArgumentHandle M()", &body, &HexNamer);
        assert!(out.body.contains("return __arglist;"), "got:\n{}", out.body);
    }

    #[test]
    fn cpblk_lifts_to_copyblock_intrinsic() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x05, 0xFE, 0x17, 0x2A]);
        let out: StructuredMethod = decompile_method(
            "void M(void* arg1, void* arg2, uint arg3)",
            &body,
            &HexNamer,
        );
        assert!(
            out.body.contains("Unsafe.CopyBlock(arg1, arg2, arg3)"),
            "cpblk must lift to the CopyBlock intrinsic; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("cpblk"), "got:\n{}", out.body);
    }

    #[test]
    fn initblk_lifts_to_initblock_intrinsic() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x05, 0xFE, 0x18, 0x2A]);
        let out: StructuredMethod =
            decompile_method("void M(void* arg1, byte arg2, uint arg3)", &body, &HexNamer);
        assert!(
            out.body.contains("Unsafe.InitBlock(arg1, arg2, arg3)"),
            "initblk must lift to the InitBlock intrinsic; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("initblk"), "got:\n{}", out.body);
    }

    #[test]
    fn static_lambda_delegate_recovers_method_group() {
        let mut code: Vec<u8> = vec![0x7E];
        code.extend_from_slice(&0x0400_0001u32.to_le_bytes());
        code.extend_from_slice(&[0xFE, 0x06]);
        code.extend_from_slice(&0x0600_0010u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0030u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Func<int, int> M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return <Doubled>b__1_0;"),
            "ldftn->newobj must collapse to a bare method group for a static lambda; got:\n{}",
            out.body
        );
        assert!(
            !out.body.contains("new Func") && !out.body.contains("<>9"),
            "delegate ctor and synthetic singleton receiver dropped; got:\n{}",
            out.body
        );
    }

    #[test]
    fn instance_delegate_recovers_bound_method_group() {
        let mut code: Vec<u8> = vec![0x02];
        code.extend_from_slice(&[0xFE, 0x06]);
        code.extend_from_slice(&0x0600_0020u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0040u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Action M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return this.Process;"),
            "instance delegate must bind the receiver into a method group; got:\n{}",
            out.body
        );
        assert!(!out.body.contains("new Action"), "got:\n{}", out.body);
    }

    #[test]
    fn ldvirtftn_delegate_recovers_virtual_method_group() {
        let mut code: Vec<u8> = vec![0x02, 0x25];
        code.extend_from_slice(&[0xFE, 0x07]);
        code.extend_from_slice(&0x0600_0020u32.to_le_bytes());
        code.push(0x73);
        code.extend_from_slice(&0x0A00_0040u32.to_le_bytes());
        code.push(0x2A);
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("Action M()", &body, &DelegateNamer);
        assert!(
            out.body.contains("return this.Process;"),
            "ldvirtftn delegate must bind its receiver into a method group; got:\n{}",
            out.body
        );
    }

    struct FilterNamer;

    impl TokenNamer for FilterNamer {
        fn name(&self, token: u32) -> String {
            match token {
                0x0100_0050 => "System.InvalidOperationException".to_owned(),
                other => format!("token_{other:08X}"),
            }
        }

        fn outer_has_this(&self) -> bool {
            false
        }
    }

    #[test]
    fn filter_single_comparison_recovers_typed_guard() {
        let mut code: Vec<u8> = vec![0x75];
        code.extend_from_slice(&0x0100_0050u32.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x2D, 0x04, 0x26, 0x16, 0x2B, 0x05, 0x02, 0x1F, 0x05]);
        code.extend_from_slice(&[0xFE, 0x01, 0xFE, 0x11]);
        let body: MethodBody = normalize_branches(&body_from(&code));
        let last: usize = body.instructions.len() - 1;
        let (catch_type, cond): (Option<String>, String) = lift_filter_condition(
            &FilterNamer,
            &NameTable::default(),
            TargetLang::CSharp,
            &body.instructions,
            0,
            last,
        )
        .expect("filter recovered");
        assert_eq!(catch_type.as_deref(), Some("InvalidOperationException"));
        assert_eq!(cond, "arg1 == 5");
    }

    #[test]
    fn filter_short_circuit_and_recovers_conjunction() {
        let mut code: Vec<u8> = vec![0x75];
        code.extend_from_slice(&0x0100_0050u32.to_le_bytes());
        code.extend_from_slice(&[0x25, 0x2D, 0x04, 0x26, 0x16, 0x2B, 0x0E]);
        code.extend_from_slice(&[0x02, 0x1F, 0x05, 0x33, 0x06]);
        code.extend_from_slice(&[0x03, 0x1F, 0x07, 0xFE, 0x01]);
        code.extend_from_slice(&[0x2B, 0x01, 0x16, 0xFE, 0x11]);
        let body: MethodBody = normalize_branches(&body_from(&code));
        let last: usize = body.instructions.len() - 1;
        let (catch_type, cond): (Option<String>, String) = lift_filter_condition(
            &FilterNamer,
            &NameTable::default(),
            TargetLang::CSharp,
            &body.instructions,
            0,
            last,
        )
        .expect("filter recovered");
        assert_eq!(catch_type.as_deref(), Some("InvalidOperationException"));
        assert_eq!(
            cond, "arg1 == 5 && arg2 == 7",
            "short-circuit && must reconstruct both positive conjuncts"
        );
    }

    #[test]
    fn static_call_qualifies_with_declaring_type() {
        assert_eq!(
            static_call_target("System.Threading.Tasks.Task::WhenAny", TargetLang::CSharp),
            "System.Threading.Tasks.Task.WhenAny"
        );
        assert_eq!(
            static_call_target("System.IO.Directory::EnumerateFiles", TargetLang::CSharp),
            "System.IO.Directory.EnumerateFiles"
        );
    }

    #[test]
    fn static_call_leaves_generated_and_placeholder_owners_bare() {
        assert_eq!(
            static_call_target("<>c__DisplayClass0_0::Foo", TargetLang::CSharp),
            "Foo"
        );
        assert_eq!(
            static_call_target(
                "EdgeCases.More.GraphAdjacency<!0>::Neighbors",
                TargetLang::CSharp
            ),
            "Neighbors"
        );
        assert_eq!(
            static_call_target("BareName", TargetLang::CSharp),
            "BareName"
        );
    }

    #[test]
    fn static_call_qualification_is_csharp_only() {
        assert_eq!(
            static_call_target("System.String::Format", TargetLang::VbNet),
            "Format"
        );
    }

    #[test]
    fn call_receiver_drops_address_of() {
        let names: NameTable = NameTable::default();
        let recv: Expr = Expr::AddressOf(Box::new(Expr::Local(2)));
        assert_eq!(call_receiver(&recv, TargetLang::CSharp, &names), "local2");
        let field_recv: Expr = Expr::AddressOf(Box::new(Expr::Field("this.x".to_owned())));
        assert_eq!(
            call_receiver(&field_recv, TargetLang::CSharp, &names),
            "this.x"
        );
    }

    #[test]
    fn deref_target_collapses_address_of_to_plain_lvalue() {
        let names: NameTable = NameTable::default();
        let addr: Expr = Expr::AddressOf(Box::new(Expr::Local(2)));
        assert_eq!(deref_target(&addr, TargetLang::CSharp, &names), "local2");
        let raw_ptr: Expr = Expr::Local(5);
        assert_eq!(
            deref_target(&raw_ptr, TargetLang::CSharp, &names),
            "*local5"
        );
    }

    #[test]
    fn managed_byref_arg_derefs_directly_but_pointer_keeps_star() {
        let byref: NameTable = NameTable::new(
            true,
            vec!["value".to_owned()],
            vec!["ref int".to_owned()],
            Vec::new(),
        );
        let arg: Expr = Expr::Arg(1);
        assert_eq!(deref_target(&arg, TargetLang::CSharp, &byref), "value");
        assert_eq!(
            Expr::Deref(Box::new(Expr::Arg(1))).render(TargetLang::CSharp, &byref),
            "value"
        );
        let ptr: NameTable = NameTable::new(
            true,
            vec!["value".to_owned()],
            vec!["int*".to_owned()],
            Vec::new(),
        );
        assert_eq!(deref_target(&arg, TargetLang::CSharp, &ptr), "*value");
        assert_eq!(
            Expr::Deref(Box::new(Expr::Arg(1))).render(TargetLang::CSharp, &ptr),
            "*value"
        );
    }

    #[test]
    fn call_info_arg_byref_accounts_for_receiver_slot() {
        let info: CallInfo = CallInfo {
            arg_count: 3,
            returns_value: true,
            has_this: true,
            byref_param_mask: 0b10,
        };
        assert!(!info.arg_is_byref(0));
        assert!(!info.arg_is_byref(1));
        assert!(info.arg_is_byref(2));
    }
}
