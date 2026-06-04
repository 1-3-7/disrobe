//! Native structural CIL → pseudo-C# decompiler.
//!
//! Performs evaluation-stack → expression lifting (§I.12.3 abstract stack machine), branch-target
//! recovery, and structured rendering of conditionals, `switch`, `throw`, and
//! `try`/`catch`/`finally`/`fault` from a method body plus its EH clauses. No .NET runtime is
//! required - this is the always-available fallback when ILSpy/dnSpy are absent. Metadata tokens
//! resolve to real member names through any [`TokenNamer`] (e.g. [`crate::model::Resolver`]).

use std::collections::BTreeSet;
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{FlowControl, Instruction, MethodBody, OperandValue};
use crate::model::Resolver;

/// Target pseudo-source language for structural decompilation.
///
/// `CSharp` is the default; `FSharp` and `VbNet` render the same recovered control-flow graph with
/// language-faithful syntax (F# preserves unstructured CIL jumps as comments since it has no
/// `goto`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TargetLang {
    #[default]
    CSharp,
    FSharp,
    VbNet,
}

/// Output of structural decompilation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredMethod {
    pub signature: String,
    pub body: String,
    pub statement_count: u32,
    pub recovered_locals: u32,
    pub recovered_branches: u32,
}

/// Argument count + return shape of a callee, used to lift calls with correct stack effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallInfo {
    /// Total stack operands the call consumes (including the implicit `this` receiver).
    pub arg_count: usize,
    /// Whether the call pushes a result (i.e. non-void return).
    pub returns_value: bool,
    /// Whether the callee is an instance method (has an implicit `this`).
    pub has_this: bool,
}

/// Resolves a metadata token to a printable member/type/string name and, where metadata is
/// available, to a [`CallInfo`] describing the callee's stack effect.
pub trait TokenNamer {
    fn name(&self, token: u32) -> String;

    /// Resolve the callee's call shape. Default returns `None`, leaving the lifter to fall back to
    /// shape-only rendering.
    fn call_info(&self, _token: u32) -> Option<CallInfo> {
        None
    }

    /// Whether the method currently being lifted has an implicit `this` (affects `ldarg.0`). Default
    /// `true` matches the common instance-method case; `decompile_method_for` overrides per method.
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
            CallInfo {
                arg_count: params + usize::from(has_this),
                returns_value: !matches!(sig.return_type, crate::signature::TypeSigOrVoid::Void),
                has_this,
            }
        })
    }
}

/// Pairs a [`Resolver`] with the `has_this` flag of the method being decompiled, so `ldarg.0`
/// resolves to `this` only for instance methods.
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
    fn outer_has_this(&self) -> bool {
        self.has_this
    }
}

/// Prints tokens as hex placeholders; used when no metadata is available.
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
    Call { target: String, args: Vec<Self> },
    NewObj { ctor: String, args: Vec<Self> },
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
    Raw(String),
}

impl Expr {
    fn render(&self, lang: TargetLang) -> String {
        match self {
            Self::Const(c) | Self::Field(c) | Self::Raw(c) => c.clone(),
            Self::Local(n) => format!("local{n}"),
            Self::Arg(n) => format!("arg{n}"),
            Self::Unary(op, e) => format!("{}{}", map_unary_op(op, lang), paren(e, lang)),
            Self::Binary(op, a, b) => {
                format!(
                    "{} {} {}",
                    paren(a, lang),
                    map_binary_op(op, lang),
                    paren(b, lang)
                )
            }
            Self::Call { target, args } => format!("{target}({})", render_args(args, lang)),
            Self::NewObj { ctor, args } => match lang {
                TargetLang::CSharp => format!("new {ctor}({})", render_args(args, lang)),
                TargetLang::FSharp => format!("{ctor}({})", render_args(args, lang)),
                TargetLang::VbNet => format!("New {ctor}({})", render_args(args, lang)),
            },
            Self::Cast(ty, e) => match lang {
                TargetLang::CSharp => format!("({ty}){}", paren(e, lang)),
                TargetLang::FSharp => format!("({} :?> {ty})", e.render(lang)),
                TargetLang::VbNet => format!("CType({}, {ty})", e.render(lang)),
            },
            Self::IsInst(ty, e) => match lang {
                TargetLang::CSharp => format!("{} as {ty}", paren(e, lang)),
                TargetLang::FSharp => format!("({} :?> {ty})", e.render(lang)),
                TargetLang::VbNet => format!("TryCast({}, {ty})", e.render(lang)),
            },
            Self::LoadElem(arr, idx) => format!("{}[{}]", paren(arr, lang), idx.render(lang)),
            Self::LoadLen(arr) => format!("{}.Length", paren(arr, lang)),
            Self::NewArr(ty, len) => format!("new {ty}[{}]", len.render(lang)),
            Self::AddressOf(e) => match lang {
                TargetLang::CSharp | TargetLang::FSharp => format!("&{}", paren(e, lang)),
                TargetLang::VbNet => e.render(lang),
            },
            Self::Deref(e) => match lang {
                TargetLang::CSharp => format!("*{}", paren(e, lang)),
                TargetLang::FSharp => format!("{}.Value", paren(e, lang)),
                TargetLang::VbNet => e.render(lang),
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
                | Self::LoadElem(_, _)
                | Self::LoadLen(_)
        )
    }
}

fn paren(e: &Expr, lang: TargetLang) -> String {
    if e.is_atom() {
        e.render(lang)
    } else {
        format!("({})", e.render(lang))
    }
}

fn render_args(args: &[Expr], lang: TargetLang) -> String {
    args.iter()
        .map(|e: &Expr| e.render(lang))
        .collect::<Vec<String>>()
        .join(", ")
}

/// Map a binary operator spelling per target language. C# spellings pass through unchanged.
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

/// Map a unary operator spelling per target language (`!` becomes `not `/`Not `; `-`/`~` pass).
fn map_unary_op(op: &str, lang: TargetLang) -> &'static str {
    match (op, lang) {
        ("!", TargetLang::FSharp) => "not ",
        ("!", TargetLang::VbNet) => "Not ",
        ("-", _) => "-",
        ("~", _) => "~",
        _ => "!",
    }
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
    lang: TargetLang,
    stack: Vec<Expr>,
    stmts: Vec<Stmt>,
    locals_used: BTreeSet<u32>,
}

impl<'a, N: TokenNamer> Lifter<'a, N> {
    const fn new(namer: &'a N, lang: TargetLang) -> Self {
        Self {
            namer,
            lang,
            stack: Vec::new(),
            stmts: Vec::new(),
            locals_used: BTreeSet::new(),
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
        self.stmts.push(Stmt::Assign {
            target: format!("local{n}"),
            value: val.render(self.lang),
        });
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
        let call: Expr = if has_this && !args.is_empty() {
            let recv: Expr = args.remove(0);
            Expr::Call {
                target: format!("{}.{}", paren(&recv, self.lang), short(&raw)),
                args,
            }
        } else {
            Expr::Call {
                target: short(&raw),
                args,
            }
        };
        if is_ctor || !returns_value {
            self.stmts.push(Stmt::Expr(call.render(self.lang)));
        } else {
            self.push(call);
        }
    }

    /// Pop two operands and render `a op b` as the condition of a comparison-branch, without
    /// emitting a goto. Used by the block lifter to feed structured `if`/`while` headers.
    fn cmp_cond(&mut self, op: &'static str, lang: TargetLang) -> String {
        let b: Expr = self.pop();
        let a: Expr = self.pop();
        Expr::Binary(op, Box::new(a), Box::new(b)).render(lang)
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
            "dup" => {
                let e: Expr = self.pop();
                let r: String = e.render(self.lang);
                self.push(e);
                self.push(Expr::Raw(r));
            }
            "pop" => {
                let e: Expr = self.pop();
                if matches!(e, Expr::Call { .. } | Expr::NewObj { .. }) {
                    self.stmts.push(Stmt::Expr(e.render(self.lang)));
                }
            }
            "ret" => {
                let val: Option<String> = if self.stack.is_empty() {
                    None
                } else {
                    Some(self.pop().render(self.lang))
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
                self.stmts.push(Stmt::Throw(Some(e.render(self.lang))));
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
                self.push(Expr::NewObj { ctor, args });
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
                    target: format!("*{}", paren(&addr, self.lang)),
                    value: val.render(self.lang),
                });
            }
            "initobj" => {
                let addr: Expr = self.pop();
                let ty: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: format!("*{}", paren(&addr, self.lang)),
                    value: format!("default({ty})"),
                });
            }
            "ldtoken" => self.push(Expr::Raw(format!(
                "typeof({})",
                short(&self.token_name(ins))
            ))),
            "ldftn" | "ldvirtftn" => {
                self.push(Expr::Raw(short(&self.token_name(ins))));
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
                    size.render(self.lang)
                )));
            }
            "ldfld" => {
                let obj: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::Field(format!("{}.{}", paren(&obj, self.lang), fld)));
            }
            "ldflda" => {
                let obj: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj, self.lang),
                    fld
                )))));
            }
            "ldsfld" => {
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::Field(fld));
            }
            "ldsflda" => {
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(fld))));
            }
            "stfld" => {
                let val: Expr = self.pop();
                let obj: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: format!("{}.{}", paren(&obj, self.lang), fld),
                    value: val.render(self.lang),
                });
            }
            "stsfld" => {
                let val: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: fld,
                    value: val.render(self.lang),
                });
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
                    target: format!("{}[{}]", paren(&arr, self.lang), idx.render(self.lang)),
                    value: val.render(self.lang),
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
                self.push(Expr::AddressOf(Box::new(Expr::Arg(idx))));
            }
            n if n.starts_with("ldarg") => {
                let idx: u32 = local_index(ins, n);
                if idx == 0 && self.namer.outer_has_this() {
                    self.push(Expr::This);
                } else {
                    let base: u32 = if self.namer.outer_has_this() {
                        idx
                    } else {
                        idx + 1
                    };
                    self.push(Expr::Arg(base));
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
                let val: Expr = self.pop();
                self.stmts.push(Stmt::Assign {
                    target: format!("arg{idx}"),
                    value: val.render(self.lang),
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
                    target: format!("*{}", paren(&addr, self.lang)),
                    value: val.render(self.lang),
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
            other => self.stmts.push(Stmt::Comment(format!(
                "{other} {}",
                render_operand(&ins.operand)
            ))),
        }
    }
}

/// A linear, label-free statement: the structured-emitter form of a lifted instruction. Control
/// flow (branches, loops, conditionals) is reconstructed separately by [`crate::structure_emit`]
/// from the CFG, so the per-block lifter only ever yields these.
#[derive(Debug, Clone)]
pub(crate) enum LinearStmt {
    Assign { target: String, value: String },
    Expr(String),
    Return(Option<String>),
    Throw(Option<String>),
    Comment(String),
}

/// One basic block lifted to linear statements plus, if the block ends in a conditional branch, the
/// rendered condition under which the *taken* edge is followed.
#[derive(Debug, Clone, Default)]
pub(crate) struct BlockCode {
    pub stmts: Vec<LinearStmt>,
    pub condition: Option<String>,
    pub switch_selector: Option<String>,
    pub locals_used: BTreeSet<u32>,
}

/// Lift one basic block's instruction range `[first, last]` to linear statements. The block's
/// terminator condition (for `Cond`/`Switch`) is returned out-of-band so the structurer can place
/// it in a real `if`/`switch` header. The evaluation stack is assumed empty at the block boundary
/// (the standard well-formed-CIL invariant).
pub(crate) fn lift_block<N: TokenNamer>(
    namer: &N,
    lang: TargetLang,
    instrs: &[Instruction],
    first: usize,
    last: usize,
) -> BlockCode {
    let mut lifter: Lifter<'_, N> = Lifter::new(namer, lang);
    let mut condition: Option<String> = None;
    let mut switch_selector: Option<String> = None;
    for ins in &instrs[first..=last] {
        match ins.flow {
            FlowControl::CondBranch => match ins.name.as_str() {
                "brtrue" | "brtrue.s" => condition = Some(lifter.pop().render(lang)),
                "brfalse" | "brfalse.s" => {
                    let c: Expr = lifter.pop();
                    condition = Some(Expr::Unary("!", Box::new(c)).render(lang));
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
                "switch" => switch_selector = Some(lifter.pop().render(lang)),
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

/// CIL branch operands are relative to the byte *after* the instruction. The disassembler records
/// each instruction's start offset, so we pre-resolve every branch operand to an absolute target by
/// using the following instruction's start as the post-instruction PC.
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

/// Public wrapper over branch normalization for [`crate::cfg`] consumers and tests.
///
/// Rewrites every branch/switch operand to be relative to the instruction's own start, so
/// `start + rel` yields the absolute target offset.
#[must_use]
pub fn normalize_branches_pub(body: &MethodBody) -> MethodBody {
    normalize_branches(body)
}

/// Decompile a method body to structured pseudo-C# using a token namer.
#[must_use]
pub fn decompile_method<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
) -> StructuredMethod {
    decompile_method_in(signature, body, namer, TargetLang::CSharp)
}

/// Decompile a method body to structured pseudo-source in the requested [`TargetLang`].
///
/// Recovers a basic-block CFG, computes dominance + natural loops, and emits structured
/// `while`/`if`-`else`/`switch`/`try` via [`crate::structure_emit`]. Residual irreducible edges fall
/// back to labeled `goto` (commented out in F#, which has no `goto`).
#[must_use]
pub fn decompile_method_in<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
    lang: TargetLang,
) -> StructuredMethod {
    let normalized: MethodBody = normalize_branches(body);
    let recovered: crate::structure_emit::StructuredOutput =
        crate::structure_emit::structure_method(&normalized, namer, lang);

    let mut text: String = String::with_capacity(recovered.body.len() + 128);
    write_prologue(&mut text, signature, &recovered.locals_used, lang);
    text.push_str(&recovered.body);
    write_epilogue(&mut text, signature, lang);

    let statement_count: u32 = u32::try_from(recovered.body.lines().count()).unwrap_or(u32::MAX);
    StructuredMethod {
        signature: signature.to_owned(),
        body: text,
        statement_count,
        recovered_locals: u32::try_from(recovered.locals_used.len()).unwrap_or(u32::MAX),
        recovered_branches: recovered.residual_gotos,
    }
}

const FSHARP_GOTO_BANNER: &str =
    "    // note: unstructured CIL jumps preserved as comments; F# has no goto";

/// Emit the method header, opening token, and local declarations per language.
fn write_prologue(text: &mut String, signature: &str, locals: &BTreeSet<u32>, lang: TargetLang) {
    match lang {
        TargetLang::CSharp => {
            let _ = writeln!(text, "{signature}");
            let _ = writeln!(text, "{{");
            for n in locals {
                let _ = writeln!(text, "    var local{n};");
            }
        }
        TargetLang::FSharp => {
            let _ = writeln!(text, "{signature} =");
            let _ = writeln!(text, "{FSHARP_GOTO_BANNER}");
            for n in locals {
                let _ = writeln!(text, "    let mutable local{n} = Unchecked.defaultof<_>");
            }
        }
        TargetLang::VbNet => {
            let _ = writeln!(text, "{signature}");
            for n in locals {
                let _ = writeln!(text, "    Dim local{n}");
            }
        }
    }
    if !locals.is_empty() {
        let _ = writeln!(text);
    }
}

/// Emit the closing token per language. C# closes its brace; VB closes `End Sub`/`End Function`
/// inferred from the signature; F#'s indentation block needs no terminator.
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

/// Choose `End Function` when the VB signature declares a return type (`... As T`), else `End Sub`.
fn vb_body_terminator(signature: &str) -> &'static str {
    if signature.contains(") As ") {
        "End Function"
    } else {
        "End Sub"
    }
}

/// Reduce a fully-qualified member name to its trailing identifier.
fn short(name: &str) -> String {
    name.rsplit("::")
        .next()
        .unwrap_or(name)
        .rsplit('.')
        .next()
        .unwrap_or(name)
        .to_owned()
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
    fn compare_branch_renders_relational() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x2F, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(int a, int b)", &body, &HexNamer);
        assert!(out.body.contains(">="), "got:\n{}", out.body);
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
}
