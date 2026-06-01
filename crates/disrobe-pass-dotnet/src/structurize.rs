//! Native structural CIL → pseudo-C# decompiler.
//!
//! Performs evaluation-stack → expression lifting (§I.12.3 abstract stack machine), branch-target
//! recovery, and structured rendering of conditionals, `switch`, `throw`, and
//! `try`/`catch`/`finally`/`fault` from a method body plus its EH clauses. No .NET runtime is
//! required - this is the always-available fallback when ILSpy/dnSpy are absent. Metadata tokens
//! resolve to real member names through any [`TokenNamer`] (e.g. [`crate::model::Resolver`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::cil::{ExceptionClause, ExceptionClauseKind, Instruction, MethodBody, OperandValue};
use crate::model::Resolver;

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
    fn render(&self) -> String {
        match self {
            Self::Const(c) | Self::Field(c) | Self::Raw(c) => c.clone(),
            Self::Local(n) => format!("local{n}"),
            Self::Arg(n) => format!("arg{n}"),
            Self::Unary(op, e) => format!("{op}{}", paren(e)),
            Self::Binary(op, a, b) => format!("{} {op} {}", paren(a), paren(b)),
            Self::Call { target, args } => format!("{target}({})", render_args(args)),
            Self::NewObj { ctor, args } => format!("new {ctor}({})", render_args(args)),
            Self::Cast(ty, e) => format!("({ty}){}", paren(e)),
            Self::IsInst(ty, e) => format!("{} as {ty}", paren(e)),
            Self::LoadElem(arr, idx) => format!("{}[{}]", paren(arr), idx.render()),
            Self::LoadLen(arr) => format!("{}.Length", paren(arr)),
            Self::NewArr(ty, len) => format!("new {ty}[{}]", len.render()),
            Self::AddressOf(e) => format!("&{}", paren(e)),
            Self::Deref(e) => format!("*{}", paren(e)),
            Self::StringLit(s) => format!("\"{}\"", escape(s)),
            Self::Null => "null".to_owned(),
            Self::This => "this".to_owned(),
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

fn paren(e: &Expr) -> String {
    if e.is_atom() {
        e.render()
    } else {
        format!("({})", e.render())
    }
}

fn render_args(args: &[Expr]) -> String {
    args.iter()
        .map(Expr::render)
        .collect::<Vec<String>>()
        .join(", ")
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
    Assign {
        target: String,
        value: String,
    },
    Expr(String),
    Return(Option<String>),
    Branch {
        cond: Option<String>,
        target: u32,
        negate: bool,
    },
    Switch {
        selector: String,
        targets: Vec<u32>,
    },
    Throw(Option<String>),
    Label(u32),
    Comment(String),
}

struct Lifter<'a, N: TokenNamer> {
    namer: &'a N,
    stack: Vec<Expr>,
    stmts: Vec<Stmt>,
    locals_used: BTreeSet<u32>,
    branches: u32,
}

impl<'a, N: TokenNamer> Lifter<'a, N> {
    const fn new(namer: &'a N) -> Self {
        Self {
            namer,
            stack: Vec::new(),
            stmts: Vec::new(),
            locals_used: BTreeSet::new(),
            branches: 0,
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
            value: val.render(),
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
                target: format!("{}.{}", paren(&recv), short(&raw)),
                args,
            }
        } else {
            Expr::Call {
                target: short(&raw),
                args,
            }
        };
        if is_ctor || !returns_value {
            self.stmts.push(Stmt::Expr(call.render()));
        } else {
            self.push(call);
        }
    }

    fn cond_branch(&mut self, ins: &Instruction, negate: bool) {
        let cond: Expr = self.pop();
        self.stmts.push(Stmt::Branch {
            cond: Some(cond.render()),
            target: abs_target(ins),
            negate,
        });
        self.branches += 1;
    }

    fn cond_branch_cmp(&mut self, ins: &Instruction, op: &'static str) {
        let b: Expr = self.pop();
        let a: Expr = self.pop();
        let cond: Expr = Expr::Binary(op, Box::new(a), Box::new(b));
        self.stmts.push(Stmt::Branch {
            cond: Some(cond.render()),
            target: abs_target(ins),
            negate: false,
        });
        self.branches += 1;
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
                let r: String = e.render();
                self.push(e);
                self.push(Expr::Raw(r));
            }
            "pop" => {
                let e: Expr = self.pop();
                if matches!(e, Expr::Call { .. } | Expr::NewObj { .. }) {
                    self.stmts.push(Stmt::Expr(e.render()));
                }
            }
            "ret" => {
                let val: Option<String> = if self.stack.is_empty() {
                    None
                } else {
                    Some(self.pop().render())
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
                self.stmts.push(Stmt::Throw(Some(e.render())));
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
            "box" | "unbox.any" | "unbox" => {}
            "ldfld" => {
                let obj: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::Field(format!("{}.{}", paren(&obj), fld)));
            }
            "ldflda" => {
                let obj: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.push(Expr::AddressOf(Box::new(Expr::Field(format!(
                    "{}.{}",
                    paren(&obj),
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
                    target: format!("{}.{}", paren(&obj), fld),
                    value: val.render(),
                });
            }
            "stsfld" => {
                let val: Expr = self.pop();
                let fld: String = short(&self.token_name(ins));
                self.stmts.push(Stmt::Assign {
                    target: fld,
                    value: val.render(),
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
                    target: format!("{}[{}]", paren(&arr), idx.render()),
                    value: val.render(),
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
                    value: val.render(),
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
                    target: format!("*{}", paren(&addr)),
                    value: val.render(),
                });
            }
            "br" | "br.s" => {
                self.stmts.push(Stmt::Branch {
                    cond: None,
                    target: abs_target(ins),
                    negate: false,
                });
                self.branches += 1;
            }
            "brtrue" | "brtrue.s" => self.cond_branch(ins, false),
            "brfalse" | "brfalse.s" => self.cond_branch(ins, true),
            "beq" | "beq.s" => self.cond_branch_cmp(ins, "=="),
            "bne.un" | "bne.un.s" => self.cond_branch_cmp(ins, "!="),
            "bgt" | "bgt.s" | "bgt.un" | "bgt.un.s" => self.cond_branch_cmp(ins, ">"),
            "bge" | "bge.s" | "bge.un" | "bge.un.s" => self.cond_branch_cmp(ins, ">="),
            "blt" | "blt.s" | "blt.un" | "blt.un.s" => self.cond_branch_cmp(ins, "<"),
            "ble" | "ble.s" | "ble.un" | "ble.un.s" => self.cond_branch_cmp(ins, "<="),
            "switch" => {
                if let OperandValue::Switch(ref rels) = ins.operand {
                    let selector: Expr = self.pop();
                    let targets: Vec<u32> = rels
                        .iter()
                        .map(|r: &i32| (i64::from(ins.offset) + i64::from(*r)) as u32)
                        .collect();
                    self.stmts.push(Stmt::Switch {
                        selector: selector.render(),
                        targets,
                    });
                    self.branches += 1;
                }
            }
            "leave" | "leave.s" => {
                self.stmts
                    .push(Stmt::Comment(format!("leave IL_{:04X}", abs_target(ins))));
                self.stack.clear();
            }
            "endfinally" | "endfilter" => self.stack.clear(),
            other => self.stmts.push(Stmt::Comment(format!(
                "{other} {}",
                render_operand(&ins.operand)
            ))),
        }
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

#[inline]
fn abs_target(ins: &Instruction) -> u32 {
    match ins.operand {
        OperandValue::BrTarget(rel) => (i64::from(ins.offset) + i64::from(rel)) as u32,
        _ => ins.offset,
    }
}

fn collect_branch_targets(body: &MethodBody) -> BTreeSet<u32> {
    let mut targets: BTreeSet<u32> = BTreeSet::new();
    for ins in &body.instructions {
        match &ins.operand {
            OperandValue::BrTarget(_) => {
                targets.insert(abs_target(ins));
            }
            OperandValue::Switch(rels) => {
                for r in rels {
                    targets.insert((i64::from(ins.offset) + i64::from(*r)) as u32);
                }
            }
            _ => {}
        }
    }
    for clause in &body.exception_clauses {
        targets.insert(clause.try_offset);
        targets.insert(clause.handler_offset);
    }
    targets
}

/// Decompile a method body to structured pseudo-C# using a token namer.
#[must_use]
pub fn decompile_method<N: TokenNamer>(
    signature: &str,
    body: &MethodBody,
    namer: &N,
) -> StructuredMethod {
    let normalized: MethodBody = normalize_branches(body);
    let branch_targets: BTreeSet<u32> = collect_branch_targets(&normalized);

    let mut lifter: Lifter<'_, N> = Lifter::new(namer);
    for ins in &normalized.instructions {
        if branch_targets.contains(&ins.offset) {
            lifter.stmts.push(Stmt::Label(ins.offset));
        }
        lifter.lift_one(ins);
    }

    let mut text: String = String::with_capacity(256);
    let _ = writeln!(text, "{signature}");
    let _ = writeln!(text, "{{");
    for n in &lifter.locals_used {
        let _ = writeln!(text, "    var local{n};");
    }
    if !lifter.locals_used.is_empty() {
        let _ = writeln!(text);
    }
    render_eh_aware(&mut text, &lifter.stmts, &normalized);
    let _ = writeln!(text, "}}");

    StructuredMethod {
        signature: signature.to_owned(),
        body: text,
        statement_count: u32::try_from(lifter.stmts.len()).unwrap_or(u32::MAX),
        recovered_locals: u32::try_from(lifter.locals_used.len()).unwrap_or(u32::MAX),
        recovered_branches: lifter.branches,
    }
}

/// Render statements, opening `try`/handler headers at the IL offsets where EH clauses begin. Full
/// nesting reconstruction is approximate; the markers + labeled gotos preserve correctness.
fn render_eh_aware(text: &mut String, stmts: &[Stmt], body: &MethodBody) {
    let try_starts: BTreeMap<u32, &ExceptionClause> = body
        .exception_clauses
        .iter()
        .map(|c: &ExceptionClause| (c.try_offset, c))
        .collect();
    let handler_kind: BTreeMap<u32, ExceptionClauseKind> = body
        .exception_clauses
        .iter()
        .map(|c: &ExceptionClause| (c.handler_offset, c.kind))
        .collect();

    for stmt in stmts {
        if let Stmt::Label(off) = stmt {
            if let Some(c) = try_starts.get(off) {
                let _ = writeln!(
                    text,
                    "    // try IL_{:04X}..IL_{:04X}",
                    c.try_offset,
                    c.try_offset.saturating_add(c.try_length)
                );
            }
            if let Some(kind) = handler_kind.get(off) {
                let head: &str = match kind {
                    ExceptionClauseKind::Catch => "// catch",
                    ExceptionClauseKind::Filter => "// catch when",
                    ExceptionClauseKind::Finally => "// finally",
                    ExceptionClauseKind::Fault => "// fault",
                };
                let _ = writeln!(text, "    {head}");
            }
        }
        render_stmt(text, stmt);
    }
}

fn render_stmt(text: &mut String, stmt: &Stmt) {
    match stmt {
        Stmt::Assign { target, value } => {
            let _ = writeln!(text, "    {target} = {value};");
        }
        Stmt::Expr(e) => {
            let _ = writeln!(text, "    {e};");
        }
        Stmt::Return(Some(v)) => {
            let _ = writeln!(text, "    return {v};");
        }
        Stmt::Return(None) => {
            let _ = writeln!(text, "    return;");
        }
        Stmt::Branch {
            cond: Some(c),
            target,
            negate,
        } => {
            let cond: String = if *negate {
                format!("!({c})")
            } else {
                c.clone()
            };
            let _ = writeln!(text, "    if ({cond}) goto IL_{target:04X};");
        }
        Stmt::Branch {
            cond: None, target, ..
        } => {
            let _ = writeln!(text, "    goto IL_{target:04X};");
        }
        Stmt::Switch { selector, targets } => {
            let _ = writeln!(text, "    switch ({selector})");
            let _ = writeln!(text, "    {{");
            for (i, t) in targets.iter().enumerate() {
                let _ = writeln!(text, "        case {i}: goto IL_{t:04X};");
            }
            let _ = writeln!(text, "    }}");
        }
        Stmt::Throw(Some(e)) => {
            let _ = writeln!(text, "    throw {e};");
        }
        Stmt::Throw(None) => {
            let _ = writeln!(text, "    throw;");
        }
        Stmt::Label(off) => {
            let _ = writeln!(text, "IL_{off:04X}:;");
        }
        Stmt::Comment(c) => {
            let _ = writeln!(text, "    /* {c} */");
        }
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
    fn conditional_branch_emits_if_goto() {
        let body: MethodBody = body_from(&[0x02, 0x2C, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(bool arg0)", &body, &HexNamer);
        assert!(out.body.contains("if (!("), "got:\n{}", out.body);
        assert!(out.body.contains("goto IL_"));
        assert!(out.recovered_branches >= 1);
    }

    #[test]
    fn compare_branch_renders_relational() {
        let body: MethodBody = body_from(&[0x03, 0x04, 0x2F, 0x01, 0x2A, 0x2A]);
        let out: StructuredMethod = decompile_method("void M(int a, int b)", &body, &HexNamer);
        assert!(out.body.contains(">="), "got:\n{}", out.body);
    }

    #[test]
    fn switch_renders_cases() {
        let code: [u8; 14] = [
            0x03, 0x45, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];
        let body: MethodBody = body_from(&code);
        let out: StructuredMethod = decompile_method("void M(int arg1)", &body, &HexNamer);
        assert!(out.body.contains("switch (arg1)"), "got:\n{}", out.body);
        assert!(out.body.contains("case 0:"));
        assert!(out.body.contains("case 1:"));
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
}
