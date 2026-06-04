use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use crate::abc::{AbcFile, DisasmLine, ExceptionInfo, MethodBody, MethodInfo, disasm};
use crate::error::Result;

/// A recovered AS3 expression node.
///
/// Produced by abstractly interpreting the AVM2 operand stack: leaf nodes
/// carry literals/identifiers; composite nodes fold property access, calls,
/// and arithmetic back into source-like text.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    This,
    Local(u32),
    Param(u32),
    IntLit(i64),
    UintLit(u64),
    DoubleLit(f64),
    StringLit(String),
    BoolLit(bool),
    Null,
    Undefined,
    NaN,
    Name(String),
    Lex(String),
    Get {
        object: Box<Self>,
        property: String,
    },
    Index {
        object: Box<Self>,
        index: Box<Self>,
    },
    Call {
        callee: Box<Self>,
        property: String,
        args: Vec<Self>,
    },
    Construct {
        callee: Box<Self>,
        property: String,
        args: Vec<Self>,
    },
    New {
        ty: Box<Self>,
        args: Vec<Self>,
    },
    Array(Vec<Self>),
    Object(Vec<(Self, Self)>),
    Unary {
        op: &'static str,
        operand: Box<Self>,
    },
    Binary {
        op: &'static str,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Coerce {
        ty: String,
        operand: Box<Self>,
    },
    Typeof(Box<Self>),
    Opaque(&'static str),
}

impl Expr {
    fn render(&self, names: &LocalNames) -> String {
        match self {
            Self::This => "this".to_owned(),
            Self::Local(i) | Self::Param(i) => names.name_of(*i),
            Self::IntLit(v) => v.to_string(),
            Self::UintLit(v) => v.to_string(),
            Self::DoubleLit(v) => render_double(*v),
            Self::StringLit(s) => render_string_lit(s),
            Self::BoolLit(b) => b.to_string(),
            Self::Null => "null".to_owned(),
            Self::Undefined => "undefined".to_owned(),
            Self::NaN => "NaN".to_owned(),
            Self::Name(n) | Self::Lex(n) => n.clone(),
            Self::Get { object, property } => {
                format!("{}.{}", object.render(names), property)
            }
            Self::Index { object, index } => {
                format!("{}[{}]", object.render(names), index.render(names))
            }
            Self::Call {
                callee,
                property,
                args,
            } => {
                let recv: String = callee.render(names);
                let arglist: String = render_args(args, names);
                if property.is_empty() {
                    format!("{recv}({arglist})")
                } else if recv == "this" || recv.is_empty() {
                    format!("{property}({arglist})")
                } else {
                    format!("{recv}.{property}({arglist})")
                }
            }
            Self::Construct {
                callee,
                property,
                args,
            } => {
                let recv: String = callee.render(names);
                let arglist: String = render_args(args, names);
                if recv == "this" || recv.is_empty() {
                    format!("new {property}({arglist})")
                } else {
                    format!("new {recv}.{property}({arglist})")
                }
            }
            Self::New { ty, args } => {
                format!("new {}({})", ty.render(names), render_args(args, names))
            }
            Self::Array(items) => format!("[{}]", render_args(items, names)),
            Self::Object(pairs) => {
                let body: String = pairs
                    .iter()
                    .map(|(k, v): &(Self, Self)| {
                        format!("{}: {}", k.render(names), v.render(names))
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                format!("{{{body}}}")
            }
            Self::Unary { op, operand } => format!("{op}{}", operand.render(names)),
            Self::Binary { op, lhs, rhs } => {
                format!("({} {} {})", lhs.render(names), op, rhs.render(names))
            }
            Self::Coerce { ty, operand } => {
                if ty == "*" || ty.is_empty() {
                    operand.render(names)
                } else {
                    format!("{}({})", ty, operand.render(names))
                }
            }
            Self::Typeof(e) => format!("typeof({})", e.render(names)),
            Self::Opaque(label) => format!("/* {label} */"),
        }
    }
}

fn render_args(args: &[Expr], names: &LocalNames) -> String {
    args.iter()
        .map(|a: &Expr| a.render(names))
        .collect::<Vec<String>>()
        .join(", ")
}

fn render_double(v: f64) -> String {
    if v.is_nan() {
        "NaN".to_owned()
    } else if v.is_infinite() {
        if v.is_sign_negative() {
            "-Infinity".to_owned()
        } else {
            "Infinity".to_owned()
        }
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v}")
    }
}

fn render_string_lit(s: &str) -> String {
    let mut out: String = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Maps a local-register slot to a recovered, source-like name.
///
/// ABC erases developer local names, so slots beyond the parameters are
/// surfaced as `loc{n}`; param slots reuse param-name strings when the method
/// carried them.
#[derive(Debug, Clone)]
pub struct LocalNames {
    param_names: Vec<String>,
    param_count: usize,
}

impl LocalNames {
    fn name_of(&self, slot: u32) -> String {
        if slot == 0 {
            return "this".to_owned();
        }
        let pidx: usize = slot as usize - 1;
        if let Some(name) = self.param_names.get(pidx)
            && !name.is_empty()
        {
            return name.clone();
        }
        if (slot as usize) <= self.param_count {
            format!("arg{slot}")
        } else {
            format!("loc{slot}")
        }
    }
}

/// A single recovered statement in a lifted method body.
#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    Assign {
        target: Expr,
        value: Expr,
    },
    AssignProperty {
        object: Expr,
        property: String,
        value: Expr,
    },
    AssignIndex {
        object: Expr,
        index: Expr,
        value: Expr,
    },
    Expression(Expr),
    Return(Option<Expr>),
    If {
        cond: Expr,
        target_label: usize,
    },
    Jump {
        target_label: usize,
    },
    Label(usize),
    Throw(Expr),
    Switch {
        selector: Expr,
        cases: usize,
    },
    IfBlock {
        cond: Expr,
        body: Vec<Self>,
    },
    Comment(String),
}

/// The outcome of lifting a single method body.
///
/// Carries the recovered statements plus an honesty flag recording whether the
/// walk reached a real `return`/throw terminator or fell back to a partial
/// recovery.
#[derive(Debug, Clone)]
pub struct LiftedBody {
    pub statements: Vec<Stmt>,
    pub recovered: bool,
}

struct Lifter<'a> {
    abc: &'a AbcFile,
    stack: Vec<Expr>,
    statements: Vec<Stmt>,
    names: &'a LocalNames,
}

impl Lifter<'_> {
    fn push(&mut self, e: Expr) {
        self.stack.push(e);
    }

    fn pop(&mut self) -> Expr {
        self.stack.pop().unwrap_or(Expr::Opaque("?"))
    }

    fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        let len: usize = self.stack.len();
        let take: usize = n.min(len);
        let mut out: Vec<Expr> = self.stack.split_off(len - take);
        while out.len() < n {
            out.insert(0, Expr::Opaque("?"));
        }
        out
    }

    fn multiname(&self, idx: i64) -> String {
        if idx <= 0 {
            return String::new();
        }
        self.abc
            .cpool
            .render_multiname(idx as u32)
            .unwrap_or_else(|_| format!("mn#{idx}"))
    }

    fn string(&self, idx: i64) -> String {
        if idx < 0 {
            return String::new();
        }
        self.abc
            .cpool
            .string_at(idx as u32)
            .map_or_else(|_| format!("str#{idx}"), str::to_owned)
    }

    fn int(&self, idx: i64) -> i64 {
        if idx < 0 {
            return 0;
        }
        self.abc
            .cpool
            .integers
            .get(idx as usize)
            .copied()
            .map_or(0, i64::from)
    }

    fn uint(&self, idx: i64) -> u64 {
        if idx < 0 {
            return 0;
        }
        self.abc
            .cpool
            .uintegers
            .get(idx as usize)
            .copied()
            .map_or(0, u64::from)
    }

    fn double(&self, idx: i64) -> f64 {
        if idx < 0 {
            return f64::NAN;
        }
        self.abc
            .cpool
            .doubles
            .get(idx as usize)
            .copied()
            .unwrap_or(f64::NAN)
    }
}

const OP_BIN: &[(u8, &str)] = &[
    (0xA0, "+"),
    (0xA1, "-"),
    (0xA2, "*"),
    (0xA3, "/"),
    (0xA4, "%"),
    (0xA5, "<<"),
    (0xA6, ">>"),
    (0xA7, ">>>"),
    (0xA8, "&"),
    (0xA9, "|"),
    (0xAA, "^"),
    (0xAB, "=="),
    (0xAC, "==="),
    (0xAD, "<"),
    (0xAE, "<="),
    (0xAF, ">"),
    (0xB0, ">="),
    (0xB1, "instanceof"),
    (0xB4, "in"),
    (0xC5, "+"),
    (0xC6, "-"),
    (0xC7, "*"),
];

fn binary_op(op: u8) -> Option<&'static str> {
    OP_BIN.iter().find(|(o, _)| *o == op).map(|(_, s)| *s)
}

const CMP_BRANCH: &[(u8, &str)] = &[
    (0x0C, ">="),
    (0x0D, ">"),
    (0x0E, "<="),
    (0x0F, "<"),
    (0x13, "=="),
    (0x14, "!="),
    (0x15, "<"),
    (0x16, "<="),
    (0x17, ">"),
    (0x18, ">="),
    (0x19, "==="),
    (0x1A, "!=="),
];

fn compare_branch_op(op: u8) -> Option<&'static str> {
    CMP_BRANCH.iter().find(|(o, _)| *o == op).map(|(_, s)| *s)
}

/// Compute the set of byte offsets that are jump targets so the renderer can
/// emit `Ln:` labels only where control flow actually lands.
fn collect_labels(lines: &[DisasmLine], exceptions: &[ExceptionInfo]) -> BTreeSet<usize> {
    let next_offset: BTreeMap<usize, usize> = lines
        .windows(2)
        .map(|w: &[DisasmLine]| (w[0].offset, w[1].offset))
        .collect();
    let end_offset: usize = lines.last().map_or(0, |l: &DisasmLine| {
        next_offset.get(&l.offset).copied().unwrap_or(l.offset)
    });
    let mut labels: BTreeSet<usize> = BTreeSet::new();
    for line in lines {
        let is_branch: bool = matches!(line.opcode, 0x0C..=0x1A);
        if is_branch && line.opcode != 0x1B {
            let after: usize = next_offset.get(&line.offset).copied().unwrap_or(end_offset);
            if let Some(rel) = line.operands.first() {
                let target: usize = (after as i64 + rel).max(0) as usize;
                labels.insert(target);
            }
        }
        if line.opcode == 0x1B {
            let after: usize = next_offset.get(&line.offset).copied().unwrap_or(end_offset);
            for rel in &line.operands[2..] {
                let target: usize = (after as i64 + rel).max(0) as usize;
                labels.insert(target);
            }
            if let Some(default_rel) = line.operands.first() {
                labels.insert((after as i64 + default_rel).max(0) as usize);
            }
        }
    }
    for exc in exceptions {
        labels.insert(exc.target as usize);
    }
    labels
}

#[allow(clippy::too_many_lines)]
fn step(lifter: &mut Lifter<'_>, line: &DisasmLine, next_off: usize, end_off: usize) {
    let op: u8 = line.opcode;
    let ops: &[i64] = &line.operands;
    if let Some(bop) = binary_op(op) {
        let rhs: Expr = lifter.pop();
        let lhs: Expr = lifter.pop();
        lifter.push(Expr::Binary {
            op: bop,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        });
        return;
    }
    match op {
        0x62 => lifter.push(local_expr(ops.first().copied().unwrap_or(0), lifter.names)),
        0xD0 => lifter.push(local_expr(0, lifter.names)),
        0xD1 => lifter.push(local_expr(1, lifter.names)),
        0xD2 => lifter.push(local_expr(2, lifter.names)),
        0xD3 => lifter.push(local_expr(3, lifter.names)),
        0x63 => emit_setlocal(lifter, ops.first().copied().unwrap_or(0)),
        0xD4 => emit_setlocal(lifter, 0),
        0xD5 => emit_setlocal(lifter, 1),
        0xD6 => emit_setlocal(lifter, 2),
        0xD7 => emit_setlocal(lifter, 3),
        0x2C => lifter.push(Expr::StringLit(
            lifter.string(ops.first().copied().unwrap_or(0)),
        )),
        0x2D => lifter.push(Expr::IntLit(lifter.int(ops.first().copied().unwrap_or(0)))),
        0x2E => lifter.push(Expr::UintLit(
            lifter.uint(ops.first().copied().unwrap_or(0)),
        )),
        0x2F => lifter.push(Expr::DoubleLit(
            lifter.double(ops.first().copied().unwrap_or(0)),
        )),
        0x24 | 0x25 => lifter.push(Expr::IntLit(ops.first().copied().unwrap_or(0))),
        0x20 => lifter.push(Expr::Null),
        0x21 => lifter.push(Expr::Undefined),
        0x26 => lifter.push(Expr::BoolLit(true)),
        0x27 => lifter.push(Expr::BoolLit(false)),
        0x28 => lifter.push(Expr::NaN),
        0x29 => {
            let e: Expr = lifter.pop();
            if expr_has_effect(&e) {
                lifter.statements.push(Stmt::Expression(e));
            }
        }
        0x2A => {
            let top: Expr = lifter.pop();
            lifter.push(top.clone());
            lifter.push(top);
        }
        0x2B => {
            let a: Expr = lifter.pop();
            let b: Expr = lifter.pop();
            lifter.push(a);
            lifter.push(b);
        }
        0x60 => lifter.push(Expr::Lex(
            lifter.multiname(ops.first().copied().unwrap_or(0)),
        )),
        0x5D | 0x5E => {
            lifter.push(Expr::Lex(
                lifter.multiname(ops.first().copied().unwrap_or(0)),
            ));
        }
        0x66 | 0x64 => emit_getproperty(lifter, ops.first().copied().unwrap_or(0)),
        0x6C => emit_getslot(lifter, ops.first().copied().unwrap_or(0)),
        0x61 | 0x68 => emit_setproperty(lifter, ops.first().copied().unwrap_or(0)),
        0x6D => emit_setslot(lifter, ops.first().copied().unwrap_or(0)),
        0x46 | 0x4C => emit_call(lifter, ops, false),
        0x4F => emit_call(lifter, ops, true),
        0x4A => emit_constructprop(lifter, ops),
        0x42 => emit_construct(lifter, ops),
        0x41 => emit_callfn(lifter, ops),
        0x49 => emit_constructsuper(lifter, ops),
        0x47 => {
            lifter.statements.push(Stmt::Return(None));
        }
        0x48 => {
            let v: Expr = lifter.pop();
            lifter.statements.push(Stmt::Return(Some(v)));
        }
        0x03 => {
            let v: Expr = lifter.pop();
            lifter.statements.push(Stmt::Throw(v));
        }
        0x56 => emit_newarray(lifter, ops.first().copied().unwrap_or(0)),
        0x55 => emit_newobject(lifter, ops.first().copied().unwrap_or(0)),
        0x90 | 0xC4 => emit_unary(lifter, "-"),
        0x96 => emit_unary(lifter, "!"),
        0x97 => emit_unary(lifter, "~"),
        0x91 | 0xC0 => emit_postfix(lifter, "++"),
        0x93 | 0xC1 => emit_postfix(lifter, "--"),
        0x95 => {
            let e: Expr = lifter.pop();
            lifter.push(Expr::Typeof(Box::new(e)));
        }
        0x80 | 0x86 => emit_coerce(lifter, lifter.multiname(ops.first().copied().unwrap_or(0))),
        0x70 | 0x85 => emit_coerce(lifter, "String".to_owned()),
        0x73 => emit_coerce(lifter, "int".to_owned()),
        0x74 => emit_coerce(lifter, "uint".to_owned()),
        0x75 => emit_coerce(lifter, "Number".to_owned()),
        0x76 => emit_coerce(lifter, "Boolean".to_owned()),
        0x0C..=0x1A => emit_branch(lifter, line, next_off, end_off),
        0x1B => emit_switch(lifter, line, next_off, end_off),
        0x08 | 0x1C | 0x30 => {
            let _ = lifter.pop();
        }
        _ => {}
    }
}

fn local_expr(slot: i64, _names: &LocalNames) -> Expr {
    if slot <= 0 {
        Expr::This
    } else {
        Expr::Local(slot as u32)
    }
}

fn emit_setlocal(lifter: &mut Lifter<'_>, slot: i64) {
    let value: Expr = lifter.pop();
    let target: Expr = local_expr(slot, lifter.names);
    lifter.statements.push(Stmt::Assign { target, value });
}

fn emit_getproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let property: String = lifter.multiname(mn_idx);
    let object: Expr = lifter.pop();
    if property == "[name]" {
        let index: Expr = lifter.pop();
        let _ = index;
    }
    lifter.push(Expr::Get {
        object: Box::new(object),
        property,
    });
}

fn emit_getslot(lifter: &mut Lifter<'_>, slot: i64) {
    let object: Expr = lifter.pop();
    lifter.push(Expr::Get {
        object: Box::new(object),
        property: format!("slot{slot}"),
    });
}

fn emit_setproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let value: Expr = lifter.pop();
    let property: String = lifter.multiname(mn_idx);
    let object: Expr = lifter.pop();
    lifter.statements.push(Stmt::AssignProperty {
        object,
        property,
        value,
    });
}

fn emit_setslot(lifter: &mut Lifter<'_>, slot: i64) {
    let value: Expr = lifter.pop();
    let object: Expr = lifter.pop();
    lifter.statements.push(Stmt::AssignProperty {
        object,
        property: format!("slot{slot}"),
        value,
    });
}

/// True when `callee` is the lexical-scope object produced by a preceding
/// `findpropstrict`/`findproperty`/`getlex` for the same multiname, i.e. the
/// `findprop name; callprop name` idiom that should collapse to a bare call.
fn lex_receiver_matches(callee: &Expr, property: &str) -> bool {
    matches!(callee, Expr::Lex(s) if s == property)
}

fn emit_call(lifter: &mut Lifter<'_>, ops: &[i64], void: bool) {
    let mn_idx: i64 = ops.first().copied().unwrap_or(0);
    let argc: usize = ops.get(1).copied().unwrap_or(0).max(0) as usize;
    let property: String = lifter.multiname(mn_idx);
    let args: Vec<Expr> = lifter.pop_n(argc);
    let callee: Expr = lifter.pop();
    let call: Expr = if lex_receiver_matches(&callee, &property) {
        Expr::Call {
            callee: Box::new(Expr::Name(String::new())),
            property,
            args,
        }
    } else {
        Expr::Call {
            callee: Box::new(callee),
            property,
            args,
        }
    };
    if void {
        lifter.statements.push(Stmt::Expression(call));
    } else {
        lifter.push(call);
    }
}

fn emit_callfn(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let argc: usize = ops.get(1).copied().unwrap_or(0).max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(argc);
    let _receiver: Expr = lifter.pop();
    let callee: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(callee),
        property: String::new(),
        args,
    });
}

fn emit_constructprop(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let mn_idx: i64 = ops.first().copied().unwrap_or(0);
    let argc: usize = ops.get(1).copied().unwrap_or(0).max(0) as usize;
    let property: String = lifter.multiname(mn_idx);
    let args: Vec<Expr> = lifter.pop_n(argc);
    let callee: Expr = lifter.pop();
    let callee: Expr = if lex_receiver_matches(&callee, &property) {
        Expr::Name(String::new())
    } else {
        callee
    };
    lifter.push(Expr::Construct {
        callee: Box::new(callee),
        property,
        args,
    });
}

fn emit_construct(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let argc: usize = ops.first().copied().unwrap_or(0).max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(argc);
    let ty: Expr = lifter.pop();
    lifter.push(Expr::New {
        ty: Box::new(ty),
        args,
    });
}

fn emit_constructsuper(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let argc: usize = ops.first().copied().unwrap_or(0).max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(argc);
    let _obj: Expr = lifter.pop();
    lifter.statements.push(Stmt::Expression(Expr::Call {
        callee: Box::new(Expr::Name("super".to_owned())),
        property: String::new(),
        args,
    }));
}

fn emit_newarray(lifter: &mut Lifter<'_>, count: i64) {
    let n: usize = count.max(0) as usize;
    let items: Vec<Expr> = lifter.pop_n(n);
    lifter.push(Expr::Array(items));
}

fn emit_newobject(lifter: &mut Lifter<'_>, count: i64) {
    let n: usize = count.max(0) as usize;
    let flat: Vec<Expr> = lifter.pop_n(n * 2);
    let mut pairs: Vec<(Expr, Expr)> = Vec::with_capacity(n);
    let mut it = flat.into_iter();
    while let (Some(k), Some(v)) = (it.next(), it.next()) {
        pairs.push((k, v));
    }
    lifter.push(Expr::Object(pairs));
}

fn emit_unary(lifter: &mut Lifter<'_>, op: &'static str) {
    let operand: Expr = lifter.pop();
    lifter.push(Expr::Unary {
        op,
        operand: Box::new(operand),
    });
}

fn emit_postfix(lifter: &mut Lifter<'_>, op: &'static str) {
    let operand: Expr = lifter.pop();
    lifter.push(Expr::Binary {
        op: if op == "++" { "+" } else { "-" },
        lhs: Box::new(operand),
        rhs: Box::new(Expr::IntLit(1)),
    });
}

fn emit_coerce(lifter: &mut Lifter<'_>, ty: String) {
    let operand: Expr = lifter.pop();
    lifter.push(Expr::Coerce {
        ty,
        operand: Box::new(operand),
    });
}

fn emit_branch(lifter: &mut Lifter<'_>, line: &DisasmLine, next_off: usize, end_off: usize) {
    let after: usize = if next_off == 0 { end_off } else { next_off };
    let rel: i64 = line.operands.first().copied().unwrap_or(0);
    let target: usize = (after as i64 + rel).max(0) as usize;
    match line.opcode {
        0x10 => lifter.statements.push(Stmt::Jump {
            target_label: target,
        }),
        0x11 => {
            let cond: Expr = lifter.pop();
            lifter.statements.push(Stmt::If {
                cond,
                target_label: target,
            });
        }
        0x12 => {
            let cond: Expr = lifter.pop();
            lifter.statements.push(Stmt::If {
                cond: Expr::Unary {
                    op: "!",
                    operand: Box::new(cond),
                },
                target_label: target,
            });
        }
        other => {
            if let Some(cmp) = compare_branch_op(other) {
                let rhs: Expr = lifter.pop();
                let lhs: Expr = lifter.pop();
                lifter.statements.push(Stmt::If {
                    cond: Expr::Binary {
                        op: cmp,
                        lhs: Box::new(lhs),
                        rhs: Box::new(rhs),
                    },
                    target_label: target,
                });
            }
        }
    }
}

fn emit_switch(lifter: &mut Lifter<'_>, line: &DisasmLine, _next_off: usize, _end_off: usize) {
    let selector: Expr = lifter.pop();
    let cases: usize = line.operands.get(1).copied().unwrap_or(0).max(0) as usize;
    lifter.statements.push(Stmt::Switch { selector, cases });
}

fn expr_has_effect(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Call { .. } | Expr::Construct { .. } | Expr::New { .. }
    )
}

/// Logically negate a recovered branch condition for `if`-block structuring.
/// Comparison operators flip to their complement; everything else is wrapped
/// in `!(...)` (rendered without the redundant outer parens for unary `!`).
fn negate(cond: Expr) -> Expr {
    if let Expr::Binary { op, lhs, rhs } = &cond {
        let flipped: Option<&'static str> = match *op {
            "==" => Some("!="),
            "!=" => Some("=="),
            "===" => Some("!=="),
            "!==" => Some("==="),
            "<" => Some(">="),
            "<=" => Some(">"),
            ">" => Some("<="),
            ">=" => Some("<"),
            _ => None,
        };
        if let Some(new_op) = flipped {
            return Expr::Binary {
                op: new_op,
                lhs: lhs.clone(),
                rhs: rhs.clone(),
            };
        }
    }
    if let Expr::Unary { op: "!", operand } = cond {
        return *operand;
    }
    Expr::Unary {
        op: "!",
        operand: Box::new(cond),
    }
}

/// True when `label` is referenced by exactly one `If`/`Jump` in `stmts`.
/// Single-entry forward branches are the only ones safe to fold into a block.
fn label_ref_count(stmts: &[Stmt], label: usize) -> usize {
    stmts
        .iter()
        .filter(|s: &&Stmt| match s {
            Stmt::If { target_label, .. } | Stmt::Jump { target_label } => *target_label == label,
            _ => false,
        })
        .count()
}

/// Conservatively re-structure the canonical forward conditional skip
/// `if (cond) goto L; <body>; L:` into `if (!cond) { <body> }`.
///
/// Strict guards: the matching `Label(L)` must appear later at the same nesting
/// level, `L` must be referenced exactly once (single entry), and the spanned
/// body must contain no labels and no jumps/ifs that escape the span. Anything
/// that fails a guard is left as labeled-goto pseudocode, so the transform
/// never reorders or drops a statement.
fn structure_if_blocks(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let mut i: usize = 0;
    while i < stmts.len() {
        if let Stmt::If { cond, target_label } = &stmts[i] {
            let label: usize = *target_label;
            if label_ref_count(&stmts, label) == 1
                && let Some(end_rel) = stmts[i + 1..]
                    .iter()
                    .position(|s: &Stmt| matches!(s, Stmt::Label(l) if *l == label))
            {
                let body_slice: &[Stmt] = &stmts[i + 1..i + 1 + end_rel];
                let body_is_clean: bool = !body_slice.iter().any(|s: &Stmt| {
                    matches!(
                        s,
                        Stmt::Label(_) | Stmt::Jump { .. } | Stmt::If { .. } | Stmt::IfBlock { .. }
                    )
                });
                if body_is_clean && !body_slice.is_empty() {
                    let cond: Expr = negate(cond.clone());
                    let body: Vec<Stmt> = body_slice.to_vec();
                    out.push(Stmt::IfBlock { cond, body });
                    i = i + 1 + end_rel + 1;
                    continue;
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

/// Lift one method body into a sequence of recovered statements by abstractly
/// interpreting the AVM2 operand stack. `info` supplies recovered param names
/// for local-slot naming.
pub fn lift_body(
    abc: &AbcFile,
    body: &MethodBody,
    info: Option<&MethodInfo>,
) -> Result<LiftedBody> {
    let lines: Vec<DisasmLine> = disasm(&body.code)?;
    let labels: BTreeSet<usize> = collect_labels(&lines, &body.exceptions);
    let names: LocalNames = local_names_for(abc, info);
    let next_offset: BTreeMap<usize, usize> = lines
        .windows(2)
        .map(|w: &[DisasmLine]| (w[0].offset, w[1].offset))
        .collect();
    let end_off: usize = lines.last().map_or(0, |l: &DisasmLine| {
        next_offset.get(&l.offset).copied().unwrap_or(l.offset + 1)
    });
    let mut lifter: Lifter<'_> = Lifter {
        abc,
        stack: Vec::new(),
        statements: Vec::new(),
        names: &names,
    };
    for line in &lines {
        if labels.contains(&line.offset) {
            lifter.statements.push(Stmt::Label(line.offset));
        }
        let next_off: usize = next_offset.get(&line.offset).copied().unwrap_or(end_off);
        step(&mut lifter, line, next_off, end_off);
    }
    let statements: Vec<Stmt> = structure_if_blocks(lifter.statements);
    let recovered: bool = statements
        .iter()
        .any(|s: &Stmt| matches!(s, Stmt::Return(_) | Stmt::Throw(_)));
    Ok(LiftedBody {
        statements,
        recovered,
    })
}

/// Render a lifted body to indented AS3 pseudocode. `indent` is the leading
/// whitespace applied to each statement line.
pub fn render_body(lifted: &LiftedBody, names: &LocalNames, indent: &str) -> String {
    let mut out: String = String::new();
    for stmt in &lifted.statements {
        render_stmt(&mut out, stmt, names, indent);
    }
    out
}

fn render_stmt(out: &mut String, stmt: &Stmt, names: &LocalNames, indent: &str) {
    match stmt {
        Stmt::Assign { target, value } => {
            let _ = writeln!(
                out,
                "{indent}{} = {};",
                target.render(names),
                value.render(names)
            );
        }
        Stmt::AssignProperty {
            object,
            property,
            value,
        } => {
            let recv: String = object.render(names);
            let lhs: String = if recv == "this" {
                format!("this.{property}")
            } else {
                format!("{recv}.{property}")
            };
            let _ = writeln!(out, "{indent}{lhs} = {};", value.render(names));
        }
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => {
            let _ = writeln!(
                out,
                "{indent}{}[{}] = {};",
                object.render(names),
                index.render(names),
                value.render(names)
            );
        }
        Stmt::Expression(e) => {
            let _ = writeln!(out, "{indent}{};", e.render(names));
        }
        Stmt::Return(Some(e)) => {
            let _ = writeln!(out, "{indent}return {};", e.render(names));
        }
        Stmt::Return(None) => {
            let _ = writeln!(out, "{indent}return;");
        }
        Stmt::Throw(e) => {
            let _ = writeln!(out, "{indent}throw {};", e.render(names));
        }
        Stmt::If { cond, target_label } => {
            let _ = writeln!(
                out,
                "{indent}if ({}) goto L{target_label};",
                cond.render(names)
            );
        }
        Stmt::Jump { target_label } => {
            let _ = writeln!(out, "{indent}goto L{target_label};");
        }
        Stmt::Label(off) => {
            let _ = writeln!(out, "{indent}L{off}:");
        }
        Stmt::Switch { selector, cases } => {
            let _ = writeln!(
                out,
                "{indent}switch ({}) {{ /* {cases} cases */ }}",
                selector.render(names)
            );
        }
        Stmt::IfBlock { cond, body } => {
            let _ = writeln!(out, "{indent}if ({}) {{", cond.render(names));
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            let _ = writeln!(out, "{indent}}}");
        }
        Stmt::Comment(c) => {
            let _ = writeln!(out, "{indent}// {c}");
        }
    }
}

/// Build the `LocalNames` table a renderer needs for a given method.
#[must_use]
pub fn local_names_for(abc: &AbcFile, info: Option<&MethodInfo>) -> LocalNames {
    let param_names: Vec<String> = info.map_or_else(Vec::new, |mi: &MethodInfo| {
        mi.param_names
            .iter()
            .map(|&idx: &u32| abc.cpool.string_at(idx).unwrap_or("").to_owned())
            .collect()
    });
    let param_count: usize = info.map_or(0, |mi: &MethodInfo| mi.param_types.len());
    LocalNames {
        param_names,
        param_count,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::abc::ConstantPool;

    fn names() -> LocalNames {
        LocalNames {
            param_names: Vec::new(),
            param_count: 0,
        }
    }

    #[test]
    fn render_string_escapes() {
        assert_eq!(render_string_lit("a\"b"), "\"a\\\"b\"");
        assert_eq!(render_string_lit("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn binary_fold_renders_infix() {
        let e: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::IntLit(1)),
            rhs: Box::new(Expr::IntLit(2)),
        };
        assert_eq!(e.render(&names()), "(1 + 2)");
    }

    #[test]
    fn call_on_this_drops_receiver() {
        let e: Expr = Expr::Call {
            callee: Box::new(Expr::This),
            property: "trace".to_owned(),
            args: vec![Expr::StringLit("hi".to_owned())],
        };
        assert_eq!(e.render(&names()), "trace(\"hi\")");
    }

    #[test]
    fn empty_body_lifts_to_no_statements() {
        let abc: AbcFile = AbcFile {
            minor: 16,
            major: 46,
            cpool: ConstantPool::default(),
            methods: Vec::new(),
            metadata_count: 0,
            instances: Vec::new(),
            classes: Vec::new(),
            scripts: Vec::new(),
            method_bodies: Vec::new(),
        };
        let body: MethodBody = MethodBody {
            method: 0,
            max_stack: 0,
            local_count: 1,
            init_scope_depth: 0,
            max_scope_depth: 0,
            code: vec![0x47],
            exceptions: Vec::new(),
            traits: Vec::new(),
        };
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(lifted.recovered);
        assert_eq!(lifted.statements.len(), 1);
        assert!(matches!(lifted.statements[0], Stmt::Return(None)));
    }
}
