use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::abc::{AbcFile, DisasmLine, ExceptionInfo, MethodBody, MethodInfo, Multiname, disasm};
use crate::debug::{dbg_enabled, dbg_kv, dbg_line};
use crate::error::Result;

fn push_format(out: &mut String, args: std::fmt::Arguments<'_>) {
    let result: std::result::Result<(), std::fmt::Error> = std::fmt::write(out, args);
    if let Err(error) = result {
        unreachable!("string formatting failed: {error}");
    }
}

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
    Update {
        op: &'static str,
        operand: Box<Self>,
        postfix: bool,
    },
    Binary {
        op: &'static str,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Ternary {
        cond: Box<Self>,
        then_value: Box<Self>,
        else_value: Box<Self>,
    },
    Coerce {
        ty: String,
        operand: Box<Self>,
    },
    Typeof(Box<Self>),
    Delete {
        object: Box<Self>,
        property: String,
    },
    Descendants {
        object: Box<Self>,
        property: String,
    },
    Applied {
        base: Box<Self>,
        args: Vec<Self>,
    },
    IsType {
        operand: Box<Self>,
        ty: Box<Self>,
    },
    AsType {
        operand: Box<Self>,
        ty: Box<Self>,
    },
    Closure(u32),
    ScopeObject,
    CaughtException,
    Phi {
        block: usize,
        slot: usize,
    },
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
            Self::Unary { op, operand } => {
                let inner: String = operand.render(names);
                if matches!(*op, "+" | "-") && inner.starts_with(*op) {
                    format!("{op}({inner})")
                } else {
                    format!("{op}{inner}")
                }
            }
            Self::Update {
                op,
                operand,
                postfix,
            } => {
                let inner: String = operand.render(names);
                if *postfix {
                    format!("{inner}{op}")
                } else {
                    format!("{op}{inner}")
                }
            }
            Self::Binary { op, lhs, rhs } => {
                format!("({} {} {})", lhs.render(names), op, rhs.render(names))
            }
            Self::Ternary {
                cond,
                then_value,
                else_value,
            } => format!(
                "({} ? {} : {})",
                cond.render(names),
                then_value.render(names),
                else_value.render(names)
            ),
            Self::Coerce { ty, operand } => {
                if ty == "*" || ty.is_empty() {
                    operand.render(names)
                } else {
                    format!("{}({})", ty, operand.render(names))
                }
            }
            Self::Typeof(e) => format!("typeof({})", e.render(names)),
            Self::Delete { object, property } => {
                format!("delete {}.{}", object.render(names), property)
            }
            Self::Descendants { object, property } => {
                format!("{}..{}", object.render(names), property)
            }
            Self::Applied { base, args } => {
                format!("{}.<{}>", base.render(names), render_args(args, names))
            }
            Self::IsType { operand, ty } => {
                format!("({} is {})", operand.render(names), ty.render(names))
            }
            Self::AsType { operand, ty } => {
                format!("({} as {})", operand.render(names), ty.render(names))
            }
            Self::Closure(idx) => format!("function() {{ /* closure method #{idx} */ }}"),
            Self::ScopeObject => String::new(),
            Self::CaughtException => "$exc".to_owned(),
            Self::Phi { block, slot } => format!("phi{block}_{slot}"),
            Self::Opaque(label) => format!("/* {label} */"),
        }
    }
}

const MAX_DUP_EXPR_NODES: usize = 1024;

const MAX_STRUCTURE_DEPTH: usize = 256;

fn expr_node_count_capped(e: &Expr, cap: usize) -> usize {
    fn walk(e: &Expr, cap: usize, acc: &mut usize) {
        if *acc >= cap {
            return;
        }
        *acc = acc.saturating_add(1);
        match e {
            Expr::Binary { lhs, rhs, .. }
            | Expr::Index {
                object: lhs,
                index: rhs,
            } => {
                walk(lhs, cap, acc);
                walk(rhs, cap, acc);
            }
            Expr::Unary { operand: value, .. }
            | Expr::Update { operand: value, .. }
            | Expr::Coerce { operand: value, .. }
            | Expr::Typeof(value)
            | Expr::Get { object: value, .. }
            | Expr::Delete { object: value, .. }
            | Expr::Descendants { object: value, .. } => walk(value, cap, acc),
            Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
                walk(operand, cap, acc);
                walk(ty, cap, acc);
            }
            Expr::Ternary {
                cond,
                then_value,
                else_value,
            } => {
                walk(cond, cap, acc);
                walk(then_value, cap, acc);
                walk(else_value, cap, acc);
            }
            Expr::Call { callee, args, .. } | Expr::Construct { callee, args, .. } => {
                walk(callee, cap, acc);
                for a in args {
                    walk(a, cap, acc);
                }
            }
            Expr::New { ty, args } => {
                walk(ty, cap, acc);
                for a in args {
                    walk(a, cap, acc);
                }
            }
            Expr::Applied { base, args } => {
                walk(base, cap, acc);
                for a in args {
                    walk(a, cap, acc);
                }
            }
            Expr::Array(items) => {
                for el in items {
                    walk(el, cap, acc);
                }
            }
            Expr::Object(pairs) => {
                for (k, v) in pairs {
                    walk(k, cap, acc);
                    walk(v, cap, acc);
                }
            }
            Expr::This
            | Expr::Local(_)
            | Expr::Param(_)
            | Expr::IntLit(_)
            | Expr::UintLit(_)
            | Expr::DoubleLit(_)
            | Expr::StringLit(_)
            | Expr::BoolLit(_)
            | Expr::Null
            | Expr::Undefined
            | Expr::NaN
            | Expr::Name(_)
            | Expr::Lex(_)
            | Expr::Closure(_)
            | Expr::ScopeObject
            | Expr::CaughtException
            | Expr::Phi { .. }
            | Expr::Opaque(_) => {}
        }
    }
    let mut acc: usize = 0;
    walk(e, cap, &mut acc);
    acc
}

fn dup_clone(e: &Expr) -> Expr {
    if expr_node_count_capped(e, MAX_DUP_EXPR_NODES) >= MAX_DUP_EXPR_NODES {
        Expr::Opaque("?")
    } else {
        e.clone()
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
    } else if v == 0.0 {
        if v.is_sign_negative() {
            "-0".to_owned()
        } else {
            "0".to_owned()
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
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            other if (other as u32) < 0x20 => {
                let code: u32 = other as u32;
                out.push_str("\\x");
                out.push(char::from_digit(code >> 4, 16).unwrap_or('0'));
                out.push(char::from_digit(code & 0x0F, 16).unwrap_or('0'));
            }
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

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
        case_labels: Vec<usize>,
        default_label: usize,
    },
    StructuredSwitch {
        selector: Expr,
        cases: Vec<SwitchCase>,
    },
    IfBlock {
        cond: Expr,
        body: Vec<Self>,
    },
    IfElse {
        cond: Expr,
        then_body: Vec<Self>,
        else_body: Vec<Self>,
    },
    While {
        cond: Expr,
        body: Vec<Self>,
    },
    DoWhile {
        cond: Expr,
        body: Vec<Self>,
    },
    For {
        init: Box<Self>,
        cond: Expr,
        update: Box<Self>,
        body: Vec<Self>,
    },
    ForEach {
        var: Expr,
        collection: Expr,
        body: Vec<Self>,
    },
    ForIn {
        var: Expr,
        collection: Expr,
        body: Vec<Self>,
    },
    Try {
        body: Vec<Self>,
        catches: Vec<CatchClause>,
    },
    With {
        object: Expr,
        body: Vec<Self>,
    },
    Break,
    Continue,
    Comment(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct CatchClause {
    pub var_name: String,
    pub type_name: String,
    pub body: Vec<Stmt>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CaseLabel {
    Value(i64),
    Expr(Expr),
    Default,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SwitchCase {
    pub labels: Vec<CaseLabel>,
    pub body: Vec<Stmt>,
    pub breaks: bool,
}

#[derive(Debug, Clone)]
pub struct LiftedBody {
    pub statements: Vec<Stmt>,
    pub structurally_recovered: bool,
    pub fully_structured: bool,
    pub reached_terminator: bool,
    pub dropped_opcodes: Vec<u8>,
    pub opaque_operands: usize,
}

impl LiftedBody {
    #[must_use]
    pub fn fidelity_warning(&self) -> Option<String> {
        if self.structurally_recovered {
            return None;
        }
        let mut reasons: Vec<String> = Vec::new();
        if !self.dropped_opcodes.is_empty() {
            let mut codes: Vec<u8> = self.dropped_opcodes.clone();
            codes.sort_unstable();
            codes.dedup();
            let hex: String = codes
                .iter()
                .map(|c: &u8| format!("0x{c:02X}"))
                .collect::<Vec<String>>()
                .join(", ");
            reasons.push(format!("{} unmodelled opcode(s): {hex}", codes.len()));
        }
        if self.opaque_operands > 0 {
            reasons.push(format!("{} fabricated operand(s)", self.opaque_operands));
        }
        if !self.reached_terminator {
            reasons.push("no return/throw terminator reached".to_owned());
        }
        if !self.fully_structured {
            reasons.push("residual goto/branch graph not fully restructured".to_owned());
        }
        if reasons.is_empty() {
            reasons.push("partial recovery".to_owned());
        }
        Some(format!("partial recovery: {}", reasons.join("; ")))
    }
}

#[derive(Debug, Clone, PartialEq)]
struct ScopeEntry {
    object: Expr,
    is_with: bool,
    identity: usize,
}

fn scope_node_count_capped(entries: &[ScopeEntry], cap: usize) -> usize {
    entries
        .iter()
        .fold(0usize, |total: usize, entry: &ScopeEntry| {
            if total > cap {
                return total;
            }
            let nodes: usize =
                expr_node_count_capped(&entry.object, MAX_DUP_EXPR_NODES.saturating_add(1));
            if nodes > MAX_DUP_EXPR_NODES {
                return cap.saturating_add(1);
            }
            total.saturating_add(nodes)
        })
}

#[derive(Debug, Clone)]
struct WithRegion {
    open_stmt: usize,
    close_stmt: usize,
    object: Expr,
}

const OP_POP: u8 = 0x29;
const OP_DUP: u8 = 0x2A;
const OP_IFTRUE: u8 = 0x11;
const OP_IFFALSE: u8 = 0x12;

const fn is_setlocal(op: u8) -> bool {
    matches!(op, 0x63 | 0xD4 | 0xD5 | 0xD6 | 0xD7)
}

#[derive(Debug, Default)]
struct Idioms {
    dup_backed_setlocals: BTreeSet<usize>,
    short_circuit_branches: BTreeMap<usize, &'static str>,
    short_circuit_discards: BTreeSet<usize>,
    defaulted_short_circuits: BTreeSet<usize>,
}

fn is_conditional_branch(op: u8) -> bool {
    matches!(op, OP_IFTRUE | OP_IFFALSE) || compare_branch_op(op).is_some()
}

fn detect_idioms(lines: &[DisasmLine]) -> Idioms {
    let mut out: Idioms = Idioms::default();
    for pair in lines.windows(2) {
        if pair[0].opcode == OP_DUP && is_setlocal(pair[1].opcode) {
            out.dup_backed_setlocals.insert(pair[1].offset);
        }
        if pair[1].opcode == OP_POP && is_conditional_branch(pair[0].opcode) {
            out.defaulted_short_circuits.insert(pair[0].offset);
        }
    }
    for triple in lines.windows(3) {
        if triple[0].opcode != OP_DUP || triple[2].opcode != OP_POP {
            continue;
        }
        let op: &'static str = match triple[1].opcode {
            OP_IFTRUE => "||",
            OP_IFFALSE => "&&",
            _ => continue,
        };
        out.short_circuit_branches.insert(triple[1].offset, op);
        out.short_circuit_discards.insert(triple[2].offset);
    }
    out
}

#[derive(Debug)]
struct ShortCircuit {
    target: usize,
    op: &'static str,
    lhs: Expr,
    join_height: usize,
    branch_index: usize,
    discard_index: Option<usize>,
}

#[derive(Debug, Clone, Copy)]
enum WrittenLocation<'a> {
    Property(&'a str),
    Element,
}

fn expr_reads_location(e: &Expr, written: WrittenLocation<'_>) -> bool {
    match e {
        Expr::Get { object, property }
        | Expr::Delete { object, property }
        | Expr::Descendants { object, property } => {
            matches!(written, WrittenLocation::Property(name) if name == property)
                || expr_reads_location(object, written)
        }
        Expr::Name(name) | Expr::Lex(name) => {
            matches!(written, WrittenLocation::Property(target) if target == name)
        }
        Expr::Index { object, index } => {
            matches!(written, WrittenLocation::Element)
                || expr_reads_location(object, written)
                || expr_reads_location(index, written)
        }
        Expr::Unary { operand, .. }
        | Expr::Update { operand, .. }
        | Expr::Coerce { operand, .. }
        | Expr::Typeof(operand) => expr_reads_location(operand, written),
        Expr::Binary { lhs, rhs, .. } => {
            expr_reads_location(lhs, written) || expr_reads_location(rhs, written)
        }
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => {
            expr_reads_location(cond, written)
                || expr_reads_location(then_value, written)
                || expr_reads_location(else_value, written)
        }
        Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
            expr_reads_location(operand, written) || expr_reads_location(ty, written)
        }
        Expr::Call { callee, args, .. } | Expr::Construct { callee, args, .. } => {
            expr_reads_location(callee, written)
                || args.iter().any(|a: &Expr| expr_reads_location(a, written))
        }
        Expr::New { ty: base, args } | Expr::Applied { base, args } => {
            expr_reads_location(base, written)
                || args.iter().any(|a: &Expr| expr_reads_location(a, written))
        }
        Expr::Array(items) => items
            .iter()
            .any(|item: &Expr| expr_reads_location(item, written)),
        Expr::Object(pairs) => pairs.iter().any(|(key, value): &(Expr, Expr)| {
            expr_reads_location(key, written) || expr_reads_location(value, written)
        }),
        _ => false,
    }
}

#[derive(Debug)]
struct BranchMark {
    stmt_index: usize,
    join_height: usize,
    else_label: usize,
    cond: Expr,
}

struct Lifter<'a> {
    abc: &'a AbcFile,
    stack: Vec<Expr>,
    statements: Vec<Stmt>,
    names: &'a LocalNames,
    slot_names: &'a BTreeMap<u32, String>,
    dropped_opcodes: Vec<u8>,
    opaque_operands: usize,
    scope_stack: Vec<ScopeEntry>,
    with_regions: Vec<WithRegion>,
    idioms: Idioms,
    short_circuits: Vec<ShortCircuit>,
    branch_marks: Vec<BranchMark>,
    hoisted_temporaries: u32,
    incoming_stacks: BTreeMap<usize, Vec<Vec<Expr>>>,
    incoming_scopes: BTreeMap<usize, Vec<Vec<ScopeEntry>>>,
    untracked_stack_entries: BTreeSet<usize>,
    untracked_scope_entries: BTreeSet<usize>,
    tracked_stack_nodes: usize,
    tracked_scope_nodes: usize,
    stack_tracking_exhausted: bool,
    scope_tracking_exhausted: bool,
    switch_direction_refusals: BTreeSet<usize>,
    switch_budget_refusals: BTreeSet<usize>,
}

impl Lifter<'_> {
    fn record_edge_stack(&mut self, target: usize) {
        self.record_operand_edge(target);
        self.record_scope_edge(target);
    }

    fn record_operand_edge(&mut self, target: usize) {
        const MAX_TRACKED_PREDECESSORS: usize = 256;
        const MAX_TRACKED_STACK_NODES: usize = 65_536;
        if self.stack_tracking_exhausted {
            return;
        }
        if self.stack.len() > STACK_SENTINEL_DEPTH || self.untracked_stack_entries.contains(&target)
        {
            self.untracked_stack_entries.insert(target);
            self.incoming_stacks.remove(&target);
            return;
        }
        if self
            .incoming_stacks
            .get(&target)
            .is_some_and(|entries: &Vec<Vec<Expr>>| {
                entries.iter().any(|entry: &Vec<Expr>| entry == &self.stack)
            })
        {
            return;
        }
        if self
            .incoming_stacks
            .get(&target)
            .is_some_and(|entries: &Vec<Vec<Expr>>| entries.len() == MAX_TRACKED_PREDECESSORS)
        {
            self.untracked_stack_entries.insert(target);
            self.incoming_stacks.remove(&target);
            return;
        }
        let remaining: usize = MAX_TRACKED_STACK_NODES.saturating_sub(self.tracked_stack_nodes);
        let nodes: usize = self
            .stack
            .iter()
            .fold(0usize, |total: usize, value: &Expr| {
                total.saturating_add(expr_node_count_capped(value, remaining.saturating_add(1)))
            });
        if nodes > remaining {
            self.incoming_stacks.clear();
            self.untracked_stack_entries.clear();
            self.stack_tracking_exhausted = true;
            return;
        }
        self.tracked_stack_nodes = self.tracked_stack_nodes.saturating_add(nodes);
        self.incoming_stacks
            .entry(target)
            .or_default()
            .push(self.stack.clone());
    }

    fn record_scope_edge(&mut self, target: usize) {
        const MAX_TRACKED_PREDECESSORS: usize = 256;
        const MAX_TRACKED_SCOPE_NODES: usize = 65_536;
        if self.scope_tracking_exhausted {
            self.untracked_scope_entries.insert(target);
            self.incoming_scopes.remove(&target);
            return;
        }
        if self.scope_stack.len() > STACK_SENTINEL_DEPTH
            || self.untracked_scope_entries.contains(&target)
        {
            self.untracked_scope_entries.insert(target);
            self.incoming_scopes.remove(&target);
            return;
        }
        let remaining: usize = MAX_TRACKED_SCOPE_NODES.saturating_sub(self.tracked_scope_nodes);
        let nodes: usize = scope_node_count_capped(&self.scope_stack, remaining);
        if nodes > remaining {
            self.untracked_scope_entries
                .extend(self.incoming_scopes.keys().copied());
            self.untracked_scope_entries.insert(target);
            self.incoming_scopes.clear();
            self.scope_tracking_exhausted = true;
            return;
        }
        self.tracked_scope_nodes = self.tracked_scope_nodes.saturating_add(nodes);
        if self
            .incoming_scopes
            .get(&target)
            .is_some_and(|entries: &Vec<Vec<ScopeEntry>>| {
                entries
                    .iter()
                    .any(|entry: &Vec<ScopeEntry>| entry == &self.scope_stack)
            })
        {
            return;
        }
        if self
            .incoming_scopes
            .get(&target)
            .is_some_and(|entries: &Vec<Vec<ScopeEntry>>| entries.len() == MAX_TRACKED_PREDECESSORS)
        {
            self.untracked_scope_entries.insert(target);
            self.incoming_scopes.remove(&target);
            return;
        }
        self.incoming_scopes
            .entry(target)
            .or_default()
            .push(self.scope_stack.clone());
    }

    fn nearest_with(&self) -> Option<&Expr> {
        self.scope_stack
            .iter()
            .rev()
            .find(|e: &&ScopeEntry| e.is_with)
            .map(|e: &ScopeEntry| &e.object)
    }
}

impl Lifter<'_> {
    fn hoist_stale_stack_reads(&mut self, written: WrittenLocation<'_>) {
        let stale: Vec<usize> = self
            .stack
            .iter()
            .enumerate()
            .filter(|(_, e): &(usize, &Expr)| expr_reads_location(e, written))
            .map(|(index, _): (usize, &Expr)| index)
            .collect();
        for index in stale {
            let value: Expr = self.stack[index].clone();
            let target: Expr = Expr::Name(format!("_temp{}", self.hoisted_temporaries));
            self.hoisted_temporaries = self.hoisted_temporaries.saturating_add(1);
            self.statements.push(Stmt::Assign {
                target: target.clone(),
                value,
            });
            self.stack[index] = target;
        }
    }

    fn remove_statement(&mut self, index: usize) {
        if index >= self.statements.len() {
            return;
        }
        self.statements.remove(index);
        self.short_circuits
            .retain(|s: &ShortCircuit| s.branch_index < index);
        self.branch_marks
            .retain(|m: &BranchMark| m.stmt_index < index);
    }

    fn short_circuit_resolves(&self, pending: &ShortCircuit) -> bool {
        if self.stack.len() != pending.join_height + 1 {
            return false;
        }
        self.statements
            .iter()
            .enumerate()
            .skip(pending.branch_index + 1)
            .all(|(index, stmt): (usize, &Stmt)| {
                Some(index) == pending.discard_index || matches!(stmt, Stmt::Label(_))
            })
    }

    fn resolve_short_circuits(&mut self, label: usize) -> bool {
        let mut resolved: bool = false;
        while let Some(position) = self
            .short_circuits
            .iter()
            .rposition(|s: &ShortCircuit| s.target == label)
        {
            let pending: ShortCircuit = self.short_circuits.remove(position);
            if !self.short_circuit_resolves(&pending) {
                continue;
            }
            let rhs: Expr = self.pop();
            self.push(Expr::Binary {
                op: pending.op,
                lhs: Box::new(pending.lhs),
                rhs: Box::new(rhs),
            });
            if let Some(discard) = pending.discard_index {
                self.remove_statement(discard);
            }
            self.remove_statement(pending.branch_index);
            resolved = true;
        }
        resolved
    }

    fn resolve_ternary(&mut self, label: usize) -> bool {
        let len: usize = self.statements.len();
        if len < 4 {
            return false;
        }
        let branch_index: usize = len - 4;
        let Some(position): Option<usize> = self
            .branch_marks
            .iter()
            .rposition(|m: &BranchMark| m.stmt_index == branch_index)
        else {
            return false;
        };
        let jump_matches: bool = matches!(
            self.statements[len - 3],
            Stmt::Jump { target_label } if target_label == label
        );
        let else_label: usize = self.branch_marks[position].else_label;
        let else_matches: bool = matches!(
            self.statements[len - 2],
            Stmt::Label(l) if l == else_label
        );
        let end_matches: bool = matches!(self.statements[len - 1], Stmt::Label(l) if l == label);
        let mark_height: usize = self.branch_marks[position].join_height;
        if !jump_matches
            || !else_matches
            || !end_matches
            || else_label == label
            || self.stack.len() != mark_height + 2
        {
            return false;
        }
        let else_value: Expr = self.pop();
        let then_value: Expr = self.pop();
        let cond: Expr = negate(self.branch_marks[position].cond.clone());
        self.push(Expr::Ternary {
            cond: Box::new(cond),
            then_value: Box::new(then_value),
            else_value: Box::new(else_value),
        });
        self.remove_statement(len - 3);
        self.remove_statement(branch_index);
        true
    }

    fn push(&mut self, e: Expr) {
        self.stack.push(e);
    }

    fn pop(&mut self) -> Expr {
        if let Some(e) = self.stack.pop() {
            e
        } else {
            self.opaque_operands += 1;
            Expr::Opaque("?")
        }
    }

    fn synthesized(&mut self, name: String) -> Expr {
        self.opaque_operands = self.opaque_operands.saturating_add(1);
        Expr::Name(name)
    }

    fn operand(&mut self, operands: &[i64], index: usize) -> i64 {
        if let Some(value) = operands.get(index) {
            *value
        } else {
            self.opaque_operands = self.opaque_operands.saturating_add(1);
            0
        }
    }

    fn reconcile_entry_height(
        &mut self,
        offset: usize,
        entry_height: usize,
        is_exc_target: bool,
        replace_values: bool,
    ) {
        if replace_values {
            self.stack = (0..entry_height)
                .map(|slot: usize| {
                    if is_exc_target && slot == 0 {
                        Expr::CaughtException
                    } else {
                        Expr::Phi {
                            block: offset,
                            slot,
                        }
                    }
                })
                .collect();
            return;
        }
        let have: usize = self.stack.len();
        if have >= entry_height {
            return;
        }
        let missing: usize = entry_height - have;
        let mut seeded: Vec<Expr> = Vec::with_capacity(entry_height);
        for slot in 0..missing {
            if is_exc_target && slot == 0 {
                seeded.push(Expr::CaughtException);
            } else {
                seeded.push(Expr::Phi {
                    block: offset,
                    slot,
                });
            }
        }
        seeded.append(&mut self.stack);
        self.stack = seeded;
    }

    fn record_scope_refusal(&mut self, reason: &'static str) {
        self.opaque_operands = self.opaque_operands.saturating_add(1);
        self.statements.push(Stmt::Comment(reason.to_owned()));
    }

    fn mark_scope_conflict(&mut self, reason: &'static str) {
        self.scope_stack.clear();
        self.with_regions
            .retain(|region: &WithRegion| region.close_stmt != region.open_stmt);
        self.record_scope_refusal(reason);
    }

    fn reconcile_scope_entry(
        &mut self,
        offset: usize,
        stack_analysis: &StackAnalysis,
        is_exc_target: bool,
    ) {
        let untracked_entry: bool = self.untracked_scope_entries.remove(&offset);
        let mut entries: Vec<Vec<ScopeEntry>> =
            self.incoming_scopes.remove(&offset).unwrap_or_default();
        if is_exc_target {
            self.scope_stack.clear();
            return;
        }
        if stack_analysis.scope_height_conflicts.contains(&offset)
            || stack_analysis.scope_unreconciled.contains(&offset)
        {
            self.mark_scope_conflict(SCOPE_HEIGHT_CONFLICT_MARKER);
            return;
        }
        let Some(&entry_height): Option<&usize> = stack_analysis.scope_entry_heights.get(&offset)
        else {
            return;
        };
        if stack_analysis.backward_entries.contains(&offset) && entry_height > 0 {
            self.mark_scope_conflict(SCOPE_VALUE_CONFLICT_MARKER);
            return;
        }
        if untracked_entry {
            self.mark_scope_conflict(SCOPE_VALUE_CONFLICT_MARKER);
            return;
        }
        if !stack_analysis.disconnected_entries.contains(&offset) {
            entries.push(self.scope_stack.clone());
        }
        if entries.is_empty() {
            if self.scope_stack.len() == entry_height {
                return;
            }
            self.mark_scope_conflict(SCOPE_HEIGHT_CONFLICT_MARKER);
            return;
        }
        if entries
            .iter()
            .any(|entry: &Vec<ScopeEntry>| entry.len() != entry_height)
        {
            self.mark_scope_conflict(SCOPE_HEIGHT_CONFLICT_MARKER);
            return;
        }
        let first: &Vec<ScopeEntry> = &entries[0];
        if first.iter().any(|entry: &ScopeEntry| entry.is_with)
            || entries.iter().any(|entry: &Vec<ScopeEntry>| entry != first)
        {
            self.mark_scope_conflict(SCOPE_VALUE_CONFLICT_MARKER);
            return;
        }
        self.scope_stack.clone_from(first);
    }

    fn enter_label(&mut self, offset: usize, stack_analysis: &StackAnalysis, is_exc_target: bool) {
        let pending_value_arm: bool = self
            .branch_marks
            .iter()
            .any(|mark: &BranchMark| mark.else_label == offset);
        self.statements.push(Stmt::Label(offset));
        self.reconcile_scope_entry(offset, stack_analysis, is_exc_target);
        if is_exc_target {
            self.stack.clear();
            self.stack.push(Expr::CaughtException);
            self.incoming_stacks.remove(&offset);
            self.untracked_stack_entries.remove(&offset);
            return;
        }
        let resolved_value: bool =
            self.resolve_short_circuits(offset) | self.resolve_ternary(offset);
        if pending_value_arm {
            return;
        }
        if let Some(&height) = stack_analysis.entry_heights.get(&offset) {
            let untracked_entry: bool = self.untracked_stack_entries.remove(&offset);
            if stack_analysis.unreconciled.contains(&offset) {
                self.stack.clear();
                self.opaque_operands = self.opaque_operands.saturating_add(1);
                self.statements
                    .push(Stmt::Comment(STACK_CONFLICT_MARKER.to_owned()));
                self.reconcile_entry_height(offset, height, is_exc_target, true);
                return;
            }
            if stack_analysis.value_joins.contains(&offset)
                && (self.stack_tracking_exhausted || untracked_entry)
            {
                self.statements
                    .push(Stmt::Comment(STACK_CONFLICT_MARKER.to_owned()));
            }
            let entries: Vec<Vec<Expr>> = self.incoming_stacks.remove(&offset).unwrap_or_default();
            let tracked_values: Option<Vec<Expr>> = if resolved_value
                || self.stack_tracking_exhausted
                || untracked_entry
                || !stack_analysis.forward_entries.contains(&offset)
                || !(stack_analysis.switch_entries.contains(&offset)
                    || stack_analysis.value_joins.contains(&offset))
            {
                None
            } else {
                let mut entries: Vec<Vec<Expr>> = entries;
                if !stack_analysis.disconnected_entries.contains(&offset) {
                    entries.push(self.stack.clone());
                }
                if entries.is_empty()
                    || entries
                        .iter()
                        .any(|entry: &Vec<Expr>| entry.len() != height)
                {
                    None
                } else {
                    Some(
                        (0..height)
                            .map(|slot: usize| {
                                let first: &Expr = &entries[0][slot];
                                if entries
                                    .iter()
                                    .all(|entry: &Vec<Expr>| &entry[slot] == first)
                                {
                                    first.clone()
                                } else {
                                    Expr::Phi {
                                        block: offset,
                                        slot,
                                    }
                                }
                            })
                            .collect(),
                    )
                }
            };
            if let Some(values) = tracked_values {
                self.stack = values;
                return;
            }
            let replace_values: bool = !resolved_value
                && (stack_analysis.value_joins.contains(&offset)
                    || stack_analysis.switch_entries.contains(&offset));
            self.reconcile_entry_height(offset, height, is_exc_target, replace_values);
        } else if stack_analysis.unreconciled.contains(&offset) {
            self.stack.clear();
            self.opaque_operands = self.opaque_operands.saturating_add(1);
            self.statements
                .push(Stmt::Comment(STACK_CONFLICT_MARKER.to_owned()));
            if stack_analysis.height_conflicts.contains(&offset) {
                self.statements
                    .push(Stmt::Comment(STACK_HEIGHT_CONFLICT_MARKER.to_owned()));
            }
        } else if stack_analysis.height_conflicts.contains(&offset) {
            self.stack.clear();
            self.opaque_operands = self.opaque_operands.saturating_add(1);
            self.statements
                .push(Stmt::Comment(STACK_HEIGHT_CONFLICT_MARKER.to_owned()));
        }
    }

    fn pop_n(&mut self, n: usize) -> Vec<Expr> {
        const MAX_SYNTHESIZED_OPERANDS: usize = 1024;
        let len: usize = self.stack.len();
        let take: usize = n.min(len);
        let mut out: Vec<Expr> = self.stack.split_off(len - take);
        let target: usize = n.min(len.saturating_add(MAX_SYNTHESIZED_OPERANDS));
        let fill: usize = target.saturating_sub(out.len());
        if fill > 0 {
            self.opaque_operands = self.opaque_operands.saturating_add(fill);
            let mut filled: Vec<Expr> = Vec::with_capacity(target);
            for _ in 0..fill {
                filled.push(Expr::Opaque("?"));
            }
            filled.append(&mut out);
            out = filled;
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

    fn property(&self, idx: i64) -> String {
        if idx <= 0 {
            return String::new();
        }
        self.abc
            .cpool
            .render_multiname_property(idx as u32)
            .unwrap_or_else(|_| format!("mn#{idx}"))
    }

    fn runtime_operands(&self, mn_idx: i64) -> (bool, bool) {
        if mn_idx <= 0 {
            return (false, false);
        }
        self.abc
            .cpool
            .multiname_at(mn_idx as u32)
            .map_or((false, false), Multiname::runtime_operands)
    }

    fn pop_runtime_selector(&mut self, mn_idx: i64, needs_ns: bool, needs_name: bool) -> Expr {
        let name: Option<Expr> = if needs_name { Some(self.pop()) } else { None };
        let ns: Option<Expr> = if needs_ns { Some(self.pop()) } else { None };
        let name_expr: Expr = name.unwrap_or_else(|| Expr::Name(self.property(mn_idx)));
        match ns {
            Some(ns_expr) => Expr::Binary {
                op: "::",
                lhs: Box::new(ns_expr),
                rhs: Box::new(name_expr),
            },
            None => name_expr,
        }
    }

    fn slot_name(&self, slot: i64) -> String {
        if slot > 0
            && let Some(name) = self.slot_names.get(&(slot as u32))
        {
            return name.clone();
        }
        format!("slot{slot}")
    }

    fn class_name(&self, class_idx: i64) -> String {
        if class_idx >= 0
            && let Some(inst) = self.abc.instances.get(class_idx as usize)
            && let Ok(name) = self.abc.cpool.render_multiname(inst.name_index)
        {
            return name;
        }
        format!("class{class_idx}")
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

    fn namespace(&self, idx: i64) -> Expr {
        if idx <= 0 {
            return Expr::Name("AS3".to_owned());
        }
        let uri: String = self
            .abc
            .cpool
            .namespace_uri(idx as u32)
            .unwrap_or("")
            .to_owned();
        if uri.is_empty() {
            let name: &str = self.abc.cpool.namespace_name(idx as u32).unwrap_or("");
            if name.is_empty() || name == "*" {
                return Expr::New {
                    ty: Box::new(Expr::Name("Namespace".to_owned())),
                    args: Vec::new(),
                };
            }
            return Expr::Name(name.to_owned());
        }
        Expr::New {
            ty: Box::new(Expr::Name("Namespace".to_owned())),
            args: vec![Expr::StringLit(uri)],
        }
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

fn relative_target(base: usize, rel: i64) -> usize {
    let magnitude: usize = rel.unsigned_abs().min(usize::MAX as u64) as usize;
    if rel.is_negative() {
        base.saturating_sub(magnitude)
    } else {
        base.saturating_add(magnitude)
    }
}

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
        if matches!(line.opcode, 0x0C..=0x1A) {
            let after: usize = next_offset.get(&line.offset).copied().unwrap_or(end_offset);
            if let Some(rel) = line.operands.first() {
                labels.insert(relative_target(after, *rel));
            }
        }
        if line.opcode == 0x1B {
            if let Some(default_rel) = line.operands.first() {
                labels.insert(relative_target(line.offset, *default_rel));
            }
            for rel in line.operands.get(2..).unwrap_or(&[]) {
                labels.insert(relative_target(line.offset, *rel));
            }
        }
    }
    for exc in exceptions {
        labels.insert(exc.from as usize);
        labels.insert(exc.to as usize);
        labels.insert(exc.target as usize);
    }
    labels
}

const STACK_SENTINEL_DEPTH: usize = 256;
const STACK_CONFLICT_MARKER: &str = "unreconciled stack merge";
const STACK_HEIGHT_CONFLICT_MARKER: &str = "unreconciled stack height";
const SCOPE_HEIGHT_CONFLICT_MARKER: &str = "unreconciled scope height";
const SCOPE_VALUE_CONFLICT_MARKER: &str = "unreconciled scope values";
const SWITCH_DIRECTION_REFUSAL_MARKER: &str = "switch dispatch is backward or mixed";
const SWITCH_ANALYSIS_BUDGET_MARKER: &str = "switch analysis budget exhausted";
const SWITCH_INVALID_TARGET_REFUSAL_MARKER: &str = "switch dispatch has an invalid target";
const SWITCH_MID_ENTRY_REFUSAL_MARKER: &str = "switch dispatch has a mid-region entry";
const SWITCH_IRREDUCIBLE_REFUSAL_MARKER: &str = "switch dispatch region is irreducible";
const SWITCH_EFFECT_REFUSAL_MARKER: &str = "forward dispatch selector or case has effects";
const SWITCH_COMPARISON_REFUSAL_MARKER: &str = "forward dispatch mixes equality semantics";
const MAX_SWITCH_ANALYSIS_FUEL: usize = 65_536;

fn line_stack_delta(scratch: &mut Lifter<'_>, line: &DisasmLine) -> Option<i64> {
    scratch.stack.truncate(STACK_SENTINEL_DEPTH);
    scratch
        .stack
        .resize(STACK_SENTINEL_DEPTH, Expr::Opaque("="));
    if !scratch.statements.is_empty() {
        scratch.statements.clear();
    }
    if !scratch.scope_stack.is_empty() {
        scratch.scope_stack.clear();
    }
    if !scratch.with_regions.is_empty() {
        scratch.with_regions.clear();
    }
    if !scratch.dropped_opcodes.is_empty() {
        scratch.dropped_opcodes.clear();
    }
    scratch.incoming_stacks.clear();
    scratch.incoming_scopes.clear();
    scratch.untracked_stack_entries.clear();
    scratch.untracked_scope_entries.clear();
    scratch.tracked_stack_nodes = 0;
    scratch.tracked_scope_nodes = 0;
    scratch.stack_tracking_exhausted = false;
    scratch.scope_tracking_exhausted = false;
    scratch.opaque_operands = 0;
    step(scratch, line, line.offset + 1, line.offset + 1);
    if scratch.opaque_operands > 0 {
        return None;
    }
    let after: usize = scratch.stack.len();
    Some(after as i64 - STACK_SENTINEL_DEPTH as i64)
}

const fn line_scope_delta(line: &DisasmLine) -> i64 {
    match line.opcode {
        0x1C | 0x30 => 1,
        0x1D => -1,
        _ => 0,
    }
}

fn line_successors(line: &DisasmLine, next_off: usize, end_off: usize) -> Vec<usize> {
    let op: u8 = line.opcode;
    let after: usize = if next_off == 0 { end_off } else { next_off };
    let mut out: Vec<usize> = Vec::new();
    match op {
        0x47 | 0x48 | 0x03 => {}
        0x10 => {
            out.push(relative_target(
                after,
                line.operands.first().copied().unwrap_or(0),
            ));
        }
        0x0C..=0x1A => {
            out.push(relative_target(
                after,
                line.operands.first().copied().unwrap_or(0),
            ));
            out.push(after);
        }
        0x1B => {
            out.push(relative_target(
                line.offset,
                line.operands.first().copied().unwrap_or(0),
            ));
            for rel in line.operands.get(2..).unwrap_or(&[]) {
                out.push(relative_target(line.offset, *rel));
            }
        }
        _ => out.push(after),
    }
    out
}

fn reachable_offsets(
    lines: &[DisasmLine],
    next_offset: &BTreeMap<usize, usize>,
    end_off: usize,
    exceptions: &[ExceptionInfo],
) -> BTreeSet<usize> {
    let valid: BTreeSet<usize> = lines.iter().map(|l: &DisasmLine| l.offset).collect();
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    let mut work: VecDeque<usize> = VecDeque::new();
    if let Some(first) = lines.first() {
        work.push_back(first.offset);
    }
    for exc in exceptions {
        let target: usize = exc.target as usize;
        if valid.contains(&target) {
            work.push_back(target);
        }
    }
    let line_at: BTreeMap<usize, &DisasmLine> =
        lines.iter().map(|l: &DisasmLine| (l.offset, l)).collect();
    while let Some(off) = work.pop_front() {
        if !seen.insert(off) {
            continue;
        }
        let Some(line): Option<&&DisasmLine> = line_at.get(&off) else {
            continue;
        };
        let next_off: usize = next_offset.get(&off).copied().unwrap_or(end_off);
        for target in line_successors(line, next_off, end_off) {
            if valid.contains(&target) {
                work.push_back(target);
            }
        }
    }
    seen
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeightCell {
    Unknown,
    Height(i64),
    Conflict,
}

impl HeightCell {
    fn join(self, other: i64) -> Self {
        match self {
            Self::Unknown => Self::Height(other),
            Self::Height(existing) if existing == other => self,
            Self::Height(_) | Self::Conflict => Self::Conflict,
        }
    }
}

struct StackAnalysis {
    entry_heights: BTreeMap<usize, usize>,
    scope_entry_heights: BTreeMap<usize, usize>,
    value_joins: BTreeSet<usize>,
    switch_entries: BTreeSet<usize>,
    forward_entries: BTreeSet<usize>,
    backward_entries: BTreeSet<usize>,
    disconnected_entries: BTreeSet<usize>,
    unreconciled: BTreeSet<usize>,
    height_conflicts: BTreeSet<usize>,
    scope_unreconciled: BTreeSet<usize>,
    scope_height_conflicts: BTreeSet<usize>,
    switch_direction_refusals: BTreeSet<usize>,
    switch_budget_refusals: BTreeSet<usize>,
}

fn reachable_from_seeds(
    successors: &BTreeMap<usize, Vec<usize>>,
    valid_offsets: &BTreeSet<usize>,
    seeds: impl IntoIterator<Item = usize>,
) -> BTreeSet<usize> {
    let mut reachable: BTreeSet<usize> = BTreeSet::new();
    let mut pending: Vec<usize> = seeds
        .into_iter()
        .filter(|offset: &usize| valid_offsets.contains(offset))
        .collect();
    while let Some(offset) = pending.pop() {
        if !reachable.insert(offset) {
            continue;
        }
        if let Some(targets) = successors.get(&offset) {
            pending.extend(
                targets
                    .iter()
                    .copied()
                    .filter(|target: &usize| valid_offsets.contains(target)),
            );
        }
    }
    reachable
}

struct SwitchAnalysisFuel {
    remaining: usize,
    exhausted: bool,
}

impl SwitchAnalysisFuel {
    fn new() -> Self {
        Self {
            remaining: MAX_SWITCH_ANALYSIS_FUEL,
            exhausted: false,
        }
    }

    fn charge(&mut self, units: usize) -> bool {
        if self.exhausted || units > self.remaining {
            self.remaining = 0;
            self.exhausted = true;
            return false;
        }
        self.remaining -= units;
        true
    }
}

fn reaches_forward_join(
    successors: &BTreeMap<usize, Vec<usize>>,
    start: usize,
    join: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> Option<bool> {
    if !fuel.charge(1) {
        return None;
    }
    let mut pending: Vec<usize> = Vec::with_capacity(1);
    pending.push(start);
    let mut visited: BTreeSet<usize> = BTreeSet::new();
    while let Some(offset) = pending.pop() {
        if !fuel.charge(1) {
            return None;
        }
        if offset == join {
            return Some(true);
        }
        if offset > join {
            continue;
        }
        if !fuel.charge(1) || !visited.insert(offset) {
            if fuel.exhausted {
                return None;
            }
            continue;
        }
        if let Some(targets) = successors.get(&offset) {
            let eligible: usize = targets
                .iter()
                .filter(|target: &&usize| **target <= join)
                .count();
            if !fuel.charge(targets.len()) || !fuel.charge(eligible) {
                return None;
            }
            pending.reserve(eligible);
            pending.extend(
                targets
                    .iter()
                    .copied()
                    .filter(|target: &usize| *target <= join),
            );
        }
    }
    Some(false)
}

fn block_entry_heights(
    abc: &AbcFile,
    lines: &[DisasmLine],
    labels: &BTreeSet<usize>,
    names: &LocalNames,
    slot_names: &BTreeMap<u32, String>,
    exceptions: &[ExceptionInfo],
) -> StackAnalysis {
    if labels.is_empty() {
        return StackAnalysis {
            entry_heights: BTreeMap::new(),
            scope_entry_heights: BTreeMap::new(),
            value_joins: BTreeSet::new(),
            switch_entries: BTreeSet::new(),
            forward_entries: BTreeSet::new(),
            backward_entries: BTreeSet::new(),
            disconnected_entries: BTreeSet::new(),
            unreconciled: BTreeSet::new(),
            height_conflicts: BTreeSet::new(),
            scope_unreconciled: BTreeSet::new(),
            scope_height_conflicts: BTreeSet::new(),
            switch_direction_refusals: BTreeSet::new(),
            switch_budget_refusals: BTreeSet::new(),
        };
    }
    let next_offset: BTreeMap<usize, usize> = lines
        .windows(2)
        .map(|w: &[DisasmLine]| (w[0].offset, w[1].offset))
        .collect();
    let end_off: usize = lines.last().map_or(0, |l: &DisasmLine| {
        next_offset.get(&l.offset).copied().unwrap_or(l.offset + 1)
    });
    let mut scratch: Lifter<'_> = Lifter {
        abc,
        stack: Vec::with_capacity(STACK_SENTINEL_DEPTH + 8),
        statements: Vec::new(),
        names,
        slot_names,
        dropped_opcodes: Vec::new(),
        opaque_operands: 0,
        scope_stack: Vec::new(),
        with_regions: Vec::new(),
        idioms: detect_idioms(lines),
        short_circuits: Vec::new(),
        branch_marks: Vec::new(),
        hoisted_temporaries: 0,
        incoming_stacks: BTreeMap::new(),
        incoming_scopes: BTreeMap::new(),
        untracked_stack_entries: BTreeSet::new(),
        untracked_scope_entries: BTreeSet::new(),
        tracked_stack_nodes: 0,
        tracked_scope_nodes: 0,
        stack_tracking_exhausted: false,
        scope_tracking_exhausted: false,
        switch_direction_refusals: BTreeSet::new(),
        switch_budget_refusals: BTreeSet::new(),
    };
    let mut line_by_offset: BTreeMap<usize, &DisasmLine> = BTreeMap::new();
    let mut succs: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for line in lines {
        line_by_offset.insert(line.offset, line);
        let next_off: usize = next_offset.get(&line.offset).copied().unwrap_or(end_off);
        succs.insert(line.offset, line_successors(line, next_off, end_off));
    }
    let mut deltas: BTreeMap<usize, i64> = BTreeMap::new();
    let valid_offsets: BTreeSet<usize> = lines.iter().map(|l: &DisasmLine| l.offset).collect();
    let exc_targets: BTreeSet<usize> = exceptions
        .iter()
        .map(|exception: &ExceptionInfo| exception.target as usize)
        .collect();
    let mut predecessors: BTreeMap<usize, BTreeSet<usize>> = BTreeMap::new();
    for (source, targets) in &succs {
        for target in targets {
            if valid_offsets.contains(target) {
                predecessors.entry(*target).or_default().insert(*source);
            }
        }
    }
    let mut value_joins: BTreeSet<usize> = BTreeSet::new();
    let normal_reachable: BTreeSet<usize> = reachable_from_seeds(
        &succs,
        &valid_offsets,
        lines.first().map(|line: &DisasmLine| line.offset),
    );
    let handler_reachable: BTreeSet<usize> =
        reachable_from_seeds(&succs, &valid_offsets, exc_targets.iter().copied());
    let exception_origin_joins: BTreeSet<usize> = predecessors
        .iter()
        .filter_map(|(target, sources): (&usize, &BTreeSet<usize>)| {
            let has_normal_only: bool = sources.iter().any(|source: &usize| {
                normal_reachable.contains(source) && !handler_reachable.contains(source)
            });
            let has_handler_only: bool = sources.iter().any(|source: &usize| {
                handler_reachable.contains(source) && !normal_reachable.contains(source)
            });
            (sources.len() > 1 && has_normal_only && has_handler_only).then_some(*target)
        })
        .collect();
    let forward_exception_value_joins: BTreeSet<usize> = exception_origin_joins
        .iter()
        .copied()
        .filter(|target: &usize| {
            predecessors
                .get(target)
                .is_some_and(|sources: &BTreeSet<usize>| {
                    sources.iter().all(|source: &usize| source < target)
                })
        })
        .collect();
    let supported_exception_merge: bool = matches!(exceptions, [exception]
        if exception.from < exception.to
            && exception.to < exception.target
            && valid_offsets.contains(&(exception.from as usize))
            && (valid_offsets.contains(&(exception.to as usize))
                || exception.to as usize == end_off)
            && valid_offsets.contains(&(exception.target as usize))
            && !normal_reachable.contains(&(exception.target as usize)));
    let mut unverifiable_joins: BTreeSet<usize> = if supported_exception_merge {
        value_joins.extend(forward_exception_value_joins.iter().copied());
        exception_origin_joins
            .difference(&forward_exception_value_joins)
            .copied()
            .collect()
    } else {
        exception_origin_joins
    };
    let switch_entries: BTreeSet<usize> = lines
        .iter()
        .filter(|line: &&DisasmLine| line.opcode == 0x1B)
        .filter_map(|line: &DisasmLine| succs.get(&line.offset))
        .flatten()
        .copied()
        .filter(|target: &usize| valid_offsets.contains(target))
        .collect();
    let switch_offsets: BTreeSet<usize> = lines
        .iter()
        .filter(|line: &&DisasmLine| line.opcode == 0x1B)
        .map(|line: &DisasmLine| line.offset)
        .collect();
    let mut switch_direction_refusals: BTreeSet<usize> = BTreeSet::new();
    let mut switch_budget_refusals: BTreeSet<usize> = BTreeSet::new();
    let mut switch_fuel: SwitchAnalysisFuel = SwitchAnalysisFuel::new();
    'switches: for line in lines
        .iter()
        .filter(|line: &&DisasmLine| line.opcode == 0x1B)
    {
        if !switch_fuel.charge(1) {
            switch_budget_refusals.extend(&switch_offsets);
            break;
        }
        let Some(targets) = succs.get(&line.offset) else {
            continue;
        };
        if !switch_fuel.charge(targets.len()) {
            switch_budget_refusals.extend(&switch_offsets);
            break;
        }
        if targets.is_empty() {
            continue;
        }
        if targets.iter().any(|target: &usize| *target <= line.offset) {
            switch_direction_refusals.insert(line.offset);
            continue;
        }
        let Some(last_entry): Option<usize> = targets.iter().copied().max() else {
            continue;
        };
        let Some(first_entry): Option<usize> = targets.iter().copied().min() else {
            continue;
        };
        let mut merge_candidates: BTreeSet<usize> = BTreeSet::new();
        for (source, candidate_line) in line_by_offset.range(first_entry..last_entry) {
            if !switch_fuel.charge(1) {
                switch_budget_refusals.extend(&switch_offsets);
                break 'switches;
            }
            if candidate_line.opcode != 0x10 {
                continue;
            }
            let Some(candidate_targets) = succs.get(source) else {
                continue;
            };
            if !switch_fuel.charge(candidate_targets.len()) {
                switch_budget_refusals.extend(&switch_offsets);
                break 'switches;
            }
            for candidate in candidate_targets {
                if *candidate <= last_entry
                    || predecessors
                        .get(candidate)
                        .is_none_or(|sources: &BTreeSet<usize>| sources.len() <= 1)
                {
                    continue;
                }
                if !switch_fuel.charge(1) {
                    switch_budget_refusals.extend(&switch_offsets);
                    break 'switches;
                }
                merge_candidates.insert(*candidate);
            }
        }
        for candidate in merge_candidates {
            let mut all_reach: bool = true;
            for target in targets {
                match reaches_forward_join(&succs, *target, candidate, &mut switch_fuel) {
                    Some(true) => {}
                    Some(false) => {
                        all_reach = false;
                        break;
                    }
                    None => {
                        unverifiable_joins.insert(candidate);
                        all_reach = false;
                        if switch_fuel.exhausted {
                            switch_budget_refusals.extend(&switch_offsets);
                            break 'switches;
                        }
                        break;
                    }
                }
            }
            if all_reach {
                value_joins.insert(candidate);
                break;
            }
        }
    }
    let forward_entries: BTreeSet<usize> = predecessors
        .iter()
        .filter(|(target, sources): &(&usize, &BTreeSet<usize>)| {
            sources.iter().all(|source: &usize| source < *target)
        })
        .map(|(target, _): (&usize, &BTreeSet<usize>)| *target)
        .collect();
    let backward_entries: BTreeSet<usize> = predecessors
        .iter()
        .filter(|(target, sources): &(&usize, &BTreeSet<usize>)| {
            sources.iter().any(|source: &usize| source >= *target)
        })
        .map(|(target, _): (&usize, &BTreeSet<usize>)| *target)
        .collect();
    let disconnected_entries: BTreeSet<usize> = lines
        .windows(2)
        .filter_map(|pair: &[DisasmLine]| {
            let previous: &DisasmLine = &pair[0];
            let current: &DisasmLine = &pair[1];
            let flows_from_previous: bool = succs
                .get(&previous.offset)
                .is_some_and(|targets: &Vec<usize>| targets.contains(&current.offset));
            (!flows_from_previous).then_some(current.offset)
        })
        .collect();
    let mut entry: BTreeMap<usize, HeightCell> = lines
        .iter()
        .map(|l: &DisasmLine| (l.offset, HeightCell::Unknown))
        .collect();
    let mut poisoned: BTreeSet<usize> = BTreeSet::new();
    let mut barrier: BTreeSet<usize> = BTreeSet::new();
    if let Some(first) = lines.first() {
        entry.insert(first.offset, HeightCell::Height(0));
    }
    for target in &exc_targets {
        if valid_offsets.contains(target) {
            entry.insert(*target, HeightCell::Height(1));
        }
    }
    let mut worklist: VecDeque<usize> = VecDeque::new();
    if let Some(first) = lines.first() {
        worklist.push_back(first.offset);
    }
    for target in &exc_targets {
        if valid_offsets.contains(target) {
            worklist.push_back(*target);
        }
    }
    let mut iterations: usize = 0;
    let cap: usize = lines.len().saturating_mul(4).saturating_add(16);
    while let Some(off) = worklist.pop_front() {
        iterations += 1;
        if iterations > cap {
            break;
        }
        let Some(HeightCell::Height(h)): Option<&HeightCell> = entry.get(&off) else {
            continue;
        };
        let h: i64 = *h;
        let delta: Option<i64> = if let Some(known) = deltas.get(&off) {
            Some(*known)
        } else if let Some(line) = line_by_offset.get(&off) {
            let computed: Option<i64> = line_stack_delta(&mut scratch, line);
            if let Some(value) = computed {
                deltas.insert(off, value);
            }
            computed
        } else {
            continue;
        };
        let Some(delta): Option<i64> = delta else {
            barrier.insert(off);
            continue;
        };
        let exit_h: i64 = h + delta;
        if exit_h < 0 {
            poisoned.insert(off);
            continue;
        }
        let Some(targets): Option<&Vec<usize>> = succs.get(&off) else {
            continue;
        };
        for target in targets.clone() {
            if !valid_offsets.contains(&target) || exc_targets.contains(&target) {
                continue;
            }
            let current: HeightCell = entry.get(&target).copied().unwrap_or(HeightCell::Unknown);
            let joined: HeightCell = current.join(exit_h);
            if joined == current {
                continue;
            }
            match joined {
                HeightCell::Conflict => {
                    entry.insert(target, HeightCell::Conflict);
                    poisoned.insert(target);
                }
                HeightCell::Height(_) => {
                    entry.insert(target, joined);
                    worklist.push_back(target);
                }
                HeightCell::Unknown => {}
            }
        }
    }
    let height_conflicts: BTreeSet<usize> = entry
        .iter()
        .filter_map(|(offset, cell): (&usize, &HeightCell)| {
            matches!(cell, HeightCell::Conflict).then_some(*offset)
        })
        .collect();
    let mut invalid_entries: BTreeSet<usize> = poisoned;
    invalid_entries.extend(barrier);
    let mut unreconciled: BTreeSet<usize> = invalid_entries
        .iter()
        .copied()
        .filter(|offset: &usize| switch_entries.contains(offset) || value_joins.contains(offset))
        .collect();
    unreconciled.extend(unverifiable_joins);
    let entry_heights: BTreeMap<usize, usize> = labels
        .iter()
        .filter(|off: &&usize| !invalid_entries.contains(off))
        .filter_map(|off: &usize| match entry.get(off) {
            Some(HeightCell::Height(h)) if *h >= 0 => Some((*off, *h as usize)),
            _ => None,
        })
        .collect();
    let mut scope_entry: BTreeMap<usize, HeightCell> = lines
        .iter()
        .map(|line: &DisasmLine| (line.offset, HeightCell::Unknown))
        .collect();
    if let Some(first) = lines.first() {
        scope_entry.insert(first.offset, HeightCell::Height(0));
    }
    for target in &exc_targets {
        if valid_offsets.contains(target) {
            scope_entry.insert(*target, HeightCell::Height(0));
        }
    }
    let mut scope_worklist: VecDeque<usize> = VecDeque::new();
    if let Some(first) = lines.first() {
        scope_worklist.push_back(first.offset);
    }
    for target in &exc_targets {
        if valid_offsets.contains(target) {
            scope_worklist.push_back(*target);
        }
    }
    let mut scope_poisoned: BTreeSet<usize> = BTreeSet::new();
    let mut scope_iterations: usize = 0;
    let mut scope_analysis_exhausted: bool = false;
    while let Some(offset) = scope_worklist.pop_front() {
        scope_iterations = scope_iterations.saturating_add(1);
        if scope_iterations > cap {
            scope_analysis_exhausted = true;
            break;
        }
        let Some(HeightCell::Height(height)): Option<&HeightCell> = scope_entry.get(&offset) else {
            continue;
        };
        let Some(line): Option<&&DisasmLine> = line_by_offset.get(&offset) else {
            continue;
        };
        let exit_height: i64 = height.saturating_add(line_scope_delta(line));
        if exit_height < 0 {
            scope_poisoned.insert(offset);
            continue;
        }
        let Some(targets): Option<&Vec<usize>> = succs.get(&offset) else {
            continue;
        };
        for target in targets {
            if !valid_offsets.contains(target) || exc_targets.contains(target) {
                continue;
            }
            let current: HeightCell = scope_entry
                .get(target)
                .copied()
                .unwrap_or(HeightCell::Unknown);
            let joined: HeightCell = current.join(exit_height);
            if joined == current {
                continue;
            }
            match joined {
                HeightCell::Conflict => {
                    scope_entry.insert(*target, HeightCell::Conflict);
                    scope_poisoned.insert(*target);
                }
                HeightCell::Height(_) => {
                    scope_entry.insert(*target, joined);
                    scope_worklist.push_back(*target);
                }
                HeightCell::Unknown => {}
            }
        }
    }
    let scope_height_conflicts: BTreeSet<usize> = scope_entry
        .iter()
        .filter_map(|(offset, cell): (&usize, &HeightCell)| {
            matches!(cell, HeightCell::Conflict).then_some(*offset)
        })
        .collect();
    let mut scope_unreconciled: BTreeSet<usize> = labels
        .iter()
        .copied()
        .filter(|offset: &usize| {
            scope_poisoned.contains(offset)
                || (predecessors.contains_key(offset)
                    && matches!(scope_entry.get(offset), Some(HeightCell::Unknown) | None))
        })
        .collect();
    if scope_analysis_exhausted {
        scope_unreconciled.extend(labels.iter().copied());
    }
    let scope_entry_heights: BTreeMap<usize, usize> = labels
        .iter()
        .filter_map(|offset: &usize| match scope_entry.get(offset) {
            Some(HeightCell::Height(height)) if *height >= 0 => Some((*offset, *height as usize)),
            _ => None,
        })
        .collect();
    StackAnalysis {
        entry_heights,
        scope_entry_heights,
        value_joins,
        switch_entries,
        forward_entries,
        backward_entries,
        disconnected_entries,
        unreconciled,
        height_conflicts,
        scope_unreconciled,
        scope_height_conflicts,
        switch_direction_refusals,
        switch_budget_refusals,
    }
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
        0x62 => {
            let index: i64 = lifter.operand(ops, 0);
            lifter.push(local_expr(index, lifter.names));
        }
        0xD0 => lifter.push(local_expr(0, lifter.names)),
        0xD1 => lifter.push(local_expr(1, lifter.names)),
        0xD2 => lifter.push(local_expr(2, lifter.names)),
        0xD3 => lifter.push(local_expr(3, lifter.names)),
        0x63 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_setlocal(lifter, index, line.offset);
        }
        0xD4 => emit_setlocal(lifter, 0, line.offset),
        0xD5 => emit_setlocal(lifter, 1, line.offset),
        0xD6 => emit_setlocal(lifter, 2, line.offset),
        0xD7 => emit_setlocal(lifter, 3, line.offset),
        0x22 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_push_float(lifter, index, "float");
        }
        0x2C => {
            let index: i64 = lifter.operand(ops, 0);
            let value: String = lifter.string(index);
            lifter.push(Expr::StringLit(value));
        }
        0x2D => {
            let index: i64 = lifter.operand(ops, 0);
            let value: i64 = lifter.int(index);
            lifter.push(Expr::IntLit(value));
        }
        0x2E => {
            let index: i64 = lifter.operand(ops, 0);
            let value: u64 = lifter.uint(index);
            lifter.push(Expr::UintLit(value));
        }
        0x2F => {
            let index: i64 = lifter.operand(ops, 0);
            let value: f64 = lifter.double(index);
            lifter.push(Expr::DoubleLit(value));
        }
        0x24 | 0x25 => {
            let value: i64 = lifter.operand(ops, 0);
            lifter.push(Expr::IntLit(value));
        }
        0x20 => lifter.push(Expr::Null),
        0x21 => lifter.push(Expr::Undefined),
        0x26 => lifter.push(Expr::BoolLit(true)),
        0x27 => lifter.push(Expr::BoolLit(false)),
        0x28 => lifter.push(Expr::NaN),
        0x29 => {
            let e: Expr = lifter.pop();
            if expr_has_effect(&e) {
                lifter.statements.push(Stmt::Expression(e));
                let index: usize = lifter.statements.len() - 1;
                if lifter.idioms.short_circuit_discards.contains(&line.offset)
                    && let Some(pending) = lifter.short_circuits.last_mut()
                    && pending.branch_index + 1 == index
                {
                    pending.discard_index = Some(index);
                }
            }
        }
        0x2A => {
            let top: Expr = lifter.pop();
            lifter.push(dup_clone(&top));
            lifter.push(top);
        }
        0x2B => {
            let a: Expr = lifter.pop();
            let b: Expr = lifter.pop();
            lifter.push(a);
            lifter.push(b);
        }
        0x60 => {
            let index: i64 = lifter.operand(ops, 0);
            let name: String = lifter.multiname(index);
            lifter.push(Expr::Lex(name));
        }
        0x5D..=0x5F => {
            let index: i64 = lifter.operand(ops, 0);
            emit_findproperty(lifter, index);
        }
        0x64 | 0x65 | 0x57 | 0x5A => lifter.push(Expr::ScopeObject),
        0x66 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_getproperty(lifter, index);
        }
        0x6C => {
            let slot: i64 = lifter.operand(ops, 0);
            emit_getslot(lifter, slot);
        }
        0x61 | 0x68 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_setproperty(lifter, index);
        }
        0x6D => {
            let slot: i64 = lifter.operand(ops, 0);
            emit_setslot(lifter, slot);
        }
        0x46 | 0x4C => emit_call(lifter, ops, false),
        0x4F => emit_call(lifter, ops, true),
        0x45 | 0x4E => emit_callsuper(lifter, ops, op == 0x4E),
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
        0x56 => {
            let count: i64 = lifter.operand(ops, 0);
            emit_newarray(lifter, count);
        }
        0x55 => {
            let count: i64 = lifter.operand(ops, 0);
            emit_newobject(lifter, count);
        }
        0x90 | 0xC4 => emit_unary(lifter, "-"),
        0x96 => emit_unary(lifter, "!"),
        0x97 => emit_unary(lifter, "~"),
        0x91 | 0xC0 => emit_postfix(lifter, "++"),
        0x93 | 0xC1 => emit_postfix(lifter, "--"),
        0x92 | 0xC2 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_inc_local(lifter, index, "+");
        }
        0x94 | 0xC3 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_inc_local(lifter, index, "-");
        }
        0x87 => emit_astypelate(lifter),
        0x0A | 0x35..=0x39 => emit_mem_load(lifter, line.mnemonic),
        0x0B | 0x3A..=0x3E => emit_mem_store(lifter, line.mnemonic),
        0x06 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_dxns(lifter, line.mnemonic, index);
        }
        0x07 => emit_dxnslate(lifter),
        0x95 => {
            let e: Expr = lifter.pop();
            lifter.push(Expr::Typeof(Box::new(e)));
        }
        0x80 | 0x86 => {
            let index: i64 = lifter.operand(ops, 0);
            let name: String = lifter.multiname(index);
            emit_coerce(lifter, name);
        }
        0x70 | 0x85 => emit_coerce(lifter, "String".to_owned()),
        0x73 | 0x83 => emit_coerce(lifter, "int".to_owned()),
        0x74 | 0x88 => emit_coerce(lifter, "uint".to_owned()),
        0x75 | 0x84 => emit_coerce(lifter, "Number".to_owned()),
        0x76 | 0x81 => emit_coerce(lifter, "Boolean".to_owned()),
        0x79 => emit_coerce(lifter, "float".to_owned()),
        0x7A => emit_unary(lifter, "+"),
        0x7B => emit_coerce(lifter, "float4".to_owned()),
        0x89 => emit_coerce(lifter, "Object".to_owned()),
        0x0C..=0x1A => emit_branch(lifter, line, next_off, end_off),
        0x1B => emit_switch(lifter, line, next_off, end_off),
        0x04 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_getsuper(lifter, index);
        }
        0x05 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_setsuper(lifter, index);
        }
        0x6A => {
            let index: i64 = lifter.operand(ops, 0);
            emit_deleteproperty(lifter, index);
        }
        0x59 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_getdescendants(lifter, index);
        }
        0x53 => {
            let count: i64 = lifter.operand(ops, 0);
            emit_applytype(lifter, count);
        }
        0x40 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_newfunction(lifter, index);
        }
        0x50..=0x52 => emit_intrinsic_unary(lifter, line.mnemonic),
        0x54 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_push_float(lifter, index, "float4");
        }
        0xB2 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_istype(lifter, index);
        }
        0xB3 => emit_istypelate(lifter),
        0x58 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_newclass(lifter, index);
        }
        0x32 => emit_hasnext2(lifter, ops),
        0x1F => emit_hasnext(lifter),
        0x1E => emit_nextname(lifter),
        0x23 => emit_nextvalue(lifter),
        0x43 => emit_callmethod(lifter, ops, "methodSlot"),
        0x44 => emit_callmethod(lifter, ops, "method"),
        0x6E => {
            let slot: i64 = lifter.operand(ops, 0);
            emit_getglobalslot(lifter, slot);
        }
        0x6F => {
            let slot: i64 = lifter.operand(ops, 0);
            emit_setglobalslot(lifter, slot);
        }
        0x31 => {
            let index: i64 = lifter.operand(ops, 0);
            let namespace: Expr = lifter.namespace(index);
            lifter.push(namespace);
        }
        0x67 => {
            let index: i64 = lifter.operand(ops, 0);
            emit_getouterscope(lifter, index);
        }
        0x30 => emit_pushscope(lifter, false, line.offset),
        0x1C => emit_pushscope(lifter, true, line.offset),
        0x1D => emit_popscope(lifter),
        0x02 | 0x08 | 0x09 | 0x71 | 0x72 | 0x77 | 0x78 | 0x82 | 0xEF | 0xF0 | 0xF1 | 0xF2
        | 0xF3 => {}
        _ => lifter.dropped_opcodes.push(op),
    }
}

fn local_expr(slot: i64, _names: &LocalNames) -> Expr {
    if slot <= 0 {
        Expr::This
    } else {
        Expr::Local(slot as u32)
    }
}

fn emit_setlocal(lifter: &mut Lifter<'_>, slot: i64, offset: usize) {
    let value: Expr = lifter.pop();
    let target: Expr = local_expr(slot, lifter.names);
    if lifter.idioms.dup_backed_setlocals.contains(&offset)
        && let Some(top) = lifter.stack.last_mut()
    {
        *top = target.clone();
    }
    lifter.statements.push(Stmt::Assign { target, value });
}

fn emit_getproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let (needs_ns, needs_name): (bool, bool) = lifter.runtime_operands(mn_idx);
    if needs_ns || needs_name {
        let index: Expr = lifter.pop_runtime_selector(mn_idx, needs_ns, needs_name);
        let object: Expr = lifter.pop();
        lifter.push(Expr::Index {
            object: Box::new(object),
            index: Box::new(index),
        });
        return;
    }
    let property: String = lifter.property(mn_idx);
    let object: Expr = lifter.pop();
    lifter.push(scope_relative_get(object, property));
}

fn scope_relative_get(object: Expr, property: String) -> Expr {
    match object {
        Expr::ScopeObject => Expr::Name(property),
        Expr::Lex(ref s) if simple_tail(s) == property => Expr::Name(s.clone()),
        other => Expr::Get {
            object: Box::new(other),
            property,
        },
    }
}

fn emit_getslot(lifter: &mut Lifter<'_>, slot: i64) {
    let property: String = lifter.slot_name(slot);
    let object: Expr = lifter.pop();
    lifter.push(scope_relative_get(object, property));
}

fn emit_setproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let value: Expr = lifter.pop();
    let (needs_ns, needs_name): (bool, bool) = lifter.runtime_operands(mn_idx);
    if needs_ns || needs_name {
        let index: Expr = lifter.pop_runtime_selector(mn_idx, needs_ns, needs_name);
        let object: Expr = lifter.pop();
        lifter.hoist_stale_stack_reads(WrittenLocation::Element);
        lifter.statements.push(Stmt::AssignIndex {
            object,
            index,
            value,
        });
        return;
    }
    let property: String = lifter.property(mn_idx);
    let object: Expr = lifter.pop();
    lifter.hoist_stale_stack_reads(WrittenLocation::Property(&property));
    lifter
        .statements
        .push(scope_relative_assign(object, property, value));
}

fn scope_relative_assign(object: Expr, property: String, value: Expr) -> Stmt {
    match object {
        Expr::ScopeObject => Stmt::Assign {
            target: Expr::Name(property),
            value,
        },
        Expr::Lex(ref s) if simple_tail(s) == property => Stmt::Assign {
            target: Expr::Name(s.clone()),
            value,
        },
        other => Stmt::AssignProperty {
            object: other,
            property,
            value,
        },
    }
}

fn emit_setslot(lifter: &mut Lifter<'_>, slot: i64) {
    let property: String = lifter.slot_name(slot);
    let value: Expr = lifter.pop();
    let object: Expr = lifter.pop();
    lifter.hoist_stale_stack_reads(WrittenLocation::Property(&property));
    lifter
        .statements
        .push(scope_relative_assign(object, property, value));
}

fn emit_pushscope(lifter: &mut Lifter<'_>, is_with: bool, offset: usize) {
    let object: Expr = lifter.pop();
    if is_with {
        lifter.with_regions.push(WithRegion {
            open_stmt: lifter.statements.len(),
            close_stmt: lifter.statements.len(),
            object: object.clone(),
        });
    }
    lifter.scope_stack.push(ScopeEntry {
        object,
        is_with,
        identity: offset,
    });
}

fn emit_popscope(lifter: &mut Lifter<'_>) {
    let Some(entry): Option<ScopeEntry> = lifter.scope_stack.pop() else {
        return;
    };
    if !entry.is_with {
        return;
    }
    let close: usize = lifter.statements.len();
    if let Some(region) = lifter
        .with_regions
        .iter_mut()
        .rev()
        .find(|r: &&mut WithRegion| r.close_stmt == r.open_stmt)
    {
        region.close_stmt = close;
    }
}

fn emit_findproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let name: String = lifter.multiname(mn_idx);
    let resolved: Option<Expr> = lifter.nearest_with().cloned();
    match resolved {
        Some(object) => lifter.push(object),
        None => lifter.push(Expr::Lex(name)),
    }
}

fn emit_getouterscope(lifter: &mut Lifter<'_>, index: i64) {
    lifter.push(Expr::Name(format!("outerScope{}", index.max(0))));
}

fn emit_getsuper(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let property: String = lifter.property(mn_idx);
    let _object: Expr = lifter.pop();
    lifter.push(Expr::Get {
        object: Box::new(Expr::Name("super".to_owned())),
        property,
    });
}

fn emit_setsuper(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let value: Expr = lifter.pop();
    let property: String = lifter.property(mn_idx);
    let _object: Expr = lifter.pop();
    lifter.statements.push(Stmt::AssignProperty {
        object: Expr::Name("super".to_owned()),
        property,
        value,
    });
}

fn emit_deleteproperty(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let property: String = lifter.property(mn_idx);
    let object: Expr = lifter.pop();
    lifter.push(Expr::Delete {
        object: Box::new(object),
        property,
    });
}

fn emit_getdescendants(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let property: String = lifter.property(mn_idx);
    let object: Expr = lifter.pop();
    lifter.push(Expr::Descendants {
        object: Box::new(object),
        property,
    });
}

fn emit_applytype(lifter: &mut Lifter<'_>, argc: i64) {
    let n: usize = argc.max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(n);
    let base: Expr = lifter.pop();
    lifter.push(Expr::Applied {
        base: Box::new(base),
        args,
    });
}

fn emit_newfunction(lifter: &mut Lifter<'_>, method_idx: i64) {
    lifter.push(Expr::Closure(method_idx.max(0) as u32));
}

fn emit_push_float(lifter: &mut Lifter<'_>, idx: i64, prefix: &str) {
    let name: String = format!("{prefix}{}", idx.max(0));
    let value: Expr = lifter.synthesized(name);
    lifter.push(value);
}

fn emit_istype(lifter: &mut Lifter<'_>, mn_idx: i64) {
    let ty: String = lifter.multiname(mn_idx);
    let operand: Expr = lifter.pop();
    lifter.push(Expr::IsType {
        operand: Box::new(operand),
        ty: Box::new(Expr::Name(ty)),
    });
}

fn emit_istypelate(lifter: &mut Lifter<'_>) {
    let ty: Expr = lifter.pop();
    let operand: Expr = lifter.pop();
    lifter.push(Expr::IsType {
        operand: Box::new(operand),
        ty: Box::new(ty),
    });
}

fn emit_newclass(lifter: &mut Lifter<'_>, class_idx: i64) {
    let _basetype: Expr = lifter.pop();
    let name: String = lifter.class_name(class_idx);
    lifter.push(Expr::Name(name));
}

fn emit_hasnext2(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let obj_reg: i64 = lifter.operand(ops, 0);
    let idx_reg: i64 = lifter.operand(ops, 1);
    let obj: Expr = local_expr(obj_reg, lifter.names);
    let idx: Expr = local_expr(idx_reg, lifter.names);
    lifter.push(Expr::Call {
        callee: Box::new(obj),
        property: "hasNext".to_owned(),
        args: vec![idx],
    });
}

fn emit_hasnext(lifter: &mut Lifter<'_>) {
    let index: Expr = lifter.pop();
    let object: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(object),
        property: "hasNext".to_owned(),
        args: vec![index],
    });
}

fn emit_nextname(lifter: &mut Lifter<'_>) {
    let index: Expr = lifter.pop();
    let object: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(object),
        property: "nextName".to_owned(),
        args: vec![index],
    });
}

fn emit_nextvalue(lifter: &mut Lifter<'_>) {
    let index: Expr = lifter.pop();
    let object: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(object),
        property: "nextValue".to_owned(),
        args: vec![index],
    });
}

fn simple_tail(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn lex_receiver_matches(callee: &Expr, property: &str) -> bool {
    matches!(callee, Expr::Lex(s) if s == property || simple_tail(s) == property)
}

fn emit_call(lifter: &mut Lifter<'_>, ops: &[i64], void: bool) {
    let mn_idx: i64 = lifter.operand(ops, 0);
    let argc: usize = lifter.operand(ops, 1).max(0) as usize;
    let (needs_ns, needs_name): (bool, bool) = lifter.runtime_operands(mn_idx);
    let args: Vec<Expr> = lifter.pop_n(argc);
    if needs_ns || needs_name {
        let index: Expr = lifter.pop_runtime_selector(mn_idx, needs_ns, needs_name);
        let object: Expr = lifter.pop();
        let call: Expr = Expr::Call {
            callee: Box::new(Expr::Index {
                object: Box::new(object),
                index: Box::new(index),
            }),
            property: String::new(),
            args,
        };
        if void {
            lifter.statements.push(Stmt::Expression(call));
        } else {
            lifter.push(call);
        }
        return;
    }
    let property: String = lifter.property(mn_idx);
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
    let argc: usize = lifter.operand(ops, 0).max(0) as usize;
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
    let mn_idx: i64 = lifter.operand(ops, 0);
    let argc: usize = lifter.operand(ops, 1).max(0) as usize;
    let (needs_ns, needs_name): (bool, bool) = lifter.runtime_operands(mn_idx);
    let args: Vec<Expr> = lifter.pop_n(argc);
    if needs_ns || needs_name {
        let index: Expr = lifter.pop_runtime_selector(mn_idx, needs_ns, needs_name);
        let object: Expr = lifter.pop();
        lifter.push(Expr::New {
            ty: Box::new(Expr::Index {
                object: Box::new(object),
                index: Box::new(index),
            }),
            args,
        });
        return;
    }
    let property: String = lifter.property(mn_idx);
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
    let argc: usize = lifter.operand(ops, 0).max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(argc);
    let ty: Expr = lifter.pop();
    lifter.push(Expr::New {
        ty: Box::new(ty),
        args,
    });
}

fn emit_constructsuper(lifter: &mut Lifter<'_>, ops: &[i64]) {
    let argc: usize = lifter.operand(ops, 0).max(0) as usize;
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
    let flat: Vec<Expr> = lifter.pop_n(n.saturating_mul(2));
    let mut pairs: Vec<(Expr, Expr)> = Vec::with_capacity(flat.len() / 2);
    let mut it: std::vec::IntoIter<Expr> = flat.into_iter();
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

fn emit_intrinsic_unary(lifter: &mut Lifter<'_>, intrinsic: &str) {
    let value: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(Expr::Name(String::new())),
        property: intrinsic.to_owned(),
        args: vec![value],
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

fn emit_inc_local(lifter: &mut Lifter<'_>, slot: i64, op: &'static str) {
    let target: Expr = local_expr(slot, lifter.names);
    let occurrences: usize = lifter
        .stack
        .iter()
        .filter(|e: &&Expr| **e == target)
        .count();
    if occurrences == 1 && lifter.stack.last() == Some(&target) {
        lifter.stack.pop();
        lifter.push(Expr::Update {
            op: if op == "+" { "++" } else { "--" },
            operand: Box::new(target),
            postfix: true,
        });
        return;
    }
    let value: Expr = Expr::Binary {
        op,
        lhs: Box::new(target.clone()),
        rhs: Box::new(Expr::IntLit(1)),
    };
    lifter.statements.push(Stmt::Assign { target, value });
}

fn emit_mem_load(lifter: &mut Lifter<'_>, intrinsic: &str) {
    let address: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(Expr::Name(String::new())),
        property: intrinsic.to_owned(),
        args: vec![address],
    });
}

fn emit_mem_store(lifter: &mut Lifter<'_>, intrinsic: &str) {
    let address: Expr = lifter.pop();
    let value: Expr = lifter.pop();
    lifter.statements.push(Stmt::Expression(Expr::Call {
        callee: Box::new(Expr::Name(String::new())),
        property: intrinsic.to_owned(),
        args: vec![value, address],
    }));
}

fn emit_dxns(lifter: &mut Lifter<'_>, _mnemonic: &str, str_idx: i64) {
    let uri: String = lifter.string(str_idx);
    lifter.statements.push(Stmt::Assign {
        target: Expr::Name("default xml namespace".to_owned()),
        value: Expr::StringLit(uri),
    });
}

fn emit_dxnslate(lifter: &mut Lifter<'_>) {
    let uri: Expr = lifter.pop();
    lifter.statements.push(Stmt::Assign {
        target: Expr::Name("default xml namespace".to_owned()),
        value: uri,
    });
}

fn emit_astypelate(lifter: &mut Lifter<'_>) {
    let ty: Expr = lifter.pop();
    let operand: Expr = lifter.pop();
    lifter.push(Expr::AsType {
        operand: Box::new(operand),
        ty: Box::new(ty),
    });
}

fn emit_callsuper(lifter: &mut Lifter<'_>, ops: &[i64], void: bool) {
    let mn_idx: i64 = lifter.operand(ops, 0);
    let argc: usize = lifter.operand(ops, 1).max(0) as usize;
    let property: String = lifter.property(mn_idx);
    let args: Vec<Expr> = lifter.pop_n(argc);
    let _receiver: Expr = lifter.pop();
    let call: Expr = Expr::Call {
        callee: Box::new(Expr::Name("super".to_owned())),
        property,
        args,
    };
    if void {
        lifter.statements.push(Stmt::Expression(call));
    } else {
        lifter.push(call);
    }
}

fn emit_callmethod(lifter: &mut Lifter<'_>, ops: &[i64], prefix: &str) {
    let index: i64 = lifter.operand(ops, 0);
    let argc: usize = lifter.operand(ops, 1).max(0) as usize;
    let args: Vec<Expr> = lifter.pop_n(argc);
    let receiver: Expr = lifter.pop();
    lifter.push(Expr::Call {
        callee: Box::new(receiver),
        property: format!("{prefix}{index}"),
        args,
    });
}

fn emit_getglobalslot(lifter: &mut Lifter<'_>, slot: i64) {
    let property: String = lifter.slot_name(slot);
    lifter.push(Expr::Get {
        object: Box::new(Expr::Name("global".to_owned())),
        property,
    });
}

fn emit_setglobalslot(lifter: &mut Lifter<'_>, slot: i64) {
    let property: String = lifter.slot_name(slot);
    let value: Expr = lifter.pop();
    lifter.statements.push(Stmt::AssignProperty {
        object: Expr::Name("global".to_owned()),
        property,
        value,
    });
}

fn emit_branch(lifter: &mut Lifter<'_>, line: &DisasmLine, next_off: usize, end_off: usize) {
    let after: usize = if next_off == 0 { end_off } else { next_off };
    let rel: i64 = lifter.operand(&line.operands, 0);
    let target: usize = relative_target(after, rel);
    match line.opcode {
        0x10 => {
            lifter.record_edge_stack(target);
            lifter.statements.push(Stmt::Jump {
                target_label: target,
            });
        }
        OP_IFTRUE | OP_IFFALSE => {
            let value: Expr = lifter.pop();
            lifter.record_edge_stack(target);
            if let Some(op) = lifter
                .idioms
                .short_circuit_branches
                .get(&line.offset)
                .copied()
                && target > line.offset
            {
                lifter.statements.push(Stmt::If {
                    cond: branch_condition(line.opcode, value.clone()),
                    target_label: target,
                });
                lifter.short_circuits.push(ShortCircuit {
                    target,
                    op,
                    lhs: value,
                    join_height: lifter.stack.len().saturating_sub(1),
                    branch_index: lifter.statements.len() - 1,
                    discard_index: None,
                });
                return;
            }
            let cond: Expr = branch_condition(line.opcode, value);
            if !push_defaulted_short_circuit(lifter, line.offset, &cond, target) {
                push_conditional_branch(lifter, cond, target);
            }
        }
        other => {
            if let Some(cmp) = compare_branch_op(other) {
                let rhs: Expr = lifter.pop();
                let lhs: Expr = lifter.pop();
                lifter.record_edge_stack(target);
                let cond: Expr = Expr::Binary {
                    op: cmp,
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                };
                if !push_defaulted_short_circuit(lifter, line.offset, &cond, target) {
                    push_conditional_branch(lifter, cond, target);
                }
            }
        }
    }
}

fn branch_condition(opcode: u8, value: Expr) -> Expr {
    if opcode == OP_IFFALSE {
        Expr::Unary {
            op: "!",
            operand: Box::new(value),
        }
    } else {
        value
    }
}

fn push_defaulted_short_circuit(
    lifter: &mut Lifter<'_>,
    offset: usize,
    cond: &Expr,
    target: usize,
) -> bool {
    if target <= offset || !lifter.idioms.defaulted_short_circuits.contains(&offset) {
        return false;
    }
    let default: bool = match lifter.stack.last() {
        Some(Expr::BoolLit(value)) => *value,
        _ => return false,
    };
    let (op, lhs): (&'static str, Expr) = if default {
        ("||", cond.clone())
    } else {
        ("&&", negate(cond.clone()))
    };
    lifter.statements.push(Stmt::If {
        cond: cond.clone(),
        target_label: target,
    });
    lifter.short_circuits.push(ShortCircuit {
        target,
        op,
        lhs,
        join_height: lifter.stack.len().saturating_sub(1),
        branch_index: lifter.statements.len() - 1,
        discard_index: None,
    });
    true
}

fn push_conditional_branch(lifter: &mut Lifter<'_>, cond: Expr, target: usize) {
    lifter.branch_marks.push(BranchMark {
        stmt_index: lifter.statements.len(),
        join_height: lifter.stack.len(),
        else_label: target,
        cond: cond.clone(),
    });
    lifter.statements.push(Stmt::If {
        cond,
        target_label: target,
    });
}

fn emit_switch(lifter: &mut Lifter<'_>, line: &DisasmLine, _next_off: usize, _end_off: usize) {
    let selector: Expr = lifter.pop();
    let default_label: usize = line
        .operands
        .first()
        .map_or(line.offset, |rel: &i64| relative_target(line.offset, *rel));
    let case_labels: Vec<usize> = line.operands[2.min(line.operands.len())..]
        .iter()
        .map(|rel: &i64| relative_target(line.offset, *rel))
        .collect();
    lifter.record_edge_stack(default_label);
    for target in &case_labels {
        lifter.record_edge_stack(*target);
    }
    if lifter.switch_direction_refusals.contains(&line.offset) {
        lifter
            .statements
            .push(Stmt::Comment(SWITCH_DIRECTION_REFUSAL_MARKER.to_owned()));
    }
    if lifter.switch_budget_refusals.contains(&line.offset) {
        lifter
            .statements
            .push(Stmt::Comment(SWITCH_ANALYSIS_BUDGET_MARKER.to_owned()));
    }
    lifter.statements.push(Stmt::Switch {
        selector,
        case_labels,
        default_label,
    });
}

fn expr_has_effect(e: &Expr) -> bool {
    matches!(
        e,
        Expr::Call { .. } | Expr::Construct { .. } | Expr::New { .. } | Expr::Update { .. }
    )
}

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

fn label_ref_count(stmts: &[Stmt], label: usize) -> usize {
    stmts
        .iter()
        .filter(|s: &&Stmt| {
            matches!(
                s,
                Stmt::If { target_label, .. } | Stmt::Jump { target_label }
                    if *target_label == label
            )
        })
        .count()
}

fn label_ref_count_deep(stmts: &[Stmt], label: usize) -> usize {
    stmts
        .iter()
        .map(|s: &Stmt| match s {
            Stmt::If { target_label, .. } | Stmt::Jump { target_label } => {
                usize::from(*target_label == label)
            }
            Stmt::Switch {
                case_labels,
                default_label,
                ..
            } => {
                case_labels.iter().filter(|l: &&usize| **l == label).count()
                    + usize::from(*default_label == label)
            }
            Stmt::IfBlock { body, .. }
            | Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::For { body, .. }
            | Stmt::ForEach { body, .. }
            | Stmt::ForIn { body, .. }
            | Stmt::With { body, .. } => label_ref_count_deep(body, label),
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => label_ref_count_deep(then_body, label) + label_ref_count_deep(else_body, label),
            Stmt::StructuredSwitch { cases, .. } => cases
                .iter()
                .map(|c: &SwitchCase| label_ref_count_deep(&c.body, label))
                .sum(),
            Stmt::Try { body, catches } => {
                label_ref_count_deep(body, label)
                    + catches
                        .iter()
                        .map(|c: &CatchClause| label_ref_count_deep(&c.body, label))
                        .sum::<usize>()
            }
            _ => 0,
        })
        .sum()
}

fn label_at(stmts: &[Stmt], label: usize) -> Option<usize> {
    stmts
        .iter()
        .position(|s: &Stmt| matches!(s, Stmt::Label(l) if *l == label))
}

fn region_is_structurable(slice: &[Stmt]) -> bool {
    !slice
        .iter()
        .any(|s: &Stmt| matches!(s, Stmt::Switch { .. }))
}

fn slice_labels_are_private(outer: &[Stmt], body: &[Stmt]) -> bool {
    body.iter().all(|s: &Stmt| match s {
        Stmt::Label(label) => {
            label_ref_count_deep(body, *label) == label_ref_count_deep(outer, *label)
        }
        _ => true,
    })
}

#[derive(Debug, Clone)]
struct RegionInfo {
    from: usize,
    to: usize,
    target: usize,
    var_name: String,
    type_name: String,
}

fn resolve_regions(lifter: &Lifter<'_>, exceptions: &[ExceptionInfo]) -> Vec<RegionInfo> {
    exceptions
        .iter()
        .map(|exc: &ExceptionInfo| {
            let var_name: String = if exc.var_name == 0 {
                "error".to_owned()
            } else {
                lifter.multiname(i64::from(exc.var_name))
            };
            let type_name: String = if exc.exc_type == 0 {
                "*".to_owned()
            } else {
                lifter.multiname(i64::from(exc.exc_type))
            };
            RegionInfo {
                from: exc.from as usize,
                to: exc.to as usize,
                target: exc.target as usize,
                var_name,
                type_name,
            }
        })
        .collect()
}

fn drop_leading_label(slice: &[Stmt]) -> &[Stmt] {
    match slice.first() {
        Some(Stmt::Label(_)) => &slice[1..],
        _ => slice,
    }
}

fn is_catch_prologue_stmt(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Assign { value, .. } => {
            matches!(value, Expr::ScopeObject | Expr::CaughtException)
        }
        Stmt::AssignProperty { value, .. } | Stmt::AssignIndex { value, .. } => {
            matches!(value, Expr::CaughtException)
        }
        _ => false,
    }
}

fn strip_catch_prologue(slice: &[Stmt]) -> &[Stmt] {
    let mut rest: &[Stmt] = drop_leading_label(slice);
    while rest.first().is_some_and(is_catch_prologue_stmt) {
        rest = &rest[1..];
    }
    rest
}

fn structure_try(stmts: Vec<Stmt>, regions: &[RegionInfo], depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let Some(region): Option<&RegionInfo> = regions
        .iter()
        .min_by_key(|r: &&RegionInfo| (r.from, std::cmp::Reverse(r.to)))
    else {
        return stmts;
    };
    let Some(from_idx): Option<usize> = label_at(&stmts, region.from) else {
        return stmts;
    };
    let Some(to_idx): Option<usize> = label_at(&stmts, region.to) else {
        return stmts;
    };
    let Some(target_idx): Option<usize> = label_at(&stmts, region.target) else {
        return stmts;
    };
    if !(from_idx < to_idx && to_idx < target_idx) {
        return stmts;
    }
    let try_inner: &[Stmt] = &stmts[from_idx + 1..to_idx];
    let gap: &[Stmt] = &stmts[to_idx + 1..target_idx];
    let merge_label: Option<usize> = match (try_inner.last(), gap.first()) {
        (Some(Stmt::Jump { target_label }), _) | (_, Some(Stmt::Jump { target_label })) => {
            Some(*target_label)
        }
        _ => None,
    };
    let try_body_slice: &[Stmt] = match try_inner.last() {
        Some(Stmt::Jump { .. }) => &try_inner[..try_inner.len() - 1],
        _ => try_inner,
    };
    let catch_end: usize = merge_label
        .and_then(|m: usize| label_at(&stmts, m))
        .filter(|m: &usize| *m > target_idx)
        .unwrap_or(stmts.len());
    let catch_inner: &[Stmt] = strip_catch_prologue(&stmts[target_idx..catch_end]);
    let remaining_regions: Vec<RegionInfo> = regions
        .iter()
        .filter(|r: &&RegionInfo| r.from != region.from || r.to != region.to)
        .cloned()
        .collect();
    let try_body: Vec<Stmt> = structure_try(try_body_slice.to_vec(), &remaining_regions, depth - 1);
    let catch_body: Vec<Stmt> = structure_try(catch_inner.to_vec(), &remaining_regions, depth - 1);
    let catch: CatchClause = CatchClause {
        var_name: region.var_name.clone(),
        type_name: region.type_name.clone(),
        body: catch_body,
    };
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    out.extend_from_slice(&stmts[..from_idx]);
    out.push(Stmt::Try {
        body: try_body,
        catches: vec![catch],
    });
    out.extend_from_slice(&stmts[catch_end..]);
    out
}

fn collect_referenced_labels(stmts: &[Stmt], acc: &mut BTreeSet<usize>) {
    for stmt in stmts {
        match stmt {
            Stmt::If { target_label, .. } | Stmt::Jump { target_label } => {
                acc.insert(*target_label);
            }
            Stmt::Switch {
                case_labels,
                default_label,
                ..
            } => {
                acc.extend(case_labels.iter().copied());
                acc.insert(*default_label);
            }
            Stmt::IfBlock { body, .. }
            | Stmt::While { body, .. }
            | Stmt::DoWhile { body, .. }
            | Stmt::For { body, .. }
            | Stmt::ForEach { body, .. }
            | Stmt::ForIn { body, .. }
            | Stmt::With { body, .. } => {
                collect_referenced_labels(body, acc);
            }
            Stmt::IfElse {
                then_body,
                else_body,
                ..
            } => {
                collect_referenced_labels(then_body, acc);
                collect_referenced_labels(else_body, acc);
            }
            Stmt::StructuredSwitch { cases, .. } => {
                for case in cases {
                    collect_referenced_labels(&case.body, acc);
                }
            }
            Stmt::Try { body, catches } => {
                collect_referenced_labels(body, acc);
                for catch in catches {
                    collect_referenced_labels(&catch.body, acc);
                }
            }
            _ => {}
        }
    }
}

fn prune_dead_labels(stmts: Vec<Stmt>, referenced: &BTreeSet<usize>) -> Vec<Stmt> {
    stmts
        .into_iter()
        .filter_map(|stmt: Stmt| match stmt {
            Stmt::Label(l) if !referenced.contains(&l) => None,
            Stmt::IfBlock { cond, body } => Some(Stmt::IfBlock {
                cond,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::While { cond, body } => Some(Stmt::While {
                cond,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::DoWhile { cond, body } => Some(Stmt::DoWhile {
                cond,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::For {
                init,
                cond,
                update,
                body,
            } => Some(Stmt::For {
                init,
                cond,
                update,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::ForEach {
                var,
                collection,
                body,
            } => Some(Stmt::ForEach {
                var,
                collection,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::ForIn {
                var,
                collection,
                body,
            } => Some(Stmt::ForIn {
                var,
                collection,
                body: prune_dead_labels(body, referenced),
            }),
            Stmt::IfElse {
                cond,
                then_body,
                else_body,
            } => Some(Stmt::IfElse {
                cond,
                then_body: prune_dead_labels(then_body, referenced),
                else_body: prune_dead_labels(else_body, referenced),
            }),
            Stmt::StructuredSwitch { selector, cases } => Some(Stmt::StructuredSwitch {
                selector,
                cases: cases
                    .into_iter()
                    .map(|case: SwitchCase| SwitchCase {
                        body: prune_dead_labels(case.body, referenced),
                        ..case
                    })
                    .collect(),
            }),
            Stmt::Try { body, catches } => Some(Stmt::Try {
                body: prune_dead_labels(body, referenced),
                catches: catches
                    .into_iter()
                    .map(|catch: CatchClause| CatchClause {
                        body: prune_dead_labels(catch.body, referenced),
                        ..catch
                    })
                    .collect(),
            }),
            Stmt::With { object, body } => Some(Stmt::With {
                object,
                body: prune_dead_labels(body, referenced),
            }),
            other => Some(other),
        })
        .collect()
}

fn drop_dead_labels(stmts: Vec<Stmt>) -> Vec<Stmt> {
    let mut referenced: BTreeSet<usize> = BTreeSet::new();
    collect_referenced_labels(&stmts, &mut referenced);
    prune_dead_labels(stmts, &referenced)
}

fn expr_is_effect_free(e: &Expr) -> bool {
    match e {
        Expr::Call { .. } | Expr::Construct { .. } | Expr::New { .. } | Expr::Update { .. } => {
            false
        }
        Expr::Binary { lhs, rhs, .. }
        | Expr::Index {
            object: lhs,
            index: rhs,
        } => expr_is_effect_free(lhs) && expr_is_effect_free(rhs),
        Expr::Unary { operand, .. }
        | Expr::Coerce { operand, .. }
        | Expr::Typeof(operand)
        | Expr::Get {
            object: operand, ..
        }
        | Expr::Delete {
            object: operand, ..
        }
        | Expr::Descendants {
            object: operand, ..
        } => expr_is_effect_free(operand),
        Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
            expr_is_effect_free(operand) && expr_is_effect_free(ty)
        }
        Expr::Array(items) => items.iter().all(expr_is_effect_free),
        Expr::Object(pairs) => pairs
            .iter()
            .all(|(k, v): &(Expr, Expr)| expr_is_effect_free(k) && expr_is_effect_free(v)),
        Expr::Applied { base, args } => {
            expr_is_effect_free(base) && args.iter().all(expr_is_effect_free)
        }
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => {
            expr_is_effect_free(cond)
                && expr_is_effect_free(then_value)
                && expr_is_effect_free(else_value)
        }
        _ => true,
    }
}

fn recurse_empty_branches(stmt: Stmt, depth: usize) -> Stmt {
    if depth == 0 {
        return stmt;
    }
    let d: usize = depth - 1;
    let recur = |body: Vec<Stmt>| -> Vec<Stmt> { drop_empty_branches_depth(body, d) };
    match stmt {
        Stmt::Try { body, catches } => Stmt::Try {
            body: recur(body),
            catches: catches
                .into_iter()
                .map(|c: CatchClause| CatchClause {
                    body: recur(c.body),
                    ..c
                })
                .collect(),
        },
        Stmt::With { object, body } => Stmt::With {
            object,
            body: recur(body),
        },
        other => other,
    }
}

fn drop_empty_branches(stmts: Vec<Stmt>) -> Vec<Stmt> {
    drop_empty_branches_depth(stmts, MAX_STRUCTURE_DEPTH)
}

fn drop_empty_branches_depth(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let mut i: usize = 0;
    while i < stmts.len() {
        let next_label: Option<usize> = match stmts.get(i + 1) {
            Some(Stmt::Label(l)) => Some(*l),
            _ => None,
        };
        match &stmts[i] {
            Stmt::Jump { target_label } if Some(*target_label) == next_label => {
                i += 1;
            }
            Stmt::If { cond, target_label }
                if Some(*target_label) == next_label && expr_is_effect_free(cond) =>
            {
                i += 1;
            }
            Stmt::If { cond, target_label } if Some(*target_label) == next_label => {
                out.push(Stmt::IfBlock {
                    cond: negate(cond.clone()),
                    body: Vec::new(),
                });
                i += 1;
            }
            _ => {
                out.push(recurse_empty_branches(stmts[i].clone(), depth));
                i += 1;
            }
        }
    }
    out
}

fn forward_dispatch_selector(cond: &Expr) -> Option<(Expr, Expr)> {
    let Expr::Binary { op, lhs, rhs } = cond else {
        return None;
    };
    if *op != "===" && *op != "==" {
        return None;
    }
    Some(((**lhs).clone(), (**rhs).clone()))
}

fn forward_dispatch_operand_is_stable(expression: &Expr) -> bool {
    matches!(
        expression,
        Expr::This
            | Expr::Local(_)
            | Expr::Param(_)
            | Expr::IntLit(_)
            | Expr::UintLit(_)
            | Expr::DoubleLit(_)
            | Expr::StringLit(_)
            | Expr::BoolLit(_)
            | Expr::Null
            | Expr::Undefined
            | Expr::NaN
            | Expr::ScopeObject
            | Expr::CaughtException
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ForwardDispatchComparison {
    Strict,
    Loose,
}

fn preflight_forward_dispatch(
    stmts: &[Stmt],
    start: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<Option<ForwardDispatchComparison>, &'static str> {
    let mut index: usize = start;
    let mut test_count: usize = 0;
    let mut comparison: Option<ForwardDispatchComparison> = None;
    let mut operands_are_stable: bool = true;
    while let Some(Stmt::If {
        cond: Expr::Binary { op, lhs, rhs },
        ..
    }) = stmts.get(index)
    {
        if *op != "===" && *op != "==" {
            break;
        }
        if !fuel.charge(1) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        let current: ForwardDispatchComparison = if *op == "===" {
            ForwardDispatchComparison::Strict
        } else {
            ForwardDispatchComparison::Loose
        };
        if comparison.is_some_and(|previous: ForwardDispatchComparison| previous != current) {
            return Err(SWITCH_COMPARISON_REFUSAL_MARKER);
        }
        comparison = Some(current);
        test_count = test_count.saturating_add(1);
        operands_are_stable &=
            forward_dispatch_operand_is_stable(lhs) && forward_dispatch_operand_is_stable(rhs);
        index = index.saturating_add(1);
    }
    if test_count < 2 {
        return Ok(None);
    }
    if !operands_are_stable {
        return Err(SWITCH_EFFECT_REFUSAL_MARKER);
    }
    Ok(comparison)
}

struct DispatchTest {
    case_const: Expr,
    condition: Expr,
    target: usize,
}

struct ForwardDispatchArm {
    case_consts: Vec<Expr>,
    loose_conditions: Vec<Expr>,
    body: Vec<Stmt>,
    breaks: bool,
}

struct InvertedDispatchTest {
    lhs: Expr,
    rhs: Expr,
    body_start: usize,
    body_end: usize,
    breaks: bool,
    comparison_is_strict: bool,
}

fn collect_dispatch_tests(
    stmts: &[Stmt],
    start: usize,
) -> Option<(Expr, Vec<DispatchTest>, usize)> {
    let mut raw: Vec<(Expr, Expr, Expr, usize)> = Vec::new();
    let mut idx: usize = start;
    while let Some(Stmt::If { cond, target_label }) = stmts.get(idx) {
        let Some((lhs, rhs)): Option<(Expr, Expr)> = forward_dispatch_selector(cond) else {
            break;
        };
        raw.push((lhs, rhs, cond.clone(), *target_label));
        idx += 1;
    }
    if raw.len() < 2 {
        return None;
    }
    let selector: Expr = {
        let (l0, r0, _, _): &(Expr, Expr, Expr, usize) = &raw[0];
        let candidates: [&Expr; 2] = [l0, r0];
        let selectors: Vec<&Expr> = candidates
            .into_iter()
            .filter(|candidate: &&Expr| {
                raw.iter()
                    .all(|(lhs, rhs, _, _): &(Expr, Expr, Expr, usize)| {
                        (*lhs == **candidate) != (*rhs == **candidate)
                    })
            })
            .collect();
        match selectors.as_slice() {
            [selector] => (*selector).clone(),
            _ => return None,
        }
    };
    let mut tests: Vec<DispatchTest> = Vec::with_capacity(raw.len());
    for (lhs, rhs, condition, target) in raw {
        let case_const: Expr = if lhs == selector {
            rhs
        } else if rhs == selector {
            lhs
        } else {
            return None;
        };
        tests.push(DispatchTest {
            case_const,
            condition,
            target,
        });
    }
    Some((selector, tests, idx))
}

fn combine_loose_dispatch_conditions(
    conditions: Vec<Expr>,
) -> core::result::Result<Expr, &'static str> {
    let mut conditions: std::vec::IntoIter<Expr> = conditions.into_iter();
    let mut combined: Expr = conditions.next().ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
    for condition in conditions {
        combined = Expr::Binary {
            op: "||",
            lhs: Box::new(combined),
            rhs: Box::new(condition),
        };
    }
    Ok(combined)
}

fn build_loose_forward_dispatch(
    arms: Vec<ForwardDispatchArm>,
    default_body: Vec<Stmt>,
) -> core::result::Result<Stmt, &'static str> {
    if arms.is_empty() || arms.iter().any(|arm: &ForwardDispatchArm| !arm.breaks) {
        return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
    }
    let mut else_body: Vec<Stmt> = default_body;
    for arm in arms.into_iter().rev() {
        let condition: Expr = combine_loose_dispatch_conditions(arm.loose_conditions)?;
        else_body = vec![Stmt::IfElse {
            cond: condition,
            then_body: arm.body,
            else_body,
        }];
    }
    let Some(statement): Option<Stmt> = else_body.pop() else {
        return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
    };
    if !else_body.is_empty() {
        return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
    }
    Ok(statement)
}

fn build_strict_forward_dispatch(
    selector: Expr,
    arms: Vec<ForwardDispatchArm>,
    default_body: Vec<Stmt>,
    default_breaks: bool,
) -> Stmt {
    let mut cases: Vec<SwitchCase> = arms
        .into_iter()
        .map(|arm: ForwardDispatchArm| SwitchCase {
            labels: arm
                .case_consts
                .iter()
                .map(|case_const: &Expr| const_to_case_label(case_const))
                .collect(),
            body: arm.body,
            breaks: arm.breaks,
        })
        .collect();
    cases.push(SwitchCase {
        labels: vec![CaseLabel::Default],
        body: default_body,
        breaks: default_breaks,
    });
    Stmt::StructuredSwitch { selector, cases }
}

fn const_to_case_label(e: &Expr) -> CaseLabel {
    match e {
        Expr::IntLit(v) => CaseLabel::Value(*v),
        Expr::UintLit(v) => {
            i64::try_from(*v).map_or_else(|_| CaseLabel::Expr(e.clone()), CaseLabel::Value)
        }
        other => CaseLabel::Expr(other.clone()),
    }
}

fn structure_forward_dispatch_body(
    stmts: &[Stmt],
    body_slice: &[Stmt],
    merge_label: usize,
    depth: usize,
) -> Option<Vec<Stmt>> {
    let body_slice: &[Stmt] = match body_slice.last() {
        Some(Stmt::Jump { target_label }) if *target_label == merge_label => {
            &body_slice[..body_slice.len() - 1]
        }
        _ => body_slice,
    };
    if !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let inner_depth: usize = depth - 1;
    let body: Vec<Stmt> = structure_if_blocks(
        structure_loops(
            structure_switches(body_slice.to_vec(), inner_depth),
            inner_depth,
        ),
        inner_depth,
    );
    slice_is_structured(&body).then_some(body)
}

fn forward_dispatch_follow(
    region: &[Stmt],
    case_label_positions: &[(usize, usize)],
) -> Option<usize> {
    let mut follow: Option<usize> = None;
    for (index, (label_pos, _)) in case_label_positions.iter().enumerate() {
        let segment_end: usize = case_label_positions
            .get(index + 1)
            .map_or(region.len(), |(next_pos, _): &(usize, usize)| *next_pos);
        let tail: &Stmt = region.get(label_pos + 1..segment_end)?.last()?;
        let target_label: &usize = match tail {
            Stmt::Jump { target_label } => target_label,
            Stmt::Return(_) | Stmt::Throw(_) => continue,
            _ => return None,
        };
        match follow {
            Some(existing) if existing != *target_label => return None,
            Some(_) => {}
            None => follow = Some(*target_label),
        }
    }
    follow
}

fn try_match_tail_dispatch(stmts: &[Stmt], index: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Jump {
        target_label: dispatch_label,
    }: &Stmt = &stmts[index]
    else {
        return None;
    };
    let dispatch_label: usize = *dispatch_label;
    let dispatch_position: usize = stmts[index + 1..]
        .iter()
        .position(
            |statement: &Stmt| matches!(statement, Stmt::Label(label) if *label == dispatch_label),
        )
        .map(|position: usize| index + 1 + position)?;
    if dispatch_position <= index + 1 {
        return None;
    }
    let (selector, tests, after_tests): (Expr, Vec<DispatchTest>, usize) =
        collect_dispatch_tests(stmts, dispatch_position + 1)?;
    if tests.iter().any(|test: &DispatchTest| {
        !matches!(
            &test.condition,
            Expr::Binary { op: "===", lhs, rhs }
                if forward_dispatch_operand_is_stable(lhs)
                    && forward_dispatch_operand_is_stable(rhs)
        )
    }) {
        return None;
    }
    let region: &[Stmt] = &stmts[index + 1..dispatch_position];
    let mut target_consts: BTreeMap<usize, Vec<Expr>> = BTreeMap::new();
    for test in &tests {
        if !region.iter().any(
            |statement: &Stmt| matches!(statement, Stmt::Label(label) if *label == test.target),
        ) {
            return None;
        }
        target_consts
            .entry(test.target)
            .or_default()
            .push(test.case_const.clone());
    }
    let case_label_positions: Vec<(usize, usize)> = region
        .iter()
        .enumerate()
        .filter_map(|(position, statement): (usize, &Stmt)| match statement {
            Stmt::Label(label) => Some((position, *label)),
            _ => None,
        })
        .collect();
    if case_label_positions.is_empty() || case_label_positions[0].0 != 0 {
        return None;
    }
    for (_, label) in &case_label_positions {
        if !target_consts.contains_key(label) {
            return None;
        }
    }
    let merge_label: usize = match stmts.get(after_tests) {
        Some(Stmt::Label(label)) => *label,
        Some(Stmt::Jump { target_label }) => *target_label,
        _ => forward_dispatch_follow(region, &case_label_positions)?,
    };
    if target_consts.contains_key(&merge_label) {
        return None;
    }
    let end: usize = stmts[after_tests..]
        .iter()
        .position(
            |statement: &Stmt| matches!(statement, Stmt::Label(label) if *label == merge_label),
        )
        .map(|position: usize| after_tests + position)?;
    let mut cases: Vec<SwitchCase> = Vec::with_capacity(case_label_positions.len() + 1);
    for (case_index, (label_pos, label)) in case_label_positions.iter().enumerate() {
        let body_start: usize = label_pos + 1;
        let body_end: usize = case_label_positions
            .get(case_index + 1)
            .map_or(region.len(), |(next_pos, _): &(usize, usize)| *next_pos);
        let segment: &[Stmt] = &region[body_start..body_end];
        let (body_slice, breaks): (&[Stmt], bool) = match segment.last() {
            Some(Stmt::Jump { target_label }) if *target_label == merge_label => {
                (&segment[..segment.len() - 1], true)
            }
            _ => (segment, false),
        };
        let body: Vec<Stmt> =
            structure_forward_dispatch_body(stmts, body_slice, merge_label, depth)?;
        let labels: Vec<CaseLabel> = target_consts
            .get(label)?
            .iter()
            .map(const_to_case_label)
            .collect();
        cases.push(SwitchCase {
            labels,
            body,
            breaks,
        });
    }
    let default_body: Vec<Stmt> =
        structure_forward_dispatch_body(stmts, &stmts[after_tests..end], merge_label, depth)?;
    cases.push(SwitchCase {
        labels: vec![CaseLabel::Default],
        body: default_body,
        breaks: false,
    });
    Some((end - index, Stmt::StructuredSwitch { selector, cases }))
}

fn forward_dispatch_segment(
    case_positions: &[usize],
    first_case: usize,
    statement: usize,
) -> Option<usize> {
    if statement < first_case {
        return Some(usize::MAX);
    }
    switch_case_index(case_positions, statement)
}

fn validate_forward_dispatch_region(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    dispatch_start: usize,
    after_tests: usize,
    case_positions: &[usize],
    merge_pos: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<(), &'static str> {
    let Some(first_case): Option<usize> = case_positions.first().copied() else {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    };
    let case_position_set: BTreeSet<usize> = case_positions.iter().copied().collect();
    for target in after_tests..merge_pos {
        if !fuel.charge(1) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        let Some(predecessors): Option<&BTreeSet<usize>> = cfg.predecessors.get(target) else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if !fuel.charge(predecessors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        for source in predecessors {
            if *source >= dispatch_start
                && *source < after_tests
                && case_position_set.contains(&target)
            {
                continue;
            }
            if source.saturating_add(1) == after_tests && target == after_tests {
                continue;
            }
            if *source < after_tests || *source >= merge_pos {
                return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
            }
        }
    }
    for source in after_tests..merge_pos {
        if !fuel.charge(1) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        let Some(source_segment): Option<usize> =
            forward_dispatch_segment(case_positions, first_case, source)
        else {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        };
        let Some(successors): Option<&BTreeSet<usize>> = cfg.successors.get(source) else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if !fuel.charge(successors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        for target in successors {
            if *target == merge_pos {
                continue;
            }
            if *target < after_tests || *target >= merge_pos {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            }
            let Some(target_segment): Option<usize> =
                forward_dispatch_segment(case_positions, first_case, *target)
            else {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            };
            if source_segment == target_segment {
                continue;
            }
            let is_case_fallthrough: bool = source_segment != usize::MAX
                && target_segment == source_segment.saturating_add(1)
                && source.saturating_add(1) == *target
                && case_position_set.contains(target);
            if !is_case_fallthrough {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            }
        }
    }
    if stmts[dispatch_start..merge_pos]
        .iter()
        .any(|statement: &Stmt| statement_has_invalid_target(statement, &cfg.label_positions))
    {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    }
    Ok(())
}

fn try_match_direct_forward_dispatch(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    index: usize,
    depth: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<Option<(usize, Stmt)>, &'static str> {
    if depth == 0 {
        return Ok(None);
    }
    if index
        .checked_sub(1)
        .and_then(|previous: usize| stmts.get(previous))
        .is_some_and(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
    {
        return Ok(None);
    }
    let Some(comparison): Option<ForwardDispatchComparison> =
        preflight_forward_dispatch(stmts, index, fuel)?
    else {
        return Ok(None);
    };
    let (selector, tests, after_tests): (Expr, Vec<DispatchTest>, usize) =
        match collect_dispatch_tests(stmts, index) {
            Some(plan) => plan,
            None => return Ok(None),
        };
    let mut target_consts: BTreeMap<usize, Vec<Expr>> = BTreeMap::new();
    let mut target_conditions: BTreeMap<usize, Vec<Expr>> = BTreeMap::new();
    let mut case_positions: Vec<usize> = Vec::new();
    let mut last_target: Option<usize> = None;
    for (test_index, test) in tests.iter().enumerate() {
        if !fuel.charge(test_index) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        if tests[..test_index].iter().any(|previous: &DispatchTest| {
            previous.case_const == test.case_const && previous.target != test.target
        }) {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        }
        let Some(target_position): Option<usize> = cfg.label_positions.get(&test.target).copied()
        else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if target_position <= index.saturating_add(test_index) {
            return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
        }
        if target_position < after_tests {
            return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
        }
        if target_consts.contains_key(&test.target) && last_target != Some(test.target) {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        }
        if !target_consts.contains_key(&test.target) {
            if case_positions
                .last()
                .is_some_and(|previous: &usize| *previous >= target_position)
            {
                return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
            }
            case_positions.push(target_position);
        }
        let case_values: &mut Vec<Expr> = target_consts.entry(test.target).or_default();
        if !fuel.charge(case_values.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        if !case_values.contains(&test.case_const) {
            case_values.push(test.case_const.clone());
        }
        target_conditions
            .entry(test.target)
            .or_default()
            .push(test.condition.clone());
        last_target = Some(test.target);
    }
    let first_case: usize = case_positions
        .first()
        .copied()
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    if first_case <= after_tests {
        return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
    }
    let default_segment: &[Stmt] = &stmts[after_tests..first_case];
    let merge_label: usize = match default_segment.last() {
        Some(Stmt::Jump { target_label }) => *target_label,
        _ => return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER),
    };
    if target_consts.contains_key(&merge_label) {
        return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
    }
    let merge_pos: usize = cfg
        .label_positions
        .get(&merge_label)
        .copied()
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    if case_positions
        .last()
        .is_none_or(|last_case: &usize| merge_pos <= *last_case)
    {
        return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
    }
    if !fuel.charge(merge_pos.saturating_sub(index)) {
        return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
    }
    if stmts[index..merge_pos].iter().any(|statement: &Stmt| {
        matches!(statement, Stmt::Comment(reason) if reason == STACK_CONFLICT_MARKER || reason == STACK_HEIGHT_CONFLICT_MARKER)
    }) {
        return Err(STACK_HEIGHT_CONFLICT_MARKER);
    }
    validate_forward_dispatch_region(
        stmts,
        cfg,
        index,
        after_tests,
        &case_positions,
        merge_pos,
        fuel,
    )?;

    let mut arms: Vec<ForwardDispatchArm> = Vec::with_capacity(case_positions.len());
    for (case_index, label_pos) in case_positions.iter().enumerate() {
        let body_start: usize = label_pos.saturating_add(1);
        let body_end: usize = case_positions
            .get(case_index.saturating_add(1))
            .copied()
            .unwrap_or(merge_pos);
        let segment: &[Stmt] = &stmts[body_start..body_end];
        let (body_slice, breaks): (&[Stmt], bool) = match segment.last() {
            Some(Stmt::Jump { target_label }) if *target_label == merge_label => {
                (&segment[..segment.len() - 1], true)
            }
            _ => (
                segment,
                case_index.saturating_add(1) == case_positions.len(),
            ),
        };
        let body: Vec<Stmt> =
            structure_forward_dispatch_body(stmts, body_slice, merge_label, depth)
                .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
        let label: usize = match stmts.get(*label_pos) {
            Some(Stmt::Label(label)) => *label,
            _ => return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER),
        };
        let case_consts: Vec<Expr> = target_consts
            .get(&label)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?
            .clone();
        let loose_conditions: Vec<Expr> = target_conditions
            .get(&label)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?
            .clone();
        arms.push(ForwardDispatchArm {
            case_consts,
            loose_conditions,
            body,
            breaks,
        });
    }
    let default_body_slice: &[Stmt] = &default_segment[..default_segment.len().saturating_sub(1)];
    let default_body: Vec<Stmt> =
        structure_forward_dispatch_body(stmts, default_body_slice, merge_label, depth)
            .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
    let stmt: Stmt = match comparison {
        ForwardDispatchComparison::Strict => {
            build_strict_forward_dispatch(selector, arms, default_body, true)
        }
        ForwardDispatchComparison::Loose => build_loose_forward_dispatch(arms, default_body)?,
    };
    Ok(Some((merge_pos - index, stmt)))
}

fn inverted_forward_dispatch_operands(cond: &Expr) -> Option<(Expr, Expr, bool)> {
    let Expr::Binary { op, lhs, rhs } = cond else {
        return None;
    };
    match *op {
        "!==" => Some(((**lhs).clone(), (**rhs).clone(), true)),
        "!=" => Some(((**lhs).clone(), (**rhs).clone(), false)),
        _ => None,
    }
}

fn try_match_inverted_forward_dispatch(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    index: usize,
    depth: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<Option<(usize, Stmt)>, &'static str> {
    if depth == 0 {
        return Ok(None);
    }
    let mut cursor: usize = index;
    let mut tests: Vec<InvertedDispatchTest> = Vec::new();
    let mut merge_label: Option<usize> = None;
    while let Some(Stmt::If { cond, target_label }) = stmts.get(cursor) {
        let Some((lhs, rhs, comparison_is_strict)): Option<(Expr, Expr, bool)> =
            inverted_forward_dispatch_operands(cond)
        else {
            break;
        };
        let Some(next_test): Option<usize> = cfg.label_positions.get(target_label).copied() else {
            return if tests.len() >= 2 {
                Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER)
            } else {
                Ok(None)
            };
        };
        if next_test <= cursor.saturating_add(1) {
            return if tests.len() >= 2 {
                Err(SWITCH_DIRECTION_REFUSAL_MARKER)
            } else {
                Ok(None)
            };
        }
        let body_start: usize = cursor.saturating_add(1);
        let body_tail: usize = next_test.saturating_sub(1);
        let (body_end, breaks, case_merge): (usize, bool, usize) = match stmts.get(body_tail) {
            Some(Stmt::Jump { target_label }) => (body_tail, true, *target_label),
            _ if merge_label == Some(*target_label) => (next_test, false, *target_label),
            _ => break,
        };
        match merge_label {
            Some(expected) if expected != case_merge => {
                return if tests.len() >= 2 {
                    Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)
                } else {
                    Ok(None)
                };
            }
            Some(_) => {}
            None => merge_label = Some(case_merge),
        }
        if !fuel.charge(next_test.saturating_sub(cursor)) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        tests.push(InvertedDispatchTest {
            lhs,
            rhs,
            body_start,
            body_end,
            breaks,
            comparison_is_strict,
        });
        let miss_reaches_merge: bool = merge_label == Some(*target_label);
        cursor = if miss_reaches_merge {
            next_test
        } else {
            next_test.saturating_add(1)
        };
        if miss_reaches_merge {
            break;
        }
    }
    if tests.len() < 2 {
        return Ok(None);
    }
    let comparisons_are_strict: bool = tests
        .iter()
        .all(|test: &InvertedDispatchTest| test.comparison_is_strict);
    let comparisons_are_loose: bool = tests
        .iter()
        .all(|test: &InvertedDispatchTest| !test.comparison_is_strict);
    let comparison: ForwardDispatchComparison = if comparisons_are_strict {
        ForwardDispatchComparison::Strict
    } else if comparisons_are_loose {
        ForwardDispatchComparison::Loose
    } else {
        return Err(SWITCH_COMPARISON_REFUSAL_MARKER);
    };
    if tests.iter().any(|test: &InvertedDispatchTest| {
        !forward_dispatch_operand_is_stable(&test.lhs)
            || !forward_dispatch_operand_is_stable(&test.rhs)
    }) {
        return Err(SWITCH_EFFECT_REFUSAL_MARKER);
    }
    let selector_candidates: [&Expr; 2] = [&tests[0].lhs, &tests[0].rhs];
    if !fuel.charge(tests.len().saturating_mul(selector_candidates.len())) {
        return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
    }
    let selectors: Vec<&Expr> = selector_candidates
        .into_iter()
        .filter(|candidate: &&Expr| {
            tests.iter().all(|test: &InvertedDispatchTest| {
                (test.lhs == **candidate) != (test.rhs == **candidate)
            })
        })
        .collect();
    let selector: Expr = match selectors.as_slice() {
        [selector] => (*selector).clone(),
        _ => return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER),
    };
    let merge_label: usize = merge_label.ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    let merge_pos: usize = cfg
        .label_positions
        .get(&merge_label)
        .copied()
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    if merge_pos < cursor {
        return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
    }
    if !fuel.charge(merge_pos.saturating_sub(index)) {
        return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
    }
    if stmts[index..merge_pos].iter().any(|statement: &Stmt| {
        matches!(statement, Stmt::Comment(reason) if reason == STACK_CONFLICT_MARKER || reason == STACK_HEIGHT_CONFLICT_MARKER)
    }) {
        return Err(STACK_HEIGHT_CONFLICT_MARKER);
    }
    for position in index.saturating_add(1)..merge_pos {
        let predecessors: &BTreeSet<usize> = cfg
            .predecessors
            .get(position)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
        if !fuel.charge(predecessors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        if predecessors
            .iter()
            .any(|source: &usize| *source < index || *source >= merge_pos)
        {
            return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
        }
    }
    for position in index..merge_pos {
        let successors: &BTreeSet<usize> = cfg
            .successors
            .get(position)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
        if !fuel.charge(successors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        if successors
            .iter()
            .any(|target: &usize| *target < index || *target > merge_pos)
        {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        }
    }
    if stmts[index..merge_pos]
        .iter()
        .any(|statement: &Stmt| statement_has_invalid_target(statement, &cfg.label_positions))
    {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    }

    let mut seen_values: Vec<Expr> = Vec::with_capacity(tests.len());
    let mut arms: Vec<ForwardDispatchArm> = Vec::with_capacity(tests.len());
    for test in &tests {
        let case_const: Expr = if test.lhs == selector {
            test.rhs.clone()
        } else if test.rhs == selector {
            test.lhs.clone()
        } else {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        };
        if !fuel.charge(seen_values.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        if seen_values.contains(&case_const) {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        }
        seen_values.push(case_const.clone());
        let body: Vec<Stmt> = structure_forward_dispatch_body(
            stmts,
            &stmts[test.body_start..test.body_end],
            merge_label,
            depth,
        )
        .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
        let loose_condition: Expr = Expr::Binary {
            op: "==",
            lhs: Box::new(test.lhs.clone()),
            rhs: Box::new(test.rhs.clone()),
        };
        arms.push(ForwardDispatchArm {
            case_consts: vec![case_const],
            loose_conditions: vec![loose_condition],
            body,
            breaks: test.breaks,
        });
    }
    let default_segment: &[Stmt] = &stmts[cursor..merge_pos];
    let (default_body_slice, default_breaks): (&[Stmt], bool) = match default_segment.last() {
        Some(Stmt::Jump { target_label }) if *target_label == merge_label => (
            &default_segment[..default_segment.len().saturating_sub(1)],
            true,
        ),
        _ => (default_segment, false),
    };
    let default_body: Vec<Stmt> =
        structure_forward_dispatch_body(stmts, default_body_slice, merge_label, depth)
            .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
    let statement: Stmt = match comparison {
        ForwardDispatchComparison::Strict => {
            build_strict_forward_dispatch(selector, arms, default_body, default_breaks)
        }
        ForwardDispatchComparison::Loose => build_loose_forward_dispatch(arms, default_body)?,
    };

    Ok(Some((merge_pos.saturating_sub(index), statement)))
}

fn try_match_forward_dispatch(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    index: usize,
    depth: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<Option<(usize, Stmt)>, &'static str> {
    if let Some(matched) = try_match_direct_forward_dispatch(stmts, cfg, index, depth, fuel)? {
        return Ok(Some(matched));
    }
    if let Some(matched) = try_match_inverted_forward_dispatch(stmts, cfg, index, depth, fuel)? {
        return Ok(Some(matched));
    }
    Ok(try_match_tail_dispatch(stmts, index, depth))
}

fn structure_forward_dispatch(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let cfg: StatementCfg = StatementCfg::new(&stmts);
    let mut fuel: SwitchAnalysisFuel = SwitchAnalysisFuel::new();
    let mut i: usize = 0;
    while i < stmts.len() {
        if let Stmt::With { object, body } = &stmts[i] {
            out.push(Stmt::With {
                object: object.clone(),
                body: structure_forward_dispatch(body.clone(), depth - 1),
            });
            i += 1;
            continue;
        }
        match try_match_forward_dispatch(&stmts, &cfg, i, depth, &mut fuel) {
            Ok(Some((consumed, stmt))) => {
                out.push(stmt);
                i += consumed;
                continue;
            }
            Ok(None) => {}
            Err(reason) => {
                let already_recorded: bool = out
                    .last()
                    .is_some_and(|statement: &Stmt| matches!(statement, Stmt::Comment(existing) if existing == reason));
                if !already_recorded {
                    out.push(Stmt::Comment(reason.to_owned()));
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

fn structure_switches(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let cfg: StatementCfg = StatementCfg::new(&stmts);
    let mut fuel: SwitchAnalysisFuel = SwitchAnalysisFuel::new();
    let mut i: usize = 0;
    while i < stmts.len() {
        if let Stmt::With { object, body } = &stmts[i] {
            out.push(Stmt::With {
                object: object.clone(),
                body: structure_switches(body.clone(), depth - 1),
            });
            i += 1;
            continue;
        }
        match try_match_switch(&stmts, &cfg, i, depth, &mut fuel) {
            Ok(Some((consumed, stmt))) => {
                out.push(stmt);
                i += consumed;
                continue;
            }
            Ok(None) => {}
            Err(reason) => {
                let already_recorded: bool = out
                    .last()
                    .is_some_and(|statement: &Stmt| matches!(statement, Stmt::Comment(existing) if existing == reason));
                if !already_recorded {
                    out.push(Stmt::Comment(reason.to_owned()));
                }
            }
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

struct SwitchPlan {
    target_keys: BTreeMap<usize, Vec<CaseLabel>>,
    ordered_targets: Vec<usize>,
    label_pos: BTreeMap<usize, usize>,
}

struct StatementCfg {
    label_positions: BTreeMap<usize, usize>,
    successors: Vec<BTreeSet<usize>>,
    predecessors: Vec<BTreeSet<usize>>,
}

impl StatementCfg {
    fn new(stmts: &[Stmt]) -> Self {
        let label_positions: BTreeMap<usize, usize> = stmts
            .iter()
            .enumerate()
            .filter_map(|(index, statement): (usize, &Stmt)| match statement {
                Stmt::Label(label) => Some((*label, index)),
                _ => None,
            })
            .collect();
        let mut successors: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); stmts.len()];
        for (index, statement) in stmts.iter().enumerate() {
            let next: Option<usize> = index
                .checked_add(1)
                .filter(|next: &usize| *next < stmts.len());
            match statement {
                Stmt::Jump { target_label } => {
                    if let Some(target) = label_positions.get(target_label) {
                        successors[index].insert(*target);
                    }
                }
                Stmt::If { target_label, .. } => {
                    if let Some(target) = label_positions.get(target_label) {
                        successors[index].insert(*target);
                    }
                    successors[index].extend(next);
                }
                Stmt::Switch {
                    case_labels,
                    default_label,
                    ..
                } => {
                    successors[index].extend(
                        case_labels
                            .iter()
                            .chain(std::iter::once(default_label))
                            .filter_map(|label: &usize| label_positions.get(label))
                            .copied(),
                    );
                }
                Stmt::Return(_) | Stmt::Throw(_) => {}
                _ => successors[index].extend(next),
            }
        }
        let mut predecessors: Vec<BTreeSet<usize>> = vec![BTreeSet::new(); stmts.len()];
        for (source, targets) in successors.iter().enumerate() {
            for target in targets {
                predecessors[*target].insert(source);
            }
        }
        Self {
            label_positions,
            successors,
            predecessors,
        }
    }
}

fn plan_switch(
    cfg: &StatementCfg,
    sw: usize,
    case_labels: &[usize],
    default_label: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<SwitchPlan, &'static str> {
    if !fuel.charge(case_labels.len().saturating_add(1)) {
        return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
    }
    let mut target_keys: BTreeMap<usize, Vec<CaseLabel>> = BTreeMap::new();
    for (value, target) in case_labels.iter().enumerate() {
        target_keys
            .entry(*target)
            .or_default()
            .push(CaseLabel::Value(value as i64));
    }
    target_keys
        .entry(default_label)
        .or_default()
        .push(CaseLabel::Default);
    let mut label_pos: BTreeMap<usize, usize> = BTreeMap::new();
    for target in target_keys.keys() {
        let Some(pos): Option<usize> = cfg.label_positions.get(target).copied() else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if pos <= sw {
            return Err(SWITCH_DIRECTION_REFUSAL_MARKER);
        }
        label_pos.insert(*target, pos);
    }
    let mut ordered_targets: Vec<usize> = target_keys.keys().copied().collect();
    ordered_targets.sort_by_key(|t: &usize| label_pos[t]);
    Ok(SwitchPlan {
        target_keys,
        ordered_targets,
        label_pos,
    })
}

fn switch_merge_pos(
    stmts: &[Stmt],
    plan: &SwitchPlan,
    last_start: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> Option<usize> {
    let case_label_positions: BTreeSet<usize> = plan
        .label_pos
        .values()
        .copied()
        .collect::<BTreeSet<usize>>();
    for (idx, stmt) in stmts.iter().enumerate().skip(last_start + 1) {
        if !fuel.charge(1) {
            return None;
        }
        if let Stmt::Label(l) = stmt
            && !case_label_positions.contains(&idx)
            && label_ref_count(stmts, *l) >= 1
        {
            return Some(idx);
        }
    }
    Some(stmts.len())
}

fn default_target_is_the_join(
    stmts: &[Stmt],
    plan: &SwitchPlan,
    sw: usize,
    scanned_merge: usize,
    default_label: usize,
) -> bool {
    if scanned_merge < stmts.len() || plan.ordered_targets.len() < 2 {
        return false;
    }
    if plan.ordered_targets.last() != Some(&default_label) {
        return false;
    }
    let Some(&last_start): Option<&usize> = plan.label_pos.get(&default_label) else {
        return false;
    };
    if last_start <= sw {
        return false;
    }
    let Some(region): Option<&[Stmt]> = stmts.get(sw + 1..last_start) else {
        return false;
    };
    label_ref_count(region, default_label) > 0
        && label_ref_count(stmts, default_label) == label_ref_count(region, default_label)
}

fn statement_has_invalid_target(statement: &Stmt, labels: &BTreeMap<usize, usize>) -> bool {
    match statement {
        Stmt::Jump { target_label } | Stmt::If { target_label, .. } => {
            !labels.contains_key(target_label)
        }
        Stmt::Switch {
            case_labels,
            default_label,
            ..
        } => {
            !labels.contains_key(default_label)
                || case_labels
                    .iter()
                    .any(|label: &usize| !labels.contains_key(label))
        }
        _ => false,
    }
}

fn switch_case_index(case_positions: &[usize], statement: usize) -> Option<usize> {
    case_positions
        .partition_point(|position: &usize| *position <= statement)
        .checked_sub(1)
}

fn validate_switch_region(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    sw: usize,
    plan: &SwitchPlan,
    merge_pos: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<(), &'static str> {
    let first_start: usize = *plan
        .label_pos
        .get(
            plan.ordered_targets
                .first()
                .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?,
        )
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    if first_start != sw.saturating_add(1) {
        return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
    }
    if merge_pos < first_start || merge_pos > stmts.len() {
        return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
    }
    let dispatch_targets: BTreeSet<usize> = plan.label_pos.values().copied().collect();
    let Some(actual_dispatch_targets): Option<&BTreeSet<usize>> = cfg.successors.get(sw) else {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    };
    if actual_dispatch_targets != &dispatch_targets {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    }
    if stmts[first_start..merge_pos]
        .iter()
        .any(|statement: &Stmt| statement_has_invalid_target(statement, &cfg.label_positions))
    {
        return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
    }
    let case_positions: Vec<usize> = dispatch_targets
        .iter()
        .copied()
        .filter(|position: &usize| *position < merge_pos)
        .collect();
    let case_position_set: BTreeSet<usize> = case_positions.iter().copied().collect();
    for target in first_start..merge_pos {
        if !fuel.charge(1) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        let Some(predecessors): Option<&BTreeSet<usize>> = cfg.predecessors.get(target) else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if !fuel.charge(predecessors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        for source in predecessors {
            if *source == sw && case_position_set.contains(&target) {
                continue;
            }
            if *source < first_start || *source >= merge_pos {
                return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
            }
        }
    }
    for source in first_start..merge_pos {
        if !fuel.charge(1) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        let Some(source_case): Option<usize> = switch_case_index(&case_positions, source) else {
            return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
        };
        let Some(successors): Option<&BTreeSet<usize>> = cfg.successors.get(source) else {
            return Err(SWITCH_INVALID_TARGET_REFUSAL_MARKER);
        };
        if !fuel.charge(successors.len()) {
            return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
        }
        for target in successors {
            if *target == merge_pos {
                continue;
            }
            if *target < first_start || *target > merge_pos {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            }
            let Some(target_case): Option<usize> = switch_case_index(&case_positions, *target)
            else {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            };
            if source_case == target_case {
                continue;
            }
            let is_ordered_fallthrough: bool = target_case == source_case.saturating_add(1)
                && source.saturating_add(1) == *target
                && case_position_set.contains(target);
            if !is_ordered_fallthrough {
                return Err(SWITCH_IRREDUCIBLE_REFUSAL_MARKER);
            }
        }
    }
    Ok(())
}

fn build_switch_case(
    stmts: &[Stmt],
    seg_start: usize,
    seg_end: usize,
    merge_label: Option<usize>,
    keys: Vec<CaseLabel>,
    depth: usize,
) -> Option<SwitchCase> {
    let inner: &[Stmt] = &stmts[seg_start + 1..seg_end];
    let (body_slice, breaks): (&[Stmt], bool) = match inner.last() {
        Some(Stmt::Jump { target_label }) if Some(*target_label) == merge_label => {
            (&inner[..inner.len() - 1], true)
        }
        _ => (inner, false),
    };
    if !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let inner_depth: usize = depth - 1;
    let body: Vec<Stmt> = structure_if_blocks(
        structure_loops(
            structure_switches(body_slice.to_vec(), inner_depth),
            inner_depth,
        ),
        inner_depth,
    );
    if !slice_is_structured(&body) {
        return None;
    }
    Some(SwitchCase {
        labels: keys,
        body,
        breaks,
    })
}

fn try_match_switch(
    stmts: &[Stmt],
    cfg: &StatementCfg,
    sw: usize,
    depth: usize,
    fuel: &mut SwitchAnalysisFuel,
) -> core::result::Result<Option<(usize, Stmt)>, &'static str> {
    if depth == 0 {
        return Ok(None);
    }
    let Stmt::Switch {
        selector,
        case_labels,
        default_label,
    }: &Stmt = &stmts[sw]
    else {
        return Ok(None);
    };
    if sw
        .checked_sub(1)
        .and_then(|index: usize| stmts.get(index))
        .is_some_and(|statement: &Stmt| {
            matches!(
                statement,
                Stmt::Comment(reason)
                    if reason == SWITCH_DIRECTION_REFUSAL_MARKER
                        || reason == SWITCH_ANALYSIS_BUDGET_MARKER
            )
        })
    {
        return Ok(None);
    }
    let plan: SwitchPlan = plan_switch(cfg, sw, case_labels, *default_label, fuel)?;
    let first_target: &usize = plan
        .ordered_targets
        .first()
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    let first_start: usize = *plan
        .label_pos
        .get(first_target)
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    if first_start != sw + 1 {
        return Err(SWITCH_MID_ENTRY_REFUSAL_MARKER);
    }
    let last_target: &usize = plan
        .ordered_targets
        .last()
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    let last_start: usize = *plan
        .label_pos
        .get(last_target)
        .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
    let scanned_merge: usize =
        switch_merge_pos(stmts, &plan, last_start, fuel).ok_or(SWITCH_ANALYSIS_BUDGET_MARKER)?;
    if !fuel.charge(stmts.len().saturating_add(scanned_merge.saturating_sub(sw))) {
        return Err(SWITCH_ANALYSIS_BUDGET_MARKER);
    }
    let trailing_default_join: bool =
        default_target_is_the_join(stmts, &plan, sw, scanned_merge, *default_label);
    let merge_pos: usize = if trailing_default_join {
        last_start
    } else {
        scanned_merge
    };
    let conflict_end: usize = merge_pos.saturating_add(2).min(stmts.len());
    if stmts[sw + 1..conflict_end].iter().any(|statement: &Stmt| {
        matches!(
            statement,
            Stmt::Comment(reason)
                if reason == STACK_CONFLICT_MARKER
                    || reason == STACK_HEIGHT_CONFLICT_MARKER
                    || reason == SWITCH_ANALYSIS_BUDGET_MARKER
        )
    }) {
        return Ok(None);
    }
    validate_switch_region(stmts, cfg, sw, &plan, merge_pos, fuel)?;
    let merge_label: Option<usize> = match stmts.get(merge_pos) {
        Some(Stmt::Label(l)) => Some(*l),
        _ => None,
    };
    let body_targets: &[usize] = if trailing_default_join {
        plan.ordered_targets
            .get(..plan.ordered_targets.len() - 1)
            .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?
    } else {
        plan.ordered_targets.as_slice()
    };
    let mut cases: Vec<SwitchCase> = Vec::with_capacity(plan.ordered_targets.len());
    for (n, target) in body_targets.iter().enumerate() {
        let seg_start: usize = *plan
            .label_pos
            .get(target)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?;
        let seg_end: usize = match body_targets.get(n + 1) {
            Some(next) => *plan
                .label_pos
                .get(next)
                .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?,
            None => merge_pos,
        };
        let keys: Vec<CaseLabel> = plan
            .target_keys
            .get(target)
            .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?
            .clone();
        let case: SwitchCase =
            build_switch_case(stmts, seg_start, seg_end, merge_label, keys, depth)
                .ok_or(SWITCH_IRREDUCIBLE_REFUSAL_MARKER)?;
        cases.push(case);
    }
    if trailing_default_join {
        cases.push(SwitchCase {
            labels: plan
                .target_keys
                .get(default_label)
                .ok_or(SWITCH_INVALID_TARGET_REFUSAL_MARKER)?
                .clone(),
            body: Vec::new(),
            breaks: true,
        });
    }
    let stmt: Stmt = Stmt::StructuredSwitch {
        selector: selector.clone(),
        cases,
    };
    Ok(Some((merge_pos - sw, stmt)))
}

fn structure_with(stmts: Vec<Stmt>, regions: &[WithRegion], depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let mut remaining: Vec<Stmt> = stmts;
    let mut shift: usize = 0;
    loop {
        let valid: Vec<&WithRegion> = regions
            .iter()
            .filter(|r: &&WithRegion| {
                r.open_stmt >= shift
                    && r.open_stmt < r.close_stmt
                    && r.close_stmt <= shift + remaining.len()
            })
            .collect();
        let Some(outer): Option<&&WithRegion> = valid
            .iter()
            .min_by_key(|r: &&&WithRegion| (r.open_stmt, std::cmp::Reverse(r.close_stmt)))
        else {
            out.extend(remaining);
            return out;
        };
        let open: usize = outer.open_stmt - shift;
        let close: usize = outer.close_stmt - shift;
        let inner_regions: Vec<WithRegion> = regions
            .iter()
            .filter(|r: &&WithRegion| {
                r.open_stmt >= outer.open_stmt
                    && r.close_stmt <= outer.close_stmt
                    && r.open_stmt != outer.open_stmt
            })
            .map(|r: &WithRegion| WithRegion {
                open_stmt: r.open_stmt - outer.open_stmt,
                close_stmt: r.close_stmt - outer.open_stmt,
                object: r.object.clone(),
            })
            .collect();
        out.extend_from_slice(&remaining[..open]);
        let body_slice: Vec<Stmt> = remaining[open..close].to_vec();
        let body: Vec<Stmt> = structure_with(body_slice, &inner_regions, depth - 1);
        out.push(Stmt::With {
            object: outer.object.clone(),
            body,
        });
        remaining = remaining[close..].to_vec();
        shift = outer.close_stmt;
    }
}

fn structure_loops(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let mut i: usize = 0;
    while i < stmts.len() {
        if let Stmt::With { object, body } = &stmts[i] {
            out.push(Stmt::With {
                object: object.clone(),
                body: structure_loops(body.clone(), depth - 1),
            });
            i += 1;
            continue;
        }
        if let Some((consumed, stmt)) = try_match_iterator_loop(&stmts, i, depth) {
            out.push(stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, stmt)) = try_match_for(&stmts, i, depth) {
            out.push(stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, while_stmt)) = try_match_while_with_exits(&stmts, i, depth) {
            out.push(while_stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, while_stmt)) = try_match_while(&stmts, i, depth) {
            out.push(while_stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, do_stmt)) = try_match_do_while(&stmts, i, depth) {
            out.push(do_stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, while_stmt)) = try_match_top_test_while(&stmts, i, depth) {
            out.push(while_stmt);
            i += consumed;
            continue;
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

const NO_BREAK_LABEL: usize = usize::MAX;

struct LoopExits {
    continue_label: usize,
    break_label: usize,
}

fn rewrite_loop_exits(stmts: Vec<Stmt>, exits: &LoopExits) -> Option<Vec<Stmt>> {
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    for stmt in stmts {
        match stmt {
            Stmt::Jump { target_label } if target_label == exits.continue_label => {
                out.push(Stmt::Continue);
            }
            Stmt::Jump { target_label } if target_label == exits.break_label => {
                out.push(Stmt::Break);
            }
            Stmt::If { cond, target_label } if target_label == exits.continue_label => {
                out.push(Stmt::IfBlock {
                    cond,
                    body: vec![Stmt::Continue],
                });
            }
            Stmt::If { cond, target_label } if target_label == exits.break_label => {
                out.push(Stmt::IfBlock {
                    cond,
                    body: vec![Stmt::Break],
                });
            }
            Stmt::IfBlock { cond, body } => out.push(Stmt::IfBlock {
                cond,
                body: rewrite_loop_exits(body, exits)?,
            }),
            Stmt::IfElse {
                cond,
                then_body,
                else_body,
            } => out.push(Stmt::IfElse {
                cond,
                then_body: rewrite_loop_exits(then_body, exits)?,
                else_body: rewrite_loop_exits(else_body, exits)?,
            }),
            Stmt::With { object, body } => out.push(Stmt::With {
                object,
                body: rewrite_loop_exits(body, exits)?,
            }),
            Stmt::Try { body, catches } => out.push(Stmt::Try {
                body: rewrite_loop_exits(body, exits)?,
                catches: catches
                    .into_iter()
                    .map(|catch: CatchClause| {
                        rewrite_loop_exits(catch.body, exits)
                            .map(|body: Vec<Stmt>| CatchClause { body, ..catch })
                    })
                    .collect::<Option<Vec<CatchClause>>>()?,
            }),
            Stmt::StructuredSwitch { ref cases, .. } => {
                if cases.iter().any(|c: &SwitchCase| {
                    stmts_target_label(&c.body, exits.continue_label)
                        || stmts_target_label(&c.body, exits.break_label)
                }) {
                    return None;
                }
                out.push(stmt);
            }
            Stmt::While { .. }
            | Stmt::DoWhile { .. }
            | Stmt::For { .. }
            | Stmt::ForEach { .. }
            | Stmt::ForIn { .. } => out.push(stmt),
            other => out.push(other),
        }
    }
    Some(out)
}

fn stmts_target_label(stmts: &[Stmt], label: usize) -> bool {
    stmts.iter().any(|s: &Stmt| match s {
        Stmt::Jump { target_label } | Stmt::If { target_label, .. } => *target_label == label,
        Stmt::IfBlock { body, .. } | Stmt::With { body, .. } => stmts_target_label(body, label),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => stmts_target_label(then_body, label) || stmts_target_label(else_body, label),
        Stmt::Try { body, catches } => {
            stmts_target_label(body, label)
                || catches
                    .iter()
                    .any(|c: &CatchClause| stmts_target_label(&c.body, label))
        }
        Stmt::StructuredSwitch { cases, .. } => cases
            .iter()
            .any(|c: &SwitchCase| stmts_target_label(&c.body, label)),
        _ => false,
    })
}

fn try_match_while_with_exits(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Jump {
        target_label: test_label,
    }: &Stmt = &stmts[i]
    else {
        return None;
    };
    let test_label: usize = *test_label;
    let Stmt::Label(top_label): &Stmt = stmts.get(i + 1)? else {
        return None;
    };
    let top_label: usize = *top_label;
    let test_idx: usize = label_at(&stmts[i + 2..], test_label).map(|p: usize| i + 2 + p)?;
    let Stmt::If {
        cond,
        target_label: back_label,
    }: &Stmt = stmts.get(test_idx + 1)?
    else {
        return None;
    };
    if *back_label != top_label {
        return None;
    }
    let merge_label: usize = match stmts.get(test_idx + 2) {
        Some(Stmt::Label(l)) => *l,
        _ => NO_BREAK_LABEL,
    };
    let body_slice: &[Stmt] = &stmts[i + 2..test_idx];
    if !region_is_structurable(body_slice) {
        return None;
    }
    if label_ref_count(stmts, top_label) != 1 {
        return None;
    }
    let inner_continue_only: usize = body_slice
        .iter()
        .filter(|s: &&Stmt| {
            matches!(
                s,
                Stmt::Jump { target_label } | Stmt::If { target_label, .. }
                    if *target_label == test_label
            )
        })
        .count();
    let outer_test_refs: usize = label_ref_count(stmts, test_label);
    if outer_test_refs != inner_continue_only + 1 {
        return None;
    }
    if !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let exits: LoopExits = LoopExits {
        continue_label: test_label,
        break_label: merge_label,
    };
    let rewritten: Vec<Stmt> = rewrite_loop_exits(body_slice.to_vec(), &exits)?;
    let body: Vec<Stmt> =
        structure_acyclic(&structure_loops(rewritten, depth - 1), None, depth - 1)?;
    if !body.iter().any(loop_has_real_exit) {
        return None;
    }
    let while_stmt: Stmt = Stmt::While {
        cond: cond.clone(),
        body,
    };
    let consumed: usize = test_idx + 2 - i;
    Some((consumed, while_stmt))
}

fn body_is_structured_with_exits(slice: &[Stmt]) -> bool {
    slice.iter().all(|s: &Stmt| match s {
        Stmt::Label(_) | Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Switch { .. } => false,
        Stmt::IfBlock { body, .. } | Stmt::With { body, .. } => body_is_structured_with_exits(body),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => body_is_structured_with_exits(then_body) && body_is_structured_with_exits(else_body),
        Stmt::Try { body, catches } => {
            body_is_structured_with_exits(body)
                && catches
                    .iter()
                    .all(|c: &CatchClause| body_is_structured_with_exits(&c.body))
        }
        Stmt::StructuredSwitch { cases, .. } => cases
            .iter()
            .all(|c: &SwitchCase| body_is_structured_with_exits(&c.body)),
        _ => true,
    })
}

fn loop_has_real_exit(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Break | Stmt::Continue => true,
        Stmt::IfBlock { body, .. } | Stmt::With { body, .. } => body.iter().any(loop_has_real_exit),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => then_body.iter().any(loop_has_real_exit) || else_body.iter().any(loop_has_real_exit),
        Stmt::Try { body, catches } => {
            body.iter().any(loop_has_real_exit)
                || catches
                    .iter()
                    .any(|c: &CatchClause| c.body.iter().any(loop_has_real_exit))
        }
        Stmt::StructuredSwitch { cases, .. } => cases
            .iter()
            .any(|c: &SwitchCase| c.body.iter().any(loop_has_real_exit)),
        _ => false,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IteratorKind {
    Each,
    In,
}

fn iterator_var_binding(stmt: &Stmt) -> Option<(Expr, Expr, IteratorKind)> {
    let (var, value): (Expr, &Expr) = match stmt {
        Stmt::Assign { target, value } => (target.clone(), value),
        Stmt::AssignProperty {
            object,
            property,
            value,
        } => (
            Expr::Get {
                object: Box::new(object.clone()),
                property: property.clone(),
            },
            value,
        ),
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => (
            Expr::Index {
                object: Box::new(object.clone()),
                index: Box::new(index.clone()),
            },
            value,
        ),
        _ => return None,
    };
    match value {
        Expr::Coerce { operand, .. } => iterator_call(&var, operand),
        other => iterator_call(&var, other),
    }
}

fn iterator_call(var: &Expr, value: &Expr) -> Option<(Expr, Expr, IteratorKind)> {
    let Expr::Call {
        callee,
        property,
        args,
    } = value
    else {
        return None;
    };
    if args.len() != 1 {
        return None;
    }
    let kind: IteratorKind = match property.as_str() {
        "nextValue" => IteratorKind::Each,
        "nextName" => IteratorKind::In,
        _ => return None,
    };
    Some(((*var).clone(), (**callee).clone(), kind))
}

fn try_match_iterator_loop(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Jump {
        target_label: test_label,
    } = &stmts[i]
    else {
        return None;
    };
    let test_label: usize = *test_label;
    let Stmt::Label(top_label) = stmts.get(i + 1)? else {
        return None;
    };
    let top_label: usize = *top_label;
    let test_idx: usize = label_at(&stmts[i + 2..], test_label).map(|p: usize| i + 2 + p)?;
    let Stmt::If {
        cond,
        target_label: back_label,
    } = stmts.get(test_idx + 1)?
    else {
        return None;
    };
    if *back_label != top_label {
        return None;
    }
    let (collection, _idx_expr): (Expr, Expr) = hasnext_cond(cond)?;
    let inner: &[Stmt] = &stmts[i + 2..test_idx];
    let (var, src_collection, kind): (Expr, Expr, IteratorKind) =
        iterator_var_binding(inner.first()?)?;
    if collection != src_collection {
        return None;
    }
    if label_ref_count(stmts, top_label) != 1 {
        return None;
    }
    let body_slice: &[Stmt] = &inner[1..];
    if !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let body: Vec<Stmt> = if label_ref_count(stmts, test_label) == 1 {
        structure_acyclic(
            &structure_loops(body_slice.to_vec(), depth - 1),
            None,
            depth - 1,
        )?
    } else {
        let merge_label: usize = match stmts.get(test_idx + 2) {
            Some(Stmt::Label(l)) => *l,
            _ => NO_BREAK_LABEL,
        };
        let inner_continue_only: usize = body_slice
            .iter()
            .filter(|s: &&Stmt| {
                matches!(
                    s,
                    Stmt::Jump { target_label } | Stmt::If { target_label, .. }
                        if *target_label == test_label
                )
            })
            .count();
        if label_ref_count(stmts, test_label) != inner_continue_only + 1 {
            return None;
        }
        let exits: LoopExits = LoopExits {
            continue_label: test_label,
            break_label: merge_label,
        };
        let rewritten: Vec<Stmt> = rewrite_loop_exits(body_slice.to_vec(), &exits)?;
        structure_acyclic(&structure_loops(rewritten, depth - 1), None, depth - 1)?
    };
    let stmt: Stmt = match kind {
        IteratorKind::Each => Stmt::ForEach {
            var,
            collection,
            body,
        },
        IteratorKind::In => Stmt::ForIn {
            var,
            collection,
            body,
        },
    };
    let consumed: usize = test_idx + 2 - i;
    Some((consumed, stmt))
}

fn hasnext_cond(cond: &Expr) -> Option<(Expr, Expr)> {
    let Expr::Call {
        callee,
        property,
        args,
    } = cond
    else {
        return None;
    };
    if property != "hasNext" || args.len() != 1 {
        return None;
    }
    Some(((**callee).clone(), args[0].clone()))
}

fn try_match_for(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let init: &Stmt = match &stmts[i] {
        s @ (Stmt::Assign { .. } | Stmt::AssignProperty { .. } | Stmt::AssignIndex { .. }) => s,
        _ => return None,
    };
    let Stmt::Jump {
        target_label: test_label,
    } = stmts.get(i + 1)?
    else {
        return None;
    };
    let test_label: usize = *test_label;
    let Stmt::Label(top_label) = stmts.get(i + 2)? else {
        return None;
    };
    let top_label: usize = *top_label;
    let test_idx: usize = label_at(&stmts[i + 3..], test_label).map(|p: usize| i + 3 + p)?;
    let Stmt::If {
        cond,
        target_label: back_label,
    } = stmts.get(test_idx + 1)?
    else {
        return None;
    };
    if *back_label != top_label {
        return None;
    }
    if hasnext_cond(cond).is_some() {
        return None;
    }
    if label_ref_count(stmts, top_label) != 1 || label_ref_count(stmts, test_label) != 1 {
        return None;
    }
    let inner: &[Stmt] = &stmts[i + 3..test_idx];
    let update: &Stmt = match inner.last()? {
        s @ (Stmt::Assign { .. } | Stmt::AssignProperty { .. } | Stmt::AssignIndex { .. }) => s,
        _ => return None,
    };
    if !for_update_matches_init(init, update) {
        return None;
    }
    let body_slice: &[Stmt] = &inner[..inner.len() - 1];
    if body_slice.is_empty() || !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let body: Vec<Stmt> = structure_acyclic(
        &structure_loops(body_slice.to_vec(), depth - 1),
        None,
        depth - 1,
    )?;
    let stmt: Stmt = Stmt::For {
        init: Box::new(init.clone()),
        cond: cond.clone(),
        update: Box::new(update.clone()),
        body,
    };
    let consumed: usize = test_idx + 2 - i;
    Some((consumed, stmt))
}

fn assign_target(stmt: &Stmt) -> Option<&Expr> {
    match stmt {
        Stmt::Assign { target, .. } => Some(target),
        _ => None,
    }
}

fn for_update_matches_init(init: &Stmt, update: &Stmt) -> bool {
    match (assign_target(init), assign_target(update)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

fn latch_index(stmts: &[Stmt], from: usize, top_label: usize) -> Option<usize> {
    stmts
        .iter()
        .enumerate()
        .skip(from)
        .rev()
        .find(|(_, s): &(usize, &Stmt)| {
            matches!(s, Stmt::Jump { target_label } if *target_label == top_label)
        })
        .map(|(index, _): (usize, &Stmt)| index)
}

fn try_match_top_test_while(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Label(top_label): &Stmt = &stmts[i] else {
        return None;
    };
    let top_label: usize = *top_label;
    let (cond, exit_label, body_start): (Expr, usize, usize) = match stmts.get(i + 1)? {
        Stmt::If {
            cond,
            target_label: exit,
        } => (negate(cond.clone()), *exit, i + 2),
        _ => (Expr::BoolLit(true), NO_BREAK_LABEL, i + 1),
    };
    let latch: usize = latch_index(stmts, body_start, top_label)?;
    let exit_label: usize = if exit_label == NO_BREAK_LABEL {
        match stmts.get(latch + 1) {
            Some(Stmt::Label(l)) => *l,
            _ => NO_BREAK_LABEL,
        }
    } else {
        if !matches!(stmts.get(latch + 1), Some(Stmt::Label(l)) if *l == exit_label) {
            return None;
        }
        exit_label
    };
    let body_slice: &[Stmt] = &stmts[body_start..latch];
    if body_slice.is_empty()
        || !region_is_structurable(body_slice)
        || !slice_labels_are_private(stmts, body_slice)
    {
        return None;
    }
    if label_ref_count_deep(&stmts[i..=latch], top_label) != label_ref_count_deep(stmts, top_label)
    {
        return None;
    }
    let exits: LoopExits = LoopExits {
        continue_label: top_label,
        break_label: exit_label,
    };
    let rewritten: Vec<Stmt> = rewrite_loop_exits(body_slice.to_vec(), &exits)?;
    let body: Vec<Stmt> =
        structure_acyclic(&structure_loops(rewritten, depth - 1), None, depth - 1)?;
    Some((latch + 1 - i, Stmt::While { cond, body }))
}

fn try_match_do_while(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Label(top_label): &Stmt = &stmts[i] else {
        return None;
    };
    let top_label: usize = *top_label;
    if label_ref_count(stmts, top_label) != 1 {
        return None;
    }
    let back_idx: usize = stmts[i + 1..]
        .iter()
        .position(
            |s: &Stmt| matches!(s, Stmt::If { target_label, .. } if *target_label == top_label),
        )
        .map(|p: usize| i + 1 + p)?;
    let Stmt::If { cond, .. }: &Stmt = &stmts[back_idx] else {
        return None;
    };
    let body_slice: &[Stmt] = &stmts[i + 1..back_idx];
    if body_slice.is_empty()
        || !region_is_structurable(body_slice)
        || !slice_labels_are_private(stmts, body_slice)
    {
        return None;
    }
    let body: Vec<Stmt> = structure_acyclic(
        &structure_loops(body_slice.to_vec(), depth - 1),
        None,
        depth - 1,
    )?;
    let do_stmt: Stmt = Stmt::DoWhile {
        cond: cond.clone(),
        body,
    };
    let consumed: usize = back_idx + 1 - i;
    Some((consumed, do_stmt))
}

fn try_match_while(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::Jump {
        target_label: test_label,
    }: &Stmt = &stmts[i]
    else {
        return None;
    };
    let test_label: usize = *test_label;
    let Stmt::Label(top_label): &Stmt = stmts.get(i + 1)? else {
        return None;
    };
    let top_label: usize = *top_label;
    let test_idx: usize = label_at(&stmts[i + 2..], test_label).map(|p: usize| i + 2 + p)?;
    let Stmt::If {
        cond,
        target_label: back_label,
    }: &Stmt = stmts.get(test_idx + 1)?
    else {
        return None;
    };
    if *back_label != top_label {
        return None;
    }
    let body_slice: &[Stmt] = &stmts[i + 2..test_idx];
    if !region_is_structurable(body_slice) {
        return None;
    }
    if label_ref_count(stmts, top_label) != 1 || label_ref_count(stmts, test_label) != 1 {
        return None;
    }
    if !slice_labels_are_private(stmts, body_slice) {
        return None;
    }
    let inner: Vec<Stmt> = structure_loops(
        structure_switches(body_slice.to_vec(), depth - 1),
        depth - 1,
    );
    let body: Vec<Stmt> = structure_acyclic(&inner, None, depth - 1)?;
    let while_stmt: Stmt = Stmt::While {
        cond: cond.clone(),
        body,
    };
    let consumed: usize = test_idx + 2 - i;
    Some((consumed, while_stmt))
}

fn structure_if_blocks(stmts: Vec<Stmt>, depth: usize) -> Vec<Stmt> {
    if depth == 0 {
        return stmts;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(stmts.len());
    let mut i: usize = 0;
    while i < stmts.len() {
        if let Stmt::With { object, body } = &stmts[i] {
            out.push(Stmt::With {
                object: object.clone(),
                body: structure_if_blocks(body.clone(), depth - 1),
            });
            i += 1;
            continue;
        }
        if let Some((consumed, stmt)) = try_match_if_else(&stmts, i, depth) {
            out.push(stmt);
            i += consumed;
            continue;
        }
        if let Some((consumed, stmt)) = try_match_if_block(&stmts, i, depth) {
            out.push(stmt);
            i += consumed;
            continue;
        }
        out.push(stmts[i].clone());
        i += 1;
    }
    out
}

fn restructure_nested(stmt: Stmt, depth: usize) -> Stmt {
    let recur =
        |body: Vec<Stmt>| -> Vec<Stmt> { structure_acyclic(&body, None, depth).unwrap_or(body) };
    match stmt {
        Stmt::IfBlock { cond, body } => Stmt::IfBlock {
            cond,
            body: recur(body),
        },
        Stmt::IfElse {
            cond,
            then_body,
            else_body,
        } => Stmt::IfElse {
            cond,
            then_body: recur(then_body),
            else_body: recur(else_body),
        },
        Stmt::With { object, body } => Stmt::With {
            object,
            body: recur(body),
        },
        Stmt::Try { body, catches } => Stmt::Try {
            body: recur(body),
            catches: catches
                .into_iter()
                .map(|c: CatchClause| CatchClause {
                    body: recur(c.body),
                    ..c
                })
                .collect(),
        },
        Stmt::StructuredSwitch { selector, cases } => Stmt::StructuredSwitch {
            selector,
            cases: cases
                .into_iter()
                .map(|c: SwitchCase| SwitchCase {
                    body: recur(c.body),
                    ..c
                })
                .collect(),
        },
        other => other,
    }
}

fn acyclic_conditional(
    slice: &[Stmt],
    i: usize,
    cond: &Expr,
    label: usize,
    end_label: Option<usize>,
    depth: usize,
) -> Option<(usize, Stmt)> {
    if let Some(merge) = label_at(&slice[i + 1..], label).map(|p: usize| i + 1 + p) {
        if label_ref_count_deep(&slice[i..=merge], label) != label_ref_count_deep(slice, label) {
            return None;
        }
        let then_slice: &[Stmt] = &slice[i + 1..merge];
        if let Some(Stmt::Jump { target_label: tail }) = then_slice.last()
            && *tail != label
        {
            let tail: usize = *tail;
            let then_core: &[Stmt] = &then_slice[..then_slice.len() - 1];
            let else_span: Option<(&[Stmt], Option<usize>, usize)> =
                match label_at(&slice[merge + 1..], tail).map(|p: usize| merge + 1 + p) {
                    Some(join)
                        if label_ref_count_deep(&slice[i..=join], tail)
                            == label_ref_count_deep(slice, tail) =>
                    {
                        Some((&slice[merge + 1..join], Some(tail), join + 1 - i))
                    }
                    None if Some(tail) == end_label => {
                        Some((&slice[merge + 1..], end_label, slice.len() - i))
                    }
                    Some(_) | None => None,
                };
            if let Some((else_slice, inner_end, consumed)) = else_span {
                let then_body: Vec<Stmt> = structure_acyclic(then_core, Some(tail), depth - 1)?;
                let else_body: Vec<Stmt> = structure_acyclic(else_slice, inner_end, depth - 1)?;
                let folded: Option<Stmt> = match (then_body.is_empty(), else_body.is_empty()) {
                    (false, false) => Some(Stmt::IfElse {
                        cond: negate(cond.clone()),
                        then_body,
                        else_body,
                    }),
                    (true, false) => Some(Stmt::IfBlock {
                        cond: cond.clone(),
                        body: else_body,
                    }),
                    (false, true) => Some(Stmt::IfBlock {
                        cond: negate(cond.clone()),
                        body: then_body,
                    }),
                    (true, true) => None,
                };
                if let Some(stmt) = folded {
                    return Some((consumed, stmt));
                }
            }
        }
        let body: Vec<Stmt> = structure_acyclic(then_slice, Some(label), depth - 1)?;
        return Some((
            merge + 1 - i,
            Stmt::IfBlock {
                cond: negate(cond.clone()),
                body,
            },
        ));
    }
    if Some(label) == end_label {
        let body: Vec<Stmt> = structure_acyclic(&slice[i + 1..], end_label, depth - 1)?;
        return Some((
            slice.len() - i,
            Stmt::IfBlock {
                cond: negate(cond.clone()),
                body,
            },
        ));
    }
    None
}

fn structure_acyclic(slice: &[Stmt], end_label: Option<usize>, depth: usize) -> Option<Vec<Stmt>> {
    if depth == 0 {
        return None;
    }
    let mut out: Vec<Stmt> = Vec::with_capacity(slice.len());
    let mut i: usize = 0;
    while i < slice.len() {
        match &slice[i] {
            Stmt::Label(_) | Stmt::Switch { .. } => return None,
            Stmt::Jump { target_label } => {
                if Some(*target_label) != end_label || i + 1 != slice.len() {
                    return None;
                }
                i += 1;
            }
            Stmt::If { cond, target_label } => {
                let (consumed, stmt): (usize, Stmt) =
                    acyclic_conditional(slice, i, cond, *target_label, end_label, depth)?;
                out.push(stmt);
                i += consumed;
            }
            other => {
                let mapped: Stmt = restructure_nested(other.clone(), depth - 1);
                if !body_is_structured_with_exits(std::slice::from_ref(&mapped)) {
                    return None;
                }
                out.push(mapped);
                i += 1;
            }
        }
    }
    Some(out)
}

fn slice_is_structured(slice: &[Stmt]) -> bool {
    !slice.iter().any(|s: &Stmt| {
        matches!(
            s,
            Stmt::Label(_) | Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Switch { .. }
        )
    })
}

fn try_match_if_block(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::If { cond, target_label }: &Stmt = &stmts[i] else {
        return None;
    };
    let label: usize = *target_label;
    if label_ref_count(stmts, label) != 1 {
        return None;
    }
    let end_rel: usize = stmts[i + 1..]
        .iter()
        .position(|s: &Stmt| matches!(s, Stmt::Label(l) if *l == label))?;
    let body_slice: &[Stmt] = &stmts[i + 1..i + 1 + end_rel];
    if body_slice.is_empty() {
        return None;
    }
    let body: Vec<Stmt> = structure_if_blocks(body_slice.to_vec(), depth - 1);
    if !slice_is_structured(&body) {
        return None;
    }
    let stmt: Stmt = Stmt::IfBlock {
        cond: negate(cond.clone()),
        body,
    };
    Some((i + 1 + end_rel + 1 - i, stmt))
}

fn try_match_if_else(stmts: &[Stmt], i: usize, depth: usize) -> Option<(usize, Stmt)> {
    if depth == 0 {
        return None;
    }
    let Stmt::If { cond, target_label }: &Stmt = &stmts[i] else {
        return None;
    };
    let else_label: usize = *target_label;
    if label_ref_count(stmts, else_label) != 1 {
        return None;
    }
    let else_rel: usize = stmts[i + 1..]
        .iter()
        .position(|s: &Stmt| matches!(s, Stmt::Label(l) if *l == else_label))?;
    let then_slice: &[Stmt] = &stmts[i + 1..i + 1 + else_rel];
    let Some(Stmt::Jump {
        target_label: end_label,
    }): Option<&Stmt> = then_slice.last()
    else {
        return None;
    };
    let end_label: usize = *end_label;
    if end_label == else_label || label_ref_count(stmts, end_label) != 1 {
        return None;
    }
    let else_label_idx: usize = i + 1 + else_rel;
    let end_idx: usize = stmts[else_label_idx + 1..]
        .iter()
        .position(|s: &Stmt| matches!(s, Stmt::Label(l) if *l == end_label))
        .map(|p: usize| else_label_idx + 1 + p)?;
    let then_body_slice: &[Stmt] = &then_slice[..then_slice.len() - 1];
    let else_body_slice: &[Stmt] = &stmts[else_label_idx + 1..end_idx];
    if then_body_slice.is_empty() || else_body_slice.is_empty() {
        return None;
    }
    let then_body: Vec<Stmt> = structure_if_blocks(then_body_slice.to_vec(), depth - 1);
    let else_body: Vec<Stmt> = structure_if_blocks(else_body_slice.to_vec(), depth - 1);
    if !slice_is_structured(&then_body) || !slice_is_structured(&else_body) {
        return None;
    }
    let stmt: Stmt = Stmt::IfElse {
        cond: negate(cond.clone()),
        then_body,
        else_body,
    };
    Some((end_idx + 1 - i, stmt))
}

fn expr_phi_count(e: &Expr) -> usize {
    match e {
        Expr::Phi { .. } => 1,
        Expr::Get { object, .. }
        | Expr::Unary {
            operand: object, ..
        }
        | Expr::Coerce {
            operand: object, ..
        }
        | Expr::Typeof(object)
        | Expr::Delete { object, .. }
        | Expr::Descendants { object, .. } => expr_phi_count(object),
        Expr::Index { object, index } => expr_phi_count(object) + expr_phi_count(index),
        Expr::Binary { lhs, rhs, .. } => expr_phi_count(lhs) + expr_phi_count(rhs),
        Expr::IsType { operand, ty } | Expr::AsType { operand, ty } => {
            expr_phi_count(operand) + expr_phi_count(ty)
        }
        Expr::Call { callee, args, .. } | Expr::Construct { callee, args, .. } => {
            expr_phi_count(callee) + args.iter().map(expr_phi_count).sum::<usize>()
        }
        Expr::New { ty, args } => {
            expr_phi_count(ty) + args.iter().map(expr_phi_count).sum::<usize>()
        }
        Expr::Applied { base, args } => {
            expr_phi_count(base) + args.iter().map(expr_phi_count).sum::<usize>()
        }
        Expr::Ternary {
            cond,
            then_value,
            else_value,
        } => expr_phi_count(cond) + expr_phi_count(then_value) + expr_phi_count(else_value),
        Expr::Array(items) => items.iter().map(expr_phi_count).sum(),
        Expr::Object(pairs) => pairs
            .iter()
            .map(|(k, v): &(Expr, Expr)| expr_phi_count(k) + expr_phi_count(v))
            .sum(),
        _ => 0,
    }
}

fn stmts_phi_count(stmts: &[Stmt]) -> usize {
    stmts.iter().map(stmt_phi_count).sum()
}

fn stmt_phi_count(stmt: &Stmt) -> usize {
    match stmt {
        Stmt::Assign { target, value } => expr_phi_count(target) + expr_phi_count(value),
        Stmt::AssignProperty { object, value, .. } => {
            expr_phi_count(object) + expr_phi_count(value)
        }
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => expr_phi_count(object) + expr_phi_count(index) + expr_phi_count(value),
        Stmt::Expression(e) | Stmt::Throw(e) | Stmt::Return(Some(e)) => expr_phi_count(e),
        Stmt::If { cond, .. } => expr_phi_count(cond),
        Stmt::Switch { selector, .. } => expr_phi_count(selector),
        Stmt::IfBlock { cond, body } => expr_phi_count(cond) + stmts_phi_count(body),
        Stmt::IfElse {
            cond,
            then_body,
            else_body,
        } => expr_phi_count(cond) + stmts_phi_count(then_body) + stmts_phi_count(else_body),
        Stmt::While { cond, body } | Stmt::DoWhile { cond, body } => {
            expr_phi_count(cond) + stmts_phi_count(body)
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            stmt_phi_count(init)
                + expr_phi_count(cond)
                + stmt_phi_count(update)
                + stmts_phi_count(body)
        }
        Stmt::ForEach {
            var,
            collection,
            body,
        }
        | Stmt::ForIn {
            var,
            collection,
            body,
        } => expr_phi_count(var) + expr_phi_count(collection) + stmts_phi_count(body),
        Stmt::Try { body, catches } => {
            stmts_phi_count(body)
                + catches
                    .iter()
                    .map(|c: &CatchClause| stmts_phi_count(&c.body))
                    .sum::<usize>()
        }
        Stmt::With { object, body } => expr_phi_count(object) + stmts_phi_count(body),
        Stmt::StructuredSwitch { selector, cases } => {
            expr_phi_count(selector)
                + cases
                    .iter()
                    .map(|c: &SwitchCase| stmts_phi_count(&c.body))
                    .sum::<usize>()
        }
        _ => 0,
    }
}

fn stmt_reaches_terminator(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) | Stmt::Throw(_) => true,
        Stmt::IfBlock { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::For { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::ForIn { body, .. }
        | Stmt::With { body, .. } => body.iter().any(stmt_reaches_terminator),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => {
            then_body.iter().any(stmt_reaches_terminator)
                && else_body.iter().any(stmt_reaches_terminator)
        }
        Stmt::Try { body, catches } => {
            body.iter().any(stmt_reaches_terminator)
                || catches
                    .iter()
                    .any(|c: &CatchClause| c.body.iter().any(stmt_reaches_terminator))
        }
        Stmt::StructuredSwitch { cases, .. } => {
            let has_default: bool = cases
                .iter()
                .any(|c: &SwitchCase| c.labels.contains(&CaseLabel::Default));
            has_default
                && cases
                    .iter()
                    .all(|c: &SwitchCase| c.body.iter().any(stmt_reaches_terminator))
        }
        _ => false,
    }
}

fn statements_fully_structured(stmts: &[Stmt]) -> bool {
    stmts.iter().all(|s: &Stmt| match s {
        Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Label(_) | Stmt::Switch { .. } => false,
        Stmt::For { body, .. }
        | Stmt::ForEach { body, .. }
        | Stmt::ForIn { body, .. }
        | Stmt::While { body, .. }
        | Stmt::DoWhile { body, .. }
        | Stmt::IfBlock { body, .. }
        | Stmt::With { body, .. } => statements_fully_structured(body),
        Stmt::IfElse {
            then_body,
            else_body,
            ..
        } => statements_fully_structured(then_body) && statements_fully_structured(else_body),
        Stmt::Try { body, catches } => {
            statements_fully_structured(body)
                && catches
                    .iter()
                    .all(|c: &CatchClause| statements_fully_structured(&c.body))
        }
        Stmt::StructuredSwitch { cases, .. } => cases
            .iter()
            .all(|c: &SwitchCase| statements_fully_structured(&c.body)),
        _ => true,
    })
}

fn build_slot_names(abc: &AbcFile, body: &MethodBody) -> BTreeMap<u32, String> {
    let mut map: BTreeMap<u32, String> = BTreeMap::new();
    let mut insert_traits = |traits: &[crate::abc::TraitInfo], overwrite: bool| {
        for tr in traits {
            let kind: u8 = tr.kind & 0x0F;
            if (kind == 0 || kind == 6) && tr.slot_id != 0 {
                if !overwrite && map.contains_key(&tr.slot_id) {
                    continue;
                }
                if let Ok(name) = abc.cpool.render_multiname(tr.name_index) {
                    map.insert(tr.slot_id, name);
                }
            }
        }
    };
    for inst in &abc.instances {
        insert_traits(&inst.traits, false);
    }
    for class in &abc.classes {
        insert_traits(&class.traits, false);
    }
    for script in &abc.scripts {
        insert_traits(&script.traits, false);
    }
    insert_traits(&body.traits, true);
    map
}

fn lift_raw(
    abc: &AbcFile,
    body: &MethodBody,
    info: Option<&MethodInfo>,
) -> Result<(Vec<Stmt>, Vec<u8>, usize)> {
    let lines: Vec<DisasmLine> = disasm(&body.code)?;
    let labels: BTreeSet<usize> = collect_labels(&lines, &body.exceptions);
    let names: LocalNames = local_names_for(abc, info);
    let slot_names: BTreeMap<u32, String> = build_slot_names(abc, body);
    let next_offset: BTreeMap<usize, usize> = lines
        .windows(2)
        .map(|w: &[DisasmLine]| (w[0].offset, w[1].offset))
        .collect();
    let end_off: usize = lines.last().map_or(0, |l: &DisasmLine| {
        next_offset.get(&l.offset).copied().unwrap_or(l.offset + 1)
    });
    let stack_analysis: StackAnalysis =
        block_entry_heights(abc, &lines, &labels, &names, &slot_names, &body.exceptions);
    let exc_targets: BTreeSet<usize> = body
        .exceptions
        .iter()
        .map(|e: &ExceptionInfo| e.target as usize)
        .collect();
    let mut lifter: Lifter<'_> = Lifter {
        abc,
        stack: Vec::new(),
        statements: Vec::new(),
        names: &names,
        slot_names: &slot_names,
        dropped_opcodes: Vec::new(),
        opaque_operands: 0,
        scope_stack: Vec::new(),
        with_regions: Vec::new(),
        idioms: detect_idioms(&lines),
        short_circuits: Vec::new(),
        branch_marks: Vec::new(),
        hoisted_temporaries: 0,
        incoming_stacks: BTreeMap::new(),
        incoming_scopes: BTreeMap::new(),
        untracked_stack_entries: BTreeSet::new(),
        untracked_scope_entries: BTreeSet::new(),
        tracked_stack_nodes: 0,
        tracked_scope_nodes: 0,
        stack_tracking_exhausted: false,
        scope_tracking_exhausted: false,
        switch_direction_refusals: stack_analysis.switch_direction_refusals.clone(),
        switch_budget_refusals: stack_analysis.switch_budget_refusals.clone(),
    };
    let reachable: BTreeSet<usize> =
        reachable_offsets(&lines, &next_offset, end_off, &body.exceptions);
    for line in &lines {
        if !reachable.contains(&line.offset) {
            continue;
        }
        if labels.contains(&line.offset) {
            lifter.enter_label(
                line.offset,
                &stack_analysis,
                exc_targets.contains(&line.offset),
            );
        }
        let next_off: usize = next_offset.get(&line.offset).copied().unwrap_or(end_off);
        step(&mut lifter, line, next_off, end_off);
    }
    let dropped_opcodes: Vec<u8> = lifter.dropped_opcodes.clone();
    let opaque_operands: usize = lifter.opaque_operands;
    Ok((lifter.statements, dropped_opcodes, opaque_operands))
}

pub fn lift_body_raw(
    abc: &AbcFile,
    body: &MethodBody,
    info: Option<&MethodInfo>,
) -> Result<Vec<Stmt>> {
    let (statements, _dropped, _opaque): (Vec<Stmt>, Vec<u8>, usize) = lift_raw(abc, body, info)?;
    Ok(statements)
}

pub fn lift_body(
    abc: &AbcFile,
    body: &MethodBody,
    info: Option<&MethodInfo>,
) -> Result<LiftedBody> {
    let lines: Vec<DisasmLine> = disasm(&body.code)?;
    let labels: BTreeSet<usize> = collect_labels(&lines, &body.exceptions);
    let names: LocalNames = local_names_for(abc, info);
    if dbg_enabled() {
        let named_params: usize = names
            .param_names
            .iter()
            .filter(|n: &&String| !n.is_empty())
            .count();
        dbg_kv("local_names", || {
            format!(
                "local_count={} param_count={} named_params={named_params}",
                body.local_count, names.param_count
            )
        });
        if names.param_count > 0 && named_params == 0 {
            dbg_line(|| {
                format!(
                    "wall: local-name erasure, {} params present but stripped of debug names",
                    names.param_count
                )
            });
        }
    }
    let slot_names: BTreeMap<u32, String> = build_slot_names(abc, body);
    let next_offset: BTreeMap<usize, usize> = lines
        .windows(2)
        .map(|w: &[DisasmLine]| (w[0].offset, w[1].offset))
        .collect();
    let end_off: usize = lines.last().map_or(0, |l: &DisasmLine| {
        next_offset.get(&l.offset).copied().unwrap_or(l.offset + 1)
    });
    let stack_analysis: StackAnalysis =
        block_entry_heights(abc, &lines, &labels, &names, &slot_names, &body.exceptions);
    let exc_targets: BTreeSet<usize> = body
        .exceptions
        .iter()
        .map(|e: &ExceptionInfo| e.target as usize)
        .collect();
    let mut lifter: Lifter<'_> = Lifter {
        abc,
        stack: Vec::new(),
        statements: Vec::new(),
        names: &names,
        slot_names: &slot_names,
        dropped_opcodes: Vec::new(),
        opaque_operands: 0,
        scope_stack: Vec::new(),
        with_regions: Vec::new(),
        idioms: detect_idioms(&lines),
        short_circuits: Vec::new(),
        branch_marks: Vec::new(),
        hoisted_temporaries: 0,
        incoming_stacks: BTreeMap::new(),
        incoming_scopes: BTreeMap::new(),
        untracked_stack_entries: BTreeSet::new(),
        untracked_scope_entries: BTreeSet::new(),
        tracked_stack_nodes: 0,
        tracked_scope_nodes: 0,
        stack_tracking_exhausted: false,
        scope_tracking_exhausted: false,
        switch_direction_refusals: stack_analysis.switch_direction_refusals.clone(),
        switch_budget_refusals: stack_analysis.switch_budget_refusals.clone(),
    };
    let reachable: BTreeSet<usize> =
        reachable_offsets(&lines, &next_offset, end_off, &body.exceptions);
    for line in &lines {
        if !reachable.contains(&line.offset) {
            continue;
        }
        if labels.contains(&line.offset) {
            lifter.enter_label(
                line.offset,
                &stack_analysis,
                exc_targets.contains(&line.offset),
            );
        }
        let next_off: usize = next_offset.get(&line.offset).copied().unwrap_or(end_off);
        step(&mut lifter, line, next_off, end_off);
    }
    let regions: Vec<RegionInfo> = resolve_regions(&lifter, &body.exceptions);
    let dropped_opcodes: Vec<u8> = lifter.dropped_opcodes;
    let lift_opaque: usize = lifter.opaque_operands;
    let with_regions: Vec<WithRegion> = lifter.with_regions.clone();
    let scoped: Vec<Stmt> = structure_with(lifter.statements, &with_regions, MAX_STRUCTURE_DEPTH);
    let raw_statements: Vec<Stmt> = structure_try(scoped, &regions, MAX_STRUCTURE_DEPTH);
    let pruned: Vec<Stmt> = drop_dead_labels(drop_empty_branches(drop_dead_labels(raw_statements)));
    let dispatched: Vec<Stmt> =
        drop_dead_labels(structure_forward_dispatch(pruned, MAX_STRUCTURE_DEPTH));
    let switched: Vec<Stmt> = drop_dead_labels(structure_switches(dispatched, MAX_STRUCTURE_DEPTH));
    let looped: Vec<Stmt> = structure_loops(switched, MAX_STRUCTURE_DEPTH);
    let acyclic: Option<Vec<Stmt>> = structure_acyclic(&looped, None, MAX_STRUCTURE_DEPTH);
    let structured: Vec<Stmt> =
        acyclic.unwrap_or_else(|| structure_if_blocks(looped, MAX_STRUCTURE_DEPTH));
    let statements: Vec<Stmt> = drop_dead_labels(structured);
    let opaque_operands: usize = lift_opaque.saturating_add(stmts_phi_count(&statements));
    let reached_terminator: bool = statements.iter().any(stmt_reaches_terminator);
    let fully_structured: bool = statements_fully_structured(&statements);
    let structurally_recovered: bool = reached_terminator
        && fully_structured
        && dropped_opcodes.is_empty()
        && opaque_operands == 0;
    if dbg_enabled() {
        if !dropped_opcodes.is_empty() {
            dbg_line(|| {
                let codes: String = dropped_opcodes
                    .iter()
                    .map(|op: &u8| format!("0x{op:02x}"))
                    .collect::<Vec<String>>()
                    .join(",");
                format!(
                    "wall: {} unmodelled opcode(s) dropped [{codes}]",
                    dropped_opcodes.len()
                )
            });
        }
        if opaque_operands > 0 {
            dbg_line(|| format!("wall: {opaque_operands} opaque stack operand(s)"));
        }
        dbg_kv("classify", || {
            format!(
                "structurally_recovered={structurally_recovered} reached_terminator={reached_terminator} fully_structured={fully_structured} stmts={}",
                statements.len()
            )
        });
    }
    Ok(LiftedBody {
        statements,
        structurally_recovered,
        fully_structured,
        reached_terminator,
        dropped_opcodes,
        opaque_operands,
    })
}

#[must_use]
pub fn render_body(lifted: &LiftedBody, names: &LocalNames, indent: &str) -> String {
    let mut out: String = String::new();
    for stmt in &lifted.statements {
        render_stmt(&mut out, stmt, names, indent);
    }
    out
}

fn iteration_binding(var: &Expr, names: &LocalNames) -> String {
    let rendered: String = var.render(names);
    if matches!(var, Expr::Local(_) | Expr::Param(_) | Expr::Name(_)) {
        format!("var {rendered}")
    } else {
        rendered
    }
}

fn render_stmt(out: &mut String, stmt: &Stmt, names: &LocalNames, indent: &str) {
    match stmt {
        Stmt::Assign { target, value } => {
            push_format(
                out,
                format_args!(
                    "{indent}{} = {};\n",
                    target.render(names),
                    value.render(names)
                ),
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
            push_format(
                out,
                format_args!("{indent}{lhs} = {};\n", value.render(names)),
            );
        }
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => {
            push_format(
                out,
                format_args!(
                    "{indent}{}[{}] = {};\n",
                    object.render(names),
                    index.render(names),
                    value.render(names)
                ),
            );
        }
        Stmt::Expression(e) => {
            push_format(out, format_args!("{indent}{};\n", e.render(names)));
        }
        Stmt::Return(Some(e)) => {
            push_format(out, format_args!("{indent}return {};\n", e.render(names)));
        }
        Stmt::Return(None) => {
            push_format(out, format_args!("{indent}return;\n"));
        }
        Stmt::Throw(e) => {
            push_format(out, format_args!("{indent}throw {};\n", e.render(names)));
        }
        Stmt::If { cond, target_label } => {
            push_format(
                out,
                format_args!(
                    "{indent}if ({}) goto L{target_label};\n",
                    cond.render(names)
                ),
            );
        }
        Stmt::Jump { target_label } => {
            push_format(out, format_args!("{indent}goto L{target_label};\n"));
        }
        Stmt::Label(off) => {
            push_format(out, format_args!("{indent}L{off}:\n"));
        }
        Stmt::Switch {
            selector,
            case_labels,
            default_label,
        } => {
            push_format(
                out,
                format_args!("{indent}switch ({}) {{\n", selector.render(names)),
            );
            let inner: String = format!("{indent}    ");
            for (i, label) in case_labels.iter().enumerate() {
                push_format(out, format_args!("{inner}case {i}: goto L{label};\n"));
            }
            push_format(
                out,
                format_args!("{inner}default: goto L{default_label};\n"),
            );
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::StructuredSwitch { selector, cases } => {
            push_format(
                out,
                format_args!("{indent}switch ({}) {{\n", selector.render(names)),
            );
            let label_indent: String = format!("{indent}    ");
            let body_indent: String = format!("{indent}        ");
            for case in cases {
                for label in &case.labels {
                    match label {
                        CaseLabel::Value(v) => {
                            push_format(out, format_args!("{label_indent}case {v}:\n"));
                        }
                        CaseLabel::Expr(e) => {
                            push_format(
                                out,
                                format_args!("{label_indent}case {}:\n", e.render(names)),
                            );
                        }
                        CaseLabel::Default => {
                            push_format(out, format_args!("{label_indent}default:\n"));
                        }
                    }
                }
                for s in &case.body {
                    render_stmt(out, s, names, &body_indent);
                }
                if case.breaks {
                    push_format(out, format_args!("{body_indent}break;\n"));
                }
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::IfBlock { cond, body } => {
            push_format(
                out,
                format_args!("{indent}if ({}) {{\n", cond.render(names)),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::IfElse {
            cond,
            then_body,
            else_body,
        } => {
            let inner: String = format!("{indent}    ");
            push_format(
                out,
                format_args!("{indent}if ({}) {{\n", cond.render(names)),
            );
            for s in then_body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}} else {{\n"));
            for s in else_body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::While { cond, body } => {
            push_format(
                out,
                format_args!("{indent}while ({}) {{\n", cond.render(names)),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::DoWhile { cond, body } => {
            push_format(out, format_args!("{indent}do {{\n"));
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(
                out,
                format_args!("{indent}}} while ({});\n", cond.render(names)),
            );
        }
        Stmt::For {
            init,
            cond,
            update,
            body,
        } => {
            push_format(
                out,
                format_args!(
                    "{indent}for ({}; {}; {}) {{\n",
                    render_stmt_inline(init, names),
                    cond.render(names),
                    render_stmt_inline(update, names)
                ),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::ForEach {
            var,
            collection,
            body,
        } => {
            push_format(
                out,
                format_args!(
                    "{indent}for each ({} in {}) {{\n",
                    iteration_binding(var, names),
                    collection.render(names)
                ),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::ForIn {
            var,
            collection,
            body,
        } => {
            push_format(
                out,
                format_args!(
                    "{indent}for ({} in {}) {{\n",
                    iteration_binding(var, names),
                    collection.render(names)
                ),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::Try { body, catches } => {
            let inner: String = format!("{indent}    ");
            push_format(out, format_args!("{indent}try {{\n"));
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            for catch in catches {
                push_format(
                    out,
                    format_args!(
                        "{indent}}} catch ({}: {}) {{\n",
                        catch.var_name, catch.type_name
                    ),
                );
                for s in &catch.body {
                    render_stmt(out, s, names, &inner);
                }
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::With { object, body } => {
            push_format(
                out,
                format_args!("{indent}with ({}) {{\n", object.render(names)),
            );
            let inner: String = format!("{indent}    ");
            for s in body {
                render_stmt(out, s, names, &inner);
            }
            push_format(out, format_args!("{indent}}}\n"));
        }
        Stmt::Break => {
            push_format(out, format_args!("{indent}break;\n"));
        }
        Stmt::Continue => {
            push_format(out, format_args!("{indent}continue;\n"));
        }
        Stmt::Comment(c) => {
            push_format(out, format_args!("{indent}// {c}\n"));
        }
    }
}

fn render_stmt_inline(stmt: &Stmt, names: &LocalNames) -> String {
    match stmt {
        Stmt::Assign { target, value } => {
            format!("{} = {}", target.render(names), value.render(names))
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
            format!("{lhs} = {}", value.render(names))
        }
        Stmt::AssignIndex {
            object,
            index,
            value,
        } => format!(
            "{}[{}] = {}",
            object.render(names),
            index.render(names),
            value.render(names)
        ),
        Stmt::Expression(e) => e.render(names),
        _ => String::new(),
    }
}

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
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::unreachable
)]
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
    fn tail_dispatch_layout_remains_structured() {
        let statements: Vec<Stmt> = vec![
            Stmt::Jump { target_label: 50 },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(50),
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(1)),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 90 },
            Stmt::Label(90),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
    }

    #[test]
    fn loose_alternating_tail_dispatch_stays_raw() {
        let statements: Vec<Stmt> = vec![
            Stmt::Jump { target_label: 50 },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(50),
            Stmt::If {
                cond: Expr::Binary {
                    op: "==",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "==",
                    lhs: Box::new(Expr::IntLit(1)),
                    rhs: Box::new(Expr::Local(1)),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 90 },
            Stmt::Label(90),
            Stmt::Return(None),
        ];

        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);

        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_DIRECTION_REFUSAL_MARKER
        )));
    }

    #[test]
    fn effectful_alternating_tail_dispatch_stays_raw() {
        let selector: Expr = Expr::Call {
            callee: Box::new(Expr::Name("source".to_owned())),
            property: String::new(),
            args: Vec::new(),
        };
        let statements: Vec<Stmt> = vec![
            Stmt::Jump { target_label: 50 },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 90 },
            Stmt::Label(50),
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(selector.clone()),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(Expr::IntLit(1)),
                    rhs: Box::new(selector),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 90 },
            Stmt::Label(90),
            Stmt::Return(None),
        ];

        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);

        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_EFFECT_REFUSAL_MARKER
        )));
    }

    #[test]
    fn effectful_forward_dispatch_selector_is_refused_by_named_reason() {
        let selectors: Vec<Expr> = vec![
            Expr::Call {
                callee: Box::new(Expr::Name("source".to_owned())),
                property: String::new(),
                args: Vec::new(),
            },
            Expr::Delete {
                object: Box::new(Expr::Local(1)),
                property: "value".to_owned(),
            },
            Expr::Get {
                object: Box::new(Expr::Local(1)),
                property: "value".to_owned(),
            },
            Expr::Index {
                object: Box::new(Expr::Local(1)),
                index: Box::new(Expr::IntLit(0)),
            },
        ];
        for selector in selectors {
            let statements: Vec<Stmt> = vec![
                Stmt::If {
                    cond: Expr::Binary {
                        op: "===",
                        lhs: Box::new(selector.clone()),
                        rhs: Box::new(Expr::IntLit(0)),
                    },
                    target_label: 10,
                },
                Stmt::If {
                    cond: Expr::Binary {
                        op: "===",
                        lhs: Box::new(selector),
                        rhs: Box::new(Expr::IntLit(1)),
                    },
                    target_label: 20,
                },
                Stmt::Expression(Expr::IntLit(0)),
                Stmt::Jump { target_label: 30 },
                Stmt::Label(10),
                Stmt::Expression(Expr::IntLit(10)),
                Stmt::Jump { target_label: 30 },
                Stmt::Label(20),
                Stmt::Expression(Expr::IntLit(20)),
                Stmt::Label(30),
                Stmt::Return(None),
            ];
            let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
            assert!(structured.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_EFFECT_REFUSAL_MARKER
            )));
            assert!(
                structured
                    .iter()
                    .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
            );
        }
    }

    #[test]
    fn inverted_dispatch_with_a_stack_conflict_stays_raw_and_unstructured() {
        let condition: fn(i64) -> Expr = |value: i64| Expr::Binary {
            op: "!==",
            lhs: Box::new(Expr::Local(1)),
            rhs: Box::new(Expr::IntLit(value)),
        };
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: condition(0),
                target_label: 10,
            },
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::If {
                cond: condition(1),
                target_label: 20,
            },
            Stmt::Comment(STACK_CONFLICT_MARKER.to_owned()),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(40)),
            Stmt::Label(30),
            Stmt::Return(None),
        ];

        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);

        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == STACK_CONFLICT_MARKER
        )));
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
        );
        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
        assert!(!statements_fully_structured(&structured));
    }

    fn assert_forward_dispatch_operand_refused(operand: Expr, is_selector: bool) {
        let selector: Expr = if is_selector {
            operand.clone()
        } else {
            Expr::Local(1)
        };
        let first_case: Expr = if is_selector {
            Expr::IntLit(0)
        } else {
            operand
        };
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(selector.clone()),
                    rhs: Box::new(first_case),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(selector),
                    rhs: Box::new(Expr::IntLit(1)),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_EFFECT_REFUSAL_MARKER
        )));
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
        );
        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
    }

    #[test]
    fn repeated_binary_forward_dispatch_selector_is_refused() {
        let selector: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::Local(1)),
            rhs: Box::new(Expr::IntLit(0)),
        };
        assert_forward_dispatch_operand_refused(selector, true);
    }

    #[test]
    fn repeated_number_coercion_forward_dispatch_selector_is_refused() {
        let selector: Expr = Expr::Coerce {
            ty: "Number".to_owned(),
            operand: Box::new(Expr::Local(1)),
        };
        assert_forward_dispatch_operand_refused(selector, true);
    }

    #[test]
    fn composite_forward_dispatch_case_is_refused() {
        let case_expression: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::Local(2)),
            rhs: Box::new(Expr::IntLit(0)),
        };
        assert_forward_dispatch_operand_refused(case_expression, false);
    }

    #[test]
    fn deeply_composite_forward_dispatch_is_refused_without_expression_walk() {
        let mut selector: Expr = Expr::Local(1);
        for _depth in 0..256_usize {
            selector = Expr::Unary {
                op: "+",
                operand: Box::new(selector),
            };
        }
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(selector.clone()),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(selector),
                    rhs: Box::new(Expr::IntLit(1)),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_EFFECT_REFUSAL_MARKER
        )));
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
        );
        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::StructuredSwitch { .. }))
        );
    }

    #[test]
    fn mixed_forward_dispatch_equality_is_refused() {
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(0)),
                },
                target_label: 10,
            },
            Stmt::If {
                cond: Expr::Binary {
                    op: "==",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(1)),
                },
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_COMPARISON_REFUSAL_MARKER
        )));
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
        );
    }

    #[test]
    fn loose_forward_dispatch_with_case_fallthrough_is_refused() {
        let condition: fn(i64) -> Expr = |value: i64| Expr::Binary {
            op: "==",
            lhs: Box::new(Expr::Local(1)),
            rhs: Box::new(Expr::IntLit(value)),
        };
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: condition(0),
                target_label: 10,
            },
            Stmt::If {
                cond: condition(1),
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];

        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);

        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_IRREDUCIBLE_REFUSAL_MARKER
        )));
        assert!(
            !structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::IfElse { .. }))
        );
    }

    #[test]
    fn unsafe_forward_dispatch_regions_are_refused_by_named_reason() {
        let cond: fn(i64) -> Expr = |value: i64| Expr::Binary {
            op: "===",
            lhs: Box::new(Expr::Local(1)),
            rhs: Box::new(Expr::IntLit(value)),
        };
        let missing_target: Vec<Stmt> = vec![
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 99,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let backward_entry: Vec<Stmt> = vec![
            Stmt::Jump { target_label: 10 },
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let irreducible: Vec<Stmt> = vec![
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 20,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 20 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let duplicate_case: Vec<Stmt> = vec![
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(0),
                target_label: 20,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 30,
            },
            Stmt::Jump { target_label: 40 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(30),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(40),
            Stmt::Return(None),
        ];
        let interleaved_target: Vec<Stmt> = vec![
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 20,
            },
            Stmt::If {
                cond: cond(2),
                target_label: 10,
            },
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let mismatched_stack: Vec<Stmt> = vec![
            Stmt::If {
                cond: cond(0),
                target_label: 10,
            },
            Stmt::If {
                cond: cond(1),
                target_label: 20,
            },
            Stmt::Comment(STACK_HEIGHT_CONFLICT_MARKER.to_owned()),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(10),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(20),
            Stmt::Jump { target_label: 30 },
            Stmt::Label(30),
            Stmt::Return(None),
        ];
        let fixtures: Vec<(Vec<Stmt>, &'static str)> = vec![
            (missing_target, SWITCH_INVALID_TARGET_REFUSAL_MARKER),
            (backward_entry, SWITCH_MID_ENTRY_REFUSAL_MARKER),
            (irreducible, SWITCH_IRREDUCIBLE_REFUSAL_MARKER),
            (duplicate_case, SWITCH_IRREDUCIBLE_REFUSAL_MARKER),
            (interleaved_target, SWITCH_IRREDUCIBLE_REFUSAL_MARKER),
            (mismatched_stack, STACK_HEIGHT_CONFLICT_MARKER),
        ];
        for (statements, expected_reason) in fixtures {
            let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
            assert!(structured.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == expected_reason
            )));
            assert!(
                structured
                    .iter()
                    .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
            );
        }
    }

    #[test]
    fn forward_dispatch_duplicate_analysis_is_budget_bounded() {
        const CASE_COUNT: usize = 400;
        const FIRST_LABEL: usize = 10_000;
        const MERGE_LABEL: usize = 20_000;
        let mut statements: Vec<Stmt> = Vec::with_capacity(CASE_COUNT.saturating_mul(3));
        for case_index in 0..CASE_COUNT {
            let case_value: i64 = i64::try_from(case_index).expect("bounded case index");
            statements.push(Stmt::If {
                cond: Expr::Binary {
                    op: "===",
                    lhs: Box::new(Expr::Local(1)),
                    rhs: Box::new(Expr::IntLit(case_value)),
                },
                target_label: FIRST_LABEL.saturating_add(case_index),
            });
        }
        statements.push(Stmt::Jump {
            target_label: MERGE_LABEL,
        });
        for case_index in 0..CASE_COUNT {
            statements.push(Stmt::Label(FIRST_LABEL.saturating_add(case_index)));
            statements.push(Stmt::Jump {
                target_label: MERGE_LABEL,
            });
        }
        statements.push(Stmt::Label(MERGE_LABEL));
        statements.push(Stmt::Return(None));

        let structured: Vec<Stmt> = structure_forward_dispatch(statements, MAX_STRUCTURE_DEPTH);
        assert!(structured.iter().any(|statement: &Stmt| matches!(
            statement,
            Stmt::Comment(reason) if reason == SWITCH_ANALYSIS_BUDGET_MARKER
        )));
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::If { .. }))
        );
    }

    #[test]
    fn switch_with_an_external_case_entry_is_refused_by_named_reason() {
        let statements: Vec<Stmt> = vec![
            Stmt::If {
                cond: Expr::Local(1),
                target_label: 10,
            },
            Stmt::Switch {
                selector: Expr::Local(2),
                case_labels: vec![10, 20],
                default_label: 30,
            },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(30),
            Stmt::Expression(Expr::IntLit(30)),
            Stmt::Label(40),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_switches(statements, MAX_STRUCTURE_DEPTH);
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::Switch { .. })),
            "a case with a predecessor outside its dispatch must keep the raw switch: {structured:?}"
        );
        assert!(
            structured.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_MID_ENTRY_REFUSAL_MARKER
            )),
            "the refusal must expose the violated CFG invariant: {structured:?}"
        );
    }

    #[test]
    fn switch_with_a_missing_case_target_is_refused_by_named_reason() {
        let statements: Vec<Stmt> = vec![
            Stmt::Switch {
                selector: Expr::Local(1),
                case_labels: vec![10, 99],
                default_label: 20,
            },
            Stmt::Label(10),
            Stmt::Return(Some(Expr::IntLit(10))),
            Stmt::Label(20),
            Stmt::Return(Some(Expr::IntLit(20))),
        ];
        let structured: Vec<Stmt> = structure_switches(statements, MAX_STRUCTURE_DEPTH);
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::Switch { .. })),
            "a dispatch target without an instruction-boundary label must keep the raw switch: {structured:?}"
        );
        assert!(
            structured.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_INVALID_TARGET_REFUSAL_MARKER
            )),
            "the invalid target must have a stable refusal reason: {structured:?}"
        );
    }

    #[test]
    fn switch_with_a_cross_case_back_edge_is_refused_by_named_reason() {
        let statements: Vec<Stmt> = vec![
            Stmt::Switch {
                selector: Expr::Local(1),
                case_labels: vec![10, 20],
                default_label: 30,
            },
            Stmt::Label(10),
            Stmt::Expression(Expr::IntLit(10)),
            Stmt::Jump { target_label: 40 },
            Stmt::Label(20),
            Stmt::Expression(Expr::IntLit(20)),
            Stmt::Jump { target_label: 10 },
            Stmt::Label(30),
            Stmt::Expression(Expr::IntLit(30)),
            Stmt::Label(40),
            Stmt::Return(None),
        ];
        let structured: Vec<Stmt> = structure_switches(statements, MAX_STRUCTURE_DEPTH);
        assert!(
            structured
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::Switch { .. })),
            "a cross-case back edge must keep the raw switch: {structured:?}"
        );
        assert!(
            structured.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_IRREDUCIBLE_REFUSAL_MARKER
            )),
            "the irreducible case graph must have a stable refusal reason: {structured:?}"
        );
    }

    #[test]
    fn render_string_escapes() {
        assert_eq!(render_string_lit("a\"b"), "\"a\\\"b\"");
        assert_eq!(render_string_lit("x\ny"), "\"x\\ny\"");
    }

    #[test]
    fn render_string_escapes_control_and_line_separators() {
        assert_eq!(render_string_lit("\u{08}\u{0C}"), "\"\\b\\f\"");
        assert_eq!(
            render_string_lit("\u{00}\u{07}\u{0B}\u{1F}"),
            "\"\\x00\\x07\\x0b\\x1f\""
        );
        assert_eq!(render_string_lit("\u{2028}\u{2029}"), "\"\\u2028\\u2029\"");
    }

    #[test]
    fn render_string_keeps_printable_high_bytes_literal() {
        assert_eq!(render_string_lit("café €"), "\"café €\"");
        assert_eq!(render_string_lit("日本語"), "\"日本語\"");
    }

    #[test]
    fn negative_zero_number_keeps_its_sign() {
        assert_eq!(render_double(-0.0), "-0");
        assert_eq!(render_double(0.0), "0");
        assert_eq!(Expr::DoubleLit(-0.0).render(&names()), "-0");
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
    fn unary_prefix_signs_do_not_merge_into_inc_dec() {
        let neg_neg: Expr = Expr::Unary {
            op: "-",
            operand: Box::new(Expr::Unary {
                op: "-",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        let neg_render: String = neg_neg.render(&names());
        assert_eq!(neg_render, "-(-loc1)");
        assert!(
            !neg_render.contains("--"),
            "double negation must not collapse into a decrement token: {neg_render}"
        );

        let plus_plus: Expr = Expr::Unary {
            op: "+",
            operand: Box::new(Expr::Unary {
                op: "+",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        let plus_render: String = plus_plus.render(&names());
        assert_eq!(plus_render, "+(+loc1)");
        assert!(
            !plus_render.contains("++"),
            "double unary plus must not collapse into an increment token: {plus_render}"
        );

        let neg_lit: Expr = Expr::Unary {
            op: "-",
            operand: Box::new(Expr::IntLit(-3)),
        };
        assert_eq!(neg_lit.render(&names()), "-(-3)");

        let bitnot: Expr = Expr::Unary {
            op: "~",
            operand: Box::new(Expr::Unary {
                op: "~",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        assert_eq!(bitnot.render(&names()), "~~loc1");
        let not: Expr = Expr::Unary {
            op: "!",
            operand: Box::new(Expr::Unary {
                op: "!",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        assert_eq!(not.render(&names()), "!!loc1");
    }

    #[test]
    fn double_negate_bytecode_keeps_parentheses() {
        let code: Vec<u8> = vec![0xD1, 0x90, 0x90, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(
            rendered.contains("return -(-loc1);"),
            "nested negate must keep the operand parenthesized: {rendered}"
        );
        assert!(
            !rendered.contains("--"),
            "no decrement token in double-negate output: {rendered}"
        );
    }

    fn node_available() -> bool {
        std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_ok_and(|o: std::process::Output| o.status.success())
    }

    fn node_eval_with_loc1(expr_src: &str) -> Option<i64> {
        let program: String = format!("var loc1 = 5; process.stdout.write(String(({expr_src})));");
        let output: std::process::Output = std::process::Command::new("node")
            .arg("-e")
            .arg(&program)
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        String::from_utf8(output.stdout)
            .ok()?
            .trim()
            .parse::<i64>()
            .ok()
    }

    #[test]
    fn emitted_unary_recompiles_to_operator_tree_value() {
        if !node_available() {
            return;
        }
        let neg_neg: Expr = Expr::Unary {
            op: "-",
            operand: Box::new(Expr::Unary {
                op: "-",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        let neg_render: String = neg_neg.render(&names());
        assert_eq!(
            node_eval_with_loc1(&neg_render),
            Some(5),
            "emitted {neg_render} must evaluate to loc1 (5), not a decrement"
        );

        let plus_plus: Expr = Expr::Unary {
            op: "+",
            operand: Box::new(Expr::Unary {
                op: "+",
                operand: Box::new(Expr::Local(1)),
            }),
        };
        let plus_render: String = plus_plus.render(&names());
        assert_eq!(
            node_eval_with_loc1(&plus_render),
            Some(5),
            "emitted {plus_render} must evaluate to loc1 (5), not an increment"
        );
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
        assert!(lifted.structurally_recovered);
        assert!(lifted.reached_terminator);
        assert!(lifted.dropped_opcodes.is_empty());
        assert_eq!(lifted.opaque_operands, 0);
        assert!(lifted.fidelity_warning().is_none());
        assert_eq!(lifted.statements.len(), 1);
        assert!(matches!(lifted.statements[0], Stmt::Return(None)));
    }

    #[test]
    fn unmodelled_opcode_marks_not_structurally_recovered() {
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
            max_stack: 1,
            local_count: 1,
            init_scope_depth: 0,
            max_scope_depth: 0,
            code: vec![0x01, 0x47],
            exceptions: Vec::new(),
            traits: Vec::new(),
        };
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(lifted.reached_terminator, "returnvoid still emitted");
        assert!(
            !lifted.structurally_recovered,
            "bkpt (0x01) is unmodelled so the body must not claim structural recovery"
        );
        assert_eq!(lifted.dropped_opcodes, vec![0x01]);
        let warning: String = lifted.fidelity_warning().expect("warning present");
        assert!(
            warning.contains("0x01"),
            "warning names the opcode: {warning}"
        );
    }

    fn bare_abc() -> AbcFile {
        AbcFile {
            minor: 16,
            major: 46,
            cpool: ConstantPool::default(),
            methods: Vec::new(),
            metadata_count: 0,
            instances: Vec::new(),
            classes: Vec::new(),
            scripts: Vec::new(),
            method_bodies: Vec::new(),
        }
    }

    fn body_with_code(code: Vec<u8>) -> MethodBody {
        MethodBody {
            method: 0,
            max_stack: 4,
            local_count: 2,
            init_scope_depth: 0,
            max_scope_depth: 0,
            code,
            exceptions: Vec::new(),
            traits: Vec::new(),
        }
    }

    #[test]
    fn relative_branch_targets_saturate_at_bounds() {
        assert_eq!(relative_target(3, -10), 0);
        assert_eq!(relative_target(8, i64::MIN), 0);
        assert_eq!(relative_target(usize::MAX - 1, 10), usize::MAX);
        assert_eq!(relative_target(9, -4), 5);
    }

    #[test]
    fn dead_zero_displacement_branch_is_elided() {
        let code: Vec<u8> = vec![0xD1, 0x24, 0x00, 0x14, 0x00, 0x00, 0x00, 0x24, 0x00, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted.fully_structured,
            "an if whose target is the next statement is a dead effect-free no-op and must collapse: {:?}",
            lifted.statements
        );
        assert!(
            lifted.structurally_recovered,
            "{:?}",
            lifted.fidelity_warning()
        );
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(
            !rendered.contains("goto"),
            "no residual goto after dead-branch elision: {rendered}"
        );
    }

    #[test]
    fn empty_branch_with_side_effecting_cond_is_kept() {
        let code: Vec<u8> = vec![0x60, 0x00, 0x46, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x47];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted
                .statements
                .iter()
                .any(|s: &Stmt| matches!(s, Stmt::If { .. } | Stmt::IfBlock { .. })),
            "a branch whose condition carries a call must not be dropped: {:?}",
            lifted.statements
        );
    }

    #[test]
    fn dup_guarded_iftrue_rebuilds_a_logical_or() {
        let code: Vec<u8> = vec![0xD1, 0x2A, 0x11, 0x03, 0x00, 0x00, 0x29, 0x24, 0x07, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert_eq!(
            lifted.statements,
            vec![Stmt::Return(Some(Expr::Binary {
                op: "||",
                lhs: Box::new(Expr::Local(1)),
                rhs: Box::new(Expr::IntLit(7)),
            }))],
            "both operands of a short-circuit disjunction must survive the join"
        );
    }

    #[test]
    fn dup_guarded_iffalse_rebuilds_a_logical_and() {
        let code: Vec<u8> = vec![0xD1, 0x2A, 0x12, 0x03, 0x00, 0x00, 0x29, 0x24, 0x07, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert_eq!(
            lifted.statements,
            vec![Stmt::Return(Some(Expr::Binary {
                op: "&&",
                lhs: Box::new(Expr::Local(1)),
                rhs: Box::new(Expr::IntLit(7)),
            }))],
            "both operands of a short-circuit conjunction must survive the join"
        );
    }

    #[test]
    fn chained_short_circuit_keeps_every_operand() {
        let code: Vec<u8> = vec![
            0xD1, 0x2A, 0x11, 0x0B, 0x00, 0x00, 0x29, 0x24, 0x07, 0x2A, 0x11, 0x03, 0x00, 0x00,
            0x29, 0x24, 0x09, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let expected: Expr = Expr::Binary {
            op: "||",
            lhs: Box::new(Expr::Local(1)),
            rhs: Box::new(Expr::Binary {
                op: "||",
                lhs: Box::new(Expr::IntLit(7)),
                rhs: Box::new(Expr::IntLit(9)),
            }),
        };
        assert_eq!(
            lifted.statements,
            vec![Stmt::Return(Some(expected))],
            "a three-way disjunction must keep all three operands"
        );
    }

    #[test]
    fn branch_over_a_value_rebuilds_a_conditional_expression() {
        let code: Vec<u8> = vec![
            0xD1, 0x12, 0x06, 0x00, 0x00, 0x24, 0x01, 0x10, 0x02, 0x00, 0x00, 0x24, 0x02, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert_eq!(
            lifted.statements,
            vec![Stmt::Return(Some(Expr::Ternary {
                cond: Box::new(Expr::Local(1)),
                then_value: Box::new(Expr::IntLit(1)),
                else_value: Box::new(Expr::IntLit(2)),
            }))],
            "a value-producing branch pair is a conditional expression, not two dead labels"
        );
    }

    #[test]
    fn disconnected_non_switch_entry_keeps_legacy_stack_value() {
        let code: Vec<u8> = vec![
            0x24, 0x01, 0x10, 0x06, 0x00, 0x00, 0x47, 0x02, 0x02, 0x02, 0x02, 0x47, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let returned: &Expr = lifted
            .statements
            .iter()
            .find_map(|statement: &Stmt| match statement {
                Stmt::Return(Some(value)) => Some(value),
                _ => None,
            })
            .expect("disconnected target returns its incoming value");
        assert_eq!(returned, &Expr::IntLit(1));
        assert!(
            !lifted
                .statements
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::Comment(reason) if reason == STACK_CONFLICT_MARKER)),
            "a non-switch disconnected entry must not synthesize a switch merge marker: {:?}",
            lifted.statements
        );
    }

    #[test]
    fn non_switch_height_conflict_emits_a_local_partial_marker() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x11, 0x06, 0x00, 0x00, 0x24, 0x01, 0x10, 0x08, 0x00, 0x00, 0x24, 0x02,
            0x24, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted.statements.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == STACK_HEIGHT_CONFLICT_MARKER
            )),
            "a non-switch height disagreement must leave a local typed marker: {:?}",
            lifted.statements
        );
    }

    #[test]
    fn non_switch_join_does_not_truncate_the_legacy_stack() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x11, 0x07, 0x00, 0x00, 0x24, 0x01, 0x02, 0x10, 0x06, 0x00, 0x00, 0x24,
            0x02, 0x10, 0x00, 0x00, 0x00, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let returned: &Expr = lifted
            .statements
            .iter()
            .find_map(|statement: &Stmt| match statement {
                Stmt::Return(Some(value)) => Some(value),
                _ => None,
            })
            .expect("non-switch join returns a value");
        assert_eq!(returned, &Expr::IntLit(2));
    }

    #[test]
    fn backward_switch_exposes_a_named_refusal() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x1B, 0xFE, 0xFF, 0xFF, 0x01, 0xFE, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0x47,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted.statements.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_DIRECTION_REFUSAL_MARKER
            )),
            "a backward switch must expose its refusal reason: {:?}",
            lifted.statements
        );
    }

    #[test]
    fn switch_analysis_budget_refusal_is_local_and_named() {
        const SWITCHES: usize = 33_000;
        let mut code: Vec<u8> = Vec::with_capacity(SWITCHES * 8 + 1);
        for _ in 0..SWITCHES {
            code.extend_from_slice(&[0x1B, 0x08, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00]);
        }
        code.push(0x47);
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted.statements.iter().any(|statement: &Stmt| matches!(
                statement,
                Stmt::Comment(reason) if reason == SWITCH_ANALYSIS_BUDGET_MARKER
            )),
            "a cumulative switch-analysis budget must leave a local named marker"
        );
    }

    #[test]
    fn switch_join_with_distinct_equal_height_values_uses_a_phi() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x1B, 0x17, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x11, 0x00, 0x00, 0x24,
            0x0A, 0x10, 0x08, 0x00, 0x00, 0x24, 0x14, 0x10, 0x02, 0x00, 0x00, 0x24, 0x1E, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let returned: &Expr = lifted
            .statements
            .iter()
            .find_map(|statement: &Stmt| match statement {
                Stmt::Return(Some(value)) => Some(value),
                _ => None,
            })
            .expect("switch merge returns a value");
        assert_eq!(
            returned,
            &Expr::Phi { block: 27, slot: 0 },
            "three distinct case values must merge instead of selecting the last linear case"
        );
        assert_eq!(lifted.opaque_operands, 1);
        assert!(!lifted.structurally_recovered);
    }

    #[test]
    fn switch_join_preserves_an_identical_value_from_every_predecessor() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x1B, 0x17, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x11, 0x00, 0x00, 0x24,
            0x0A, 0x10, 0x08, 0x00, 0x00, 0x24, 0x0A, 0x10, 0x02, 0x00, 0x00, 0x24, 0x0A, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let returned: &Expr = lifted
            .statements
            .iter()
            .find_map(|statement: &Stmt| match statement {
                Stmt::Return(Some(value)) => Some(value),
                _ => None,
            })
            .expect("switch merge returns a value");
        assert_eq!(returned, &Expr::IntLit(10));
        assert_eq!(lifted.opaque_operands, 0);
        assert!(lifted.structurally_recovered);
    }

    #[test]
    fn switch_join_with_different_stack_heights_stays_unstructured() {
        let code: Vec<u8> = vec![
            0x24, 0x00, 0x1B, 0x19, 0x00, 0x00, 0x01, 0x0B, 0x00, 0x00, 0x11, 0x00, 0x00, 0x24,
            0x0A, 0x10, 0x0A, 0x00, 0x00, 0x24, 0x14, 0x24, 0x15, 0x10, 0x02, 0x00, 0x00, 0x24,
            0x1E, 0x48,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            !lifted.fully_structured,
            "a switch whose predecessors disagree on stack height must retain its raw CFG"
        );
        assert!(
            lifted
                .statements
                .iter()
                .any(|statement: &Stmt| matches!(statement, Stmt::Switch { .. })),
            "the unproven switch must not be rewritten as a structured switch"
        );
        assert!(!lifted.structurally_recovered);
    }

    #[test]
    fn dup_into_a_local_reuses_the_local_instead_of_repeating_the_value() {
        let code: Vec<u8> = vec![0x60, 0x00, 0x2A, 0xD5, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert_eq!(
            lifted.statements,
            vec![
                Stmt::Assign {
                    target: Expr::Local(1),
                    value: Expr::Lex(String::new()),
                },
                Stmt::Return(Some(Expr::Local(1))),
            ],
            "the copy left by a dup is the stored local, not a second evaluation"
        );
    }

    #[test]
    fn a_property_read_held_across_a_store_is_saved_first() {
        let code: Vec<u8> = vec![0xD0, 0xD0, 0x66, 0x01, 0xD0, 0x24, 0x01, 0x61, 0x01, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let saved: Expr = Expr::Name("_temp0".to_owned());
        assert_eq!(
            lifted.statements,
            vec![
                Stmt::Assign {
                    target: saved.clone(),
                    value: Expr::Get {
                        object: Box::new(Expr::This),
                        property: "mn#1".to_owned(),
                    },
                },
                Stmt::AssignProperty {
                    object: Expr::This,
                    property: "mn#1".to_owned(),
                    value: Expr::IntLit(1),
                },
                Stmt::Return(Some(saved)),
            ],
            "a pending read of the property being written must be captured before the write"
        );
    }

    #[test]
    fn while_loop_with_back_jump_is_structured() {
        let code: Vec<u8> = vec![
            0x10, 0x05, 0x00, 0x00, 0xD1, 0x24, 0x01, 0xA0, 0xD5, 0xD1, 0x24, 0x0A, 0x15, 0xF4,
            0xFF, 0xFF, 0x47,
        ];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(
            lifted.dropped_opcodes.is_empty(),
            "no opcode should drop: {:?}",
            lifted.dropped_opcodes
        );
        let while_count: usize = lifted
            .statements
            .iter()
            .filter(|s: &&Stmt| matches!(s, Stmt::While { .. }))
            .count();
        assert_eq!(while_count, 1, "back-jump must fold into one while loop");
        let goto_count: usize = lifted
            .statements
            .iter()
            .filter(|s: &&Stmt| matches!(s, Stmt::Jump { .. } | Stmt::If { .. } | Stmt::Label(_)))
            .count();
        assert_eq!(goto_count, 0, "loop scaffolding gotos/labels are consumed");
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(
            rendered.contains("while ((loc1 < 10))"),
            "while header recovered: {rendered}"
        );
        assert!(
            rendered.contains("loc1 = (loc1 + 1);"),
            "loop body recovered: {rendered}"
        );
        assert!(!rendered.contains("goto"), "no residual gotos: {rendered}");
    }

    #[test]
    fn try_catch_region_is_structured() {
        let code: Vec<u8> = vec![
            0xD1, 0x24, 0x01, 0xA0, 0xD5, 0x10, 0x08, 0x00, 0x00, 0x5A, 0x00, 0xD6, 0xD2, 0x24,
            0x01, 0xA0, 0xD6, 0x47,
        ];
        let abc: AbcFile = bare_abc();
        let mut body: MethodBody = body_with_code(code);
        body.exceptions = vec![crate::abc::ExceptionInfo {
            from: 0,
            to: 5,
            target: 9,
            exc_type: 0,
            var_name: 0,
        }];
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let try_count: usize = lifted
            .statements
            .iter()
            .filter(|s: &&Stmt| matches!(s, Stmt::Try { .. }))
            .count();
        assert_eq!(
            try_count, 1,
            "exception region must fold into one try block"
        );
        let try_stmt: &Stmt = lifted
            .statements
            .iter()
            .find(|s: &&Stmt| matches!(s, Stmt::Try { .. }))
            .expect("try statement present");
        let Stmt::Try { body, catches }: &Stmt = try_stmt else {
            unreachable!("filtered to Try above")
        };
        assert_eq!(catches.len(), 1, "single catch clause");
        assert!(
            body.iter().any(|s: &Stmt| matches!(s, Stmt::Assign { .. })),
            "try body retains its assignment: {body:?}"
        );
        assert!(
            !catches[0].body.iter().any(|s: &Stmt| matches!(
                s,
                Stmt::Assign {
                    value: Expr::ScopeObject,
                    ..
                }
            )),
            "catch prologue scope binding is stripped: {:?}",
            catches[0].body
        );
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(rendered.contains("try {"), "try header: {rendered}");
        assert!(
            rendered.contains("catch (error: *) {"),
            "catch header: {rendered}"
        );
        assert!(
            rendered.contains("loc1 = (loc1 + 1);"),
            "try body recovered: {rendered}"
        );
        assert!(
            rendered.contains("loc2 = (loc2 + 1);"),
            "catch body recovered: {rendered}"
        );
        assert!(!rendered.contains("goto"), "no residual gotos: {rendered}");
    }

    #[test]
    fn stack_underflow_marks_opaque_operands() {
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
            max_stack: 1,
            local_count: 1,
            init_scope_depth: 0,
            max_scope_depth: 0,
            code: vec![0x48],
            exceptions: Vec::new(),
            traits: Vec::new(),
        };
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        assert!(lifted.reached_terminator);
        assert!(
            !lifted.structurally_recovered,
            "returnvalue with empty stack underflows"
        );
        assert_eq!(lifted.opaque_operands, 1);
        assert!(
            lifted
                .fidelity_warning()
                .is_some_and(|w: String| w.contains("fabricated operand"))
        );
    }

    #[test]
    fn missing_instruction_operand_marks_opaque_operands() {
        let abc: AbcFile = bare_abc();
        let local_names: LocalNames = names();
        let slot_names: BTreeMap<u32, String> = BTreeMap::new();
        let mut lifter: Lifter<'_> = Lifter {
            abc: &abc,
            stack: vec![Expr::This],
            statements: Vec::new(),
            names: &local_names,
            slot_names: &slot_names,
            dropped_opcodes: Vec::new(),
            opaque_operands: 0,
            scope_stack: Vec::new(),
            with_regions: Vec::new(),
            idioms: Idioms::default(),
            short_circuits: Vec::new(),
            branch_marks: Vec::new(),
            hoisted_temporaries: 0,
            incoming_stacks: BTreeMap::new(),
            incoming_scopes: BTreeMap::new(),
            untracked_stack_entries: BTreeSet::new(),
            untracked_scope_entries: BTreeSet::new(),
            tracked_stack_nodes: 0,
            tracked_scope_nodes: 0,
            stack_tracking_exhausted: false,
            scope_tracking_exhausted: false,
            switch_direction_refusals: BTreeSet::new(),
            switch_budget_refusals: BTreeSet::new(),
        };
        let line: DisasmLine = DisasmLine {
            offset: 0,
            opcode: 0x46,
            mnemonic: "callproperty",
            operands: vec![0],
        };
        step(&mut lifter, &line, 1, 1);
        assert_eq!(lifter.opaque_operands, 1);
        assert!(matches!(lifter.stack.as_slice(), [Expr::Call { .. }]));
    }

    #[test]
    fn dup_then_multiply_chain_stays_bounded() {
        const DUP_PAIRS: usize = 200;
        let mut code: Vec<u8> = vec![0x24, 0x05];
        for _ in 0..DUP_PAIRS {
            code.push(0x2A);
            code.push(0xA2);
        }
        code.push(0x48);
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let returned: &Expr = lifted
            .statements
            .iter()
            .find_map(|s: &Stmt| match s {
                Stmt::Return(Some(e)) => Some(e),
                _ => None,
            })
            .expect("returnvalue carries the dup-chain expression");
        let linear_ceiling: usize = MAX_DUP_EXPR_NODES
            .saturating_mul(2)
            .saturating_add(DUP_PAIRS.saturating_mul(2))
            .saturating_add(64);
        let measured: usize = expr_node_count_capped(returned, linear_ceiling.saturating_mul(8));
        assert!(
            measured <= linear_ceiling,
            "dup-bomb growth must stay linear under the node cap, not double per pair: {measured} nodes"
        );
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(
            rendered.len() < 1_000_000,
            "dup-bomb render must stay bounded, got {} bytes",
            rendered.len()
        );
        assert!(
            rendered.contains("/* ? */"),
            "dup cap must emit the opaque hole marker"
        );
    }

    #[test]
    fn newobject_with_huge_count_does_not_overcommit() {
        let code: Vec<u8> = vec![0x55, 0xFF, 0xFF, 0xFF, 0xFF, 0x03, 0x48];
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift");
        let object_pairs: usize = lifted
            .statements
            .iter()
            .find_map(|s: &Stmt| match s {
                Stmt::Return(Some(Expr::Object(pairs))) => Some(pairs.len()),
                _ => None,
            })
            .expect("newobject result reaches the return");
        assert!(
            object_pairs <= MAX_DUP_EXPR_NODES,
            "newobject capacity must follow the clamped pop length, not the raw u30: got {object_pairs} pairs"
        );
    }

    #[test]
    fn dup_clone_bails_on_oversized_tree() {
        let small: Expr = Expr::Binary {
            op: "+",
            lhs: Box::new(Expr::IntLit(1)),
            rhs: Box::new(Expr::IntLit(2)),
        };
        assert_eq!(dup_clone(&small), small);
        let mut big: Expr = Expr::IntLit(0);
        for _ in 0..MAX_DUP_EXPR_NODES {
            big = Expr::Unary {
                op: "-",
                operand: Box::new(big),
            };
        }
        assert_eq!(dup_clone(&big), Expr::Opaque("?"));
    }

    #[test]
    fn scope_tracking_refuses_an_oversized_expression_tree() {
        let mut object: Expr = Expr::IntLit(0);
        for _index in 0..MAX_DUP_EXPR_NODES {
            object = Expr::Unary {
                op: "-",
                operand: Box::new(object),
            };
        }
        let entries: Vec<ScopeEntry> = vec![ScopeEntry {
            object,
            is_with: false,
            identity: 0,
        }];
        assert_eq!(scope_node_count_capped(&entries, 65_536), 65_537);
    }

    fn nested_with_chain(levels: usize) -> Vec<Stmt> {
        let mut acc: Vec<Stmt> = vec![Stmt::Comment("leaf".to_owned())];
        for _ in 0..levels {
            acc = vec![Stmt::With {
                object: Expr::Null,
                body: acc,
            }];
        }
        acc
    }

    fn with_block_nesting(stmt: &Stmt) -> usize {
        match stmt {
            Stmt::With { body, .. } => 1 + body.iter().map(with_block_nesting).max().unwrap_or(0),
            _ => 0,
        }
    }

    fn flat_with_region_input(levels: usize) -> (Vec<Stmt>, Vec<WithRegion>) {
        let span: usize = levels * 2 + 2;
        let stmts: Vec<Stmt> = (0..span)
            .map(|i: usize| Stmt::Comment(format!("s{i}")))
            .collect();
        let regions: Vec<WithRegion> = (0..levels)
            .map(|k: usize| WithRegion {
                open_stmt: k,
                close_stmt: span - k,
                object: Expr::Null,
            })
            .collect();
        (stmts, regions)
    }

    #[test]
    fn structure_with_caps_expansion_at_depth_budget() {
        let levels: usize = MAX_STRUCTURE_DEPTH + 64;
        let (stmts, regions): (Vec<Stmt>, Vec<WithRegion>) = flat_with_region_input(levels);
        let out: Vec<Stmt> = structure_with(stmts, &regions, MAX_STRUCTURE_DEPTH);
        let outer: &Stmt = out
            .iter()
            .find(|s: &&Stmt| matches!(s, Stmt::With { .. }))
            .expect("outermost with is still recovered");
        assert_eq!(
            with_block_nesting(outer),
            MAX_STRUCTURE_DEPTH,
            "region expansion must stop exactly at the depth budget, not at the {levels} declared regions"
        );
    }

    #[test]
    fn shallow_with_nesting_is_fully_structured() {
        let (stmts, regions): (Vec<Stmt>, Vec<WithRegion>) = flat_with_region_input(3);
        let out: Vec<Stmt> = structure_with(stmts, &regions, MAX_STRUCTURE_DEPTH);
        let outer: &Stmt = out
            .iter()
            .find(|s: &&Stmt| matches!(s, Stmt::With { .. }))
            .expect("outermost with present");
        assert_eq!(
            with_block_nesting(outer),
            3,
            "all three nested regions recovered when under the cap"
        );
    }

    #[test]
    fn structure_loops_terminates_on_deep_with_nesting() {
        let levels: usize = MAX_STRUCTURE_DEPTH + 64;
        let out: Vec<Stmt> = structure_loops(nested_with_chain(levels), MAX_STRUCTURE_DEPTH);
        assert_eq!(out.len(), 1, "single outer with survives the bounded walk");
        assert_eq!(
            with_block_nesting(&out[0]),
            levels,
            "loop structuring preserves the existing with chain without inflating it"
        );
    }

    #[test]
    fn structure_if_blocks_terminates_on_deep_with_nesting() {
        let levels: usize = MAX_STRUCTURE_DEPTH + 64;
        let out: Vec<Stmt> = structure_if_blocks(nested_with_chain(levels), MAX_STRUCTURE_DEPTH);
        assert_eq!(out.len(), 1, "single outer with survives the bounded walk");
    }

    #[test]
    fn structure_switches_terminates_on_deep_with_nesting() {
        let levels: usize = MAX_STRUCTURE_DEPTH + 64;
        let out: Vec<Stmt> = structure_switches(nested_with_chain(levels), MAX_STRUCTURE_DEPTH);
        assert_eq!(out.len(), 1, "single outer with survives the bounded walk");
    }

    #[test]
    fn lift_body_survives_deep_branch_chain() {
        const BRANCHES: usize = 4096;
        let mut code: Vec<u8> = Vec::new();
        for _ in 0..BRANCHES {
            code.push(0x26);
            code.push(0x12);
            code.push(0x00);
            code.push(0x00);
            code.push(0x00);
        }
        code.push(0x47);
        let abc: AbcFile = bare_abc();
        let body: MethodBody = body_with_code(code);
        let lifted: LiftedBody = lift_body(&abc, &body, None).expect("lift must not overflow");
        assert!(
            lifted.reached_terminator,
            "returnvoid is still emitted after the branch chain"
        );
        let rendered: String = render_body(&lifted, &names(), "");
        assert!(
            rendered.len() < 8_000_000,
            "render stays bounded: {} bytes",
            rendered.len()
        );
    }

    #[test]
    fn degenerate_exception_region_to_equals_target_returns_unchanged() {
        let stmts: Vec<Stmt> = vec![
            Stmt::Label(0),
            Stmt::Assign {
                target: Expr::Local(1),
                value: Expr::IntLit(5),
            },
            Stmt::Label(5),
            Stmt::Return(None),
        ];
        let regions: Vec<RegionInfo> = vec![RegionInfo {
            from: 0,
            to: 5,
            target: 5,
            var_name: "error".to_owned(),
            type_name: "*".to_owned(),
        }];
        let out: Vec<Stmt> = structure_try(stmts.clone(), &regions, MAX_STRUCTURE_DEPTH);
        assert_eq!(
            out, stmts,
            "a to==target exception region has no gap slice and must early-return untouched"
        );
        assert!(
            !out.iter().any(|s: &Stmt| matches!(s, Stmt::Try { .. })),
            "no try block is fabricated from a degenerate region: {out:?}"
        );
    }

    #[test]
    fn inverted_exception_region_target_before_to_returns_unchanged() {
        let stmts: Vec<Stmt> = vec![
            Stmt::Label(0),
            Stmt::Assign {
                target: Expr::Local(1),
                value: Expr::IntLit(5),
            },
            Stmt::Label(9),
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::IntLit(7),
            },
            Stmt::Label(5),
            Stmt::Return(None),
        ];
        let regions: Vec<RegionInfo> = vec![RegionInfo {
            from: 0,
            to: 5,
            target: 9,
            var_name: "error".to_owned(),
            type_name: "*".to_owned(),
        }];
        let out: Vec<Stmt> = structure_try(stmts.clone(), &regions, MAX_STRUCTURE_DEPTH);
        assert_eq!(
            out, stmts,
            "a target-before-to region violates from<to<target and must early-return untouched"
        );
    }

    #[test]
    fn well_formed_exception_region_still_structures() {
        let stmts: Vec<Stmt> = vec![
            Stmt::Label(0),
            Stmt::Assign {
                target: Expr::Local(1),
                value: Expr::IntLit(5),
            },
            Stmt::Jump { target_label: 100 },
            Stmt::Label(5),
            Stmt::Label(9),
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::CaughtException,
            },
            Stmt::Assign {
                target: Expr::Local(2),
                value: Expr::IntLit(7),
            },
            Stmt::Label(100),
            Stmt::Return(None),
        ];
        let regions: Vec<RegionInfo> = vec![RegionInfo {
            from: 0,
            to: 5,
            target: 9,
            var_name: "error".to_owned(),
            type_name: "*".to_owned(),
        }];
        let out: Vec<Stmt> = structure_try(stmts, &regions, MAX_STRUCTURE_DEPTH);
        let try_stmt: &Stmt = out
            .iter()
            .find(|s: &&Stmt| matches!(s, Stmt::Try { .. }))
            .expect("from<to<target region folds into a try");
        let Stmt::Try { body, catches }: &Stmt = try_stmt else {
            unreachable!("filtered to Try above")
        };
        assert_eq!(catches.len(), 1, "single catch clause");
        assert!(
            body.iter().any(|s: &Stmt| matches!(
                s,
                Stmt::Assign {
                    value: Expr::IntLit(5),
                    ..
                }
            )),
            "try body retains its assignment: {body:?}"
        );
        assert!(
            catches[0].body.iter().any(|s: &Stmt| matches!(
                s,
                Stmt::Assign {
                    value: Expr::IntLit(7),
                    ..
                }
            )),
            "catch body retains its assignment: {:?}",
            catches[0].body
        );
        assert!(
            !catches[0].body.iter().any(|s: &Stmt| matches!(
                s,
                Stmt::Assign {
                    value: Expr::CaughtException,
                    ..
                }
            )),
            "catch prologue is stripped: {:?}",
            catches[0].body
        );
    }
}
