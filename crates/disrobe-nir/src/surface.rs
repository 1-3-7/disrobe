use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::hir::{
    HirCond, HirCondExpr, HirCondRoute, HirCondTest, HirDispatchCase, HirExpr, HirFunction,
    HirInstrStmt, HirLeafStmt, HirModule, HirStmt,
};
use crate::types::{BinaryOp, NirInstr, NirModule, NirSymbol, SourceLang, SourceRef};

const MAX_SURFACE_DEPTH: usize = 128;
const UNRECOVERED_EXPRESSION: &str = "__unrecovered_expression";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceType {
    Bool,
    Byte,
    Word,
    Pointer,
    Unknown,
}

impl SurfaceType {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Bool => "bool",
            Self::Byte => "u8",
            Self::Word => "word",
            Self::Pointer => "ptr",
            Self::Unknown => "auto",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SurfaceExpr {
    Literal {
        text: String,
    },
    Local {
        name: String,
    },
    Field {
        cell: String,
    },
    Unary {
        op: BinaryOp,
        operand: Box<Self>,
    },
    Binary {
        op: BinaryOp,
        lhs: Box<Self>,
        rhs: Box<Self>,
    },
    Call {
        target: Option<String>,
        args: Vec<Self>,
    },
    Raw {
        text: String,
    },
}

impl SurfaceExpr {
    fn referenced_locals(&self, out: &mut BTreeSet<String>) {
        let mut pending: Vec<&Self> = vec![self];
        while let Some(expression) = pending.pop() {
            match expression {
                Self::Local { name } => {
                    out.insert(name.clone());
                }
                Self::Unary { operand, .. } => pending.push(operand),
                Self::Binary { lhs, rhs, .. } => {
                    pending.push(lhs);
                    pending.push(rhs);
                }
                Self::Call { args, .. } => pending.extend(args),
                Self::Literal { .. } | Self::Field { .. } | Self::Raw { .. } => {}
            }
        }
    }

    fn unlink_children(&mut self, pending: &mut Vec<Self>) {
        match self {
            Self::Unary { operand, .. } => {
                let operand: Self = std::mem::replace(
                    operand.as_mut(),
                    Self::Raw {
                        text: String::new(),
                    },
                );
                pending.push(operand);
            }
            Self::Binary { lhs, rhs, .. } => {
                let lhs: Self = std::mem::replace(
                    lhs.as_mut(),
                    Self::Raw {
                        text: String::new(),
                    },
                );
                let rhs: Self = std::mem::replace(
                    rhs.as_mut(),
                    Self::Raw {
                        text: String::new(),
                    },
                );
                pending.push(lhs);
                pending.push(rhs);
            }
            Self::Call { args, .. } => pending.extend(std::mem::take(args)),
            Self::Literal { .. } | Self::Local { .. } | Self::Field { .. } | Self::Raw { .. } => {}
        }
    }

    const fn inferred_type(&self) -> SurfaceType {
        match self {
            Self::Literal { .. } => SurfaceType::Word,
            Self::Field { .. } => SurfaceType::Pointer,
            Self::Binary { op, .. } | Self::Unary { op, .. } if is_bitwise(*op) => {
                SurfaceType::Word
            }
            Self::Local { .. }
            | Self::Unary { .. }
            | Self::Binary { .. }
            | Self::Call { .. }
            | Self::Raw { .. } => SurfaceType::Unknown,
        }
    }
}

impl Drop for SurfaceExpr {
    fn drop(&mut self) {
        let mut pending: Vec<Self> = Vec::new();
        self.unlink_children(&mut pending);
        while let Some(mut expression) = pending.pop() {
            expression.unlink_children(&mut pending);
        }
    }
}

const fn is_bitwise(op: BinaryOp) -> bool {
    matches!(
        op,
        BinaryOp::And
            | BinaryOp::Or
            | BinaryOp::Xor
            | BinaryOp::Shl
            | BinaryOp::Shr
            | BinaryOp::Not
    )
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceLocal {
    pub name: String,
    pub ty: SurfaceType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceConditionRoute {
    pub block_start: u64,
    pub statements: Vec<SurfaceLeaf>,
    pub successor: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceConditionTest {
    pub block_start: u64,
    pub statements: Vec<SurfaceLeaf>,
    pub at: u64,
    pub mnemonic: String,
    pub operands: Vec<String>,
    pub taken_target: Option<u64>,
    pub fallthrough_target: Option<u64>,
    pub taken_route: Vec<SurfaceConditionRoute>,
    pub fallthrough_route: Vec<SurfaceConditionRoute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "condition", rename_all = "kebab-case")]
pub enum SurfaceConditionExpr {
    Test {
        test: SurfaceConditionTest,
        negated: bool,
    },
    All {
        terms: Vec<Self>,
    },
    Any {
        terms: Vec<Self>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceCondition {
    pub expression: SurfaceConditionExpr,
    pub taken_target: Option<u64>,
    pub fallthrough_target: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "node", rename_all = "kebab-case")]
pub enum SurfaceStmt {
    Block {
        body: Vec<Self>,
    },
    Leaf {
        block_start: u64,
        statements: Vec<SurfaceLeaf>,
    },
    If {
        cond: SurfaceCondition,
        then_branch: Box<Self>,
        else_branch: Box<Self>,
    },
    Loop {
        label: u64,
        body: Box<Self>,
    },
    Break {
        label: u64,
    },
    Continue {
        label: u64,
    },
    Return {
        value: Option<SurfaceExpr>,
    },
    Switch {
        entry: u64,
        cases: Vec<SurfaceCase>,
    },
    GotoGraph {
        entry: u64,
        blocks: Vec<SurfaceCase>,
    },
    Nop,
}

impl SurfaceStmt {
    fn unlink_children(&mut self, pending: &mut Vec<Self>) {
        match self {
            Self::Block { body } => pending.extend(std::mem::take(body)),
            Self::If {
                then_branch,
                else_branch,
                ..
            } => {
                let then_branch: Self = std::mem::replace(then_branch.as_mut(), Self::Nop);
                let else_branch: Self = std::mem::replace(else_branch.as_mut(), Self::Nop);
                pending.push(then_branch);
                pending.push(else_branch);
            }
            Self::Loop { body, .. } => {
                let body: Self = std::mem::replace(body.as_mut(), Self::Nop);
                pending.push(body);
            }
            Self::Leaf { .. }
            | Self::Break { .. }
            | Self::Continue { .. }
            | Self::Return { .. }
            | Self::Switch { .. }
            | Self::GotoGraph { .. }
            | Self::Nop => {}
        }
    }
}

impl Drop for SurfaceStmt {
    fn drop(&mut self) {
        let mut pending: Vec<Self> = Vec::new();
        self.unlink_children(&mut pending);
        while let Some(mut statement) = pending.pop() {
            statement.unlink_children(&mut pending);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceCase {
    pub block_start: u64,
    pub statements: Vec<SurfaceLeaf>,
    pub successors: Vec<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceLeaf {
    pub instr: NirInstr,
    pub stmt: SurfaceStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "stmt", rename_all = "kebab-case")]
pub enum SurfaceStatement {
    Assign {
        target: SurfaceExpr,
        value: SurfaceExpr,
    },
    Store {
        cell: SurfaceExpr,
        value: SurfaceExpr,
    },
    Call {
        target: Option<String>,
        args: Vec<SurfaceExpr>,
    },
    Expr {
        value: SurfaceExpr,
    },
}

impl SurfaceStatement {
    fn collect_locals(&self, out: &mut BTreeMap<String, SurfaceType>) {
        match self {
            Self::Assign { target, value } => {
                declare_target_local(target, value, out);
                value.referenced_locals_typed(out);
            }
            Self::Store { cell, value } => {
                cell.referenced_locals_typed(out);
                value.referenced_locals_typed(out);
            }
            Self::Call { args, .. } => {
                for arg in args {
                    arg.referenced_locals_typed(out);
                }
            }
            Self::Expr { value } => value.referenced_locals_typed(out),
        }
    }
}

impl SurfaceExpr {
    fn referenced_locals_typed(&self, out: &mut BTreeMap<String, SurfaceType>) {
        let mut names: BTreeSet<String> = BTreeSet::new();
        self.referenced_locals(&mut names);
        for name in names {
            out.entry(name).or_insert(SurfaceType::Unknown);
        }
    }
}

fn declare_target_local(
    target: &SurfaceExpr,
    value: &SurfaceExpr,
    out: &mut BTreeMap<String, SurfaceType>,
) {
    if let SurfaceExpr::Local { name } = target {
        let ty: SurfaceType = value.inferred_type();
        out.entry(name.clone())
            .and_modify(|existing: &mut SurfaceType| {
                if *existing == SurfaceType::Unknown {
                    *existing = ty;
                }
            })
            .or_insert(ty);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceSignature {
    pub name: String,
    pub params: Vec<SurfaceLocal>,
    pub return_type: SurfaceType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceFunction {
    pub signature: SurfaceSignature,
    pub address: u64,
    pub end: u64,
    pub is_export: bool,
    pub locals: Vec<SurfaceLocal>,
    pub body: SurfaceStmt,
    pub structured: bool,
    pub source: SourceRef,
}

impl SurfaceFunction {
    #[must_use]
    pub fn name(&self) -> &str {
        &self.signature.name
    }

    #[must_use]
    pub fn block_starts(&self) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = BTreeSet::new();
        collect_block_starts(&self.body, &mut out);
        out
    }

    #[must_use]
    pub fn instruction_addresses(&self) -> BTreeSet<u64> {
        let mut out: BTreeSet<u64> = BTreeSet::new();
        collect_addresses(&self.body, &mut out);
        out
    }

    #[must_use]
    pub fn to_nir_function(&self) -> crate::types::NirFunction {
        let mut instructions: Vec<NirInstr> = Vec::new();
        collect_instructions(&self.body, &mut instructions);
        instructions.sort_by_key(|i: &NirInstr| i.address);
        crate::types::NirFunction {
            name: self.signature.name.clone(),
            address: self.address,
            end: self.end,
            is_export: self.is_export,
            instructions,
            source: self.source.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SurfaceModule {
    pub source_hash: [u8; 32],
    pub lang: SourceLang,
    pub functions: Vec<SurfaceFunction>,
    pub symbols: Vec<NirSymbol>,
}

impl SurfaceModule {
    #[must_use]
    pub fn to_nir_module(&self) -> NirModule {
        NirModule {
            source_hash: self.source_hash,
            lang: self.lang,
            functions: self
                .functions
                .iter()
                .map(SurfaceFunction::to_nir_function)
                .collect(),
            symbols: self.symbols.clone(),
        }
    }

    #[must_use]
    pub fn fully_structured(&self) -> bool {
        self.functions
            .iter()
            .all(|f: &SurfaceFunction| f.structured)
    }
}

#[must_use]
pub fn surfacify_module(module: &HirModule) -> SurfaceModule {
    SurfaceModule {
        source_hash: module.source_hash,
        lang: module.lang,
        functions: module.functions.iter().map(surfacify_function).collect(),
        symbols: module.symbols.clone(),
    }
}

#[must_use]
pub fn surfacify_function(function: &HirFunction) -> SurfaceFunction {
    let exceeded: bool = hir_stmt_exceeds_depth(&function.body);
    let fallback: Option<HirStmt> = if exceeded {
        let nir: crate::types::NirFunction = function.to_nir_function();
        Some(crate::hir::complete_fallback_body(&nir))
    } else {
        None
    };
    let input_body: &HirStmt = fallback.as_ref().unwrap_or(&function.body);
    let mut lifter: Lifter = Lifter::new();
    let body: SurfaceStmt = lifter.lift(input_body, 0);
    let mut declared: BTreeMap<String, SurfaceType> = BTreeMap::new();
    collect_locals(&body, &mut declared);
    let locals: Vec<SurfaceLocal> = declared
        .into_iter()
        .map(|(name, ty): (String, SurfaceType)| SurfaceLocal { name, ty })
        .collect();
    let return_type: SurfaceType = body_return_type(&body);
    SurfaceFunction {
        signature: SurfaceSignature {
            name: function.name.clone(),
            params: Vec::new(),
            return_type,
        },
        address: function.address,
        end: function.end,
        is_export: function.is_export,
        locals,
        body,
        structured: function.structured && !exceeded && lifter.complete,
        source: function.source.clone(),
    }
}

fn hir_stmt_exceeds_depth(stmt: &HirStmt) -> bool {
    let mut pending: Vec<(&HirStmt, usize)> = vec![(stmt, 0)];
    while let Some((current, depth)) = pending.pop() {
        if depth >= MAX_SURFACE_DEPTH {
            return true;
        }
        let child_depth: usize = depth.saturating_add(1);
        match current {
            HirStmt::Seq { body } => {
                for child in body {
                    pending.push((child, child_depth));
                }
            }
            HirStmt::If {
                cond,
                then_branch,
                else_branch,
            } => {
                if condition_exceeds_depth(&cond.expression, child_depth) {
                    return true;
                }
                pending.push((then_branch, child_depth));
                pending.push((else_branch, child_depth));
            }
            HirStmt::Loop { body, .. } => pending.push((body, child_depth)),
            HirStmt::Leaf { .. }
            | HirStmt::Break { .. }
            | HirStmt::Continue { .. }
            | HirStmt::Return { .. }
            | HirStmt::Dispatch { .. }
            | HirStmt::GotoGraph { .. }
            | HirStmt::Empty => {}
        }
    }
    false
}

fn condition_exceeds_depth(expression: &HirCondExpr, depth: usize) -> bool {
    let mut pending: Vec<(&HirCondExpr, usize)> = vec![(expression, depth)];
    while let Some((current, current_depth)) = pending.pop() {
        if current_depth >= MAX_SURFACE_DEPTH {
            return true;
        }
        let child_depth: usize = current_depth.saturating_add(1);
        match current {
            HirCondExpr::Test { .. } => {}
            HirCondExpr::All { terms } | HirCondExpr::Any { terms } => {
                pending.extend(terms.iter().map(|term: &HirCondExpr| (term, child_depth)));
            }
        }
    }
    false
}

struct Lifter {
    complete: bool,
}

impl Lifter {
    const fn new() -> Self {
        Self { complete: true }
    }

    fn lift(&mut self, stmt: &HirStmt, depth: usize) -> SurfaceStmt {
        if depth >= MAX_SURFACE_DEPTH {
            self.complete = false;
            return SurfaceStmt::Nop;
        }
        match stmt {
            HirStmt::Empty => SurfaceStmt::Nop,
            HirStmt::Seq { body } => {
                let lowered: Vec<SurfaceStmt> = body
                    .iter()
                    .map(|child: &HirStmt| self.lift(child, depth + 1))
                    .collect();
                block(lowered)
            }
            HirStmt::Leaf { block_start, stmts } => self.lift_leaf(*block_start, stmts),
            HirStmt::If {
                cond,
                then_branch,
                else_branch,
            } => {
                let then_lowered: SurfaceStmt = self.lift(then_branch, depth + 1);
                let else_lowered: SurfaceStmt = self.lift(else_branch, depth + 1);
                SurfaceStmt::If {
                    cond: self.lift_condition(cond),
                    then_branch: Box::new(then_lowered),
                    else_branch: Box::new(else_lowered),
                }
            }
            HirStmt::Loop { label, body } => {
                let lowered: SurfaceStmt = self.lift(body, depth + 1);
                SurfaceStmt::Loop {
                    label: *label,
                    body: Box::new(lowered),
                }
            }
            HirStmt::Break { label } => SurfaceStmt::Break { label: *label },
            HirStmt::Continue { label } => SurfaceStmt::Continue { label: *label },
            HirStmt::Return { value } => SurfaceStmt::Return {
                value: value
                    .as_ref()
                    .map(|expression: &HirExpr| self.lift_expr(expression, 0)),
            },
            HirStmt::Dispatch { entry, cases } => SurfaceStmt::Switch {
                entry: *entry,
                cases: cases
                    .iter()
                    .map(|case: &HirDispatchCase| self.lift_case(case))
                    .collect(),
            },
            HirStmt::GotoGraph { entry, blocks } => SurfaceStmt::GotoGraph {
                entry: *entry,
                blocks: blocks
                    .iter()
                    .map(|case: &HirDispatchCase| self.lift_case(case))
                    .collect(),
            },
        }
    }

    fn lift_case(&mut self, case: &HirDispatchCase) -> SurfaceCase {
        SurfaceCase {
            block_start: case.block_start,
            statements: case
                .stmts
                .iter()
                .map(|leaf: &HirLeafStmt| self.lift_leaf_stmt(leaf))
                .collect(),
            successors: case.successors.clone(),
        }
    }

    fn lift_condition(&mut self, condition: &HirCond) -> SurfaceCondition {
        SurfaceCondition {
            expression: self.lift_condition_expression(&condition.expression, 0),
            taken_target: condition.taken_target,
            fallthrough_target: condition.fallthrough_target,
        }
    }

    fn lift_condition_expression(
        &mut self,
        expression: &HirCondExpr,
        depth: usize,
    ) -> SurfaceConditionExpr {
        if depth >= MAX_SURFACE_DEPTH {
            self.complete = false;
            return SurfaceConditionExpr::Any { terms: Vec::new() };
        }
        let child_depth: usize = depth.saturating_add(1);
        match expression {
            HirCondExpr::Test { test, negated } => SurfaceConditionExpr::Test {
                test: self.lift_condition_test(test),
                negated: *negated,
            },
            HirCondExpr::All { terms } => SurfaceConditionExpr::All {
                terms: terms
                    .iter()
                    .map(|term: &HirCondExpr| self.lift_condition_expression(term, child_depth))
                    .collect(),
            },
            HirCondExpr::Any { terms } => SurfaceConditionExpr::Any {
                terms: terms
                    .iter()
                    .map(|term: &HirCondExpr| self.lift_condition_expression(term, child_depth))
                    .collect(),
            },
        }
    }

    fn lift_condition_test(&mut self, test: &HirCondTest) -> SurfaceConditionTest {
        SurfaceConditionTest {
            block_start: test.block_start,
            statements: test
                .stmts
                .iter()
                .map(|leaf: &HirLeafStmt| self.lift_leaf_stmt(leaf))
                .collect(),
            at: test.at,
            mnemonic: test.mnemonic.clone(),
            operands: test.operands.clone(),
            taken_target: test.taken_target,
            fallthrough_target: test.fallthrough_target,
            taken_route: test
                .taken_route
                .iter()
                .map(|route: &HirCondRoute| self.lift_condition_route(route))
                .collect(),
            fallthrough_route: test
                .fallthrough_route
                .iter()
                .map(|route: &HirCondRoute| self.lift_condition_route(route))
                .collect(),
        }
    }

    fn lift_condition_route(&mut self, route: &HirCondRoute) -> SurfaceConditionRoute {
        SurfaceConditionRoute {
            block_start: route.block_start,
            statements: route
                .stmts
                .iter()
                .map(|leaf: &HirLeafStmt| self.lift_leaf_stmt(leaf))
                .collect(),
            successor: route.successor,
        }
    }

    fn lift_leaf(&mut self, block_start: u64, stmts: &[HirLeafStmt]) -> SurfaceStmt {
        SurfaceStmt::Leaf {
            block_start,
            statements: stmts
                .iter()
                .map(|leaf: &HirLeafStmt| self.lift_leaf_stmt(leaf))
                .collect(),
        }
    }

    fn lift_leaf_stmt(&mut self, leaf: &HirLeafStmt) -> SurfaceLeaf {
        SurfaceLeaf {
            instr: leaf.instr.clone(),
            stmt: self.lift_statement(&leaf.stmt),
        }
    }

    fn lift_statement(&mut self, stmt: &HirInstrStmt) -> SurfaceStatement {
        match stmt {
            HirInstrStmt::Assign { dst, value } => SurfaceStatement::Assign {
                target: self.lift_expr(dst, 0),
                value: self.lift_expr(value, 0),
            },
            HirInstrStmt::Store { cell, value } => SurfaceStatement::Store {
                cell: self.lift_expr(cell, 0),
                value: self.lift_expr(value, 0),
            },
            HirInstrStmt::Call { target, args } => {
                let lowered: Vec<SurfaceExpr> = args
                    .iter()
                    .map(|expression: &HirExpr| self.lift_expr(expression, 0))
                    .collect();
                SurfaceStatement::Call {
                    target: target.clone(),
                    args: lowered,
                }
            }
            HirInstrStmt::Effect { expr } => SurfaceStatement::Expr {
                value: self.lift_expr(expr, 0),
            },
        }
    }

    fn lift_expr(&mut self, expr: &HirExpr, depth: usize) -> SurfaceExpr {
        if depth >= MAX_SURFACE_DEPTH {
            self.complete = false;
            return SurfaceExpr::Raw {
                text: UNRECOVERED_EXPRESSION.to_owned(),
            };
        }
        let child_depth: usize = depth.saturating_add(1);
        match expr {
            HirExpr::Const { text } => SurfaceExpr::Literal { text: text.clone() },
            HirExpr::Var { name } => SurfaceExpr::Local { name: name.clone() },
            HirExpr::Mem { cell } => SurfaceExpr::Field { cell: cell.clone() },
            HirExpr::Unary { op, operand } => SurfaceExpr::Unary {
                op: *op,
                operand: Box::new(self.lift_expr(operand, child_depth)),
            },
            HirExpr::Binary { op, lhs, rhs } => SurfaceExpr::Binary {
                op: *op,
                lhs: Box::new(self.lift_expr(lhs, child_depth)),
                rhs: Box::new(self.lift_expr(rhs, child_depth)),
            },
            HirExpr::Call { target, args } => {
                let lowered: Vec<SurfaceExpr> = args
                    .iter()
                    .map(|expression: &HirExpr| self.lift_expr(expression, child_depth))
                    .collect();
                SurfaceExpr::Call {
                    target: target.clone(),
                    args: lowered,
                }
            }
            HirExpr::Unknown { text } => SurfaceExpr::Raw { text: text.clone() },
        }
    }
}

fn block(parts: Vec<SurfaceStmt>) -> SurfaceStmt {
    let mut flat: Vec<SurfaceStmt> = Vec::with_capacity(parts.len());
    for mut part in parts {
        match &mut part {
            SurfaceStmt::Nop => {}
            SurfaceStmt::Block { body } => flat.extend(std::mem::take(body)),
            _ => flat.push(part),
        }
    }
    match flat.len() {
        0 => SurfaceStmt::Nop,
        1 => flat.into_iter().next().unwrap_or(SurfaceStmt::Nop),
        _ => SurfaceStmt::Block { body: flat },
    }
}

fn body_return_type(stmt: &SurfaceStmt) -> SurfaceType {
    match stmt {
        SurfaceStmt::Return { value: Some(expr) } => expr.inferred_type(),
        SurfaceStmt::Block { body } => body
            .iter()
            .rev()
            .find_map(|child: &SurfaceStmt| match child {
                SurfaceStmt::Return { .. } => Some(body_return_type(child)),
                _ => None,
            })
            .unwrap_or(SurfaceType::Unknown),
        SurfaceStmt::If {
            then_branch,
            else_branch,
            ..
        } => {
            let then_ty: SurfaceType = body_return_type(then_branch);
            if then_ty == SurfaceType::Unknown {
                body_return_type(else_branch)
            } else {
                then_ty
            }
        }
        SurfaceStmt::Loop { body, .. } => body_return_type(body),
        SurfaceStmt::Return { value: None }
        | SurfaceStmt::Switch { .. }
        | SurfaceStmt::GotoGraph { .. }
        | SurfaceStmt::Leaf { .. }
        | SurfaceStmt::Break { .. }
        | SurfaceStmt::Continue { .. }
        | SurfaceStmt::Nop => SurfaceType::Unknown,
    }
}

fn collect_locals(stmt: &SurfaceStmt, out: &mut BTreeMap<String, SurfaceType>) {
    match stmt {
        SurfaceStmt::Leaf { statements, .. } => {
            for leaf in statements {
                leaf.stmt.collect_locals(out);
            }
        }
        SurfaceStmt::Switch { cases, .. } => {
            for case in cases {
                for leaf in &case.statements {
                    leaf.stmt.collect_locals(out);
                }
            }
        }
        SurfaceStmt::GotoGraph { blocks, .. } => {
            for block in blocks {
                for leaf in &block.statements {
                    leaf.stmt.collect_locals(out);
                }
            }
        }
        SurfaceStmt::Block { body } => {
            for child in body {
                collect_locals(child, out);
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_condition_locals(&cond.expression, out);
            collect_locals(then_branch, out);
            collect_locals(else_branch, out);
        }
        SurfaceStmt::Loop { body, .. } => collect_locals(body, out),
        SurfaceStmt::Return { value: Some(expr) } => expr.referenced_locals_typed(out),
        SurfaceStmt::Return { value: None }
        | SurfaceStmt::Break { .. }
        | SurfaceStmt::Continue { .. }
        | SurfaceStmt::Nop => {}
    }
}

fn collect_block_starts(stmt: &SurfaceStmt, out: &mut BTreeSet<u64>) {
    match stmt {
        SurfaceStmt::Leaf { block_start, .. } => {
            out.insert(*block_start);
        }
        SurfaceStmt::Switch { cases, .. } => {
            for case in cases {
                out.insert(case.block_start);
            }
        }
        SurfaceStmt::GotoGraph { blocks, .. } => {
            for block in blocks {
                out.insert(block.block_start);
            }
        }
        SurfaceStmt::Block { body } => {
            for child in body {
                collect_block_starts(child, out);
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_condition_block_starts(&cond.expression, out);
            collect_block_starts(then_branch, out);
            collect_block_starts(else_branch, out);
        }
        SurfaceStmt::Loop { body, .. } => collect_block_starts(body, out),
        SurfaceStmt::Break { .. }
        | SurfaceStmt::Continue { .. }
        | SurfaceStmt::Return { .. }
        | SurfaceStmt::Nop => {}
    }
}

fn collect_addresses(stmt: &SurfaceStmt, out: &mut BTreeSet<u64>) {
    match stmt {
        SurfaceStmt::Leaf { statements, .. } => {
            out.extend(statements.iter().map(|s: &SurfaceLeaf| s.instr.address));
        }
        SurfaceStmt::Switch { cases, .. } => {
            for case in cases {
                out.extend(
                    case.statements
                        .iter()
                        .map(|s: &SurfaceLeaf| s.instr.address),
                );
            }
        }
        SurfaceStmt::GotoGraph { blocks, .. } => {
            for block in blocks {
                out.extend(
                    block
                        .statements
                        .iter()
                        .map(|statement: &SurfaceLeaf| statement.instr.address),
                );
            }
        }
        SurfaceStmt::Block { body } => {
            for child in body {
                collect_addresses(child, out);
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_condition_addresses(&cond.expression, out);
            collect_addresses(then_branch, out);
            collect_addresses(else_branch, out);
        }
        SurfaceStmt::Loop { body, .. } => collect_addresses(body, out),
        SurfaceStmt::Break { .. }
        | SurfaceStmt::Continue { .. }
        | SurfaceStmt::Return { .. }
        | SurfaceStmt::Nop => {}
    }
}

fn collect_instructions(stmt: &SurfaceStmt, out: &mut Vec<NirInstr>) {
    match stmt {
        SurfaceStmt::Leaf { statements, .. } => {
            for leaf in statements {
                out.push(leaf.instr.clone());
            }
        }
        SurfaceStmt::Switch { cases, .. } => {
            for case in cases {
                for leaf in &case.statements {
                    out.push(leaf.instr.clone());
                }
            }
        }
        SurfaceStmt::GotoGraph { blocks, .. } => {
            for block in blocks {
                for leaf in &block.statements {
                    out.push(leaf.instr.clone());
                }
            }
        }
        SurfaceStmt::Block { body } => {
            for child in body {
                collect_instructions(child, out);
            }
        }
        SurfaceStmt::If {
            cond,
            then_branch,
            else_branch,
        } => {
            collect_condition_instructions(&cond.expression, out);
            collect_instructions(then_branch, out);
            collect_instructions(else_branch, out);
        }
        SurfaceStmt::Loop { body, .. } => collect_instructions(body, out),
        SurfaceStmt::Break { .. }
        | SurfaceStmt::Continue { .. }
        | SurfaceStmt::Return { .. }
        | SurfaceStmt::Nop => {}
    }
}

fn condition_tests(expression: &SurfaceConditionExpr) -> Vec<&SurfaceConditionTest> {
    let mut tests: Vec<&SurfaceConditionTest> = Vec::new();
    let mut pending: Vec<&SurfaceConditionExpr> = vec![expression];
    while let Some(current) = pending.pop() {
        match current {
            SurfaceConditionExpr::Test { test, .. } => tests.push(test),
            SurfaceConditionExpr::All { terms } | SurfaceConditionExpr::Any { terms } => {
                pending.extend(terms.iter().rev());
            }
        }
    }
    tests
}

fn collect_condition_locals(
    expression: &SurfaceConditionExpr,
    out: &mut BTreeMap<String, SurfaceType>,
) {
    for test in condition_tests(expression) {
        for leaf in &test.statements {
            leaf.stmt.collect_locals(out);
        }
        for route in test.taken_route.iter().chain(&test.fallthrough_route) {
            for leaf in &route.statements {
                leaf.stmt.collect_locals(out);
            }
        }
    }
}

fn collect_condition_block_starts(expression: &SurfaceConditionExpr, out: &mut BTreeSet<u64>) {
    out.extend(
        condition_tests(expression)
            .into_iter()
            .map(|test: &SurfaceConditionTest| test.block_start),
    );
    for test in condition_tests(expression) {
        out.extend(
            test.taken_route
                .iter()
                .chain(&test.fallthrough_route)
                .map(|route: &SurfaceConditionRoute| route.block_start),
        );
    }
}

fn collect_condition_addresses(expression: &SurfaceConditionExpr, out: &mut BTreeSet<u64>) {
    for test in condition_tests(expression) {
        out.extend(
            test.statements
                .iter()
                .map(|leaf: &SurfaceLeaf| leaf.instr.address),
        );
        for route in test.taken_route.iter().chain(&test.fallthrough_route) {
            out.extend(
                route
                    .statements
                    .iter()
                    .map(|leaf: &SurfaceLeaf| leaf.instr.address),
            );
        }
    }
}

fn collect_condition_instructions(expression: &SurfaceConditionExpr, out: &mut Vec<NirInstr>) {
    for test in condition_tests(expression) {
        out.extend(
            test.statements
                .iter()
                .map(|leaf: &SurfaceLeaf| leaf.instr.clone()),
        );
        for route in test.taken_route.iter().chain(&test.fallthrough_route) {
            out.extend(
                route
                    .statements
                    .iter()
                    .map(|leaf: &SurfaceLeaf| leaf.instr.clone()),
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::emit::emit_pseudo_source;
    use crate::hir::structurize_function;
    use crate::types::{NirFunction, NirOp};

    fn instr(address: u64, op: NirOp, mnemonic: &str, operands: &[&str]) -> NirInstr {
        NirInstr {
            address,
            op,
            mnemonic: mnemonic.to_owned(),
            operands: operands.iter().map(|s: &&str| (*s).to_owned()).collect(),
            reads_memory: false,
            writes_memory: false,
            byte_width: false,
            source: SourceRef::new(SourceLang::NativeX86, address),
        }
    }

    fn function(instructions: Vec<NirInstr>, end: u64) -> NirFunction {
        NirFunction {
            name: "f".to_owned(),
            address: instructions.first().map_or(0, |i: &NirInstr| i.address),
            end,
            is_export: false,
            instructions,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    fn count_control(stmt: &SurfaceStmt, ifs: &mut usize, loops: &mut usize) {
        match stmt {
            SurfaceStmt::If {
                then_branch,
                else_branch,
                ..
            } => {
                *ifs += 1;
                count_control(then_branch, ifs, loops);
                count_control(else_branch, ifs, loops);
            }
            SurfaceStmt::Loop { body, .. } => {
                *loops += 1;
                count_control(body, ifs, loops);
            }
            SurfaceStmt::Block { body } => {
                for child in body {
                    count_control(child, ifs, loops);
                }
            }
            SurfaceStmt::Leaf { .. }
            | SurfaceStmt::Switch { .. }
            | SurfaceStmt::GotoGraph { .. }
            | SurfaceStmt::Break { .. }
            | SurfaceStmt::Continue { .. }
            | SurfaceStmt::Return { .. }
            | SurfaceStmt::Nop => {}
        }
    }

    #[test]
    fn surface_accounts_for_every_hir_block_and_address() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::CondBranch { target: Some(0x4) }, "je", &["0x4"]),
                instr(0x2, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x4, NirOp::Return, "ret", &[]),
            ],
            0x5,
        );
        let hir: HirFunction = structurize_function(&f);
        let surface: SurfaceFunction = surfacify_function(&hir);
        assert_eq!(
            surface.block_starts(),
            hir.block_starts(),
            "surface must account for every hir basic block"
        );
        assert_eq!(
            surface.instruction_addresses(),
            hir.instruction_addresses(),
            "surface must account for every hir instruction address"
        );
    }

    #[test]
    fn surface_preserves_the_hir_control_shape() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::CondBranch { target: Some(0x4) }, "je", &["0x4"]),
                instr(0x2, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x4, NirOp::Return, "ret", &[]),
            ],
            0x5,
        );
        let hir: HirFunction = structurize_function(&f);
        let surface: SurfaceFunction = surfacify_function(&hir);
        let mut ifs: usize = 0;
        let mut loops: usize = 0;
        count_control(&surface.body, &mut ifs, &mut loops);
        assert_eq!(ifs, 1, "the hir if must become exactly one surface if");
        assert_eq!(loops, 0);
        assert_eq!(surface.name(), "f");
    }

    #[test]
    fn surface_loop_mirrors_hir_loop() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::Const, "mov", &["ecx", "0x0"]),
                instr(
                    0x2,
                    NirOp::BinOp { op: BinaryOp::Add },
                    "add",
                    &["ecx", "0x1"],
                ),
                instr(0x4, NirOp::CondBranch { target: Some(0x2) }, "jl", &["0x2"]),
                instr(0x6, NirOp::Return, "ret", &[]),
            ],
            0x7,
        );
        let hir: HirFunction = structurize_function(&f);
        let surface: SurfaceFunction = surfacify_function(&hir);
        let mut ifs: usize = 0;
        let mut loops: usize = 0;
        count_control(&surface.body, &mut ifs, &mut loops);
        assert_eq!(
            loops, 1,
            "a hir loop must become a surface loop: {:?}",
            surface.body
        );
    }

    #[test]
    fn binop_assign_hoists_a_typed_local() {
        let f: NirFunction = function(
            vec![
                instr(
                    0x0,
                    NirOp::BinOp { op: BinaryOp::Xor },
                    "xor",
                    &["eax", "0x5"],
                ),
                instr(0x2, NirOp::Return, "ret", &[]),
            ],
            0x3,
        );
        let hir: HirFunction = structurize_function(&f);
        let surface: SurfaceFunction = surfacify_function(&hir);
        let eax: &SurfaceLocal = surface
            .locals
            .iter()
            .find(|l: &&SurfaceLocal| l.name == "eax")
            .expect("eax local hoisted");
        assert_eq!(
            eax.ty,
            SurfaceType::Word,
            "a bitwise binop result is a word-typed local"
        );
    }

    #[test]
    fn to_nir_function_round_trips_every_instruction_address() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::CondBranch { target: Some(0x4) }, "je", &["0x4"]),
                instr(0x2, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x4, NirOp::Return, "ret", &[]),
            ],
            0x5,
        );
        let hir: HirFunction = structurize_function(&f);
        let surface: SurfaceFunction = surfacify_function(&hir);
        let lowered: NirFunction = surface.to_nir_function();
        let lowered_addrs: BTreeSet<u64> = lowered
            .instructions
            .iter()
            .map(|i: &NirInstr| i.address)
            .collect();
        let original_addrs: BTreeSet<u64> = f
            .instructions
            .iter()
            .map(|i: &NirInstr| i.address)
            .collect();
        assert_eq!(
            lowered_addrs, original_addrs,
            "lowering surface back to nir must preserve every instruction address"
        );
    }

    #[test]
    fn surfacify_is_deterministic() {
        let f: NirFunction = function(
            vec![
                instr(0x0, NirOp::CondBranch { target: Some(0x4) }, "je", &["0x4"]),
                instr(0x2, NirOp::Const, "mov", &["eax", "0x1"]),
                instr(0x4, NirOp::Return, "ret", &[]),
            ],
            0x5,
        );
        let first: SurfaceFunction = surfacify_function(&structurize_function(&f));
        let second: SurfaceFunction = surfacify_function(&structurize_function(&f));
        assert_eq!(first, second);
    }

    fn hir_function(body: HirStmt) -> HirFunction {
        HirFunction {
            name: "deep".to_owned(),
            address: 0,
            end: 1,
            is_export: false,
            body,
            structured: true,
            decline: None,
            source: SourceRef::new(SourceLang::NativeX86, 0),
        }
    }

    fn nested_hir_expression(depth: usize) -> HirExpr {
        let mut expression: HirExpr = HirExpr::Const {
            text: "1".to_owned(),
        };
        for _index in 0..depth {
            expression = HirExpr::Unary {
                op: BinaryOp::Neg,
                operand: Box::new(expression),
            };
        }
        expression
    }

    #[test]
    fn expression_past_bound_is_marked_unrecovered() {
        let hir: HirFunction = hir_function(HirStmt::Return {
            value: Some(nested_hir_expression(MAX_SURFACE_DEPTH)),
        });
        let surface: SurfaceFunction = surfacify_function(&hir);
        let source: String = emit_pseudo_source(&surface).expect("emit bounded expression");
        assert!(!surface.structured);
        assert!(source.contains("unrecovered"), "got:\n{source}");
    }

    #[test]
    fn maximum_bounded_expression_surfacifies_successfully() {
        let hir: HirFunction = hir_function(HirStmt::Return {
            value: Some(nested_hir_expression(MAX_SURFACE_DEPTH - 1)),
        });
        let surface: SurfaceFunction = surfacify_function(&hir);
        assert!(surface.structured);
        let source: String = emit_pseudo_source(&surface).expect("emit bounded expression");
        assert!(source.contains('1'));
    }

    #[test]
    fn region_past_bound_uses_complete_surface_graph_fallback() {
        let instruction: NirInstr = instr(0, NirOp::Const, "mov", &["eax", "1"]);
        let mut body: HirStmt = HirStmt::Leaf {
            block_start: 0,
            stmts: vec![HirLeafStmt {
                instr: instruction,
                stmt: HirInstrStmt::Effect {
                    expr: HirExpr::Unknown {
                        text: "mov".to_owned(),
                    },
                },
            }],
        };
        for index in 0..MAX_SURFACE_DEPTH {
            body = HirStmt::Loop {
                label: u64::try_from(index).expect("loop label"),
                body: Box::new(body),
            };
        }
        let hir: HirFunction = hir_function(body);
        let surface: SurfaceFunction = surfacify_function(&hir);
        assert!(!surface.structured);
        assert!(matches!(
            surface.body,
            SurfaceStmt::GotoGraph { entry: 0, .. }
        ));
        assert_eq!(surface.instruction_addresses(), BTreeSet::from([0]));
        let source: String = emit_pseudo_source(&surface).expect("emit graph fallback");
        assert!(source.contains("unrecovered"), "got:\n{source}");
    }

    #[test]
    fn deep_surface_expression_drop_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut expression: SurfaceExpr = SurfaceExpr::Literal {
                    text: "1".to_owned(),
                };
                for _index in 0..100_000 {
                    expression = SurfaceExpr::Unary {
                        op: BinaryOp::Neg,
                        operand: Box::new(expression),
                    };
                }
                std::hint::black_box(&expression);
            })
            .expect("spawn surface expression drop thread");
        handle.join().expect("surface expression drop thread");
    }

    #[test]
    fn deep_surface_region_drop_does_not_use_tree_depth_as_call_depth() {
        let handle: std::thread::JoinHandle<()> = std::thread::Builder::new()
            .stack_size(1_048_576)
            .spawn(|| {
                let mut statement: SurfaceStmt = SurfaceStmt::Nop;
                for index in 0..100_000 {
                    statement = SurfaceStmt::Loop {
                        label: u64::try_from(index).expect("loop label"),
                        body: Box::new(statement),
                    };
                }
                std::hint::black_box(&statement);
            })
            .expect("spawn surface region drop thread");
        handle.join().expect("surface region drop thread");
    }
}
