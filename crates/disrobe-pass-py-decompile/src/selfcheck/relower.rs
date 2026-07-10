use std::collections::BTreeSet;

use disrobe_py_marshal::{CodeObject, Object};

use crate::ast::node::{ConstValue as AstConst, Expr, ExprCtx, Stmt};
use crate::bytecode::opcode::{BinOp, CmpOp, UnaryOp};
use crate::roundtrip::normalize::canonicalize_relowered;
use crate::roundtrip::{ConstValue, NameValue, NormToken, NormalizedOp};

const CO_OPTIMIZED: i32 = 0x0001;
const KIND_CELL: u8 = 0x40;
const KIND_FREE: u8 = 0x80;
const NB_SUBSCR: u32 = 26;

#[derive(Debug)]
pub(crate) enum Relowered {
    Ops(Vec<NormalizedOp>),
    Uncovered,
}

#[derive(Debug)]
pub(crate) struct ScopeCtx {
    fast: BTreeSet<String>,
    deref: BTreeSet<String>,
    function_scope: bool,
}

impl ScopeCtx {
    #[must_use]
    pub(crate) fn from_code(code: &CodeObject) -> Self {
        let function_scope: bool = (code.flags & CO_OPTIMIZED) != 0;
        let mut fast: BTreeSet<String> = BTreeSet::new();
        let mut deref: BTreeSet<String> = BTreeSet::new();
        if code.localsplusnames.is_empty() {
            for obj in &code.varnames {
                if let Some(name) = object_str(obj) {
                    fast.insert(name);
                }
            }
            for obj in code.cellvars.iter().chain(code.freevars.iter()) {
                if let Some(name) = object_str(obj) {
                    deref.insert(name);
                }
            }
        } else {
            for (idx, obj) in code.localsplusnames.iter().enumerate() {
                let Some(name): Option<String> = object_str(obj) else {
                    continue;
                };
                let kind: u8 = code.localspluskinds.get(idx).copied().unwrap_or(0);
                if kind & (KIND_CELL | KIND_FREE) != 0 {
                    deref.insert(name);
                } else {
                    fast.insert(name);
                }
            }
        }
        Self {
            fast,
            deref,
            function_scope,
        }
    }

    #[must_use]
    pub(crate) fn is_function_scope(&self) -> bool {
        self.function_scope
    }

    #[must_use]
    fn load_op_for(&self, name: &str) -> Option<&'static str> {
        if self.deref.contains(name) {
            Some("LOAD_DEREF")
        } else if self.fast.contains(name) {
            Some("LOAD_FAST")
        } else if self.function_scope {
            Some("LOAD_GLOBAL")
        } else {
            None
        }
    }

    #[must_use]
    fn store_op_for(&self, name: &str) -> Option<&'static str> {
        if self.deref.contains(name) {
            Some("STORE_DEREF")
        } else if self.fast.contains(name) {
            Some("STORE_FAST")
        } else if self.function_scope {
            Some("STORE_GLOBAL")
        } else {
            None
        }
    }
}

#[cfg(test)]
impl ScopeCtx {
    #[must_use]
    pub(crate) fn from_parts(fast: &[&str], deref: &[&str], function_scope: bool) -> Self {
        Self {
            fast: fast.iter().map(|s: &&str| (*s).to_owned()).collect(),
            deref: deref.iter().map(|s: &&str| (*s).to_owned()).collect(),
            function_scope,
        }
    }
}

#[must_use]
fn object_str(obj: &Object) -> Option<String> {
    match obj {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

#[must_use]
pub(crate) fn relower_function_body(body: &[Stmt], ctx: &ScopeCtx) -> Relowered {
    if !ctx.is_function_scope() {
        return Relowered::Uncovered;
    }
    let mut out: Vec<NormalizedOp> = Vec::new();
    for stmt in body {
        if lower_stmt(stmt, ctx, &mut out).is_none() {
            return Relowered::Uncovered;
        }
    }
    if !ends_with_terminator(body) {
        out.push(op_const(ConstValue::None));
        out.push(op_bare("RETURN_VALUE"));
    }
    Relowered::Ops(canonicalize_relowered(out))
}

#[must_use]
fn ends_with_terminator(body: &[Stmt]) -> bool {
    matches!(
        body.last(),
        Some(Stmt::Return(_) | Stmt::Raise { .. } | Stmt::Continue | Stmt::Break)
    )
}

#[must_use]
fn lower_stmt(stmt: &Stmt, ctx: &ScopeCtx, out: &mut Vec<NormalizedOp>) -> Option<()> {
    match stmt {
        Stmt::Pass => Some(()),
        Stmt::Return(None) => {
            out.push(op_const(ConstValue::None));
            out.push(op_bare("RETURN_VALUE"));
            Some(())
        }
        Stmt::Return(Some(value)) => {
            lower_expr(value, ctx, out)?;
            out.push(op_bare("RETURN_VALUE"));
            Some(())
        }
        Stmt::Expr(call @ Expr::Call { .. }) => {
            lower_expr(call, ctx, out)?;
            out.push(op_bare("POP_TOP"));
            Some(())
        }
        Stmt::Assign { targets, value, .. } if targets.len() == 1 => {
            lower_assign(&targets[0], value, ctx, out)
        }
        _ => None,
    }
}

#[must_use]
fn lower_assign(
    target: &Expr,
    value: &Expr,
    ctx: &ScopeCtx,
    out: &mut Vec<NormalizedOp>,
) -> Option<()> {
    match target {
        Expr::Name {
            id,
            ctx: ExprCtx::Store,
            ..
        } => {
            lower_expr(value, ctx, out)?;
            let op: &'static str = ctx.store_op_for(id)?;
            out.push(op_name(op, id));
            Some(())
        }
        Expr::Attribute {
            value: obj,
            attr,
            ctx: ExprCtx::Store,
        } => {
            lower_expr(value, ctx, out)?;
            lower_expr(obj, ctx, out)?;
            out.push(op_name("STORE_ATTR", attr));
            Some(())
        }
        Expr::Subscript {
            value: obj,
            slice,
            ctx: ExprCtx::Store,
        } => {
            if matches!(slice.as_ref(), Expr::Slice { .. }) {
                return None;
            }
            lower_expr(value, ctx, out)?;
            lower_expr(obj, ctx, out)?;
            lower_expr(slice, ctx, out)?;
            out.push(op_bare("STORE_SUBSCR"));
            Some(())
        }
        _ => None,
    }
}

#[must_use]
fn lower_expr(expr: &Expr, ctx: &ScopeCtx, out: &mut Vec<NormalizedOp>) -> Option<()> {
    match expr {
        Expr::Constant { value, .. } => {
            out.push(op_const(map_const(value)?));
            Some(())
        }
        Expr::Name {
            id,
            ctx: ExprCtx::Load,
            ..
        } => {
            let op: &'static str = ctx.load_op_for(id)?;
            out.push(op_name(op, id));
            Some(())
        }
        Expr::Attribute {
            value,
            attr,
            ctx: ExprCtx::Load,
        } => {
            lower_expr(value, ctx, out)?;
            out.push(op_name("LOAD_ATTR", attr));
            Some(())
        }
        Expr::Subscript {
            value,
            slice,
            ctx: ExprCtx::Load,
        } => {
            if matches!(slice.as_ref(), Expr::Slice { .. }) {
                return None;
            }
            lower_expr(value, ctx, out)?;
            lower_expr(slice, ctx, out)?;
            out.push(op_operator("BINARY_OP", NB_SUBSCR));
            Some(())
        }
        Expr::BinOp { left, op, right } => {
            let code: u32 = binop_code(*op)?;
            lower_expr(left, ctx, out)?;
            lower_expr(right, ctx, out)?;
            out.push(op_operator("BINARY_OP", code));
            Some(())
        }
        Expr::UnaryOp { op, operand } => {
            let name: &'static str = unary_name(*op)?;
            lower_expr(operand, ctx, out)?;
            out.push(op_bare(name));
            Some(())
        }
        Expr::Compare {
            left,
            ops,
            comparators,
        } if ops.len() == 1 && comparators.len() == 1 => {
            lower_expr(left, ctx, out)?;
            lower_expr(&comparators[0], ctx, out)?;
            out.push(compare_op(ops[0])?);
            Some(())
        }
        Expr::Call {
            func,
            args,
            keywords,
        } if keywords.is_empty() => lower_call(func, args, ctx, out),
        _ => None,
    }
}

#[must_use]
fn lower_call(
    func: &Expr,
    args: &[Expr],
    ctx: &ScopeCtx,
    out: &mut Vec<NormalizedOp>,
) -> Option<()> {
    if args
        .iter()
        .any(|a: &Expr| matches!(a, Expr::Starred { .. }))
    {
        return None;
    }
    match func {
        Expr::Name {
            id,
            ctx: ExprCtx::Load,
            ..
        } => {
            let op: &'static str = ctx.load_op_for(id)?;
            if op != "LOAD_GLOBAL" {
                return None;
            }
            out.push(op_name(op, id));
        }
        Expr::Attribute {
            value,
            attr,
            ctx: ExprCtx::Load,
        } => {
            lower_expr(value, ctx, out)?;
            out.push(op_name("LOAD_ATTR", attr));
        }
        _ => return None,
    }
    for arg in args {
        lower_expr(arg, ctx, out)?;
    }
    let argc: u32 = u32::try_from(args.len()).ok()?;
    out.push(op_operator("CALL", argc));
    Some(())
}

#[must_use]
fn map_const(value: &AstConst) -> Option<ConstValue> {
    match value {
        AstConst::None => Some(ConstValue::None),
        AstConst::True => Some(ConstValue::Bool(true)),
        AstConst::False => Some(ConstValue::Bool(false)),
        AstConst::Int(i) => i32::try_from(*i).ok().map(ConstValue::SmallInt),
        AstConst::Str(s) | AstConst::Unicode(s) => Some(ConstValue::Str(s.clone())),
        AstConst::Bytes(b) => Some(ConstValue::Bytes(b.clone())),
        AstConst::Float(f) => Some(ConstValue::Float(canonical_float_bits(*f))),
        _ => None,
    }
}

#[must_use]
fn canonical_float_bits(f: f64) -> u64 {
    if f.is_nan() {
        f64::NAN.to_bits()
    } else {
        f.to_bits()
    }
}

#[must_use]
const fn binop_code(op: BinOp) -> Option<u32> {
    let code: u32 = match op {
        BinOp::Add => 0,
        BinOp::BitAnd => 1,
        BinOp::FloorDiv => 2,
        BinOp::Lshift => 3,
        BinOp::MatMul => 4,
        BinOp::Mul => 5,
        BinOp::Mod => 6,
        BinOp::BitOr => 7,
        BinOp::Pow => 8,
        BinOp::Rshift => 9,
        BinOp::Sub => 10,
        BinOp::TrueDiv => 11,
        BinOp::BitXor => 12,
        _ => return None,
    };
    Some(code)
}

#[must_use]
const fn unary_name(op: UnaryOp) -> Option<&'static str> {
    match op {
        UnaryOp::Negative => Some("UNARY_NEGATIVE"),
        UnaryOp::Invert => Some("UNARY_INVERT"),
        _ => None,
    }
}

#[must_use]
fn compare_op(op: CmpOp) -> Option<NormalizedOp> {
    let (name, operator_id): (&'static str, u32) = match op {
        CmpOp::Lt => ("COMPARE_OP", 0),
        CmpOp::Le => ("COMPARE_OP", 2),
        CmpOp::Eq => ("COMPARE_OP", 4),
        CmpOp::Ne => ("COMPARE_OP", 6),
        CmpOp::Gt => ("COMPARE_OP", 8),
        CmpOp::Ge => ("COMPARE_OP", 10),
        CmpOp::Is => ("IS_OP", 0),
        CmpOp::IsNot => ("IS_OP", 1),
        CmpOp::In => ("CONTAINS_OP", 0),
        CmpOp::NotIn => ("CONTAINS_OP", 1),
        _ => return None,
    };
    Some(op_operator(name, operator_id))
}

#[must_use]
fn op_bare(name: &'static str) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(name.into()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_const(value: ConstValue) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op("LOAD_CONST".into()),
        const_value: Some(value),
        name_value: None,
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_name(op: &'static str, name: &str) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(op.into()),
        const_value: None,
        name_value: Some(NameValue(name.to_owned())),
        jump_target_index: None,
        operator_id: None,
        raw_arg: None,
    }
}

#[must_use]
fn op_operator(op: &'static str, operator_id: u32) -> NormalizedOp {
    NormalizedOp {
        token: NormToken::Op(op.into()),
        const_value: None,
        name_value: None,
        jump_target_index: None,
        operator_id: Some(operator_id),
        raw_arg: None,
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::ast::node::{BoolOpKind, ConstValue as AstConst};

    fn load(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Load,
            line: None,
        }
    }

    fn store(id: &str) -> Expr {
        Expr::Name {
            id: id.to_owned(),
            ctx: ExprCtx::Store,
            line: None,
        }
    }

    fn assign(target: Expr, value: Expr) -> Stmt {
        Stmt::Assign {
            targets: vec![target],
            value,
            type_comment: None,
            line: None,
        }
    }

    fn attr_load(obj: Expr, attr: &str) -> Expr {
        Expr::Attribute {
            value: Box::new(obj),
            attr: attr.to_owned(),
            ctx: ExprCtx::Load,
        }
    }

    fn call(func: Expr, args: Vec<Expr>) -> Expr {
        Expr::Call {
            func: Box::new(func),
            args,
            keywords: Vec::new(),
        }
    }

    fn ops(body: &[Stmt], ctx: &ScopeCtx) -> Vec<NormalizedOp> {
        match relower_function_body(body, ctx) {
            Relowered::Ops(o) => o,
            Relowered::Uncovered => panic!("expected covered body, got Uncovered"),
        }
    }

    fn jret_none() -> NormalizedOp {
        NormalizedOp {
            token: NormToken::JRetLeaf,
            const_value: Some(ConstValue::None),
            name_value: None,
            jump_target_index: None,
            operator_id: None,
            raw_arg: None,
        }
    }

    #[test]
    fn assign_binop_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b", "x"], &[], true);
        let body: Vec<Stmt> = vec![
            assign(
                store("x"),
                Expr::BinOp {
                    left: Box::new(load("a")),
                    op: BinOp::Add,
                    right: Box::new(load("b")),
                },
            ),
            Stmt::Return(Some(load("x"))),
        ];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "a"),
            op_name("LOAD_FAST", "b"),
            op_operator("BINARY_OP", 0),
            op_name("STORE_FAST", "x"),
            op_name("LOAD_FAST", "x"),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn method_call_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["self", "x"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(call(
            attr_load(load("self"), "g"),
            vec![load("x")],
        )))];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "self"),
            op_name("LOAD_ATTR", "g"),
            op_name("LOAD_FAST", "x"),
            op_operator("CALL", 1),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn global_call_and_attr_store_and_implicit_return() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["self", "x"], &[], true);
        let body: Vec<Stmt> = vec![
            assign(
                Expr::Attribute {
                    value: Box::new(load("self")),
                    attr: "y".to_owned(),
                    ctx: ExprCtx::Store,
                },
                load("x"),
            ),
            Stmt::Expr(call(load("log"), vec![])),
        ];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "x"),
            op_name("LOAD_FAST", "self"),
            op_name("STORE_ATTR", "y"),
            op_name("LOAD_GLOBAL", "log"),
            op_operator("CALL", 0),
            op_bare("POP_TOP"),
            jret_none(),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn compare_return_matches_3_14_codegen() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(Expr::Compare {
            left: Box::new(load("a")),
            ops: vec![CmpOp::Lt],
            comparators: vec![load("b")],
        }))];
        let expected: Vec<NormalizedOp> = vec![
            op_name("LOAD_FAST", "a"),
            op_name("LOAD_FAST", "b"),
            op_operator("COMPARE_OP", 0),
            op_bare("RETURN_VALUE"),
        ];
        assert_eq!(ops(&body, &ctx), expected);
    }

    #[test]
    fn deref_and_global_resolution() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &["cell"], true);
        let body: Vec<Stmt> = vec![
            assign(store("a"), load("cell")),
            assign(store("a"), load("glob")),
        ];
        let out: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(out[0], op_name("LOAD_DEREF", "cell"));
        assert_eq!(out[2], op_name("LOAD_GLOBAL", "glob"));
    }

    #[test]
    fn non_function_scope_abstains() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a"], &[], false);
        let body: Vec<Stmt> = vec![Stmt::Return(Some(load("a")))];
        assert!(matches!(
            relower_function_body(&body, &ctx),
            Relowered::Uncovered
        ));
    }

    #[test]
    fn control_flow_and_uncovered_expr_abstain() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["a", "b"], &[], true);
        let with_if: Vec<Stmt> = vec![Stmt::If {
            test: load("a"),
            body: vec![Stmt::Pass],
            orelse: Vec::new(),
            line: None,
        }];
        assert!(matches!(
            relower_function_body(&with_if, &ctx),
            Relowered::Uncovered
        ));
        let with_boolop: Vec<Stmt> = vec![Stmt::Return(Some(Expr::BoolOp {
            op: BoolOpKind::And,
            values: vec![load("a"), load("b")],
        }))];
        assert!(matches!(
            relower_function_body(&with_boolop, &ctx),
            Relowered::Uncovered
        ));
    }

    #[test]
    fn small_int_and_none_consts() {
        let ctx: ScopeCtx = ScopeCtx::from_parts(&["x"], &[], true);
        let body: Vec<Stmt> = vec![assign(
            store("x"),
            Expr::Constant {
                value: AstConst::Int(5),
                line: None,
            },
        )];
        let out: Vec<NormalizedOp> = ops(&body, &ctx);
        assert_eq!(out[0], op_const(ConstValue::SmallInt(5)));
        assert_eq!(out[1], op_name("STORE_FAST", "x"));
        assert_eq!(out[2], jret_none());
    }
}
