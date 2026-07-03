use crate::ast::node::{Expr, ExprCtx, Keyword};

#[must_use]
pub fn pypy_method_call(receiver: Expr, attr: String, args: Vec<Expr>) -> Expr {
    let func: Expr = Expr::Attribute {
        value: Box::new(receiver),
        attr,
        ctx: ExprCtx::Load,
    };
    Expr::Call {
        func: Box::new(func),
        args,
        keywords: Vec::new(),
    }
}

#[must_use]
pub fn pypy_method_call_kw(
    receiver: Expr,
    attr: String,
    args: Vec<Expr>,
    keywords: Vec<Keyword>,
) -> Expr {
    let func: Expr = Expr::Attribute {
        value: Box::new(receiver),
        attr,
        ctx: ExprCtx::Load,
    };
    Expr::Call {
        func: Box::new(func),
        args,
        keywords,
    }
}

#[must_use]
pub fn pypy_build_list_from_arg(iter_expr: Expr) -> Expr {
    let list_name: Expr = Expr::Name {
        id: "list".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    Expr::Call {
        func: Box::new(list_name),
        args: vec![iter_expr],
        keywords: Vec::new(),
    }
}

#[must_use]
pub fn pypy_load_revdb_var(name: String) -> Expr {
    let receiver: Expr = Expr::Name {
        id: "__revdb__".to_owned(),
        ctx: ExprCtx::Load,
        line: None,
    };
    Expr::Attribute {
        value: Box::new(receiver),
        attr: name,
        ctx: ExprCtx::Load,
    }
}

#[must_use]
pub const fn pypy_jump_if_not_debug_preserves_assert() -> bool {
    true
}
