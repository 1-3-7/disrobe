use crate::ast::node::Expr;
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::render_expr;

#[must_use]
pub fn emit_walrus(target: &Expr, value: &Expr, version: &PyVersion) -> String {
    format!(
        "({} := {})",
        render_expr(target, version),
        render_expr(value, version)
    )
}

#[must_use]
pub fn supports_walrus(version: &PyVersion) -> bool {
    version.supports_walrus()
}
