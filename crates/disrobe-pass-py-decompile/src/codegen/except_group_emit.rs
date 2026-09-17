use std::fmt::Write as _;

use crate::ast::node::{ExceptHandler, Stmt};
use crate::bytecode::version::PyVersion;
use crate::codegen::modern_expr_render::{indent_str, render_body, render_expr};

#[must_use]
pub fn emit_try_star(
    body: &[Stmt],
    handlers: &[ExceptHandler],
    orelse: &[Stmt],
    finalbody: &[Stmt],
    indent: u32,
    version: &PyVersion,
) -> String {
    let prefix: String = indent_str(indent);
    let mut out: String = String::new();
    let _ = writeln!(out, "{prefix}try:");
    out.push_str(&render_body(body, indent + 1, version));
    for h in handlers {
        out.push('\n');
        out.push_str(&render_except_star_handler(h, indent, version));
    }
    if !orelse.is_empty() {
        let _ = write!(out, "\n{prefix}else:\n");
        out.push_str(&render_body(orelse, indent + 1, version));
    }
    if !finalbody.is_empty() {
        let _ = write!(out, "\n{prefix}finally:\n");
        out.push_str(&render_body(finalbody, indent + 1, version));
    }
    out
}

#[must_use]
fn render_except_star_handler(h: &ExceptHandler, indent: u32, version: &PyVersion) -> String {
    let prefix: String = indent_str(indent);
    let head: String = match (&h.typ, &h.name) {
        (Some(t), Some(n)) => {
            format!("{prefix}except* {} as {n}:", render_expr(t, version))
        }
        (Some(t), None) => format!("{prefix}except* {}:", render_expr(t, version)),
        (None, _) => format!("{prefix}except*:"),
    };
    let body: String = render_body(&h.body, indent + 1, version);
    format!("{head}\n{body}")
}

#[must_use]
pub fn supports_except_groups(version: &PyVersion) -> bool {
    version.supports_except_groups()
}
