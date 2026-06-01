use crate::ast::node::{Comprehension, Expr};
use crate::bytecode::version::PyVersion;
use crate::codegen::DefaultEmitter;
use crate::codegen::expr::{Precedence, emit_expr};

#[must_use]
pub fn emit_comp_body(
    em: &DefaultEmitter,
    elt: &Expr,
    generators: &[Comprehension],
    version: &PyVersion,
) -> String {
    let mut out: String = emit_expr(em, elt, version, Precedence::Lambda);
    for comp in generators {
        out.push_str(&emit_generator(em, comp, version));
    }
    out
}

#[must_use]
pub fn emit_dict_comp(
    em: &DefaultEmitter,
    key: &Expr,
    value: &Expr,
    generators: &[Comprehension],
    version: &PyVersion,
) -> String {
    let mut out: String = format!(
        "{{{}: {}",
        emit_expr(em, key, version, Precedence::Lambda),
        emit_expr(em, value, version, Precedence::Lambda)
    );
    for comp in generators {
        out.push_str(&emit_generator(em, comp, version));
    }
    out.push('}');
    out
}

#[must_use]
fn emit_generator(em: &DefaultEmitter, comp: &Comprehension, version: &PyVersion) -> String {
    let prefix: &str = if comp.is_async {
        " async for "
    } else {
        " for "
    };
    let target: String = emit_expr(em, &comp.target, version, Precedence::Lowest);
    let iter: String = emit_expr(em, &comp.iter, version, Precedence::IfExpr);
    let mut out: String = format!("{prefix}{target} in {iter}");
    for cond in &comp.ifs {
        out.push_str(" if ");
        out.push_str(&emit_expr(em, cond, version, Precedence::IfExpr));
    }
    out
}
