use std::cell::Cell;

use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::{
    AtomicNodeIndex, ConversionFlag, Expr, ExprBinOp, ExprCall, ExprFString, ExprName,
    ExprStringLiteral, FString, FStringFlags, FStringValue, InterpolatedElement,
    InterpolatedStringElement, InterpolatedStringElements, InterpolatedStringLiteralElement,
    ModModule, Operator,
};
use ruff_text_size::Ranged;

pub(crate) fn recover(module: &mut ModModule) -> usize {
    let rewriter: FStringRewriter = FStringRewriter {
        count: Cell::new(0),
    };
    for stmt in &mut module.body {
        rewriter.visit_stmt(stmt);
    }
    rewriter.count.get()
}

#[derive(Debug)]
struct FStringRewriter {
    count: Cell<usize>,
}

impl Transformer for FStringRewriter {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        if let Expr::BinOp(b) = expr
            && matches!(b.op, Operator::Add)
            && let Some(new_expr) = try_rewrite_concat(b)
        {
            *expr = new_expr;
            self.count.set(self.count.get() + 1);
        }
    }
}

#[derive(Debug, Clone)]
enum Fragment {
    Literal(String),
    Interpolation {
        expression: Box<Expr>,
        conversion: ConversionFlag,
    },
}

fn try_rewrite_concat(bin: &ExprBinOp) -> Option<Expr> {
    let mut fragments: Vec<Fragment> = Vec::new();
    if !flatten_add(&bin.left, &mut fragments) {
        return None;
    }
    if !flatten_add(&bin.right, &mut fragments) {
        return None;
    }
    if !fragments
        .iter()
        .any(|f| matches!(f, Fragment::Interpolation { .. }))
    {
        return None;
    }
    let merged: Vec<Fragment> = merge_literals(fragments);
    let elements: InterpolatedStringElements = build_elements(merged, bin.range);
    Some(Expr::FString(ExprFString {
        range: bin.range,
        node_index: AtomicNodeIndex::default(),
        value: FStringValue::single(FString {
            range: bin.range,
            node_index: AtomicNodeIndex::default(),
            elements,
            flags: FStringFlags::empty(),
        }),
    }))
}

fn flatten_add(expr: &Expr, out: &mut Vec<Fragment>) -> bool {
    match expr {
        Expr::BinOp(b) if matches!(b.op, Operator::Add) => {
            flatten_add(&b.left, out) && flatten_add(&b.right, out)
        }
        Expr::StringLiteral(ExprStringLiteral { value, .. }) => {
            out.push(Fragment::Literal(value.to_str().to_owned()));
            true
        }
        Expr::Call(call) => {
            let Some(conversion) = call_conversion(call) else {
                return false;
            };
            if !call.arguments.keywords.is_empty() || call.arguments.args.len() != 1 {
                return false;
            }
            let Some(inner) = call.arguments.args.first() else {
                return false;
            };
            if !is_simple_interpolatable(inner) {
                return false;
            }
            out.push(Fragment::Interpolation {
                expression: Box::new(inner.clone()),
                conversion,
            });
            true
        }
        _ => false,
    }
}

#[inline]
fn call_conversion(call: &ExprCall) -> Option<ConversionFlag> {
    let Expr::Name(ExprName { id, .. }) = call.func.as_ref() else {
        return None;
    };
    match id.as_str() {
        "str" => Some(ConversionFlag::None),
        "repr" => Some(ConversionFlag::Repr),
        "ascii" => Some(ConversionFlag::Ascii),
        _ => None,
    }
}

#[inline]
const fn is_simple_interpolatable(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Name(_)
            | Expr::Attribute(_)
            | Expr::Subscript(_)
            | Expr::NumberLiteral(_)
            | Expr::BooleanLiteral(_)
    )
}

fn merge_literals(fragments: Vec<Fragment>) -> Vec<Fragment> {
    let mut out: Vec<Fragment> = Vec::with_capacity(fragments.len());
    for frag in fragments {
        match (out.last_mut(), &frag) {
            (Some(Fragment::Literal(prev)), Fragment::Literal(next)) => prev.push_str(next),
            _ => out.push(frag),
        }
    }
    out
}

fn build_elements(
    fragments: Vec<Fragment>,
    range: ruff_text_size::TextRange,
) -> InterpolatedStringElements {
    let mut elements: Vec<InterpolatedStringElement> = Vec::with_capacity(fragments.len());
    for frag in fragments {
        match frag {
            Fragment::Literal(s) => {
                elements.push(InterpolatedStringElement::Literal(
                    InterpolatedStringLiteralElement {
                        range,
                        node_index: AtomicNodeIndex::default(),
                        value: s.into_boxed_str(),
                    },
                ));
            }
            Fragment::Interpolation {
                expression,
                conversion,
            } => {
                let expr_range: ruff_text_size::TextRange = expression.range();
                elements.push(InterpolatedStringElement::Interpolation(
                    InterpolatedElement {
                        range: expr_range,
                        node_index: AtomicNodeIndex::default(),
                        expression,
                        debug_text: None,
                        conversion,
                        format_spec: None,
                    },
                ));
            }
        }
    }
    InterpolatedStringElements::from(elements)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use crate::source_cleanup::cleanup_source;

    fn run(src: &str) -> String {
        let Ok((out, _stats)): crate::error::Result<(String, crate::source_cleanup::CleanupStats)> =
            cleanup_source(src)
        else {
            panic!("cleanup failed for: {src}");
        };
        out
    }

    #[test]
    fn recovers_simple_str_concat() {
        let out: String = run("x = 5\nmsg = 'val=' + str(x)\nprint(msg)\n");
        assert!(
            out.contains("f'val={x}'") || out.contains("f\"val={x}\""),
            "expected f-string; got: {out}"
        );
    }

    #[test]
    fn recovers_sandwiched_interpolation() {
        let out: String = run("name = 'world'\nmsg = 'hello ' + str(name) + '!'\nprint(msg)\n");
        assert!(
            out.contains("hello ") && out.contains("{name}") && out.contains('!'),
            "expected f-string with sandwich; got: {out}"
        );
    }

    #[test]
    fn ignores_pure_literal_concat() {
        let out: String = run("msg = 'a' + 'b' + 'c'\nprint(msg)\n");
        assert!(
            !out.contains("f'") && !out.contains("f\""),
            "no f-string when no interpolation needed; got: {out}"
        );
    }

    #[test]
    fn handles_repr_conversion() {
        let out: String = run("x = 5\nmsg = 'val=' + repr(x)\nprint(msg)\n");
        assert!(
            out.contains("{x!r}") || out.contains("repr"),
            "expected !r conversion or fallback; got: {out}"
        );
    }

    #[test]
    fn refuses_complex_inner_expr() {
        let out: String = run("x = 5\nmsg = 'a' + str(x + 1)\nprint(msg)\n");
        assert!(
            out.contains("str(") && !out.contains("f'"),
            "must NOT rewrite for complex inner expr; got: {out}"
        );
    }
}
