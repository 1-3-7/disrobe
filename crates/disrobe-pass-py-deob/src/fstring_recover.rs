use std::cell::Cell;
use std::collections::BTreeSet;

use ruff_python_ast::visitor::transformer::{Transformer, walk_expr};
use ruff_python_ast::{
    AtomicNodeIndex, ConversionFlag, Expr, ExprBinOp, ExprCall, ExprFString, ExprList, ExprName,
    ExprStringLiteral, ExprTuple, FString, FStringFlags, FStringValue, InterpolatedElement,
    InterpolatedStringElement, InterpolatedStringElements, InterpolatedStringFormatSpec,
    InterpolatedStringLiteralElement, ModModule, Operator,
};
use ruff_text_size::{Ranged, TextRange};

use crate::bindings::bindings;

const FORMAT_BUILTINS: [&str; 4] = ["ascii", "format", "repr", "str"];

pub(crate) fn recover(module: &mut ModModule) -> usize {
    let bound: BTreeSet<String> = bindings(&module.body);
    let rewriter: FStringRewriter = FStringRewriter {
        count: Cell::new(0),
        joins: !FORMAT_BUILTINS
            .iter()
            .any(|name: &&str| bound.contains(*name)),
    };
    for stmt in &mut module.body {
        rewriter.visit_stmt(stmt);
    }
    rewriter.count.get()
}

#[derive(Debug)]
struct FStringRewriter {
    count: Cell<usize>,
    joins: bool,
}

impl Transformer for FStringRewriter {
    fn visit_expr(&self, expr: &mut Expr) {
        walk_expr(self, expr);
        let rewritten: Option<Expr> = match expr {
            Expr::BinOp(b) if matches!(b.op, Operator::Add) => try_rewrite_concat(b),
            Expr::Call(call) if self.joins => try_rewrite_join(call),
            _ => None,
        };
        if let Some(new_expr) = rewritten {
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
        spec: String,
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
    Some(fstring(fragments, bin.range))
}

fn fstring(fragments: Vec<Fragment>, range: TextRange) -> Expr {
    let merged: Vec<Fragment> = merge_literals(fragments);
    let elements: InterpolatedStringElements = build_elements(merged, range);
    Expr::FString(ExprFString {
        range,
        node_index: AtomicNodeIndex::default(),
        value: FStringValue::single(FString {
            range,
            node_index: AtomicNodeIndex::default(),
            elements,
            flags: FStringFlags::empty(),
        }),
    })
}

fn try_rewrite_join(call: &ExprCall) -> Option<Expr> {
    let parts: &[Expr] = empty_join(call)?;
    let mut fragments: Vec<Fragment> = Vec::with_capacity(parts.len());
    for part in parts {
        match part {
            Expr::StringLiteral(literal) => {
                fragments.push(Fragment::Literal(literal.value.to_str().to_owned()));
            }
            Expr::Call(formatted) => fragments.push(format_fragment(formatted)?),
            _ => return None,
        }
    }
    fragments
        .iter()
        .any(|f| matches!(f, Fragment::Interpolation { .. }))
        .then(|| fstring(fragments, call.range))
}

fn empty_join(call: &ExprCall) -> Option<&[Expr]> {
    let Expr::Attribute(join) = call.func.as_ref() else {
        return None;
    };
    let separator_is_empty: bool = matches!(
        join.value.as_ref(),
        Expr::StringLiteral(separator) if separator.value.to_str().is_empty()
    );
    if join.attr.as_str() != "join" || !separator_is_empty || !call.arguments.keywords.is_empty() {
        return None;
    }
    match call.arguments.args.as_ref() {
        [Expr::List(ExprList { elts, .. }) | Expr::Tuple(ExprTuple { elts, .. })] => Some(elts),
        _ => None,
    }
}

fn format_fragment(call: &ExprCall) -> Option<Fragment> {
    let Expr::Name(callee) = call.func.as_ref() else {
        return None;
    };
    let [value, spec] = call.arguments.args.as_ref() else {
        return None;
    };
    if callee.id.as_str() != "format" || !call.arguments.keywords.is_empty() {
        return None;
    }
    let spec: String = constant_text(spec)?;
    let (expression, conversion): (&Expr, ConversionFlag) = match value {
        Expr::Call(converted)
            if converted.arguments.keywords.is_empty() && converted.arguments.args.len() == 1 =>
        {
            let flag: ConversionFlag = match converted.func.as_ref() {
                Expr::Name(name) if name.id.as_str() == "str" => ConversionFlag::Str,
                Expr::Name(name) if name.id.as_str() == "repr" => ConversionFlag::Repr,
                Expr::Name(name) if name.id.as_str() == "ascii" => ConversionFlag::Ascii,
                _ => return None,
            };
            (converted.arguments.args.first()?, flag)
        }
        other => (other, ConversionFlag::None),
    };
    if !is_simple_interpolatable(expression) || spec.contains(['{', '}']) {
        return None;
    }
    Some(Fragment::Interpolation {
        expression: Box::new(expression.clone()),
        conversion,
        spec,
    })
}

fn constant_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(literal.value.to_str().to_owned()),
        Expr::Call(call) => empty_join(call)?
            .iter()
            .map(|part: &Expr| match part {
                Expr::StringLiteral(literal) => Some(literal.value.to_str()),
                _ => None,
            })
            .collect(),
        _ => None,
    }
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
                spec: String::new(),
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
                spec,
            } => {
                let expr_range: ruff_text_size::TextRange = expression.range();
                let format_spec: Option<Box<InterpolatedStringFormatSpec>> = (!spec.is_empty())
                    .then(|| {
                        Box::new(InterpolatedStringFormatSpec {
                            range,
                            node_index: AtomicNodeIndex::default(),
                            elements: InterpolatedStringElements::from(vec![
                                InterpolatedStringElement::Literal(
                                    InterpolatedStringLiteralElement {
                                        range,
                                        node_index: AtomicNodeIndex::default(),
                                        value: spec.into_boxed_str(),
                                    },
                                ),
                            ]),
                        })
                    });
                elements.push(InterpolatedStringElement::Interpolation(
                    InterpolatedElement {
                        range: expr_range,
                        node_index: AtomicNodeIndex::default(),
                        expression,
                        debug_text: None,
                        conversion,
                        format_spec,
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
    fn recovers_a_lowered_join_of_format_calls() {
        let out: String = run(
            "def f(name, score, pct):\n    return ''.join(['hi ', format(repr(name), ''), ', score=', format(score, ''.join(['04d'])), ' pct=', format(pct, '.2f'), format(str(name), '')])\nprint(f('a', 7, 0.5))\n",
        );
        assert!(
            out.contains("f'hi {name!r}, score={score:04d} pct={pct:.2f}{name!s}'")
                || out.contains("f\"hi {name!r}, score={score:04d} pct={pct:.2f}{name!s}\""),
            "expected the f-string back; got: {out}"
        );
    }

    #[test]
    fn a_rebound_format_keeps_the_join() {
        let out: String =
            run("def format(value, spec):\n    return '?'\nmsg = ''.join(['a', format(1, '')])\n");
        assert!(out.contains("''.join("), "format is user code here: {out}");
        let braces: String = run("x = 1\nmsg = ''.join(['a', format(x, '{')])\n");
        assert!(braces.contains("''.join("), "{braces}");
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
