use std::collections::BTreeMap;

use ruff_python_ast::visitor::{Visitor, walk_expr};
use ruff_python_ast::{CmpOp, Expr, ExprBinOp, ExprCompare, ModModule, Number, Operator, Stmt};
use ruff_python_parser::{Parsed, parse_module};

use crate::ast_eval::{EvalReport, evaluate_source};
use crate::codec::{b64_decode, zlib_decompress_bounded};

const MAX_LAYERS: usize = 16;
const LAYER_OUTPUT_LIMIT: u64 = 64 * 1024 * 1024;
const MIN_PAYLOAD_ITEMS: usize = 16;
const MIN_BASE64_LITERAL: usize = 64;
const BANNER: &str = "\"\"\":: You managed to break through BlankOBF";

#[derive(Debug, Default)]
pub(crate) struct LayerPeel {
    pub(crate) source: String,
    pub(crate) stages: Vec<String>,
    pub(crate) banner_removed: bool,
    pub(crate) exprs_folded: usize,
    pub(crate) bindings_learned: usize,
    pub(crate) layer_limit_reached: bool,
}

pub(crate) fn peel_layers(text: &str) -> LayerPeel {
    let mut peel: LayerPeel = LayerPeel::default();
    let mut current: String = text.to_owned();
    for depth in 0..=MAX_LAYERS {
        let folded: String = match evaluate_source(&current) {
            Ok((folded, report)) => {
                let report: EvalReport = report;
                peel.exprs_folded += report.exprs_folded;
                peel.bindings_learned += report.bindings_learned;
                folded
            }
            Err(_) => current.clone(),
        };
        match decode_layer(&folded) {
            Some((label, next)) if depth < MAX_LAYERS => {
                peel.stages.push(label.to_owned());
                current = next;
            }
            Some(_) => {
                peel.layer_limit_reached = true;
                current = folded;
                break;
            }
            None => {
                if peel.stages.is_empty() {
                    current = folded;
                }
                break;
            }
        }
    }
    if let Some(rest) = strip_banner(&current) {
        peel.banner_removed = true;
        let consumed: usize = current.len() - rest.len();
        current.drain(..consumed);
    }
    if !peel.stages.is_empty()
        && let Some(rest) = current.strip_prefix("pass\n")
        && !rest.trim().is_empty()
    {
        let consumed: usize = current.len() - rest.len();
        current.drain(..consumed);
    }
    peel.source = current;
    peel
}

fn strip_banner(text: &str) -> Option<&str> {
    let after_open: &str = text.trim_start().strip_prefix(BANNER)?;
    let close: usize = after_open.find("\"\"\"")?;
    let rest: &str = after_open.get(close + 3..)?;
    Some(
        rest.strip_prefix("\r\n")
            .or_else(|| rest.strip_prefix('\n'))
            .unwrap_or(rest),
    )
}

#[derive(Clone, Copy)]
enum SliceEnd {
    Open,
    At(usize),
}

enum Part {
    Slice(SliceEnd, SliceEnd),
    Literal(Vec<u8>),
}

#[derive(Default)]
struct LayerShape {
    int_lists: BTreeMap<String, Vec<u8>>,
    dotted_lists: Vec<Vec<String>>,
    xor_key: Option<u8>,
    slices: Option<(Option<String>, Vec<Part>)>,
    longest_text: Option<String>,
}

fn decode_layer(source: &str) -> Option<(&'static str, String)> {
    let parsed: Parsed<ModModule> = parse_module(source).ok()?;
    let mut shape: LayerShape = LayerShape::default();
    for stmt in &parsed.syntax().body {
        record_assignment(stmt, &mut shape);
        shape.visit_stmt(stmt);
    }
    xor_list_layer(&shape)
        .map(|text: String| ("blankobf-xor-list", text))
        .or_else(|| dotted_list_layer(&shape).map(|text: String| ("blankobf-ip-list", text)))
        .or_else(|| base64_layer(&shape).map(|text: String| ("blankobf-base64-zlib", text)))
}

fn next_source(payload: &[u8]) -> Option<String> {
    let inflated: Vec<u8> = zlib_decompress_bounded(payload, LAYER_OUTPUT_LIMIT).ok()?;
    let text: String = String::from_utf8(inflated).ok()?;
    parse_module(&text).ok()?;
    Some(text)
}

fn xor_list_layer(shape: &LayerShape) -> Option<String> {
    let key: u8 = shape.xor_key?;
    let (name, parts): &(Option<String>, Vec<Part>) = shape.slices.as_ref()?;
    let list: Option<&Vec<u8>> = name
        .as_ref()
        .and_then(|name: &String| shape.int_lists.get(name));
    let mut data: Vec<u8> = Vec::new();
    for part in parts {
        match part {
            Part::Slice(lower, upper) => {
                let list: &Vec<u8> = list?;
                let start: usize = match lower {
                    SliceEnd::Open => 0,
                    SliceEnd::At(at) => *at,
                };
                let end: usize = match upper {
                    SliceEnd::Open => list.len(),
                    SliceEnd::At(at) => *at,
                };
                data.extend_from_slice(list.get(start..end)?);
            }
            Part::Literal(bytes) => data.extend_from_slice(bytes),
        }
    }
    let decoded: Vec<u8> = data.iter().map(|byte: &u8| byte ^ key).collect();
    next_source(&decoded)
}

fn dotted_list_layer(shape: &LayerShape) -> Option<String> {
    shape.dotted_lists.iter().find_map(|quads: &Vec<String>| {
        let mut encoded: Vec<u8> = Vec::with_capacity(quads.len() * 4);
        for quad in quads {
            for octet in quad.split('.') {
                encoded.push(octet.parse::<u8>().ok()?);
            }
        }
        next_source(&b64_decode(&encoded).ok()?)
    })
}

fn base64_layer(shape: &LayerShape) -> Option<String> {
    let literal: &String = shape.longest_text.as_ref()?;
    if literal.len() < MIN_BASE64_LITERAL {
        return None;
    }
    next_source(&b64_decode(literal.as_bytes()).ok()?)
}

fn record_assignment(stmt: &Stmt, shape: &mut LayerShape) {
    let Stmt::Assign(assign) = stmt else {
        return;
    };
    let [Expr::Name(target)] = assign.targets.as_slice() else {
        return;
    };
    let Expr::List(list) = assign.value.as_ref() else {
        return;
    };
    if list.elts.len() < MIN_PAYLOAD_ITEMS {
        return;
    }
    let bytes: Option<Vec<u8>> = list.elts.iter().map(small_int).collect();
    if let Some(bytes) = bytes {
        shape.int_lists.insert(target.id.as_str().to_owned(), bytes);
        return;
    }
    let quads: Option<Vec<String>> = list
        .elts
        .iter()
        .map(|item: &Expr| match item {
            Expr::StringLiteral(text) if text.value.to_str().split('.').count() == 4 => {
                Some(text.value.to_str().to_owned())
            }
            _ => None,
        })
        .collect();
    if let Some(quads) = quads {
        shape.dotted_lists.push(quads);
    }
}

const fn int_value(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            Number::Int(int) => int.as_u64(),
            _ => None,
        },
        _ => None,
    }
}

fn small_int(expr: &Expr) -> Option<u8> {
    u8::try_from(int_value(expr)?).ok()
}

fn slice_bound(expr: Option<&Expr>) -> Option<SliceEnd> {
    match expr {
        None => Some(SliceEnd::Open),
        Some(bound) => usize::try_from(int_value(bound)?).ok().map(SliceEnd::At),
    }
}

fn slice_chain(expr: &Expr, name: &mut Option<String>, out: &mut Vec<Part>) -> bool {
    match expr {
        Expr::BinOp(ExprBinOp {
            left,
            op: Operator::Add,
            right,
            ..
        }) => slice_chain(left, name, out) && slice_chain(right, name, out),
        Expr::List(list) => list
            .elts
            .iter()
            .map(small_int)
            .collect::<Option<Vec<u8>>>()
            .is_some_and(|bytes: Vec<u8>| {
                out.push(Part::Literal(bytes));
                true
            }),
        Expr::Subscript(subscript) => {
            let Expr::Name(base) = subscript.value.as_ref() else {
                return false;
            };
            if name
                .as_deref()
                .is_some_and(|seen: &str| seen != base.id.as_str())
            {
                return false;
            }
            let Expr::Slice(slice) = subscript.slice.as_ref() else {
                return false;
            };
            if slice.step.is_some() {
                return false;
            }
            let (Some(lower), Some(upper)) = (
                slice_bound(slice.lower.as_deref()),
                slice_bound(slice.upper.as_deref()),
            ) else {
                return false;
            };
            *name = Some(base.id.as_str().to_owned());
            out.push(Part::Slice(lower, upper));
            true
        }
        _ => false,
    }
}

impl<'a> Visitor<'a> for LayerShape {
    fn visit_expr(&mut self, expr: &'a Expr) {
        match expr {
            Expr::Compare(ExprCompare {
                left,
                ops,
                comparators,
                ..
            }) if self.xor_key.is_none() => {
                if let (
                    Expr::BinOp(ExprBinOp {
                        left: constant,
                        op: Operator::BitXor,
                        right: variable,
                        ..
                    }),
                    [CmpOp::Eq],
                    [expected],
                ) = (left.as_ref(), ops.as_ref(), comparators.as_ref())
                    && matches!(variable.as_ref(), Expr::Name(_))
                    && let (Some(a), Some(b)) = (small_int(constant), small_int(expected))
                {
                    self.xor_key = Some(a ^ b);
                }
            }
            Expr::BinOp(ExprBinOp {
                op: Operator::Add, ..
            }) if self.slices.is_none() => {
                let mut name: Option<String> = None;
                let mut parts: Vec<Part> = Vec::new();
                if slice_chain(expr, &mut name, &mut parts) {
                    self.slices = Some((name, parts));
                }
            }
            Expr::StringLiteral(text) => {
                let value: &str = text.value.to_str();
                if self
                    .longest_text
                    .as_ref()
                    .is_none_or(|longest: &String| value.len() > longest.len())
                {
                    self.longest_text = Some(value.to_owned());
                }
            }
            _ => {}
        }
        walk_expr(self, expr);
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::codec::{b64_encode, zlib_compress};

    fn int_list(bytes: &[u8]) -> String {
        bytes
            .iter()
            .map(u8::to_string)
            .collect::<Vec<String>>()
            .join(", ")
    }

    #[test]
    fn peels_the_three_blankobf_layer_shapes_and_the_banner() {
        let inner: String = format!("{BANNER} ::\"\"\"\nprint('hello world')\n");
        let packed: String = b64_encode(&zlib_compress(inner.as_bytes()));
        let quads: String = packed
            .as_bytes()
            .chunks(4)
            .map(|chunk: &[u8]| {
                format!(
                    "'{}'",
                    chunk
                        .iter()
                        .map(u8::to_string)
                        .collect::<Vec<String>>()
                        .join(".")
                )
            })
            .collect::<Vec<String>>()
            .join(", ");
        let ip_layer: String = format!("_0xaa = [{quads}]\nexec(_0xaa)\n");
        let b64_layer: String = format!(
            "exec(zlib.decompress(base64.b64decode('{}')))\n",
            b64_encode(&zlib_compress(ip_layer.as_bytes()))
        );
        let key: u8 = 0x4b ^ 0x64;
        let mut xored: Vec<u8> = zlib_compress(b64_layer.as_bytes())
            .iter()
            .map(|byte: &u8| byte ^ key)
            .collect();
        xored.insert(3, 0);
        let outer: String = format!(
            "_0xbb = [{}]\nfor _0xk in range(1, 100):\n    if 75 ^ _0xk == 100:\n        exec(zlib.decompress(bytes(map(lambda x: x ^ _0xk, _0xbb[0:3] + _0xbb[4:]))))\n        break\n",
            int_list(&xored)
        );
        let peel: LayerPeel = peel_layers(&outer);
        assert_eq!(
            peel.stages,
            vec![
                "blankobf-xor-list",
                "blankobf-base64-zlib",
                "blankobf-ip-list"
            ]
        );
        assert!(peel.banner_removed);
        assert_eq!(peel.source.trim(), "print('hello world')");
    }

    #[test]
    fn layer_depth_is_bounded() {
        let mut layer: String = "print('core')\n".to_owned();
        for _ in 0..=MAX_LAYERS + 1 {
            layer = format!(
                "exec(zlib.decompress(base64.b64decode('{}')))\n",
                b64_encode(&zlib_compress(layer.as_bytes()))
            );
        }
        let peel: LayerPeel = peel_layers(&layer);
        assert!(peel.layer_limit_reached);
        assert_eq!(peel.stages.len(), MAX_LAYERS);
    }

    #[test]
    fn a_layer_that_inflates_past_the_limit_is_not_decoded() {
        let bomb: Vec<u8> = vec![b'#'; usize::try_from(LAYER_OUTPUT_LIMIT).expect("fits") + 1];
        let layer: String = format!(
            "exec(zlib.decompress(base64.b64decode('{}')))\n",
            b64_encode(&zlib_compress(&bomb))
        );
        let peel: LayerPeel = peel_layers(&layer);
        assert!(peel.stages.is_empty());
    }

    #[test]
    fn plain_programs_have_no_layer() {
        let peel: LayerPeel = peel_layers("data = [1, 2, 3]\nprint(data[0:1] + data[2:])\n");
        assert!(peel.stages.is_empty());
        assert!(!peel.banner_removed);
    }
}
