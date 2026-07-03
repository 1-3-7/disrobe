use std::collections::BTreeMap;
use std::ops::Range;

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;
use regex::Regex;
use serde::Serialize;

use super::scanner::{
    apply_splice_edits, consume_trailing_semicolon, find_paren_close, scan_balanced_brace,
    split_top_level_args,
};

#[derive(Debug, Clone, Serialize)]
pub struct CalculatorReversalResult {
    pub calc_fn_name: Option<String>,
    pub ops_extracted: usize,
    pub call_sites_inlined: usize,
    pub rewritten_source: String,
}

#[must_use]
pub fn reverse_calculator(source: &str) -> CalculatorReversalResult {
    let Some(found): Option<CalculatorFn> = find_calculator_fn(source) else {
        return passthrough(source, None);
    };

    let Some(ops): Option<BTreeMap<i64, String>> =
        parse_op_table(&found.body).filter(|m| !m.is_empty())
    else {
        return passthrough(source, Some(found.fn_name));
    };

    let call_sites: Vec<CallSite> = find_call_sites(source, &found.fn_name, &ops);
    if call_sites.is_empty() {
        return CalculatorReversalResult {
            calc_fn_name: Some(found.fn_name),
            ops_extracted: ops.len(),
            call_sites_inlined: 0,
            rewritten_source: source.to_owned(),
        };
    }

    let mut edits: Vec<(Range<usize>, Option<String>)> = Vec::with_capacity(call_sites.len() + 1);
    let mut decl_safe: bool = true;
    let mut site_edits: Vec<(Range<usize>, Option<String>)> = Vec::with_capacity(call_sites.len());
    for site in &call_sites {
        if let Some(op) = ops.get(&site.op_code) {
            if is_short_circuit(op) && !operand_is_pure(&site.rhs) {
                decl_safe = false;
                continue;
            }
            let lhs: &String = &site.lhs;
            let rhs: &String = &site.rhs;
            let replacement: String = format!("({lhs} {op} {rhs})");
            site_edits.push((site.range.clone(), Some(replacement)));
        }
    }
    if decl_safe {
        edits.push((found.decl_range.clone(), None));
    }
    edits.extend(site_edits);
    let (rewritten, inlined): (String, usize) = apply_splice_edits(source, &mut edits);

    CalculatorReversalResult {
        calc_fn_name: Some(found.fn_name),
        ops_extracted: ops.len(),
        call_sites_inlined: inlined,
        rewritten_source: rewritten,
    }
}

fn passthrough(source: &str, calc_fn_name: Option<String>) -> CalculatorReversalResult {
    CalculatorReversalResult {
        calc_fn_name,
        ops_extracted: 0,
        call_sites_inlined: 0,
        rewritten_source: source.to_owned(),
    }
}

#[derive(Debug, Clone)]
struct CalculatorFn {
    fn_name: String,
    body: String,
    decl_range: Range<usize>,
}

#[derive(Debug, Clone)]
struct CallSite {
    range: Range<usize>,
    op_code: i64,
    lhs: String,
    rhs: String,
}

fn find_calculator_fn(source: &str) -> Option<CalculatorFn> {
    find_function_decl_calculator(source).or_else(|| find_var_assigned_calculator(source))
}

fn find_function_decl_calculator(source: &str) -> Option<CalculatorFn> {
    let re: Regex = Regex::new(
        r"(?ms)function\s+([A-Za-z_$][\w$]*)\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{",
    )
    .ok()?;
    for cap in re.captures_iter(source) {
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(op_param): Option<regex::Match<'_>> = cap.get(2) else {
            continue;
        };
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let body_open: usize = whole.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let body: String = source.get(body_open + 1..body_close)?.to_owned();
        if !body_looks_like_calculator(&body, op_param.as_str()) {
            continue;
        }
        let stmt_end: usize = consume_trailing_semicolon(source, body_close + 1);
        return Some(CalculatorFn {
            fn_name: name.as_str().to_owned(),
            body,
            decl_range: whole.start()..stmt_end,
        });
    }
    None
}

fn find_var_assigned_calculator(source: &str) -> Option<CalculatorFn> {
    let re: Regex = Regex::new(
        r"(?ms)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*function\s*\(\s*([A-Za-z_$][\w$]*)\s*,\s*[A-Za-z_$][\w$]*\s*,\s*[A-Za-z_$][\w$]*\s*\)\s*\{",
    )
    .ok()?;
    for cap in re.captures_iter(source) {
        let Some(name): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(op_param): Option<regex::Match<'_>> = cap.get(2) else {
            continue;
        };
        let Some(whole): Option<regex::Match<'_>> = cap.get(0) else {
            continue;
        };
        let body_open: usize = whole.end() - 1;
        let Some(body_close): Option<usize> = scan_balanced_brace(source, body_open + 1) else {
            continue;
        };
        let body: String = source.get(body_open + 1..body_close)?.to_owned();
        if !body_looks_like_calculator(&body, op_param.as_str()) {
            continue;
        }
        let stmt_end: usize = consume_trailing_semicolon(source, body_close + 1);
        return Some(CalculatorFn {
            fn_name: name.as_str().to_owned(),
            body,
            decl_range: whole.start()..stmt_end,
        });
    }
    None
}

fn body_looks_like_calculator(body: &str, op_param: &str) -> bool {
    let escaped: String = regex::escape(op_param);
    let Ok(switch_re): Result<Regex, regex::Error> =
        Regex::new(&format!(r"(?ms)switch\s*\(\s*{escaped}\s*\)"))
    else {
        return false;
    };
    if !switch_re.is_match(body) {
        return false;
    }
    let Ok(case_re): Result<Regex, regex::Error> =
        Regex::new(r"(?ms)case\s+(?:0x[0-9a-fA-F]+|-?\d+)\s*:")
    else {
        return false;
    };
    case_re.find_iter(body).count() >= 2
}

fn parse_op_table(body: &str) -> Option<BTreeMap<i64, String>> {
    let arms_re: Regex = Regex::new(
        r"(?ms)case\s+(0x[0-9a-fA-F]+|-?\d+)\s*:\s*return\s+([A-Za-z_$][\w$]*)\s*(===|!==|==|!=|<=|>=|<<|>>>|>>|&&|\|\||\?\?|\*\*|\+|-|\*|/|%|\^|&|\||<|>)\s*([A-Za-z_$][\w$]*)\s*;?",
    )
    .ok()?;
    let mut out: BTreeMap<i64, String> = BTreeMap::new();
    for cap in arms_re.captures_iter(body) {
        let Some(code_raw): Option<regex::Match<'_>> = cap.get(1) else {
            continue;
        };
        let Some(op): Option<regex::Match<'_>> = cap.get(3) else {
            continue;
        };
        let Some(code): Option<i64> = parse_int(code_raw.as_str()) else {
            continue;
        };
        out.insert(code, op.as_str().to_owned());
    }
    if out.is_empty() { None } else { Some(out) }
}

fn parse_int(s: &str) -> Option<i64> {
    let trimmed: &str = s.trim();
    let Some(hex): Option<&str> = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("-0x"))
    else {
        return trimmed.parse::<i64>().ok();
    };
    let sign: i64 = if trimmed.starts_with('-') { -1 } else { 1 };
    i64::from_str_radix(hex, 16).ok().map(|v| sign * v)
}

fn find_call_sites(source: &str, calc_fn: &str, ops: &BTreeMap<i64, String>) -> Vec<CallSite> {
    let escaped: String = regex::escape(calc_fn);
    let Ok(re): Result<Regex, regex::Error> = Regex::new(&format!(r"(?ms)\b{escaped}\s*\(")) else {
        return Vec::new();
    };
    let bytes: &[u8] = source.as_bytes();
    let mut out: Vec<CallSite> = Vec::new();
    for mat in re.find_iter(source) {
        let open_paren: usize = mat.end() - 1;
        let Some(close): Option<usize> = find_paren_close(bytes, open_paren + 1) else {
            continue;
        };
        let arg_text: &str = &source[open_paren + 1..close];
        let args: Vec<String> = split_top_level_args(arg_text);
        if args.len() != 3 {
            continue;
        }
        let Some(op_code): Option<i64> = parse_int(&args[0]) else {
            continue;
        };
        if !ops.contains_key(&op_code) {
            continue;
        }
        if !is_valid_operand(&args[1]) || !is_valid_operand(&args[2]) {
            continue;
        }
        out.push(CallSite {
            range: mat.start()..close + 1,
            op_code,
            lhs: args[1].trim().to_owned(),
            rhs: args[2].trim().to_owned(),
        });
    }
    out
}

const fn is_short_circuit(op: &str) -> bool {
    matches!(op.as_bytes(), b"&&" | b"||" | b"??")
}

fn operand_is_pure(operand: &str) -> bool {
    let trimmed: &str = operand.trim();
    if trimmed.is_empty() {
        return false;
    }
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("operand.js").unwrap_or_default();
    let wrapped: String = format!("({trimmed});");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    if !parsed.errors.is_empty() || parsed.panicked {
        return false;
    }
    let Some(oxc_ast::ast::Statement::ExpressionStatement(stmt)) = parsed.program.body.first()
    else {
        return false;
    };
    expression_is_pure(&stmt.expression)
}

fn expression_is_pure(expr: &oxc_ast::ast::Expression<'_>) -> bool {
    use oxc_ast::ast::Expression;
    match expr {
        Expression::Identifier(_)
        | Expression::StringLiteral(_)
        | Expression::NumericLiteral(_)
        | Expression::BooleanLiteral(_)
        | Expression::NullLiteral(_)
        | Expression::BigIntLiteral(_)
        | Expression::RegExpLiteral(_)
        | Expression::ThisExpression(_) => true,
        Expression::ParenthesizedExpression(p) => expression_is_pure(&p.expression),
        Expression::UnaryExpression(u) => {
            !matches!(u.operator, oxc_ast::ast::UnaryOperator::Delete)
                && expression_is_pure(&u.argument)
        }
        Expression::StaticMemberExpression(m) => expression_is_pure(&m.object),
        Expression::ComputedMemberExpression(m) => {
            expression_is_pure(&m.object) && expression_is_pure(&m.expression)
        }
        Expression::BinaryExpression(b) => {
            expression_is_pure(&b.left) && expression_is_pure(&b.right)
        }
        Expression::LogicalExpression(l) => {
            expression_is_pure(&l.left) && expression_is_pure(&l.right)
        }
        Expression::ConditionalExpression(c) => {
            expression_is_pure(&c.test)
                && expression_is_pure(&c.consequent)
                && expression_is_pure(&c.alternate)
        }
        _ => false,
    }
}

fn is_valid_operand(s: &str) -> bool {
    let trimmed: &str = s.trim();
    if trimmed.is_empty() {
        return false;
    }
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("operand.js").unwrap_or_default();
    let wrapped: String = format!("({trimmed});");
    let parsed: oxc_parser::ParserReturn<'_> =
        Parser::new(&allocator, &wrapped, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_three_arm_op_table() {
        let body: &str =
            "switch (op) { case 0: return a + b; case 1: return a - b; case 2: return a * b; }";
        let table: BTreeMap<i64, String> = parse_op_table(body).expect("table must parse");
        assert_eq!(table.get(&0).map(String::as_str), Some("+"));
        assert_eq!(table.get(&1).map(String::as_str), Some("-"));
        assert_eq!(table.get(&2).map(String::as_str), Some("*"));
    }

    #[test]
    fn detects_function_declaration_form() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; case 1: return a - b; } }";
        let found: CalculatorFn = find_calculator_fn(src).expect("calculator must be detected");
        assert_eq!(found.fn_name, "_calc");
    }

    #[test]
    fn detects_var_assigned_form() {
        let src: &str = "var _c = function(op, x, y) { switch (op) { case 0x0: return x + y; case 0x1: return x * y; } };";
        let found: CalculatorFn =
            find_calculator_fn(src).expect("var-assigned calculator must be detected");
        assert_eq!(found.fn_name, "_c");
    }

    #[test]
    fn rewrites_single_call_site_add() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; case 1: return a - b; } } var z = _calc(0, 5, 7);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.calc_fn_name.as_deref(), Some("_calc"));
        assert_eq!(result.ops_extracted, 2);
        assert_eq!(result.call_sites_inlined, 1);
        assert!(
            result.rewritten_source.contains("var z = (5 + 7);"),
            "expected (5 + 7), got: {}",
            result.rewritten_source
        );
        assert!(
            !result.rewritten_source.contains("function _calc"),
            "decl should be stripped: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn rewrites_three_call_sites_mixed_ops() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; case 1: return a * b; case 2: return a === b; } }
            var p = _calc(0, x, y);
            var q = _calc(1, p, 2);
            var r = _calc(2, q, 4);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.ops_extracted, 3);
        assert_eq!(result.call_sites_inlined, 3);
        let s: &String = &result.rewritten_source;
        assert!(s.contains("var p = (x + y);"), "got: {s}");
        assert!(s.contains("var q = (p * 2);"), "got: {s}");
        assert!(s.contains("var r = (q === 4);"), "got: {s}");
    }

    #[test]
    fn unknown_op_code_leaves_call_alone() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; case 1: return a - b; } } var z = _calc(99, 1, 2);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.ops_extracted, 2);
        assert_eq!(result.call_sites_inlined, 0);
        assert!(
            result.rewritten_source.contains("_calc(99, 1, 2)"),
            "unknown-op call must be preserved: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn passthrough_when_no_calculator() {
        let src: &str = "function add(a, b) { return a + b; } var z = add(1, 2);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert!(result.calc_fn_name.is_none());
        assert_eq!(result.ops_extracted, 0);
        assert_eq!(result.call_sites_inlined, 0);
        assert_eq!(result.rewritten_source, src);
    }

    #[test]
    fn handles_hex_op_codes() {
        let src: &str = "function _c(op, a, b) { switch (op) { case 0x10: return a & b; case 0x11: return a | b; } } var k = _c(0x10, mask, bit);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.ops_extracted, 2);
        assert_eq!(result.call_sites_inlined, 1);
        assert!(
            result.rewritten_source.contains("(mask & bit)"),
            "hex op fold missing: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn skips_calls_with_wrong_arity() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; case 1: return a - b; } } var z = _calc(0, 5);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.ops_extracted, 2);
        assert_eq!(result.call_sites_inlined, 0);
        assert!(
            result.rewritten_source.contains("_calc(0, 5)"),
            "wrong-arity call must be preserved: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn rejects_malformed_operand_in_call() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a + b; } } var z = _calc(0, @@@, 7);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.call_sites_inlined, 0);
        assert!(
            result.rewritten_source.contains("@@@"),
            "malformed operand call must pass through: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn does_not_drop_side_effecting_rhs_under_short_circuit_and() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a && b; case 1: return a + b; } } var z = _calc(0, flag, side());";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(
            result.call_sites_inlined, 0,
            "folding (flag && side()) would skip side() when flag is falsy; must be left alone"
        );
        assert!(
            result.rewritten_source.contains("_calc(0, flag, side())"),
            "the call with a side-effecting rhs under && must survive: {}",
            result.rewritten_source
        );
        assert!(
            result.rewritten_source.contains("function _calc"),
            "the calculator decl must be kept when a short-circuit fold was refused: {}",
            result.rewritten_source
        );
    }

    #[test]
    fn folds_short_circuit_with_pure_rhs() {
        let src: &str = "function _calc(op, a, b) { switch (op) { case 0: return a && b; case 1: return a + b; } } var z = _calc(0, flag, ready);";
        let result: CalculatorReversalResult = reverse_calculator(src);
        assert_eq!(result.call_sites_inlined, 1);
        assert!(
            result.rewritten_source.contains("(flag && ready)"),
            "a pure rhs under && is safe to fold: {}",
            result.rewritten_source
        );
    }
}
