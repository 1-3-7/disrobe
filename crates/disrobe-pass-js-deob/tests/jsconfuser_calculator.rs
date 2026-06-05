#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{CalculatorReversalResult, reverse_calculator};

#[test]
fn reverses_realistic_three_op_calculator() {
    let src: &str = r"function _calc(op, a, b) {
    switch (op) {
        case 0: return a + b;
        case 1: return a - b;
        case 2: return a * b;
        case 3: return a / b;
        case 4: return a === b;
    }
}
var x = _calc(0, 10, 5);
var y = _calc(2, x, 3);
var z = _calc(4, y, 90);
";
    let result: CalculatorReversalResult = reverse_calculator(src);
    assert_eq!(result.calc_fn_name.as_deref(), Some("_calc"));
    assert_eq!(result.ops_extracted, 5);
    assert_eq!(result.call_sites_inlined, 3);

    let s: &String = &result.rewritten_source;
    assert!(s.contains("var x = (10 + 5);"), "add fold missing: {s}");
    assert!(s.contains("var y = (x * 3);"), "mul fold missing: {s}");
    assert!(s.contains("var z = (y === 90);"), "eq fold missing: {s}");
    assert!(!s.contains("function _calc"), "decl must be stripped: {s}");
}

#[test]
fn combined_with_dispatcher_pipeline() {
    let src: &str = r#"function _calc(op, a, b) {
    switch (op) {
        case 0: return a + b;
        case 1: return a * b;
    }
}
var fns = Object.create(null);
fns["compute"] = function(p, q){ return _calc(0, p, q); };
function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }
var r = dispatch("compute", 7, 3);
"#;
    let after_calc: CalculatorReversalResult = reverse_calculator(src);
    assert_eq!(after_calc.ops_extracted, 2);
    assert_eq!(after_calc.call_sites_inlined, 1);

    let s: &String = &after_calc.rewritten_source;
    assert!(s.contains("return (p + q);"), "inner fold missing: {s}");
    assert!(!s.contains("_calc("), "_calc reference leak: {s}");
}

#[test]
fn rejects_function_that_isnt_calculator() {
    let src: &str = r"function nonCalc(op, a, b) { console.log(op); return a + b; }
var x = nonCalc(0, 1, 2);";
    let result: CalculatorReversalResult = reverse_calculator(src);
    assert!(result.calc_fn_name.is_none());
    assert_eq!(result.ops_extracted, 0);
    assert_eq!(result.call_sites_inlined, 0);
    assert_eq!(result.rewritten_source, src);
}

#[test]
fn handles_relational_and_logical_ops() {
    let src: &str = r"function _c(o, a, b) {
    switch (o) {
        case 0: return a < b;
        case 1: return a > b;
        case 2: return a && b;
        case 3: return a || b;
    }
}
var p = _c(0, x, 10);
var q = _c(2, p, ready);
";
    let result: CalculatorReversalResult = reverse_calculator(src);
    assert_eq!(result.ops_extracted, 4);
    assert_eq!(result.call_sites_inlined, 2);
    let s: &String = &result.rewritten_source;
    assert!(s.contains("var p = (x < 10);"), "lt fold missing: {s}");
    assert!(s.contains("var q = (p && ready);"), "and fold missing: {s}");
}

#[test]
fn empty_input_passes_through_cleanly() {
    let result: CalculatorReversalResult = reverse_calculator("");
    assert!(result.calc_fn_name.is_none());
    assert_eq!(result.ops_extracted, 0);
    assert_eq!(result.call_sites_inlined, 0);
    assert_eq!(result.rewritten_source, "");
}
