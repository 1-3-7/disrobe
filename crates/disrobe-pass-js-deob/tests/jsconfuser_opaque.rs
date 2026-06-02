#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    DispatcherReversalResult, OpaqueReversalResult, RgfReversalResult, reverse_dispatcher,
    reverse_opaque_predicates, reverse_rgf,
};

#[test]
fn folds_negation_array_true_predicate() {
    let src: &str = "function gate(ready){ if (!![] && ready) { return ready; } return false; }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    assert!(
        result
            .rewritten_source
            .contains("if (ready) { return ready; }"),
        "expected `!![] &&` stripped, got: {}",
        result.rewritten_source
    );
    assert!(
        !result.rewritten_source.contains("!![]"),
        "opaque-true literal should be gone: {}",
        result.rewritten_source
    );
}

#[test]
fn folds_string_equality_or_predicate() {
    let src: &str = "function run(go){ if ('x' === 'y' || go) { dispatch(); } }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    assert!(
        result.rewritten_source.contains("if (go) { dispatch(); }"),
        "expected always-false || stripped, got: {}",
        result.rewritten_source
    );
}

#[test]
fn folds_xor_self_ternary_to_consequent() {
    let src: &str = "var pick = ((9 ^ 0) === 9) ? realPayload() : junk();";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    assert!(
        result
            .rewritten_source
            .contains("var pick = realPayload();"),
        "expected ternary true-branch, got: {}",
        result.rewritten_source
    );
    assert!(
        !result.rewritten_source.contains("junk()"),
        "junk-fn (false branch) should be gone: {}",
        result.rewritten_source
    );
}

#[test]
fn folds_typeof_predicate_standalone_if() {
    let src: &str = "function init(){ if (typeof 0 === 'number') { setup(); load(); } }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    let rewritten: &String = &result.rewritten_source;
    assert!(rewritten.contains("setup();"), "body kept: {rewritten}");
    assert!(rewritten.contains("load();"), "body kept: {rewritten}");
    assert!(
        !rewritten.contains("typeof 0"),
        "always-true if should be unwrapped: {rewritten}"
    );
}

#[test]
fn folds_arithmetic_equality_and_predicate() {
    let src: &str = "if (1 + 1 === 2 && condition()) { execute(); }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    assert!(
        result
            .rewritten_source
            .contains("if (condition()) { execute(); }"),
        "expected arithmetic-true predicate stripped, got: {}",
        result.rewritten_source
    );
}

#[test]
fn drops_always_false_standalone_if() {
    let src: &str = "function clean(){ stay(); if ([].length) { dead(); } go(); }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 1);
    let rewritten: &String = &result.rewritten_source;
    assert!(rewritten.contains("stay();"), "pre-if kept: {rewritten}");
    assert!(rewritten.contains("go();"), "post-if kept: {rewritten}");
    assert!(
        !rewritten.contains("dead()"),
        "false-branch body dropped: {rewritten}"
    );
}

#[test]
fn leaves_unrelated_predicates_alone() {
    let src: &str = "if (user.isAdmin && hasPermission(action)) { allow(); }";
    let result: OpaqueReversalResult = reverse_opaque_predicates(src);

    assert_eq!(result.predicates_folded, 0);
    assert_eq!(
        result.rewritten_source, src,
        "real predicates must pass through"
    );
}

#[test]
fn combined_with_rgf_and_dispatcher() {
    let src: &str = r#"var _rgf_pipe = [new Function('return 42'), new Function('return 99')];
var fns = Object.create(null);
fns["taskA"] = function tA(){ return 1; };
fns["taskB"] = function tB(arg){ return arg * 2; };
function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }
function exec(go){
    var first = _rgf_pipe[0].apply(this, [_rgf_pipe, arguments]);
    var second = _rgf_pipe[1].apply(this, [_rgf_pipe, arguments]);
    if (!![] && go) {
        var a = dispatch("taskA");
        var b = dispatch("taskB", 21);
        return ('a' === 'a') ? (first + second + a + b) : junk();
    }
    return null;
}
"#;

    let after_rgf: RgfReversalResult = reverse_rgf(src);
    assert_eq!(after_rgf.entries_extracted, 2, "rgf entries");
    assert_eq!(after_rgf.call_sites_inlined, 2, "rgf call-sites");

    let after_dispatcher: DispatcherReversalResult =
        reverse_dispatcher(&after_rgf.rewritten_source);
    assert_eq!(after_dispatcher.entries_extracted, 2, "dispatcher entries");
    assert_eq!(
        after_dispatcher.call_sites_inlined, 2,
        "dispatcher call-sites"
    );

    let after_opaque: OpaqueReversalResult =
        reverse_opaque_predicates(&after_dispatcher.rewritten_source);
    assert!(
        after_opaque.predicates_folded >= 2,
        "expected ≥2 predicates folded, got {}",
        after_opaque.predicates_folded
    );

    let final_src: &String = &after_opaque.rewritten_source;
    assert!(
        final_src.contains("(function(){return 42})()"),
        "rgf body 0 inlined: {final_src}"
    );
    assert!(
        final_src.contains("(function(){return 99})()"),
        "rgf body 1 inlined: {final_src}"
    );
    assert!(
        final_src.contains("(function tA(){ return 1; })()"),
        "dispatcher taskA inlined: {final_src}"
    );
    assert!(
        final_src.contains("(function tB(arg){ return arg * 2; })(21)"),
        "dispatcher taskB inlined: {final_src}"
    );
    assert!(
        final_src.contains("if (go)"),
        "opaque-true `&& go` should reduce to `if (go)`: {final_src}"
    );
    assert!(
        !final_src.contains("!![]"),
        "opaque-true literal should be gone: {final_src}"
    );
    assert!(
        !final_src.contains("junk()"),
        "ternary false-branch should be dropped: {final_src}"
    );
    assert!(
        !final_src.contains("Object.create(null)"),
        "dispatcher table should be stripped: {final_src}"
    );
    assert!(
        !final_src.contains("_rgf_pipe ="),
        "rgf decl should be stripped: {final_src}"
    );
}
