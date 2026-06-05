#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{DispatcherReversalResult, reverse_dispatcher};

#[test]
fn realistic_three_entry_pipeline() {
    let src: &str = r#"var fns = Object.create(null);
fns["a1b2"] = function nm1(){ return 1 + 2; };
fns["c3d4"] = function nm2(arg){ return arg * 2; };
fns["e5f6"] = function nm3(a, b){ return a + b; };
function dispatch(key, flag, retType){ return fns[key].apply(this, [].slice.call(arguments, 1)); }
var alpha = dispatch("a1b2", 0, undefined);
var beta = dispatch("c3d4", 1, 21);
var gamma = dispatch("e5f6", 2, 10, 20);
"#;
    let result: DispatcherReversalResult = reverse_dispatcher(src);

    assert_eq!(result.table_id.as_deref(), Some("fns"));
    assert_eq!(result.entries_extracted, 3);
    assert_eq!(result.call_sites_inlined, 3);

    let rewritten: &String = &result.rewritten_source;
    assert!(
        rewritten.contains("(function nm1(){ return 1 + 2; })(0, undefined)"),
        "first inline missing: {rewritten}"
    );
    assert!(
        rewritten.contains("(function nm2(arg){ return arg * 2; })(1, 21)"),
        "second inline missing: {rewritten}"
    );
    assert!(
        rewritten.contains("(function nm3(a, b){ return a + b; })(2, 10, 20)"),
        "third inline missing: {rewritten}"
    );

    assert!(
        !rewritten.contains("Object.create(null)"),
        "table decl not stripped: {rewritten}"
    );
    assert!(
        !rewritten.contains("fns[\"a1b2\"]"),
        "entry 1 not stripped: {rewritten}"
    );
    assert!(
        !rewritten.contains("fns[\"c3d4\"]"),
        "entry 2 not stripped: {rewritten}"
    );
    assert!(
        !rewritten.contains("function dispatch("),
        "dispatcher fn not stripped: {rewritten}"
    );
}

#[test]
fn passthrough_when_no_dispatch_fn() {
    let src: &str = r#"var fns = Object.create(null);
fns["only"] = function(){ return 42; };
var x = fns["only"];
"#;
    let result: DispatcherReversalResult = reverse_dispatcher(src);
    assert_eq!(result.table_id.as_deref(), Some("fns"));
    assert_eq!(result.entries_extracted, 0);
    assert_eq!(result.call_sites_inlined, 0);
    assert_eq!(result.rewritten_source, src, "source must be untouched");
}

#[test]
fn passthrough_when_unrelated_source() {
    let src: &str = "function add(a,b){ return a+b; } var z = add(1,2);";
    let result: DispatcherReversalResult = reverse_dispatcher(src);
    assert!(result.table_id.is_none());
    assert_eq!(result.entries_extracted, 0);
    assert_eq!(result.call_sites_inlined, 0);
    assert_eq!(result.rewritten_source, src);
}

#[test]
fn handles_string_args_with_commas() {
    let src: &str = r#"var fns = Object.create(null);
fns["log"] = function(msg){ return msg; };
function dispatch(k){ return fns[k].apply(this, [].slice.call(arguments, 1)); }
var out = dispatch("log", "hello, world");
"#;
    let result: DispatcherReversalResult = reverse_dispatcher(src);
    assert_eq!(result.entries_extracted, 1);
    assert_eq!(result.call_sites_inlined, 1);
    assert!(
        result
            .rewritten_source
            .contains(r#"(function(msg){ return msg; })("hello, world")"#),
        "string-arg with comma must survive: {}",
        result.rewritten_source
    );
}
