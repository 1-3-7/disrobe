#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var __out = []; var print = function(v){{ __out.push(String(v)); }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

fn assert_recovered_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String = eval_capture(original).expect("orig evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ORIG_FOR_INFINITE: &str = r"
function countTo(n) {
  var out = [];
  var i = 0;
  for (;;) {
    if (i >= n) { break; }
    out.push(i);
    i++;
  }
  return out.join(',');
}
print(countTo(4));
";

#[test]
fn for_infinite_becomes_while_true() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_FOR_INFINITE);
    assert!(
        stats.for_loops_to_while >= 1,
        "for(;;) must become while(true); got {}",
        stats.for_loops_to_while
    );
    assert!(
        recovered.contains("while (true)") && !recovered.contains("for (;;)"),
        "must convert to while loop:\n{recovered}"
    );
    assert_recovered_equivalent("for-infinite", ORIG_FOR_INFINITE, &recovered);
}

const ORIG_FOR_TEST_ONLY: &str = r"
function drain(n) {
  var out = [];
  var i = 0;
  for (; i < n;) {
    out.push(i);
    i++;
  }
  return out.join(',');
}
print(drain(3));
";

#[test]
fn for_test_only_becomes_while_cond() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_FOR_TEST_ONLY);
    assert!(
        stats.for_loops_to_while >= 1,
        "for(;cond;) must become while(cond); got {}",
        stats.for_loops_to_while
    );
    assert!(
        recovered.contains("while (i < n)"),
        "must convert to while with the test:\n{recovered}"
    );
    assert_recovered_equivalent("for-test", ORIG_FOR_TEST_ONLY, &recovered);
}

const NEG_FOR_FULL: &str = r"
function s(n) { var t = 0; for (var i = 0; i < n; i++) { t += i; } return t; }
print(s(5));
";

#[test]
fn full_for_loop_is_not_converted() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_FOR_FULL);
    assert_eq!(
        stats.for_loops_to_while, 0,
        "a for with init and update must NOT be converted to while"
    );
    assert!(
        recovered.contains("for (var i = 0; i < n; i++)"),
        "the full for loop must be preserved:\n{recovered}"
    );
}

const ORIG_BLOCKLESS: &str = r"
function f(x) {
  if (x > 0) return 'pos';
  else return 'neg';
}
print(f(3));
print(f(-2));
";

#[test]
fn braceless_if_else_gets_blocks() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_BLOCKLESS);
    assert!(
        stats.statement_bodies_blocked >= 2,
        "both the if and else single statements must be wrapped; got {}",
        stats.statement_bodies_blocked
    );
    assert!(
        recovered.contains("if (x > 0) { return 'pos'; }"),
        "if body must be wrapped in braces:\n{recovered}"
    );
    assert_recovered_equivalent("blockless", ORIG_BLOCKLESS, &recovered);
}

const ORIG_ELSE_IF_CHAIN: &str = r"
function grade(n) {
  if (n >= 90) return 'a';
  else if (n >= 80) return 'b';
  else return 'c';
}
print(grade(95));
print(grade(85));
print(grade(50));
";

#[test]
fn else_if_chain_is_not_broken() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ORIG_ELSE_IF_CHAIN);
    assert!(
        recovered.contains("else if (n >= 80)"),
        "the else-if chain must be preserved, not wrapped into else block:\n{recovered}"
    );
    assert!(
        stats.statement_bodies_blocked >= 1,
        "the return bodies should still be wrapped; got {}",
        stats.statement_bodies_blocked
    );
    assert_recovered_equivalent("else-if", ORIG_ELSE_IF_CHAIN, &recovered);
}

fn jsx_reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.jsx").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

const JSX_AUTO_SIMPLE: &str = "var a = _jsx(\"div\", { children: \"hello\" });\n";

#[test]
fn automatic_runtime_element_with_text_child() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_SIMPLE);
    assert!(
        stats.jsx_automatic_elements_restored >= 1,
        "_jsx must restore; got {}",
        stats.jsx_automatic_elements_restored
    );
    assert!(
        out.contains("<div>hello</div>"),
        "expected `<div>hello</div>`:\n{out}"
    );
    assert!(!out.contains("_jsx("), "the _jsx call must be gone:\n{out}");
    assert!(jsx_reparses(&out), "output must be valid JSX:\n{out}");
}

const JSX_AUTO_PROPS: &str =
    "var a = _jsx(\"a\", { href: \"/x\", id: \"link\", children: \"go\" });\n";

#[test]
fn automatic_runtime_props_and_children() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_PROPS);
    assert!(stats.jsx_automatic_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<a href=\"/x\" id=\"link\">go</a>"),
        "expected attributes and child:\n{out}"
    );
    assert!(jsx_reparses(&out), "output must be valid JSX:\n{out}");
}

const JSX_AUTO_JSXS_ARRAY: &str = "var a = _jsxs(\"ul\", { children: [_jsx(\"li\", { children: \"one\" }), _jsx(\"li\", { children: \"two\" })] });\n";

#[test]
fn automatic_runtime_jsxs_array_children() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_JSXS_ARRAY);
    assert!(
        stats.jsx_automatic_elements_restored >= 3,
        "ul + 2 li must restore; got {}",
        stats.jsx_automatic_elements_restored
    );
    assert!(
        out.contains("<ul><li>one</li><li>two</li></ul>"),
        "expected nested jsx:\n{out}"
    );
    assert!(jsx_reparses(&out), "output must be valid JSX:\n{out}");
}

const JSX_AUTO_COMPONENT: &str =
    "var a = _jsx(Button, { kind: \"primary\", children: \"Save\" });\n";

#[test]
fn automatic_runtime_component_tag() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_COMPONENT);
    assert!(stats.jsx_automatic_elements_restored >= 1, "must restore");
    assert!(
        out.contains("<Button kind=\"primary\">Save</Button>"),
        "expected component element:\n{out}"
    );
}

const JSX_AUTO_FRAGMENT: &str =
    "var a = _jsx(_Fragment, { children: _jsx(\"p\", { children: \"x\" }) });\n";

#[test]
fn automatic_runtime_fragment() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_FRAGMENT);
    assert!(
        stats.jsx_automatic_fragments_restored >= 1,
        "_Fragment must restore as <>; got {}",
        stats.jsx_automatic_fragments_restored
    );
    assert!(out.contains("<><p>x</p></>"), "expected fragment:\n{out}");
}

const JSX_AUTO_SELF_CLOSING: &str = "var a = _jsx(\"br\", {});\n";

#[test]
fn automatic_runtime_childless_self_closes() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(JSX_AUTO_SELF_CLOSING);
    assert!(stats.jsx_automatic_elements_restored >= 1, "must restore");
    assert!(out.contains("<br />"), "expected self-closing:\n{out}");
}

const NEG_JSX_DYNAMIC_PROPS: &str = "var a = _jsx(\"div\", props);\n";

#[test]
fn automatic_runtime_non_object_props_skipped() {
    let (out, stats): (String, AstUnminifyStats) = unminify_ast(NEG_JSX_DYNAMIC_PROPS);
    assert_eq!(
        stats.jsx_automatic_elements_restored, 0,
        "a non-object props bag is ambiguous and must be skipped"
    );
    assert!(out.contains("_jsx"), "the call must be preserved:\n{out}");
}
