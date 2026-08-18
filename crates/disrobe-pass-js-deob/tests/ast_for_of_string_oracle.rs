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
    let want: String = eval_capture(original).expect("original evaluates");
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered diverged\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const ASTRAL_LITERAL_SUBJECT: &str = r#"
var out = [];
for (var _i = 0, _s = "a\u{1F600}b"; _i < _s.length; _i++) {
  var ch = _s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
"#;

const ASTRAL_BINDING_SUBJECT: &str = r#"
var s = "a\u{1F600}b";
var out = [];
for (var _i = 0; _i < s.length; _i++) {
  var ch = s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
"#;

const ASTRAL_TEMPLATE_SUBJECT: &str = r"
var s = `a\u{1F600}b`;
var out = [];
for (var _i = 0; _i < s.length; _i++) {
  var ch = s[_i];
  out.push(ch.codePointAt(0).toString(16));
}
print(out.length + ':' + out.join(','));
";

const BMP_LITERAL_SUBJECT: &str = r#"
var out = [];
for (var _i = 0, _s = "abc"; _i < _s.length; _i++) {
  var ch = _s[_i];
  out.push(ch);
}
print(out.join(','));
"#;

const ARRAY_SUBJECT: &str = r"
var items = ['a', 'b', 'c'];
var out = [];
for (var _i = 0; _i < items.length; _i++) {
  var item = items[_i];
  out.push(item.toUpperCase());
}
print(out.join(','));
";

fn assert_astral_string_subject_is_not_resugared(label: &str, original: &str) {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(original);
    assert_recovered_equivalent(label, original, &recovered);
    assert_eq!(
        stats.index_loops_to_for_of, 0,
        "{label}: an index loop over a string that holds an astral code point must not become for...of, because the loop walks utf-16 code units and for...of walks code points:\n{recovered}"
    );
}

#[test]
fn an_index_loop_over_an_astral_string_literal_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared("astral literal subject", ASTRAL_LITERAL_SUBJECT);
}

#[test]
fn an_index_loop_over_an_astral_string_binding_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared("astral binding subject", ASTRAL_BINDING_SUBJECT);
}

#[test]
fn an_index_loop_over_an_astral_template_literal_is_not_resugared() {
    assert_astral_string_subject_is_not_resugared(
        "astral template subject",
        ASTRAL_TEMPLATE_SUBJECT,
    );
}

#[test]
fn an_index_loop_over_a_basic_plane_string_literal_keeps_its_behaviour() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(BMP_LITERAL_SUBJECT);
    assert_recovered_equivalent(
        "basic plane literal subject",
        BMP_LITERAL_SUBJECT,
        &recovered,
    );
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "a string literal with no astral code point iterates identically both ways, so refusing it would cost recovery for no correctness gain:
{recovered}"
    );
}

#[test]
fn an_index_loop_over_an_array_still_becomes_for_of() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ARRAY_SUBJECT);
    assert_eq!(
        stats.index_loops_to_for_of, 1,
        "an array subject must still be recovered:\n{recovered}"
    );
    assert!(
        recovered.contains(" of items)"),
        "the for...of head must reference the original iterable:\n{recovered}"
    );
    assert_recovered_equivalent("array subject", ARRAY_SUBJECT, &recovered);
}
