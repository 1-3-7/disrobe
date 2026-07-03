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

const IF_TRUE: &str = r"
function pick() {
  if (true) { return 'live'; } else { return 'dead'; }
}
print(pick());
";

#[test]
fn constant_true_if_inlines_consequent() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(IF_TRUE);
    assert!(
        stats.constant_if_folds >= 1,
        "if (true) must fold; got {}",
        stats.constant_if_folds
    );
    assert!(
        !recovered.contains("dead"),
        "the false branch must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("if_true", IF_TRUE, &recovered);
}

const IF_FALSE: &str = r"
function pick() {
  if (false) { return 'dead'; } else { return 'live'; }
}
print(pick());
";

#[test]
fn constant_false_if_inlines_alternate() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(IF_FALSE);
    assert!(
        stats.constant_if_folds >= 1,
        "if (false) must fold; got {}",
        stats.constant_if_folds
    );
    assert!(
        !recovered.contains("'dead'"),
        "the dead branch must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("if_false", IF_FALSE, &recovered);
}

const IF_FALSE_NO_ELSE: &str = r"
var log = [];
function run() {
  if (false) { log.push('dead'); }
  log.push('live');
}
run();
print(log.join(','));
";

#[test]
fn constant_false_if_without_else_drops_block() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(IF_FALSE_NO_ELSE);
    assert!(
        stats.constant_if_folds >= 1,
        "if (false) with no else must fold; got {}",
        stats.constant_if_folds
    );
    assert!(
        !recovered.contains("'dead'"),
        "the dead branch must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("if_false_no_else", IF_FALSE_NO_ELSE, &recovered);
}

const UNREACHABLE: &str = r"
function f() {
  return 1;
  print('never');
  print('also never');
}
print(f());
";

#[test]
fn statements_after_return_are_dropped() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(UNREACHABLE);
    assert!(
        stats.unreachable_statement_drops >= 1,
        "code after return must drop; got {}",
        stats.unreachable_statement_drops
    );
    assert!(
        !recovered.contains("never"),
        "unreachable statements must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("unreachable", UNREACHABLE, &recovered);
}

const NEG_UNREACHABLE_HOIST: &str = r"
function f() {
  return g();
  function g() { return 7; }
}
print(f());
";

#[test]
fn hoisted_function_after_return_is_preserved() {
    let want: String = eval_capture(NEG_UNREACHABLE_HOIST).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_UNREACHABLE_HOIST);
    assert_eq!(
        stats.unreachable_statement_drops, 0,
        "a hoisted function declaration after return is reachable and must NOT drop"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_VARIABLE_COND: &str = r"
var flag = true;
function pick() {
  if (flag) { return 'a'; }
  return 'b';
}
print(pick());
";

#[test]
fn non_literal_condition_is_not_folded() {
    let want: String = eval_capture(NEG_VARIABLE_COND).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_VARIABLE_COND);
    assert_eq!(
        stats.constant_if_folds, 0,
        "a runtime condition must NOT be folded"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const IMPORT_DUP: &str =
    "import { a } from \"mod\";\nimport { b } from \"mod\";\nimport { c } from \"mod\";\n";

#[test]
fn duplicate_named_imports_from_same_module_merge() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(IMPORT_DUP);
    assert!(
        stats.import_merges >= 1,
        "three imports from the same module must merge; got {}",
        stats.import_merges
    );
    assert!(
        recovered.contains("import { a, b, c } from \"mod\";"),
        "must produce a single merged import:\n{recovered}"
    );
    assert_eq!(
        recovered.matches("from \"mod\"").count(),
        1,
        "only one import statement from `mod` may remain:\n{recovered}"
    );
}

const NEG_IMPORT_MIXED: &str = "import def, { a } from \"mod\";\nimport { b } from \"mod\";\n";

#[test]
fn default_plus_named_import_is_not_merged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_IMPORT_MIXED);
    assert_eq!(
        stats.import_merges, 0,
        "a default+named import is not the conservative named-only shape and must NOT merge"
    );
    assert!(
        recovered.contains("import def, { a } from \"mod\";"),
        "the mixed import must be preserved verbatim:\n{recovered}"
    );
}

const NEG_IMPORT_DIFF_SOURCE: &str = "import { a } from \"x\";\nimport { b } from \"y\";\n";

#[test]
fn imports_from_different_modules_are_not_merged() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_IMPORT_DIFF_SOURCE);
    assert_eq!(
        stats.import_merges, 0,
        "different module specifiers must NOT merge"
    );
    assert!(recovered.contains("from \"x\""), "x import preserved");
    assert!(recovered.contains("from \"y\""), "y import preserved");
}
