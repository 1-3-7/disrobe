#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstRuleId, AstUnminifyStats, unminify_ast};

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

fn assert_faithful_input(label: &str, original: &str, input: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String =
        eval_capture(input).unwrap_or_else(|| panic!("{label}: input must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-written input is not behaviorally identical to the original BEFORE transform"
    );
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

const ORIG: &str = r"
var log = [];
function a() { log.push('a'); }
function b() { log.push('b'); }
var x = 1;
var y = 2;
a();
b();
print(x + y);
print(log.join(','));
";

const INPUT: &str = r"
var log = [];
(function () {
  function a() { log.push('a'); }
  function b() { log.push('b'); }
  var x = 1;
  var y = 2;
  a();
  b();
  print(x + y);
})();
print(log.join(','));
";

#[test]
fn module_iife_unwrap_reeval_equivalent() {
    assert_faithful_input("iife", ORIG, INPUT);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT);
    assert!(
        stats.iifes_unwrapped >= 1,
        "the module IIFE must unwrap; got {}",
        stats.iifes_unwrapped
    );
    assert!(
        !recovered.contains("(function ()"),
        "the IIFE wrapper must be gone:\n{recovered}"
    );
    assert!(
        recovered.contains("x = 1;") && recovered.contains("y = 2;"),
        "the hoisted body statements must appear at top level:\n{recovered}"
    );
    assert_recovered_equivalent("iife", ORIG, &recovered);
}

const INPUT_BANG: &str = r"
var log = [];
!function () {
  log.push('z');
  print('inside');
}();
print(log.join(','));
";

const ORIG_BANG: &str = r"
var log = [];
log.push('z');
print('inside');
print(log.join(','));
";

#[test]
fn bang_prefixed_iife_unwraps() {
    assert_faithful_input("bang", ORIG_BANG, INPUT_BANG);
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(INPUT_BANG);
    assert!(
        stats.iifes_unwrapped >= 1,
        "the !-prefixed IIFE must unwrap"
    );
    assert!(
        !recovered.contains("!function"),
        "the bang wrapper must be gone:\n{recovered}"
    );
    assert_recovered_equivalent("bang", ORIG_BANG, &recovered);
}

const NEG_RETURN: &str = r"
var v = (function () {
  return 7;
})();
print(v);
";

#[test]
fn negative_iife_with_return_value_used_is_unchanged() {
    let want: String = eval_capture(NEG_RETURN).expect("evaluates");
    let pipeline: AstPipeline = AstPipeline::default();
    let (recovered, stats): (String, AstUnminifyStats) = pipeline.run(NEG_RETURN);
    assert_eq!(
        stats.iifes_unwrapped, 0,
        "an IIFE whose return value is used must NOT be unwrapped"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_RETURN_STMT: &str = r"
var log = [];
(function () {
  log.push('a');
  if (log.length > 5) return;
  log.push('b');
})();
print(log.join(','));
";

#[test]
fn negative_iife_with_internal_return_is_unchanged() {
    let want: String = eval_capture(NEG_RETURN_STMT).expect("evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = AstPipeline::default()
        .with_rule(AstRuleId::SequenceSplit, false)
        .run(NEG_RETURN_STMT);
    assert_eq!(
        stats.iifes_unwrapped, 0,
        "an IIFE whose body has a top-level return must NOT be unwrapped (return is illegal at module scope)"
    );
    let got: String = eval_capture(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved");
}

const NEG_THIS: &str = r"
var obj = { tag: 'T', run: function () {
  (function () {
    print(this === undefined ? 'global' : 'bound');
  })();
} };
obj.run();
";

#[test]
fn negative_iife_using_this_is_unchanged() {
    let pipeline: AstPipeline = AstPipeline::default();
    let (_, stats): (String, AstUnminifyStats) = pipeline.run(NEG_THIS);
    assert_eq!(
        stats.iifes_unwrapped, 0,
        "an IIFE whose body uses `this` must NOT be unwrapped (this rebinds when hoisted)"
    );
}

const NEG_ARGS: &str = r"
function outer() {
  (function () {
    print(arguments.length);
  })();
}
outer(1, 2, 3);
";

#[test]
fn negative_iife_using_arguments_is_unchanged() {
    let pipeline: AstPipeline = AstPipeline::default();
    let (_, stats): (String, AstUnminifyStats) = pipeline.run(NEG_ARGS);
    assert_eq!(
        stats.iifes_unwrapped, 0,
        "an IIFE referencing `arguments` must NOT be unwrapped"
    );
}

const NEG_PARAM: &str = r"
var log = [];
(function (g) {
  g.push('p');
})(log);
print(log.join(','));
";

#[test]
fn negative_iife_with_args_is_unchanged() {
    let pipeline: AstPipeline = AstPipeline::default();
    let (_, stats): (String, AstUnminifyStats) = pipeline.run(NEG_PARAM);
    assert_eq!(
        stats.iifes_unwrapped, 0,
        "an IIFE that receives arguments must NOT be unwrapped (params would dangle)"
    );
}
