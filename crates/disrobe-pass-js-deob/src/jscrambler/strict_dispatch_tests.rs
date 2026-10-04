use boa_engine::{Context, Source};

use super::detect::JscramblerTransform;
use super::dispatch_reverse_strict;
use super::transforms::{TransformOpts, TransformOutput};
use crate::error::{Error, Result};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = crate::sandbox_guard::bounded_boa_context().ok()?;
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

fn assert_faithful_input(label: &str, original: &str, obfuscated: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let have: String = eval_capture(obfuscated)
        .unwrap_or_else(|| panic!("{label}: obfuscated shape must evaluate"));
    assert_eq!(
        want, have,
        "{label}: hand-built obfuscation shape is not behaviorally identical to the clean source BEFORE reversal"
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

fn reverse(transform: JscramblerTransform, source: &str) -> TransformOutput {
    let opts: TransformOpts = TransformOpts::default();
    dispatch_reverse_strict(transform, source, &opts).expect("strict reverse ok")
}

const FN_REORDER_CLEAN: &str = r"
var log = [];
function area(w, h) { return w * h; }
function describe(w, h) { log.push('area=' + area(w, h)); }
describe(3, 4);
describe(5, 6);
print(log.join(','));
";

const FN_REORDER_OBF: &str = r"
var log = [];
function describe(w, h) { log.push('area=' + area(w, h)); }
function area(w, h) { return w * h; }
describe(3, 4);
describe(5, 6);
print(log.join(','));
";

#[test]
fn function_reordering_restores_dependency_order_and_behavior() {
    assert_faithful_input("function-reordering", FN_REORDER_CLEAN, FN_REORDER_OBF);
    let out: TransformOutput = reverse(JscramblerTransform::FunctionReordering, FN_REORDER_OBF);
    assert!(
        out.stats.reversed >= 1,
        "the reordered declarations must be detected and restored; stats={:?}",
        out.stats
    );
    let area_pos: usize = out
        .source
        .find("function area(")
        .expect("area decl present");
    let describe_pos: usize = out
        .source
        .find("function describe(")
        .expect("describe decl present");
    assert!(
        area_pos < describe_pos,
        "callee `area` must be restored before its caller `describe`:\n{}",
        out.source
    );
    assert_recovered_equivalent("function-reordering", FN_REORDER_CLEAN, &out.source);
}

const FN_OUTLINE_CLEAN: &str = r"
function run() {
  var total = (10 + 20 + 12);
  print(total);
}
run();
";

const FN_OUTLINE_OBF: &str = r"
function _outlined_0() { return 10 + 20 + 12; }
function run() {
  var total = _outlined_0();
  print(total);
}
run();
";

#[test]
fn function_outlining_inlines_single_use_helper_and_behavior() {
    assert_faithful_input("function-outlining", FN_OUTLINE_CLEAN, FN_OUTLINE_OBF);
    let out: TransformOutput = reverse(JscramblerTransform::FunctionOutlining, FN_OUTLINE_OBF);
    assert!(
        out.stats.reversed >= 1,
        "the single-use outlined helper must be inlined; stats={:?}",
        out.stats
    );
    assert!(
        !out.source.contains("_outlined_0"),
        "the outlined helper and its call must be gone:\n{}",
        out.source
    );
    assert!(
        out.source.contains("10 + 20 + 12"),
        "the helper body must be inlined at the call site:\n{}",
        out.source
    );
    assert_recovered_equivalent("function-outlining", FN_OUTLINE_CLEAN, &out.source);
}

const FN_OUTLINE_NEG_CLEAN: &str = r"
function helper() { return 9; }
function consume(fn) { return fn() + fn(); }
print(consume(helper));
";

#[test]
fn function_outlining_preserves_non_eager_reference() {
    let out: TransformOutput =
        reverse(JscramblerTransform::FunctionOutlining, FN_OUTLINE_NEG_CLEAN);
    assert_eq!(
        out.stats.reversed, 0,
        "a helper passed as a value (non-eager reference) must NOT be inlined:\n{}",
        out.source
    );
    assert!(
        out.source.contains("function helper()"),
        "the helper declaration must survive:\n{}",
        out.source
    );
    let want: String = eval_capture(FN_OUTLINE_NEG_CLEAN).expect("evaluates");
    let got: String = eval_capture(&out.source).expect("recovered evaluates");
    assert_eq!(want, got, "behavior preserved when nothing is inlined");
}

const SPARSE_CLEAN: &str = r"
function build() {
  var cfg = { host: 'local', port: 8080, secure: false };
  return cfg.host + ':' + cfg.port + ':' + cfg.secure;
}
print(build());
";

const SPARSE_OBF: &str = r"
function build() {
  var cfg = {};
  cfg.host = 'local';
  cfg.port = 8080;
  cfg.secure = false;
  return cfg.host + ':' + cfg.port + ':' + cfg.secure;
}
print(build());
";

#[test]
fn object_properties_sparsing_gathers_props_and_behavior() {
    assert_faithful_input("object-sparsing", SPARSE_CLEAN, SPARSE_OBF);
    let out: TransformOutput = reverse(JscramblerTransform::ObjectPropertiesSparsing, SPARSE_OBF);
    assert!(
        out.stats.reversed >= 1,
        "the sparse assignments must be gathered into the literal; stats={:?}",
        out.stats
    );
    assert!(
        out.source.contains("host: 'local'") || out.source.contains("host: \"local\""),
        "the host property must move into the object literal:\n{}",
        out.source
    );
    assert!(
        out.source.contains("port: 8080") && out.source.contains("secure: false"),
        "all sparse properties must move into the literal:\n{}",
        out.source
    );
    assert!(
        !out.source.contains("cfg.host = "),
        "the standalone property assignments must be gone:\n{}",
        out.source
    );
    assert_recovered_equivalent("object-sparsing", SPARSE_CLEAN, &out.source);
}

const SPARSE_NEG: &str = r"
function build() {
  var acc = {};
  acc.a = 1;
  acc.b = acc.a + 1;
  return acc.a + acc.b;
}
print(build());
";

#[test]
fn object_properties_sparsing_stops_on_self_dependent_value() {
    let out: TransformOutput = reverse(JscramblerTransform::ObjectPropertiesSparsing, SPARSE_NEG);
    assert!(
        out.source.contains("acc.b = acc.a"),
        "an assignment whose value reads the object being built must not be folded:\n{}",
        out.source
    );
    let want: String = eval_capture(SPARSE_NEG).expect("evaluates");
    let got: String = eval_capture(&out.source).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "folding a self-dependent property would change behavior; must be preserved"
    );
}

const PROP_REORDER_CLEAN: &str = r"
function make() {
  return { alpha: 1, beta: 2, gamma: 3 };
}
var o = make();
print(o.alpha + ',' + o.beta + ',' + o.gamma);
";

const PROP_REORDER_OBF: &str = r"
function make() {
  return { gamma: 3, alpha: 1, beta: 2 };
}
var o = make();
print(o.alpha + ',' + o.beta + ',' + o.gamma);
";

#[test]
fn property_keys_reordering_canonicalizes_keys_and_behavior() {
    assert_faithful_input("property-keys", PROP_REORDER_CLEAN, PROP_REORDER_OBF);
    let out: TransformOutput = reverse(
        JscramblerTransform::PropertyKeysReordering,
        PROP_REORDER_OBF,
    );
    assert!(
        out.stats.reversed >= 1,
        "the reordered keys must be canonicalized; stats={:?}",
        out.stats
    );
    let alpha_pos: usize = out.source.find("alpha:").expect("alpha key present");
    let beta_pos: usize = out.source.find("beta:").expect("beta key present");
    let gamma_pos: usize = out.source.find("gamma:").expect("gamma key present");
    assert!(
        alpha_pos < beta_pos && beta_pos < gamma_pos,
        "keys must be restored to their alphabetical (clean-source) order:\n{}",
        out.source
    );
    assert_recovered_equivalent("property-keys", PROP_REORDER_CLEAN, &out.source);
}

#[test]
fn property_keys_reordering_is_behavior_preserving_on_side_effect_values() {
    let with_calls: &str = r"
var seq = [];
function tag(name, value) { seq.push(name); return value; }
var o = { b: tag('b', 2), a: tag('a', 1) };
print(o.a + ',' + o.b + '|' + seq.join(','));
";
    let out: TransformOutput = reverse(JscramblerTransform::PropertyKeysReordering, with_calls);
    assert_eq!(
        out.stats.reversed, 0,
        "object values with observable evaluation-order side effects must NOT be reordered:\n{}",
        out.source
    );
    let want: String = eval_capture(with_calls).expect("evaluates");
    let got: String = eval_capture(&out.source).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "reordering side-effecting values would change evaluation order; must be preserved"
    );
}

#[test]
fn strict_reverse_surfaces_parse_failure_not_a_panic() {
    let opts: TransformOpts = TransformOpts::default();
    let broken: &str = "function (";
    for transform in [
        JscramblerTransform::FunctionReordering,
        JscramblerTransform::FunctionOutlining,
        JscramblerTransform::ObjectPropertiesSparsing,
        JscramblerTransform::PropertyKeysReordering,
    ] {
        let res: Result<TransformOutput> = dispatch_reverse_strict(transform, broken, &opts);
        assert!(
            res.is_err(),
            "unparseable input must return a typed error, not a fabricated pass, for {transform:?}"
        );
    }
}

const AUTHORIZATION_GATED: &[(JscramblerTransform, &str)] = &[
    (
        JscramblerTransform::AntiDebugging,
        "function f(){ debugger; }",
    ),
    (JscramblerTransform::AntiMonkeyPatching, "var x = 1;"),
    (
        JscramblerTransform::AntiTampering,
        "var n = fn.toString().replace(/ /g,'').length;",
    ),
    (
        JscramblerTransform::DeadObjects,
        "var __deadFoo = { a: 1 };",
    ),
    (
        JscramblerTransform::SelfDefending,
        "(function(){var t = function(){return ('xy').toString().search('z');}; t();}());",
    ),
    (
        JscramblerTransform::SelfHealing,
        "window.onerror = function(e){ tamper(); };",
    ),
    (
        JscramblerTransform::BrowserLock,
        "if (navigator.userAgent.indexOf('Chrome') !== -1) { run(); }",
    ),
    (
        JscramblerTransform::DateLock,
        "if (Date.now() > 1) { stop(); }",
    ),
    (
        JscramblerTransform::DomainLock,
        "if (location.hostname !== 'x') { y(); }",
    ),
    (
        JscramblerTransform::OsLock,
        "if (navigator.platform !== 'Win32') { stop(); }",
    ),
];

#[test]
fn strict_dispatch_refuses_every_rasp_and_lock_transform_without_authorization() {
    for (transform, source) in AUTHORIZATION_GATED {
        let err: Error = dispatch_reverse_strict(*transform, source, &TransformOpts::default())
            .expect_err("an unauthorized RASP or lock reversal must refuse");
        assert!(
            matches!(err, Error::AuthorizationRequired { .. }),
            "{transform:?} must gate on authorization, got {err}"
        );
    }
}

#[test]
fn strict_dispatch_runs_every_rasp_and_lock_transform_with_authorization() {
    let opts: TransformOpts = TransformOpts {
        i_have_authorization: true,
    };
    for (transform, _) in AUTHORIZATION_GATED {
        let res: Result<TransformOutput> = dispatch_reverse_strict(*transform, "var x = 1;", &opts);
        assert!(res.is_ok(), "{transform:?} must succeed when authorized");
    }
}

#[test]
fn strict_dispatch_does_not_gate_optimization_transforms() {
    for transform in [
        JscramblerTransform::AssertionsRemoval,
        JscramblerTransform::ConstantFolding,
        JscramblerTransform::DeadCodeElimination,
        JscramblerTransform::DebugCodeElimination,
        JscramblerTransform::DuplicateLiteralsRemoval,
        JscramblerTransform::IdentifiersRenaming,
        JscramblerTransform::WhitespaceRemoval,
    ] {
        let res: Result<TransformOutput> =
            dispatch_reverse_strict(transform, "var x = 1;", &TransformOpts::default());
        assert!(res.is_ok(), "{transform:?} must not gate on authorization");
    }
}
