#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration;

use boa_engine::{Context, Source};
use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_js_deob::{
    Error, TerserRestoreReport, restore_terser_mangled as restore_terser_mangled_result,
};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 1usize << 18;

fn restore_terser_mangled(source: &str) -> TerserRestoreReport {
    restore_terser_mangled_result(source).expect("caller fixture must be within the source limit")
}

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

fn node_capture(program: &str) -> String {
    let harness: String = format!(
        "var __out=[];var print=function(v){{__out.push(String(v));}};{program};process.stdout.write(__out.join('\\u0001'));"
    );
    let args: [&OsStr; 2] = [OsStr::new("-e"), OsStr::new(&harness)];
    let output: CapturedOutput = run_captured(Path::new("node"), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("node is required for the name-inference semantic reference")
        .expect("name-inference semantic reference must finish within the timeout");
    assert_eq!(
        output.exit_code,
        Some(0),
        "node must execute source\nstderr: {}\nsource:\n{program}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)
        .expect("Node output is utf-8")
        .trim()
        .to_owned()
}

fn reparses(source: &str) -> bool {
    use oxc_allocator::Allocator;
    use oxc_parser::Parser;
    use oxc_span::SourceType;
    let allocator: Allocator = Allocator::default();
    let source_type: SourceType = SourceType::from_path("check.js").unwrap_or_default();
    let parsed: oxc_parser::ParserReturn<'_> = Parser::new(&allocator, source, source_type).parse();
    parsed.errors.is_empty() && !parsed.panicked
}

fn assert_behavior_preserved(label: &str, original: &str, recovered: &str) {
    assert!(
        reparses(recovered),
        "{label}: recovered must re-parse:\n{recovered}"
    );
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered must evaluate:\n{recovered}"));
    assert_eq!(want, got, "{label}: behavior diverged\n{recovered}");
}

const DOM_TARGET: &str = r#"
function bind(a) {
  a.addEventListener("click", function () {});
  a.removeEventListener("scroll", function () {});
  return typeof a.addEventListener;
}
print(bind({ addEventListener: function () {}, removeEventListener: function () {} }));
"#;

#[test]
fn a_param_that_calls_addeventlistener_is_named_from_usage() {
    let r: TerserRestoreReport = restore_terser_mangled(DOM_TARGET);
    assert!(
        r.rewritten.contains("target.addEventListener"),
        "the DOM-target usage context must rename `a`->`target`, not a corpus default:\n{}",
        r.rewritten
    );
    assert!(
        !r.rewritten.contains("(a)") && !r.rewritten.contains(" a.addEventListener"),
        "the minified `a` binding must be gone:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("dom-target", DOM_TARGET, &r.rewritten);
}

const PROMISE_LIKE: &str = r"
function chain(p) {
  return p.then(function (v) { return v; }).catch(function () { return 0; });
}
var fake = { then: function (cb) { cb(1); return { catch: function () { return 7; } }; } };
print(chain(fake));
";

#[test]
fn a_param_with_user_defined_chain_members_is_not_named_promise() {
    let r: TerserRestoreReport = restore_terser_mangled(PROMISE_LIKE);
    assert!(
        !has_heuristic_role(&r, "promise"),
        "user-defined `.then` and `.catch` members do not prove a native promise:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("promise", PROMISE_LIKE, &r.rewritten);
}

const ARRAY_LIKE: &str = r"
function fill(l) {
  l.push(1);
  l.push(2);
  return l.length;
}
print(fill([]));
";

#[test]
fn a_param_that_calls_push_is_named_list() {
    let r: TerserRestoreReport = restore_terser_mangled(ARRAY_LIKE);
    assert!(
        r.rewritten.contains("list.push"),
        "the `.push`/`.length` usage must rename `l`->`list`:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("array", ARRAY_LIKE, &r.rewritten);
}

const ASSIGNED_FROM_NEW: &str = r#"
function make() {
  var s = new Map();
  s.set("x", 1);
  return s.get("x");
}
print(make());
"#;

#[test]
fn a_local_assigned_from_new_map_keeps_behavior_and_renames() {
    let r: TerserRestoreReport = restore_terser_mangled(ASSIGNED_FROM_NEW);
    assert!(
        r.identifiers_renamed >= 1,
        "the short local `s` must be picked up:\n{}",
        r.rewritten
    );
    assert_behavior_preserved("assigned-new", ASSIGNED_FROM_NEW, &r.rewritten);
}

const NO_USAGE_SIGNAL: &str = r"
function calc(a, b) {
  var c = a + b;
  return c * 2;
}
print(calc(3, 4));
";

#[test]
fn pure_arithmetic_locals_still_recover_and_preserve_behavior() {
    let r: TerserRestoreReport = restore_terser_mangled(NO_USAGE_SIGNAL);
    assert!(r.identifiers_renamed >= 1, "{}", r.rewritten);
    assert_behavior_preserved("arith", NO_USAGE_SIGNAL, &r.rewritten);
}

const OBJECT_KEYS_CONCAT: &str = r#"
function f() {
  var a = Object.keys({ left: 1 }).concat(Object.keys({ right: 2 }));
  print(a.join(","));
}
f();
"#;

#[test]
fn object_keys_concat_names_the_result_and_preserves_boa_and_node_behavior() {
    let report: TerserRestoreReport = restore_terser_mangled(OBJECT_KEYS_CONCAT);
    assert!(
        report.rewritten.contains("var keys = Object.keys"),
        "the Object.keys result must retain its collection provenance:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("object-keys-concat", OBJECT_KEYS_CONCAT, &report.rewritten);
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(OBJECT_KEYS_CONCAT),
        "Object.keys result inference must preserve Node output"
    );
}

const INDEX_OF_RESULT: &str = r#"
function locate(values, needle) {
  var a = values.indexOf(needle);
  print(a);
  return a;
}
locate(["x", "y"], "y");
"#;

#[test]
fn index_of_names_its_result_role_and_preserves_boa_and_node_behavior() {
    let first: TerserRestoreReport = restore_terser_mangled(INDEX_OF_RESULT);
    let second: TerserRestoreReport = restore_terser_mangled(INDEX_OF_RESULT);
    assert!(
        first
            .rewritten
            .contains("var position = values.indexOf(needle)"),
        "the generic indexOf result role must be named at low confidence:\n{}",
        first.rewritten
    );
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved("index-of-result", INDEX_OF_RESULT, &first.rewritten);
    assert_eq!(
        node_capture(&first.rewritten),
        node_capture(INDEX_OF_RESULT)
    );
}

const INDEX_OF_CAPTURE: &str = r#"
var position = 7;
function locate(values, needle) {
  var a = values.indexOf(needle);
  print(position + a);
  return a;
}
locate(["x", "y"], "y");
"#;

#[test]
fn index_of_result_role_does_not_shadow_an_outer_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(INDEX_OF_CAPTURE);
    assert!(
        report
            .rewritten
            .contains("var position_2 = values.indexOf(needle)"),
        "the semantic role must be suffixed rather than capture the outer position:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("index-of-capture", INDEX_OF_CAPTURE, &report.rewritten);
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(INDEX_OF_CAPTURE)
    );
}

const INDEX_OF_DIRECT_EVAL: &str =
    "function locate(values,needle){var a=values.indexOf(needle);return eval(\"a\");}";
const INDEX_OF_WITH: &str =
    "function locate(values,needle){with({needle:0}){var a=values.indexOf(needle);return a;}}";
const SLICE_DIRECT_EVAL: &str =
    "function copy(a){var b=a.slice(1);return eval(\"a.length+b.length\");}";
const SLICE_WITH: &str = "function copy(a){with({a:[9]}){return a.slice(1);}}";
const QUERY_DIRECT_EVAL: &str =
    "function build(){var a=[];a.push('x=1');return eval(\"a.join('&')\");}";
const QUERY_WITH: &str =
    "function build(){var a=[];a.push('x=1');with({a:['y=2']}){return a.join('&');}}";
const LISTENERS_DIRECT_EVAL: &str = "function fire(){var a=[];function f(){}a.push(f);a[0]();var p=a.indexOf(f);a.splice(p,1);return eval(\"a.length\");}";
const LISTENERS_WITH: &str = "function fire(){var a=[];function f(){}a.push(f);a[0]();var p=a.indexOf(f);a.splice(p,1);with({a:[f]}){return a.length;}}";

#[test]
fn dynamic_name_scopes_refuse_semantic_role_inference() {
    for source in [
        INDEX_OF_DIRECT_EVAL,
        INDEX_OF_WITH,
        SLICE_DIRECT_EVAL,
        SLICE_WITH,
        QUERY_DIRECT_EVAL,
        QUERY_WITH,
        LISTENERS_DIRECT_EVAL,
        LISTENERS_WITH,
    ] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert_eq!(report.rewritten, source);
        assert!(report.renames.is_empty());
    }
}

const SLICE_SOURCE: &str = r#"
function copy(a) {
  var output = a.slice(1);
  print(output.join(","));
  return output;
}
copy([0, 1, 2]);
"#;

#[test]
fn slice_names_its_receiver_role_and_preserves_boa_and_node_behavior() {
    let first: TerserRestoreReport = restore_terser_mangled(SLICE_SOURCE);
    let second: TerserRestoreReport = restore_terser_mangled(SLICE_SOURCE);
    assert!(
        first.rewritten.contains("function copy(source)"),
        "the generic slice receiver role must be named at low confidence:\n{}",
        first.rewritten
    );
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved("slice-source", SLICE_SOURCE, &first.rewritten);
    assert_eq!(node_capture(&first.rewritten), node_capture(SLICE_SOURCE));
}

const SLICE_CAPTURE: &str = r#"
var source = [9];
function copy(a) {
  print(source.length);
  return a.slice(1);
}
print(copy([0, 1, 2]).join(","));
"#;

#[test]
fn slice_receiver_role_does_not_shadow_an_outer_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(SLICE_CAPTURE);
    assert!(
        report.rewritten.contains("function copy(source_2)"),
        "the semantic role must be suffixed rather than shadow the outer source:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("slice-capture", SLICE_CAPTURE, &report.rewritten);
    assert_eq!(node_capture(&report.rewritten), node_capture(SLICE_CAPTURE));
}

const QUERY_COMPONENTS: &str = r#"
function build() {
  var a = [];
  a.push("left=1");
  a.push("right=2");
  print(a.join("&"));
  return a;
}
build();
"#;

#[test]
fn ampersand_joined_components_receive_the_query_role_deterministically() {
    let first: TerserRestoreReport = restore_terser_mangled(QUERY_COMPONENTS);
    let second: TerserRestoreReport = restore_terser_mangled(QUERY_COMPONENTS);
    assert!(
        first.rewritten.contains("var query = []"),
        "the combined push/join/ampersand evidence must name query components:\n{}",
        first.rewritten
    );
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved("query-components", QUERY_COMPONENTS, &first.rewritten);
    assert_eq!(
        node_capture(&first.rewritten),
        node_capture(QUERY_COMPONENTS)
    );
}

const QUERY_CAPTURE: &str = r#"
var query = 7;
function build() {
  var a = [];
  a.push("left=1");
  print(a.join("&"));
  return query;
}
build();
"#;

#[test]
fn query_role_does_not_shadow_an_outer_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(QUERY_CAPTURE);
    assert!(
        report.rewritten.contains("var query_2 = []"),
        "the semantic role must be suffixed rather than shadow the outer query:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("query-capture", QUERY_CAPTURE, &report.rewritten);
    assert_eq!(node_capture(&report.rewritten), node_capture(QUERY_CAPTURE));
}

const COMMA_JOINED_COMPONENTS: &str =
    "function collect(a){a.push('x');print(a.join(','));}collect([]);";
const DYNAMIC_JOINED_COMPONENTS: &str =
    "function collect(a,d){a.push('x');print(a.join(d));}collect([],'&');";

#[test]
fn other_or_nonliteral_join_delimiters_remain_lists() {
    for source in [COMMA_JOINED_COMPONENTS, DYNAMIC_JOINED_COMPONENTS] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert!(
            report.rewritten.contains("function collect(list"),
            "only a direct ampersand literal may select the query role:\n{}",
            report.rewritten
        );
        assert!(!report.rewritten.contains("query"));
        assert_behavior_preserved("non-query-components", source, &report.rewritten);
        assert_eq!(node_capture(&report.rewritten), node_capture(source));
    }
}

const LISTENER_COLLECTION: &str = r#"
function cycle() {
  var a = [];
  function handler(value) { print(value); }
  a.push(handler);
  a[0]("ready");
  var p = a.indexOf(handler);
  if (p >= 0) a.splice(p, 1);
  print(a.length);
}
cycle();
"#;

#[test]
fn callable_identity_removed_elements_receive_the_listeners_role_deterministically() {
    let first: TerserRestoreReport = restore_terser_mangled(LISTENER_COLLECTION);
    let second: TerserRestoreReport = restore_terser_mangled(LISTENER_COLLECTION);
    assert!(
        first.rewritten.contains("var listeners = []"),
        "combined append, invocation, lookup, and removal evidence must name listeners:\n{}",
        first.rewritten
    );
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved("listener-collection", LISTENER_COLLECTION, &first.rewritten);
    assert_eq!(
        node_capture(&first.rewritten),
        node_capture(LISTENER_COLLECTION)
    );
}

const LISTENER_CAPTURE: &str = r#"
var listeners = 7;
function cycle() {
  var a = [];
  function handler(value) { print(value); }
  a.push(handler);
  a[0]("ready");
  var p = a.indexOf(handler);
  a.splice(p, 1);
  return listeners;
}
print(cycle());
"#;

#[test]
fn listeners_role_does_not_shadow_an_outer_binding() {
    let report: TerserRestoreReport = restore_terser_mangled(LISTENER_CAPTURE);
    assert!(
        report.rewritten.contains("var listeners_2 = []"),
        "the semantic role must be suffixed rather than shadow the outer listeners:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("listener-capture", LISTENER_CAPTURE, &report.rewritten);
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(LISTENER_CAPTURE)
    );
}

const MUTABLE_VALUES: &str =
    "function edit(a){a.push(3);var p=a.indexOf(2);a.splice(p,1);print(a.join(','));}edit([1,2]);";
const CALLED_VALUES: &str = "function run(a){a.push(function(){print('x');});a[0]();}run([]);";

#[test]
fn incomplete_listener_evidence_remains_a_list() {
    for source in [MUTABLE_VALUES, CALLED_VALUES] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert!(
            report.rewritten.contains("function edit(list")
                || report.rewritten.contains("function run(list"),
            "every listener signal is required before selecting the role:\n{}",
            report.rewritten
        );
        assert!(!report.rewritten.contains("listeners"));
        assert_behavior_preserved("non-listener-collection", source, &report.rewritten);
        assert_eq!(node_capture(&report.rewritten), node_capture(source));
    }
}

const CONDITIONAL_PREDICATE: &str = r#"
function partition(values, a) {
  var matched = [];
  var rejected = [];
  values.forEach(function (value, index) {
    a(value, index) ? matched.push(value) : rejected.push(value);
  });
  print(matched.join(",") + ":" + rejected.join(","));
}
partition([1, 2, 3], function (value) { return value > 1; });
"#;

#[test]
fn direct_conditional_test_calls_receive_the_predicate_role_deterministically() {
    let first: TerserRestoreReport = restore_terser_mangled(CONDITIONAL_PREDICATE);
    let second: TerserRestoreReport = restore_terser_mangled(CONDITIONAL_PREDICATE);
    assert!(
        first
            .rewritten
            .contains("function partition(values, predicate)"),
        "a scope-resolved call used directly as a conditional test must name its predicate role:\n{}",
        first.rewritten
    );
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved(
        "conditional-predicate",
        CONDITIONAL_PREDICATE,
        &first.rewritten,
    );
    assert_eq!(
        node_capture(&first.rewritten),
        node_capture(CONDITIONAL_PREDICATE)
    );
}

const IF_PREDICATE_COLLISION: &str = r#"
var predicate = "outer";
function accepts(a, value) {
  if (a(value)) {
    print(predicate + ":yes");
  }
}
accepts(function (value) { return value === 3; }, 3);
"#;

#[test]
fn if_test_predicate_roles_do_not_shadow_outer_bindings() {
    let report: TerserRestoreReport = restore_terser_mangled(IF_PREDICATE_COLLISION);
    assert!(
        report
            .rewritten
            .contains("function accepts(predicate_2, value)"),
        "the predicate role must be suffixed rather than shadow the outer binding:\n{}",
        report.rewritten
    );
    assert_behavior_preserved(
        "if-predicate-collision",
        IF_PREDICATE_COLLISION,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(IF_PREDICATE_COLLISION)
    );
}

const VALUE_CALL: &str = r"
function transform(a, value) {
  var b = a(value);
  print(b);
}
transform(function (value) { return value + 1; }, 2);
";

#[test]
fn calls_consumed_as_values_refuse_the_predicate_role() {
    let report: TerserRestoreReport = restore_terser_mangled(VALUE_CALL);
    assert!(
        !report.rewritten.contains("predicate"),
        "a call result used as a value does not prove a predicate role:\n{}",
        report.rewritten
    );
    assert_behavior_preserved("value-call", VALUE_CALL, &report.rewritten);
    assert_eq!(node_capture(&report.rewritten), node_capture(VALUE_CALL));
}

const HTTP_ROLE_FAMILY: &str = r#"
function m(a, b) {
  var c = {};
  function d(e, f) {
    var g = [];
    for (var h in f) {
      if (Object.prototype.hasOwnProperty.call(f, h)) {
        g.push(encodeURIComponent(h) + "=" + encodeURIComponent(f[h]));
      }
    }
    return a + "/" + e + (g.length ? "?" + g.join("&") : "");
  }
  function i(e, f) {
    var g = d(e, f);
    if (c[g]) return c[g];
    var h = b(g).then(function (j) {
      if (!j.ok) throw new Error("request failed");
      return j.json();
    }).catch(function (k) {
      delete c[g];
      throw k;
    });
    c[g] = h;
    return h;
  }
  return i;
}
var calls = 0;
var client = m("https://service.invalid", function (url) {
  calls += 1;
  return Promise.resolve({ ok: true, json: function () { return url; } });
});
var first = client("users", { page: 2 });
print(first instanceof Promise);
print(client("users", { page: 2 }) === first);
print(calls);
"#;

#[test]
fn correlated_http_and_promise_evidence_recovers_the_complete_defensible_role_family() {
    let first: TerserRestoreReport = restore_terser_mangled(HTTP_ROLE_FAMILY);
    let second: TerserRestoreReport = restore_terser_mangled(HTTP_ROLE_FAMILY);
    for expected in [
        "function map(args, transport)",
        "var cache = {}",
        "function data(event, params)",
        "for (var key in params)",
        "function index(event, params)",
        "var url = data(event, params)",
        "var promise = transport(url).then(function (response)",
        ").catch(function (error)",
    ] {
        assert!(
            first.rewritten.contains(expected),
            "missing `{expected}` from the correlated role family:\n{}",
            first.rewritten
        );
    }
    for ambiguous in ["baseUrl", "resource", "prefix", "removed", "buildUrl"] {
        assert!(
            !first.rewritten.contains(ambiguous),
            "the caller does not prove the more specific `{ambiguous}` spelling:\n{}",
            first.rewritten
        );
    }
    assert_eq!(first.rewritten, second.rewritten);
    assert_behavior_preserved("http-role-family", HTTP_ROLE_FAMILY, &first.rewritten);
    assert_eq!(
        node_capture(&first.rewritten),
        node_capture(HTTP_ROLE_FAMILY)
    );
}

const HTTP_ROLE_COLLISIONS: &str = r#"
var transport = 1, cache = 2, params = 3, key = 4, url = 5;
var promise = 6, response = 7, error = 8;
function m(a, b) {
  var c = {};
  function d(e, f) {
    var g = [];
    for (var h in f) {
      if (Object.prototype.hasOwnProperty.call(f, h)) {
        g.push(encodeURIComponent(h) + "=" + encodeURIComponent(f[h]));
      }
    }
    return a + "/" + e + (g.length ? "?" + g.join("&") : "");
  }
  function i(e, f) {
    var g = d(e, f);
    if (c[g]) return c[g];
    var h = b(g).then(function (j) { return j.ok ? j.json() : null; })
      .catch(function (k) { delete c[g]; throw k; });
    c[g] = h;
    return h;
  }
  print(transport + cache + params + key + url + promise + response + error);
  return i;
}
var client = m("base", function (requestUrl) {
  return Promise.resolve({ ok: true, json: function () { return requestUrl; } });
});
print(client("item", { q: 1 }) instanceof Promise);
"#;

#[test]
fn http_role_family_suffixes_every_outer_collision() {
    let report: TerserRestoreReport = restore_terser_mangled(HTTP_ROLE_COLLISIONS);
    let second: TerserRestoreReport = restore_terser_mangled(HTTP_ROLE_COLLISIONS);
    for expected in [
        "function map(args, transport_2)",
        "var cache_2 = {}",
        "function data(event, params_2)",
        "for (var key_2 in params_2)",
        "var url_2 = data(event, params_2)",
        "var promise_2 = transport_2(url_2).then(function (response_2)",
        ".catch(function (error_2)",
    ] {
        assert!(
            report.rewritten.contains(expected),
            "missing collision-safe `{expected}`:\n{}",
            report.rewritten
        );
    }
    assert_eq!(report.rewritten, second.rewritten);
    assert_behavior_preserved(
        "http-role-collisions",
        HTTP_ROLE_COLLISIONS,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(HTTP_ROLE_COLLISIONS)
    );
}

const HTTP_ROLE_DIRECT_EVAL: &str = "function f(a){var b=a('/').then(function(c){return c.ok?c.json():0;}).catch(function(d){throw d;});return eval('b');}";
const HTTP_ROLE_WITH: &str = "function f(a){with({a:function(){}}){var b=a('/').then(function(c){return c.ok?c.json():0;}).catch(function(d){throw d;});return b;}}";

#[test]
fn dynamic_scopes_refuse_the_entire_http_role_family() {
    for source in [HTTP_ROLE_DIRECT_EVAL, HTTP_ROLE_WITH] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert_eq!(report.rewritten, source);
        assert!(report.renames.is_empty());
    }
}

const RESPONSE_NEAR_MISS: &str = "function inspect(a){return a.ok?a.json():null;}print(inspect({ok:true,json:function(){return 1;}}));";
const ERROR_NEAR_MISS: &str =
    "function run(a){return a().catch(function(b){throw new Error('masked');});}";
const CACHE_NEAR_MISS: &str = "function table(a,b){var c={};if(c[a])return c[a];c[a]=b;delete c[a];return b;}print(table('x',1));";
const PARAMS_NEAR_MISS: &str = "function values(a){for(var b in a){print(a[b]);}}values({x:1});";
const MEMOIZED_PROMISE_NEAR_MISS: &str = r"
function memo(a, b) {
  var c = {};
  if (c[b]) return c[b];
  var d = a(b).then(function (e) { return e; }).catch(function (e) {
    delete c[b];
    throw e;
  });
  c[b] = d;
  return d;
}
";

const ARBITRARY_CHAIN_NEAR_MISS: &str = r#"
function chain(a) {
  var b = {};
  function load(c, d) {
    if (b[c]) return b[c];
    var e = d(c).then(function (f) {
      if (!f.ok) throw new Error("not ok");
      return f.json();
    }).catch(function (g) {
      delete b[c];
      throw g;
    });
    b[c] = e;
    return e;
  }
  return load;
}
var fake = {
  then: function (callback) {
    callback({ ok: true, json: function () { return 1; } });
    return { catch: function () { return "not a promise"; } };
  }
};
var load = chain("unused");
print(load("x", function () { return fake; }));
"#;

const NESTED_RETURN_THENABLE_NEAR_MISS: &str = r#"
function chain(a) {
  var b = {};
  function load(c) {
    if (b[c]) return b[c];
    var d = a(c).then(function (e) {
      if (!e.ok) throw new Error("not ok");
      return e.json();
    }).catch(function (f) {
      delete b[c];
      throw f;
    });
    b[c] = d;
    return d;
  }
  return load;
}
var fake = {
  then: function (callback) {
    callback({ ok: true, json: function () { return 1; } });
    return { catch: function () { return "not a promise"; } };
  }
};
var load = chain(function (url) {
  if (url === "fake") return fake;
  return Promise.resolve({ ok: true, json: function () { return url; } });
});
print(load("fake"));
"#;

const GENERATOR_TRANSPORT_NEAR_MISS: &str = r#"
function chain(a) {
  var b = {};
  function load(c) {
    if (b[c]) return b[c];
    var d = a(c).then(function (e) {
      if (!e.ok) throw new Error("not ok");
      return e.json();
    }).catch(function (f) {
      delete b[c];
      throw f;
    });
    b[c] = d;
    return d;
  }
  return load;
}
var load = chain(function* (url) {
  return Promise.resolve({ ok: true, json: function () { return url; } });
});
print(typeof load);
"#;

const REASSIGNED_CALLEE_NEAR_MISS: &str = r#"
function outer(a, b) {
  function build(c, d) {
    var e = [];
    for (var f in d) {
      if (Object.prototype.hasOwnProperty.call(d, f)) {
        e.push(encodeURIComponent(f) + "=" + encodeURIComponent(d[f]));
      }
    }
    return e.join("&");
  }
  build = function (c, d) { return String(c) + String(d); };
  return build(a, b);
}
print(outer("x", "y"));
"#;

const REDECLARED_CALLEE_NEAR_MISS: &str = r#"
function outer(a, b) {
  function build(c, d) {
    var e = [];
    for (var f in d) {
      if (Object.prototype.hasOwnProperty.call(d, f)) {
        e.push(encodeURIComponent(f) + "=" + encodeURIComponent(d[f]));
      }
    }
    return e.join("&");
  }
  function build(c, d) { return String(c) + String(d); }
  return build(a, b);
}
print(outer("x", "y"));
"#;

const DISCARDED_ENCODING_NEAR_MISS: &str = r"
function inspect(a) {
  for (var b in a) {
    if (Object.prototype.hasOwnProperty.call(a, b)) {
      encodeURIComponent(b);
      encodeURIComponent(a[b]);
    }
  }
  return 1;
}
print(inspect({ x: 1 }));
";

const NESTED_CACHE_NEAR_MISS: &str = r#"
function memo(a, b) {
  var c = {};
  function unrelated() {
    if (c[a]) return c[a];
    delete c[a];
  }
  var d = b(a).then(function (e) {
    return e.ok ? e.json() : null;
  }).catch(function (f) {
    unrelated();
    throw f;
  });
  c[a] = d;
  return d;
}
var result = memo("x", function (url) {
  return Promise.resolve({ ok: true, json: function () { return url; } });
});
print(result instanceof Promise);
"#;

fn has_heuristic_role(report: &TerserRestoreReport, role: &str) -> bool {
    report
        .renames
        .iter()
        .any(|rename| rename.source_label == "heuristic" && rename.restored.starts_with(role))
}

#[test]
fn incomplete_or_uncorrelated_http_shapes_refuse_specific_roles() {
    for (source, refused) in [
        (RESPONSE_NEAR_MISS, "response"),
        (ERROR_NEAR_MISS, "error"),
        (CACHE_NEAR_MISS, "cache"),
        (PARAMS_NEAR_MISS, "params"),
        (MEMOIZED_PROMISE_NEAR_MISS, "transport"),
        (MEMOIZED_PROMISE_NEAR_MISS, "cache"),
        (MEMOIZED_PROMISE_NEAR_MISS, "url"),
        (MEMOIZED_PROMISE_NEAR_MISS, "promise"),
        (MEMOIZED_PROMISE_NEAR_MISS, "error"),
    ] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert!(
            !report.rewritten.contains(refused),
            "uncorrelated evidence must not infer `{refused}`:\n{}",
            report.rewritten
        );
        assert_behavior_preserved("http-role-near-miss", source, &report.rewritten);
        assert_eq!(node_capture(&report.rewritten), node_capture(source));
    }
}

#[test]
fn cached_arbitrary_thenable_does_not_prove_http_or_promise_roles() {
    let report: TerserRestoreReport = restore_terser_mangled(ARBITRARY_CHAIN_NEAR_MISS);
    for role in ["transport", "cache", "url", "promise", "response", "error"] {
        assert!(!has_heuristic_role(&report, role), "{}", report.rewritten);
    }
    assert_behavior_preserved(
        "arbitrary-chain",
        ARBITRARY_CHAIN_NEAR_MISS,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(ARBITRARY_CHAIN_NEAR_MISS)
    );
}

#[test]
fn nested_arbitrary_return_does_not_prove_native_promise_roles() {
    let report: TerserRestoreReport = restore_terser_mangled(NESTED_RETURN_THENABLE_NEAR_MISS);
    for role in ["transport", "cache", "url", "promise", "response", "error"] {
        assert!(!has_heuristic_role(&report, role), "{}", report.rewritten);
    }
    assert_behavior_preserved(
        "nested-promise-return",
        NESTED_RETURN_THENABLE_NEAR_MISS,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(NESTED_RETURN_THENABLE_NEAR_MISS)
    );
}

#[test]
fn generator_transport_does_not_prove_native_promise_roles() {
    let report: TerserRestoreReport = restore_terser_mangled(GENERATOR_TRANSPORT_NEAR_MISS);
    for role in ["transport", "cache", "url", "promise", "response", "error"] {
        assert!(!has_heuristic_role(&report, role), "{}", report.rewritten);
    }
    assert_behavior_preserved(
        "generator-promise-return",
        GENERATOR_TRANSPORT_NEAR_MISS,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(GENERATOR_TRANSPORT_NEAR_MISS)
    );
}

#[test]
fn reassigned_callees_do_not_propagate_parameter_roles() {
    for source in [REASSIGNED_CALLEE_NEAR_MISS, REDECLARED_CALLEE_NEAR_MISS] {
        let report: TerserRestoreReport = restore_terser_mangled(source);
        assert!(
            !report.renames.iter().any(|rename| {
                rename.original == "b"
                    && rename.source_label == "heuristic"
                    && rename.restored.starts_with("params")
            }),
            "{}",
            report.rewritten
        );
        assert_behavior_preserved("ambiguous-callee", source, &report.rewritten);
        assert_eq!(node_capture(&report.rewritten), node_capture(source));
    }
}

#[test]
fn discarded_encoding_calls_do_not_prove_parameter_roles() {
    let report: TerserRestoreReport = restore_terser_mangled(DISCARDED_ENCODING_NEAR_MISS);
    assert!(
        !has_heuristic_role(&report, "params"),
        "{}",
        report.rewritten
    );
    assert!(!has_heuristic_role(&report, "key"), "{}", report.rewritten);
    assert_behavior_preserved(
        "discarded-encoding",
        DISCARDED_ENCODING_NEAR_MISS,
        &report.rewritten,
    );
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(DISCARDED_ENCODING_NEAR_MISS)
    );
}

#[test]
fn nested_cache_operations_do_not_prove_loader_storage_roles() {
    let report: TerserRestoreReport = restore_terser_mangled(NESTED_CACHE_NEAR_MISS);
    for role in ["transport", "cache", "url"] {
        assert!(!has_heuristic_role(&report, role), "{}", report.rewritten);
    }
    assert_behavior_preserved("nested-cache", NESTED_CACHE_NEAR_MISS, &report.rewritten);
    assert_eq!(
        node_capture(&report.rewritten),
        node_capture(NESTED_CACHE_NEAR_MISS)
    );
}

#[test]
fn oversized_name_analysis_abstains_without_panicking() {
    let source: String = format!(
        "function f(a){{{}return a.length;}}",
        "a.push(0);".repeat(110_000)
    );
    let error: Error =
        restore_terser_mangled_result(&source).expect_err("oversized source must fail");
    assert!(matches!(
        error,
        Error::SyntaxLimit {
            kind: "JavaScript source bytes",
            observed,
            maximum: 1_048_576,
        } if observed == source.len()
    ));
}
