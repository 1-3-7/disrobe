#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

fn eval_exports_shape(module_body: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!(
        "var exports = {{}};\n{module_body}\ndelete exports.__esModule;\nvar __keys = Object.keys(exports).sort();\nvar __out = []; for (var i = 0; i < __keys.length; i++) {{ __out.push(__keys[i] + '=' + String(exports[__keys[i]])); }}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

const ESMODULE_DEFINE: &str = r#"
Object.defineProperty(exports, "__esModule", { value: true });
exports.foo = 1;
exports.bar = 'two';
"#;

#[test]
fn define_property_esmodule_marker_is_stripped_and_exports_unchanged() {
    let want: String = eval_exports_shape(ESMODULE_DEFINE).expect("input evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ESMODULE_DEFINE);
    assert!(
        stats.esmodule_markers_stripped >= 1,
        "the __esModule marker must be stripped; got {}",
        stats.esmodule_markers_stripped
    );
    assert!(
        !recovered.contains("__esModule"),
        "the marker must be gone:\n{recovered}"
    );
    let got: String = eval_exports_shape(&recovered).expect("recovered evaluates");
    assert_eq!(
        want, got,
        "stripping pure metadata must not change the observable exports shape"
    );
}

const ESMODULE_ASSIGN: &str = r"
exports.__esModule = true;
exports.value = 42;
";

#[test]
fn exports_dot_esmodule_assignment_is_stripped() {
    let want: String = eval_exports_shape(ESMODULE_ASSIGN).expect("input evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(ESMODULE_ASSIGN);
    assert!(
        stats.esmodule_markers_stripped >= 1,
        "exports.__esModule = true must strip; got {}",
        stats.esmodule_markers_stripped
    );
    assert!(
        !recovered.contains("__esModule"),
        "the marker must be gone:\n{recovered}"
    );
    let got: String = eval_exports_shape(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "exports shape preserved");
}

const NEG_REAL_EXPORT: &str = r"
exports.__esModuleHelper = true;
exports.keep = 9;
";

#[test]
fn similarly_named_export_is_not_stripped() {
    let want: String = eval_exports_shape(NEG_REAL_EXPORT).expect("input evaluates");
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_REAL_EXPORT);
    assert_eq!(
        stats.esmodule_markers_stripped, 0,
        "__esModuleHelper is a real export and must NOT be stripped"
    );
    let got: String = eval_exports_shape(&recovered).expect("recovered evaluates");
    assert_eq!(want, got, "exports shape preserved");
}

const WILDCARD: &str = "var _react = _interopRequireWildcard(require(\"react\"));\n";

#[test]
fn interop_require_wildcard_becomes_namespace_import_structural() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(WILDCARD);
    assert!(
        stats.wildcard_imports_unwrapped >= 1,
        "_interopRequireWildcard must become a namespace import; got {}",
        stats.wildcard_imports_unwrapped
    );
    assert!(
        recovered.contains("import * as _react from \"react\";"),
        "must produce a namespace import:\n{recovered}"
    );
    assert!(
        !recovered.contains("_interopRequireWildcard"),
        "the interop helper call must be gone:\n{recovered}"
    );
}

const NEG_PLAIN_REQUIRE: &str = "var x = require(\"mod\");\n";

#[test]
fn plain_require_is_not_unwrapped() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_PLAIN_REQUIRE);
    assert_eq!(
        stats.wildcard_imports_unwrapped, 0,
        "a bare require is not the interop-wildcard shape and must NOT be rewritten"
    );
    assert!(
        recovered.contains("require(\"mod\")"),
        "the plain require must be preserved:\n{recovered}"
    );
}
