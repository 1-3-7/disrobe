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
        "var __out = [];\nvar print = function(v){{ __out.push(String(v)); }};\nvar __modules = {{\n  './math': {{ add: function(a, b){{ return a + b; }}, mul: function(a, b){{ return a * b; }} }},\n  'fs': {{ readFile: function(p){{ return 'R:' + p; }}, writeFile: function(p, d){{ return 'W:' + p + '=' + d; }} }}\n}};\nvar require = function(id){{ return __modules[id]; }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
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

const REFERENCE_MATH: &str = "const { add, mul } = require('./math');\nfunction calc(x, y) { return add(x, y) + mul(x, y); }\nprint(calc(2, 3));";

const TERSER_MANGLED_MATH: &str =
    "const{add:n,mul:r}=require(\"./math\");function t(t,u){return n(t,u)+r(t,u)}print(t(2,3));";

#[test]
fn terser_mangled_destructured_members_recover_property_names() {
    assert_behavior_preserved("baseline", REFERENCE_MATH, TERSER_MANGLED_MATH);

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MANGLED_MATH);
    assert_eq!(
        stats.require_members_unaliased, 2,
        "both `add:n` and `mul:r` aliases must collapse:\n{recovered}"
    );
    assert!(
        recovered.contains("add") && recovered.contains("mul"),
        "the readable property names must be restored:\n{recovered}"
    );
    assert!(
        recovered.contains("add(t,u)") || recovered.contains("add(t, u)"),
        "the mangled local `n` must be rewritten to `add` at its call site:\n{recovered}"
    );
    assert!(
        recovered.contains("mul(t,u)") || recovered.contains("mul(t, u)"),
        "the mangled local `r` must be rewritten to `mul` at its call site:\n{recovered}"
    );
    assert!(
        !recovered.contains("add:n") && !recovered.contains("mul:r"),
        "no aliased binding-property may remain:\n{recovered}"
    );
    assert_behavior_preserved("math-recovered", REFERENCE_MATH, &recovered);
}

const REFERENCE_FS: &str = "const { readFile, writeFile } = require('fs');\nfunction run(p, d) { return readFile(p) + '|' + writeFile(p, d); }\nprint(run('a', 'b'));";

const TERSER_MANGLED_FS: &str = "const{readFile:e,writeFile:i}=require(\"fs\");function n(n,o){return e(n)+\"|\"+i(n,o)}print(n(\"a\",\"b\"));";

#[test]
fn terser_mangled_builtin_module_members_recover() {
    assert_behavior_preserved("baseline", REFERENCE_FS, TERSER_MANGLED_FS);

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MANGLED_FS);
    assert_eq!(
        stats.require_members_unaliased, 2,
        "`readFile:e` and `writeFile:i` must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("readFile") && recovered.contains("writeFile"),
        "the fs member names must be restored:\n{recovered}"
    );
    assert!(
        !recovered.contains("readFile:e") && !recovered.contains("writeFile:i"),
        "no aliased binding-property may remain:\n{recovered}"
    );
    assert_behavior_preserved("fs-recovered", REFERENCE_FS, &recovered);
}

const SAFETY_LOCAL_COLLISION: &str =
    "const{add:n,mul:r}=require(\"./math\");const add=n(1,2);print(add+r(2,3));";

#[test]
fn member_recovery_blocked_when_property_name_already_bound() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_LOCAL_COLLISION);
    assert_eq!(
        stats.require_members_unaliased, 1,
        "only `mul:r` may recover; `add:n` collides with the local `const add`:\n{recovered}"
    );
    assert!(
        recovered.contains("add:n"),
        "the colliding `add:n` alias must survive untouched:\n{recovered}"
    );
    assert!(
        reparses(&recovered),
        "recovered must re-parse:\n{recovered}"
    );
}

const REFERENCE_UNALIASED: &str = "const { readFile } = require('fs');\nprint(readFile('x'));";

#[test]
fn already_shorthand_destructure_is_untouched() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(REFERENCE_UNALIASED);
    assert_eq!(
        stats.require_members_unaliased, 0,
        "a shorthand destructure has no alias to un-rename"
    );
}
