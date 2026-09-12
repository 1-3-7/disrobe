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
        "var __out = [];\nvar print = function(v){{ __out.push(String(v)); }};\nvar __modules = {{\n  './math': {{ add: function(a, b){{ return a + b; }}, mul: function(a, b){{ return a * b; }} }},\n  './util/index.js': {{ shout: function(s){{ return s + '!'; }} }},\n  'tiny-emitter': function(){{ this.fired = 0; this.emit = function(){{ this.fired++; return this.fired; }}; }}\n}};\nvar require = function(id){{ return __modules[id]; }};\n{program}\n__out.join('\\u0001');"
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

const REFERENCE_RELATIVE: &str =
    "const math = require('./math');\nconst total = math.add(2, 3);\nprint(math.mul(total, 2));";
const MINIFIED_RELATIVE: &str =
    "const a = require('./math');\nconst total = a.add(2, 3);\nprint(a.mul(total, 2));";

#[test]
fn single_letter_relative_require_alias_recovers_module_name() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(MINIFIED_RELATIVE);
    assert!(
        stats.require_aliases_renamed >= 1,
        "the `const a = require('./math')` alias must be un-renamed; got {}",
        stats.require_aliases_renamed
    );
    assert!(
        recovered.contains("const math = require('./math');"),
        "the binding must be restored to the module name:\n{recovered}"
    );
    assert!(
        recovered.contains("math.add(2, 3)") && recovered.contains("math.mul(total, 2)"),
        "every member-access reference must follow the rename:\n{recovered}"
    );
    assert!(
        !recovered.contains(" a."),
        "the minified `a` alias must be gone:\n{recovered}"
    );
    assert_behavior_preserved("relative", REFERENCE_RELATIVE, &recovered);
    assert_behavior_preserved("relative-vs-ref", REFERENCE_RELATIVE, MINIFIED_RELATIVE);
}

const MINIFIED_INDEX: &str = "var u = require('./util/index.js');\nprint(u.shout('hi'));";
const REFERENCE_INDEX: &str = "var util = require('./util/index.js');\nprint(util.shout('hi'));";

#[test]
fn index_basename_falls_back_to_directory_name() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(MINIFIED_INDEX);
    assert_eq!(
        stats.require_aliases_renamed, 1,
        "the `index.js` basename must be skipped in favor of the directory:\n{recovered}"
    );
    assert!(
        recovered.contains("util = require('./util/index.js');"),
        "the directory `util` must name the binding, not `index`:\n{recovered}"
    );
    assert!(
        recovered.contains("util.shout('hi')"),
        "the reference must be rewritten:\n{recovered}"
    );
    assert_behavior_preserved("index", REFERENCE_INDEX, &recovered);
}

const MINIFIED_DASHED: &str =
    "const t = require('tiny-emitter');\nconst e = new t();\ne.emit();\nprint(e.emit());";
const REFERENCE_DASHED: &str = "const tinyEmitter = require('tiny-emitter');\nconst e = new tinyEmitter();\ne.emit();\nprint(e.emit());";

#[test]
fn dashed_package_recovers_camel_cased_name() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(MINIFIED_DASHED);
    assert!(
        stats.require_aliases_renamed >= 1,
        "the dashed package alias must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("const tinyEmitter = require('tiny-emitter');"),
        "`tiny-emitter` must camel-case to `tinyEmitter`:\n{recovered}"
    );
    assert!(
        recovered.contains("new tinyEmitter()"),
        "the constructor reference must be rewritten:\n{recovered}"
    );
    assert_behavior_preserved("dashed", REFERENCE_DASHED, &recovered);
}

const SAFETY_COLLISION: &str =
    "const a = require('./math');\nconst math = a.add(1, 1);\nprint(a.mul(math, 3));";

#[test]
fn a_local_named_like_the_module_blocks_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_COLLISION);
    assert_eq!(
        stats.require_aliases_renamed, 0,
        "renaming `a`->`math` would collide with the local `const math`:\n{recovered}"
    );
    assert!(
        recovered.contains("const a = require('./math');"),
        "the aliased require must survive untouched:\n{recovered}"
    );
}

const SAFETY_DESTRUCTURE: &str =
    "const { add, mul } = require('./math');\nprint(add(1, 2) + mul(2, 3));";

#[test]
fn destructured_require_is_left_to_other_passes() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_DESTRUCTURE);
    assert_eq!(
        stats.require_aliases_renamed, 0,
        "a destructured require binds member names, not a module alias"
    );
}
