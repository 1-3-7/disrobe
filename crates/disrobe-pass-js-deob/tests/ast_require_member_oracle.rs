#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstPipeline, AstUnminifyStats, unminify_ast};

const AST_TRANSFORM_FLOOR: usize = 45;

fn distinct_enabled_transforms() -> usize {
    let rendered: String = format!("{:?}", AstPipeline::default());
    let start: usize = rendered
        .find("enabled: [")
        .map(|i: usize| i + "enabled: [".len())
        .expect("pipeline debug lists enabled rules");
    let end: usize = rendered[start..]
        .find(']')
        .map(|i: usize| start + i)
        .expect("enabled list is bracketed");
    let mut names: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for token in rendered[start..end].split(',') {
        let name: &str = token.trim();
        if !name.is_empty() {
            names.insert(name);
        }
    }
    names.len()
}

#[test]
fn ast_unminify_transform_count_holds_its_floor() {
    let count: usize = distinct_enabled_transforms();
    assert!(
        count >= AST_TRANSFORM_FLOOR,
        "the AST unminify pipeline regressed below its transform floor: {count} < {AST_TRANSFORM_FLOOR}"
    );
}

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
        "var __out = [];\nvar print = function(v){{ __out.push(String(v)); }};\nvar __modules = {{\n  'react': {{ useState: function(x){{ return 'S:' + x; }}, useEffect: function(x){{ return 'E:' + x; }} }},\n  'fs': {{ readFile: function(p){{ return 'R:' + p; }}, writeFile: function(p, d){{ return 'W:' + p + '=' + d; }} }}\n}};\nvar require = function(id){{ return __modules[id]; }};\n{program}\n__out.join('\\u0001');"
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

const REFERENCE_SINGLE: &str = "const useState = require('react').useState;\nfunction counter(start) { return useState(start); }\nprint(counter(5));";

const TERSER_MANGLED_SINGLE: &str = "const e=require(\"react\").useState;print(e(5));";

#[test]
fn terser_mangled_chained_member_recovers_property_name() {
    assert_behavior_preserved("baseline", REFERENCE_SINGLE, TERSER_MANGLED_SINGLE);

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MANGLED_SINGLE);
    assert_eq!(
        stats.require_member_aliases_renamed, 1,
        "the `const e = require(\"react\").useState` alias must recover the property name:\n{recovered}"
    );
    assert!(
        recovered.contains("const useState = require(\"react\").useState;")
            || recovered.contains("const useState=require(\"react\").useState;"),
        "the binding must be renamed to the accessed property:\n{recovered}"
    );
    assert!(
        recovered.contains("useState(5)"),
        "the call-site reference must follow the rename:\n{recovered}"
    );
    assert!(
        !recovered.contains("const e=") && !recovered.contains("const e ="),
        "the mangled `e` binding must be gone:\n{recovered}"
    );
    assert_behavior_preserved("single-recovered", REFERENCE_SINGLE, &recovered);
}

const REFERENCE_MULTI: &str = "const useState = require('react').useState;\nconst useEffect = require('react').useEffect;\nfunction makeApp(a, b) { const s = useState(a); const e = useEffect(b); return s + e + useState(a) + useEffect(b); }\nprint(makeApp(1, 2));";

const TERSER_MANGLED_MULTI: &str = "const t=require(\"react\").useState;const e=require(\"react\").useEffect;function r(r,c){const n=t(r);const s=e(c);return n+s+t(r)+e(c)}print(r(1,2));";

#[test]
fn terser_mangled_multiple_chained_members_recover() {
    assert_behavior_preserved("baseline", REFERENCE_MULTI, TERSER_MANGLED_MULTI);

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MANGLED_MULTI);
    assert_eq!(
        stats.require_member_aliases_renamed, 2,
        "both `t`->useState and `e`->useEffect chained aliases must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("useState=require(\"react\").useState")
            || recovered.contains("useState = require(\"react\").useState"),
        "the first alias must recover useState:\n{recovered}"
    );
    assert!(
        recovered.contains("useEffect=require(\"react\").useEffect")
            || recovered.contains("useEffect = require(\"react\").useEffect"),
        "the second alias must recover useEffect:\n{recovered}"
    );
    assert!(
        recovered.contains("useState(r)") && recovered.contains("useEffect(c)"),
        "the mangled call sites must be rewritten to the recovered names:\n{recovered}"
    );
    assert_behavior_preserved("multi-recovered", REFERENCE_MULTI, &recovered);
}

const REFERENCE_FS: &str = "const readFile = require('fs').readFile;\nfunction run(p) { return readFile(p) + '|' + readFile(p + '2'); }\nprint(run('a'));";

const MINIFIED_FS: &str = "const e=require(\"fs\").readFile;function run(p){return e(p)+\"|\"+e(p+\"2\")}print(run(\"a\"));";

#[test]
fn builtin_module_chained_member_recovers_and_preserves_behavior() {
    assert_behavior_preserved("baseline", REFERENCE_FS, MINIFIED_FS);

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(MINIFIED_FS);
    assert_eq!(
        stats.require_member_aliases_renamed, 1,
        "the fs.readFile chained alias must recover:\n{recovered}"
    );
    assert!(
        recovered.contains("readFile(p)"),
        "both call sites must be rewritten to readFile:\n{recovered}"
    );
    assert_behavior_preserved("fs-recovered", REFERENCE_FS, &recovered);
}

const SAFETY_COLLISION: &str =
    "const e=require(\"react\").useState;const useState=e(1);print(useState+e(2));";

#[test]
fn a_local_named_like_the_property_blocks_the_rename() {
    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(SAFETY_COLLISION);
    assert_eq!(
        stats.require_member_aliases_renamed, 0,
        "renaming `e`->`useState` would collide with the local `const useState`:\n{recovered}"
    );
    assert!(
        recovered.contains("require(\"react\").useState"),
        "the aliased chained require must survive untouched:\n{recovered}"
    );
    assert!(
        reparses(&recovered),
        "recovered must re-parse:\n{recovered}"
    );
}

const NEG_ALREADY_NAMED: &str = "const useState = require('react').useState;\nprint(useState(3));";

#[test]
fn already_meaningful_binding_is_untouched() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_ALREADY_NAMED);
    assert_eq!(
        stats.require_member_aliases_renamed, 0,
        "a binding already named after its property has nothing to recover"
    );
}

const NEG_PLAIN_REQUIRE: &str = "const e = require('react');\nprint(e.useState(4));";

#[test]
fn plain_require_without_member_is_left_to_other_passes() {
    let (_recovered, stats): (String, AstUnminifyStats) = unminify_ast(NEG_PLAIN_REQUIRE);
    assert_eq!(
        stats.require_member_aliases_renamed, 0,
        "a plain require with no chained member is the require-alias pass's job"
    );
}
