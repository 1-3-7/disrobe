#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{AstUnminifyStats, unminify_ast};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

const PARITY_FIXTURE: &str = include_str!("../corpus/unminify/parity/min.js");

const TERSER_MINIFIED: &str = "function greet(e,t){if(null!=e){for(var n=\"user \"+e.name+\" has \"+t+\" items\";!(t<=0);)t--;return\"active\"===e.status?n:\"inactive\"}}";

fn eval_capture(program: &str, tail: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(LOOP_LIMIT);
        runtime.set_recursion_limit(RECURSION_LIMIT);
        runtime.set_stack_size_limit(STACK_LIMIT);
    }
    let harness: String = format!("{program}\n{tail}");
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

const PROBE: &str = r#"
var probe = [
  built.join("|"),
  String(label),
  String(none),
  joined
].join("");
probe;
"#;

#[test]
fn real_minified_fixture_recovers_and_preserves_behavior() {
    let want: String = eval_capture(PARITY_FIXTURE, PROBE)
        .expect("minified fixture must evaluate before transform");

    let (recovered, stats): (String, AstUnminifyStats) = unminify_ast(PARITY_FIXTURE);

    assert!(
        stats.indirect_calls_simplified >= 1,
        "(0, mod.render)(...) indirect call must be simplified; got {}",
        stats.indirect_calls_simplified
    );
    assert!(
        stats.bracket_accesses_dotted >= 2,
        "this[\"total\"] and o[\"label\"] must become dot access; got {}",
        stats.bracket_accesses_dotted
    );
    assert!(
        stats.template_literals_rebuilt >= 1,
        "the \"row \" + n + \" of \" + this.total concat must become a template literal; got {}",
        stats.template_literals_rebuilt
    );
    assert!(
        stats.optional_chains_rebuilt >= 1,
        "o == null ? void 0 : o[\"label\"] must become o?.label; got {}",
        stats.optional_chains_rebuilt
    );
    assert!(
        stats.apply_calls_spread >= 1,
        "joinAll.apply(void 0, parts) must become joinAll(...parts); got {}",
        stats.apply_calls_spread
    );

    assert!(
        recovered.contains("mod.render(items[i])"),
        "indirect call must collapse:\n{recovered}"
    );
    assert!(
        recovered.contains("o?.label"),
        "optional chain expected:\n{recovered}"
    );
    assert!(
        recovered.contains("joinAll(...parts)"),
        "spread call expected:\n{recovered}"
    );

    let got: String = eval_capture(&recovered, PROBE)
        .unwrap_or_else(|| panic!("recovered must evaluate:\n{recovered}"));
    assert_eq!(
        want, got,
        "recovered diverged from the real minified fixture\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
}

const TERSER_PROBE: &str = r#"
var probe = [
  String(greet({ name: "ann", status: "active" }, 3)),
  String(greet({ name: "bob", status: "off" }, 1)),
  String(greet(null, 5))
].join("");
probe;
"#;

#[test]
fn real_terser_output_unminifies_equivalently() {
    let want: String =
        eval_capture(TERSER_MINIFIED, TERSER_PROBE).expect("terser output must evaluate");

    let (recovered, _stats): (String, AstUnminifyStats) = unminify_ast(TERSER_MINIFIED);

    let got: String = eval_capture(&recovered, TERSER_PROBE)
        .unwrap_or_else(|| panic!("recovered terser output must evaluate:\n{recovered}"));
    assert_eq!(
        want, got,
        "recovered diverged from real terser output\n--want--\n{want}\n--got--\n{got}\n--src--\n{recovered}"
    );
    assert!(
        reparses(&recovered),
        "recovered terser output must re-parse:\n{recovered}"
    );
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
