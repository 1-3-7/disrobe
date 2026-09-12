#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use boa_engine::{Context, Source};
use disrobe_pass_js_deob::{ObfuscatorIoOptions, ObfuscatorIoOutput, obfuscator_io_deobfuscate};

const CFF: &str = include_str!(
    "../../../corpus/src/javascript/obfuscator-io-samples/controls/controlFlowFlattening.js"
);

const HARNESS: &str =
    "var __log = [];var console = { log: function(x){ __log.push(String(x)); } };";

const PROBE: &str = "var __out = [String(calculate('add', 10, 5)),String(calculate('sub', 10, 5)),String(calculate('mul', 10, 5)),String(calculate('div', 10, 5)),greet('disrobe'),runSamples().join('|'),__log.join('#')].join(';');__out;";

fn eval_capture(program: &str) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(2_000_000);
        runtime.set_recursion_limit(1_500);
        runtime.set_stack_size_limit(50_000);
    }
    let harness: String = format!("{HARNESS}\n{program}\n{PROBE}");
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

#[test]
fn control_flow_object_proxy_declaration_is_removed_after_full_inline() {
    let want: String =
        eval_capture(CFF).expect("obfuscated control-flow fixture must evaluate before transform");

    let opts: ObfuscatorIoOptions = ObfuscatorIoOptions::all();
    let out: ObfuscatorIoOutput = obfuscator_io_deobfuscate(CFF, &opts).expect("deob ok");

    for proxy_marker in [
        "poLyL", "FatOg", "xvNoh", "TZuPv", "lVzeW", "pgsOS", "mOEWM",
    ] {
        assert!(
            !out.source.contains(proxy_marker),
            "control-flow proxy member `{proxy_marker}` must be inlined and its object removed, not left as a dead declaration:\n{}",
            out.source
        );
    }
    assert!(
        out.source.contains("case 'add':return add(")
            || out.source.contains("case 'add': return add("),
        "the switch body must recover direct calls after the proxy object is dissolved:\n{}",
        out.source
    );
    assert!(
        !out.source.contains("={'"),
        "no residual five-character-key proxy object literal should survive:\n{}",
        out.source
    );

    assert!(
        reparses(&out.source),
        "recovered source must re-parse as valid javascript:\n{}",
        out.source
    );

    let got: String = eval_capture(&out.source)
        .unwrap_or_else(|| panic!("recovered source must evaluate:\n{}", out.source));
    assert_eq!(
        want, got,
        "recovered behavior diverged from the real obfuscated fixture\n--want--\n{want}\n--got--\n{got}\n--src--\n{}",
        out.source
    );
}
