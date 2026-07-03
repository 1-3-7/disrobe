#![allow(dead_code, clippy::redundant_pub_crate)]
use boa_engine::{Context, Source};

const LOOP_LIMIT: u64 = 2_000_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;

const PRELUDE: &str = r"var __out = [];
var print = function (v) { __out.push(String(v)); };
var __log = function () { var __p = []; for (var __i = 0; __i < arguments.length; __i++) { __p.push(String(arguments[__i])); } __out.push(__p.join(' ')); };
var console = { log: __log, error: __log, warn: __log, info: __log, debug: __log, trace: __log };
var setInterval = function () { return 0; };
var clearInterval = function () {};
var setTimeout = function () { return 0; };
var clearTimeout = function () {};
";

fn configure(context: &mut Context) {
    let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
    runtime.set_loop_iteration_limit(LOOP_LIMIT);
    runtime.set_recursion_limit(RECURSION_LIMIT);
    runtime.set_stack_size_limit(STACK_LIMIT);
}

fn argv_literal(argv: &[&str]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(argv.len() + 2);
    parts.push("\"node\"".to_owned());
    parts.push("\"script\"".to_owned());
    for arg in argv {
        parts.push(serde_json::to_string(arg).unwrap_or_else(|_| "\"\"".to_owned()));
    }
    parts.join(", ")
}

pub(crate) fn eval_capture_with_argv(program: &str, argv: &[&str]) -> Option<String> {
    let mut context: Context = Context::default();
    configure(&mut context);
    let argv_list: String = argv_literal(argv);
    let harness: String = format!(
        "{PRELUDE}var process = {{ argv: [{argv_list}] }};\n{program}\n__out.join('\\u0001');"
    );
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(harness.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
}

pub(crate) fn eval_capture(program: &str) -> Option<String> {
    eval_capture_with_argv(program, &[])
}

pub(crate) fn assert_equivalent(label: &str, original: &str, recovered: &str) {
    let want: String =
        eval_capture(original).unwrap_or_else(|| panic!("{label}: original fixture must evaluate"));
    let got: String = eval_capture(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered output must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered behavior diverged from original\n--want--\n{want}\n--got--\n{got}\n--recovered src--\n{recovered}"
    );
}
