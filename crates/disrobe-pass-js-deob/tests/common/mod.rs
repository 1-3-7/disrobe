#![allow(dead_code, clippy::redundant_pub_crate)]
use boa_engine::{Context, JsError, Source};

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

const BROWSER_SHIM: &str = r"var __dr_host = (function () {
  var target = function () {};
  var handler = {
    get: function (t, prop) {
      if (prop === Symbol.toPrimitive) { return function () { return ''; }; }
      if (prop === Symbol.iterator) { return undefined; }
      if (prop === Symbol.toStringTag) { return 'Object'; }
      if (prop === 'toString' || prop === 'valueOf') { return function () { return ''; }; }
      if (prop === 'length') { return 0; }
      return host;
    },
    set: function () { return true; },
    has: function () { return true; },
    deleteProperty: function () { return true; },
    apply: function () { return host; },
    construct: function () { return host; }
  };
  var host = new Proxy(target, handler);
  return host;
})();
var window = __dr_host;
var self = __dr_host;
var document = __dr_host;
var navigator = __dr_host;
var location = __dr_host;
var screen = __dr_host;
var history = __dr_host;
var frames = __dr_host;
var top = __dr_host;
var parent = __dr_host;
var localStorage = __dr_host;
var sessionStorage = __dr_host;
";

const HARNESS_HEAD: &str = "var __dr_term = 0;\nvar __dr_ctor = \"\";\ntry {\n";
const HARNESS_TAIL: &str = "\n} catch (__dr_err) {\n__dr_term = 1;\ntry { __dr_ctor = (__dr_err && __dr_err.constructor && __dr_err.constructor.name) ? String(__dr_err.constructor.name) : ((__dr_err && __dr_err.name) ? String(__dr_err.name) : \"Error\"); } catch (__dr_err2) { __dr_ctor = \"Error\"; }\n}\nJSON.stringify({ t: __dr_term, c: __dr_ctor, o: __out.join(\"\\u0001\") });";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Terminal {
    Completed,
    Threw(String),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvalOutcome {
    pub(crate) console: String,
    pub(crate) terminal: Terminal,
}

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

fn run_harness(program: &str, argv: &[&str], with_host: bool) -> Option<EvalOutcome> {
    let mut context: Context = Context::default();
    configure(&mut context);
    let argv_list: String = argv_literal(argv);
    let host: &str = if with_host { BROWSER_SHIM } else { "" };
    let harness: String = format!(
        "{PRELUDE}{host}var process = {{ argv: [{argv_list}] }};\n{HARNESS_HEAD}{program}{HARNESS_TAIL}"
    );
    let value: boa_engine::JsValue = match context.eval(Source::from_bytes(harness.as_bytes())) {
        Ok(value) => value,
        Err(err) => return outcome_from_error(&err),
    };
    let rendered: String = value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)?;
    parse_outcome(&rendered)
}

pub(crate) fn eval_outcome_with_argv(program: &str, argv: &[&str]) -> Option<EvalOutcome> {
    run_harness(program, argv, true)
}

pub(crate) fn eval_outcome_bare(program: &str) -> Option<EvalOutcome> {
    run_harness(program, &[], false)
}

fn outcome_from_error(err: &JsError) -> Option<EvalOutcome> {
    if err
        .as_native()
        .is_some_and(boa_engine::JsNativeError::is_runtime_limit)
    {
        return Some(EvalOutcome {
            console: String::new(),
            terminal: Terminal::TimedOut,
        });
    }
    None
}

fn parse_outcome(rendered: &str) -> Option<EvalOutcome> {
    let parsed: serde_json::Value = serde_json::from_str(rendered).ok()?;
    let console: String = parsed.get("o")?.as_str()?.to_owned();
    let terminal: Terminal = if parsed.get("t")?.as_u64()? == 0 {
        Terminal::Completed
    } else {
        let ctor: String = parsed
            .get("c")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Error")
            .to_owned();
        Terminal::Threw(ctor)
    };
    Some(EvalOutcome { console, terminal })
}

pub(crate) fn eval_outcome(program: &str) -> Option<EvalOutcome> {
    eval_outcome_with_argv(program, &[])
}

pub(crate) fn eval_capture_with_argv(program: &str, argv: &[&str]) -> Option<String> {
    match eval_outcome_with_argv(program, argv) {
        Some(EvalOutcome {
            console,
            terminal: Terminal::Completed,
        }) => Some(console),
        _ => None,
    }
}

pub(crate) fn eval_capture(program: &str) -> Option<String> {
    eval_capture_with_argv(program, &[])
}

pub(crate) fn assert_equivalent(label: &str, original: &str, recovered: &str) {
    let want: EvalOutcome =
        eval_outcome(original).unwrap_or_else(|| panic!("{label}: original fixture must evaluate"));
    let got: EvalOutcome = eval_outcome(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered output must evaluate; src=\n{recovered}"));
    assert_eq!(
        want, got,
        "{label}: recovered behavior diverged from original\n--want--\n{want:?}\n--got--\n{got:?}\n--recovered src--\n{recovered}"
    );
}
