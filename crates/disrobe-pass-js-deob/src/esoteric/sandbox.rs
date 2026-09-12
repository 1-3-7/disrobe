use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boa_engine::{Context, Source};

use crate::sandbox_guard::{nesting_is_safe, nesting_is_safe_for_capture};

pub(super) const MAX_SCRIPT_BYTES: usize = 256 * 1024;
pub(super) const MAX_CAPTURE_SCRIPT_BYTES: usize = 8 * 1024 * 1024;
pub(super) const WALL_TIMEOUT_BACKSTOP: Duration = Duration::from_secs(30);
pub(super) const LOOP_ITERATION_LIMIT: u64 = 1_000_000;
pub(super) const RECURSION_LIMIT: usize = 1_024;
pub(super) const STACK_SIZE_LIMIT: usize = 16 * 1024;
pub(super) const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;

const NEUTERED_GLOBALS_PREAMBLE: &str = "\
delete globalThis.fetch;\
delete globalThis.XMLHttpRequest;\
delete globalThis.WebSocket;\
delete globalThis.import;\
delete globalThis.process;\
delete globalThis.require;\
delete globalThis.window;\
delete globalThis.document;\
delete globalThis.navigator;\
delete globalThis.location;\
delete globalThis.localStorage;\
delete globalThis.sessionStorage;\
delete globalThis.indexedDB;\
delete globalThis.crypto;\
delete globalThis.performance;\
delete globalThis.setTimeout;\
delete globalThis.setInterval;\
delete globalThis.setImmediate;\
delete globalThis.queueMicrotask;\
delete globalThis.atob;\
delete globalThis.btoa;\
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct SandboxLimits {
    pub(super) wall_timeout: Duration,
    pub(super) loop_iteration_limit: u64,
    pub(super) recursion_limit: usize,
    pub(super) stack_size_limit: usize,
}

impl Default for SandboxLimits {
    fn default() -> Self {
        Self {
            wall_timeout: WALL_TIMEOUT_BACKSTOP,
            loop_iteration_limit: LOOP_ITERATION_LIMIT,
            recursion_limit: RECURSION_LIMIT,
            stack_size_limit: STACK_SIZE_LIMIT,
        }
    }
}

const CAPTURE_PREFIX: &str = "(function(){\
var __dr_capture='';\
var __dr_real=Function;\
var __dr_hook=function(){\
var args=Array.prototype.slice.call(arguments);\
var body=args.length?String(args[args.length-1]):'';\
var built;\
try{built=__dr_real.apply(null,args);}catch(e){built=null;}\
return function(){\
if(built){try{var r=built.apply(this,arguments);if(typeof r==='string'){__dr_capture=r;return r;}}catch(e){}}\
__dr_capture=body;return body;\
};\
};\
__dr_hook.prototype=__dr_real.prototype;\
__dr_real.prototype.constructor=__dr_hook;\
try{globalThis.Function=__dr_hook;}catch(e){}\
try{globalThis.eval=function(s){__dr_capture=String(s);return undefined;};}catch(e){}\
try{\n";

const CAPTURE_SUFFIX: &str = "\n}catch(e){}\
return __dr_capture;\
})()";

pub(crate) fn eval_to_string(script: &str) -> Option<String> {
    eval_to_string_with_limits(script, SandboxLimits::default())
}

pub(super) fn eval_to_source(script: &str) -> Option<String> {
    if script.len() > MAX_CAPTURE_SCRIPT_BYTES {
        return None;
    }
    if !nesting_is_safe_for_capture(script) {
        return None;
    }
    let mut wrapped: String =
        String::with_capacity(script.len() + CAPTURE_PREFIX.len() + CAPTURE_SUFFIX.len());
    wrapped.push_str(CAPTURE_PREFIX);
    wrapped.push_str(script);
    wrapped.push_str(CAPTURE_SUFFIX);
    let limits: SandboxLimits = SandboxLimits {
        wall_timeout: WALL_TIMEOUT_BACKSTOP,
        loop_iteration_limit: 50_000_000,
        recursion_limit: 20_000,
        stack_size_limit: 16 * 1024 * 1024,
    };
    let captured: Option<String> = eval_capture_with_limits(&wrapped, limits)
        .filter(|s| !s.is_empty())
        .or_else(|| eval_value_relaxed(script, limits));
    captured.filter(|s| !s.is_empty())
}

fn eval_value_relaxed(script: &str, limits: SandboxLimits) -> Option<String> {
    let coerced: String = format!("String(({script}))");
    eval_capture_with_limits(&coerced, limits)
}

fn eval_capture_with_limits(script: &str, limits: SandboxLimits) -> Option<String> {
    let script_owned: String = script.to_owned();
    let (tx, rx): (
        mpsc::SyncSender<Option<String>>,
        mpsc::Receiver<Option<String>>,
    ) = mpsc::sync_channel::<Option<String>>(1);
    let Ok(_handle): std::io::Result<thread::JoinHandle<()>> = thread::Builder::new()
        .name("disrobe-esoteric-capture".to_owned())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let result: Option<String> = run_eval(&script_owned, limits);
            let _ = tx.send(result);
        })
    else {
        return None;
    };
    rx.recv_timeout(limits.wall_timeout).ok().flatten()
}

pub(super) fn eval_to_string_with_limits(script: &str, limits: SandboxLimits) -> Option<String> {
    if script.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    if !nesting_is_safe(script) {
        return None;
    }
    let script_owned: String = script.to_owned();
    let (tx, rx): (
        mpsc::SyncSender<Option<String>>,
        mpsc::Receiver<Option<String>>,
    ) = mpsc::sync_channel::<Option<String>>(1);
    let Ok(_handle): std::io::Result<thread::JoinHandle<()>> = thread::Builder::new()
        .name("disrobe-esoteric-eval".to_owned())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let result: Option<String> = run_eval(&script_owned, limits);
            let _ = tx.send(result);
        })
    else {
        return None;
    };
    rx.recv_timeout(limits.wall_timeout).ok().flatten()
}

fn run_eval(script: &str, limits: SandboxLimits) -> Option<String> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    if context
        .eval(Source::from_bytes(NEUTERED_GLOBALS_PREAMBLE.as_bytes()))
        .is_err()
    {
        return None;
    }
    let value: boa_engine::JsValue = context.eval(Source::from_bytes(script.as_bytes())).ok()?;
    value
        .as_string()
        .map(boa_engine::JsString::to_std_string_escaped)
        .or_else(|| {
            let coerced: boa_engine::JsString = value.to_string(&mut context).ok()?;
            Some(coerced.to_std_string_escaped())
        })
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn evaluates_simple_string_expression() {
        let Some(out): Option<String> = eval_to_string("'hel' + 'lo'") else {
            panic!("eval must succeed");
        };
        assert_eq!(out, "hello");
    }

    #[test]
    fn capture_intercepts_eval_call() {
        let Some(out): Option<String> = eval_to_source("eval('var recovered=1;')") else {
            panic!("capture must intercept eval");
        };
        assert_eq!(out, "var recovered=1;");
    }

    #[test]
    fn capture_intercepts_reflective_function_constructor() {
        let script: &str = "[][\"filter\"][\"constructor\"](\"return 'recovered-body'\")()";
        let Some(out): Option<String> = eval_to_source(script) else {
            panic!("capture must intercept the reflective Function constructor");
        };
        assert_eq!(out, "recovered-body");
    }

    #[test]
    fn capture_coerces_pure_string_expression() {
        let Some(out): Option<String> = eval_to_source("'al'+'pha'") else {
            panic!("capture must coerce a pure string expression");
        };
        assert_eq!(out, "alpha");
    }

    #[test]
    fn capture_rejects_oversized_script() {
        let big: String = "1".repeat(MAX_CAPTURE_SCRIPT_BYTES + 1);
        assert!(eval_to_source(&big).is_none());
    }

    #[test]
    fn coerces_numeric_to_string() {
        let Some(out): Option<String> = eval_to_string("1 + 2") else {
            panic!("eval must succeed");
        };
        assert_eq!(out, "3");
    }

    #[test]
    fn infinite_loop_dies_via_step_budget_not_wall_clock() {
        let started: std::time::Instant = std::time::Instant::now();
        let res: Option<String> = eval_to_string("while(true){}");
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "the deterministic loop-iteration budget must terminate the loop well before the {}s wall backstop; took {elapsed:?}",
            WALL_TIMEOUT_BACKSTOP.as_secs()
        );
        assert!(res.is_none());
    }

    #[test]
    fn unbounded_recursion_dies_via_step_budget() {
        let res: Option<String> = eval_to_string("(function r(){ return r(); })()");
        assert!(
            res.is_none(),
            "the recursion budget must reject unbounded self-recursion"
        );
    }

    #[test]
    fn fetch_is_unavailable() {
        let res: Option<String> = eval_to_string("typeof fetch");
        assert_eq!(res.as_deref(), Some("undefined"));
    }

    #[test]
    fn deeply_nested_parens_rejected_without_overflow() {
        let depth: usize = 5_000;
        let mut script: String = String::with_capacity(depth * 2 + 8);
        for _ in 0..depth {
            script.push('(');
        }
        script.push('1');
        for _ in 0..depth {
            script.push(')');
        }
        let res: Option<String> = eval_to_string(&script);
        assert!(
            res.is_none(),
            "pathologically nested script must be rejected pre-eval"
        );
    }

    #[test]
    fn brackets_inside_strings_do_not_count_toward_depth() {
        let mut script: String = String::from("'");
        for _ in 0..700 {
            script.push('(');
        }
        script.push('\'');
        let res: Option<String> = eval_to_string(&script);
        assert!(
            res.is_some(),
            "brackets inside a string literal must not trip the guard"
        );
    }

    #[test]
    fn moderate_nesting_still_evaluates() {
        let res: Option<String> = eval_to_string("(((((((((('ok'))))))))))");
        assert_eq!(res.as_deref(), Some("ok"));
    }

    #[test]
    fn moderate_nesting_evaluates_under_simulated_cpu_load() {
        let stop: std::sync::Arc<std::sync::atomic::AtomicBool> =
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hogs: Vec<thread::JoinHandle<()>> = Vec::new();
        let worker_count: usize = std::thread::available_parallelism()
            .map_or(4, std::num::NonZeroUsize::get)
            .saturating_mul(2)
            .max(4);
        for _ in 0..worker_count {
            let stop: std::sync::Arc<std::sync::atomic::AtomicBool> = stop.clone();
            hogs.push(thread::spawn(move || {
                let mut acc: u64 = 0;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    acc = acc.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                    std::hint::black_box(acc);
                }
            }));
        }
        for _ in 0..16 {
            let res: Option<String> = eval_to_string("(((((((((('ok'))))))))))");
            assert_eq!(
                res.as_deref(),
                Some("ok"),
                "the step-budget sandbox must return deterministically even under heavy parallel CPU load"
            );
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in hogs {
            let _ = h.join();
        }
    }
}
