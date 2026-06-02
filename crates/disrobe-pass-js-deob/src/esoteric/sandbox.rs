use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boa_engine::{Context, Source};

use crate::sandbox_guard::nesting_is_safe;

pub(super) const MAX_SCRIPT_BYTES: usize = 256 * 1024;
pub(super) const DEFAULT_WALL_TIMEOUT: Duration = Duration::from_secs(1);
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
            wall_timeout: DEFAULT_WALL_TIMEOUT,
            loop_iteration_limit: LOOP_ITERATION_LIMIT,
            recursion_limit: RECURSION_LIMIT,
            stack_size_limit: STACK_SIZE_LIMIT,
        }
    }
}

pub(super) fn eval_to_string(script: &str) -> Option<String> {
    eval_to_string_with_limits(script, SandboxLimits::default())
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
    fn coerces_numeric_to_string() {
        let Some(out): Option<String> = eval_to_string("1 + 2") else {
            panic!("eval must succeed");
        };
        assert_eq!(out, "3");
    }

    #[test]
    fn infinite_loop_dies_within_deadline() {
        let started: std::time::Instant = std::time::Instant::now();
        let res: Option<String> = eval_to_string("while(true){}");
        let elapsed: Duration = started.elapsed();
        assert!(elapsed < Duration::from_secs(2));
        assert!(res.is_none());
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
}
