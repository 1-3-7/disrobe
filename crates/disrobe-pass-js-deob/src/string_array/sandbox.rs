use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boa_engine::{Context, Source};
use serde::Serialize;

use crate::sandbox_guard::nesting_is_safe;

type ExprResults = Vec<Option<String>>;

const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const DEFAULT_WALL_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_LOOP_ITERATION_LIMIT: u64 = 100_000;
const DEFAULT_RECURSION_LIMIT: usize = 256;
const DEFAULT_STACK_SIZE_LIMIT: usize = 8 * 1024;
const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;
const RUNTIME_PREAMBLE: &str = "
Math.random = function () { return 0.5; };
Date.now = function () { return 1000; };
performance = { now: function () { return 1000; } };
delete globalThis.fetch;
Function.prototype.toString = function () { return 'function (){\\n[native code]\\n}'; };
Object.defineProperty(Function.prototype, 'toString', { value: function () { return 'function (){\\n[native code]\\n}'; }, writable: true, configurable: true });
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ProbeLimits {
    pub(super) wall_timeout: Duration,
    pub(super) loop_iteration_limit: u64,
    pub(super) recursion_limit: usize,
    pub(super) stack_size_limit: usize,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            wall_timeout: Duration::from_millis(DEFAULT_WALL_TIMEOUT_MS),
            loop_iteration_limit: DEFAULT_LOOP_ITERATION_LIMIT,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            stack_size_limit: DEFAULT_STACK_SIZE_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DecoderProbe {
    pub(super) indices_probed: usize,
    pub(super) successful: usize,
    pub(super) samples: Vec<DecoderSample>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct DecoderSample {
    pub(super) index: i64,
    pub(super) decoded: String,
}

pub(super) fn probe_expressions(prelude: &str, expressions: &[String]) -> Vec<Option<String>> {
    let limits: ProbeLimits = ProbeLimits::default();
    if prelude.len() > MAX_SCRIPT_BYTES || !nesting_is_safe(prelude) {
        return vec![None; expressions.len()];
    }
    let prelude_owned: String = prelude.to_owned();
    let exprs_owned: Vec<String> = expressions.to_vec();
    let (tx, rx): (mpsc::SyncSender<ExprResults>, mpsc::Receiver<ExprResults>) =
        mpsc::sync_channel::<ExprResults>(1);
    let expr_count: usize = expressions.len();
    let Ok(handle): std::io::Result<thread::JoinHandle<()>> = thread::Builder::new()
        .name("disrobe-boa-expr".to_owned())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let result: ExprResults = run_expressions(&prelude_owned, &exprs_owned, limits);
            let _ = tx.send(result);
        })
    else {
        return vec![None; expr_count];
    };
    let outcome: ExprResults = rx
        .recv_timeout(limits.wall_timeout)
        .unwrap_or_else(|_| vec![None; expr_count]);
    drop(handle);
    outcome
}

#[derive(Debug, Clone)]
pub(super) struct RotationSearchOutcome {
    pub(super) rotation: u32,
    pub(super) decoded: Vec<Option<String>>,
    #[allow(dead_code)]
    pub(super) score: u64,
}

const ROTATION_SEARCH_TIMEOUT_MS: u64 = 30_000;
const ROTATION_SEARCH_MAX_K: u32 = 4_096;
const ROTATION_SAMPLE_TARGET: usize = 24;
const ROTATION_MIN_SCORE_PER_SAMPLE: u64 = 6;
const ROTATION_EARLY_ACCEPT_PER_SAMPLE: u64 = 20;

pub(super) fn probe_with_rotation_search(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    array_len: usize,
) -> Option<RotationSearchOutcome> {
    if prelude.len() > MAX_SCRIPT_BYTES || !nesting_is_safe(prelude) {
        return None;
    }
    if expressions.is_empty() || array_len == 0 {
        return None;
    }
    let max_k: u32 = u32::try_from(array_len)
        .unwrap_or(u32::MAX)
        .min(ROTATION_SEARCH_MAX_K);
    let prelude_owned: String = prelude.to_owned();
    let provider_owned: String = provider_name.to_owned();
    let exprs_owned: Vec<String> = expressions.to_vec();
    let (tx, rx): (
        mpsc::SyncSender<Option<RotationSearchOutcome>>,
        mpsc::Receiver<Option<RotationSearchOutcome>>,
    ) = mpsc::sync_channel::<Option<RotationSearchOutcome>>(1);
    let Ok(handle): std::io::Result<thread::JoinHandle<()>> = thread::Builder::new()
        .name("disrobe-boa-rotsearch".to_owned())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let result: Option<RotationSearchOutcome> =
                run_rotation_search(&prelude_owned, &provider_owned, &exprs_owned, max_k);
            let _ = tx.send(result);
        })
    else {
        return None;
    };
    let outcome: Option<RotationSearchOutcome> = rx
        .recv_timeout(Duration::from_millis(ROTATION_SEARCH_TIMEOUT_MS))
        .ok()
        .flatten();
    drop(handle);
    outcome
}

fn run_rotation_search(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    max_k: u32,
) -> Option<RotationSearchOutcome> {
    let limits: ProbeLimits = ProbeLimits {
        wall_timeout: Duration::from_millis(ROTATION_SEARCH_TIMEOUT_MS),
        loop_iteration_limit: 10_000_000,
        recursion_limit: DEFAULT_RECURSION_LIMIT,
        stack_size_limit: DEFAULT_STACK_SIZE_LIMIT,
    };
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    if context
        .eval(Source::from_bytes(RUNTIME_PREAMBLE.as_bytes()))
        .is_err()
        || context
            .eval(Source::from_bytes(prelude.as_bytes()))
            .is_err()
    {
        return None;
    }
    let materialise: String = format!("var __disrobe_arr = {provider_name}();");
    if context
        .eval(Source::from_bytes(materialise.as_bytes()))
        .is_err()
    {
        return None;
    }
    let sample_indices: Vec<usize> = pick_sample_indices(expressions.len(), ROTATION_SAMPLE_TARGET);
    let sample_exprs: Vec<&String> = sample_indices.iter().map(|&i| &expressions[i]).collect();
    let early_accept_score: u64 =
        u64::try_from(sample_exprs.len()).unwrap_or(u64::MAX) * ROTATION_EARLY_ACCEPT_PER_SAMPLE;
    let min_score: u64 =
        u64::try_from(sample_exprs.len()).unwrap_or(u64::MAX) * ROTATION_MIN_SCORE_PER_SAMPLE;
    let mut best_k: u32 = 0;
    let mut best_score: u64 = 0;
    for k in 0..max_k {
        let sample_results: Vec<Option<String>> = eval_samples(&mut context, &sample_exprs);
        let score: u64 = score_samples(&sample_results);
        if score > best_score {
            best_score = score;
            best_k = k;
            if score >= early_accept_score {
                break;
            }
        }
        if context
            .eval(Source::from_bytes(
                b"__disrobe_arr.push(__disrobe_arr.shift());",
            ))
            .is_err()
        {
            break;
        }
    }
    if best_score < min_score {
        return None;
    }
    let mut fresh: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = fresh.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    if fresh
        .eval(Source::from_bytes(RUNTIME_PREAMBLE.as_bytes()))
        .is_err()
        || fresh.eval(Source::from_bytes(prelude.as_bytes())).is_err()
        || fresh
            .eval(Source::from_bytes(materialise.as_bytes()))
            .is_err()
    {
        return None;
    }
    let rotate_to: String =
        format!("for (var __i=0;__i<{best_k};__i++) __disrobe_arr.push(__disrobe_arr.shift());");
    if fresh
        .eval(Source::from_bytes(rotate_to.as_bytes()))
        .is_err()
    {
        return None;
    }
    let mut full: Vec<Option<String>> = Vec::with_capacity(expressions.len());
    for expr in expressions {
        let script: String = format!("String({expr})");
        let decoded: Option<String> = fresh
            .eval(Source::from_bytes(script.as_bytes()))
            .ok()
            .and_then(|v: boa_engine::JsValue| {
                v.as_string()
                    .map(boa_engine::JsString::to_std_string_escaped)
            });
        full.push(decoded);
    }
    Some(RotationSearchOutcome {
        rotation: best_k,
        decoded: full,
        score: best_score,
    })
}

fn eval_samples(context: &mut Context, sample_exprs: &[&String]) -> Vec<Option<String>> {
    let mut out: Vec<Option<String>> = Vec::with_capacity(sample_exprs.len());
    for expr in sample_exprs {
        let script: String = format!("String({expr})");
        let decoded: Option<String> = context
            .eval(Source::from_bytes(script.as_bytes()))
            .ok()
            .and_then(|v: boa_engine::JsValue| {
                v.as_string()
                    .map(boa_engine::JsString::to_std_string_escaped)
            });
        out.push(decoded);
    }
    out
}

fn pick_sample_indices(total: usize, target: usize) -> Vec<usize> {
    if total == 0 {
        return Vec::new();
    }
    let cap: usize = total.min(target.max(1));
    if total <= cap {
        return (0..total).collect();
    }
    let step: usize = total / cap;
    let mut out: Vec<usize> = Vec::with_capacity(cap);
    let mut i: usize = 0;
    while i < total && out.len() < cap {
        out.push(i);
        i = i.saturating_add(step.max(1));
    }
    out
}

fn score_samples(samples: &[Option<String>]) -> u64 {
    let mut score: u64 = 0;
    for sample in samples {
        let Some(text): &Option<String> = sample else {
            continue;
        };
        score = score.saturating_add(score_string(text));
    }
    score
}

fn score_string(text: &str) -> u64 {
    if text.is_empty() {
        return 1;
    }
    let bytes: &[u8] = text.as_bytes();
    let mut printable: usize = 0;
    let mut nonprintable: usize = 0;
    for &b in bytes {
        if is_printable_ascii(b) {
            printable += 1;
        } else {
            nonprintable += 1;
        }
    }
    let total: usize = printable + nonprintable;
    if total == 0 {
        return 1;
    }
    let printable_ratio_x100: u64 =
        (u64::try_from(printable).unwrap_or(0)) * 100 / u64::try_from(total).unwrap_or(1);
    if printable_ratio_x100 < 80 {
        return 1;
    }
    let mut score: u64 = 1 + printable_ratio_x100 / 20;
    if has_keyword_hit(text) {
        score = score.saturating_add(12);
    }
    if looks_like_identifier(text) {
        score = score.saturating_add(4);
    }
    score
}

const fn is_printable_ascii(b: u8) -> bool {
    matches!(b, 0x20..=0x7E | b'\n' | b'\r' | b'\t')
}

const KEYWORDS: &[&str] = &[
    "console",
    "log",
    "warn",
    "info",
    "error",
    "trace",
    "table",
    "prototype",
    "constructor",
    "toString",
    "Function",
    "Object",
    "Array",
    "Math",
    "length",
    "push",
    "shift",
    "apply",
    "bind",
    "call",
    "indexOf",
    "charAt",
    "charCodeAt",
    "fromCharCode",
    "slice",
    "split",
    "join",
    "concat",
    "replace",
    "search",
    "match",
    "test",
    "exec",
    "return",
    "undefined",
    "null",
    "true",
    "false",
    "forEach",
    "map",
    "filter",
    "reduce",
    "decodeURIComponent",
    "encodeURIComponent",
    "String",
    "Number",
    "Boolean",
    "window",
    "document",
    "globalThis",
];

fn has_keyword_hit(text: &str) -> bool {
    KEYWORDS.iter().any(|kw| text == *kw || text.contains(kw))
}

fn looks_like_identifier(text: &str) -> bool {
    let bytes: &[u8] = text.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    let first_ok: bool = matches!(bytes[0], b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$');
    if !first_ok {
        return false;
    }
    bytes
        .iter()
        .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_' | b'$'))
}

fn run_expressions(
    prelude: &str,
    expressions: &[String],
    limits: ProbeLimits,
) -> Vec<Option<String>> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    if context
        .eval(Source::from_bytes(RUNTIME_PREAMBLE.as_bytes()))
        .is_err()
        || context
            .eval(Source::from_bytes(prelude.as_bytes()))
            .is_err()
    {
        return vec![None; expressions.len()];
    }
    let mut out: Vec<Option<String>> = Vec::with_capacity(expressions.len());
    for expr in expressions {
        let script: String = format!("String({expr})");
        let decoded: Option<String> = context
            .eval(Source::from_bytes(script.as_bytes()))
            .ok()
            .and_then(|v: boa_engine::JsValue| {
                v.as_string()
                    .map(boa_engine::JsString::to_std_string_escaped)
            });
        out.push(decoded);
    }
    out
}

pub(super) fn probe_decoder(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
) -> Option<DecoderProbe> {
    probe_decoder_with_limits(
        decoder_source,
        string_array_source,
        decoder_name,
        indices,
        ProbeLimits::default(),
    )
}

pub(super) fn probe_decoder_with_limits(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
    limits: ProbeLimits,
) -> Option<DecoderProbe> {
    if decoder_source.len() + string_array_source.len() > MAX_SCRIPT_BYTES {
        return None;
    }
    if !nesting_is_safe(decoder_source) || !nesting_is_safe(string_array_source) {
        return None;
    }
    let decoder_owned: String = decoder_source.to_owned();
    let array_owned: String = string_array_source.to_owned();
    let name_owned: String = decoder_name.to_owned();
    let indices_owned: Vec<i64> = indices.to_vec();
    let (tx, rx): (
        mpsc::SyncSender<Option<DecoderProbe>>,
        mpsc::Receiver<Option<DecoderProbe>>,
    ) = mpsc::sync_channel::<Option<DecoderProbe>>(1);
    let Ok(handle): std::io::Result<thread::JoinHandle<()>> = thread::Builder::new()
        .name("disrobe-boa-probe".to_owned())
        .stack_size(WORKER_STACK_BYTES)
        .spawn(move || {
            let result: Option<DecoderProbe> = run_probe(
                &decoder_owned,
                &array_owned,
                &name_owned,
                &indices_owned,
                limits,
            );
            let _ = tx.send(result);
        })
    else {
        return None;
    };
    let outcome: Option<DecoderProbe> = rx.recv_timeout(limits.wall_timeout).ok().flatten();
    drop(handle);
    outcome
}

fn run_probe(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
    limits: ProbeLimits,
) -> Option<DecoderProbe> {
    let mut context: Context = Context::default();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    if context
        .eval(Source::from_bytes(RUNTIME_PREAMBLE.as_bytes()))
        .is_err()
    {
        return None;
    }
    if context
        .eval(Source::from_bytes(string_array_source.as_bytes()))
        .is_err()
    {
        return None;
    }
    if context
        .eval(Source::from_bytes(decoder_source.as_bytes()))
        .is_err()
    {
        return None;
    }
    let mut samples: Vec<DecoderSample> = Vec::with_capacity(indices.len());
    let mut successful: usize = 0;
    for &idx in indices {
        let script: String = format!("String({decoder_name}({idx}))");
        if let Ok(value) = context.eval(Source::from_bytes(script.as_bytes()))
            && let Some(decoded) = value
                .as_string()
                .map(boa_engine::JsString::to_std_string_escaped)
        {
            successful += 1;
            samples.push(DecoderSample {
                index: idx,
                decoded,
            });
        }
    }
    Some(DecoderProbe {
        indices_probed: indices.len(),
        successful,
        samples,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[test]
    fn probe_simple_lookup() {
        let arr: &str = "var _arr = ['hello','world','log'];";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        let Some(probe): Option<DecoderProbe> = probe_decoder(dec, arr, "_decode", &[0, 1, 2])
        else {
            panic!("probe must succeed for simple decoder");
        };
        assert_eq!(probe.indices_probed, 3);
        assert_eq!(probe.successful, 3);
        assert_eq!(probe.samples[0].decoded, "hello");
        assert_eq!(probe.samples[1].decoded, "world");
        assert_eq!(probe.samples[2].decoded, "log");
    }

    #[test]
    fn probe_with_offset() {
        let arr: &str = "var _arr = ['x','y','z'];";
        let dec: &str = "function _dec(i) { return _arr[i - 0x1]; }";
        let Some(probe): Option<DecoderProbe> = probe_decoder(dec, arr, "_dec", &[1, 2, 3]) else {
            panic!("probe must succeed with offset decoder");
        };
        assert_eq!(probe.successful, 3);
        assert_eq!(probe.samples[0].decoded, "x");
        assert_eq!(probe.samples[2].decoded, "z");
    }

    #[test]
    fn probe_handles_bad_decoder() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "this is not valid js {";
        let probe: Option<DecoderProbe> = probe_decoder(dec, arr, "_dec", &[0]);
        let bad: bool = probe.is_none_or(|p| p.successful == 0);
        assert!(bad);
    }

    #[test]
    fn probe_rejects_infinite_loop_within_deadline() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "function _decode(i) { while(true) {} return ''; }";
        let started: Instant = Instant::now();
        let probe: Option<DecoderProbe> = probe_decoder(dec, arr, "_decode", &[0]);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "infinite loop should be killed within 3s, took {elapsed:?}",
        );
        let safe: bool = probe.is_none_or(|p| p.successful == 0);
        assert!(safe, "infinite loop must not yield successful decode");
    }

    #[test]
    fn probe_rejects_unbounded_recursion() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "function _decode(i) { return _decode(i); }";
        let started: Instant = Instant::now();
        let probe: Option<DecoderProbe> = probe_decoder(dec, arr, "_decode", &[0]);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "recursion bomb should be killed within 3s, took {elapsed:?}",
        );
        let safe: bool = probe.is_none_or(|p| p.successful == 0);
        assert!(safe, "unbounded recursion must not yield successful decode");
    }
}
