use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use boa_engine::{Context, Source};
use serde::Serialize;

const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const DEFAULT_WALL_TIMEOUT_MS: u64 = 2_000;
const DEFAULT_LOOP_ITERATION_LIMIT: u64 = 100_000;
const DEFAULT_RECURSION_LIMIT: usize = 256;
const DEFAULT_STACK_SIZE_LIMIT: usize = 8 * 1024;
const WORKER_STACK_BYTES: usize = 2 * 1024 * 1024;
const RUNTIME_PREAMBLE: &str = "
Math.random = function () { return 0.5; };
Date.now = function () { return 1000; };
performance = { now: function () { return 1000; } };
delete globalThis.fetch;
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
