use std::fmt::Write;
use std::future::Future;
use std::sync::{Condvar, Mutex, OnceLock};
use std::task::{Context as TaskContext, Poll, Waker};
use std::thread;
use std::time::{Duration, Instant};

use boa_engine::{Context, JsError, Script, Source};
use serde::Serialize;

use crate::sandbox_guard::nesting_is_safe;

type ExprResults = Vec<Option<String>>;
type EnvironmentRun<T> = Result<EnvironmentResult<T>, ProbeRefusal>;
type EnvironmentPair<T> = (EnvironmentRun<T>, EnvironmentRun<T>);

pub(super) const MAX_SCRIPT_BYTES: usize = 256 * 1024;
const MAX_EXPRESSION_BYTES: usize = 64 * 1024;
const MAX_AGGREGATE_EXPRESSION_BYTES: usize = 4 * 1024 * 1024;
const MAX_GENERATED_SCRIPT_BYTES: usize = 4 * 1024 * 1024;
const MAX_DECODED_VALUE_BYTES: usize = 64 * 1024;
const MAX_DECODED_TOTAL_BYTES: usize = 4 * 1024 * 1024;
const MAX_BATCH_JSON_BYTES: usize = 8 * 1024 * 1024;
const MAX_BATCH_OUTPUT_UNITS: usize = 1024 * 1024;
const MAX_ENVIRONMENT_CALLS: u64 = 10_000_000;
const MAX_CONCURRENT_PROBES: usize = 1;
const MAX_ADMISSION_WAIT_MS: u64 = 30_000;
pub(super) const MAX_PROBE_EXPRESSIONS: usize = 65_536;
const BATCH_SCRIPT_PREFIX: &str = "(function(){var b=0,t=0,fs=[";
const BATCH_SCRIPT_SUFFIX_VALUE: &str = "],r=[];for(var i=0;i<fs.length;i++){var f=fs[i];if(b){r[i]=[2,''];continue;}try{var v=f();t+=v.length;if(v.length>";
const BATCH_SCRIPT_SUFFIX_TOTAL: &str = "||t>";
const BATCH_SCRIPT_SUFFIX_END: &str = "){b=1;r[i]=[2,''];}else{r[i]=[1,v];}}catch(e){r[i]=[0,e instanceof __disrobe_native_reference_error?'ReferenceError':'Error'];}}return __disrobe_native_json_stringify(r);})()";
const BATCH_WRAPPER_PREFIX: &str = "function(){return __disrobe_native_string(";
const BATCH_WRAPPER_SUFFIX: &str = ");}";
const DEFAULT_WALL_TIMEOUT_MS: u64 = 4_000;
const DEFAULT_LOOP_ITERATION_LIMIT: u64 = 100_000;
const DEFAULT_RECURSION_LIMIT: usize = 256;
const DEFAULT_STACK_SIZE_LIMIT: usize = 8 * 1024;
const WORKER_STACK_BYTES: usize = 64 * 1024 * 1024;
static PROBE_SLOTS: OnceLock<ProbeSlots> = OnceLock::new();

#[cfg(test)]
static ACTIVE_ENVIRONMENTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static PEAK_ENVIRONMENTS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const FIRST_ENVIRONMENT: ProbeEnvironment = ProbeEnvironment {
    seed: 0x243f_6a88,
    date_now: 1_700_000_000_137,
    performance_now: 137,
};
const SECOND_ENVIRONMENT: ProbeEnvironment = ProbeEnvironment {
    seed: 0x85a3_08d3,
    date_now: 1_700_000_009_973,
    performance_now: 9_973,
};
const RUNTIME_SUPPORT: &str = r"
delete globalThis.fetch;
Object.defineProperty(globalThis, '__disrobe_native_string', { value: String, writable: false, configurable: false });
Object.defineProperty(globalThis, '__disrobe_native_json_stringify', { value: JSON.stringify, writable: false, configurable: false });
Object.defineProperty(globalThis, '__disrobe_native_reference_error', { value: ReferenceError, writable: false, configurable: false });
Function.prototype.toString = function () { return 'function (){\n[native code]\n}'; };
Object.defineProperty(Function.prototype, 'toString', { value: function () { return 'function (){\n[native code]\n}'; }, writable: true, configurable: true });
if (typeof globalThis.atob !== 'function') {
  globalThis.atob = function (data) {
    var input = __disrobe_native_string(data).replace(/[\t\n\f\r ]+/g, '');
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var padless = input.replace(/=+$/, '');
    if (padless.length % 4 === 1) { throw new Error('atob: invalid length'); }
    var output = '';
    var acc = 0;
    var bits = 0;
    for (var i = 0; i < padless.length; i++) {
      var code = chars.indexOf(padless.charAt(i));
      if (code === -1) { throw new Error('atob: invalid base64'); }
      acc = (acc << 6) | code;
      bits += 6;
      if (bits >= 8) { bits -= 8; output += String.fromCharCode((acc >> bits) & 255); }
    }
    return output;
  };
}
if (typeof globalThis.btoa !== 'function') {
  globalThis.btoa = function (data) {
    var input = __disrobe_native_string(data);
    var chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
    var output = '';
    for (var i = 0; i < input.length; i += 3) {
      var c0 = input.charCodeAt(i);
      var c1 = input.charCodeAt(i + 1);
      var c2 = input.charCodeAt(i + 2);
      var hasC1 = i + 1 < input.length;
      var hasC2 = i + 2 < input.length;
      if (c0 > 255 || (hasC1 && c1 > 255) || (hasC2 && c2 > 255)) { throw new Error('btoa: invalid character'); }
      var n0 = c0 >> 2;
      var n1 = ((c0 & 3) << 4) | (hasC1 ? (c1 >> 4) : 0);
      var n2 = hasC1 ? (((c1 & 15) << 2) | (hasC2 ? (c2 >> 6) : 0)) : 64;
      var n3 = hasC2 ? (c2 & 63) : 64;
      output += chars.charAt(n0) + chars.charAt(n1) + (n2 === 64 ? '=' : chars.charAt(n2)) + (n3 === 64 ? '=' : chars.charAt(n3));
    }
    return output;
  };
}
";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProbeEnvironment {
    seed: u32,
    date_now: u64,
    performance_now: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProbeRefusal {
    InputTooLarge,
    UnsafeNesting,
    WorkerSpawn,
    WallTimeout,
    BoundExceeded,
    EnvironmentAbsent,
    EvaluationFailed,
    SeedConditionalThrow,
    EnvironmentDesynchronized,
    EnvironmentDisagreement,
    NoCandidates,
    RotationNotFound,
}

#[derive(Debug)]
struct ProbeSlots {
    active: Mutex<usize>,
    available: Condvar,
}

struct ProbePermit {
    slots: &'static ProbeSlots,
}

impl Drop for ProbePermit {
    fn drop(&mut self) {
        let mut active: std::sync::MutexGuard<'_, usize> = match self.slots.active.lock() {
            Ok(active) => active,
            Err(poisoned) => poisoned.into_inner(),
        };
        *active = active.saturating_sub(1);
        drop(active);
        self.slots.available.notify_one();
    }
}

#[derive(Debug, Clone, Copy)]
struct ProbeDeadline {
    expires_at: Instant,
}

impl ProbeDeadline {
    fn from_timeout(timeout: Duration) -> Self {
        let started: Instant = Instant::now();
        let expires_at: Instant = started.checked_add(timeout).unwrap_or(started);
        Self { expires_at }
    }

    fn remaining(self) -> Option<Duration> {
        self.expires_at.checked_duration_since(Instant::now())
    }

    fn expired(self) -> bool {
        self.remaining()
            .is_none_or(|remaining: Duration| remaining.is_zero())
    }
}

#[derive(Debug)]
struct OutputBudget {
    bytes: usize,
}

impl OutputBudget {
    const fn new() -> Self {
        Self { bytes: 0 }
    }

    fn accept(&mut self, value: &str) -> Result<(), ProbeRefusal> {
        if value.len() > MAX_DECODED_VALUE_BYTES {
            return Err(ProbeRefusal::BoundExceeded);
        }
        self.bytes = self
            .bytes
            .checked_add(value.len())
            .ok_or(ProbeRefusal::BoundExceeded)?;
        if self.bytes > MAX_DECODED_TOTAL_BYTES {
            return Err(ProbeRefusal::BoundExceeded);
        }
        Ok(())
    }
}

fn acquire_probe_permit(deadline: ProbeDeadline) -> Result<ProbePermit, ProbeRefusal> {
    let slots: &'static ProbeSlots = PROBE_SLOTS.get_or_init(|| ProbeSlots {
        active: Mutex::new(0),
        available: Condvar::new(),
    });
    acquire_probe_permit_from(slots, deadline)
}

fn acquire_probe_permit_from(
    slots: &'static ProbeSlots,
    deadline: ProbeDeadline,
) -> Result<ProbePermit, ProbeRefusal> {
    let mut active: std::sync::MutexGuard<'_, usize> = match slots.active.lock() {
        Ok(active) => active,
        Err(poisoned) => poisoned.into_inner(),
    };
    loop {
        if deadline.expired() {
            return Err(ProbeRefusal::WallTimeout);
        }
        if *active < MAX_CONCURRENT_PROBES {
            *active += 1;
            return Ok(ProbePermit { slots });
        }
        let Some(remaining): Option<Duration> = deadline.remaining() else {
            return Err(ProbeRefusal::WallTimeout);
        };
        let (next, wait): (
            std::sync::MutexGuard<'_, usize>,
            std::sync::WaitTimeoutResult,
        ) = match slots.available.wait_timeout(active, remaining) {
            Ok(result) => result,
            Err(poisoned) => poisoned.into_inner(),
        };
        active = next;
        if wait.timed_out() && *active >= MAX_CONCURRENT_PROBES {
            return Err(ProbeRefusal::WallTimeout);
        }
    }
}

fn run_scoped_probe<T, F>(name: &str, limits: ProbeLimits, run: F) -> Result<T, ProbeRefusal>
where
    T: Send,
    F: FnOnce(ProbeDeadline) -> Result<T, ProbeRefusal> + Send,
{
    let admission_deadline: ProbeDeadline =
        ProbeDeadline::from_timeout(Duration::from_millis(MAX_ADMISSION_WAIT_MS));
    let _permit: ProbePermit = acquire_probe_permit(admission_deadline)?;
    let deadline: ProbeDeadline = ProbeDeadline::from_timeout(limits.wall_timeout);
    run_joined_worker(name, deadline, run)
}

fn run_joined_worker<T, F>(name: &str, deadline: ProbeDeadline, run: F) -> Result<T, ProbeRefusal>
where
    T: Send,
    F: FnOnce(ProbeDeadline) -> Result<T, ProbeRefusal> + Send,
{
    let outcome: Result<T, ProbeRefusal> = thread::scope(|scope: &thread::Scope<'_, '_>| {
        let worker: thread::ScopedJoinHandle<'_, Result<T, ProbeRefusal>> = thread::Builder::new()
            .name(name.to_owned())
            .stack_size(WORKER_STACK_BYTES)
            .spawn_scoped(scope, move || run(deadline))
            .map_err(|_| ProbeRefusal::WorkerSpawn)?;
        worker.join().map_err(|_| ProbeRefusal::EvaluationFailed)?
    });
    if outcome.is_ok() && deadline.expired() {
        Err(ProbeRefusal::WallTimeout)
    } else {
        outcome
    }
}

fn validate_expressions(expressions: &[String]) -> Result<(), ProbeRefusal> {
    validate_expression_lengths(expressions.iter().map(String::len), expressions.len())
}

pub(super) fn validate_expression_lengths(
    expression_lengths: impl IntoIterator<Item = usize>,
    expression_count: usize,
) -> Result<(), ProbeRefusal> {
    if expression_count > MAX_PROBE_EXPRESSIONS {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let mut aggregate: usize = 0;
    let mut observed: usize = 0;
    for expression_len in expression_lengths {
        observed = observed.checked_add(1).ok_or(ProbeRefusal::BoundExceeded)?;
        if expression_len > MAX_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        aggregate = aggregate
            .checked_add(expression_len)
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if aggregate > MAX_AGGREGATE_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
    }
    if observed != expression_count {
        return Err(ProbeRefusal::BoundExceeded);
    }
    Ok(())
}

fn validate_batched_expressions(expressions: &[String]) -> Result<(), ProbeRefusal> {
    validate_batched_expression_lengths(expressions.iter().map(String::len), expressions.len())
}

pub(super) fn validate_batched_expression_lengths(
    expression_lengths: impl IntoIterator<Item = usize>,
    expression_count: usize,
) -> Result<(), ProbeRefusal> {
    if expression_count > MAX_PROBE_EXPRESSIONS {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let mut aggregate: usize = 0;
    let mut batch_capacity: usize = batch_script_capacity(std::iter::empty(), 0)?;
    let mut batch_count: usize = 0;
    let mut observed: usize = 0;
    for expression_len in expression_lengths {
        observed = observed.checked_add(1).ok_or(ProbeRefusal::BoundExceeded)?;
        if expression_len > MAX_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        aggregate = aggregate
            .checked_add(expression_len)
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if aggregate > MAX_AGGREGATE_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        batch_capacity = batch_capacity
            .checked_add(BATCH_WRAPPER_PREFIX.len())
            .and_then(|value: usize| value.checked_add(expression_len))
            .and_then(|value: usize| value.checked_add(BATCH_WRAPPER_SUFFIX.len()))
            .and_then(|value: usize| value.checked_add(usize::from(batch_count > 0)))
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if batch_capacity > MAX_GENERATED_SCRIPT_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        batch_count += 1;
        if batch_count == DECODE_BATCH_CHUNK {
            batch_capacity = batch_script_capacity(std::iter::empty(), 0)?;
            batch_count = 0;
        }
    }
    if observed != expression_count {
        return Err(ProbeRefusal::BoundExceeded);
    }
    Ok(())
}

fn batch_script_capacity(
    expression_lengths: impl IntoIterator<Item = usize>,
    expression_count: usize,
) -> Result<usize, ProbeRefusal> {
    if expression_count > DECODE_BATCH_CHUNK {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let mut capacity: usize = BATCH_SCRIPT_PREFIX
        .len()
        .checked_add(BATCH_SCRIPT_SUFFIX_VALUE.len())
        .and_then(|value: usize| value.checked_add(usize_decimal_len(MAX_DECODED_VALUE_BYTES)))
        .and_then(|value: usize| value.checked_add(BATCH_SCRIPT_SUFFIX_TOTAL.len()))
        .and_then(|value: usize| value.checked_add(usize_decimal_len(MAX_BATCH_OUTPUT_UNITS)))
        .and_then(|value: usize| value.checked_add(BATCH_SCRIPT_SUFFIX_END.len()))
        .ok_or(ProbeRefusal::InputTooLarge)?;
    for (index, expression_len) in expression_lengths.into_iter().enumerate() {
        capacity = capacity
            .checked_add(BATCH_WRAPPER_PREFIX.len())
            .and_then(|value: usize| value.checked_add(expression_len))
            .and_then(|value: usize| value.checked_add(BATCH_WRAPPER_SUFFIX.len()))
            .and_then(|value: usize| value.checked_add(usize::from(index > 0)))
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if capacity > MAX_GENERATED_SCRIPT_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
    }
    Ok(capacity)
}

fn validate_prelude(prelude: &str) -> Result<(), ProbeRefusal> {
    if prelude.len() > MAX_SCRIPT_BYTES {
        return Err(ProbeRefusal::InputTooLarge);
    }
    if !nesting_is_safe(prelude) {
        return Err(ProbeRefusal::UnsafeNesting);
    }
    Ok(())
}

fn validate_decoder_expression_plan(
    decoder_name: &str,
    indices: &[i64],
) -> Result<(), ProbeRefusal> {
    let mut aggregate: usize = 0;
    let mut batch_capacity: usize = batch_script_capacity(std::iter::empty(), 0)?;
    let mut batch_count: usize = 0;
    for index in indices {
        let expression_len: usize = decoder_name
            .len()
            .checked_add(i64_decimal_len(*index))
            .and_then(|value: usize| value.checked_add(2))
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if expression_len > MAX_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        aggregate = aggregate
            .checked_add(expression_len)
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if aggregate > MAX_AGGREGATE_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        batch_capacity = batch_capacity
            .checked_add(BATCH_WRAPPER_PREFIX.len())
            .and_then(|value: usize| value.checked_add(expression_len))
            .and_then(|value: usize| value.checked_add(BATCH_WRAPPER_SUFFIX.len()))
            .and_then(|value: usize| value.checked_add(usize::from(batch_count > 0)))
            .ok_or(ProbeRefusal::InputTooLarge)?;
        if batch_capacity > MAX_GENERATED_SCRIPT_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
        batch_count += 1;
        if batch_count == DECODE_BATCH_CHUNK {
            batch_capacity = batch_script_capacity(std::iter::empty(), 0)?;
            batch_count = 0;
        }
    }
    Ok(())
}

const fn i64_decimal_len(value: i64) -> usize {
    let mut magnitude: u64 = value.unsigned_abs();
    let mut digits: usize = 1;
    while magnitude >= 10 {
        magnitude /= 10;
        digits += 1;
    }
    digits + if value.is_negative() { 1 } else { 0 }
}

const fn usize_decimal_len(mut value: usize) -> usize {
    let mut digits: usize = 1;
    while value >= 10 {
        value /= 10;
        digits += 1;
    }
    digits
}

fn runtime_preamble(environment: ProbeEnvironment) -> String {
    format!(
        r"var __disrobe_prng_state = {seed} >>> 0;
var __disrobe_random_calls = 0;
var __disrobe_date_calls = 0;
var __disrobe_performance_calls = 0;
Math.random = function () {{
  __disrobe_random_calls++;
  __disrobe_prng_state = (__disrobe_prng_state + 0x6D2B79F5) >>> 0;
  var t = __disrobe_prng_state;
  t = Math.imul(t ^ (t >>> 15), t | 1);
  t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}};
Date.now = function () {{ __disrobe_date_calls++; return {date_now}; }};
performance = {{ now: function () {{ __disrobe_performance_calls++; return {performance_now}; }} }};
{RUNTIME_SUPPORT}",
        seed = environment.seed,
        date_now = environment.date_now,
        performance_now = environment.performance_now,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) struct ProbeLimits {
    pub(super) wall_timeout: Duration,
    pub(super) loop_iteration_limit: u64,
    pub(super) recursion_limit: usize,
    pub(super) stack_size_limit: usize,
    #[cfg(test)]
    pub(super) track_activity: bool,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            wall_timeout: Duration::from_millis(DEFAULT_WALL_TIMEOUT_MS),
            loop_iteration_limit: DEFAULT_LOOP_ITERATION_LIMIT,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            stack_size_limit: DEFAULT_STACK_SIZE_LIMIT,
            #[cfg(test)]
            track_activity: false,
        }
    }
}

const fn tracks_activity(limits: ProbeLimits) -> bool {
    #[cfg(test)]
    {
        limits.track_activity
    }
    #[cfg(not(test))]
    {
        let _: ProbeLimits = limits;
        false
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct DecoderProbe {
    pub(super) indices_probed: usize,
    pub(super) successful: usize,
    pub(super) samples: Vec<DecoderSample>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct DecoderSample {
    pub(super) index: i64,
    pub(super) decoded: String,
}

pub(super) fn probe_expressions(
    prelude: &str,
    expressions: &[String],
) -> Result<Vec<Option<String>>, ProbeRefusal> {
    let limits: ProbeLimits = ProbeLimits::default();
    validate_prelude(prelude)?;
    validate_batched_expressions(expressions)?;
    run_scoped_probe("disrobe-boa-expr", limits, |deadline: ProbeDeadline| {
        run_expressions(prelude, expressions, limits, deadline)
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RotationSearchOutcome {
    pub(super) rotation: u32,
    pub(super) decoded: Vec<Option<String>>,
    #[allow(dead_code)]
    pub(super) score: u64,
    failed_evaluations: usize,
}

const ROTATION_SEARCH_TIMEOUT_MS: u64 = 180_000;
const ROTATION_SEARCH_MAX_K: u32 = 4_096;
const ROTATION_SAMPLE_TARGET: usize = 24;
const ROTATION_MIN_SCORE_PER_SAMPLE: u64 = 6;
const ROTATION_EARLY_ACCEPT_PER_SAMPLE: u64 = 20;

pub(super) fn probe_with_rotation_search(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    array_len: usize,
) -> Result<RotationSearchOutcome, ProbeRefusal> {
    validate_prelude(prelude)?;
    validate_batched_expressions(expressions)?;
    if expressions.is_empty() || array_len == 0 {
        return Err(ProbeRefusal::NoCandidates);
    }
    let max_k: u32 = u32::try_from(array_len)
        .unwrap_or(u32::MAX)
        .min(ROTATION_SEARCH_MAX_K);
    let limits: ProbeLimits = rotation_probe_limits();
    run_scoped_probe(
        "disrobe-boa-rotsearch",
        limits,
        |deadline: ProbeDeadline| {
            run_rotation_search(prelude, provider_name, expressions, max_k, limits, deadline)
        },
    )
}

fn run_rotation_search(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    max_k: u32,
    limits: ProbeLimits,
    deadline: ProbeDeadline,
) -> Result<RotationSearchOutcome, ProbeRefusal> {
    let (first, second): (
        Result<EnvironmentResult<RotationSearchOutcome>, ProbeRefusal>,
        Result<EnvironmentResult<RotationSearchOutcome>, ProbeRefusal>,
    ) = run_environment_pair(
        |environment: ProbeEnvironment| {
            run_rotation_search_once(
                prelude,
                provider_name,
                expressions,
                max_k,
                limits,
                environment,
                deadline,
            )
        },
        deadline,
        tracks_activity(limits),
    )?;
    compare_rotation_search_results(first, second)
}

const fn rotation_probe_limits() -> ProbeLimits {
    ProbeLimits {
        wall_timeout: Duration::from_millis(ROTATION_SEARCH_TIMEOUT_MS),
        loop_iteration_limit: 10_000_000,
        recursion_limit: DEFAULT_RECURSION_LIMIT,
        stack_size_limit: DEFAULT_STACK_SIZE_LIMIT,
        #[cfg(test)]
        track_activity: false,
    }
}

fn compare_rotation_search_results(
    first: Result<EnvironmentResult<RotationSearchOutcome>, ProbeRefusal>,
    second: Result<EnvironmentResult<RotationSearchOutcome>, ProbeRefusal>,
) -> Result<RotationSearchOutcome, ProbeRefusal> {
    let (left, right): (
        EnvironmentResult<RotationSearchOutcome>,
        EnvironmentResult<RotationSearchOutcome>,
    ) = match (first, second) {
        (Ok(left), Ok(right)) => (left, right),
        (left, right) => return compare_environment_results(left, right),
    };
    if left.calls != right.calls {
        return Err(ProbeRefusal::EnvironmentDesynchronized);
    }
    if left.value.failed_evaluations != right.value.failed_evaluations {
        return Err(ProbeRefusal::SeedConditionalThrow);
    }
    if left.value != right.value {
        return Err(ProbeRefusal::EnvironmentDisagreement);
    }
    Ok(left.value)
}

fn run_rotation_search_once(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    max_k: u32,
    limits: ProbeLimits,
    environment: ProbeEnvironment,
    deadline: ProbeDeadline,
) -> Result<EnvironmentResult<RotationSearchOutcome>, ProbeRefusal> {
    let mut context: Context = Context::default();
    let mut output_budget: OutputBudget = OutputBudget::new();
    let first_runtime_preamble: String = runtime_preamble(environment);
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    evaluate(&mut context, &first_runtime_preamble, deadline)?;
    evaluate(&mut context, prelude, deadline)?;
    let materialise: String = format!("var __disrobe_arr = {provider_name}();");
    validate_generated_script(&materialise)?;
    evaluate(&mut context, &materialise, deadline)?;
    let sample_indices: Vec<usize> = pick_sample_indices(expressions.len(), ROTATION_SAMPLE_TARGET);
    let sample_exprs: Vec<&String> = sample_indices.iter().map(|&i| &expressions[i]).collect();
    let batch_script: String = build_batch_decode_script(&sample_exprs)?;
    let early_accept_score: u64 =
        u64::try_from(sample_exprs.len()).unwrap_or(u64::MAX) * ROTATION_EARLY_ACCEPT_PER_SAMPLE;
    let min_score: u64 =
        u64::try_from(sample_exprs.len()).unwrap_or(u64::MAX) * ROTATION_MIN_SCORE_PER_SAMPLE;
    let mut best_k: u32 = 0;
    let mut best_score: u64 = 0;
    let mut failed_evaluations: usize = 0;
    for k in 0..max_k {
        let sample_run: BatchRun = eval_batch(
            &mut context,
            &batch_script,
            sample_exprs.len(),
            &mut output_budget,
            deadline,
        )?;
        failed_evaluations = failed_evaluations
            .checked_add(sample_run.failed)
            .ok_or(ProbeRefusal::BoundExceeded)?;
        let score: u64 = score_samples(&sample_run.values);
        if score > best_score {
            best_score = score;
            best_k = k;
            if score >= early_accept_score {
                break;
            }
        }
        evaluate(
            &mut context,
            "__disrobe_arr.push(__disrobe_arr.shift());",
            deadline,
        )?;
    }
    if best_score < min_score {
        return Err(ProbeRefusal::RotationNotFound);
    }
    let search_calls: [u64; 3] = environment_calls(&mut context, deadline)?;
    let mut fresh: Context = Context::default();
    let fresh_runtime_preamble: String = runtime_preamble(environment);
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = fresh.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    evaluate(&mut fresh, &fresh_runtime_preamble, deadline)?;
    evaluate(&mut fresh, prelude, deadline)?;
    evaluate(&mut fresh, &materialise, deadline)?;
    let rotate_to: String =
        format!("for (var __i=0;__i<{best_k};__i++) __disrobe_arr.push(__disrobe_arr.shift());");
    validate_generated_script(&rotate_to)?;
    evaluate(&mut fresh, &rotate_to, deadline)?;
    let full: BatchRun = decode_all(&mut fresh, expressions, &mut output_budget, deadline)?;
    failed_evaluations = failed_evaluations
        .checked_add(full.failed)
        .ok_or(ProbeRefusal::BoundExceeded)?;
    let fresh_calls: [u64; 3] = environment_calls(&mut fresh, deadline)?;
    let calls: [u64; 3] = add_environment_calls(search_calls, fresh_calls)?;
    Ok(EnvironmentResult {
        value: RotationSearchOutcome {
            rotation: best_k,
            decoded: full.values,
            score: best_score,
            failed_evaluations,
        },
        calls,
    })
}

pub(super) fn probe_rotation_to_match(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    reference: &[Option<String>],
    array_len: usize,
) -> Result<u32, ProbeRefusal> {
    validate_prelude(prelude)?;
    validate_batched_expressions(expressions)?;
    if expressions.len() != reference.len() {
        return Err(ProbeRefusal::NoCandidates);
    }
    let mut reference_bytes: usize = 0;
    for value in reference.iter().flatten() {
        if value.len() > MAX_DECODED_VALUE_BYTES {
            return Err(ProbeRefusal::BoundExceeded);
        }
        reference_bytes = reference_bytes
            .checked_add(value.len())
            .ok_or(ProbeRefusal::BoundExceeded)?;
        if reference_bytes > MAX_DECODED_TOTAL_BYTES {
            return Err(ProbeRefusal::BoundExceeded);
        }
    }
    if expressions.is_empty() || array_len == 0 {
        return Err(ProbeRefusal::NoCandidates);
    }
    let max_k: u32 = u32::try_from(array_len)
        .unwrap_or(u32::MAX)
        .min(ROTATION_SEARCH_MAX_K);
    let limits: ProbeLimits = rotation_probe_limits();
    run_scoped_probe("disrobe-boa-rotmatch", limits, |deadline: ProbeDeadline| {
        run_rotation_to_match(
            prelude,
            provider_name,
            expressions,
            reference,
            max_k,
            limits,
            deadline,
        )
    })
}

fn run_rotation_to_match(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    reference: &[Option<String>],
    max_k: u32,
    limits: ProbeLimits,
    deadline: ProbeDeadline,
) -> Result<u32, ProbeRefusal> {
    let (first, second): (
        Result<EnvironmentResult<RotationMatchRun>, ProbeRefusal>,
        Result<EnvironmentResult<RotationMatchRun>, ProbeRefusal>,
    ) = run_environment_pair(
        |environment: ProbeEnvironment| {
            run_rotation_to_match_once(
                prelude,
                provider_name,
                expressions,
                reference,
                max_k,
                limits,
                environment,
                deadline,
            )
        },
        deadline,
        tracks_activity(limits),
    )?;
    compare_rotation_match_results(first, second)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RotationMatchRun {
    rotation: u32,
    failed_evaluations: usize,
}

fn compare_rotation_match_results(
    first: Result<EnvironmentResult<RotationMatchRun>, ProbeRefusal>,
    second: Result<EnvironmentResult<RotationMatchRun>, ProbeRefusal>,
) -> Result<u32, ProbeRefusal> {
    let (left, right): (
        EnvironmentResult<RotationMatchRun>,
        EnvironmentResult<RotationMatchRun>,
    ) = match (first, second) {
        (Ok(left), Ok(right)) => (left, right),
        (left, right) => {
            return compare_environment_results(left, right).map(|run| run.rotation);
        }
    };
    if left.calls != right.calls {
        return Err(ProbeRefusal::EnvironmentDesynchronized);
    }
    if left.value.failed_evaluations != right.value.failed_evaluations {
        return Err(ProbeRefusal::SeedConditionalThrow);
    }
    if left.value.rotation != right.value.rotation {
        return Err(ProbeRefusal::EnvironmentDisagreement);
    }
    Ok(left.value.rotation)
}

#[allow(clippy::too_many_arguments)]
fn run_rotation_to_match_once(
    prelude: &str,
    provider_name: &str,
    expressions: &[String],
    reference: &[Option<String>],
    max_k: u32,
    limits: ProbeLimits,
    environment: ProbeEnvironment,
    deadline: ProbeDeadline,
) -> Result<EnvironmentResult<RotationMatchRun>, ProbeRefusal> {
    let sample_indices: Vec<usize> = reference
        .iter()
        .enumerate()
        .filter_map(|(i, r): (usize, &Option<String>)| r.as_ref().map(|_| i))
        .take(ROTATION_SAMPLE_TARGET)
        .collect();
    if sample_indices.is_empty() {
        return Err(ProbeRefusal::NoCandidates);
    }
    let expected: Vec<&String> = sample_indices
        .iter()
        .filter_map(|&i| reference[i].as_ref())
        .collect();
    let sample_exprs: Vec<&String> = sample_indices.iter().map(|&i| &expressions[i]).collect();
    let batch_script: String = build_batch_decode_script(&sample_exprs)?;
    let mut context: Context = Context::default();
    let mut output_budget: OutputBudget = OutputBudget::new();
    let runtime_preamble: String = runtime_preamble(environment);
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    evaluate(&mut context, &runtime_preamble, deadline)?;
    evaluate(&mut context, prelude, deadline)?;
    let materialise: String = format!("var __disrobe_arr = {provider_name}();");
    validate_generated_script(&materialise)?;
    evaluate(&mut context, &materialise, deadline)?;
    let mut failed_evaluations: usize = 0;
    for k in 0..max_k {
        let results: BatchRun = eval_batch(
            &mut context,
            &batch_script,
            sample_exprs.len(),
            &mut output_budget,
            deadline,
        )?;
        failed_evaluations = failed_evaluations
            .checked_add(results.failed)
            .ok_or(ProbeRefusal::BoundExceeded)?;
        let all_match: bool = results.values.len() == expected.len()
            && results
                .values
                .iter()
                .zip(expected.iter())
                .all(|(got, want): (&Option<String>, &&String)| got.as_ref() == Some(*want));
        if all_match {
            let calls: [u64; 3] = environment_calls(&mut context, deadline)?;
            return Ok(EnvironmentResult {
                value: RotationMatchRun {
                    rotation: k,
                    failed_evaluations,
                },
                calls,
            });
        }
        evaluate(
            &mut context,
            "__disrobe_arr.push(__disrobe_arr.shift());",
            deadline,
        )?;
    }
    Err(ProbeRefusal::RotationNotFound)
}

fn build_batch_decode_script(exprs: &[&String]) -> Result<String, ProbeRefusal> {
    if exprs.len() > MAX_PROBE_EXPRESSIONS {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let capacity: usize = batch_script_capacity(
        exprs.iter().map(|expression: &&String| expression.len()),
        exprs.len(),
    )?;
    for expression in exprs {
        if expression.len() > MAX_EXPRESSION_BYTES {
            return Err(ProbeRefusal::InputTooLarge);
        }
    }
    let mut script: String = String::new();
    script
        .try_reserve_exact(capacity)
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
    script.push_str(BATCH_SCRIPT_PREFIX);
    for (i, expr) in exprs.iter().enumerate() {
        if i > 0 {
            script.push(',');
        }
        script.push_str(BATCH_WRAPPER_PREFIX);
        script.push_str(expr);
        script.push_str(BATCH_WRAPPER_SUFFIX);
    }
    script.push_str(BATCH_SCRIPT_SUFFIX_VALUE);
    write!(&mut script, "{MAX_DECODED_VALUE_BYTES}").map_err(|_| ProbeRefusal::BoundExceeded)?;
    script.push_str(BATCH_SCRIPT_SUFFIX_TOTAL);
    write!(&mut script, "{MAX_BATCH_OUTPUT_UNITS}").map_err(|_| ProbeRefusal::BoundExceeded)?;
    script.push_str(BATCH_SCRIPT_SUFFIX_END);
    Ok(script)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchRun {
    values: Vec<Option<String>>,
    failed: usize,
}

fn eval_batch(
    context: &mut Context,
    batch_script: &str,
    expected: usize,
    output_budget: &mut OutputBudget,
    deadline: ProbeDeadline,
) -> Result<BatchRun, ProbeRefusal> {
    let rendered: boa_engine::JsValue = evaluate(context, batch_script, deadline)?;
    let rendered_string: &boa_engine::JsString =
        rendered.as_string().ok_or(ProbeRefusal::EvaluationFailed)?;
    if rendered_string.len() > MAX_BATCH_JSON_BYTES {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let json: String = rendered_string.to_std_string_escaped();
    if json.len() > MAX_BATCH_JSON_BYTES {
        return Err(ProbeRefusal::BoundExceeded);
    }
    let parsed: Vec<(u8, String)> =
        serde_json::from_str(&json).map_err(|_| ProbeRefusal::EvaluationFailed)?;
    if parsed.len() != expected {
        return Err(ProbeRefusal::EvaluationFailed);
    }
    let mut values: Vec<Option<String>> = Vec::with_capacity(expected);
    let mut failed: usize = 0;
    for (status, value) in parsed {
        match status {
            0 if value == "ReferenceError" => return Err(ProbeRefusal::EnvironmentAbsent),
            0 => {
                values.push(None);
                failed = failed.checked_add(1).ok_or(ProbeRefusal::BoundExceeded)?;
            }
            1 => {
                output_budget.accept(&value)?;
                values.push(Some(value));
            }
            2 => return Err(ProbeRefusal::BoundExceeded),
            _ => return Err(ProbeRefusal::EvaluationFailed),
        }
    }
    Ok(BatchRun { values, failed })
}

const DECODE_BATCH_CHUNK: usize = 64;

fn decode_all(
    context: &mut Context,
    expressions: &[String],
    output_budget: &mut OutputBudget,
    deadline: ProbeDeadline,
) -> Result<BatchRun, ProbeRefusal> {
    validate_batched_expressions(expressions)?;
    let mut out: Vec<Option<String>> = Vec::new();
    out.try_reserve_exact(expressions.len())
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
    let mut failed: usize = 0;
    for chunk in expressions.chunks(DECODE_BATCH_CHUNK) {
        let refs: Vec<&String> = chunk.iter().collect();
        let script: String = build_batch_decode_script(&refs)?;
        let decoded: BatchRun = eval_batch(context, &script, refs.len(), output_budget, deadline)?;
        failed = failed
            .checked_add(decoded.failed)
            .ok_or(ProbeRefusal::BoundExceeded)?;
        out.extend(decoded.values);
    }
    Ok(BatchRun {
        values: out,
        failed,
    })
}

const fn validate_generated_script(script: &str) -> Result<(), ProbeRefusal> {
    if script.len() > MAX_GENERATED_SCRIPT_BYTES {
        Err(ProbeRefusal::InputTooLarge)
    } else {
        Ok(())
    }
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
    deadline: ProbeDeadline,
) -> Result<Vec<Option<String>>, ProbeRefusal> {
    let (first, second): (
        Result<EnvironmentResult<ExpressionRun>, ProbeRefusal>,
        Result<EnvironmentResult<ExpressionRun>, ProbeRefusal>,
    ) = run_environment_pair(
        |environment: ProbeEnvironment| {
            run_expressions_once(prelude, expressions, limits, environment, deadline)
        },
        deadline,
        tracks_activity(limits),
    )?;
    compare_expression_results(first, second)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExpressionRun {
    values: ExprResults,
    failed: Vec<usize>,
}

fn run_expressions_once(
    prelude: &str,
    expressions: &[String],
    limits: ProbeLimits,
    environment: ProbeEnvironment,
    deadline: ProbeDeadline,
) -> Result<EnvironmentResult<ExpressionRun>, ProbeRefusal> {
    let mut context: Context = Context::default();
    let mut output_budget: OutputBudget = OutputBudget::new();
    let runtime_preamble: String = runtime_preamble(environment);
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    evaluate(&mut context, &runtime_preamble, deadline)?;
    evaluate(&mut context, prelude, deadline)?;
    let decoded: BatchRun = decode_all(&mut context, expressions, &mut output_budget, deadline)?;
    let failed: Vec<usize> = decoded
        .values
        .iter()
        .enumerate()
        .filter_map(|(index, value): (usize, &Option<String>)| value.is_none().then_some(index))
        .collect();
    let calls: [u64; 3] = environment_calls(&mut context, deadline)?;
    Ok(EnvironmentResult {
        value: ExpressionRun {
            values: decoded.values,
            failed,
        },
        calls,
    })
}

fn compare_expression_results(
    first: Result<EnvironmentResult<ExpressionRun>, ProbeRefusal>,
    second: Result<EnvironmentResult<ExpressionRun>, ProbeRefusal>,
) -> Result<ExprResults, ProbeRefusal> {
    let (left, right): (
        EnvironmentResult<ExpressionRun>,
        EnvironmentResult<ExpressionRun>,
    ) = match (first, second) {
        (Ok(left), Ok(right)) => (left, right),
        (left, right) => return compare_environment_results(left, right).map(|run| run.values),
    };
    if left.calls != right.calls {
        return Err(ProbeRefusal::EnvironmentDesynchronized);
    }
    if left.value.failed != right.value.failed {
        return Err(ProbeRefusal::SeedConditionalThrow);
    }
    if left.value.values != right.value.values {
        return Err(ProbeRefusal::EnvironmentDisagreement);
    }
    if left.value.failed.len() == left.value.values.len() {
        return Err(ProbeRefusal::EvaluationFailed);
    }
    Ok(left.value.values)
}

pub(super) fn probe_decoder(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
) -> Result<DecoderProbe, ProbeRefusal> {
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
) -> Result<DecoderProbe, ProbeRefusal> {
    let source_bytes: usize = decoder_source
        .len()
        .checked_add(string_array_source.len())
        .ok_or(ProbeRefusal::InputTooLarge)?;
    if source_bytes > MAX_SCRIPT_BYTES {
        return Err(ProbeRefusal::InputTooLarge);
    }
    if indices.len() > MAX_PROBE_EXPRESSIONS {
        return Err(ProbeRefusal::BoundExceeded);
    }
    if decoder_name.len() > MAX_EXPRESSION_BYTES {
        return Err(ProbeRefusal::InputTooLarge);
    }
    validate_decoder_expression_plan(decoder_name, indices)?;
    if !nesting_is_safe(decoder_source) || !nesting_is_safe(string_array_source) {
        return Err(ProbeRefusal::UnsafeNesting);
    }
    run_scoped_probe("disrobe-boa-probe", limits, |deadline: ProbeDeadline| {
        run_probe(
            decoder_source,
            string_array_source,
            decoder_name,
            indices,
            limits,
            deadline,
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct EnvironmentResult<T> {
    value: T,
    calls: [u64; 3],
}

fn run_environment_pair<T, F>(
    run: F,
    deadline: ProbeDeadline,
    track_activity: bool,
) -> Result<EnvironmentPair<T>, ProbeRefusal>
where
    T: Send,
    F: Fn(ProbeEnvironment) -> Result<EnvironmentResult<T>, ProbeRefusal> + Sync,
{
    if deadline.expired() {
        return Err(ProbeRefusal::WallTimeout);
    }
    thread::scope(|scope: &thread::Scope<'_, '_>| {
        let second: thread::ScopedJoinHandle<'_, Result<EnvironmentResult<T>, ProbeRefusal>> =
            thread::Builder::new()
                .name("disrobe-boa-second-environment".to_owned())
                .stack_size(WORKER_STACK_BYTES)
                .spawn_scoped(scope, || {
                    track_environment(track_activity, || run(SECOND_ENVIRONMENT))
                })
                .map_err(|_| ProbeRefusal::WorkerSpawn)?;
        let first: Result<EnvironmentResult<T>, ProbeRefusal> =
            track_environment(track_activity, || run(FIRST_ENVIRONMENT));
        let second: Result<EnvironmentResult<T>, ProbeRefusal> =
            second.join().map_err(|_| ProbeRefusal::EvaluationFailed)?;
        Ok((first, second))
    })
}

fn track_environment<T>(track_activity: bool, run: impl FnOnce() -> T) -> T {
    #[cfg(test)]
    let _activity: Option<TestEnvironmentActivity> = TestEnvironmentActivity::enter(track_activity);
    #[cfg(not(test))]
    let _: bool = track_activity;
    run()
}

#[cfg(test)]
struct TestEnvironmentActivity;

#[cfg(test)]
impl TestEnvironmentActivity {
    fn enter(enabled: bool) -> Option<Self> {
        use std::sync::atomic::Ordering;

        if !enabled {
            return None;
        }
        let active: usize = ACTIVE_ENVIRONMENTS.fetch_add(1, Ordering::SeqCst) + 1;
        PEAK_ENVIRONMENTS.fetch_max(active, Ordering::SeqCst);
        Some(Self)
    }
}

#[cfg(test)]
impl Drop for TestEnvironmentActivity {
    fn drop(&mut self) {
        ACTIVE_ENVIRONMENTS.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

fn run_probe(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
    limits: ProbeLimits,
    deadline: ProbeDeadline,
) -> Result<DecoderProbe, ProbeRefusal> {
    let (first, second): (
        Result<EnvironmentResult<DecoderRun>, ProbeRefusal>,
        Result<EnvironmentResult<DecoderRun>, ProbeRefusal>,
    ) = run_environment_pair(
        |environment: ProbeEnvironment| {
            run_probe_once(
                decoder_source,
                string_array_source,
                decoder_name,
                indices,
                limits,
                environment,
                deadline,
            )
        },
        deadline,
        tracks_activity(limits),
    )?;
    compare_decoder_results(first, second)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecoderRun {
    probe: DecoderProbe,
    failed: Vec<i64>,
}

fn compare_decoder_results(
    first: Result<EnvironmentResult<DecoderRun>, ProbeRefusal>,
    second: Result<EnvironmentResult<DecoderRun>, ProbeRefusal>,
) -> Result<DecoderProbe, ProbeRefusal> {
    let (left, right): (EnvironmentResult<DecoderRun>, EnvironmentResult<DecoderRun>) =
        match (first, second) {
            (Ok(left), Ok(right)) => (left, right),
            (left, right) => return compare_environment_results(left, right).map(|run| run.probe),
        };
    if left.calls != right.calls {
        return Err(ProbeRefusal::EnvironmentDesynchronized);
    }
    if left.value.failed != right.value.failed {
        return Err(ProbeRefusal::SeedConditionalThrow);
    }
    if left.value.probe != right.value.probe {
        return Err(ProbeRefusal::EnvironmentDisagreement);
    }
    if left.value.failed.len() == left.value.probe.indices_probed {
        return Err(ProbeRefusal::EvaluationFailed);
    }
    Ok(left.value.probe)
}

fn compare_environment_results<T: PartialEq>(
    first: Result<EnvironmentResult<T>, ProbeRefusal>,
    second: Result<EnvironmentResult<T>, ProbeRefusal>,
) -> Result<T, ProbeRefusal> {
    match (first, second) {
        (Ok(left), Ok(right)) if left.calls != right.calls => {
            Err(ProbeRefusal::EnvironmentDesynchronized)
        }
        (Ok(left), Ok(right)) if left.value != right.value => {
            Err(ProbeRefusal::EnvironmentDisagreement)
        }
        (Ok(left), Ok(_)) => Ok(left.value),
        (Ok(_), Err(ProbeRefusal::WallTimeout)) | (Err(ProbeRefusal::WallTimeout), Ok(_)) => {
            Err(ProbeRefusal::WallTimeout)
        }
        (Ok(_), Err(ProbeRefusal::BoundExceeded)) | (Err(ProbeRefusal::BoundExceeded), Ok(_)) => {
            Err(ProbeRefusal::BoundExceeded)
        }
        (Ok(_), Err(ProbeRefusal::EnvironmentAbsent))
        | (Err(ProbeRefusal::EnvironmentAbsent), Ok(_)) => Err(ProbeRefusal::EnvironmentAbsent),
        (Ok(_), Err(_)) | (Err(_), Ok(_)) => Err(ProbeRefusal::SeedConditionalThrow),
        (Err(left), Err(right)) if left == right => Err(left),
        (Err(ProbeRefusal::WallTimeout), Err(_)) | (Err(_), Err(ProbeRefusal::WallTimeout)) => {
            Err(ProbeRefusal::WallTimeout)
        }
        (Err(ProbeRefusal::BoundExceeded), Err(_)) | (Err(_), Err(ProbeRefusal::BoundExceeded)) => {
            Err(ProbeRefusal::BoundExceeded)
        }
        (Err(ProbeRefusal::EnvironmentAbsent), Err(_))
        | (Err(_), Err(ProbeRefusal::EnvironmentAbsent)) => Err(ProbeRefusal::EnvironmentAbsent),
        (Err(_), Err(_)) => Err(ProbeRefusal::EvaluationFailed),
    }
}

fn run_probe_once(
    decoder_source: &str,
    string_array_source: &str,
    decoder_name: &str,
    indices: &[i64],
    limits: ProbeLimits,
    environment: ProbeEnvironment,
    deadline: ProbeDeadline,
) -> Result<EnvironmentResult<DecoderRun>, ProbeRefusal> {
    let mut context: Context = Context::default();
    let mut output_budget: OutputBudget = OutputBudget::new();
    {
        let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
        runtime.set_loop_iteration_limit(limits.loop_iteration_limit);
        runtime.set_recursion_limit(limits.recursion_limit);
        runtime.set_stack_size_limit(limits.stack_size_limit);
    }
    let preamble: String = runtime_preamble(environment);
    evaluate(&mut context, &preamble, deadline)?;
    evaluate(&mut context, string_array_source, deadline)?;
    evaluate(&mut context, decoder_source, deadline)?;
    let mut expressions: Vec<String> = Vec::new();
    expressions
        .try_reserve_exact(indices.len())
        .map_err(|_| ProbeRefusal::BoundExceeded)?;
    for index in indices {
        let expression: String = format!("{decoder_name}({index})");
        expressions.push(expression);
    }
    validate_expressions(&expressions)?;
    let decoded: BatchRun = decode_all(&mut context, &expressions, &mut output_budget, deadline)?;
    let mut samples: Vec<DecoderSample> = Vec::with_capacity(indices.len() - decoded.failed);
    let mut failed: Vec<i64> = Vec::with_capacity(decoded.failed);
    for (&index, value) in indices.iter().zip(decoded.values) {
        if let Some(decoded) = value {
            samples.push(DecoderSample { index, decoded });
        } else {
            failed.push(index);
        }
    }
    let successful: usize = samples.len();
    let calls: [u64; 3] = environment_calls(&mut context, deadline)?;
    Ok(EnvironmentResult {
        value: DecoderRun {
            probe: DecoderProbe {
                indices_probed: indices.len(),
                successful,
                samples,
            },
            failed,
        },
        calls,
    })
}

fn environment_calls(
    context: &mut Context,
    deadline: ProbeDeadline,
) -> Result<[u64; 3], ProbeRefusal> {
    let counts: [u64; 3] = [
        environment_call_count(context, "__disrobe_random_calls", deadline)?,
        environment_call_count(context, "__disrobe_date_calls", deadline)?,
        environment_call_count(context, "__disrobe_performance_calls", deadline)?,
    ];
    let total: u64 = counts
        .iter()
        .try_fold(0_u64, |sum: u64, value: &u64| sum.checked_add(*value))
        .ok_or(ProbeRefusal::BoundExceeded)?;
    if counts
        .iter()
        .any(|count: &u64| *count > MAX_ENVIRONMENT_CALLS)
        || total > MAX_ENVIRONMENT_CALLS
    {
        return Err(ProbeRefusal::BoundExceeded);
    }
    Ok(counts)
}

fn environment_call_count(
    context: &mut Context,
    binding: &str,
    deadline: ProbeDeadline,
) -> Result<u64, ProbeRefusal> {
    let value: boa_engine::JsValue = evaluate(context, binding, deadline)?;
    let count: f64 = value.as_number().ok_or(ProbeRefusal::EvaluationFailed)?;
    if !count.is_finite() || count.is_sign_negative() || count.fract() != 0.0 {
        return Err(ProbeRefusal::EvaluationFailed);
    }
    if count > MAX_ENVIRONMENT_CALLS as f64 {
        return Err(ProbeRefusal::BoundExceeded);
    }
    Ok(count as u64)
}

fn add_environment_calls(left: [u64; 3], right: [u64; 3]) -> Result<[u64; 3], ProbeRefusal> {
    let combined: [u64; 3] = [
        left[0]
            .checked_add(right[0])
            .ok_or(ProbeRefusal::BoundExceeded)?,
        left[1]
            .checked_add(right[1])
            .ok_or(ProbeRefusal::BoundExceeded)?,
        left[2]
            .checked_add(right[2])
            .ok_or(ProbeRefusal::BoundExceeded)?,
    ];
    let total: u64 = combined
        .iter()
        .try_fold(0_u64, |sum: u64, count: &u64| sum.checked_add(*count))
        .ok_or(ProbeRefusal::BoundExceeded)?;
    if combined
        .iter()
        .any(|count: &u64| *count > MAX_ENVIRONMENT_CALLS)
        || total > MAX_ENVIRONMENT_CALLS
    {
        return Err(ProbeRefusal::BoundExceeded);
    }
    Ok(combined)
}

fn evaluate(
    context: &mut Context,
    source: &str,
    deadline: ProbeDeadline,
) -> Result<boa_engine::JsValue, ProbeRefusal> {
    if deadline.expired() {
        return Err(ProbeRefusal::WallTimeout);
    }
    let script: Script = Script::parse(Source::from_bytes(source.as_bytes()), None, context)
        .map_err(|error: JsError| refusal_from_error(&error, context))?;
    if deadline.expired() {
        return Err(ProbeRefusal::WallTimeout);
    }
    let outcome: Result<boa_engine::JsValue, JsError> = {
        let mut evaluation = Box::pin(script.evaluate_async_with_budget(context, 256));
        let waker: &Waker = Waker::noop();
        let mut task_context: TaskContext<'_> = TaskContext::from_waker(waker);
        loop {
            if deadline.expired() {
                return Err(ProbeRefusal::WallTimeout);
            }
            match evaluation.as_mut().poll(&mut task_context) {
                Poll::Ready(result) => break result,
                Poll::Pending => thread::yield_now(),
            }
        }
    };
    let outcome: Result<boa_engine::JsValue, ProbeRefusal> =
        outcome.map_err(|error: JsError| refusal_from_error(&error, context));
    if outcome.is_ok() && deadline.expired() {
        Err(ProbeRefusal::WallTimeout)
    } else {
        outcome
    }
}

fn refusal_from_error(error: &JsError, context: &mut Context) -> ProbeRefusal {
    if error
        .as_native()
        .is_some_and(boa_engine::JsNativeError::is_runtime_limit)
    {
        return ProbeRefusal::BoundExceeded;
    }
    match error.try_native(context) {
        Ok(native) if native.is_runtime_limit() => ProbeRefusal::BoundExceeded,
        Ok(native) if native.is_reference() => ProbeRefusal::EnvironmentAbsent,
        Ok(_) | Err(_) => ProbeRefusal::EvaluationFailed,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::atomic::Ordering;
    use std::time::Instant;

    use super::*;

    #[test]
    fn probe_simple_lookup() {
        let arr: &str = "var _arr = ['hello','world','log'];";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_decode", &[0, 1, 2]).expect("simple decoder");
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
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_dec", &[1, 2, 3]).expect("offset decoder");
        assert_eq!(probe.successful, 3);
        assert_eq!(probe.samples[0].decoded, "x");
        assert_eq!(probe.samples[2].decoded, "z");
    }

    #[test]
    fn probe_decodes_atob_base64_decoder() {
        let arr: &str = "var _arr = ['aGVsbG8=', 'd29ybGQ=', 'bG9n'];";
        let dec: &str = "function _decode(i) { return atob(_arr[i]); }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_decode", &[0, 1, 2]).expect("atob decoder");
        assert_eq!(probe.successful, 3, "all three atob decodes must succeed");
        assert_eq!(probe.samples[0].decoded, "hello");
        assert_eq!(probe.samples[1].decoded, "world");
        assert_eq!(probe.samples[2].decoded, "log");
    }

    #[test]
    fn probe_btoa_atob_roundtrip_is_faithful() {
        let arr: &str = "var _arr = ['console', 'log', 'prototype'];";
        let dec: &str = "function _rt(i) { return atob(btoa(_arr[i])); }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_rt", &[0, 1, 2]).expect("btoa atob decoder");
        assert_eq!(probe.successful, 3);
        assert_eq!(probe.samples[0].decoded, "console");
        assert_eq!(probe.samples[1].decoded, "log");
        assert_eq!(probe.samples[2].decoded, "prototype");
    }

    #[test]
    fn probe_handles_bad_decoder() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "this is not valid js {";
        let refusal: ProbeRefusal = probe_decoder(dec, arr, "_dec", &[0]).expect_err("bad decoder");
        assert_eq!(refusal, ProbeRefusal::EvaluationFailed);
    }

    #[test]
    fn probe_rejects_infinite_loop_within_deadline() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "function _decode(i) { while(true) {} return ''; }";
        let started: Instant = Instant::now();
        let probe: Result<DecoderProbe, ProbeRefusal> = probe_decoder(dec, arr, "_decode", &[0]);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "infinite loop should be killed within 3s, took {elapsed:?}",
        );
        assert_eq!(probe, Err(ProbeRefusal::BoundExceeded));
    }

    #[test]
    fn probe_rejects_unbounded_recursion() {
        let arr: &str = "var _arr = ['a'];";
        let dec: &str = "function _decode(i) { return _decode(i); }";
        let started: Instant = Instant::now();
        let probe: Result<DecoderProbe, ProbeRefusal> = probe_decoder(dec, arr, "_decode", &[0]);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "recursion bomb should be killed within 3s, took {elapsed:?}",
        );
        assert_eq!(probe, Err(ProbeRefusal::BoundExceeded));
    }

    #[test]
    fn seeded_environment_recovers_a_paired_random_shuffle() {
        let arr: &str = r"
var _arr = ['zero', 'one', 'two', 'three'];
var _order = [0, 1, 2, 3];
var _first = Math.random();
var _second = Math.random();
if (_first === _second) { throw new Error('frozen random source'); }
for (var _i = _arr.length - 1; _i > 0; _i--) {
  var _j = Math.floor(Math.random() * (_i + 1));
  var _value = _arr[_i]; _arr[_i] = _arr[_j]; _arr[_j] = _value;
  var _index = _order[_i]; _order[_i] = _order[_j]; _order[_j] = _index;
}
";
        let dec: &str = "function _decode(i) { return _arr[_order.indexOf(i)]; }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_decode", &[0, 1, 2, 3]).expect("seeded probe");
        let decoded: Vec<&str> = probe
            .samples
            .iter()
            .map(|sample: &DecoderSample| sample.decoded.as_str())
            .collect();
        assert_eq!(decoded, ["zero", "one", "two", "three"]);
    }

    #[test]
    fn environment_dependent_decoder_is_not_baked() {
        let arr: &str = "var _arr = ['x'];";
        let dec: &str = "function _decode(i) { return Math.random() + ':' + Date.now() + ':' + performance.now(); }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::EnvironmentDisagreement)
        );
    }

    #[test]
    fn performance_only_output_is_not_baked() {
        let arr: &str = "var _arr = ['x'];";
        let dec: &str = "function _decode(i) { return String(performance.now()); }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::EnvironmentDisagreement)
        );
    }

    #[test]
    fn performance_only_call_desynchronization_is_typed() {
        let expressions: Vec<String> = vec![format!(
            "performance.now()==={}?(performance.now(),'stable'):'stable'",
            FIRST_ENVIRONMENT.performance_now
        )];
        assert_eq!(
            probe_expressions("", &expressions),
            Err(ProbeRefusal::EnvironmentDesynchronized)
        );
    }

    #[test]
    fn expression_count_is_rejected_before_probe_execution() {
        let expressions: Vec<String> = vec!["'x'".to_owned(); MAX_PROBE_EXPRESSIONS + 1];
        assert_eq!(
            probe_expressions("", &expressions),
            Err(ProbeRefusal::BoundExceeded)
        );
    }

    #[test]
    fn per_expression_and_aggregate_input_quotas_are_typed() {
        let oversized: Vec<String> = vec!["x".repeat(MAX_EXPRESSION_BYTES + 1)];
        assert_eq!(
            probe_expressions("", &oversized),
            Err(ProbeRefusal::InputTooLarge)
        );
        let aggregate: Vec<String> = vec![
            "x".repeat(MAX_EXPRESSION_BYTES);
            (MAX_AGGREGATE_EXPRESSION_BYTES / MAX_EXPRESSION_BYTES)
                + 1
        ];
        assert_eq!(
            probe_expressions("", &aggregate),
            Err(ProbeRefusal::InputTooLarge)
        );
    }

    #[test]
    fn generated_batch_script_quota_is_checked_before_probe_execution() {
        let expressions: Vec<String> = vec![
            "x".repeat(MAX_EXPRESSION_BYTES);
            MAX_AGGREGATE_EXPRESSION_BYTES / MAX_EXPRESSION_BYTES
        ];
        assert_eq!(
            probe_with_rotation_search(
                "function provider(){return ['x'];}",
                "provider",
                &expressions,
                1,
            ),
            Err(ProbeRefusal::InputTooLarge)
        );
    }

    #[test]
    fn total_decoded_output_and_environment_call_quotas_are_typed() {
        let expressions: Vec<String> = vec![
            "'x'.repeat(65536)".to_owned();
            (MAX_DECODED_TOTAL_BYTES / MAX_DECODED_VALUE_BYTES) + 1
        ];
        assert_eq!(
            probe_expressions("", &expressions),
            Err(ProbeRefusal::BoundExceeded)
        );
        assert_eq!(
            probe_expressions(
                "__disrobe_performance_calls=10000001;",
                &["'stable'".to_owned()],
            ),
            Err(ProbeRefusal::BoundExceeded)
        );
    }

    #[test]
    fn maximum_decoded_value_size_remains_accepted() {
        let expression: String = format!("'x'.repeat({MAX_DECODED_VALUE_BYTES})");
        let decoded: Vec<Option<String>> =
            probe_expressions("", &[expression]).expect("boundary value");
        assert_eq!(
            decoded[0].as_ref().map(String::len),
            Some(MAX_DECODED_VALUE_BYTES)
        );
    }

    #[test]
    fn probe_transport_uses_captured_intrinsics() {
        let arr: &str = "var _arr=['x'];String=function(){return {length:0,payload:'y'.repeat(2000000)};};JSON.stringify=function(){return 'corrupt';};ReferenceError=function(){};";
        let decoder: &str = "function _decode(i){return _arr[i];}";
        let probe: DecoderProbe =
            probe_decoder(decoder, arr, "_decode", &[0]).expect("captured intrinsics");
        assert_eq!(probe.samples[0].decoded, "x");
        let absent: &str = "var _arr=['x'];ReferenceError=function(){};";
        let missing: &str = "function _decode(i){return fetch(_arr[i]);}";
        assert_eq!(
            probe_decoder(missing, absent, "_decode", &[0]),
            Err(ProbeRefusal::EnvironmentAbsent)
        );
    }

    #[test]
    fn refusal_serialization_remains_stable_and_extensible() {
        let cases: [(ProbeRefusal, &str); 12] = [
            (ProbeRefusal::InputTooLarge, "\"input-too-large\""),
            (ProbeRefusal::UnsafeNesting, "\"unsafe-nesting\""),
            (ProbeRefusal::WorkerSpawn, "\"worker-spawn\""),
            (ProbeRefusal::WallTimeout, "\"wall-timeout\""),
            (ProbeRefusal::BoundExceeded, "\"bound-exceeded\""),
            (ProbeRefusal::EnvironmentAbsent, "\"environment-absent\""),
            (ProbeRefusal::EvaluationFailed, "\"evaluation-failed\""),
            (
                ProbeRefusal::SeedConditionalThrow,
                "\"seed-conditional-throw\"",
            ),
            (
                ProbeRefusal::EnvironmentDesynchronized,
                "\"environment-desynchronized\"",
            ),
            (
                ProbeRefusal::EnvironmentDisagreement,
                "\"environment-disagreement\"",
            ),
            (ProbeRefusal::NoCandidates, "\"no-candidates\""),
            (ProbeRefusal::RotationNotFound, "\"rotation-not-found\""),
        ];
        for (refusal, expected) in cases {
            assert_eq!(
                serde_json::to_string(&refusal).expect("serialization"),
                expected
            );
        }
    }

    #[test]
    fn timed_out_probe_has_no_live_environment_after_return() {
        let baseline: usize = ACTIVE_ENVIRONMENTS.load(Ordering::SeqCst);
        PEAK_ENVIRONMENTS.store(baseline, Ordering::SeqCst);
        let limits: ProbeLimits = ProbeLimits {
            wall_timeout: Duration::from_millis(100),
            loop_iteration_limit: 20_000_000,
            recursion_limit: DEFAULT_RECURSION_LIMIT,
            stack_size_limit: DEFAULT_STACK_SIZE_LIMIT,
            track_activity: true,
        };
        let arr: &str = "var _arr=['x'];";
        let dec: &str =
            "function _decode(i){var n=0;for(var j=0;j<10000000;j++){n+=j;}return _arr[i];}";
        let deadline: ProbeDeadline = ProbeDeadline::from_timeout(limits.wall_timeout);
        let started: Instant = Instant::now();
        let result: Result<DecoderProbe, ProbeRefusal> =
            run_joined_worker("disrobe-boa-lifecycle-test", deadline, |deadline| {
                run_probe(dec, arr, "_decode", &[0], limits, deadline)
            });
        assert_eq!(result, Err(ProbeRefusal::WallTimeout));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(PEAK_ENVIRONMENTS.load(Ordering::SeqCst) > baseline);
        assert_eq!(ACTIVE_ENVIRONMENTS.load(Ordering::SeqCst), baseline);
    }

    #[test]
    fn global_probe_admission_is_bounded() {
        static TEST_SLOTS: ProbeSlots = ProbeSlots {
            active: Mutex::new(0),
            available: Condvar::new(),
        };
        let mut permits: Vec<ProbePermit> = Vec::new();
        for _ in 0..MAX_CONCURRENT_PROBES {
            permits.push(
                acquire_probe_permit_from(
                    &TEST_SLOTS,
                    ProbeDeadline::from_timeout(Duration::from_secs(1)),
                )
                .expect("available slot"),
            );
        }
        let refused: Result<ProbePermit, ProbeRefusal> = acquire_probe_permit_from(
            &TEST_SLOTS,
            ProbeDeadline::from_timeout(Duration::from_millis(10)),
        );
        assert!(matches!(refused, Err(ProbeRefusal::WallTimeout)));
        drop(permits);
    }

    #[test]
    fn modern_expression_probe_requires_environment_agreement() {
        let expressions: Vec<String> = vec![
            "_arr[0]".to_owned(),
            "Math.random() + ':' + Date.now() + ':' + performance.now()".to_owned(),
        ];
        assert_eq!(
            probe_expressions("var _arr = ['stable'];", &expressions),
            Err(ProbeRefusal::EnvironmentDisagreement)
        );
    }

    #[test]
    fn modern_expression_probe_accepts_seeded_shuffle_with_stable_mapping() {
        let prelude: &str = r"
var _arr = ['zero', 'one', 'two', 'three'];
var _order = [0, 1, 2, 3];
for (var _round = 0; _round < 3; _round++) {
  for (var _i = _arr.length - 1; _i > 0; _i--) {
    var _j = Math.floor(Math.random() * (_i + 1));
    var _value = _arr[_i]; _arr[_i] = _arr[_j]; _arr[_j] = _value;
    var _index = _order[_i]; _order[_i] = _order[_j]; _order[_j] = _index;
  }
}
";
        let expressions: Vec<String> = (0..4)
            .map(|index: usize| format!("_arr[_order.indexOf({index})]"))
            .collect();
        assert_eq!(
            probe_expressions(prelude, &expressions),
            Ok(vec![
                Some("zero".to_owned()),
                Some("one".to_owned()),
                Some("two".to_owned()),
                Some("three".to_owned()),
            ])
        );
    }

    #[test]
    fn rotation_match_refuses_environment_selected_rotation() {
        let prelude: String = format!(
            "function provider() {{ return Date.now() === {} ? ['console','log'] : ['log','console']; }}",
            FIRST_ENVIRONMENT.date_now
        );
        let expressions: Vec<String> = vec!["__disrobe_arr[0]".to_owned()];
        let reference: Vec<Option<String>> = vec![Some("console".to_owned())];
        assert_eq!(
            probe_rotation_to_match(&prelude, "provider", &expressions, &reference, 2),
            Err(ProbeRefusal::EnvironmentDisagreement)
        );
    }

    #[test]
    fn rotation_search_refuses_environment_selected_array_order() {
        let prelude: String = format!(
            "function provider() {{ return Date.now() === {} ? ['console','log'] : ['log','console']; }}",
            FIRST_ENVIRONMENT.date_now
        );
        let expressions: Vec<String> =
            vec!["__disrobe_arr[0]".to_owned(), "__disrobe_arr[1]".to_owned()];
        assert_eq!(
            probe_with_rotation_search(&prelude, "provider", &expressions, 2),
            Err(ProbeRefusal::EnvironmentDisagreement)
        );
    }

    #[test]
    fn rotation_match_classifies_batch_failures() {
        let provider: &str = "function provider(){return ['console'];}";
        let reference: Vec<Option<String>> = vec![Some("console".to_owned())];
        let cases: [(String, ProbeRefusal); 4] = [
            (
                "fetch('https://example.invalid')".to_owned(),
                ProbeRefusal::EnvironmentAbsent,
            ),
            (
                "(function(){while(true){}})()".to_owned(),
                ProbeRefusal::BoundExceeded,
            ),
            (
                format!(
                    "Date.now()==={}?(function(){{throw new Error('first');}})():'console'",
                    FIRST_ENVIRONMENT.date_now
                ),
                ProbeRefusal::SeedConditionalThrow,
            ),
            (
                format!(
                    "Date.now()==={}?(Math.random(),'console'):'console'",
                    FIRST_ENVIRONMENT.date_now
                ),
                ProbeRefusal::EnvironmentDesynchronized,
            ),
        ];
        for (expression, expected) in cases {
            assert_eq!(
                probe_rotation_to_match(provider, "provider", &[expression], &reference, 1),
                Err(expected)
            );
        }
    }

    #[test]
    fn rotation_search_classifies_batch_failures() {
        let provider: &str = "function provider(){return ['console'];}";
        let cases: [(String, ProbeRefusal); 4] = [
            (
                "fetch('https://example.invalid')".to_owned(),
                ProbeRefusal::EnvironmentAbsent,
            ),
            (
                "(function(){while(true){}})()".to_owned(),
                ProbeRefusal::BoundExceeded,
            ),
            (
                format!(
                    "Date.now()==={}?(function(){{throw new Error('first');}})():'console'",
                    FIRST_ENVIRONMENT.date_now
                ),
                ProbeRefusal::SeedConditionalThrow,
            ),
            (
                format!(
                    "Date.now()==={}?(Math.random(),'console'):'console'",
                    FIRST_ENVIRONMENT.date_now
                ),
                ProbeRefusal::EnvironmentDesynchronized,
            ),
        ];
        for (expression, expected) in cases {
            assert_eq!(
                probe_with_rotation_search(provider, "provider", &[expression], 1),
                Err(expected)
            );
        }
    }

    #[test]
    fn unequal_environment_consumption_is_typed_as_desynchronization() {
        let arr: &str = "var _arr = ['x']; if (Date.now() === 1700000000137) { Math.random(); }";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::EnvironmentDesynchronized)
        );
    }

    #[test]
    fn one_environment_throw_is_typed_separately() {
        let arr: &str = "var _arr = ['x']; if (Date.now() === 1700000000137) { throw new Error('first seed'); }";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::SeedConditionalThrow)
        );
    }

    #[test]
    fn seed_independent_decoder_throw_preserves_other_samples() {
        let arr: &str = "var _arr = ['zero', 'one', 'two'];";
        let dec: &str =
            "function _decode(i) { if (i === 1) { throw new Error('missing'); } return _arr[i]; }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_decode", &[0, 1, 2]).expect("partial decoder");
        assert_eq!(probe.indices_probed, 3);
        assert_eq!(probe.successful, 2);
        assert_eq!(probe.samples[0].decoded, "zero");
        assert_eq!(probe.samples[1].decoded, "two");
    }

    #[test]
    fn seed_independent_expression_throw_preserves_other_values() {
        let expressions: Vec<String> = vec![
            "_arr[0]".to_owned(),
            "(function(){throw new Error('missing');})()".to_owned(),
            "_arr[2]".to_owned(),
        ];
        assert_eq!(
            probe_expressions("var _arr = ['zero','one','two'];", &expressions),
            Ok(vec![Some("zero".to_owned()), None, Some("two".to_owned()),])
        );
    }

    #[test]
    fn seed_independent_expression_throw_is_typed_when_every_value_fails() {
        let expressions: Vec<String> = vec![
            "(function(){throw new Error('first');})()".to_owned(),
            "(function(){throw new Error('second');})()".to_owned(),
        ];
        assert_eq!(
            probe_expressions("", &expressions),
            Err(ProbeRefusal::EvaluationFailed)
        );
    }

    #[test]
    fn seed_independent_decoder_throw_is_typed_when_every_index_fails() {
        let arr: &str = "var _arr = ['zero', 'one'];";
        let dec: &str = "function _decode(i) { throw new Error(_arr[i]); }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0, 1]),
            Err(ProbeRefusal::EvaluationFailed)
        );
    }

    #[test]
    fn one_environment_expression_throw_is_typed_separately() {
        let expressions: Vec<String> = vec![format!(
            "Date.now() === {} ? (function(){{throw new Error('first');}})() : 'ok'",
            FIRST_ENVIRONMENT.date_now
        )];
        assert_eq!(
            probe_expressions("", &expressions),
            Err(ProbeRefusal::SeedConditionalThrow)
        );
    }

    #[test]
    fn one_environment_limit_breach_is_not_disagreement() {
        let arr: &str = "var _arr = ['x']; if (Date.now() === 1700000000137) { while (true) {} }";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::BoundExceeded)
        );
    }

    #[test]
    fn deleted_fetch_is_typed_as_environment_absent() {
        let arr: &str = "var _arr = ['x']; fetch('https://example.invalid');";
        let dec: &str = "function _decode(i) { return _arr[i]; }";
        assert_eq!(
            probe_decoder(dec, arr, "_decode", &[0]),
            Err(ProbeRefusal::EnvironmentAbsent)
        );
    }

    #[test]
    fn function_source_neutering_survives_environment_differential() {
        let arr: &str = "var _arr = ['x'];";
        let dec: &str = "function _decode(i) { return Function.prototype.toString.call(_decode); }";
        let probe: DecoderProbe =
            probe_decoder(dec, arr, "_decode", &[0]).expect("function source probe");
        assert_eq!(probe.samples.len(), 1);
        assert_eq!(probe.samples[0].decoded, "function (){\n[native code]\n}");
    }
}
