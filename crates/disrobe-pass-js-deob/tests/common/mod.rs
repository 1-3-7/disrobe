#![allow(dead_code, clippy::redundant_pub_crate)]
use std::cell::{Cell, RefCell};
use std::fs;
use std::future::Future;
use std::io::Read;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context as TaskContext, Poll, Waker};
use std::time::Duration;

use boa_engine::{
    Context, JsError, JsNativeError, JsResult, JsValue, Script, Source,
    context::{ContextBuilder, HostHooks},
    error::TryNativeError,
    job::{FutureJob, JobQueue, NativeJob},
    js_string,
    native_function::NativeFunction,
};
use disrobe_core::scratch::ScratchDir;
use disrobe_testkit::{CommandSpec, ProcessMemoryLimit, ToolOutput, tool_output};

const LOOP_LIMIT: u64 = 2_000_000;
const STEP_SLICE_COST: u32 = 256;
const STEP_SLICE_LIMIT: u64 = 400_000;
const RECURSION_LIMIT: usize = 1_500;
const STACK_LIMIT: usize = 50_000;
const FIXED_EPOCH_MILLIS: i64 = 1_700_000_000_000;
const ARRAY_BUFFER_LIMIT: u64 = 64 * 1_024 * 1_024;
const TRACE_EVENT_LIMIT: usize = 4_096;
const TRACE_ARGUMENT_LIMIT: usize = 128;
const TRACE_VALUE_CODE_UNIT_LIMIT: usize = 16 * 1_024;
const TRACE_BYTE_LIMIT: usize = 512 * 1_024;
const WORKER_REQUEST_ENV: &str = "DISROBE_JS_BOA_ORACLE_REQUEST";
const WORKER_RESPONSE_ENV: &str = "DISROBE_JS_BOA_ORACLE_RESPONSE";
const WORKER_CAPTURE_LIMIT: usize = 256 * 1_024;
const WORKER_MEMORY_LIMIT_BYTES: usize = 512 * 1_024 * 1_024;
const WORKER_REQUEST_LIMIT: u64 = 32 * 1_024 * 1_024;
const WORKER_RESPONSE_LIMIT: u64 = 32 * 1_024 * 1_024;
const WORKER_BACKSTOP: Duration = Duration::from_mins(5);

struct OracleHostHooks;

impl HostHooks for OracleHostHooks {
    fn utc_now(&self) -> i64 {
        FIXED_EPOCH_MILLIS
    }

    fn local_timezone_offset_seconds(&self, _unix_time_seconds: i64) -> i32 {
        0
    }

    fn max_buffer_size(&self, _context: &mut Context) -> u64 {
        ARRAY_BUFFER_LIMIT
    }
}

static ORACLE_HOST_HOOKS: OracleHostHooks = OracleHostHooks;

#[derive(Default)]
struct OracleJobQueue {
    queued: Cell<bool>,
}

impl JobQueue for OracleJobQueue {
    fn enqueue_promise_job(&self, _job: NativeJob, _context: &mut Context) {
        self.queued.set(true);
    }

    fn run_jobs(&self, _context: &mut Context) {}

    fn enqueue_future_job(&self, _future: FutureJob, _context: &mut Context) {
        self.queued.set(true);
    }
}

const PRELUDE: &str = r#"
var __disrobe_oracle_emit = function (name, args) {
  var forwarded = [name];
  for (var index = 0; index < args.length; index += 1) {
    forwarded.push(args[index]);
  }
  return __disrobe_oracle_record.apply(undefined, forwarded);
};
var print = function () { return __disrobe_oracle_emit("print", arguments); };
var console = {
  log: function () { return __disrobe_oracle_emit("console.log", arguments); },
  error: function () { return __disrobe_oracle_emit("console.error", arguments); },
  warn: function () { return __disrobe_oracle_emit("console.warn", arguments); },
  info: function () { return __disrobe_oracle_emit("console.info", arguments); },
  debug: function () { return __disrobe_oracle_emit("console.debug", arguments); },
  trace: function () { return __disrobe_oracle_emit("console.trace", arguments); }
};
var __disrobe_oracle_timer_id = 0;
var setInterval = function () {
  __disrobe_oracle_emit("setInterval", arguments);
  __disrobe_oracle_timer_id += 1;
  return __disrobe_oracle_timer_id;
};
var clearInterval = function () { return __disrobe_oracle_emit("clearInterval", arguments); };
var setTimeout = function () {
  __disrobe_oracle_emit("setTimeout", arguments);
  __disrobe_oracle_timer_id += 1;
  return __disrobe_oracle_timer_id;
};
var clearTimeout = function () { return __disrobe_oracle_emit("clearTimeout", arguments); };
var queueMicrotask = function () { return __disrobe_oracle_emit("queueMicrotask", arguments); };
var __disrobe_oracle_real_date = Date;
var __disrobe_oracle_fixed_epoch = 1700000000000;
var __disrobe_oracle_date = function () {
  var args = Array.prototype.slice.call(arguments);
  __disrobe_oracle_emit(new.target ? "Date.construct" : "Date.call", args);
  if (!new.target) {
    return new __disrobe_oracle_real_date(__disrobe_oracle_fixed_epoch).toString();
  }
  if (args.length === 0) {
    return new __disrobe_oracle_real_date(__disrobe_oracle_fixed_epoch);
  }
  return Reflect.construct(__disrobe_oracle_real_date, args, new.target);
};
Object.setPrototypeOf(__disrobe_oracle_date, __disrobe_oracle_real_date);
__disrobe_oracle_date.prototype = __disrobe_oracle_real_date.prototype;
Date = __disrobe_oracle_date;
Date.now = function () {
  __disrobe_oracle_emit("Date.now", arguments);
  return __disrobe_oracle_fixed_epoch;
};
Math.random = function () {
  __disrobe_oracle_emit("Math.random", arguments);
  return 0.125;
};
var performance = Object.freeze({
  timeOrigin: __disrobe_oracle_fixed_epoch,
  now: function () {
    __disrobe_oracle_emit("performance.now", arguments);
    return 1234.5;
  }
});
var crypto = Object.freeze({
  randomUUID: function () {
    __disrobe_oracle_emit("crypto.randomUUID", arguments);
    return "00000000-0000-4000-8000-000000000001";
  },
  getRandomValues: function (view) {
    __disrobe_oracle_emit("crypto.getRandomValues", arguments);
    for (var index = 0; index < view.length; index += 1) {
      view[index] = (index * 17 + 23) & 255;
    }
    return view;
  }
});
"#;

const BROWSER_SHIM: &str = r#"
var __disrobe_oracle_host_proxy = function (path, target) {
  return new Proxy(target, {
    get: function (inner, property, receiver) {
      if (typeof property !== "string") {
        return Reflect.get(inner, property, receiver);
      }
      if (Reflect.has(inner, property)) {
        __disrobe_oracle_emit("host.get", [path + "." + property]);
        return Reflect.get(inner, property, receiver);
      }
      __disrobe_oracle_emit("host.unsupported.get", [path + "." + property]);
      return undefined;
    },
    set: function (inner, property, value) {
      if (typeof property !== "string" || !Reflect.has(inner, property)) {
        __disrobe_oracle_emit("host.unsupported.set", [path + "." + String(property), value]);
        return false;
      }
      __disrobe_oracle_emit("host.set", [path + "." + property, value]);
      return Reflect.set(inner, property, value, inner);
    },
    has: function (inner, property) {
      var known = Reflect.has(inner, property);
      __disrobe_oracle_emit(known ? "host.has" : "host.unsupported.has", [path + "." + String(property)]);
      return known;
    },
    deleteProperty: function (inner, property) {
      __disrobe_oracle_emit("host.unsupported.delete", [path + "." + String(property)]);
      return false;
    },
    defineProperty: function (inner, property) {
      __disrobe_oracle_emit("host.unsupported.define", [path + "." + String(property)]);
      return false;
    },
    ownKeys: function (inner) {
      __disrobe_oracle_emit("host.keys", [path]);
      return Reflect.ownKeys(inner);
    }
  });
};
var __disrobe_oracle_location_target = {
  pathname: "/fixture",
  href: "https://example.invalid/fixture",
  protocol: "https:",
  host: "example.invalid",
  hostname: "example.invalid",
  port: "",
  search: "",
  hash: ""
};
var location = __disrobe_oracle_host_proxy("location", __disrobe_oracle_location_target);
var __disrobe_oracle_navigator_target = {
  userAgent: "disrobe-boa",
  language: "en-US",
  languages: Object.freeze(["en-US"]),
  platform: "boa",
  cookieEnabled: false
};
var navigator = __disrobe_oracle_host_proxy("navigator", __disrobe_oracle_navigator_target);
var __disrobe_oracle_screen_target = {
  width: 1280,
  height: 720,
  availWidth: 1280,
  availHeight: 720,
  colorDepth: 24,
  pixelDepth: 24
};
var screen = __disrobe_oracle_host_proxy("screen", __disrobe_oracle_screen_target);
var __disrobe_oracle_document_title = "";
var __disrobe_oracle_document_target = {
  querySelector: function () {
    __disrobe_oracle_emit("document.querySelector", arguments);
    return null;
  }
};
Object.defineProperty(__disrobe_oracle_document_target, "title", {
  enumerable: true,
  configurable: false,
  get: function () {
    __disrobe_oracle_emit("host.get", ["document.title"]);
    return __disrobe_oracle_document_title;
  },
  set: function (value) {
    __disrobe_oracle_document_title = value;
  }
});
var document = __disrobe_oracle_host_proxy("document", __disrobe_oracle_document_target);
var __disrobe_oracle_window_target = {
  location: location,
  navigator: navigator,
  screen: screen,
  document: document,
  console: console,
  JSON: JSON
};
var window = __disrobe_oracle_host_proxy("window", __disrobe_oracle_window_target);
var self = window;
var top = window;
var parent = window;
var frames = window;
var history = Object.freeze({});
var localStorage = Object.freeze({});
var sessionStorage = Object.freeze({});
"#;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct ObservedValue {
    pub(crate) kind: String,
    pub(crate) value: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct TraceEvent {
    pub(crate) call: String,
    pub(crate) arguments: Vec<ObservedValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) enum Terminal {
    Completed(ObservedValue),
    Threw { kind: String, message: String },
    ParseFailed { kind: String, message: String },
    ExecutionLimitExceeded,
    ObservationLimitExceeded(String),
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct EvalOutcome {
    pub(crate) trace: Vec<TraceEvent>,
    pub(crate) terminal: Terminal,
}

#[derive(Debug)]
pub(crate) enum BoaWorkerError {
    ProviderUnavailable(String),
    BackstopExceeded,
    AllocationLimitRefusal {
        evidence: WorkerRefusalEvidence,
        detail: String,
    },
    HarnessFailure(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WorkerRefusalEvidence {
    WorkerTerminated,
    ResponseUnavailable,
    InvalidReply,
}

#[derive(Debug)]
pub(crate) struct BoaWorker {
    executable: PathBuf,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct EvalBatchRequest {
    program: String,
    argv_battery: Vec<Vec<String>>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct EvalBatchResponse {
    evaluations: Vec<Result<EvalOutcome, String>>,
}

impl BoaWorker {
    pub(crate) fn new(executable: impl AsRef<Path>) -> Result<Self, BoaWorkerError> {
        let executable: PathBuf =
            executable
                .as_ref()
                .canonicalize()
                .map_err(|error: std::io::Error| {
                    BoaWorkerError::ProviderUnavailable(format!(
                        "resolve Boa worker executable {}: {error}",
                        executable.as_ref().display()
                    ))
                })?;
        let metadata: fs::Metadata =
            fs::metadata(&executable).map_err(|error: std::io::Error| {
                BoaWorkerError::ProviderUnavailable(format!(
                    "inspect Boa worker executable {}: {error}",
                    executable.display()
                ))
            })?;
        if !metadata.is_file() {
            return Err(BoaWorkerError::ProviderUnavailable(format!(
                "Boa worker executable is not a regular file: {}",
                executable.display()
            )));
        }
        Ok(Self { executable })
    }

    pub(crate) fn evaluate_batch(
        &self,
        program: &str,
        argv_battery: &[&[&str]],
    ) -> Result<Vec<Result<EvalOutcome, String>>, BoaWorkerError> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-js-boa-oracle").map_err(|error| {
            BoaWorkerError::HarnessFailure(format!("create Boa worker scratch directory: {error}"))
        })?;
        let request_path: PathBuf = scratch.path().join("request.json");
        let response_path: PathBuf = scratch.path().join("response.json");
        let request: EvalBatchRequest = EvalBatchRequest {
            program: program.to_owned(),
            argv_battery: argv_battery
                .iter()
                .map(|argv: &&[&str]| {
                    argv.iter()
                        .map(|argument: &&str| (*argument).to_owned())
                        .collect()
                })
                .collect(),
        };
        let request_bytes: Vec<u8> = serde_json::to_vec(&request).map_err(|error| {
            BoaWorkerError::HarnessFailure(format!("encode Boa worker request: {error}"))
        })?;
        if u64::try_from(request_bytes.len()).unwrap_or(u64::MAX) > WORKER_REQUEST_LIMIT {
            return Err(BoaWorkerError::HarnessFailure(format!(
                "Boa worker request exceeds {WORKER_REQUEST_LIMIT} bytes"
            )));
        }
        fs::write(&request_path, request_bytes).map_err(|error: std::io::Error| {
            BoaWorkerError::HarnessFailure(format!("write Boa worker request: {error}"))
        })?;
        let worker_filter: String = worker_test_filter(module_path!());
        let spec: CommandSpec = CommandSpec::new(&self.executable, WORKER_BACKSTOP)
            .args([
                "--ignored".to_owned(),
                "--exact".to_owned(),
                worker_filter,
                "--nocapture".to_owned(),
                "--test-threads=1".to_owned(),
            ])
            .env(WORKER_REQUEST_ENV, &request_path)
            .env(WORKER_RESPONSE_ENV, &response_path)
            .memory_limit(ProcessMemoryLimit::new(
                NonZeroUsize::new(WORKER_MEMORY_LIMIT_BYTES)
                    .expect("Boa worker memory limit must be nonzero"),
            ))
            .capture_limits(WORKER_CAPTURE_LIMIT, WORKER_CAPTURE_LIMIT);
        let output: ToolOutput = tool_output(spec)
            .map_err(|error| BoaWorkerError::HarnessFailure(format!("run Boa worker: {error}")))?;
        classify_worker_completion(&output)?;
        let response_bytes: Vec<u8> = read_worker_response(&response_path).map_err(|reason| {
            BoaWorkerError::AllocationLimitRefusal {
                evidence: WorkerRefusalEvidence::ResponseUnavailable,
                detail: format!("{reason}; {}", worker_diagnostics(&output)),
            }
        })?;
        let response: EvalBatchResponse =
            decode_worker_response(&response_bytes, &worker_diagnostics(&output))?;
        Ok(response.evaluations)
    }

    pub(crate) fn evaluate(
        &self,
        program: &str,
        argv: &[&str],
    ) -> Result<EvalOutcome, BoaWorkerError> {
        let argv_battery: [&[&str]; 1] = [argv];
        let mut evaluations: Vec<Result<EvalOutcome, String>> =
            self.evaluate_batch(program, &argv_battery)?;
        if evaluations.len() != 1 {
            return Err(BoaWorkerError::HarnessFailure(format!(
                "Boa worker returned {} evaluations for one argument case",
                evaluations.len()
            )));
        }
        evaluations
            .pop()
            .expect("one Boa worker evaluation must be present")
            .map_err(BoaWorkerError::HarnessFailure)
    }

    pub(crate) fn eval_capture(
        &self,
        program: &str,
        argv: &[&str],
    ) -> Result<String, BoaWorkerError> {
        let outcome: EvalOutcome = self.evaluate(program, argv)?;
        let Terminal::Completed(_) = &outcome.terminal else {
            return Err(BoaWorkerError::HarnessFailure(format!(
                "Boa worker program did not complete: {:?}",
                outcome.terminal
            )));
        };
        console_capture(&outcome.trace).ok_or_else(|| {
            BoaWorkerError::HarnessFailure(
                "Boa worker produced an unsupported console value".to_owned(),
            )
        })
    }

    pub(crate) fn eval_stdout(
        &self,
        program: &str,
        argv: &[&str],
    ) -> Result<String, BoaWorkerError> {
        let outcome: EvalOutcome = self.evaluate(program, argv)?;
        let Terminal::Completed(_) = &outcome.terminal else {
            return Err(BoaWorkerError::HarnessFailure(format!(
                "Boa worker program did not complete: {:?}",
                outcome.terminal
            )));
        };
        let mut stdout: String = String::new();
        for event in outcome.trace {
            if !matches!(
                event.call.as_str(),
                "console.log" | "console.info" | "console.debug"
            ) {
                continue;
            }
            let values: Vec<String> = event
                .arguments
                .iter()
                .map(legacy_render)
                .collect::<Option<Vec<String>>>()
                .ok_or_else(|| {
                    BoaWorkerError::HarnessFailure(
                        "Boa worker produced an unsupported stdout value".to_owned(),
                    )
                })?;
            stdout.push_str(&values.join(" "));
            stdout.push('\n');
        }
        Ok(stdout)
    }
}

fn worker_test_filter(module: &str) -> String {
    let (_, test_module): (&str, &str) = module.split_once("::").unwrap_or(("", module));
    format!("{test_module}::boa_eval_subprocess_worker")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TerminalSignature {
    Completed(ObservedValue),
    Threw(String),
    ParseFailed(String),
    ExecutionLimitExceeded,
    ObservationLimitExceeded,
}

fn terminal_signature(terminal: &Terminal) -> TerminalSignature {
    match terminal {
        Terminal::Completed(value) => TerminalSignature::Completed(value.clone()),
        Terminal::Threw { kind, .. } => TerminalSignature::Threw(kind.clone()),
        Terminal::ParseFailed { kind, .. } => TerminalSignature::ParseFailed(kind.clone()),
        Terminal::ExecutionLimitExceeded => TerminalSignature::ExecutionLimitExceeded,
        Terminal::ObservationLimitExceeded(_) => TerminalSignature::ObservationLimitExceeded,
    }
}

pub(crate) fn outcomes_equivalent(expected: &EvalOutcome, actual: &EvalOutcome) -> bool {
    !exhausted_a_limit(expected)
        && !exhausted_a_limit(actual)
        && expected.trace == actual.trace
        && terminal_signature(&expected.terminal) == terminal_signature(&actual.terminal)
}

const fn exhausted_a_limit(outcome: &EvalOutcome) -> bool {
    matches!(
        outcome.terminal,
        Terminal::ExecutionLimitExceeded | Terminal::ObservationLimitExceeded(_)
    )
}

#[derive(Default)]
struct ObservationState {
    trace: Vec<TraceEvent>,
    bytes: usize,
    limit: Option<String>,
}

thread_local! {
    static OBSERVATION_STATE: RefCell<ObservationState> = RefCell::new(ObservationState::default());
}

fn observed(kind: &str, value: String) -> ObservedValue {
    ObservedValue {
        kind: kind.to_owned(),
        value,
    }
}

fn observe_number(number: f64) -> ObservedValue {
    let rendered: String = if number.is_nan() {
        "NaN".to_owned()
    } else if number == f64::INFINITY {
        "Infinity".to_owned()
    } else if number == f64::NEG_INFINITY {
        "-Infinity".to_owned()
    } else if number == 0.0 && number.is_sign_negative() {
        "-0".to_owned()
    } else {
        JsValue::new(number).display().to_string()
    };
    observed("number", rendered)
}

fn observe_value(value: &JsValue) -> ObservedValue {
    if value.is_undefined() {
        return observed("undefined", String::new());
    }
    if value.is_null() {
        return observed("null", String::new());
    }
    let boolean: Option<bool> = value.as_boolean();
    if let Some(boolean) = boolean {
        return observed("boolean", boolean.to_string());
    }
    let number: Option<f64> = value.as_number();
    if let Some(number) = number {
        return observe_number(number);
    }
    let string: Option<&boa_engine::JsString> = value.as_string();
    if let Some(string) = string {
        return observed("string", string.to_std_string_escaped());
    }
    let bigint: Option<&boa_engine::JsBigInt> = value.as_bigint();
    if let Some(bigint) = bigint {
        return observed("bigint", bigint.to_string());
    }
    let symbol: Option<boa_engine::JsSymbol> = value.as_symbol();
    if let Some(symbol) = symbol {
        let description: String = symbol
            .description()
            .map(|value: boa_engine::JsString| value.to_std_string_escaped())
            .unwrap_or_default();
        return observed("symbol", description);
    }
    if value.is_callable() {
        return observed("function", String::new());
    }
    observed("object", String::new())
}

fn value_limit_reason(value: &JsValue) -> Option<String> {
    let bigint: Option<&boa_engine::JsBigInt> = value.as_bigint();
    if bigint.is_some_and(|bigint: &boa_engine::JsBigInt| !bigint.to_f64().is_finite()) {
        return Some("observable BigInt exceeds the supported magnitude".to_owned());
    }
    let string: Option<&boa_engine::JsString> = value.as_string();
    if let Some(string) = string {
        if string.len() > TRACE_VALUE_CODE_UNIT_LIMIT {
            return Some(format!(
                "observable string exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} UTF-16 code units"
            ));
        }
        return None;
    }
    let symbol: Option<boa_engine::JsSymbol> = value.as_symbol();
    let description: Option<boa_engine::JsString> =
        symbol.and_then(|symbol: boa_engine::JsSymbol| symbol.description());
    if description
        .as_ref()
        .is_some_and(|description: &boa_engine::JsString| {
            description.len() > TRACE_VALUE_CODE_UNIT_LIMIT
        })
    {
        return Some(format!(
            "observable symbol description exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} UTF-16 code units"
        ));
    }
    None
}

fn set_observation_limit(reason: String) {
    OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| {
        let mut state: std::cell::RefMut<'_, ObservationState> = state.borrow_mut();
        if state.limit.is_none() {
            state.limit = Some(reason);
        }
    });
}

fn observation_limit_reached() -> bool {
    OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| state.borrow().limit.is_some())
}

fn record_event(_this: &JsValue, args: &[JsValue], _context: &mut Context) -> JsResult<JsValue> {
    let Some(call_value): Option<&boa_engine::JsString> = args.first().and_then(JsValue::as_string)
    else {
        return Err(JsNativeError::typ()
            .with_message("trace event name must be a string")
            .into());
    };
    if observation_limit_reached() {
        return Ok(JsValue::undefined());
    }
    let event_count: usize =
        OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| state.borrow().trace.len());
    if event_count >= TRACE_EVENT_LIMIT {
        set_observation_limit(format!("trace event limit {TRACE_EVENT_LIMIT} exceeded"));
        return Ok(JsValue::undefined());
    }
    let argument_count: usize = args.len().saturating_sub(1);
    if argument_count > TRACE_ARGUMENT_LIMIT {
        set_observation_limit(format!(
            "trace argument limit {TRACE_ARGUMENT_LIMIT} exceeded"
        ));
        return Ok(JsValue::undefined());
    }
    if call_value.len() > TRACE_VALUE_CODE_UNIT_LIMIT {
        set_observation_limit(format!(
            "trace call name exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} UTF-16 code units"
        ));
        return Ok(JsValue::undefined());
    }
    let call: String = call_value.to_std_string_escaped();
    let mut arguments: Vec<ObservedValue> = Vec::with_capacity(argument_count);
    let mut event_bytes: usize = call.len();
    for value in args.iter().skip(1) {
        if let Some(reason) = value_limit_reason(value) {
            set_observation_limit(reason);
            return Ok(JsValue::undefined());
        }
        let observed: ObservedValue = observe_value(value);
        event_bytes = event_bytes
            .saturating_add(observed.kind.len())
            .saturating_add(observed.value.len());
        arguments.push(observed);
    }
    OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| {
        let mut state: std::cell::RefMut<'_, ObservationState> = state.borrow_mut();
        let next_bytes: usize = state.bytes.saturating_add(event_bytes);
        if next_bytes > TRACE_BYTE_LIMIT {
            state.limit = Some(format!("trace byte limit {TRACE_BYTE_LIMIT} exceeded"));
            return;
        }
        state.bytes = next_bytes;
        state.trace.push(TraceEvent { call, arguments });
    });
    Ok(JsValue::undefined())
}

fn reset_trace() {
    OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| {
        *state.borrow_mut() = ObservationState::default();
    });
}

fn take_observation() -> (Vec<TraceEvent>, Option<String>) {
    OBSERVATION_STATE.with(|state: &RefCell<ObservationState>| {
        let mut state: std::cell::RefMut<'_, ObservationState> = state.borrow_mut();
        (std::mem::take(&mut state.trace), state.limit.take())
    })
}

fn configure(context: &mut Context) {
    let runtime: &mut boa_engine::vm::RuntimeLimits = context.runtime_limits_mut();
    runtime.set_loop_iteration_limit(LOOP_LIMIT);
    runtime.set_recursion_limit(RECURSION_LIMIT);
    runtime.set_stack_size_limit(STACK_LIMIT);
}

fn argv_literal(argv: &[&str]) -> Result<String, String> {
    let mut parts: Vec<String> = Vec::with_capacity(argv.len() + 2);
    parts.push("\"node\"".to_owned());
    parts.push("\"script\"".to_owned());
    for arg in argv {
        let encoded: String = serde_json::to_string(arg)
            .map_err(|error: serde_json::Error| format!("encode process argument: {error}"))?;
        parts.push(encoded);
    }
    Ok(parts.join(", "))
}

fn process_prelude(argv: &[&str]) -> Result<String, String> {
    let argv_list: String = argv_literal(argv)?;
    Ok(format!(
        r#"var process = Object.freeze({{
  argv: Object.freeze([{argv_list}]),
  env: Object.freeze({{}}),
  platform: "boa",
  arch: "fixed",
  versions: Object.freeze({{}}),
  cwd: function () {{
    __disrobe_oracle_emit("process.cwd", arguments);
    return "/disrobe";
  }}
}});"#
    ))
}

fn terminal_from_error(error: &JsError, context: &mut Context) -> Terminal {
    if error
        .as_native()
        .is_some_and(boa_engine::JsNativeError::is_runtime_limit)
    {
        return Terminal::ExecutionLimitExceeded;
    }
    match error.try_native(context) {
        Ok(native) if native.is_runtime_limit() => Terminal::ExecutionLimitExceeded,
        Ok(native) => {
            let kind: String = native.kind.to_string();
            let message_source: &str = native.message();
            let message: String = if message_source.len() > TRACE_VALUE_CODE_UNIT_LIMIT {
                set_observation_limit(format!(
                    "thrown message exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} bytes"
                ));
                String::new()
            } else {
                message_source.to_owned()
            };
            Terminal::Threw { kind, message }
        }
        Err(_) => {
            let opaque: JsValue = error.to_opaque(context);
            let value: ObservedValue = value_limit_reason(&opaque).map_or_else(
                || observe_value(&opaque),
                |reason: String| {
                    set_observation_limit(reason);
                    observed("unavailable", String::new())
                },
            );
            Terminal::Threw {
                kind: format!("Thrown{}", value.kind),
                message: value.value,
            }
        }
    }
}

fn parse_failure_from_error(error: &JsError, context: &mut Context) -> Terminal {
    let native_result: Result<JsNativeError, TryNativeError> = error.try_native(context);
    if let Ok(native) = native_result {
        let kind: String = native.kind.to_string();
        let message_source: &str = native.message();
        let message: String = if message_source.len() > TRACE_VALUE_CODE_UNIT_LIMIT {
            set_observation_limit(format!(
                "parse error message exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} bytes"
            ));
            String::new()
        } else {
            message_source.to_owned()
        };
        Terminal::ParseFailed { kind, message }
    } else {
        let message_source: String = error.to_string();
        let message: String = if message_source.len() > TRACE_VALUE_CODE_UNIT_LIMIT {
            set_observation_limit(format!(
                "parse error message exceeds {TRACE_VALUE_CODE_UNIT_LIMIT} bytes"
            ));
            String::new()
        } else {
            message_source
        };
        Terminal::ParseFailed {
            kind: "ParseError".to_owned(),
            message,
        }
    }
}

fn eval_setup(context: &mut Context, source: &str, label: &str) -> Result<(), String> {
    context
        .eval(Source::from_bytes(source))
        .map(|_: JsValue| ())
        .map_err(|error: JsError| format!("{label}: {error}"))
}

enum Fueled {
    Finished(JsResult<JsValue>),
    Exhausted,
}

fn evaluate_with_step_fuel(script: &Script, context: &mut Context) -> Fueled {
    let mut evaluation: Pin<Box<dyn Future<Output = JsResult<JsValue>> + '_>> =
        Box::pin(script.evaluate_async_with_budget(context, STEP_SLICE_COST));
    let mut task_context: TaskContext<'_> = TaskContext::from_waker(Waker::noop());
    let mut slices: u64 = 0;
    loop {
        match evaluation.as_mut().poll(&mut task_context) {
            Poll::Ready(result) => return Fueled::Finished(result),
            Poll::Pending => {
                slices += 1;
                if slices >= STEP_SLICE_LIMIT {
                    return Fueled::Exhausted;
                }
            }
        }
    }
}

fn run_harness(program: &str, argv: &[&str], with_host: bool) -> Result<EvalOutcome, String> {
    reset_trace();
    let job_queue: Rc<OracleJobQueue> = Rc::new(OracleJobQueue::default());
    let mut context: Context = ContextBuilder::new()
        .host_hooks(&ORACLE_HOST_HOOKS)
        .job_queue(Rc::clone(&job_queue))
        .build()
        .map_err(|error: JsError| format!("initialize Boa context: {error}"))?;
    configure(&mut context);
    context
        .register_global_callable(
            js_string!("__disrobe_oracle_record"),
            1,
            NativeFunction::from_fn_ptr(record_event),
        )
        .map_err(|error: JsError| format!("register observation recorder: {error}"))?;
    eval_setup(&mut context, PRELUDE, "initialize deterministic runtime")?;
    if with_host {
        eval_setup(&mut context, BROWSER_SHIM, "initialize browser host")?;
    }
    let process: String = process_prelude(argv)?;
    eval_setup(&mut context, &process, "initialize process host")?;
    let evaluated_terminal: Terminal =
        match Script::parse(Source::from_bytes(program), None, &mut context) {
            Ok(script) => match evaluate_with_step_fuel(&script, &mut context) {
                Fueled::Finished(Ok(value)) => {
                    Terminal::Completed(value_limit_reason(&value).map_or_else(
                        || observe_value(&value),
                        |reason: String| {
                            set_observation_limit(reason);
                            observed("unavailable", String::new())
                        },
                    ))
                }
                Fueled::Finished(Err(error)) => terminal_from_error(&error, &mut context),
                Fueled::Exhausted => Terminal::ExecutionLimitExceeded,
            },
            Err(error) => parse_failure_from_error(&error, &mut context),
        };
    if job_queue.queued.get() {
        set_observation_limit("pending Promise jobs are unsupported".to_owned());
    }
    let (trace, limit): (Vec<TraceEvent>, Option<String>) = take_observation();
    let terminal: Terminal = limit.map_or(evaluated_terminal, Terminal::ObservationLimitExceeded);
    Ok(EvalOutcome { trace, terminal })
}

pub(crate) fn try_eval_outcome_with_argv(
    program: &str,
    argv: &[&str],
) -> Result<EvalOutcome, String> {
    run_harness(program, argv, true)
}

pub(crate) fn eval_outcome_with_argv(program: &str, argv: &[&str]) -> Option<EvalOutcome> {
    try_eval_outcome_with_argv(program, argv).ok()
}

pub(crate) fn eval_outcome_bare(program: &str) -> Option<EvalOutcome> {
    run_harness(program, &[], false).ok()
}

pub(crate) fn eval_outcome(program: &str) -> Option<EvalOutcome> {
    eval_outcome_with_argv(program, &[])
}

fn legacy_render(value: &ObservedValue) -> Option<String> {
    match value.kind.as_str() {
        "undefined" => Some("undefined".to_owned()),
        "null" => Some("null".to_owned()),
        "number" if value.value == "-0" => Some("0".to_owned()),
        "boolean" | "number" | "string" | "bigint" => Some(value.value.clone()),
        "symbol" => Some(format!("Symbol({})", value.value)),
        _ => None,
    }
}

fn console_capture(trace: &[TraceEvent]) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    for event in trace {
        if event.call != "print" && !event.call.starts_with("console.") {
            continue;
        }
        let values: Vec<String> = event
            .arguments
            .iter()
            .map(legacy_render)
            .collect::<Option<Vec<String>>>()?;
        entries.push(values.join(" "));
    }
    Some(entries.join("\u{1}"))
}

pub(crate) fn eval_capture_with_argv(program: &str, argv: &[&str]) -> Option<String> {
    match eval_outcome_with_argv(program, argv) {
        Some(EvalOutcome {
            trace,
            terminal: Terminal::Completed(_),
        }) => console_capture(&trace),
        _ => None,
    }
}

pub(crate) fn eval_stdout_with_argv(program: &str, argv: &[&str]) -> Option<String> {
    let EvalOutcome {
        trace,
        terminal: Terminal::Completed(_),
    } = eval_outcome_with_argv(program, argv)?
    else {
        return None;
    };
    let mut stdout: String = String::new();
    for event in trace {
        if !matches!(
            event.call.as_str(),
            "console.log" | "console.info" | "console.debug"
        ) {
            continue;
        }
        let values: Vec<String> = event
            .arguments
            .iter()
            .map(legacy_render)
            .collect::<Option<Vec<String>>>()?;
        stdout.push_str(&values.join(" "));
        stdout.push('\n');
    }
    Some(stdout)
}

pub(crate) fn eval_capture(program: &str) -> Option<String> {
    eval_capture_with_argv(program, &[])
}

pub(crate) fn assert_equivalent(label: &str, original: &str, recovered: &str) {
    let want: EvalOutcome =
        eval_outcome(original).unwrap_or_else(|| panic!("{label}: original fixture must evaluate"));
    let got: EvalOutcome = eval_outcome(recovered)
        .unwrap_or_else(|| panic!("{label}: recovered output must evaluate; src=\n{recovered}"));
    assert!(
        outcomes_equivalent(&want, &got),
        "{label}: recovered behavior diverged from original\n--want--\n{want:?}\n--got--\n{got:?}\n--recovered src--\n{recovered}"
    );
}

#[test]
#[ignore = "invoked only as bounded Boa subprocess worker"]
fn boa_eval_subprocess_worker() {
    let request_path: PathBuf = std::env::var_os(WORKER_REQUEST_ENV).map_or_else(
        || panic!("the Boa evaluation worker needs {WORKER_REQUEST_ENV} naming its request file"),
        PathBuf::from,
    );
    let response_path: PathBuf = std::env::var_os(WORKER_RESPONSE_ENV)
        .map(PathBuf::from)
        .expect("Boa evaluation worker response path must be set");
    let request_bytes: Vec<u8> =
        read_worker_request(&request_path).expect("Boa worker must read its bounded request");
    let request: EvalBatchRequest =
        serde_json::from_slice(&request_bytes).expect("Boa worker request must decode");
    let mut evaluations: Vec<Result<EvalOutcome, String>> =
        Vec::with_capacity(request.argv_battery.len());
    for argv in &request.argv_battery {
        let argv_refs: Vec<&str> = argv.iter().map(String::as_str).collect();
        evaluations.push(try_eval_outcome_with_argv(&request.program, &argv_refs));
    }
    let response_bytes: Vec<u8> = serde_json::to_vec(&EvalBatchResponse { evaluations })
        .expect("Boa worker response must encode");
    let response_limit: usize =
        usize::try_from(WORKER_RESPONSE_LIMIT).expect("Boa worker response limit must fit usize");
    assert!(
        response_bytes.len() <= response_limit,
        "Boa worker response exceeds {WORKER_RESPONSE_LIMIT} bytes"
    );
    fs::write(&response_path, response_bytes).expect("Boa worker must write its response");
}

fn worker_diagnostics(output: &ToolOutput) -> String {
    let stdout: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    format!(
        "exit={:?}; stdout={stdout:?}; stderr={stderr:?}",
        output.exit_code
    )
}

fn classify_worker_completion(output: &ToolOutput) -> Result<(), BoaWorkerError> {
    if output.timed_out {
        return Err(BoaWorkerError::BackstopExceeded);
    }
    if output.exit_code != Some(0) {
        return Err(BoaWorkerError::AllocationLimitRefusal {
            evidence: WorkerRefusalEvidence::WorkerTerminated,
            detail: format!(
                "Boa worker terminated without a valid result: {}",
                worker_diagnostics(output)
            ),
        });
    }
    Ok(())
}

fn decode_worker_response(
    response_bytes: &[u8],
    diagnostics: &str,
) -> Result<EvalBatchResponse, BoaWorkerError> {
    serde_json::from_slice(response_bytes).map_err(|error| BoaWorkerError::AllocationLimitRefusal {
        evidence: WorkerRefusalEvidence::InvalidReply,
        detail: format!("decode Boa worker response: {error}; {diagnostics}"),
    })
}

fn read_worker_response(path: &Path) -> Result<Vec<u8>, String> {
    read_bounded_worker_file(path, WORKER_RESPONSE_LIMIT, "Boa worker response")
}

fn read_worker_request(path: &Path) -> Result<Vec<u8>, String> {
    read_bounded_worker_file(path, WORKER_REQUEST_LIMIT, "Boa worker request")
}

fn read_bounded_worker_file(path: &Path, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let metadata: fs::Metadata =
        fs::metadata(path).map_err(|error: std::io::Error| format!("inspect {label}: {error}"))?;
    if metadata.len() > limit {
        return Err(format!(
            "{label} is {} bytes, above the {limit}-byte limit",
            metadata.len()
        ));
    }
    let file: fs::File =
        fs::File::open(path).map_err(|error: std::io::Error| format!("open {label}: {error}"))?;
    let mut reader: std::io::Take<fs::File> = file.take(limit.saturating_add(1));
    let mut bytes: Vec<u8> = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|error: std::io::Error| format!("read {label}: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
        return Err(format!(
            "{label} grew above the {limit}-byte limit while it was read"
        ));
    }
    Ok(bytes)
}

#[test]
fn oversized_worker_response_is_rejected_before_read() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-js-boa-response-limit").expect("scratch directory must open");
    let response_path: PathBuf = scratch.path().join("response.json");
    let response: fs::File =
        fs::File::create(&response_path).expect("response fixture must be created");
    response
        .set_len(WORKER_RESPONSE_LIMIT + 1)
        .expect("response fixture length must be set");
    let error: String =
        read_worker_response(&response_path).expect_err("oversized response must be rejected");
    assert!(
        error.contains("above the"),
        "response limit diagnostic missing: {error}"
    );
}

#[test]
fn oversized_worker_request_is_rejected_before_read() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-js-boa-request-limit").expect("scratch directory must open");
    let request_path: PathBuf = scratch.path().join("request.json");
    let request: fs::File =
        fs::File::create(&request_path).expect("request fixture must be created");
    request
        .set_len(WORKER_REQUEST_LIMIT + 1)
        .expect("request fixture length must be set");
    let error: String =
        read_worker_request(&request_path).expect_err("oversized request must be rejected");
    assert!(
        error.contains("above the"),
        "request limit diagnostic missing: {error}"
    );
}

#[test]
fn absent_worker_provider_returns_a_typed_refusal() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-js-boa-missing-worker").expect("scratch directory must open");
    let error: BoaWorkerError = BoaWorker::new(scratch.path().join("missing-worker"))
        .expect_err("an absent worker provider must be refused");
    assert!(
        matches!(error, BoaWorkerError::ProviderUnavailable(_)),
        "unexpected worker error: {error:?}"
    );
}

#[test]
fn worker_termination_maps_to_an_allocation_limit_refusal() {
    let output: ToolOutput = ToolOutput {
        success: false,
        timed_out: false,
        exit_code: None,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    let error: BoaWorkerError = classify_worker_completion(&output)
        .expect_err("worker termination must be a typed refusal");
    assert!(
        matches!(
            error,
            BoaWorkerError::AllocationLimitRefusal {
                evidence: WorkerRefusalEvidence::WorkerTerminated,
                ..
            }
        ),
        "unexpected worker error: {error:?}"
    );
}

#[test]
fn invalid_worker_reply_maps_to_an_allocation_limit_refusal() {
    let error: BoaWorkerError = decode_worker_response(b"{", "controlled diagnostics")
        .expect_err("an invalid worker reply must be a typed refusal");
    assert!(
        matches!(
            error,
            BoaWorkerError::AllocationLimitRefusal {
                evidence: WorkerRefusalEvidence::InvalidReply,
                ..
            }
        ),
        "unexpected worker error: {error:?}"
    );
}
