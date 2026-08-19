#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use disrobe_pass_wasm_deob::{
    LiftResult, LiftTarget, c_runtime_prelude, rust_runtime_prelude, try_lift_functions_from_module,
};

const RUN_DEADLINE: Duration = Duration::from_mins(2);
const WORKER_THREADS: u32 = 4;
const WORKER_INCREMENTS: u32 = 25_000;

const SHARED_ATOMICS_WAT: &str = r#"(module
  (memory 1 1 shared)
  (func (export "at_increment") (param i32) (result i32)
    local.get 0
    i32.const 1
    i32.atomic.rmw.add)
  (func (export "at_cmpxchg") (param i32 i32 i32) (result i32)
    local.get 0
    local.get 1
    local.get 2
    i32.atomic.rmw.cmpxchg)
  (func (export "at_fence")
    atomic.fence)
  (func (export "at_load") (param i32) (result i32)
    local.get 0
    i32.atomic.load)
  (func (export "at_store") (param i32 i32)
    local.get 0
    local.get 1
    i32.atomic.store)
  (func (export "at_store64") (param i32 i64)
    local.get 0
    local.get 1
    i64.atomic.store)
  (func (export "at_wait32") (param i32 i32 i64) (result i32)
    local.get 0
    local.get 1
    local.get 2
    memory.atomic.wait32)
  (func (export "at_wait64") (param i32 i64 i64) (result i32)
    local.get 0
    local.get 1
    local.get 2
    memory.atomic.wait64)
  (func (export "at_notify") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    memory.atomic.notify))
"#;

const RUST_DRIVER: &str = r#"
fn spawn_waiters(
    address: i32,
    arrived: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    finished: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    outcomes: &std::sync::Arc<std::sync::Mutex<Vec<i32>>>,
) -> Vec<std::thread::JoinHandle<()>> {
    let mut handles: Vec<std::thread::JoinHandle<()>> = Vec::new();
    for _ in 0..2 {
        let arrived: std::sync::Arc<std::sync::atomic::AtomicUsize> = std::sync::Arc::clone(arrived);
        let finished: std::sync::Arc<std::sync::atomic::AtomicUsize> = std::sync::Arc::clone(finished);
        let outcomes: std::sync::Arc<std::sync::Mutex<Vec<i32>>> = std::sync::Arc::clone(outcomes);
        handles.push(std::thread::spawn(move || {
            arrived.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let outcome: i32 = at_wait32(address, 0, -1);
            outcomes.lock().expect("outcome lock").push(outcome);
            finished.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }));
    }
    while arrived.load(std::sync::atomic::Ordering::SeqCst) < 2 {
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    std::thread::sleep(std::time::Duration::from_millis(300));
    handles
}

fn main() {
    let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
    for _ in 0..WORKER_THREADS_PLACEHOLDER {
        workers.push(std::thread::spawn(|| {
            for _ in 0..WORKER_INCREMENTS_PLACEHOLDER {
                at_increment(0);
                at_fence();
            }
        }));
    }
    for worker in workers {
        worker.join().expect("worker join");
    }
    println!("rmw_total {}", at_load(0));

    at_store(64, 0);
    let arrived: std::sync::Arc<std::sync::atomic::AtomicUsize> =
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let finished: std::sync::Arc<std::sync::atomic::AtomicUsize> =
        std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let outcomes: std::sync::Arc<std::sync::Mutex<Vec<i32>>> =
        std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let waiters: Vec<std::thread::JoinHandle<()>> =
        spawn_waiters(64, &arrived, &finished, &outcomes);
    let mut first: i32 = 0;
    let mut largest: i32 = 0;
    let mut total: i32 = 0;
    let mut attempts: u32 = 0;
    while first == 0 && attempts < 400 {
        first = at_notify(64, 1);
        largest = largest.max(first);
        total += first;
        attempts += 1;
        if first == 0 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    std::thread::sleep(std::time::Duration::from_millis(250));
    println!("notify_first {first}");
    println!("woke_after_first {}", finished.load(std::sync::atomic::Ordering::SeqCst));
    println!("grow_during_wait {}", wasm_memory_grow(1));
    println!("size_after_grow {}", wasm_memory_size());
    let mut second: i32 = 0;
    attempts = 0;
    while second == 0 && attempts < 400 {
        second = at_notify(64, 1);
        largest = largest.max(second);
        total += second;
        attempts += 1;
        if second == 0 {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }
    println!("notify_second {second}");
    println!("notify_largest_single {largest}");
    println!("notify_total {total}");
    for waiter in waiters {
        waiter.join().expect("waiter join");
    }
    let mut observed: Vec<i32> = outcomes.lock().expect("outcome lock").clone();
    observed.sort_unstable();
    println!("wait_outcome_low {}", observed[0]);
    println!("wait_outcome_high {}", observed[1]);

    println!("not_equal {}", at_wait32(64, 12345, -1));
    println!("timeout_zero {}", at_wait32(64, 0, 0));
    let started: std::time::Instant = std::time::Instant::now();
    let timed: i32 = at_wait32(64, 0, 40_000_000);
    let blocked: bool = started.elapsed() >= std::time::Duration::from_millis(30);
    println!("timed_out {timed}");
    println!("timed_out_blocked {}", i32::from(blocked));
    println!("notify_no_waiters {}", at_notify(64, 100));
    println!("notify_zero_count {}", at_notify(64, 0));

    at_store64(128, 0);
    println!("wait64_not_equal {}", at_wait64(128, 9, -1));
    println!("wait64_timeout_zero {}", at_wait64(128, 0, 0));

    at_store(192, 11);
    println!("cmpxchg_hit {}", at_cmpxchg(192, 11, 12));
    println!("cmpxchg_miss {}", at_cmpxchg(192, 11, 13));
    println!("cmpxchg_final {}", at_load(192));
}
"#;

const C_DRIVER: &str = r#"
#if defined(_WIN32)
typedef HANDLE probe_thread;
static DWORD WINAPI probe_incrementer(LPVOID argument);
static DWORD WINAPI probe_waiter(LPVOID argument);
static void probe_spawn_incrementer(probe_thread *handle) { *handle = CreateThread(NULL, 0, probe_incrementer, NULL, 0, NULL); }
static void probe_spawn_waiter(probe_thread *handle) { *handle = CreateThread(NULL, 0, probe_waiter, NULL, 0, NULL); }
static void probe_join(probe_thread handle) { WaitForSingleObject(handle, INFINITE); CloseHandle(handle); }
static void probe_pause_ms(unsigned long milliseconds) { Sleep(milliseconds); }
#define PROBE_INCREMENTER DWORD WINAPI probe_incrementer(LPVOID argument)
#define PROBE_WAITER DWORD WINAPI probe_waiter(LPVOID argument)
#define PROBE_RETURN return 0
#else
typedef pthread_t probe_thread;
static void *probe_incrementer(void *argument);
static void *probe_waiter(void *argument);
static void probe_spawn_incrementer(probe_thread *handle) { pthread_create(handle, NULL, probe_incrementer, NULL); }
static void probe_spawn_waiter(probe_thread *handle) { pthread_create(handle, NULL, probe_waiter, NULL); }
static void probe_join(probe_thread handle) { pthread_join(handle, NULL); }
static void probe_pause_ms(unsigned long milliseconds) { struct timespec nap; nap.tv_sec = (time_t)(milliseconds / 1000u); nap.tv_nsec = (long)((milliseconds % 1000u) * 1000000u); nanosleep(&nap, NULL); }
#define PROBE_INCREMENTER void *probe_incrementer(void *argument)
#define PROBE_WAITER void *probe_waiter(void *argument)
#define PROBE_RETURN return NULL
#endif

static int32_t probe_outcomes[2];
static int probe_outcome_count;
static int probe_finished;
static int probe_arrived;

PROBE_INCREMENTER {
  (void)argument;
  for (uint32_t index = 0; index < WORKER_INCREMENTS_PLACEHOLDER; index++) {
    at_increment(0);
    at_fence();
  }
  PROBE_RETURN;
}

PROBE_WAITER {
  (void)argument;
  __atomic_fetch_add(&probe_arrived, 1, __ATOMIC_SEQ_CST);
  int32_t outcome = at_wait32(64, 0, INT64_C(-1));
  int slot = __atomic_fetch_add(&probe_outcome_count, 1, __ATOMIC_SEQ_CST);
  if (slot < 2) __atomic_store_n(&probe_outcomes[slot], outcome, __ATOMIC_SEQ_CST);
  __atomic_fetch_add(&probe_finished, 1, __ATOMIC_SEQ_CST);
  PROBE_RETURN;
}

int main(void) {
  probe_thread workers[WORKER_THREADS_PLACEHOLDER];
  for (int index = 0; index < WORKER_THREADS_PLACEHOLDER; index++) probe_spawn_incrementer(&workers[index]);
  for (int index = 0; index < WORKER_THREADS_PLACEHOLDER; index++) probe_join(workers[index]);
  printf("rmw_total %d\n", at_load(0));

  at_store(64, 0);
  probe_thread waiters[2];
  for (int index = 0; index < 2; index++) probe_spawn_waiter(&waiters[index]);
  while (__atomic_load_n(&probe_arrived, __ATOMIC_SEQ_CST) < 2) probe_pause_ms(5);
  probe_pause_ms(300);
  int32_t first = 0;
  int32_t largest = 0;
  int32_t total = 0;
  int attempts = 0;
  while (first == 0 && attempts < 400) { first = at_notify(64, 1); if (first > largest) largest = first; total += first; attempts++; if (first == 0) probe_pause_ms(5); }
  probe_pause_ms(250);
  printf("notify_first %d\n", first);
  printf("woke_after_first %d\n", __atomic_load_n(&probe_finished, __ATOMIC_SEQ_CST));
  int32_t second = 0;
  attempts = 0;
  while (second == 0 && attempts < 400) { second = at_notify(64, 1); if (second > largest) largest = second; total += second; attempts++; if (second == 0) probe_pause_ms(5); }
  printf("notify_second %d\n", second);
  printf("notify_largest_single %d\n", largest);
  printf("notify_total %d\n", total);
  for (int index = 0; index < 2; index++) probe_join(waiters[index]);
  int32_t low = probe_outcomes[0] < probe_outcomes[1] ? probe_outcomes[0] : probe_outcomes[1];
  int32_t high = probe_outcomes[0] < probe_outcomes[1] ? probe_outcomes[1] : probe_outcomes[0];
  printf("wait_outcome_low %d\n", low);
  printf("wait_outcome_high %d\n", high);

  printf("not_equal %d\n", at_wait32(64, 12345, INT64_C(-1)));
  printf("timeout_zero %d\n", at_wait32(64, 0, INT64_C(0)));
  uint64_t started = wasm_atomic_now_ns();
  int32_t timed = at_wait32(64, 0, INT64_C(40000000));
  uint64_t elapsed = wasm_atomic_now_ns() - started;
  printf("timed_out %d\n", timed);
  printf("timed_out_blocked %d\n", !(elapsed < UINT64_C(30000000)));
  printf("notify_no_waiters %d\n", at_notify(64, 100));
  printf("notify_zero_count %d\n", at_notify(64, 0));

  at_store64(128, INT64_C(0));
  printf("wait64_not_equal %d\n", at_wait64(128, INT64_C(9), INT64_C(-1)));
  printf("wait64_timeout_zero %d\n", at_wait64(128, INT64_C(0), INT64_C(0)));

  at_store(192, 11);
  printf("cmpxchg_hit %d\n", at_cmpxchg(192, 11, 12));
  printf("cmpxchg_miss %d\n", at_cmpxchg(192, 11, 13));
  printf("cmpxchg_final %d\n", at_load(192));
  return 0;
}
"#;

fn tool(name: &str) -> Option<PathBuf> {
    let finder: &str = if cfg!(windows) { "where" } else { "which" };
    let output: Output = Command::new(finder).arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout.lines().next().map(PathBuf::from)
}

fn lifted_functions(bytes: &[u8], target: LiftTarget) -> String {
    let lifted: Vec<LiftResult> = try_lift_functions_from_module(bytes, target)
        .expect("every shared-memory atomic export must lift without a refusal");
    let mut source: String = String::new();
    for result in &lifted {
        source.push_str(&result.pseudo_source);
        source.push('\n');
    }
    source
}

fn substituted(driver: &str) -> String {
    driver
        .replace("WORKER_THREADS_PLACEHOLDER", &WORKER_THREADS.to_string())
        .replace(
            "WORKER_INCREMENTS_PLACEHOLDER",
            &WORKER_INCREMENTS.to_string(),
        )
}

fn run_bounded(mut child: Child, label: &str) -> Output {
    let started: Instant = Instant::now();
    while child.try_wait().expect("poll the lifted program").is_none() {
        if started.elapsed() > RUN_DEADLINE {
            let _ignored: std::io::Result<()> = child.kill();
            let _reaped: std::io::Result<std::process::ExitStatus> = child.wait();
            panic!(
                "{label}: the lifted program did not finish within {RUN_DEADLINE:?}, so a blocking \
                 wait never woke"
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child
        .wait_with_output()
        .expect("collect the lifted program output")
}

fn observed_values(label: &str, stdout: &str) -> BTreeMap<String, i64> {
    let mut values: BTreeMap<String, i64> = BTreeMap::new();
    for line in stdout.lines() {
        let mut fields: std::str::SplitWhitespace<'_> = line.split_whitespace();
        let Some(key): Option<&str> = fields.next() else {
            panic!("{label}: empty output line");
        };
        let Some(raw): Option<&str> = fields.next() else {
            panic!("{label}: incomplete output line {line:?}");
        };
        assert!(
            fields.next().is_none(),
            "{label}: output line has too many fields {line:?}"
        );
        let Ok(value): Result<i64, _> = raw.parse::<i64>() else {
            panic!("{label}: unparsable output line {line:?}");
        };
        assert!(
            values.insert(key.to_owned(), value).is_none(),
            "{label}: duplicate output key {key:?}"
        );
    }
    values
}

fn spec_outcomes(with_growth: bool) -> Vec<(&'static str, i64)> {
    let total: i64 = i64::from(WORKER_THREADS) * i64::from(WORKER_INCREMENTS);
    let mut expected: Vec<(&'static str, i64)> = vec![
        ("rmw_total", total),
        ("notify_first", 1),
        ("woke_after_first", 1),
        ("notify_second", 1),
        ("notify_largest_single", 1),
        ("notify_total", 2),
        ("wait_outcome_low", 0),
        ("wait_outcome_high", 0),
        ("not_equal", 1),
        ("timeout_zero", 2),
        ("timed_out", 2),
        ("timed_out_blocked", 1),
        ("notify_no_waiters", 0),
        ("notify_zero_count", 0),
        ("wait64_not_equal", 1),
        ("wait64_timeout_zero", 2),
        ("cmpxchg_hit", 11),
        ("cmpxchg_miss", 12),
        ("cmpxchg_final", 12),
    ];
    if with_growth {
        expected.push(("grow_during_wait", 1));
        expected.push(("size_after_grow", 2));
    }
    expected
}

fn grade(label: &str, stdout: &str, with_growth: bool) {
    let observed: BTreeMap<String, i64> = observed_values(label, stdout);
    let expected: Vec<(&'static str, i64)> = spec_outcomes(with_growth);
    let denominator: usize = expected.len();
    let mut matched: usize = 0;
    let mut divergences: Vec<String> = Vec::new();
    for (key, want) in &expected {
        match observed.get(*key) {
            Some(got) if got == want => matched += 1,
            Some(got) => divergences.push(format!("{key}: expected {want}, observed {got}")),
            None => divergences.push(format!("{key}: the lifted program printed nothing")),
        }
    }
    assert!(
        divergences.is_empty(),
        "{label}: {matched}/{denominator} spec-mandated outcomes reproduced; divergences:\n{}",
        divergences.join("\n")
    );
    assert_eq!(
        matched, denominator,
        "{label}: {matched}/{denominator} spec-mandated outcomes reproduced"
    );
    assert_eq!(
        observed.len(),
        denominator,
        "{label}: the lifted program printed {} results but {denominator} are graded, so a case \
         was silently dropped",
        observed.len()
    );
    println!("{label}: {matched}/{denominator} spec-mandated outcomes reproduced");
}

#[test]
fn rust_lift_shares_memory_and_blocks_on_wait_until_notify() {
    let bytes: Vec<u8> = wat::parse_str(SHARED_ATOMICS_WAT).expect("assemble the shared module");
    let program: String = format!(
        "{}\n{}\n{}",
        rust_runtime_prelude(),
        lifted_functions(&bytes, LiftTarget::Rust),
        substituted(RUST_DRIVER)
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm-shared-atomics-rust")
            .expect("create scratch directory");
    let source_path: PathBuf = scratch.path().join("shared_atomics.rs");
    std::fs::write(&source_path, &program).expect("write the Rust program");
    let binary: PathBuf = scratch.path().join(if cfg!(windows) {
        "shared.exe"
    } else {
        "shared"
    });
    let rustc: PathBuf =
        tool("rustc").expect("rustc is required for the shared-memory atomics gate");
    let build: Output = Command::new(rustc)
        .args(["--edition", "2021", "-O", "-o"])
        .arg(&binary)
        .arg(&source_path)
        .output()
        .expect("run rustc");
    assert!(
        build.status.success(),
        "rustc rejected the lifted shared-memory program: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    let child: Child = Command::new(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the lifted Rust program");
    let run: Output = run_bounded(child, "rust");
    assert!(
        run.status.success(),
        "the lifted Rust program exited {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    grade("rust", &String::from_utf8_lossy(&run.stdout), true);
}

#[test]
fn c_lift_shares_memory_and_blocks_on_wait_until_notify() {
    let bytes: Vec<u8> = wat::parse_str(SHARED_ATOMICS_WAT).expect("assemble the shared module");
    let program: String = format!(
        "{}\n{}\n{}",
        c_runtime_prelude(),
        lifted_functions(&bytes, LiftTarget::C),
        substituted(C_DRIVER)
    );
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm-shared-atomics-c")
            .expect("create scratch directory");
    let source_path: PathBuf = scratch.path().join("shared_atomics.c");
    std::fs::write(&source_path, &program).expect("write the C program");
    let binary: PathBuf = scratch.path().join(if cfg!(windows) {
        "shared.exe"
    } else {
        "shared"
    });
    let compiler: PathBuf = ["cc", "clang", "gcc"]
        .into_iter()
        .find_map(tool)
        .expect("a C11 compiler is required for the shared-memory atomics gate");
    let mut build: Command = Command::new(&compiler);
    build
        .arg("-O2")
        .arg("-std=c11")
        .arg("-o")
        .arg(&binary)
        .arg(&source_path);
    if !cfg!(windows) {
        build.arg("-pthread").arg("-lm");
    }
    let built: Output = build.output().expect("run the C compiler");
    assert!(
        built.status.success(),
        "the C compiler rejected the lifted shared-memory program: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let child: Child = Command::new(&binary)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the lifted C program");
    let run: Output = run_bounded(child, "c");
    assert!(
        run.status.success(),
        "the lifted C program exited {:?}: {}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );
    grade("c", &String::from_utf8_lossy(&run.stdout), false);
}
