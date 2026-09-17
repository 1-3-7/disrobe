#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_wasm_deob::{
    AtomicMemoryRefusal, Error, LiftTarget, TypeScriptModuleLift, try_lift_function_from_module,
    try_lift_typescript_module, typescript_runtime_prelude,
};

const NODE_TIMEOUT: Duration = Duration::from_secs(30);
const NODE_CAPTURE: usize = 256 * 1024;

fn node() -> PathBuf {
    ["node", "node.exe"]
        .into_iter()
        .map(PathBuf::from)
        .find(|candidate: &PathBuf| {
            std::process::Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output: std::process::Output| output.status.success())
        })
        .expect("Node is required for the TypeScript atomic runtime gate")
}

fn run_typescript(source: &str) -> CapturedOutput {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm-typescript-atomic-runtime")
            .expect("create scratch directory");
    let source_path: PathBuf = scratch.path().join("atomic-runtime.ts");
    std::fs::write(&source_path, source).expect("write TypeScript atomic runtime");
    let args: Vec<OsString> = vec![
        OsString::from("--experimental-strip-types"),
        OsString::from("--no-warnings"),
        source_path.as_os_str().to_owned(),
    ];
    run_captured(&node(), &args, NODE_TIMEOUT, NODE_CAPTURE)
        .expect("spawn Node")
        .expect("Node atomic runtime must finish within its deadline")
}

#[test]
fn typescript_module_factory_isolates_default_shared_memories() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "increment") (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.atomic.rmw.add))"#,
    )
    .expect("assemble the fixed shared-memory module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift the complete TypeScript module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r"
const first: LiftedInstance = instantiate();
const second: LiftedInstance = instantiate();
const observed: readonly number[] = [
  first.increment(0),
  first.increment(0),
  second.increment(0),
  new Int32Array(first.memory.buffer)[0],
  new Int32Array(second.memory.buffer)[0],
];
console.log(JSON.stringify(observed));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the TypeScript module factory: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[0,1,0,2,1]"
    );
}

#[test]
fn typescript_module_factory_preserves_function_export_aliases() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func $increment (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.atomic.rmw.add)
          (export "increment" (func $increment))
          (export "increment_alias" (func $increment)))"#,
    )
    .expect("assemble aliased atomic function module");
    let lifted: TypeScriptModuleLift =
        try_lift_typescript_module(&bytes).expect("lift aliased TypeScript module");
    assert_eq!(
        lifted.exported_functions,
        ["increment".to_owned(), "increment_alias".to_owned()]
    );
    let execution: String = format!(
        "{}\n{}",
        lifted.source,
        r"
const instance: LiftedInstance = instantiate();
console.log(JSON.stringify([instance.increment(0), instance.increment_alias(0)]));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected aliased TypeScript exports: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[0,1]");
}

#[test]
fn typescript_module_factory_preserves_exact_colliding_export_names() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "value-hyphen") (result i32)
            i32.const 17)
          (func (export "value_hyphen") (result i32)
            i32.const 29))"#,
    )
    .expect("assemble colliding export-name module");
    let lifted: TypeScriptModuleLift =
        try_lift_typescript_module(&bytes).expect("lift exact export-name module");
    assert_eq!(
        lifted.exported_functions,
        ["value-hyphen".to_owned(), "value_hyphen".to_owned()]
    );
    let execution: String = format!(
        "{}\n{}",
        lifted.source,
        r#"
const instance: LiftedInstance = instantiate();
console.log(JSON.stringify([instance["value-hyphen"](), instance.value_hyphen()]));
"#
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected exact TypeScript exports: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[17,29]");
}

#[test]
fn typescript_module_factory_isolates_internal_names_from_local_debug_names() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func $callee (result i32)
            i32.const 43)
          (func (export "run") (param $disrobeWasmFunction0 i32) (result i32)
            call $callee))"#,
    )
    .expect("assemble local-name collision module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift local-name collision module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r"
const instance: LiftedInstance = instantiate();
console.log(instance.run(7));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected isolated internal names: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "43");
}

#[test]
fn typescript_module_factory_publishes_proto_named_exports_as_own_properties() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "__proto__") (result i32)
            i32.const 37))"#,
    )
    .expect("assemble prototype-named export module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift prototype-named TypeScript module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r#"
const instance: LiftedInstance = instantiate();
const owns: boolean = Object.prototype.hasOwnProperty.call(instance, "__proto__");
console.log(JSON.stringify([owns, instance["__proto__"]()]));
"#
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the prototype-named export: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[true,37]");
}

#[test]
fn typescript_module_factory_refuses_an_export_that_shadows_instance_memory() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "memory") (result i32)
            i32.const 1))"#,
    )
    .expect("assemble memory-named function export module");
    let error: Error = try_lift_typescript_module(&bytes)
        .expect_err("a function export must not shadow the instance memory");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::ReservedExportName { function_index: 0 })
    ));
}

#[test]
fn standalone_typescript_function_refuses_instance_owned_atomics() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    )
    .expect("assemble standalone atomic function module");
    let error: Error = try_lift_function_from_module(&bytes, 0, LiftTarget::TypeScript)
        .expect_err("standalone TypeScript function lifting must not invent instance memory");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::UnsupportedTarget {
            target: "typescript",
            operation: "instance-owned atomic memory"
        })
    ));
}

const SYNCHRONIZATION_WAT: &str = r#"(module
  (memory 1 1 shared)
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
    memory.atomic.notify)
  (func (export "at_fence")
    atomic.fence))
"#;

fn synchronization_module_source() -> String {
    let bytes: Vec<u8> =
        wat::parse_str(SYNCHRONIZATION_WAT).expect("assemble the synchronization module");
    try_lift_typescript_module(&bytes)
        .expect("the TypeScript module lift must express wait, notify and fence")
        .source
}

#[test]
fn typescript_module_emits_engine_atomics_for_every_synchronization_operation() {
    let source: String = synchronization_module_source();
    for expected in [
        "wasmMemoryAtomicWait32(",
        "wasmMemoryAtomicWait64(",
        "wasmMemoryAtomicNotify(",
        "wasmAtomicFence();",
        "Atomics.wait(",
        "Atomics.notify(",
        "new WebAssembly.Instance(compiled, {}).exports[\"fence\"]",
    ] {
        assert!(
            source.contains(expected),
            "the lifted TypeScript module must reach {expected}"
        );
    }
}

#[test]
fn typescript_module_reports_the_specified_wait_and_notify_outcomes() {
    let source: String = format!(
        "{}\n{}",
        synchronization_module_source(),
        r"
const instance: LiftedInstance = instantiate();
instance.at_fence();
instance.at_store(64, 7);
instance.at_store64(128, 0n);
const started: number = Date.now();
const timedOut: number = instance.at_wait32(64, 7, 20000000n);
const blocked: number = Date.now() - started >= 15 ? 1 : 0;
console.log(JSON.stringify([
  instance.at_wait32(64, 8, -1n),
  instance.at_wait32(64, 7, 0n),
  timedOut,
  blocked,
  instance.at_notify(64, 100),
  instance.at_notify(64, 0),
  instance.at_wait64(128, 9n, -1n),
  instance.at_wait64(128, 0n, 0n),
]));
"
    );
    let output: CapturedOutput = run_typescript(&source);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the lifted synchronization module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[1,2,2,1,0,0,1,2]"
    );
}

#[test]
fn typescript_module_wait_blocks_until_notify_wakes_exactly_one_worker() {
    let source: String = format!(
        "{}\n{}",
        synchronization_module_source(),
        r#"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const sleep = (milliseconds: number): Promise<void> =>
  new Promise<void>((resolve: () => void): void => { setTimeout(resolve, milliseconds); });

const ARRIVAL_INDEX: number = 64;

if (isMainThread) {
  const instance: LiftedInstance = instantiate();
  instance.at_store(64, 0);
  const arrivals: Int32Array = new Int32Array(instance.memory.buffer);
  const outcomes: number[] = [];
  const exits: Promise<void>[] = [];
  for (let index: number = 0; index < 2; index += 1) {
    const worker: Worker = new Worker(import.meta.filename, {
      execArgv: ["--experimental-strip-types", "--no-warnings"],
      workerData: { wasmMemory: instance.memory },
    });
    worker.on("message", (value: number): void => { outcomes.push(value); });
    exits.push(new Promise<void>((resolve: () => void, reject: (reason: unknown) => void): void => {
      worker.once("exit", (): void => resolve());
      worker.once("error", (error: Error): void => reject(error));
    }));
  }
  while (Atomics.load(arrivals, ARRIVAL_INDEX) < 2) { await sleep(5); }
  await sleep(400);
  let first: number = 0;
  let largest: number = 0;
  let total: number = 0;
  for (let attempt: number = 0; attempt < 400 && first === 0; attempt += 1) {
    first = instance.at_notify(64, 1);
    largest = Math.max(largest, first);
    total += first;
    if (first === 0) await sleep(5);
  }
  await sleep(400);
  const wokeAfterFirst: number = outcomes.length;
  let second: number = 0;
  for (let attempt: number = 0; attempt < 400 && second === 0; attempt += 1) {
    second = instance.at_notify(64, 1);
    largest = Math.max(largest, second);
    total += second;
    if (second === 0) await sleep(5);
  }
  if (second !== 0) { await Promise.all(exits); }
  outcomes.sort((left: number, right: number): number => left - right);
  console.log(JSON.stringify([first, second, largest, total, wokeAfterFirst, outcomes[0], outcomes[1]]));
} else {
  const instance: LiftedInstance = instantiate({ memories: [workerData.wasmMemory] });
  Atomics.add(new Int32Array(workerData.wasmMemory.buffer), ARRIVAL_INDEX, 1);
  parentPort?.postMessage(instance.at_wait32(64, 0, -1n));
}
"#
    );
    let output: CapturedOutput = run_typescript(&source);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the lifted blocking-wait module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[1,1,1,2,1,0,0]"
    );
}

#[test]
fn typescript_negative_wait_timeouts_remain_blocked_for_both_widths_until_notify() {
    let source: String = format!(
        "{}\n{}",
        synchronization_module_source(),
        r#"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const sleep = (milliseconds: number): Promise<void> =>
  new Promise<void>((resolve: () => void): void => { setTimeout(resolve, milliseconds); });

const ARRIVAL_INDEX: number = 64;
const INFINITE_WAIT_HOLD_MILLISECONDS: number = 50;

const notifyRegisteredWaiter = async (instance: LiftedInstance, address: number): Promise<number> => {
  for (let attempt: number = 0; attempt < 400; attempt += 1) {
    const notified: number = instance.at_notify(address, 1);
    if (notified === 1) return notified;
    await sleep(5);
  }
  throw new Error(`no waiter registered at address ${address} within 400 attempts`);
};

if (isMainThread) {
  const instance: LiftedInstance = instantiate();
  instance.at_store(64, 0);
  instance.at_store64(128, 0n);
  const arrivals: Int32Array = new Int32Array(instance.memory.buffer);
  const outcomes: Array<readonly [number, number]> = [];
  const exits: Promise<void>[] = [];
  const widths: readonly number[] = [32, 64];
  for (const width of widths) {
    const worker: Worker = new Worker(import.meta.filename, {
      execArgv: ["--experimental-strip-types", "--no-warnings"],
      workerData: { wasmMemory: instance.memory, width },
    });
    worker.on("message", (value: readonly [number, number]): void => { outcomes.push(value); });
    exits.push(new Promise<void>((resolve: () => void, reject: (reason: unknown) => void): void => {
      worker.once("exit", (): void => resolve());
      worker.once("error", (error: Error): void => reject(error));
    }));
  }
  while (Atomics.load(arrivals, ARRIVAL_INDEX) < 2) { await sleep(5); }
  await sleep(INFINITE_WAIT_HOLD_MILLISECONDS);
  const notified32: number = await notifyRegisteredWaiter(instance, 64);
  const notified64: number = await notifyRegisteredWaiter(instance, 128);
  await Promise.all(exits);
  outcomes.sort((left: readonly [number, number], right: readonly [number, number]): number => left[0] - right[0]);
  console.log(JSON.stringify([notified32, notified64, outcomes]));
} else {
  const instance: LiftedInstance = instantiate({ memories: [workerData.wasmMemory] });
  const width: number = workerData.width;
  Atomics.add(new Int32Array(workerData.wasmMemory.buffer), ARRIVAL_INDEX, 1);
  const outcome: number = width === 64
    ? instance.at_wait64(128, 0n, -1n)
    : instance.at_wait32(64, 0, -1n);
  const result: readonly [number, number] = [width, outcome];
  parentPort?.postMessage(result);
}
"#
    );
    let output: CapturedOutput = run_typescript(&source);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the lifted infinite-wait module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[1,1,[[32,0],[64,0]]]"
    );
}

#[test]
fn typescript_module_reinterpretation_does_not_mutate_linear_memory() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "reinterpret") (param f32) (result i32)
            local.get 0
            i32.reinterpret_f32))"#,
    )
    .expect("assemble reinterpretation module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift reinterpretation module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r"
const instance: LiftedInstance = instantiate();
const bits: number = instance.reinterpret(1.5);
const memory: readonly number[] = Array.from(new Uint8Array(instance.memory.buffer, 0, 4));
console.log(JSON.stringify([bits, memory]));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the reinterpretation module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "[1069547520,[0,0,0,0]]"
    );
}

#[test]
fn supplied_memory_cannot_widen_the_lifted_module_address_space() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "load") (param i32) (result i32)
            local.get 0
            i32.atomic.load))"#,
    )
    .expect("assemble fixed-memory load module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift fixed-memory load module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r#"
const backing: WebAssembly.Memory = new WebAssembly.Memory({ initial: 2, maximum: 2, shared: true });
const instance: LiftedInstance = instantiate({ memories: [backing] });
let result: string = "accepted";
try {
  instance.load(65536);
} catch (error: unknown) {
  result = error instanceof RangeError ? error.message : "wrong-error";
}
console.log(result);
"#
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the supplied-memory boundary gate: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "wasm atomic trap"
    );
}

#[test]
fn typescript_module_executes_nonblocking_atomic_families_and_widths() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "store32") (param i32 i32) local.get 0 local.get 1 i32.atomic.store)
          (func (export "load32") (param i32) (result i32) local.get 0 i32.atomic.load)
          (func (export "add32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.add)
          (func (export "sub32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.sub)
          (func (export "and32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.and)
          (func (export "or32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.or)
          (func (export "xor32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.xor)
          (func (export "exchange32") (param i32 i32) (result i32) local.get 0 local.get 1 i32.atomic.rmw.xchg)
          (func (export "compare32") (param i32 i32 i32) (result i32) local.get 0 local.get 1 local.get 2 i32.atomic.rmw.cmpxchg)
          (func (export "store8") (param i32 i32) local.get 0 local.get 1 i32.atomic.store8)
          (func (export "load8") (param i32) (result i32) local.get 0 i32.atomic.load8_u)
          (func (export "store16") (param i32 i32) local.get 0 local.get 1 i32.atomic.store16)
          (func (export "load16") (param i32) (result i32) local.get 0 i32.atomic.load16_u)
          (func (export "store64") (param i32 i64) local.get 0 local.get 1 i64.atomic.store)
          (func (export "load64") (param i32) (result i64) local.get 0 i64.atomic.load)
          (func (export "add64") (param i32 i64) (result i64) local.get 0 local.get 1 i64.atomic.rmw.add)
          (func (export "store64_32") (param i32 i64) local.get 0 local.get 1 i64.atomic.store32)
          (func (export "load64_32") (param i32) (result i64) local.get 0 i64.atomic.load32_u)
          (func (export "compare64_8") (param i32 i64 i64) (result i64) local.get 0 local.get 1 local.get 2 i64.atomic.rmw8.cmpxchg_u))"#,
    )
    .expect("assemble nonblocking atomic family module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift nonblocking atomic family module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r"
const instance: LiftedInstance = instantiate();
const observed: string[] = [];
instance.store32(0, 15);
observed.push(String(instance.add32(0, 5)));
observed.push(String(instance.sub32(0, 3)));
observed.push(String(instance.and32(0, 6)));
observed.push(String(instance.or32(0, 8)));
observed.push(String(instance.xor32(0, 3)));
observed.push(String(instance.exchange32(0, 12)));
observed.push(String(instance.compare32(0, 12, 21)));
observed.push(String(instance.compare32(0, 12, 99)));
observed.push(String(instance.load32(0)));
instance.store8(8, -1);
instance.store16(10, -1);
observed.push(String(instance.load8(8)));
observed.push(String(instance.load16(10)));
instance.store64(16, 9223372036854775807n);
observed.push(String(instance.add64(16, 1n)));
observed.push(String(instance.load64(16)));
instance.store64_32(24, -1n);
observed.push(String(instance.load64_32(24)));
observed.push(String(instance.compare64_8(24, 255n, 7n)));
observed.push(String(instance.compare64_8(24, 255n, 9n)));
console.log(JSON.stringify(observed));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the nonblocking atomic family module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"["15","20","17","0","8","11","12","21","21","255","65535","9223372036854775807","-9223372036854775808","4294967295","255","7"]"#
    );
}

#[test]
fn typescript_memory64_factory_preserves_atomic_trap_precedence() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory i64 1 1 shared)
          (func (export "load") (param i64) (result i32) local.get 0 i32.atomic.load)
          (func (export "misaligned") (result i32) i64.const -1 i32.atomic.load offset=2 align=4)
          (func (export "large_offset") (result i32) i64.const 0 i32.atomic.load offset=9007199254740992 align=4)
          (func (export "overflow") (result i32) i64.const 1 i32.atomic.load offset=18446744073709551615 align=4))"#,
    )
    .expect("assemble memory64 trap module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift memory64 trap module")
        .source;
    if let Some(path) = std::env::var_os("DISROBE_TYPESCRIPT_DUMP") {
        std::fs::write(path, &source).expect("write generated memory64 TypeScript module");
    }
    let execution: String = format!(
        "{source}\n{}",
        r#"
const instance: LiftedInstance = instantiate();
const observed: string[] = [String(instance.load(0n))];
for (const invoke of [instance.misaligned, instance.large_offset, instance.overflow]) {
  try {
    invoke();
    observed.push("accepted");
  } catch (error: unknown) {
    observed.push(error instanceof RangeError ? error.message : "wrong-error");
  }
}
console.log(JSON.stringify(observed));
"#
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the memory64 module: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        r#"["0","wasm atomic trap","wasm atomic trap","wasm atomic trap"]"#
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr)
            .lines()
            .collect::<Vec<&str>>(),
        [
            "DR-WASMDEOB-TRAP/1:atomic-unaligned",
            "DR-WASMDEOB-TRAP/1:atomic-oob",
            "DR-WASMDEOB-TRAP/1:atomic-oob",
        ]
    );
}

#[test]
fn typescript_module_refuses_function_rosters_above_the_publication_limit() {
    let mut wat_source: String = String::from("(module (memory 1 1 shared)");
    for _ in 0..4097 {
        wat_source.push_str(" (func)");
    }
    wat_source.push(')');
    let bytes: Vec<u8> = wat::parse_str(&wat_source).expect("assemble oversized function roster");
    let error: Error = try_lift_typescript_module(&bytes)
        .expect_err("TypeScript module publication must cap the function roster");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::FunctionCount {
            actual: 4097,
            limit: 4096
        })
    ));
}

#[test]
fn typescript_module_refuses_multi_result_signatures_before_publication() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "pair") (result i32 i64)
            i32.const 1
            i64.const 2))"#,
    )
    .expect("assemble multi-result module");
    let error: Error = try_lift_typescript_module(&bytes)
        .expect_err("TypeScript module publication must refuse multi-result signatures");
    assert!(matches!(
        error,
        Error::AtomicMemoryModel(AtomicMemoryRefusal::ResultCount {
            function_index: 0,
            actual: 2,
            limit: 1
        })
    ));
}

#[test]
fn typescript_atomic_runtime_uses_shared_storage_and_atomic_primitives() {
    let prelude: &str = typescript_runtime_prelude();
    assert!(prelude.contains("new SharedArrayBuffer(64 * 1024)"));
    for primitive in [
        "Atomics.load(",
        "Atomics.store(",
        "Atomics.add(",
        "Atomics.sub(",
        "Atomics.and(",
        "Atomics.or(",
        "Atomics.xor(",
        "Atomics.exchange(",
        "Atomics.compareExchange(",
    ] {
        assert!(
            prelude.contains(primitive),
            "TypeScript atomic runtime is missing `{primitive}`"
        );
    }
    assert!(!prelude.contains(
        "const wasmI32AtomicRmwAdd = (addr: number, offset: number, val: number): number => { const cur = wasmLoadI32"
    ));
}

#[test]
fn typescript_plain_and_atomic_memory_operations_alias() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "store_plain") (param i32)
            i32.const 0
            local.get 0
            i32.store)
          (func (export "load_plain") (result i32)
            i32.const 0
            i32.load)
          (func (export "increment") (result i32)
            i32.const 0
            i32.const 1
            i32.atomic.rmw.add))"#,
    )
    .expect("assemble plain and atomic alias module");
    let source: String = try_lift_typescript_module(&bytes)
        .expect("lift plain and atomic alias module")
        .source;
    let execution: String = format!(
        "{source}\n{}",
        r"
const instance: LiftedInstance = instantiate();
instance.store_plain(41);
const old: number = instance.increment();
const current: number = instance.load_plain();
console.log(JSON.stringify([old, current]));
"
    );
    let output: CapturedOutput = run_typescript(&execution);
    assert_eq!(
        output.exit_code,
        Some(0),
        "Node rejected plain and atomic aliasing: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[41,42]");
}

#[test]
fn typescript_atomic_add_is_indivisible_across_workers() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "increment") (param i32) (result i32)
            local.get 0
            i32.const 1
            i32.atomic.rmw.add))"#,
    )
    .expect("assemble the worker-shared module");
    let module_source: String = try_lift_typescript_module(&bytes)
        .expect("lift the worker-shared TypeScript module")
        .source;
    let source: String = format!(
        "{module_source}\n{}",
        r#"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const WORKER_COUNT: number = 4;
const INCREMENTS: number = 25000;

if (isMainThread) {
  const instance: LiftedInstance = instantiate();
  const completions: Promise<void>[] = Array.from({ length: WORKER_COUNT }, (): Promise<void> => {
    const worker: Worker = new Worker(import.meta.filename, {
      execArgv: ["--experimental-strip-types", "--no-warnings"],
      workerData: { wasmMemory: instance.memory },
    });
    return new Promise<void>((resolve: () => void, reject: (reason: unknown) => void): void => {
      worker.once("message", (): void => resolve());
      worker.once("error", (error: Error): void => reject(error));
    });
  });
  await Promise.all(completions);
  console.log(String(new Int32Array(instance.memory.buffer)[0]));
} else {
  const instance: LiftedInstance = instantiate({ memories: [workerData.wasmMemory] });
  for (let index: number = 0; index < INCREMENTS; index += 1) {
    instance.increment(0);
  }
  parentPort?.postMessage("done");
}
"#
    );
    let output: CapturedOutput = run_typescript(&source);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the TypeScript atomic runtime: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "100000");
}

#[test]
fn typescript_atomic_compare_exchange_is_indivisible_across_workers() {
    let bytes: Vec<u8> = wat::parse_str(
        r#"(module
          (memory 1 1 shared)
          (func (export "compare") (param i32 i32 i32) (result i32)
            local.get 0
            local.get 1
            local.get 2
            i32.atomic.rmw.cmpxchg))"#,
    )
    .expect("assemble the worker-shared compare-exchange module");
    let module_source: String = try_lift_typescript_module(&bytes)
        .expect("lift the worker-shared compare-exchange module")
        .source;
    let source: String = format!(
        "{module_source}\n{}",
        r#"
import { Worker, isMainThread, parentPort, workerData } from "node:worker_threads";

const WORKER_COUNT: number = 4;
const INCREMENTS: number = 25000;

if (isMainThread) {
  const instance: LiftedInstance = instantiate();
  const completions: Promise<void>[] = Array.from({ length: WORKER_COUNT }, (): Promise<void> => {
    const worker: Worker = new Worker(import.meta.filename, {
      execArgv: ["--experimental-strip-types", "--no-warnings"],
      workerData: { wasmMemory: instance.memory },
    });
    return new Promise<void>((resolve: () => void, reject: (reason: unknown) => void): void => {
      worker.once("message", (): void => resolve());
      worker.once("error", (error: Error): void => reject(error));
    });
  });
  await Promise.all(completions);
  console.log(String(new Int32Array(instance.memory.buffer)[0]));
} else {
  const instance: LiftedInstance = instantiate({ memories: [workerData.wasmMemory] });
  const view: Int32Array = new Int32Array(instance.memory.buffer);
  for (let index: number = 0; index < INCREMENTS; index += 1) {
    while (true) {
      const current: number = Atomics.load(view, 0);
      if (instance.compare(0, current, current + 1) === current) break;
    }
  }
  parentPort?.postMessage("done");
}
"#
    );
    let output: CapturedOutput = run_typescript(&source);
    assert!(
        output.exit_code == Some(0),
        "Node rejected the TypeScript compare-exchange runtime: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "100000");
}
