//! Capability-gated WebAssembly plugin sandbox.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use thiserror::Error;
use wasmtime::{
    Config, Engine, Instance, Linker, Memory, Module, ResourceLimiter, Store, Trap, TypedFunc,
};

const DEFAULT_FUEL_BUDGET: u64 = 50_000_000;
const DEFAULT_WALL_DEADLINE_MS: u64 = 1_000;
const DEFAULT_MEMORY_CAP_BYTES: usize = 16 * 1024 * 1024;
const EPOCH_DEADLINE_TICKS: u64 = 1;
const WATCHDOG_TICK_MS: u64 = 10;
const GUEST_IO_BASE: usize = 0;
const GUEST_ENTRY: &str = "run";

/// Per-run containment budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum number of wasm instructions the guest may execute.
    pub fuel_budget: u64,
    /// Real-time deadline; the epoch watchdog interrupts the guest after this.
    pub wall_deadline: Duration,
    /// Hard ceiling, in bytes, on guest linear-memory and table growth.
    pub memory_cap_bytes: usize,
}

impl Default for Limits {
    #[inline]
    fn default() -> Self {
        Self {
            fuel_budget: DEFAULT_FUEL_BUDGET,
            wall_deadline: Duration::from_millis(DEFAULT_WALL_DEADLINE_MS),
            memory_cap_bytes: DEFAULT_MEMORY_CAP_BYTES,
        }
    }
}

/// Reason a sandboxed run was refused or aborted.
#[derive(Debug, Error)]
pub enum SandboxError {
    /// The guest exhausted its instruction fuel budget.
    #[error("plugin exhausted its fuel budget")]
    Fuel,
    /// The wall-clock watchdog interrupted the guest past its deadline.
    #[error("plugin exceeded its wall-clock deadline")]
    Timeout,
    /// The guest tried to grow memory or a table past the configured byte cap.
    #[error("plugin exceeded its memory cap")]
    Memory,
    /// The module requested a host import; ambient authority is denied.
    #[error("plugin requested a denied host import: {0}")]
    DeniedImport(String),
    /// The guest trapped for any other reason, or the host ABI was violated.
    #[error("plugin trapped: {0}")]
    Trap(String),
}

/// Tracks whether the guest hit the memory cap to classify a denied-growth trap.
#[derive(Debug)]
struct MemoryGate {
    cap_bytes: usize,
    denied: bool,
}

impl ResourceLimiter for MemoryGate {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired > self.cap_bytes {
            self.denied = true;
            return Ok(false);
        }
        Ok(true)
    }

    fn table_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if desired.saturating_mul(std::mem::size_of::<usize>()) > self.cap_bytes {
            self.denied = true;
            return Ok(false);
        }
        Ok(true)
    }
}

/// The sandbox entry point.
#[derive(Debug, Default)]
pub struct PluginHost;

impl PluginHost {
    /// Run `wasm` against `input` under `limits`, returning the guest's output bytes.
    pub fn run(wasm: &[u8], input: &[u8], limits: Limits) -> Result<Vec<u8>, SandboxError> {
        let mut config: Config = Config::new();
        config
            .consume_fuel(true)
            .epoch_interruption(true)
            .wasm_backtrace(false);
        let engine: Engine =
            Engine::new(&config).map_err(|e| SandboxError::Trap(format!("engine: {e}")))?;
        let module: Module =
            Module::new(&engine, wasm).map_err(|e| SandboxError::Trap(format!("module: {e}")))?;

        if let Some(denied) = first_import(&module) {
            return Err(SandboxError::DeniedImport(denied));
        }

        let gate: MemoryGate = MemoryGate {
            cap_bytes: limits.memory_cap_bytes,
            denied: false,
        };
        let mut store: Store<MemoryGate> = Store::new(&engine, gate);
        store.limiter(|state: &mut MemoryGate| state as &mut dyn ResourceLimiter);
        store
            .set_fuel(limits.fuel_budget)
            .map_err(|e| SandboxError::Trap(format!("set_fuel: {e}")))?;
        store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);

        let mut linker: Linker<MemoryGate> = Linker::new(&engine);
        linker
            .define_unknown_imports_as_traps(&module)
            .map_err(|e| SandboxError::Trap(format!("trap-imports: {e}")))?;

        let instance: Instance = linker
            .instantiate(&mut store, &module)
            .map_err(|e| SandboxError::Trap(format!("instantiate: {e}")))?;

        let memory: Option<Memory> = instance.get_memory(&mut store, "memory");
        if let Some(mem) = memory
            && !input.is_empty()
        {
            mem.write(&mut store, GUEST_IO_BASE, input)
                .map_err(|e| SandboxError::Trap(format!("input write: {e}")))?;
        }

        let entry: TypedFunc<i32, i32> = instance
            .get_typed_func::<i32, i32>(&mut store, GUEST_ENTRY)
            .map_err(|e| SandboxError::Trap(format!("entry lookup: {e}")))?;

        let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let watchdog: JoinHandle<()> =
            spawn_epoch_watchdog(engine, Arc::clone(&stopper), limits.wall_deadline)
                .map_err(|e| SandboxError::Trap(format!("watchdog spawn: {e}")))?;

        let input_len: i32 = i32::try_from(input.len())
            .map_err(|_| SandboxError::Trap("input too large for i32 length".to_owned()))?;
        let call_result: wasmtime::Result<i32> = entry.call(&mut store, input_len);

        stopper.store(true, Ordering::Relaxed);
        let _ = watchdog.join();

        let out_len: i32 = match call_result {
            Ok(v) => v,
            Err(err) => return Err(classify(&store, err)),
        };

        if store.data().denied {
            return Err(SandboxError::Memory);
        }

        let out_len: usize = usize::try_from(out_len)
            .map_err(|_| SandboxError::Trap("guest returned a negative length".to_owned()))?;
        if out_len == 0 {
            return Ok(Vec::new());
        }
        let Some(mem): Option<Memory> = memory else {
            return Err(SandboxError::Trap(
                "guest returned output but exports no memory".to_owned(),
            ));
        };
        let mut buffer: Vec<u8> = vec![0u8; out_len];
        mem.read(&store, GUEST_IO_BASE, &mut buffer)
            .map_err(|e| SandboxError::Trap(format!("output read: {e}")))?;
        Ok(buffer)
    }
}

/// Returns the first import in `module` as `"module::name"`, or `None` if self-contained.
fn first_import(module: &Module) -> Option<String> {
    module
        .imports()
        .next()
        .map(|imp| format!("{}::{}", imp.module(), imp.name()))
}

/// Maps a wasmtime call error onto the sandbox taxonomy.
fn classify(store: &Store<MemoryGate>, err: wasmtime::Error) -> SandboxError {
    if store.data().denied {
        return SandboxError::Memory;
    }
    match err.downcast_ref::<Trap>() {
        Some(Trap::OutOfFuel) => SandboxError::Fuel,
        Some(Trap::Interrupt) => SandboxError::Timeout,
        Some(other) => SandboxError::Trap(other.to_string()),
        None => SandboxError::Trap(err.to_string()),
    }
}

/// Spawns a thread that bumps the engine epoch once `wall_deadline` elapses.
fn spawn_epoch_watchdog(
    engine: Engine,
    stopper: Arc<AtomicBool>,
    wall_deadline: Duration,
) -> std::io::Result<JoinHandle<()>> {
    Builder::new()
        .name("disrobe-plugin-host-watchdog".to_owned())
        .spawn(move || {
            let started: Instant = Instant::now();
            let tick: Duration = Duration::from_millis(WATCHDOG_TICK_MS);
            while !stopper.load(Ordering::Relaxed) {
                if started.elapsed() >= wall_deadline {
                    engine.increment_epoch();
                    break;
                }
                std::thread::sleep(tick);
            }
        })
}
