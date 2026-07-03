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
const MAX_FUEL_BUDGET: u64 = 1_000_000_000;
const MAX_WALL_DEADLINE: Duration = Duration::from_secs(30);
const MAX_MEMORY_CAP_BYTES: usize = 256 * 1024 * 1024;
const MAX_WASM_MODULE_BYTES: usize = DEFAULT_MEMORY_CAP_BYTES;
const EPOCH_DEADLINE_TICKS: u64 = 1;
const WATCHDOG_TICK_MS: u64 = 10;
const GUEST_IO_BASE: usize = 0;
const GUEST_ENTRY: &str = "run";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub fuel_budget: u64,

    pub wall_deadline: Duration,

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

impl Limits {
    #[must_use]
    fn effective(self) -> Self {
        Self {
            fuel_budget: self.fuel_budget.min(MAX_FUEL_BUDGET),
            wall_deadline: self.wall_deadline.min(MAX_WALL_DEADLINE),
            memory_cap_bytes: self.memory_cap_bytes.min(MAX_MEMORY_CAP_BYTES),
        }
    }
}

#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("plugin exhausted its fuel budget")]
    Fuel,

    #[error("plugin exceeded its wall-clock deadline")]
    Timeout,

    #[error("plugin exceeded its memory cap")]
    Memory,

    #[error("plugin module too large: {actual} bytes exceeds {max} bytes")]
    ModuleTooLarge { actual: usize, max: usize },

    #[error("plugin requested a denied host import: {0}")]
    DeniedImport(String),

    #[error("plugin trapped: {0}")]
    Trap(String),
}

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
        let Some(desired_bytes): Option<usize> = desired.checked_mul(std::mem::size_of::<usize>())
        else {
            self.denied = true;
            return Ok(false);
        };
        if desired_bytes > self.cap_bytes {
            self.denied = true;
            return Ok(false);
        }
        Ok(true)
    }
}

#[derive(Debug, Default)]
pub struct PluginHost;

impl PluginHost {
    pub fn run(wasm: &[u8], input: &[u8], limits: Limits) -> Result<Vec<u8>, SandboxError> {
        let limits: Limits = limits.effective();
        if wasm.len() > MAX_WASM_MODULE_BYTES {
            return Err(SandboxError::ModuleTooLarge {
                actual: wasm.len(),
                max: MAX_WASM_MODULE_BYTES,
            });
        }
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

        let instance: Instance = match linker.instantiate(&mut store, &module) {
            Ok(instance) => instance,
            Err(_) if store.data().denied => return Err(SandboxError::Memory),
            Err(err) => return Err(SandboxError::Trap(format!("instantiate: {err}"))),
        };

        let memory: Option<Memory> = instance.get_memory(&mut store, "memory");
        if memory.is_none() && !input.is_empty() {
            return Err(SandboxError::Trap(
                "guest received input but exports no memory".to_owned(),
            ));
        }
        if let Some(mem) = memory
            && mem.data_size(&store) > limits.memory_cap_bytes
        {
            return Err(SandboxError::Memory);
        }
        let input_len: i32 = i32::try_from(input.len())
            .map_err(|_| SandboxError::Trap("input too large for i32 length".to_owned()))?;
        if input.len() > limits.memory_cap_bytes {
            return Err(SandboxError::Memory);
        }
        if let Some(mem) = memory
            && !input.is_empty()
        {
            let writable_bytes: usize = guest_io_capacity(&mem, &store, limits.memory_cap_bytes)?;
            if input.len() > writable_bytes {
                return Err(SandboxError::Memory);
            }
            mem.write(&mut store, GUEST_IO_BASE, input)
                .map_err(|e| SandboxError::Trap(format!("input write: {e}")))?;
        }

        let entry: TypedFunc<i32, i32> = instance
            .get_typed_func::<i32, i32>(&mut store, GUEST_ENTRY)
            .map_err(|e| SandboxError::Trap(format!("entry lookup: {e}")))?;

        let started: Instant = Instant::now();
        let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let watchdog: JoinHandle<()> =
            spawn_epoch_watchdog(engine, Arc::clone(&stopper), limits.wall_deadline, started)
                .map_err(|e| SandboxError::Trap(format!("watchdog spawn: {e}")))?;

        let call_result: wasmtime::Result<i32> = entry.call(&mut store, input_len);

        stopper.store(true, Ordering::Relaxed);
        watchdog
            .join()
            .map_err(|_| SandboxError::Trap("watchdog thread panicked".to_owned()))?;
        if started.elapsed() >= limits.wall_deadline && call_result.is_ok() {
            return Err(SandboxError::Timeout);
        }

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
        let max_output_bytes: usize = guest_io_capacity(&mem, &store, limits.memory_cap_bytes)?;
        if out_len > max_output_bytes {
            return Err(SandboxError::Memory);
        }
        let mut buffer: Vec<u8> = vec![0u8; out_len];
        mem.read(&store, GUEST_IO_BASE, &mut buffer)
            .map_err(|e| SandboxError::Trap(format!("output read: {e}")))?;
        Ok(buffer)
    }
}

fn guest_io_capacity(
    mem: &Memory,
    store: &Store<MemoryGate>,
    memory_cap_bytes: usize,
) -> Result<usize, SandboxError> {
    let guest_bytes: usize = mem
        .data_size(store)
        .checked_sub(GUEST_IO_BASE)
        .ok_or(SandboxError::Memory)?;
    Ok(memory_cap_bytes.min(guest_bytes))
}

fn first_import(module: &Module) -> Option<String> {
    module
        .imports()
        .next()
        .map(|imp| format!("{}::{}", imp.module(), imp.name()))
}

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

fn spawn_epoch_watchdog(
    engine: Engine,
    stopper: Arc<AtomicBool>,
    wall_deadline: Duration,
    started: Instant,
) -> std::io::Result<JoinHandle<()>> {
    Builder::new()
        .name("disrobe-plugin-host-watchdog".to_owned())
        .spawn(move || {
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

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{
        Limits, MAX_FUEL_BUDGET, MAX_MEMORY_CAP_BYTES, MAX_WALL_DEADLINE, MAX_WASM_MODULE_BYTES,
        MemoryGate, PluginHost, SandboxError,
    };
    use std::time::Duration;
    use wasmtime::ResourceLimiter;

    #[test]
    fn caller_limits_are_capped() {
        let limits: Limits = Limits {
            fuel_budget: u64::MAX,
            wall_deadline: Duration::from_mins(10),
            memory_cap_bytes: usize::MAX,
        }
        .effective();
        assert_eq!(limits.fuel_budget, MAX_FUEL_BUDGET);
        assert_eq!(limits.wall_deadline, MAX_WALL_DEADLINE);
        assert_eq!(limits.memory_cap_bytes, MAX_MEMORY_CAP_BYTES);
    }

    #[test]
    fn table_growth_overflow_is_denied() {
        let mut gate: MemoryGate = MemoryGate {
            cap_bytes: usize::MAX,
            denied: false,
        };
        let result: wasmtime::Result<bool> = gate.table_growing(0, usize::MAX, None);
        assert!(matches!(result, Ok(false)));
        assert!(gate.denied);
    }

    #[test]
    fn oversized_wasm_is_rejected_by_size_before_compilation() {
        let wasm: Vec<u8> = vec![0u8; MAX_WASM_MODULE_BYTES + 1];
        let result: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], Limits::default());
        assert!(matches!(
            result,
            Err(SandboxError::ModuleTooLarge {
                actual,
                max: MAX_WASM_MODULE_BYTES
            }) if actual == MAX_WASM_MODULE_BYTES + 1
        ));
    }

    #[test]
    fn expired_wall_deadline_rejects_successful_guest_return() {
        let wasm: Vec<u8> = wat::parse_str(
            r#"
            (module
              (func (export "run") (param i32) (result i32)
                i32.const 0))
            "#,
        )
        .expect("deadline test module must assemble");
        let limits: Limits = Limits {
            fuel_budget: 50_000,
            wall_deadline: Duration::ZERO,
            memory_cap_bytes: 1024 * 1024,
        };
        let result: Result<Vec<u8>, SandboxError> = PluginHost::run(&wasm, &[], limits);
        assert!(matches!(result, Err(SandboxError::Timeout)));
    }
}
