use crate::error::Result;

use super::stub_detect::StubInfo;

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 100_000_000;

#[cfg(feature = "sandbox")]
const EPOCH_DEADLINE_TICKS: u64 = 1;

#[cfg(feature = "sandbox")]
const WALL_DEADLINE_MS: u64 = 2_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnwrappedSegment {
    pub call_site_offset: usize,
    pub decrypted: Vec<u8>,
}

#[cfg(feature = "sandbox")]
pub fn unwrap_decryption(bytes: &[u8], stubs: &[StubInfo]) -> Result<Vec<UnwrappedSegment>> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use wasmtime::{Config, Engine, Linker, Module, Store};

    use crate::error::Error;

    if stubs.is_empty() {
        return Ok(Vec::new());
    }

    let mut config: Config = Config::new();
    config.consume_fuel(true).epoch_interruption(true);
    let engine: Engine =
        Engine::new(&config).map_err(|e| Error::Parse(format!("wasmtime engine: {e}")))?;
    let module: Module =
        Module::new(&engine, bytes).map_err(|e| Error::Parse(format!("wasmtime module: {e}")))?;
    let mut store: Store<()> = Store::new(&engine, ());
    store
        .set_fuel(FUEL_BUDGET)
        .map_err(|e| Error::Parse(format!("set_fuel: {e}")))?;
    store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
    let mut linker: Linker<()> = Linker::new(&engine);
    linker
        .define_unknown_imports_as_traps(&module)
        .map_err(|e| Error::Parse(format!("define_unknown_imports_as_traps: {e}")))?;
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .map_err(|e| Error::Parse(format!("instantiate: {e}")))?;

    let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let watchdog: std::io::Result<std::thread::JoinHandle<()>> = spawn_epoch_watchdog(
        engine,
        Arc::clone(&stopper),
        Duration::from_millis(WALL_DEADLINE_MS),
    );

    let probes: Vec<DecryptProbe> = collect_decrypt_probes(stubs);
    let mut out: Vec<UnwrappedSegment> = Vec::with_capacity(probes.len());
    for probe in &probes {
        let Some(typed): Option<wasmtime::TypedFunc<(i32, i32), i32>> =
            lookup_typed_decrypt(&instance, &mut store, probe.fn_index)
        else {
            continue;
        };
        let scratch_off: i32 = match typed.call(&mut store, (probe.off, probe.len)) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let Some(decrypted): Option<Vec<u8>> =
            read_instance_memory(&instance, &mut store, scratch_off, probe.len)
        else {
            continue;
        };
        out.push(UnwrappedSegment {
            call_site_offset: probe.call_site_offset,
            decrypted,
        });
    }

    stopper.store(true, Ordering::Relaxed);
    if let Ok(handle) = watchdog {
        let _ = handle.join();
    }

    Ok(out)
}

#[cfg(feature = "sandbox")]
fn spawn_epoch_watchdog(
    engine: wasmtime::Engine,
    stopper: std::sync::Arc<std::sync::atomic::AtomicBool>,
    wall_deadline: std::time::Duration,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    use std::sync::atomic::Ordering;
    use std::thread;
    use std::time::{Duration, Instant};

    thread::Builder::new()
        .name("disrobe-wasmtime-watchdog".to_owned())
        .spawn(move || {
            let started: Instant = Instant::now();
            let tick: Duration = Duration::from_millis(50);
            while !stopper.load(Ordering::Relaxed) {
                thread::sleep(tick);
                if started.elapsed() >= wall_deadline {
                    engine.increment_epoch();
                    break;
                }
            }
        })
}

#[cfg(feature = "sandbox")]
#[derive(Debug, Clone, Copy)]
struct DecryptProbe {
    fn_index: u32,
    off: i32,
    len: i32,
    call_site_offset: usize,
}

#[cfg(feature = "sandbox")]
fn collect_decrypt_probes(stubs: &[StubInfo]) -> Vec<DecryptProbe> {
    stubs
        .iter()
        .map(|s| DecryptProbe {
            fn_index: s.fn_index,
            off: 0,
            len: 0,
            call_site_offset: 0,
        })
        .collect()
}

#[cfg(feature = "sandbox")]
fn lookup_typed_decrypt(
    instance: &wasmtime::Instance,
    store: &mut wasmtime::Store<()>,
    fn_index: u32,
) -> Option<wasmtime::TypedFunc<(i32, i32), i32>> {
    let name: String = format!("__disrobe_decrypt_{fn_index}");
    if let Some(func) = instance.get_func(&mut *store, &name)
        && let Ok(typed) = func.typed::<(i32, i32), i32>(&*store)
    {
        return Some(typed);
    }
    let candidate_funcs: Vec<wasmtime::Func> = instance
        .exports(&mut *store)
        .filter_map(wasmtime::Export::into_func)
        .collect();
    for func in candidate_funcs {
        if let Ok(typed) = func.typed::<(i32, i32), i32>(&*store) {
            return Some(typed);
        }
    }
    None
}

#[cfg(feature = "sandbox")]
fn read_instance_memory(
    instance: &wasmtime::Instance,
    store: &mut wasmtime::Store<()>,
    offset: i32,
    len: i32,
) -> Option<Vec<u8>> {
    if len <= 0 {
        return Some(Vec::new());
    }
    let memory: wasmtime::Memory = instance.get_memory(&mut *store, "memory")?;
    let data: &[u8] = memory.data(&*store);
    let start: usize = usize::try_from(offset).ok()?;
    let end: usize = start.checked_add(usize::try_from(len).ok()?)?;
    if end > data.len() {
        return None;
    }
    Some(data[start..end].to_vec())
}

#[cfg(not(feature = "sandbox"))]
pub fn unwrap_decryption(_bytes: &[u8], _stubs: &[StubInfo]) -> Result<Vec<UnwrappedSegment>> {
    Err(crate::error::Error::Parse(
        "wasmtime sandbox feature disabled".to_owned(),
    ))
}

#[cfg(all(test, not(feature = "sandbox")))]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod feature_off_tests {
    use super::*;

    #[test]
    fn returns_parse_error_when_feature_disabled() {
        let result: Result<Vec<UnwrappedSegment>> = unwrap_decryption(&[], &[]);
        assert!(matches!(result, Err(crate::error::Error::Parse(_))));
    }
}

#[cfg(all(test, feature = "sandbox"))]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod sandbox_tests {
    use std::collections::BTreeMap;
    use std::time::{Duration, Instant};

    use super::*;

    const fn stub(fn_index: u32) -> StubInfo {
        StubInfo {
            fn_index,
            key: None,
            op_histogram: BTreeMap::new(),
            confidence: 1.0,
        }
    }

    fn assemble(wat_text: &str) -> Option<Vec<u8>> {
        wat::parse_str(wat_text).ok()
    }

    #[test]
    fn empty_stubs_short_circuit() {
        let out: Vec<UnwrappedSegment> =
            unwrap_decryption(&[], &[]).expect("empty stub list is a clean no-op");
        assert!(out.is_empty());
    }

    #[test]
    fn rejects_infinite_loop_in_stub_within_deadline() {
        let wat_text: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "__disrobe_decrypt_0") (param i32 i32) (result i32)
                (loop $spin
                  br $spin)
                i32.const 0))
        "#;
        let Some(bytes): Option<Vec<u8>> = assemble(wat_text) else {
            panic!("test fixture wat must assemble");
        };
        let stubs: [StubInfo; 1] = [stub(0)];
        let started: Instant = Instant::now();
        let outcome: Result<Vec<UnwrappedSegment>> = unwrap_decryption(&bytes, &stubs);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "infinite wasm loop must be trapped within 3s, took {elapsed:?}",
        );
        if let Ok(segments) = outcome {
            assert!(
                segments.is_empty(),
                "trapping stub must not yield decrypted segments, got {segments:?}",
            );
        }
    }
}
