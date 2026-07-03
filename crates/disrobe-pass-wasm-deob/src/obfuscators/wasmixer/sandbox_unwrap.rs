use wasmparser::{ConstExpr, DataKind, Operator, Parser, Payload};

use crate::error::{Error, Result};

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
    pub off: i32,
    pub len: i32,
    pub source: ProbeSource,
    pub decrypted: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeSource {
    CallSiteConstants,
    ActiveDataSegment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnresolvedReason {
    NoStaticSpan,
    SandboxDeclined,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnresolvedStub {
    pub fn_index: u32,
    pub reason: UnresolvedReason,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UnwrapReport {
    pub segments: Vec<UnwrappedSegment>,
    pub unresolved: Vec<UnresolvedStub>,
}

impl UnwrapReport {
    #[must_use]
    pub const fn recovered(&self) -> usize {
        self.segments.len()
    }

    #[must_use]
    pub const fn failed(&self) -> usize {
        self.unresolved.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DataSpan {
    base: i32,
    len: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecryptProbe {
    fn_index: u32,
    off: i32,
    len: i32,
    absolute_base: i32,
    call_site_offset: usize,
    source: ProbeSource,
}

fn read_const_i32(expr: &ConstExpr<'_>) -> Option<i32> {
    let mut reader: wasmparser::OperatorsReader<'_> = expr.get_operators_reader();
    let op: Operator<'_> = reader.read().ok()?;
    match op {
        Operator::I32Const { value } => Some(value),
        _ => None,
    }
}

fn scan_active_data_spans(bytes: &[u8]) -> Result<Vec<DataSpan>> {
    let mut spans: Vec<DataSpan> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        if let Payload::DataSection(reader) = payload {
            for entry in reader {
                let segment: wasmparser::Data<'_> =
                    entry.map_err(|e| Error::Parse(e.to_string()))?;
                let DataKind::Active { offset_expr, .. } = segment.kind else {
                    continue;
                };
                let Some(base): Option<i32> = read_const_i32(&offset_expr) else {
                    continue;
                };
                let Ok(len): std::result::Result<i32, _> = i32::try_from(segment.data.len()) else {
                    continue;
                };
                if len > 0 {
                    spans.push(DataSpan { base, len });
                }
            }
        }
    }
    Ok(spans)
}

fn body_references_const(body: &wasmparser::FunctionBody<'_>, needle: i32) -> bool {
    let Ok(reader): std::result::Result<wasmparser::OperatorsReader<'_>, _> =
        body.get_operators_reader()
    else {
        return false;
    };
    for op in reader {
        if let Ok(Operator::I32Const { value }) = op
            && value == needle
        {
            return true;
        }
    }
    false
}

fn function_body_embeds_any_base(bytes: &[u8], fn_index: u32, spans: &[DataSpan]) -> bool {
    let mut imported_funcs: u32 = 0;
    let mut local_idx: u32 = 0;
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(payload): std::result::Result<Payload<'_>, _> = payload else {
            return false;
        };
        match payload {
            Payload::ImportSection(reader) => {
                for group in reader.into_iter().flatten() {
                    if let wasmparser::Imports::Single(_, imp) = group
                        && matches!(imp.ty, wasmparser::TypeRef::Func(_))
                    {
                        imported_funcs = imported_funcs.saturating_add(1);
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let current: u32 = imported_funcs.saturating_add(local_idx);
                local_idx = local_idx.saturating_add(1);
                if current == fn_index {
                    return spans.iter().any(|s| body_references_const(&body, s.base));
                }
            }
            _ => {}
        }
    }
    false
}

fn collect_call_site_args(bytes: &[u8], fn_index: u32) -> Result<Vec<(usize, i32, i32)>> {
    let mut sites: Vec<(usize, i32, i32)> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.map_err(|e| Error::Parse(e.to_string()))?;
        if let Payload::CodeSectionEntry(body) = payload {
            let reader: wasmparser::OperatorsReader<'_> = body
                .get_operators_reader()
                .map_err(|e| Error::Parse(e.to_string()))?;
            let mut prev_const: Option<i32> = None;
            let mut last_const: Option<i32> = None;
            for item in reader.into_iter_with_offsets() {
                let (op, offset): (Operator<'_>, usize) =
                    item.map_err(|e| Error::Parse(e.to_string()))?;
                match op {
                    Operator::I32Const { value } => {
                        prev_const = last_const;
                        last_const = Some(value);
                        continue;
                    }
                    Operator::Call { function_index } if function_index == fn_index => {
                        if let Some(off) = prev_const
                            && let Some(len) = last_const
                            && len > 0
                        {
                            sites.push((offset, off, len));
                        }
                    }
                    _ => {}
                }
                prev_const = None;
                last_const = None;
            }
        }
    }
    Ok(sites)
}

fn recover_probe(
    bytes: &[u8],
    stub: &StubInfo,
    spans: &[DataSpan],
) -> Result<Option<DecryptProbe>> {
    let call_sites: Vec<(usize, i32, i32)> = collect_call_site_args(bytes, stub.fn_index)?;
    if let Some((call_site_offset, off, len)) = call_sites.first().copied() {
        let absolute_base: i32 = spans.iter().find(|s| s.base == off).map_or(off, |s| s.base);
        return Ok(Some(DecryptProbe {
            fn_index: stub.fn_index,
            off,
            len,
            absolute_base,
            call_site_offset,
            source: ProbeSource::CallSiteConstants,
        }));
    }

    let embeds_base: bool = function_body_embeds_any_base(bytes, stub.fn_index, spans);
    let Some(span): Option<&DataSpan> = spans.first() else {
        return Ok(None);
    };
    let off: i32 = if embeds_base { 0 } else { span.base };
    Ok(Some(DecryptProbe {
        fn_index: stub.fn_index,
        off,
        len: span.len,
        absolute_base: span.base,
        call_site_offset: 0,
        source: ProbeSource::ActiveDataSegment,
    }))
}

fn collect_decrypt_probes(
    bytes: &[u8],
    stubs: &[StubInfo],
) -> Result<(Vec<DecryptProbe>, Vec<u32>)> {
    let spans: Vec<DataSpan> = scan_active_data_spans(bytes)?;
    let mut probes: Vec<DecryptProbe> = Vec::with_capacity(stubs.len());
    let mut unresolved: Vec<u32> = Vec::new();
    for stub in stubs {
        match recover_probe(bytes, stub, &spans)? {
            Some(probe) => probes.push(probe),
            None => unresolved.push(stub.fn_index),
        }
    }
    Ok((probes, unresolved))
}

#[cfg(feature = "sandbox")]
pub fn unwrap_decryption(bytes: &[u8], stubs: &[StubInfo]) -> Result<UnwrapReport> {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use wasmtime::{Config, Engine, Module};

    if stubs.is_empty() {
        return Ok(UnwrapReport::default());
    }

    crate::debug::dbg_section("wasmtime-unwrap");
    let (probes, unresolved_spans): (Vec<DecryptProbe>, Vec<u32>) =
        collect_decrypt_probes(bytes, stubs)?;
    crate::debug::dbg_kv("decrypt-probes", || {
        format!(
            "stubs={} static_probes={} no_static_span={}",
            stubs.len(),
            probes.len(),
            unresolved_spans.len()
        )
    });
    let mut report: UnwrapReport = UnwrapReport {
        segments: Vec::with_capacity(probes.len()),
        unresolved: unresolved_spans
            .into_iter()
            .map(|fn_index| UnresolvedStub {
                fn_index,
                reason: UnresolvedReason::NoStaticSpan,
            })
            .collect(),
    };

    if probes.is_empty() {
        return Ok(report);
    }

    let mut config: Config = Config::new();
    config.consume_fuel(true).epoch_interruption(true);
    let engine: Engine =
        Engine::new(&config).map_err(|e| Error::Parse(format!("wasmtime engine: {e}")))?;
    let module: Module =
        Module::new(&engine, bytes).map_err(|e| Error::Parse(format!("wasmtime module: {e}")))?;

    let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
    let watchdog: std::io::Result<std::thread::JoinHandle<()>> = spawn_epoch_watchdog(
        engine.clone(),
        Arc::clone(&stopper),
        Duration::from_millis(WALL_DEADLINE_MS),
    );

    for probe in &probes {
        if let Some(decrypted) = run_probe(&engine, &module, bytes, probe) {
            crate::debug::dbg_kv("probe-differential", || {
                format!(
                    "fn_index={} off={} len={} source={:?} outcome=recovered bytes={}",
                    probe.fn_index,
                    probe.off,
                    probe.len,
                    probe.source,
                    decrypted.len()
                )
            });
            report.segments.push(UnwrappedSegment {
                call_site_offset: probe.call_site_offset,
                off: probe.off,
                len: probe.len,
                source: probe.source,
                decrypted,
            });
        } else {
            crate::debug::dbg_kv("probe-differential", || {
                format!(
                    "fn_index={} off={} len={} source={:?} outcome=sandbox-declined",
                    probe.fn_index, probe.off, probe.len, probe.source
                )
            });
            report.unresolved.push(UnresolvedStub {
                fn_index: probe.fn_index,
                reason: UnresolvedReason::SandboxDeclined,
            });
        }
    }

    stopper.store(true, Ordering::Relaxed);
    if let Ok(handle) = watchdog {
        let _ = handle.join();
    }

    crate::debug::dbg_kv("unwrap-result", || {
        format!(
            "recovered={} unresolved={}",
            report.recovered(),
            report.failed()
        )
    });
    Ok(report)
}

#[cfg(feature = "sandbox")]
fn run_probe(
    engine: &wasmtime::Engine,
    module: &wasmtime::Module,
    bytes: &[u8],
    probe: &DecryptProbe,
) -> Option<Vec<u8>> {
    use wasmtime::{Linker, Store};

    let mut store: Store<()> = Store::new(engine, ());
    store.set_fuel(FUEL_BUDGET).ok()?;
    store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
    let mut linker: Linker<()> = Linker::new(engine);
    linker.define_unknown_imports_as_traps(module).ok()?;
    let instance: wasmtime::Instance = linker.instantiate(&mut store, module).ok()?;

    let typed: wasmtime::TypedFunc<(i32, i32), i32> =
        lookup_typed_decrypt(&instance, &mut store, bytes, probe.fn_index)?;
    let returned: i32 = typed.call(&mut store, (probe.off, probe.len)).ok()?;

    if let Some(decrypted) = read_instance_memory(&instance, &mut store, returned, probe.len) {
        return Some(decrypted);
    }
    read_instance_memory(&instance, &mut store, probe.absolute_base, probe.len)
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
fn export_name_for_func_index(bytes: &[u8], fn_index: u32) -> Option<String> {
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.ok()?;
        if let Payload::ExportSection(reader) = payload {
            for export in reader.into_iter().flatten() {
                if matches!(export.kind, wasmparser::ExternalKind::Func) && export.index == fn_index
                {
                    return Some(export.name.to_owned());
                }
            }
        }
    }
    None
}

#[cfg(feature = "sandbox")]
fn lookup_typed_decrypt(
    instance: &wasmtime::Instance,
    store: &mut wasmtime::Store<()>,
    bytes: &[u8],
    fn_index: u32,
) -> Option<wasmtime::TypedFunc<(i32, i32), i32>> {
    if let Some(name) = export_name_for_func_index(bytes, fn_index)
        && let Some(func) = instance.get_func(&mut *store, &name)
        && let Ok(typed) = func.typed::<(i32, i32), i32>(&*store)
    {
        return Some(typed);
    }
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
pub fn unwrap_decryption(bytes: &[u8], stubs: &[StubInfo]) -> Result<UnwrapReport> {
    if stubs.is_empty() {
        return Ok(UnwrapReport::default());
    }
    let (_probes, unresolved): (Vec<DecryptProbe>, Vec<u32>) =
        collect_decrypt_probes(bytes, stubs)?;
    let _ = unresolved;
    Err(crate::error::Error::Parse(
        "wasmtime sandbox feature disabled".to_owned(),
    ))
}

#[cfg(all(test, not(feature = "sandbox")))]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod feature_off_tests {
    use super::*;

    #[test]
    fn returns_parse_error_when_feature_disabled_with_stub() {
        let stub: StubInfo = StubInfo {
            fn_index: 0,
            key: None,
            op_histogram: std::collections::BTreeMap::new(),
            confidence: 1.0,
        };
        let result: Result<UnwrapReport> = unwrap_decryption(&[], &[stub]);
        assert!(matches!(result, Err(crate::error::Error::Parse(_))));
    }

    #[test]
    fn empty_stub_list_is_clean_noop_even_without_sandbox() {
        let report: UnwrapReport =
            unwrap_decryption(&[], &[]).expect("empty stub list short-circuits");
        assert!(report.segments.is_empty());
        assert_eq!(report.failed(), 0);
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

    fn hex_escape(plain: &[u8], key: u8) -> String {
        const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out: String = String::with_capacity(plain.len() * 4);
        for byte in plain {
            let encrypted: u8 = byte ^ key;
            out.push('\\');
            out.push(LOWER_HEX[(encrypted >> 4) as usize] as char);
            out.push(LOWER_HEX[(encrypted & 0x0f) as usize] as char);
        }
        out
    }

    #[test]
    fn empty_stubs_short_circuit() {
        let report: UnwrapReport =
            unwrap_decryption(&[], &[]).expect("empty stub list is a clean no-op");
        assert!(report.segments.is_empty());
        assert_eq!(report.recovered(), 0);
    }

    #[test]
    fn rejects_infinite_loop_in_stub_within_deadline() {
        let wat_text: &str = r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 0) "\01\02\03\04")
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
        let outcome: Result<UnwrapReport> = unwrap_decryption(&bytes, &stubs);
        let elapsed: Duration = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(3),
            "infinite wasm loop must be trapped within 3s, took {elapsed:?}",
        );
        if let Ok(report) = outcome {
            assert!(
                report.segments.is_empty(),
                "trapping stub must not yield decrypted segments, got {:?}",
                report.segments,
            );
        }
    }

    #[test]
    fn garbage_module_yields_no_fabricated_output() {
        let stubs: [StubInfo; 1] = [stub(0)];
        let junk: [u8; 16] = [0xff; 16];
        let report: Result<UnwrapReport> = unwrap_decryption(&junk, &stubs);
        if let Ok(report) = report {
            assert!(
                report.segments.is_empty(),
                "a non-wasm blob must never produce decrypted bytes"
            );
        }
    }

    #[test]
    fn no_data_segment_reports_unresolved_not_zero_span() {
        let wat_text: &str = r#"
            (module
              (memory (export "memory") 1)
              (func (export "__disrobe_decrypt_0") (param i32 i32) (result i32)
                local.get 0))
        "#;
        let Some(bytes): Option<Vec<u8>> = assemble(wat_text) else {
            panic!("fixture must assemble");
        };
        let stubs: [StubInfo; 1] = [stub(0)];
        let report: UnwrapReport =
            unwrap_decryption(&bytes, &stubs).expect("runs on a span-less module");
        assert_eq!(
            report.recovered(),
            0,
            "no static span means nothing decrypts"
        );
        assert_eq!(report.failed(), 1, "the span-less stub is reported failed");
        assert_eq!(report.unresolved[0].fn_index, 0);
        assert_eq!(report.unresolved[0].reason, UnresolvedReason::NoStaticSpan);
    }

    #[test]
    fn decrypts_active_segment_with_relative_offset_thunk() {
        let key: u8 = 0x4b;
        let plain: &[u8] = b"helloworld!";
        let cipher: String = hex_escape(plain, key);
        let wat_text: String = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 256) "{cipher}")
              (func (export "__disrobe_decrypt_0") (param i32 i32) (result i32)
                (local i32 i32 i32)
                local.get 0
                i32.const 256
                i32.add
                local.set 2
                block
                  loop
                    local.get 3
                    local.get 1
                    i32.ge_s
                    br_if 1
                    local.get 2
                    local.get 3
                    i32.add
                    local.tee 4
                    local.get 4
                    i32.load8_u
                    i32.const {key}
                    i32.xor
                    i32.store8
                    local.get 3
                    i32.const 1
                    i32.add
                    local.set 3
                    br 0
                  end
                end
                local.get 2))
        "#
        );
        let Some(bytes): Option<Vec<u8>> = assemble(&wat_text) else {
            panic!("relative-offset fixture must assemble");
        };
        let stubs: [StubInfo; 1] = [stub(0)];
        let report: UnwrapReport =
            unwrap_decryption(&bytes, &stubs).expect("relative-offset thunk runs");
        assert_eq!(
            report.recovered(),
            1,
            "the one stub must decrypt its buffer"
        );
        assert_eq!(report.failed(), 0);
        let segment: &UnwrappedSegment = &report.segments[0];
        assert_eq!(
            segment.decrypted, plain,
            "sandbox-recovered plaintext must equal the known input"
        );
        assert_eq!(segment.off, 0, "relative thunk is driven with off=0");
        assert_eq!(segment.len, plain.len() as i32);
        assert_eq!(segment.source, ProbeSource::ActiveDataSegment);
    }

    #[test]
    fn call_site_constants_drive_absolute_offset_thunk() {
        let key: u8 = 0x29;
        let plain: &[u8] = b"SECRET";
        let cipher: String = hex_escape(plain, key);
        let wat_text: String = format!(
            r#"
            (module
              (memory (export "memory") 1)
              (data (i32.const 1024) "{cipher}")
              (func $dec (param i32 i32) (result i32)
                (local i32 i32)
                block
                  loop
                    local.get 2
                    local.get 1
                    i32.ge_s
                    br_if 1
                    local.get 0
                    local.get 2
                    i32.add
                    local.tee 3
                    local.get 3
                    i32.load8_u
                    i32.const {key}
                    i32.xor
                    i32.store8
                    local.get 2
                    i32.const 1
                    i32.add
                    local.set 2
                    br 0
                  end
                end
                local.get 0)
              (func (export "run") (result i32)
                i32.const 1024
                i32.const {plen}
                call $dec)
              (export "__disrobe_decrypt_0" (func $dec)))
        "#,
            plen = plain.len()
        );
        let Some(bytes): Option<Vec<u8>> = assemble(&wat_text) else {
            panic!("absolute-offset fixture must assemble");
        };
        let stubs: [StubInfo; 1] = [stub(0)];
        let report: UnwrapReport =
            unwrap_decryption(&bytes, &stubs).expect("absolute-offset thunk runs");
        assert_eq!(report.recovered(), 1);
        let segment: &UnwrappedSegment = &report.segments[0];
        assert_eq!(
            segment.decrypted, plain,
            "call-site-driven plaintext must equal the known input"
        );
        assert_eq!(segment.off, 1024, "absolute thunk uses the call-site base");
        assert!(
            segment.call_site_offset > 0,
            "the call-site bytecode offset must be recorded"
        );
        assert_eq!(segment.source, ProbeSource::CallSiteConstants);
    }
}
