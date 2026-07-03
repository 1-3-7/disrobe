#![cfg(feature = "sandbox")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, lift_module_faithful_wat, recover_gc_types, scan_function_refs,
    scan_module_eh, scan_stack_switching,
};
use wasmparser::{FunctionBody, Operator, Parser, Payload, ValType};
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

const FUEL_BUDGET: u64 = 2_000_000;
const EPOCH_DEADLINE_TICKS: u64 = 1;
const WALL_DEADLINE_MS: u64 = 2_000;
const MEMORY_COMPARE_BYTES: usize = 4_096;

fn corpus_dirs() -> Vec<PathBuf> {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        root.join("../../corpus/src/wasm/sources"),
        root.join("../../corpus/src/wasm/edge_cases"),
        root.join("../../corpus/wasm/wat"),
        root.join("../../corpus/wasm/plugins"),
    ]
}

fn wat_files() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in corpus_dirs() {
        let Ok(entries): Result<fs::ReadDir, _> = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path: PathBuf = entry.path();
            if path.extension().is_some_and(|e| e == "wat") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpVal {
    I32(i32),
    I64(i64),
    F32Bits(u32),
    F64Bits(u64),
    RefNull,
    RefNonNull,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Returned(Vec<CmpVal>),
    Trapped,
}

#[derive(Debug, Default)]
struct DiffTally {
    total_functions: usize,
    fully_recovered: usize,
    execution_eligible: usize,
    execution_equivalent: usize,
    memory_verified: usize,
    diverged: Vec<String>,
    ineligible_reason: BTreeMap<String, usize>,
}

fn rich_config() -> Config {
    let mut config: Config = Config::new();
    config
        .consume_fuel(true)
        .epoch_interruption(true)
        .wasm_gc(true)
        .wasm_function_references(true)
        .wasm_tail_call(true)
        .wasm_threads(true)
        .wasm_relaxed_simd(true)
        .wasm_simd(true)
        .wasm_exceptions(true)
        .wasm_multi_memory(true)
        .wasm_memory64(true)
        .wasm_extended_const(true)
        .wasm_custom_page_sizes(true)
        .wasm_wide_arithmetic(true);
    config
}

fn core_config() -> Config {
    let mut config: Config = Config::new();
    config.consume_fuel(true).epoch_interruption(true);
    config
}

fn engine() -> Engine {
    Engine::new(&rich_config())
        .or_else(|_| Engine::new(&core_config()))
        .expect("wasmtime engine with at least core deterministic features")
}

struct Sandbox {
    store: Store<()>,
    instance: wasmtime::Instance,
}

fn instantiate(eng: &Engine, bytes: &[u8]) -> Option<Sandbox> {
    let module: Module = Module::new(eng, bytes).ok()?;
    let mut store: Store<()> = Store::new(eng, ());
    store.set_fuel(FUEL_BUDGET).ok()?;
    store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
    let mut linker: Linker<()> = Linker::new(eng);
    linker.define_unknown_imports_as_traps(&module).ok()?;
    let instance: wasmtime::Instance = linker.instantiate(&mut store, &module).ok()?;
    Some(Sandbox { store, instance })
}

fn spawn_watchdog(eng: Engine, stopper: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("disrobe-diff-watchdog".to_owned())
        .spawn(move || {
            let started: std::time::Instant = std::time::Instant::now();
            let tick: Duration = Duration::from_millis(25);
            while !stopper.load(Ordering::Relaxed) {
                std::thread::sleep(tick);
                if started.elapsed() >= Duration::from_millis(WALL_DEADLINE_MS) {
                    eng.increment_epoch();
                    break;
                }
            }
        })
        .expect("spawn watchdog")
}

const fn to_cmp(val: &Val) -> Option<CmpVal> {
    match val {
        Val::I32(v) => Some(CmpVal::I32(*v)),
        Val::I64(v) => Some(CmpVal::I64(*v)),
        Val::F32(bits) => Some(CmpVal::F32Bits(canonical_f32(*bits))),
        Val::F64(bits) => Some(CmpVal::F64Bits(canonical_f64(*bits))),
        Val::FuncRef(r) => Some(if r.is_none() {
            CmpVal::RefNull
        } else {
            CmpVal::RefNonNull
        }),
        Val::ExternRef(r) => Some(if r.is_none() {
            CmpVal::RefNull
        } else {
            CmpVal::RefNonNull
        }),
        Val::AnyRef(r) => Some(if r.is_none() {
            CmpVal::RefNull
        } else {
            CmpVal::RefNonNull
        }),
        _ => None,
    }
}

const fn canonical_f32(bits: u32) -> u32 {
    if f32::from_bits(bits).is_nan() {
        0x7fc0_0000
    } else {
        bits
    }
}

const fn canonical_f64(bits: u64) -> u64 {
    if f64::from_bits(bits).is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        bits
    }
}

fn call_outcome(sandbox: &mut Sandbox, export: &str, args: &[Val], result_arity: usize) -> Outcome {
    let Some(func): Option<wasmtime::Func> = sandbox.instance.get_func(&mut sandbox.store, export)
    else {
        return Outcome::Trapped;
    };
    let mut results: Vec<Val> = vec![Val::I32(0); result_arity];
    if func.call(&mut sandbox.store, args, &mut results).is_err() {
        let _ = sandbox.store.set_fuel(FUEL_BUDGET);
        sandbox.store.set_epoch_deadline(EPOCH_DEADLINE_TICKS);
        return Outcome::Trapped;
    }
    let mapped: Option<Vec<CmpVal>> = results.iter().map(to_cmp).collect();
    mapped.map_or(Outcome::Trapped, Outcome::Returned)
}

fn first_memory(sandbox: &mut Sandbox) -> Option<wasmtime::Memory> {
    let names: Vec<String> = sandbox
        .instance
        .exports(&mut sandbox.store)
        .filter_map(|e| {
            let name: String = e.name().to_owned();
            e.into_memory().map(|_| name)
        })
        .collect();
    let first: &String = names.first()?;
    sandbox.instance.get_memory(&mut sandbox.store, first)
}

fn memory_prefix(sandbox: &mut Sandbox) -> Option<Vec<u8>> {
    let memory: wasmtime::Memory = first_memory(sandbox)?;
    let data: &[u8] = memory.data(&sandbox.store);
    let take: usize = data.len().min(MEMORY_COMPARE_BYTES);
    Some(data[..take].to_vec())
}

const fn numeric(ty: ValType) -> bool {
    matches!(
        ty,
        ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64
    )
}

const fn nullable_ref(ty: ValType) -> bool {
    matches!(ty, ValType::Ref(r) if r.is_nullable())
}

const fn comparable(ty: ValType) -> bool {
    matches!(
        ty,
        ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64 | ValType::Ref(_)
    )
}

const fn seedable(ty: ValType) -> bool {
    numeric(ty) || nullable_ref(ty)
}

fn signature_is_numeric(sig: &FunctionSig) -> bool {
    sig.params.iter().copied().all(numeric) && sig.results.iter().copied().all(numeric)
}

fn signature_is_executable(sig: &FunctionSig) -> bool {
    sig.params.iter().copied().all(seedable) && sig.results.iter().copied().all(comparable)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModuleConstruct {
    Plain,
    Gc,
    ExceptionHandling,
    StackSwitching,
}

fn classify_module_construct(bytes: &[u8]) -> ModuleConstruct {
    if scan_stack_switching(bytes).is_ok_and(|r| !r.is_empty()) {
        return ModuleConstruct::StackSwitching;
    }
    if scan_module_eh(bytes).is_ok_and(|s| s.uses_exception_handling()) {
        return ModuleConstruct::ExceptionHandling;
    }
    let uses_gc: bool = recover_gc_types(bytes).is_ok_and(|g| !g.is_empty());
    let uses_funcref: bool = scan_function_refs(bytes).is_ok_and(|r| !r.is_empty());
    if uses_gc || uses_funcref {
        return ModuleConstruct::Gc;
    }
    ModuleConstruct::Plain
}

fn module_has_memory(bytes: &[u8]) -> bool {
    for payload in Parser::new(0).parse_all(bytes) {
        match payload {
            Ok(Payload::MemorySection(reader)) if reader.count() > 0 => return true,
            Ok(Payload::ImportSection(reader)) => {
                for imp in reader.into_imports().flatten() {
                    if matches!(imp.ty, wasmparser::TypeRef::Memory(_)) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    false
}

fn module_has_nonzero_data(bytes: &[u8]) -> bool {
    for payload in Parser::new(0).parse_all(bytes) {
        let Ok(Payload::DataSection(reader)) = payload else {
            continue;
        };
        for item in reader {
            let Ok(data): Result<wasmparser::Data<'_>, _> = item else {
                return true;
            };
            if data.data.iter().any(|b| *b != 0) {
                return true;
            }
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Eligibility {
    Ok { writes_memory: bool },
    Reject(&'static str),
}

const fn is_atomic(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::AtomicFence
            | Operator::MemoryAtomicNotify { .. }
            | Operator::MemoryAtomicWait32 { .. }
            | Operator::MemoryAtomicWait64 { .. }
            | Operator::I32AtomicLoad { .. }
            | Operator::I64AtomicLoad { .. }
            | Operator::I32AtomicLoad8U { .. }
            | Operator::I32AtomicLoad16U { .. }
            | Operator::I64AtomicLoad8U { .. }
            | Operator::I64AtomicLoad16U { .. }
            | Operator::I64AtomicLoad32U { .. }
            | Operator::I32AtomicStore { .. }
            | Operator::I64AtomicStore { .. }
            | Operator::I32AtomicStore8 { .. }
            | Operator::I32AtomicStore16 { .. }
            | Operator::I64AtomicStore8 { .. }
            | Operator::I64AtomicStore16 { .. }
            | Operator::I64AtomicStore32 { .. }
            | Operator::I32AtomicRmwAdd { .. }
            | Operator::I64AtomicRmwAdd { .. }
            | Operator::I32AtomicRmw8AddU { .. }
            | Operator::I32AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw8AddU { .. }
            | Operator::I64AtomicRmw16AddU { .. }
            | Operator::I64AtomicRmw32AddU { .. }
            | Operator::I32AtomicRmwSub { .. }
            | Operator::I64AtomicRmwSub { .. }
            | Operator::I32AtomicRmw8SubU { .. }
            | Operator::I32AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw8SubU { .. }
            | Operator::I64AtomicRmw16SubU { .. }
            | Operator::I64AtomicRmw32SubU { .. }
            | Operator::I32AtomicRmwAnd { .. }
            | Operator::I64AtomicRmwAnd { .. }
            | Operator::I32AtomicRmw8AndU { .. }
            | Operator::I32AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw8AndU { .. }
            | Operator::I64AtomicRmw16AndU { .. }
            | Operator::I64AtomicRmw32AndU { .. }
            | Operator::I32AtomicRmwOr { .. }
            | Operator::I64AtomicRmwOr { .. }
            | Operator::I32AtomicRmw8OrU { .. }
            | Operator::I32AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw8OrU { .. }
            | Operator::I64AtomicRmw16OrU { .. }
            | Operator::I64AtomicRmw32OrU { .. }
            | Operator::I32AtomicRmwXor { .. }
            | Operator::I64AtomicRmwXor { .. }
            | Operator::I32AtomicRmw8XorU { .. }
            | Operator::I32AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw8XorU { .. }
            | Operator::I64AtomicRmw16XorU { .. }
            | Operator::I64AtomicRmw32XorU { .. }
            | Operator::I32AtomicRmwXchg { .. }
            | Operator::I64AtomicRmwXchg { .. }
            | Operator::I32AtomicRmw8XchgU { .. }
            | Operator::I32AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw8XchgU { .. }
            | Operator::I64AtomicRmw16XchgU { .. }
            | Operator::I64AtomicRmw32XchgU { .. }
            | Operator::I32AtomicRmwCmpxchg { .. }
            | Operator::I64AtomicRmwCmpxchg { .. }
            | Operator::I32AtomicRmw8CmpxchgU { .. }
            | Operator::I32AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw8CmpxchgU { .. }
            | Operator::I64AtomicRmw16CmpxchgU { .. }
            | Operator::I64AtomicRmw32CmpxchgU { .. }
    )
}

fn memarg_uses_nonzero_memory(op: &Operator<'_>) -> bool {
    let memarg: Option<wasmparser::MemArg> = match op {
        Operator::I32Load { memarg }
        | Operator::I64Load { memarg }
        | Operator::F32Load { memarg }
        | Operator::F64Load { memarg }
        | Operator::I32Load8U { memarg }
        | Operator::I32Load8S { memarg }
        | Operator::I32Load16U { memarg }
        | Operator::I32Load16S { memarg }
        | Operator::I64Load8U { memarg }
        | Operator::I64Load8S { memarg }
        | Operator::I64Load16U { memarg }
        | Operator::I64Load16S { memarg }
        | Operator::I64Load32U { memarg }
        | Operator::I64Load32S { memarg }
        | Operator::I32Store { memarg }
        | Operator::I64Store { memarg }
        | Operator::F32Store { memarg }
        | Operator::F64Store { memarg }
        | Operator::I32Store8 { memarg }
        | Operator::I32Store16 { memarg }
        | Operator::I64Store8 { memarg }
        | Operator::I64Store16 { memarg }
        | Operator::I64Store32 { memarg } => Some(*memarg),
        _ => None,
    };
    memarg.is_some_and(|m| m.memory != 0)
}

const fn op_breaks_faithful_render(op: &Operator<'_>) -> bool {
    matches!(
        op,
        Operator::TableGet { .. }
            | Operator::TableSet { .. }
            | Operator::TableSize { .. }
            | Operator::TableGrow { .. }
            | Operator::TableFill { .. }
            | Operator::TableCopy { .. }
            | Operator::TableInit { .. }
            | Operator::ElemDrop { .. }
            | Operator::MemoryInit { .. }
            | Operator::DataDrop { .. }
            | Operator::MemorySize { mem: 1.. }
            | Operator::MemoryGrow { mem: 1.. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryFill { mem: 1.. }
    )
}

fn body_renders_faithfully(body: &FunctionBody<'_>) -> bool {
    let Ok(reader): Result<wasmparser::OperatorsReader<'_>, _> = body.get_operators_reader() else {
        return false;
    };
    for op in reader {
        let Ok(op): Result<Operator<'_>, _> = op else {
            return false;
        };
        if op_breaks_faithful_render(&op) || memarg_uses_nonzero_memory(&op) {
            return false;
        }
    }
    true
}

fn body_has_atomics(body: &FunctionBody<'_>) -> bool {
    let Ok(reader): Result<wasmparser::OperatorsReader<'_>, _> = body.get_operators_reader() else {
        return true;
    };
    for op in reader {
        let Ok(op): Result<Operator<'_>, _> = op else {
            return true;
        };
        if is_atomic(&op) {
            return true;
        }
    }
    false
}

fn classify_executability(body: &FunctionBody<'_>) -> Eligibility {
    let Ok(reader): Result<wasmparser::OperatorsReader<'_>, _> = body.get_operators_reader() else {
        return Eligibility::Reject("operator-decode");
    };
    let mut writes_memory: bool = false;
    for op in reader {
        let Ok(op): Result<Operator<'_>, _> = op else {
            return Eligibility::Reject("operator-decode");
        };
        if is_atomic(&op) {
            return Eligibility::Reject("atomic-concurrency");
        }
        match op {
            Operator::Call { .. }
            | Operator::CallIndirect { .. }
            | Operator::ReturnCall { .. }
            | Operator::ReturnCallIndirect { .. }
            | Operator::CallRef { .. }
            | Operator::ReturnCallRef { .. } => {
                return Eligibility::Reject("calls-external-state");
            }
            Operator::GlobalGet { .. } | Operator::GlobalSet { .. } => {
                return Eligibility::Reject("global-state");
            }
            Operator::MemoryInit { .. } | Operator::DataDrop { .. } => {
                return Eligibility::Reject("data-segment-dependent");
            }
            Operator::TableGet { .. }
            | Operator::TableSet { .. }
            | Operator::TableSize { .. }
            | Operator::TableGrow { .. }
            | Operator::TableFill { .. }
            | Operator::TableCopy { .. }
            | Operator::TableInit { .. }
            | Operator::ElemDrop { .. } => {
                return Eligibility::Reject("table-state");
            }
            Operator::I32Store { .. }
            | Operator::I64Store { .. }
            | Operator::F32Store { .. }
            | Operator::F64Store { .. }
            | Operator::I32Store8 { .. }
            | Operator::I32Store16 { .. }
            | Operator::I64Store8 { .. }
            | Operator::I64Store16 { .. }
            | Operator::I64Store32 { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryFill { .. } => {
                writes_memory = true;
            }
            _ => {}
        }
    }
    Eligibility::Ok { writes_memory }
}

fn seed_values(ty: ValType) -> Vec<Val> {
    match ty {
        ValType::I32 => [0_i32, 1, -1, 2, 7, -8, 100, i32::MIN, i32::MAX, 0x5555_5555]
            .iter()
            .map(|v| Val::I32(*v))
            .collect(),
        ValType::I64 => [
            0_i64,
            1,
            -1,
            3,
            65_536,
            i64::MIN,
            i64::MAX,
            0x0123_4567_89ab_cdef,
        ]
        .iter()
        .map(|v| Val::I64(*v))
        .collect(),
        ValType::F32 => [0.0_f32, 1.0, -1.0, 3.5, -2.25, f32::INFINITY, f32::NAN]
            .iter()
            .map(|v| Val::F32(v.to_bits()))
            .collect(),
        ValType::F64 => [0.0_f64, 1.0, -1.0, 2.5, -0.5, f64::INFINITY, f64::NAN]
            .iter()
            .map(|v| Val::F64(v.to_bits()))
            .collect(),
        ValType::Ref(r) => vec![null_ref_value(r)],
        ValType::V128 => Vec::new(),
    }
}

fn null_ref_value(r: wasmparser::RefType) -> Val {
    use wasmparser::{AbstractHeapType, HeapType};
    match r.heap_type() {
        HeapType::Abstract {
            ty: AbstractHeapType::Extern | AbstractHeapType::NoExtern,
            ..
        } => Val::ExternRef(None),
        HeapType::Abstract {
            ty: AbstractHeapType::Func | AbstractHeapType::NoFunc,
            ..
        } => Val::FuncRef(None),
        _ => Val::AnyRef(None),
    }
}

fn argument_battery(params: &[ValType], cap: usize) -> Vec<Vec<Val>> {
    if params.is_empty() {
        return vec![Vec::new()];
    }
    let per_param: Vec<Vec<Val>> = params.iter().map(|ty| seed_values(*ty)).collect();
    let mut out: Vec<Vec<Val>> = vec![Vec::new()];
    for choices in &per_param {
        let mut next: Vec<Vec<Val>> = Vec::new();
        for prefix in &out {
            for choice in choices {
                let mut extended: Vec<Val> = prefix.clone();
                extended.push(*choice);
                next.push(extended);
                if next.len() >= cap {
                    break;
                }
            }
            if next.len() >= cap {
                break;
            }
        }
        out = next;
    }
    out.truncate(cap);
    out
}

const fn reason_covered_by_whole_module(reason: &str) -> bool {
    matches!(
        reason.as_bytes(),
        b"calls-external-state" | b"global-state" | b"table-state" | b"data-segment-dependent"
    )
}

struct Candidate {
    label: String,
    export: String,
    params: Vec<ValType>,
    result_arity: usize,
    writes_memory: bool,
}

fn collect_candidates(wat_path: &Path, tally: &mut DiffTally) -> Option<(Vec<u8>, Vec<Candidate>)> {
    let text: String = fs::read_to_string(wat_path).expect("read wat");
    let original: Vec<u8> = wat::parse_str(&text).ok()?;
    let sigs: ModuleSignatures = extract_signatures(&original).ok()?;
    let defined: &[FunctionSig] = sigs.defined();

    if classify_module_construct(&original) != ModuleConstruct::Plain {
        return None;
    }
    let callees: CalleeNames = callees(&sigs);
    let nonzero_data: bool = module_has_nonzero_data(&original);
    let file: String = wat_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let mut candidates: Vec<Candidate> = Vec::new();
    for (i, body) in defined_bodies(&original).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(i) else {
            continue;
        };
        tally.total_functions += 1;
        let label: String = format!("{file}:{}", sig.name);
        let lifted: LiftResult = lift_function_body(body, sig, &callees, LiftTarget::Wat);
        if !lifted.coverage.fully_recovered() {
            *tally
                .ineligible_reason
                .entry("op-coverage-gap".to_owned())
                .or_default() += 1;
            continue;
        }
        tally.fully_recovered += 1;
        if !sig.exported {
            *tally
                .ineligible_reason
                .entry("not-exported".to_owned())
                .or_default() += 1;
            continue;
        }
        let whole_module_covers: bool = signature_is_executable(sig);
        if !signature_is_numeric(sig) {
            if !whole_module_covers {
                *tally
                    .ineligible_reason
                    .entry("non-numeric-abi".to_owned())
                    .or_default() += 1;
            }
            continue;
        }
        let writes_memory: bool = match classify_executability(body) {
            Eligibility::Reject(reason) => {
                if !whole_module_covers || !reason_covered_by_whole_module(reason) {
                    *tally
                        .ineligible_reason
                        .entry(reason.to_owned())
                        .or_default() += 1;
                }
                continue;
            }
            Eligibility::Ok { writes_memory } => writes_memory,
        };
        if nonzero_data {
            continue;
        }
        candidates.push(Candidate {
            label,
            export: sig.name.clone(),
            params: sig.params.clone(),
            result_arity: sig.results.len(),
            writes_memory,
        });
    }
    if candidates.is_empty() {
        return None;
    }
    Some((original, candidates))
}

fn expose_memory(wat_text: &str) -> String {
    const HEADER: &str = "(module\n";
    let Some(rest): Option<&str> = wat_text.strip_prefix(HEADER) else {
        return wat_text.to_owned();
    };
    format!("{HEADER}  (export \"disrobe_diff_mem\" (memory 0))\n{rest}")
}

fn lifted_single_module(wat_path: &Path, target_export: &str) -> Option<Vec<u8>> {
    let text: String = fs::read_to_string(wat_path).ok()?;
    let original: Vec<u8> = wat::parse_str(&text).ok()?;
    let sigs: ModuleSignatures = extract_signatures(&original).ok()?;
    let defined: &[FunctionSig] = sigs.defined();
    let callees: CalleeNames = callees(&sigs);
    for (i, body) in defined_bodies(&original).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(i) else {
            continue;
        };
        if sig.name != target_export {
            continue;
        }
        let lifted: LiftResult = lift_function_body(body, sig, &callees, LiftTarget::Wat);
        let exposed: String = expose_memory(&lifted.pseudo_source);
        return wat::parse_str(&exposed).ok();
    }
    None
}

fn whole_module_gc_phase(wat_path: &Path, tally: &mut DiffTally, eng: &Engine) {
    let text: String = fs::read_to_string(wat_path).expect("read wat");
    let Ok(original): Result<Vec<u8>, _> = wat::parse_str(&text) else {
        return;
    };
    let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&original) else {
        return;
    };
    let defined: Vec<FunctionSig> = sigs.defined().to_vec();
    let callees: CalleeNames = callees(&sigs);
    for (i, body) in defined_bodies(&original).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(i) else {
            continue;
        };
        tally.total_functions += 1;
        let lifted: LiftResult = lift_function_body(body, sig, &callees, LiftTarget::Wat);
        if lifted.coverage.fully_recovered() {
            tally.fully_recovered += 1;
        } else {
            *tally
                .ineligible_reason
                .entry("op-coverage-gap".to_owned())
                .or_default() += 1;
        }
    }
    let numeric_exports: Vec<FunctionSig> = defined
        .iter()
        .filter(|s| s.exported && signature_is_numeric(s))
        .cloned()
        .collect();
    if numeric_exports.is_empty() {
        *tally
            .ineligible_reason
            .entry("gc-no-numeric-export".to_owned())
            .or_default() += defined.len();
        return;
    }
    if instantiate(eng, &original).is_none() {
        *tally
            .ineligible_reason
            .entry("gc-original-not-isolatable".to_owned())
            .or_default() += numeric_exports.len();
        return;
    }
    let Some(lifted_wat): Option<String> = lift_module_faithful_wat(&original) else {
        for s in &numeric_exports {
            tally.diverged.push(format!(
                "{}:{}: faithful whole-module GC lift failed to assemble",
                file_label(wat_path),
                s.name
            ));
        }
        return;
    };
    let Ok(lifted_bytes): Result<Vec<u8>, _> = wat::parse_str(&lifted_wat) else {
        for s in &numeric_exports {
            tally.diverged.push(format!(
                "{}:{}: faithful whole-module GC lift did not reassemble to wasm",
                file_label(wat_path),
                s.name
            ));
        }
        return;
    };

    for sig in &numeric_exports {
        tally.execution_eligible += 1;
        let label: String = format!("{}:{}", file_label(wat_path), sig.name);

        let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let watchdog: std::thread::JoinHandle<()> =
            spawn_watchdog(eng.clone(), Arc::clone(&stopper));

        let Some(mut sandbox_a): Option<Sandbox> = instantiate(eng, &original) else {
            stopper.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            tally
                .diverged
                .push(format!("{label}: original GC module failed to instantiate"));
            continue;
        };
        let Some(mut sandbox_b): Option<Sandbox> = instantiate(eng, &lifted_bytes) else {
            stopper.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            tally
                .diverged
                .push(format!("{label}: lifted GC module failed to instantiate"));
            continue;
        };

        let battery: Vec<Vec<Val>> = argument_battery(&sig.params, 64);
        let mut equivalent: bool = true;
        for args in &battery {
            let out_a: Outcome = call_outcome(&mut sandbox_a, &sig.name, args, sig.results.len());
            let out_b: Outcome = call_outcome(&mut sandbox_b, &sig.name, args, sig.results.len());
            if out_a != out_b {
                equivalent = false;
                tally.diverged.push(format!(
                    "{label}: args={args:?} original={out_a:?} recovered={out_b:?}"
                ));
                break;
            }
        }
        stopper.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        if equivalent {
            tally.execution_equivalent += 1;
        }
    }
}

fn per_function_eligible(body: &FunctionBody<'_>, sig: &FunctionSig, nonzero_data: bool) -> bool {
    if !sig.exported || !signature_is_numeric(sig) {
        return false;
    }
    if nonzero_data {
        return false;
    }
    matches!(classify_executability(body), Eligibility::Ok { .. })
}

fn whole_module_plain_phase(wat_path: &Path, tally: &mut DiffTally, eng: &Engine) {
    let text: String = fs::read_to_string(wat_path).expect("read wat");
    let Ok(original): Result<Vec<u8>, _> = wat::parse_str(&text) else {
        return;
    };
    let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&original) else {
        return;
    };
    let defined: Vec<FunctionSig> = sigs.defined().to_vec();
    let nonzero_data: bool = module_has_nonzero_data(&original);

    let mut targets: Vec<FunctionSig> = Vec::new();
    for (i, body) in defined_bodies(&original).iter().enumerate() {
        let Some(sig): Option<&FunctionSig> = defined.get(i) else {
            continue;
        };
        if !sig.exported || !signature_is_executable(sig) {
            continue;
        }
        if per_function_eligible(body, sig, nonzero_data) {
            continue;
        }
        if body_has_atomics(body) {
            continue;
        }
        if !body_renders_faithfully(body) {
            *tally
                .ineligible_reason
                .entry("table-or-multimem-renderer-gap".to_owned())
                .or_default() += 1;
            continue;
        }
        targets.push(sig.clone());
    }
    if targets.is_empty() {
        return;
    }

    let Some(lifted_wat): Option<String> = lift_module_faithful_wat(&original) else {
        for s in &targets {
            tally.diverged.push(format!(
                "{}:{}: faithful whole-module lift failed to assemble",
                file_label(wat_path),
                s.name
            ));
        }
        return;
    };
    let exposed: String = if module_has_memory(&original) {
        expose_memory(&lifted_wat)
    } else {
        lifted_wat
    };
    let Ok(lifted_bytes): Result<Vec<u8>, _> = wat::parse_str(&exposed) else {
        for s in &targets {
            tally.diverged.push(format!(
                "{}:{}: faithful whole-module lift did not reassemble to wasm",
                file_label(wat_path),
                s.name
            ));
        }
        return;
    };

    if instantiate(eng, &original).is_none() {
        *tally
            .ineligible_reason
            .entry("plain-original-not-isolatable".to_owned())
            .or_default() += targets.len();
        return;
    }

    for sig in &targets {
        tally.execution_eligible += 1;
        let label: String = format!("{}:{}", file_label(wat_path), sig.name);

        let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let watchdog: std::thread::JoinHandle<()> =
            spawn_watchdog(eng.clone(), Arc::clone(&stopper));

        let Some(mut sandbox_a): Option<Sandbox> = instantiate(eng, &original) else {
            stopper.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            tally.diverged.push(format!(
                "{label}: original plain module failed to instantiate"
            ));
            continue;
        };
        let Some(mut sandbox_b): Option<Sandbox> = instantiate(eng, &lifted_bytes) else {
            stopper.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            tally.diverged.push(format!(
                "{label}: faithful plain module failed to instantiate"
            ));
            continue;
        };

        let battery: Vec<Vec<Val>> = argument_battery(&sig.params, 48);
        let mut equivalent: bool = true;
        for args in &battery {
            let out_a: Outcome = call_outcome(&mut sandbox_a, &sig.name, args, sig.results.len());
            let out_b: Outcome = call_outcome(&mut sandbox_b, &sig.name, args, sig.results.len());
            if out_a != out_b {
                equivalent = false;
                tally.diverged.push(format!(
                    "{label}: args={args:?} original={out_a:?} recovered={out_b:?}"
                ));
                break;
            }
        }

        if equivalent {
            let mem_a: Option<Vec<u8>> = memory_prefix(&mut sandbox_a);
            let mem_b: Option<Vec<u8>> = memory_prefix(&mut sandbox_b);
            match (mem_a, mem_b) {
                (Some(a), Some(b)) if a == b => tally.memory_verified += 1,
                (Some(_), Some(_)) => {
                    equivalent = false;
                    tally.diverged.push(format!(
                        "{label}: linear-memory prefix diverged after battery"
                    ));
                }
                _ => {}
            }
        }

        stopper.store(true, Ordering::Relaxed);
        let _ = watchdog.join();
        if equivalent {
            tally.execution_equivalent += 1;
        }
    }
}

fn file_label(wat_path: &Path) -> String {
    wat_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn flag_unsupported_construct(wat_path: &Path, tally: &mut DiffTally, construct: ModuleConstruct) {
    let Ok(text): Result<String, _> = fs::read_to_string(wat_path) else {
        return;
    };
    let Ok(original): Result<Vec<u8>, _> = wat::parse_str(&text) else {
        return;
    };
    let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&original) else {
        return;
    };
    let count: usize = sigs.defined().len();
    let reason: &str = match construct {
        ModuleConstruct::ExceptionHandling => "eh-unsupported-by-wasmtime-cranelift",
        ModuleConstruct::StackSwitching => "stack-switching-unsupported-by-wasmtime-cranelift",
        ModuleConstruct::Plain | ModuleConstruct::Gc => return,
    };
    *tally
        .ineligible_reason
        .entry(reason.to_owned())
        .or_default() += count;
}

#[test]
fn differential_execution_equivalence_under_wasmtime() {
    let mut tally: DiffTally = DiffTally::default();
    let eng: Engine = engine();

    for wat_path in wat_files() {
        let Ok(bytes): Result<Vec<u8>, _> = fs::read_to_string(&wat_path)
            .map_err(|_| ())
            .and_then(|t| wat::parse_str(&t).map_err(|_| ()))
        else {
            continue;
        };
        match classify_module_construct(&bytes) {
            ModuleConstruct::Gc => whole_module_gc_phase(&wat_path, &mut tally, &eng),
            ModuleConstruct::ExceptionHandling => {
                flag_unsupported_construct(
                    &wat_path,
                    &mut tally,
                    ModuleConstruct::ExceptionHandling,
                );
            }
            ModuleConstruct::StackSwitching => {
                flag_unsupported_construct(&wat_path, &mut tally, ModuleConstruct::StackSwitching);
            }
            ModuleConstruct::Plain => whole_module_plain_phase(&wat_path, &mut tally, &eng),
        }

        let Some((original, candidates)): Option<(Vec<u8>, Vec<Candidate>)> =
            collect_candidates(&wat_path, &mut tally)
        else {
            continue;
        };

        if instantiate(&eng, &original).is_none() {
            *tally
                .ineligible_reason
                .entry("original-not-isolatable".to_owned())
                .or_default() += candidates.len();
            continue;
        }

        for candidate in candidates {
            tally.execution_eligible += 1;
            let Some(lifted_bytes): Option<Vec<u8>> =
                lifted_single_module(&wat_path, &candidate.export)
            else {
                tally.diverged.push(format!(
                    "{}: lifted wat failed to assemble",
                    candidate.label
                ));
                continue;
            };

            let stopper: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
            let watchdog: std::thread::JoinHandle<()> =
                spawn_watchdog(eng.clone(), Arc::clone(&stopper));

            let Some(mut sandbox_a): Option<Sandbox> = instantiate(&eng, &original) else {
                stopper.store(true, Ordering::Relaxed);
                let _ = watchdog.join();
                tally.diverged.push(format!(
                    "{}: original module failed to instantiate",
                    candidate.label
                ));
                continue;
            };
            let Some(mut sandbox_b): Option<Sandbox> = instantiate(&eng, &lifted_bytes) else {
                stopper.store(true, Ordering::Relaxed);
                let _ = watchdog.join();
                tally.diverged.push(format!(
                    "{}: lifted module failed to instantiate",
                    candidate.label
                ));
                continue;
            };

            let battery: Vec<Vec<Val>> = argument_battery(&candidate.params, 64);
            let mut equivalent: bool = true;
            for args in &battery {
                let out_a: Outcome = call_outcome(
                    &mut sandbox_a,
                    &candidate.export,
                    args,
                    candidate.result_arity,
                );
                let out_b: Outcome = call_outcome(
                    &mut sandbox_b,
                    &candidate.export,
                    args,
                    candidate.result_arity,
                );
                if out_a != out_b {
                    equivalent = false;
                    tally.diverged.push(format!(
                        "{}: args={args:?} original={out_a:?} recovered={out_b:?}",
                        candidate.label
                    ));
                    break;
                }
            }

            if equivalent && candidate.writes_memory {
                let mem_a: Option<Vec<u8>> = memory_prefix(&mut sandbox_a);
                let mem_b: Option<Vec<u8>> = memory_prefix(&mut sandbox_b);
                match (mem_a, mem_b) {
                    (Some(a), Some(b)) if a == b => tally.memory_verified += 1,
                    (Some(_), Some(_)) => {
                        equivalent = false;
                        tally.diverged.push(format!(
                            "{}: linear-memory prefix diverged after battery",
                            candidate.label
                        ));
                    }
                    _ => {}
                }
            }

            stopper.store(true, Ordering::Relaxed);
            let _ = watchdog.join();
            if equivalent {
                tally.execution_equivalent += 1;
            }
        }
    }

    eprintln!(
        "wasm DIFFERENTIAL execution oracle (wasmtime {}):",
        wasmtime_pin()
    );
    eprintln!(
        "  corpus functions: {}, fully-recovered (op-coverage): {}",
        tally.total_functions, tally.fully_recovered
    );
    eprintln!(
        "  execution-eligible (per-fn isolatable + whole-module faithful plain/GC, numeric+nullable-ref ABI): {}",
        tally.execution_eligible
    );
    eprintln!(
        "  EXECUTION-EQUIVALENT original==recovered over input battery: {}/{}",
        tally.execution_equivalent, tally.execution_eligible
    );
    eprintln!(
        "  of which linear-memory state also byte-identical: {}",
        tally.memory_verified
    );
    eprintln!("  op-coverage-only (not execution-checked) by reason:");
    for (reason, count) in &tally.ineligible_reason {
        eprintln!("    {reason}: {count}");
    }
    if !tally.diverged.is_empty() {
        eprintln!("  DIVERGENCES:");
        for line in &tally.diverged {
            eprintln!("    {line}");
        }
    }

    assert!(
        tally.execution_eligible >= 36,
        "expected the whole-module faithful phase to keep a large execution-eligible set, got {}",
        tally.execution_eligible
    );
    assert_eq!(
        tally.execution_equivalent,
        tally.execution_eligible,
        "every execution-eligible function MUST be observationally equivalent between the \
         original module and disrobe's recovered wasm under wasmtime; divergences:\n{}",
        tally.diverged.join("\n")
    );
}

const fn wasmtime_pin() -> &'static str {
    "36"
}
