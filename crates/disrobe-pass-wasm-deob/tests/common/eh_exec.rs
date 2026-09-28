#![allow(
    dead_code,
    unreachable_pub,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc
)]

use std::collections::BTreeSet;

use wasm_encoder::{CodeSection, RawSection};
use wasmparser::{ExternalKind, Operator, Parser, Payload, TypeRef};
use wasmtime::{
    Config, Engine, ExternType, FuncType, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
    ThrownException, Trap, Val, ValType,
};

pub const FUEL_BUDGET: u64 = 2_000_000;
pub const STORE_MEMORY_LIMIT_BYTES: usize = 16 * 1024 * 1024;
const ARGUMENT_VECTOR_CAP: usize = 32;
const UNREACHABLE_BODY: [u8; 3] = [0x00, 0x00, 0x0b];

#[must_use]
pub fn eh_engine() -> Engine {
    let mut config: Config = Config::new();
    config
        .wasm_gc(true)
        .wasm_function_references(true)
        .wasm_exceptions(true)
        .consume_fuel(true);
    Engine::new(&config).expect("wasmtime engine with exceptions and fuel metering")
}

fn store_limits() -> StoreLimits {
    StoreLimitsBuilder::new()
        .memory_size(STORE_MEMORY_LIMIT_BYTES)
        .table_elements(10_000)
        .instances(1)
        .tables(1)
        .memories(1)
        .build()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Returned(Vec<i64>),
    Thrown { tag: Vec<String>, payload: Vec<i64> },
    Trapped(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub returned: usize,
    pub thrown: usize,
    pub trapped: usize,
}

impl Tally {
    #[must_use]
    pub const fn checked(&self) -> usize {
        self.returned + self.thrown + self.trapped
    }
}

fn integer(value: &Val) -> i64 {
    match value {
        Val::I32(x) => i64::from(*x),
        Val::I64(x) => *x,
        other => panic!("the EH probe compares only i32 and i64 values, got {other:?}"),
    }
}

pub fn run(engine: &Engine, bytes: &[u8], export: &str, args: &[Val], arity: usize) -> Outcome {
    let module: Module = Module::new(engine, bytes).expect("module compiles under the EH engine");
    run_module(engine, &module, export, args, arity).expect("module instantiates within limits")
}

pub fn run_module(
    engine: &Engine,
    module: &Module,
    export: &str,
    args: &[Val],
    arity: usize,
) -> wasmtime::Result<Outcome> {
    let mut store: Store<StoreLimits> = Store::new(engine, store_limits());
    store.limiter(|limits: &mut StoreLimits| limits);
    store.set_fuel(FUEL_BUDGET)?;
    let mut linker: Linker<StoreLimits> = Linker::new(engine);
    linker.define_unknown_imports_as_traps(module)?;
    let instance: wasmtime::Instance = linker.instantiate(&mut store, module)?;
    let func: wasmtime::Func = instance
        .get_func(&mut store, export)
        .unwrap_or_else(|| panic!("export `{export}` is missing"));
    let mut results: Vec<Val> = vec![Val::I32(0); arity];
    let Err(error) = func.call(&mut store, args, &mut results) else {
        return Ok(Outcome::Returned(results.iter().map(integer).collect()));
    };
    if error.downcast_ref::<ThrownException>().is_some() {
        let exception: wasmtime::Rooted<wasmtime::ExnRef> = store
            .take_pending_exception()
            .expect("a thrown exception leaves a pending exception on the store");
        let tag: wasmtime::Tag = exception.tag(&mut store)?;
        let params: Vec<ValType> = tag.ty(&store).ty().params().collect();
        let mut payload: Vec<i64> = Vec::with_capacity(params.len());
        for index in 0..params.len() {
            payload.push(integer(&exception.field(&mut store, index)?));
        }
        return Ok(Outcome::Thrown {
            tag: params.iter().map(ToString::to_string).collect(),
            payload,
        });
    }
    let Some(trap): Option<&Trap> = error.downcast_ref::<Trap>() else {
        panic!("{export}: call failed without a trap or an exception: {error:#}");
    };
    Ok(Outcome::Trapped(format!("{trap:?}")))
}

fn seeds(ty: &ValType) -> Result<Vec<Val>, String> {
    match ty {
        ValType::I32 => Ok([0, 1, 2, -3, 7, 42, 50].into_iter().map(Val::I32).collect()),
        ValType::I64 => Ok([0, 1, 9, -2].into_iter().map(Val::I64).collect()),
        other => Err(format!("the EH probe has no argument seeds for {other}")),
    }
}

fn argument_vectors(ty: &FuncType) -> Result<Vec<Vec<Val>>, String> {
    if let Some(result) = ty
        .results()
        .find(|t: &ValType| !matches!(t, ValType::I32 | ValType::I64))
    {
        return Err(format!("the EH probe cannot compare a {result} result"));
    }
    let mut out: Vec<Vec<Val>> = vec![Vec::new()];
    for param in ty.params() {
        let choices: Vec<Val> = seeds(&param)?;
        let mut next: Vec<Vec<Val>> = Vec::new();
        for prefix in &out {
            for choice in &choices {
                let mut vector: Vec<Val> = prefix.clone();
                vector.push(*choice);
                next.push(vector);
            }
        }
        next.truncate(ARGUMENT_VECTOR_CAP);
        out = next;
    }
    Ok(out)
}

pub struct Projection {
    pub bytes: Vec<u8>,
    pub stubbed_exports: BTreeSet<String>,
}

fn uses_legacy_eh(body: &wasmparser::FunctionBody<'_>) -> bool {
    let mut reader: wasmparser::OperatorsReader<'_> = body
        .get_operators_reader()
        .expect("function body operators");
    while !reader.eof() {
        let op: Operator<'_> = reader.read().expect("function body operator");
        if matches!(
            op,
            Operator::Try { .. }
                | Operator::Catch { .. }
                | Operator::CatchAll
                | Operator::Delegate { .. }
                | Operator::Rethrow { .. }
        ) {
            return true;
        }
    }
    false
}

#[must_use]
pub fn modern_projection(bytes: &[u8]) -> Projection {
    let mut module: wasm_encoder::Module = wasm_encoder::Module::new();
    let mut code: Option<CodeSection> = None;
    let mut imported_functions: u32 = 0;
    let mut stubbed: BTreeSet<u32> = BTreeSet::new();
    let mut exports: Vec<(String, u32)> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'_> = payload.expect("module payload");
        match &payload {
            Payload::ImportSection(reader) => {
                for import in reader.clone().into_imports() {
                    let import: wasmparser::Import<'_> = import.expect("import");
                    if matches!(import.ty, TypeRef::Func(_) | TypeRef::FuncExact(_)) {
                        imported_functions += 1;
                    }
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader.clone() {
                    let export: wasmparser::Export<'_> = export.expect("export");
                    if matches!(export.kind, ExternalKind::Func | ExternalKind::FuncExact) {
                        exports.push((export.name.to_owned(), export.index));
                    }
                }
            }
            Payload::CodeSectionStart { .. } => {
                code = Some(CodeSection::new());
                continue;
            }
            Payload::CodeSectionEntry(body) => {
                let section: &mut CodeSection = code
                    .as_mut()
                    .expect("code entries follow the code section start");
                if uses_legacy_eh(body) {
                    stubbed.insert(imported_functions + section.len());
                    section.raw(&UNREACHABLE_BODY);
                } else {
                    section.raw(&bytes[body.range()]);
                }
                continue;
            }
            _ => {}
        }
        if let Some(section) = code.take() {
            module.section(&section);
        }
        if let Some((id, range)) = payload.as_section() {
            module.section(&RawSection {
                id,
                data: &bytes[range],
            });
        }
    }
    Projection {
        bytes: module.finish(),
        stubbed_exports: exports
            .into_iter()
            .filter(|(_, index)| stubbed.contains(index))
            .map(|(name, _)| name)
            .collect(),
    }
}

#[must_use]
pub fn drop_first_catch_clause(wat: &str) -> String {
    let start: usize = wat
        .find("(catch ")
        .expect("the lifted module has a try_table catch clause to drop");
    let len: usize = wat[start..].find(')').expect("the catch clause closes") + 1;
    let mut mutated: String = String::with_capacity(wat.len());
    mutated.push_str(&wat[..start]);
    mutated.push_str(wat[start + len..].trim_start_matches(' '));
    mutated
}

pub struct Differential {
    pub tally: Tally,
    pub stubbed_exports: BTreeSet<String>,
}

pub fn differential(original: &[u8], lifted: &[u8]) -> Result<Differential, String> {
    let original: Projection = modern_projection(original);
    let lifted: Projection = modern_projection(lifted);
    if original.stubbed_exports != lifted.stubbed_exports {
        return Err(format!(
            "legacy-EH exports differ: original {:?}, lifted {:?}",
            original.stubbed_exports, lifted.stubbed_exports
        ));
    }
    let engine: Engine = eh_engine();
    let reference: Module = Module::new(&engine, &original.bytes)
        .map_err(|e| format!("the original does not compile under the EH engine: {e:#}"))?;
    let candidate: Module = Module::new(&engine, &lifted.bytes)
        .map_err(|e| format!("the lifted module does not compile under the EH engine: {e:#}"))?;
    let mut tally: Tally = Tally::default();
    for export in reference.exports() {
        let name: &str = export.name();
        if original.stubbed_exports.contains(name) {
            continue;
        }
        let ExternType::Func(ty) = export.ty() else {
            continue;
        };
        let vectors: Vec<Vec<Val>> = argument_vectors(&ty).map_err(|e| format!("{name}: {e}"))?;
        for args in vectors {
            let expected: Outcome =
                run_module(&engine, &reference, name, &args, ty.results().len())
                    .map_err(|e| format!("{name} {args:?}: original: {e:#}"))?;
            let actual: Outcome = run_module(&engine, &candidate, name, &args, ty.results().len())
                .map_err(|e| format!("{name} {args:?}: lifted: {e:#}"))?;
            if expected != actual {
                return Err(format!(
                    "{name} {args:?} diverged: original {expected:?}, lifted {actual:?}"
                ));
            }
            match expected {
                Outcome::Returned(_) => tally.returned += 1,
                Outcome::Thrown { .. } => tally.thrown += 1,
                Outcome::Trapped(_) => tally.trapped += 1,
            }
        }
    }
    Ok(Differential {
        tally,
        stubbed_exports: original.stubbed_exports,
    })
}
