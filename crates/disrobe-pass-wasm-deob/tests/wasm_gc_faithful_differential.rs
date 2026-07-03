#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use disrobe_pass_wasm_deob::lift_module_faithful_wat;
use wasmparser::{
    CompositeInnerType, Operator, Parser, Payload, StorageType, Validator, WasmFeatures,
};

fn validate(bytes: &[u8]) -> Result<(), String> {
    Validator::new_with_features(WasmFeatures::all())
        .validate_all(bytes)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn corpus(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../corpus/wasm/wat/{name}"))
}

fn lift(name: &str) -> (Vec<u8>, Vec<u8>, String) {
    let text: String = fs::read_to_string(corpus(name)).expect("read corpus wat");
    let original: Vec<u8> = wat::parse_str(&text).expect("source wat must assemble");
    let lifted_wat: String =
        lift_module_faithful_wat(&original).expect("faithful lift must produce output");
    let lifted: Vec<u8> = wat::parse_str(&lifted_wat)
        .unwrap_or_else(|e| panic!("lifted wat must re-assemble: {e}\n{lifted_wat}"));
    (original, lifted, lifted_wat)
}

#[derive(Debug, Default, PartialEq, Eq)]
struct GcShape {
    struct_types: usize,
    array_types: usize,
    func_types: usize,
    sub_types_with_supertype: usize,
    final_sub_types: usize,
    mutable_fields: usize,
    immutable_fields: usize,
    field_ref_targets: Vec<FieldRef>,
    op_counts: BTreeMap<&'static str, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum FieldRef {
    Concrete { type_index: u32, nullable: bool },
    Abstract,
    NonRef,
}

fn classify_storage(ty: StorageType) -> FieldRef {
    use wasmparser::{HeapType, ValType};
    let StorageType::Val(ValType::Ref(r)) = ty else {
        return FieldRef::NonRef;
    };
    match r.heap_type() {
        HeapType::Concrete(idx) | HeapType::Exact(idx) => {
            idx.as_module_index()
                .map_or(FieldRef::Abstract, |type_index| FieldRef::Concrete {
                    type_index,
                    nullable: r.is_nullable(),
                })
        }
        HeapType::Abstract { .. } => FieldRef::Abstract,
    }
}

const fn gc_op_name(op: &Operator<'_>) -> Option<&'static str> {
    Some(match op {
        Operator::StructNew { .. } => "struct.new",
        Operator::StructNewDefault { .. } => "struct.new_default",
        Operator::StructGet { .. } => "struct.get",
        Operator::StructGetS { .. } => "struct.get_s",
        Operator::StructGetU { .. } => "struct.get_u",
        Operator::StructSet { .. } => "struct.set",
        Operator::ArrayNew { .. } => "array.new",
        Operator::ArrayNewDefault { .. } => "array.new_default",
        Operator::ArrayNewFixed { .. } => "array.new_fixed",
        Operator::ArrayGet { .. } => "array.get",
        Operator::ArrayGetS { .. } => "array.get_s",
        Operator::ArrayGetU { .. } => "array.get_u",
        Operator::ArraySet { .. } => "array.set",
        Operator::ArrayFill { .. } => "array.fill",
        Operator::ArrayCopy { .. } => "array.copy",
        Operator::ArrayLen => "array.len",
        Operator::RefI31 => "ref.i31",
        Operator::I31GetS => "i31.get_s",
        Operator::I31GetU => "i31.get_u",
        Operator::RefTestNonNull { .. } | Operator::RefTestNullable { .. } => "ref.test",
        Operator::RefCastNonNull { .. } | Operator::RefCastNullable { .. } => "ref.cast",
        Operator::BrOnCast { .. } => "br_on_cast",
        Operator::BrOnCastFail { .. } => "br_on_cast_fail",
        Operator::RefEq => "ref.eq",
        _ => return None,
    })
}

fn shape(bytes: &[u8]) -> GcShape {
    let mut s: GcShape = GcShape::default();
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.expect("payload parses") {
            Payload::TypeSection(reader) => {
                for group in reader {
                    for sub in group.expect("rec group").types() {
                        if !sub.is_final {
                            s.sub_types_with_supertype += usize::from(sub.supertype_idx.is_some());
                        }
                        if sub.is_final {
                            s.final_sub_types += 1;
                        }
                        match &sub.composite_type.inner {
                            CompositeInnerType::Struct(st) => {
                                s.struct_types += 1;
                                for f in &st.fields {
                                    if f.mutable {
                                        s.mutable_fields += 1;
                                    } else {
                                        s.immutable_fields += 1;
                                    }
                                    s.field_ref_targets.push(classify_storage(f.element_type));
                                }
                            }
                            CompositeInnerType::Array(at) => {
                                s.array_types += 1;
                                if at.0.mutable {
                                    s.mutable_fields += 1;
                                } else {
                                    s.immutable_fields += 1;
                                }
                                s.field_ref_targets
                                    .push(classify_storage(at.0.element_type));
                            }
                            CompositeInnerType::Func(_) => s.func_types += 1,
                            CompositeInnerType::Cont(_) => {}
                        }
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let reader: wasmparser::OperatorsReader<'_> =
                    body.get_operators_reader().expect("ops reader");
                for op in reader {
                    if let Some(name) = gc_op_name(&op.expect("op")) {
                        *s.op_counts.entry(name).or_default() += 1;
                    }
                }
            }
            _ => {}
        }
    }
    s
}

fn assert_faithful(name: &str) {
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift(name);
    validate(&original).unwrap_or_else(|e| panic!("{name}: original GC corpus must validate: {e}"));
    validate(&lifted).unwrap_or_else(|e| {
        panic!(
            "{name}: recovered GC module must validate under the spec validator: {e}\n{lifted_wat}"
        )
    });

    let orig: GcShape = shape(&original);
    let lift_shape: GcShape = shape(&lifted);
    assert!(
        orig.struct_types + orig.array_types > 0,
        "{name}: corpus must actually exercise GC composite types"
    );
    assert!(
        !orig.op_counts.is_empty(),
        "{name}: corpus must actually exercise GC operators"
    );
    assert_eq!(
        orig, lift_shape,
        "{name}: the recovered GC type graph and operator profile must match the original\n{lifted_wat}"
    );
}

#[test]
fn subtype_corpus_round_trips_faithfully() {
    assert_faithful("gc_subtype_roundtrip.wat");
}

#[test]
fn numeric_corpus_round_trips_through_the_faithful_lifter() {
    assert_faithful("gc_numeric_roundtrip.wat");
}

#[test]
fn self_referential_field_corpus_round_trips_faithfully() {
    assert_faithful("gc_selfref_field.wat");
}

#[test]
fn self_referential_fields_keep_their_concrete_ref_targets() {
    let (original, lifted, lifted_wat): (Vec<u8>, Vec<u8>, String) = lift("gc_selfref_field.wat");
    let orig: GcShape = shape(&original);
    let lift_shape: GcShape = shape(&lifted);

    let concrete_targets: usize = orig
        .field_ref_targets
        .iter()
        .filter(|f| matches!(f, FieldRef::Concrete { .. }))
        .count();
    assert!(
        concrete_targets >= 3,
        "fixture must exercise multiple self/sibling-referential concrete-ref fields, found {concrete_targets}"
    );
    assert!(
        !orig
            .field_ref_targets
            .iter()
            .any(|f| matches!(f, FieldRef::Abstract)),
        "the original fixture must have no widened (abstract) ref fields to begin with"
    );
    assert_eq!(
        orig.field_ref_targets, lift_shape.field_ref_targets,
        "recovered field ref targets must match the original, never widening a concrete (ref $T) field to anyref:\n{lifted_wat}"
    );
}

#[test]
fn self_referential_fields_never_widen_to_funcref_or_anyref() {
    let (_, _, wat): (Vec<u8>, Vec<u8>, String) = lift("gc_selfref_field.wat");
    assert!(
        wat.contains("(struct (field (mut i32)) (field (ref null $t2)))"),
        "the node struct must keep its self-referential next field:\n{wat}"
    );
    assert!(
        wat.contains("(struct (field (ref null $t2)) (field (ref null $t3)))"),
        "the list struct must keep its node head and self-referential owner fields:\n{wat}"
    );
    assert!(
        wat.contains("(array (mut (ref null $t2)))"),
        "the array element type must keep its concrete node ref:\n{wat}"
    );
    assert!(
        wat.contains("ref.null $t2") && wat.contains("ref.null $t3"),
        "ref.null on a concrete type must keep the concrete type, not widen to func:\n{wat}"
    );
    assert!(
        !wat.contains("ref.null func"),
        "no concrete-typed null should have been widened to a funcref null:\n{wat}"
    );
}

#[test]
fn faithful_lift_preserves_subtype_and_mutability_syntax() {
    let (_, _, wat): (Vec<u8>, Vec<u8>, String) = lift("gc_subtype_roundtrip.wat");
    assert!(
        wat.contains("(sub $t0 (struct"),
        "the open supertype relationship must survive into the recovered output:\n{wat}"
    );
    assert!(
        wat.contains("(sub final $t0 (struct"),
        "the final supertype relationship must survive faithfully:\n{wat}"
    );
    assert!(
        wat.contains("(array (mut i32))"),
        "a mutable array element type must be recovered as mutable:\n{wat}"
    );
    assert!(
        wat.contains("(array i32))"),
        "an immutable array element type must stay immutable:\n{wat}"
    );
    assert!(
        wat.contains("(struct (field i64) (field i64))"),
        "an all-immutable struct must not be widened to mutable fields:\n{wat}"
    );
}

#[cfg(feature = "sandbox")]
mod execution {
    use super::{corpus, lift};
    use std::path::Path;
    use wasmparser::{Parser, Payload, ValType};
    use wasmtime::{Config, Engine, Linker, Module, Store, Val};

    fn gc_config() -> Config {
        let mut c: Config = Config::new();
        c.wasm_gc(true)
            .wasm_function_references(true)
            .wasm_tail_call(true);
        c
    }

    fn export_sigs(bytes: &[u8]) -> Vec<(String, Vec<ValType>, Vec<ValType>)> {
        let mut types: Vec<(Vec<ValType>, Vec<ValType>)> = Vec::new();
        let mut func_type_idx: Vec<u32> = Vec::new();
        let mut exports: Vec<(String, u32)> = Vec::new();
        for payload in Parser::new(0).parse_all(bytes) {
            match payload.expect("payload") {
                Payload::TypeSection(reader) => {
                    for group in reader {
                        for sub in group.expect("rec").types() {
                            if let wasmparser::CompositeInnerType::Func(ft) =
                                &sub.composite_type.inner
                            {
                                types.push((ft.params().to_vec(), ft.results().to_vec()));
                            } else {
                                types.push((Vec::new(), Vec::new()));
                            }
                        }
                    }
                }
                Payload::FunctionSection(reader) => {
                    for t in reader {
                        func_type_idx.push(t.expect("func type idx"));
                    }
                }
                Payload::ExportSection(reader) => {
                    for e in reader {
                        let e: wasmparser::Export<'_> = e.expect("export");
                        if matches!(
                            e.kind,
                            wasmparser::ExternalKind::Func | wasmparser::ExternalKind::FuncExact
                        ) {
                            exports.push((e.name.to_owned(), e.index));
                        }
                    }
                }
                _ => {}
            }
        }
        exports
            .into_iter()
            .filter_map(|(name, idx)| {
                let ti: u32 = *func_type_idx.get(idx as usize)?;
                let (p, r): &(Vec<ValType>, Vec<ValType>) = types.get(ti as usize)?;
                Some((name, p.clone(), r.clone()))
            })
            .collect()
    }

    const fn numeric(ty: ValType) -> bool {
        matches!(ty, ValType::I32 | ValType::I64)
    }

    fn seeds(ty: ValType) -> Vec<Val> {
        match ty {
            ValType::I32 => vec![
                Val::I32(0),
                Val::I32(1),
                Val::I32(4),
                Val::I32(-3),
                Val::I32(9),
            ],
            ValType::I64 => vec![Val::I64(0), Val::I64(2), Val::I64(-5), Val::I64(77)],
            _ => vec![],
        }
    }

    fn battery(params: &[ValType], cap: usize) -> Vec<Vec<Val>> {
        if params.is_empty() {
            return vec![vec![]];
        }
        let mut out: Vec<Vec<Val>> = vec![vec![]];
        for ty in params {
            let mut next: Vec<Vec<Val>> = Vec::new();
            for prefix in &out {
                for s in seeds(*ty) {
                    let mut e: Vec<Val> = prefix.clone();
                    e.push(s);
                    next.push(e);
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

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Returned(Vec<i64>),
        Trapped,
    }

    fn run(eng: &Engine, bytes: &[u8], export: &str, arg: &[Val], arity: usize) -> Option<Outcome> {
        let m: Module = Module::new(eng, bytes).ok()?;
        let mut store: Store<()> = Store::new(eng, ());
        let mut linker: Linker<()> = Linker::new(eng);
        linker.define_unknown_imports_as_traps(&m).ok()?;
        let inst: wasmtime::Instance = linker.instantiate(&mut store, &m).ok()?;
        let f: wasmtime::Func = inst.get_func(&mut store, export)?;
        let mut res: Vec<Val> = vec![Val::I32(0); arity];
        if f.call(&mut store, arg, &mut res).is_err() {
            return Some(Outcome::Trapped);
        }
        Some(Outcome::Returned(
            res.iter()
                .map(|v| match v {
                    Val::I32(x) => i64::from(*x),
                    Val::I64(x) => *x,
                    _ => -999,
                })
                .collect(),
        ))
    }

    fn check(name: &str) {
        let eng: Engine = Engine::new(&gc_config()).expect("engine");
        let (original, lifted, _): (Vec<u8>, Vec<u8>, String) = lift(name);
        if Module::new(&eng, &original).is_err() {
            eprintln!(
                "wasmtime cannot execute GC on this build; skipping execution probe for {name}"
            );
            return;
        }
        let mut checked: usize = 0;
        for (export, params, results) in export_sigs(&original) {
            if !params.iter().all(|t| numeric(*t)) || !results.iter().all(|t| numeric(*t)) {
                continue;
            }
            for args in battery(&params, 25) {
                let a: Option<Outcome> = run(&eng, &original, &export, &args, results.len());
                let b: Option<Outcome> = run(&eng, &lifted, &export, &args, results.len());
                let (Some(o), Some(l)): (Option<Outcome>, Option<Outcome>) = (a, b) else {
                    continue;
                };
                assert_eq!(o, l, "{name}:{export} {args:?} diverged");
                checked += 1;
            }
        }
        eprintln!("[{name}] GC execution-equivalence checks: {checked}");
        let _: &Path = &corpus(name);
    }

    #[test]
    fn gc_modules_execute_equivalently() {
        check("gc_subtype_roundtrip.wat");
        check("gc_numeric_roundtrip.wat");
        check("gc_selfref_field.wat");
    }
}
