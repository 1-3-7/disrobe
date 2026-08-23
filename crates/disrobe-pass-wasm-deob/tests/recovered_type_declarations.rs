#![allow(clippy::expect_used, clippy::panic)]

use std::error::Error as StdError;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_wasm_deob::{
    BlockId, ConstVal, Error, LiftResult, LiftTarget, OpKind, RecoveredTypesError, SsaBlock,
    SsaFunction, SsaMemArg, SsaTerm, TypeRecoveryRefusal, TypeScriptModuleLift, ValueDef, ValueId,
    c_runtime_prelude, recover_types, recover_types_full, rust_runtime_prelude,
    try_lift_function_from_module, try_lift_functions_from_module, try_lift_typescript_module,
};
use smallvec::smallvec;
use wasmparser::ValType;

const fn assert_public_error_bounds<T: StdError + Send + Sync + 'static>() {}

const _: fn() = assert_public_error_bounds::<TypeRecoveryRefusal>;
const _: fn() = assert_public_error_bounds::<RecoveredTypesError>;

const TRACKED_STRUCT: &str = r#"
(module
  (memory 1 1 shared)
  (func (export "read_record") (param i32) (result f64)
    local.get 0
    i32.load
    drop
    local.get 0
    i32.const 4
    i32.add
    f32.load offset=4
    drop
    local.get 0
    f64.load offset=16))
"#;

fn bytes(wat_source: &str) -> Vec<u8> {
    wat::parse_str(wat_source).expect("tracked fixture parses")
}

fn lift(wat_source: &str, target: LiftTarget) -> String {
    let lifted: LiftResult = try_lift_function_from_module(&bytes(wat_source), 0, target)
        .expect("tracked fixture lifts");
    lifted.pseudo_source
}

fn tool(name: &str) -> Option<PathBuf> {
    let finder: &str = if cfg!(windows) { "where" } else { "which" };
    let output: Output = Command::new(finder).arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(PathBuf::from)
}

fn compile_rust(source: &str, directory: &Path, label: &str) -> Output {
    let source_path: PathBuf = directory.join(format!("{label}.rs"));
    std::fs::write(&source_path, source).expect("write Rust layout grade");
    let rustc: PathBuf = tool("rustc").expect("rustc is required for the recovered-layout grade");
    Command::new(rustc)
        .args([
            "--edition",
            "2024",
            "--crate-type",
            "lib",
            "--emit=metadata",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join(format!("{label}.rmeta")))
        .output()
        .expect("run rustc layout grade")
}

fn compile_c(source: &str, directory: &Path, label: &str) -> Output {
    let source_path: PathBuf = directory.join(format!("{label}.c"));
    std::fs::write(&source_path, source).expect("write C layout grade");
    let compiler: PathBuf = ["clang", "cc", "gcc"]
        .into_iter()
        .find_map(tool)
        .expect("a C compiler is required for the recovered-layout grade");
    Command::new(compiler)
        .args(["-std=c11", "-Werror", "-c"])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join(format!("{label}.o")))
        .output()
        .expect("run C layout grade")
}

#[test]
fn tracked_fixture_emits_exact_sparse_float_aware_declarations() {
    let rust: String = lift(TRACKED_STRUCT, LiftTarget::Rust);
    let c: String = lift(TRACKED_STRUCT, LiftTarget::C);
    let typescript: String = lift(TRACKED_STRUCT, LiftTarget::TypeScript);

    assert!(rust.starts_with(
        "#[repr(C)]\nstruct DisrobeStructFunction0Param0 {\n    field_0: i32,\n    disrobe_padding_8: [u8; 4],\n    field_8: f32,\n    disrobe_padding_16: [u8; 4],\n    field_16: f64,\n}\n\n"
    ));
    assert!(c.starts_with(
        "typedef struct {\n    int32_t field_0;\n    uint8_t disrobe_padding_8[4];\n    float field_8;\n    uint8_t disrobe_padding_16[4];\n    double field_16;\n} DisrobeStructFunction0Param0;\n\n"
    ));
    assert!(typescript.starts_with(
        "export interface DisrobeStructFunction0Param0 {\n    readonly field_0: number;\n    readonly field_8: number;\n    readonly field_16: number;\n}\n\n"
    ));
}

#[test]
fn rust_and_c_compilers_grade_sparse_offsets_and_field_types() {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wasm_type_layout")
            .expect("create layout-grade directory");
    let directory: &Path = scratch.path();
    let rust_lift: String = lift(TRACKED_STRUCT, LiftTarget::Rust);
    let c_lift: String = lift(TRACKED_STRUCT, LiftTarget::C);
    let rust_grade: String = format!(
        "{}\n{rust_lift}\nconst _: () = assert!(std::mem::offset_of!(DisrobeStructFunction0Param0, field_8) == 8);\nconst _: () = assert!(std::mem::offset_of!(DisrobeStructFunction0Param0, field_16) == 16);\nconst _: () = assert!(std::mem::size_of::<DisrobeStructFunction0Param0>() == 24);\nfn type_grade(value: &DisrobeStructFunction0Param0) {{ let _: f32 = value.field_8; let _: f64 = value.field_16; }}\n",
        rust_runtime_prelude()
    );
    let c_grade: String = format!(
        "{}\n{c_lift}\n_Static_assert(offsetof(DisrobeStructFunction0Param0, field_8) == 8, \"field_8 offset\");\n_Static_assert(offsetof(DisrobeStructFunction0Param0, field_16) == 16, \"field_16 offset\");\n_Static_assert(sizeof(DisrobeStructFunction0Param0) == 24, \"aggregate size\");\n_Static_assert(_Generic(((DisrobeStructFunction0Param0*)0)->field_8, float: 1, default: 0), \"field_8 type\");\n",
        c_runtime_prelude()
    );
    let rust_output: Output = compile_rust(&rust_grade, directory, "correct_layout");
    let c_output: Output = compile_c(&c_grade, directory, "correct_layout");
    assert!(
        rust_output.status.success(),
        "rustc rejected the exact recovered layout: {}",
        String::from_utf8_lossy(&rust_output.stderr)
    );
    assert!(
        c_output.status.success(),
        "the C compiler rejected the exact recovered layout: {}",
        String::from_utf8_lossy(&c_output.stderr)
    );

    let wrong_rust: String = rust_grade
        .replace("    disrobe_padding_8: [u8; 4],\n", "")
        .replace("    field_8: f32,\n", "    field_8: f64,\n");
    let wrong_c: String = c_grade
        .replace("    uint8_t disrobe_padding_8[4];\n", "")
        .replace("    float field_8;\n", "    double field_8;\n");
    assert!(
        !compile_rust(&wrong_rust, directory, "wrong_layout")
            .status
            .success(),
        "the Rust grade accepted perturbed offset and type evidence"
    );
    assert!(
        !compile_c(&wrong_c, directory, "wrong_layout")
            .status
            .success(),
        "the C grade accepted perturbed offset and type evidence"
    );
}

#[test]
fn scalar_and_array_declarations_preserve_storage_types_and_zero_origin() {
    let scalar: &str = "(module (memory 1) (func (param i32) (result f32) local.get 0 f32.load))";
    let fixed_array: &str = "(module (memory 1) (func (param i32) (result f32) local.get 0 f32.load local.get 0 f32.load offset=4 f32.add))";
    let indexed_array: &str = "(module (memory 1) (func (param i32 i32) (result f32) local.get 0 local.get 1 i32.const 4 i32.mul i32.add f32.load))";
    let wrong_stride: &str = "(module (memory 1) (func (param i32 i32) (result f32) local.get 0 local.get 1 i32.const 8 i32.mul i32.add f32.load))";
    let two_indices: &str = "(module (memory 1) (func (param i32 i32 i32) (result f32) local.get 0 local.get 1 i32.const 4 i32.mul i32.add local.get 2 i32.const 4 i32.mul i32.add f32.load))";

    assert!(
        lift(scalar, LiftTarget::Rust).starts_with("type DisrobeScalarFunction0Param0 = f32;\n\n")
    );
    assert!(
        lift(scalar, LiftTarget::C).starts_with("typedef float DisrobeScalarFunction0Param0;\n\n")
    );
    assert!(
        lift(fixed_array, LiftTarget::Rust)
            .starts_with("type DisrobeArrayFunction0Param0 = [f32; 2];\n\n")
    );
    assert!(
        lift(indexed_array, LiftTarget::Rust)
            .starts_with("type DisrobeArrayFunction0Param0 = [f32];\n\n")
    );
    assert!(lift(wrong_stride, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0009:"));
    assert!(lift(two_indices, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0003:"));
}

#[test]
fn conflicting_overlapping_high_and_memory64_evidence_names_the_exact_refusal() {
    let conflicting: &str = "(module (memory 1) (func (param i32) (result i32) local.get 0 f32.load drop local.get 0 i32.load))";
    let overlapping: &str = "(module (memory 1) (func (param i32) (result i32) local.get 0 i64.load drop local.get 0 i32.load offset=4))";
    let high_offsets: &str = "(module (memory 1) (func (param i32) (result i32) local.get 0 i32.load offset=2147483648 drop local.get 0 i32.load offset=2147483649))";
    let memory64: &str =
        "(module (memory i64 1) (func (param i64) (result i32) local.get 0 i32.load))";

    assert!(lift(conflicting, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0007:"));
    assert!(lift(overlapping, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0008:"));
    assert!(lift(high_offsets, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0005:"));
    assert!(lift(memory64, LiftTarget::Rust).starts_with("// DR-WASMDEOB-TYPES-0002:"));
}

#[test]
fn function_index_keeps_recovered_declaration_names_collision_free() {
    let module: Vec<u8> = bytes(
        "(module (memory 1) (func (param i32) (result i32) local.get 0 i32.load) (func (param i32) (result i32) local.get 0 i32.load))",
    );
    let lifted: Vec<LiftResult> =
        try_lift_functions_from_module(&module, LiftTarget::Rust).expect("both functions lift");
    assert!(
        lifted[0]
            .pseudo_source
            .contains("DisrobeScalarFunction0Param0")
    );
    assert!(
        lifted[1]
            .pseudo_source
            .contains("DisrobeScalarFunction1Param0")
    );
    assert_ne!(lifted[0].pseudo_source, lifted[1].pseudo_source);
}

#[test]
fn hostile_address_depth_returns_a_typed_refusal() {
    let mut values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Const(ConstVal::I32(0)),
    ];
    let mut address: ValueId = ValueId(0);
    for _ in 0..1_025 {
        let next: ValueId = ValueId(u32::try_from(values.len()).expect("bounded value count"));
        values.push(ValueDef::Op {
            kind: OpKind::I32Add,
            args: smallvec![address, ValueId(1)],
            ty: ValType::I32,
        });
        address = next;
    }
    let load: ValueId = ValueId(u32::try_from(values.len()).expect("bounded value count"));
    values.push(ValueDef::Load {
        addr: address,
        memarg: SsaMemArg {
            align: 2,
            offset: 0,
            memory: 0,
        },
        kind: disrobe_pass_wasm_deob::LoadKind::I32,
        ty: ValType::I32,
    });
    let ssa: SsaFunction = SsaFunction {
        values,
        blocks: vec![SsaBlock {
            id: BlockId(0),
            params: smallvec![],
            instrs: vec![load],
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Return(smallvec![]),
            preds: Vec::new(),
        }],
        entry: BlockId(0),
    };
    assert_eq!(recover_types(&ssa), Err(TypeRecoveryRefusal::AddressDepth));
}

#[test]
fn repeated_address_diamond_resolves_each_ssa_value_once() {
    let mut values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Const(ConstVal::I32(0)),
    ];
    let mut shared: ValueId = ValueId(1);
    for _ in 0..30 {
        let next: ValueId = ValueId(u32::try_from(values.len()).expect("bounded value count"));
        values.push(ValueDef::Op {
            kind: OpKind::I32Add,
            args: smallvec![shared, shared],
            ty: ValType::I32,
        });
        shared = next;
    }
    let address: ValueId = ValueId(u32::try_from(values.len()).expect("bounded value count"));
    values.push(ValueDef::Op {
        kind: OpKind::I32Add,
        args: smallvec![ValueId(0), shared],
        ty: ValType::I32,
    });
    let load: ValueId = ValueId(u32::try_from(values.len()).expect("bounded value count"));
    values.push(ValueDef::Load {
        addr: address,
        memarg: SsaMemArg {
            align: 2,
            offset: 0,
            memory: 0,
        },
        kind: disrobe_pass_wasm_deob::LoadKind::I32,
        ty: ValType::I32,
    });
    let ssa: SsaFunction = SsaFunction {
        values,
        blocks: vec![SsaBlock {
            id: BlockId(0),
            params: smallvec![],
            instrs: vec![load],
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Return(smallvec![]),
            preds: Vec::new(),
        }],
        entry: BlockId(0),
    };
    assert!(recover_types(&ssa).is_ok());
}

#[test]
fn cyclic_address_graph_returns_a_stable_typed_refusal() {
    let values: Vec<ValueDef> = vec![
        ValueDef::Param(BlockId(0), 0),
        ValueDef::Op {
            kind: OpKind::I32Add,
            args: smallvec![ValueId(1), ValueId(2)],
            ty: ValType::I32,
        },
        ValueDef::Const(ConstVal::I32(0)),
        ValueDef::Load {
            addr: ValueId(1),
            memarg: SsaMemArg {
                align: 2,
                offset: 0,
                memory: 0,
            },
            kind: disrobe_pass_wasm_deob::LoadKind::I32,
            ty: ValType::I32,
        },
    ];
    let ssa: SsaFunction = SsaFunction {
        values,
        blocks: vec![SsaBlock {
            id: BlockId(0),
            params: smallvec![],
            instrs: vec![ValueId(3)],
            stores: Vec::new(),
            global_sets: Vec::new(),
            terminator: SsaTerm::Return(smallvec![]),
            preds: Vec::new(),
        }],
        entry: BlockId(0),
    };
    assert_eq!(recover_types(&ssa), Err(TypeRecoveryRefusal::CyclicAddress));
    assert!(matches!(
        recover_types_full(&bytes("(module)"), &ssa),
        Err(RecoveredTypesError::Memory(
            TypeRecoveryRefusal::CyclicAddress
        ))
    ));
}

#[test]
fn public_recovery_errors_display_stable_codes_and_chain_their_sources() {
    let refusal: TypeRecoveryRefusal = TypeRecoveryRefusal::CyclicAddress;
    assert_eq!(
        refusal.to_string(),
        "DR-WASMDEOB-TYPES-0011: the memory address contains a cyclic SSA dependency"
    );
    assert!(refusal.source().is_none());

    let memory: RecoveredTypesError = RecoveredTypesError::Memory(refusal);
    assert_eq!(memory.to_string(), refusal.to_string());
    assert_eq!(
        memory.source().map(ToString::to_string),
        Some(refusal.to_string())
    );

    let gc: RecoveredTypesError =
        RecoveredTypesError::Gc(Error::Parse("tracked GC failure".to_owned()));
    assert_eq!(
        gc.to_string(),
        "DR-WASMDEOB-0001: input is not a valid WebAssembly module: tracked GC failure"
    );
    assert_eq!(
        gc.source().map(ToString::to_string),
        Some(
            "DR-WASMDEOB-0001: input is not a valid WebAssembly module: tracked GC failure"
                .to_owned()
        )
    );
}

#[test]
fn tracked_fixture_emits_the_recovered_interface_through_the_module_api() {
    let lifted: TypeScriptModuleLift =
        try_lift_typescript_module(&bytes(TRACKED_STRUCT)).expect("tracked fixture module lifts");
    assert!(lifted.source.starts_with(
        "import { writeSync } from \"node:fs\";\n\nexport interface DisrobeStructFunction0Param0 {\n    readonly field_0: number;\n    readonly field_8: number;\n    readonly field_16: number;\n}\n\n"
    ));
}

#[test]
fn an_unsupported_ssa_operator_names_the_declaration_refusal_without_blocking_the_lift() {
    let mixed: &str = "(module (memory 1 1 shared) (func (param i32) (result i32) atomic.fence local.get 0 i32.load))";
    let lifted: String = lift(mixed, LiftTarget::Rust);
    assert!(lifted.starts_with("// DR-WASMDEOB-TYPES-0001:"));
    assert!(lifted.contains("wasm_load_i32(p0, 0)"));
}
