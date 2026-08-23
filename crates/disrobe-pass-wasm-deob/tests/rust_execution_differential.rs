#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#[cfg(feature = "sandbox")]
use std::fmt::Write as _;
#[cfg(feature = "sandbox")]
use std::fs;
#[cfg(feature = "sandbox")]
use std::path::{Path, PathBuf};
#[cfg(feature = "sandbox")]
use std::process::Command;

#[cfg(feature = "sandbox")]
#[path = "common/div_cases.rs"]
mod div_cases;

#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, ModuleSignatures, extract_signatures,
    lift_function_body, rust_runtime_prelude,
};
#[cfg(feature = "sandbox")]
use div_cases::{DIV_REM_MODULE, I32Case, I64Case, i32_cases, i64_cases};
#[cfg(feature = "sandbox")]
use wasmparser::{FunctionBody, Operator, Parser, Payload, ValType};
#[cfg(feature = "sandbox")]
use wasmtime::{Config, Engine, Linker, Module, Store, Val};

#[cfg(feature = "sandbox")]
const FUEL_BUDGET: u64 = 4_000_000;

#[cfg(feature = "sandbox")]
fn corpus_dirs() -> Vec<PathBuf> {
    let root: &Path = Path::new(env!("CARGO_MANIFEST_DIR"));
    vec![
        root.join("../../corpus/src/wasm/sources"),
        root.join("../../corpus/src/wasm/edge_cases"),
        root.join("../../corpus/wasm/wat"),
        root.join("../../corpus/wasm/plugins"),
    ]
}

#[cfg(feature = "sandbox")]
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

#[cfg(feature = "sandbox")]
fn defined_bodies(bytes: &[u8]) -> Vec<FunctionBody<'_>> {
    let mut out: Vec<FunctionBody<'_>> = Vec::new();
    for payload in Parser::new(0).parse_all(bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            out.push(body);
        }
    }
    out
}

#[cfg(feature = "sandbox")]
fn callees(sigs: &ModuleSignatures) -> CalleeNames {
    CalleeNames::with_signatures(
        sigs.callee_names(),
        sigs.call_signatures(),
        sigs.call_signatures(),
    )
}

#[cfg(feature = "sandbox")]
const fn numeric(ty: ValType) -> bool {
    matches!(
        ty,
        ValType::I32 | ValType::I64 | ValType::F32 | ValType::F64
    )
}

#[cfg(feature = "sandbox")]
fn signature_is_numeric(sig: &FunctionSig) -> bool {
    sig.params.iter().copied().all(numeric)
        && sig.results.len() == 1
        && sig.results.iter().copied().all(numeric)
}

#[cfg(feature = "sandbox")]
fn body_is_self_contained_and_total(body: &FunctionBody<'_>) -> bool {
    let Ok(reader): Result<wasmparser::OperatorsReader<'_>, _> = body.get_operators_reader() else {
        return false;
    };
    for op in reader {
        let Ok(op): Result<Operator<'_>, _> = op else {
            return false;
        };
        match op {
            Operator::Call { .. }
            | Operator::CallIndirect { .. }
            | Operator::ReturnCall { .. }
            | Operator::ReturnCallIndirect { .. }
            | Operator::CallRef { .. }
            | Operator::ReturnCallRef { .. }
            | Operator::GlobalGet { .. }
            | Operator::GlobalSet { .. }
            | Operator::I32Load { .. }
            | Operator::I64Load { .. }
            | Operator::F32Load { .. }
            | Operator::F64Load { .. }
            | Operator::I32Load8U { .. }
            | Operator::I32Load8S { .. }
            | Operator::I32Load16U { .. }
            | Operator::I32Load16S { .. }
            | Operator::I64Load8U { .. }
            | Operator::I64Load8S { .. }
            | Operator::I64Load16U { .. }
            | Operator::I64Load16S { .. }
            | Operator::I64Load32U { .. }
            | Operator::I64Load32S { .. }
            | Operator::I32Store { .. }
            | Operator::I64Store { .. }
            | Operator::F32Store { .. }
            | Operator::F64Store { .. }
            | Operator::I32Store8 { .. }
            | Operator::I32Store16 { .. }
            | Operator::I64Store8 { .. }
            | Operator::I64Store16 { .. }
            | Operator::I64Store32 { .. }
            | Operator::MemorySize { .. }
            | Operator::MemoryGrow { .. }
            | Operator::MemoryCopy { .. }
            | Operator::MemoryFill { .. }
            | Operator::MemoryInit { .. }
            | Operator::I32DivS
            | Operator::I32DivU
            | Operator::I32RemS
            | Operator::I32RemU
            | Operator::I64DivS
            | Operator::I64DivU
            | Operator::I64RemS
            | Operator::I64RemU
            | Operator::I32TruncF32S
            | Operator::I32TruncF32U
            | Operator::I32TruncF64S
            | Operator::I32TruncF64U
            | Operator::I64TruncF32S
            | Operator::I64TruncF32U
            | Operator::I64TruncF64S
            | Operator::I64TruncF64U
            | Operator::Unreachable => return false,
            other if other.is_simd() || other.is_atomic() || other.is_reference_or_gc() => {
                return false;
            }
            _ => {}
        }
    }
    true
}

#[cfg(feature = "sandbox")]
trait OpClass {
    fn is_simd(&self) -> bool;
    fn is_atomic(&self) -> bool;
    fn is_reference_or_gc(&self) -> bool;
}

#[cfg(feature = "sandbox")]
impl OpClass for Operator<'_> {
    fn is_simd(&self) -> bool {
        let mnemonic: String = format!("{self:?}");
        mnemonic.contains("x16")
            || mnemonic.contains("x8")
            || mnemonic.contains("x4")
            || mnemonic.contains("x2")
            || mnemonic.starts_with("V128")
    }
    fn is_atomic(&self) -> bool {
        format!("{self:?}").contains("Atomic")
    }
    fn is_reference_or_gc(&self) -> bool {
        let mnemonic: String = format!("{self:?}");
        mnemonic.starts_with("Ref")
            || mnemonic.starts_with("Struct")
            || mnemonic.starts_with("Array")
            || mnemonic.starts_with("I31")
            || mnemonic.starts_with("Table")
            || mnemonic.starts_with("Elem")
            || mnemonic.starts_with("CallRef")
            || mnemonic.starts_with("BrOn")
            || mnemonic.starts_with("Throw")
            || mnemonic.starts_with("Try")
            || mnemonic.starts_with("Catch")
            || mnemonic.starts_with("Rethrow")
            || mnemonic.starts_with("Delegate")
            || mnemonic.starts_with("Cont")
            || mnemonic.starts_with("Resume")
            || mnemonic.starts_with("Suspend")
            || mnemonic.starts_with("Switch")
    }
}

#[cfg(feature = "sandbox")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CmpVal {
    I32(i32),
    I64(i64),
    F32Bits(u32),
    F64Bits(u64),
}

#[cfg(feature = "sandbox")]
const fn canonical_f32(bits: u32) -> u32 {
    if f32::from_bits(bits).is_nan() {
        0x7fc0_0000
    } else {
        bits
    }
}

#[cfg(feature = "sandbox")]
const fn canonical_f64(bits: u64) -> u64 {
    if f64::from_bits(bits).is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        bits
    }
}

#[cfg(feature = "sandbox")]
const fn from_val(val: &Val) -> Option<CmpVal> {
    match val {
        Val::I32(v) => Some(CmpVal::I32(*v)),
        Val::I64(v) => Some(CmpVal::I64(*v)),
        Val::F32(bits) => Some(CmpVal::F32Bits(canonical_f32(*bits))),
        Val::F64(bits) => Some(CmpVal::F64Bits(canonical_f64(*bits))),
        _ => None,
    }
}

#[cfg(feature = "sandbox")]
fn seed_values(ty: ValType) -> Vec<Val> {
    match ty {
        ValType::I32 => [0_i32, 1, -1, 2, 7, -8, 100, i32::MIN, i32::MAX]
            .iter()
            .map(|v| Val::I32(*v))
            .collect(),
        ValType::I64 => [0_i64, 1, -1, 3, 65_536, i64::MIN, i64::MAX]
            .iter()
            .map(|v| Val::I64(*v))
            .collect(),
        ValType::F32 => [0.0_f32, 1.0, -1.0, 3.5, -2.25]
            .iter()
            .map(|v| Val::F32(v.to_bits()))
            .collect(),
        ValType::F64 => [0.0_f64, 1.0, -1.0, 2.5, -0.5]
            .iter()
            .map(|v| Val::F64(v.to_bits()))
            .collect(),
        ValType::Ref(_) | ValType::V128 => Vec::new(),
    }
}

#[cfg(feature = "sandbox")]
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

#[cfg(feature = "sandbox")]
fn result_print_expr(ty: ValType, call: &str) -> String {
    match ty {
        ValType::I32 => format!("println!(\"I32 {{}}\", ({call}))"),
        ValType::I64 => format!("println!(\"I64 {{}}\", ({call}))"),
        ValType::F32 => format!("println!(\"F32 {{}}\", ({call}).to_bits())"),
        ValType::F64 => format!("println!(\"F64 {{}}\", ({call}).to_bits())"),
        ValType::Ref(_) | ValType::V128 => "()".to_owned(),
    }
}

#[cfg(feature = "sandbox")]
fn rich_config() -> Config {
    let mut config: Config = Config::new();
    config.consume_fuel(true);
    config
}

#[cfg(feature = "sandbox")]
struct Sandbox {
    store: Store<()>,
    instance: wasmtime::Instance,
}

#[cfg(feature = "sandbox")]
fn instantiate(eng: &Engine, bytes: &[u8]) -> Option<Sandbox> {
    let module: Module = Module::new(eng, bytes).ok()?;
    let mut store: Store<()> = Store::new(eng, ());
    store.set_fuel(FUEL_BUDGET).ok()?;
    let mut linker: Linker<()> = Linker::new(eng);
    linker.define_unknown_imports_as_traps(&module).ok()?;
    let instance: wasmtime::Instance = linker.instantiate(&mut store, &module).ok()?;
    Some(Sandbox { store, instance })
}

#[cfg(feature = "sandbox")]
fn wasm_outcome(
    sandbox: &mut Sandbox,
    export: &str,
    args: &[Val],
    result_ty: ValType,
) -> Option<CmpVal> {
    let func: wasmtime::Func = sandbox.instance.get_func(&mut sandbox.store, export)?;
    let mut results: Vec<Val> = vec![Val::I32(0)];
    if func.call(&mut sandbox.store, args, &mut results).is_err() {
        let _ = sandbox.store.set_fuel(FUEL_BUDGET);
        return None;
    }
    let _ = result_ty;
    from_val(results.first()?)
}

#[cfg(feature = "sandbox")]
fn tool_on_path(tool: &str) -> Option<PathBuf> {
    let probe: &str = if cfg!(windows) { "where" } else { "which" };
    let output: std::process::Output = Command::new(probe).arg(tool).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).to_string();
    let first: &str = stdout.lines().next()?.trim();
    (!first.is_empty()).then(|| PathBuf::from(first))
}

#[cfg(feature = "sandbox")]
struct Target {
    export: String,
    rust_name: String,
    params: Vec<ValType>,
    result_ty: ValType,
    battery: Vec<Vec<Val>>,
}

#[cfg(feature = "sandbox")]
#[test]
fn recovered_rust_executes_identically_to_original_under_wasmtime() {
    let Some(rustc): Option<PathBuf> = tool_on_path("rustc") else {
        eprintln!("SKIP: rustc not on PATH for the rust-execution differential");
        return;
    };

    let eng: Engine = Engine::new(&rich_config()).expect("wasmtime engine");
    let mut program: String = rust_runtime_prelude().to_owned();
    let mut targets: Vec<(Vec<u8>, Target)> = Vec::new();
    let mut emitted_names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut idiomatic_functions: usize = 0;
    let mut scaffolded_functions: usize = 0;
    let mut control_functions: usize = 0;
    let mut total_labeled_loops: usize = 0;
    let mut nested_loop_functions: usize = 0;

    for wat_path in wat_files() {
        let Ok(text): Result<String, _> = fs::read_to_string(&wat_path) else {
            continue;
        };
        let Ok(bytes): Result<Vec<u8>, _> = wat::parse_str(&text) else {
            continue;
        };
        let Ok(sigs): Result<ModuleSignatures, _> = extract_signatures(&bytes) else {
            continue;
        };
        let defined: Vec<FunctionSig> = sigs.defined().to_vec();
        let calls: CalleeNames = callees(&sigs);

        for (i, body) in defined_bodies(&bytes).iter().enumerate() {
            let Some(sig): Option<&FunctionSig> = defined.get(i) else {
                continue;
            };
            if !sig.exported || !signature_is_numeric(sig) {
                continue;
            }
            if !body_is_self_contained_and_total(body) {
                continue;
            }
            let lifted: LiftResult = lift_function_body(body, sig, &calls, LiftTarget::Rust);
            if !lifted.coverage.fully_recovered() {
                continue;
            }
            let has_control: bool = lifted.pseudo_source.contains("if ")
                || lifted.pseudo_source.contains("loop {")
                || lifted.pseudo_source.contains("match ");
            if has_control {
                control_functions += 1;
                let labeled_loops: usize = lifted.pseudo_source.matches(": loop {").count();
                total_labeled_loops += labeled_loops;
                if labeled_loops >= 2 {
                    nested_loop_functions += 1;
                }
                if labeled_loops == 0 {
                    idiomatic_functions += 1;
                } else {
                    scaffolded_functions += 1;
                }
            }

            let rust_name: String = sig.name.clone();
            if !emitted_names.insert(rust_name.clone()) {
                continue;
            }
            program.push('\n');
            program.push_str(&lifted.pseudo_source);
            targets.push((
                bytes.clone(),
                Target {
                    export: sig.name.clone(),
                    rust_name,
                    params: sig.params.clone(),
                    result_ty: sig.results[0],
                    battery: argument_battery(&sig.params, 48),
                },
            ));
        }
    }

    assert!(
        targets.len() >= 5,
        "expected a non-trivial executable target set, got {}",
        targets.len()
    );

    program.push_str("\nfn main() {\n");
    program.push_str("    let args: Vec<String> = std::env::args().collect();\n");
    program.push_str("    let which: &str = args.get(1).map(|s| s.as_str()).unwrap_or(\"\");\n");
    program.push_str("    let raw: Vec<String> = args.iter().skip(2).cloned().collect();\n");
    program.push_str("    match which {\n");
    for (_bytes, target) in &targets {
        let mut call_args: Vec<String> = Vec::with_capacity(target.params.len());
        for (idx, ty) in target.params.iter().enumerate() {
            let parse: &str = match ty {
                ValType::I64 => "parse::<i64>().unwrap()",
                ValType::F32 => "parse::<u32>().map(f32::from_bits).unwrap()",
                ValType::F64 => "parse::<u64>().map(f64::from_bits).unwrap()",
                ValType::I32 | ValType::Ref(_) | ValType::V128 => "parse::<i32>().unwrap()",
            };
            call_args.push(format!("raw[{idx}].{parse}"));
        }
        let call: String = format!("{}({})", target.rust_name, call_args.join(", "));
        let print: String = result_print_expr(target.result_ty, &call);
        let _ = writeln!(program, "        \"{}\" => {{ {print}; }}", target.export);
    }
    program.push_str("        _ => { eprintln!(\"unknown fn\"); }\n");
    program.push_str("    }\n}\n");

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wasm_exec_diff").expect("mkdir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let rs: PathBuf = dir.join("recovered.rs");
    fs::write(&rs, &program).expect("write rs");
    let bin: PathBuf = dir.join(if cfg!(windows) {
        "recovered.exe"
    } else {
        "recovered"
    });
    let compile: std::process::Output = Command::new(&rustc)
        .args(["--edition", "2021", "-O", "-o"])
        .arg(&bin)
        .arg(&rs)
        .output()
        .expect("spawn rustc");
    assert!(
        compile.status.success(),
        "rustc rejected recovered idiomatic Rust (exit {:?})\n{}",
        compile.status.code(),
        String::from_utf8_lossy(&compile.stderr)
    );

    let mut checked: usize = 0;
    let mut equivalent: usize = 0;
    let mut diverged: Vec<String> = Vec::new();

    for (bytes, target) in &targets {
        let Some(mut sandbox): Option<Sandbox> = instantiate(&eng, bytes) else {
            continue;
        };
        for args in &target.battery {
            let Some(want): Option<CmpVal> =
                wasm_outcome(&mut sandbox, &target.export, args, target.result_ty)
            else {
                continue;
            };
            checked += 1;
            let arg_strs: Vec<String> = args.iter().map(val_to_rust_arg_string).collect();
            let run: std::process::Output = Command::new(&bin)
                .arg(&target.export)
                .args(&arg_strs)
                .output()
                .expect("run recovered binary");
            let stdout: String = String::from_utf8_lossy(&run.stdout).trim().to_owned();
            let got: Option<CmpVal> = parse_cmp(&stdout);
            if got == Some(want) {
                equivalent += 1;
            } else {
                diverged.push(format!(
                    "{}({args:?}): wasmtime={want:?} recovered-rust={got:?} (raw {stdout:?})",
                    target.export
                ));
            }
        }
    }

    eprintln!("recovered-RUST execution differential vs wasmtime:");
    eprintln!(
        "  executable targets compiled into one binary: {}",
        targets.len()
    );
    eprintln!("  control-flow functions among targets: {control_functions}");
    eprintln!(
        "  of those, idiomatic (no loop-scaffold): {idiomatic_functions}, scaffolded: {scaffolded_functions}"
    );
    eprintln!(
        "  labeled loops emitted across control fns: {total_labeled_loops} (functions still nesting 2+ labeled loops: {nested_loop_functions})"
    );
    eprintln!("  battery invocations checked: {checked}");
    eprintln!("  EXECUTION-EQUIVALENT recovered-rust == original-wasm: {equivalent}/{checked}");
    if !diverged.is_empty() {
        eprintln!("  DIVERGENCES:");
        for line in &diverged {
            eprintln!("    {line}");
        }
    }

    assert!(
        checked >= 200,
        "expected a real battery (ratchet floor), only checked {checked}"
    );
    assert_eq!(
        equivalent,
        checked,
        "every recovered idiomatic Rust function MUST execute identically to the original wasm \
         under wasmtime; divergences:\n{}",
        diverged.join("\n")
    );
    assert!(
        idiomatic_functions >= 6,
        "the relooper must produce idiomatic (scaffold-free) control flow for a real share of \
         functions; ratchet this up as more CFG shapes are relooped; \
         idiomatic={idiomatic_functions} scaffolded={scaffolded_functions}"
    );
    assert!(
        nested_loop_functions <= 1,
        "the canonical block+loop counted idiom must collapse to a single labeled loop, so only \
         genuine multi-exit cascades (br_table) may keep nested labeled loops; \
         nested_loop_functions={nested_loop_functions}"
    );
    assert!(
        total_labeled_loops <= 8,
        "labeled-loop scaffolding must not regress above the collapsed floor; \
         total_labeled_loops={total_labeled_loops}"
    );
}

#[cfg(feature = "sandbox")]
fn lifted_div_rem_program(bytes: &[u8], sigs: &ModuleSignatures, driver: &str) -> String {
    let defined: Vec<FunctionSig> = sigs.defined().to_vec();
    let calls: CalleeNames = callees(sigs);
    let mut program: String = rust_runtime_prelude().to_owned();
    for (i, body) in defined_bodies(bytes).iter().enumerate() {
        let sig: &FunctionSig = &defined[i];
        let lifted: LiftResult = lift_function_body(body, sig, &calls, LiftTarget::Rust);
        assert!(
            lifted.coverage.fully_recovered(),
            "{} did not fully lift: {:?}",
            sig.name,
            lifted.coverage.untranslated
        );
        program.push('\n');
        program.push_str(&lifted.pseudo_source);
    }
    program.push_str(driver);
    program
}

#[cfg(feature = "sandbox")]
#[test]
fn divide_and_remainder_helpers_execute_identically_on_non_trapping_inputs() {
    let Some(rustc): Option<PathBuf> = tool_on_path("rustc") else {
        eprintln!("SKIP: rustc not on PATH for the divide/remainder differential");
        return;
    };
    let bytes: Vec<u8> = wat::parse_str(DIV_REM_MODULE).expect("assemble the div/rem module");
    let sigs: ModuleSignatures = extract_signatures(&bytes).expect("signatures");

    let i32s: Vec<I32Case> = i32_cases();
    let i64s: Vec<I64Case> = i64_cases();
    let mut expected: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut driver: String = String::from("\nfn main() {\n");
    for case in &i32s {
        for (op, want) in [
            ("i32_div_s", case.div_s),
            ("i32_div_u", case.div_u),
            ("i32_rem_s", case.rem_s),
            ("i32_rem_u", case.rem_u),
        ] {
            let key: String = format!("{op} {} {}", case.a, case.b);
            expected.insert(key.clone(), want.to_string());
            let _: Result<(), std::fmt::Error> = writeln!(
                driver,
                "    println!(\"{key} {{}}\", {op}({}i32, {}i32));",
                case.a, case.b
            );
        }
    }
    for case in &i64s {
        for (op, want) in [
            ("i64_div_s", case.div_s),
            ("i64_div_u", case.div_u),
            ("i64_rem_s", case.rem_s),
            ("i64_rem_u", case.rem_u),
        ] {
            let key: String = format!("{op} {} {}", case.a, case.b);
            expected.insert(key.clone(), want.to_string());
            let _: Result<(), std::fmt::Error> = writeln!(
                driver,
                "    println!(\"{key} {{}}\", {op}({}i64, {}i64));",
                case.a, case.b
            );
        }
    }
    driver.push_str("}\n");

    let program: String = lifted_div_rem_program(&bytes, &sigs, &driver);
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wasm_div_rem_diff").expect("mkdir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let rs: PathBuf = dir.join("div_rem.rs");
    fs::write(&rs, &program).expect("write rs");
    let bin: PathBuf = dir.join(if cfg!(windows) {
        "div_rem.exe"
    } else {
        "div_rem"
    });
    let compile: std::process::Output = Command::new(&rustc)
        .args(["--edition", "2021", "-O", "-o"])
        .arg(&bin)
        .arg(&rs)
        .output()
        .expect("spawn rustc");
    assert!(
        compile.status.success(),
        "rustc rejected the lifted divide/remainder program\n{}",
        String::from_utf8_lossy(&compile.stderr)
    );
    let run: std::process::Output = Command::new(&bin).output().expect("run div/rem binary");
    assert!(
        run.status.success(),
        "lifted divide/remainder program crashed"
    );
    let stdout: String = String::from_utf8_lossy(&run.stdout).to_string();

    let mut got: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let [op, a, b, value] = parts.as_slice() else {
            panic!("unparsable divide/remainder result line {line:?}");
        };
        got.insert(format!("{op} {a} {b}"), (*value).to_owned());
    }

    let eng: Engine = Engine::new(&rich_config()).expect("wasmtime engine");
    let mut sandbox: Sandbox = instantiate(&eng, &bytes).expect("div/rem module instantiates");
    let mut diverged: Vec<String> = Vec::new();
    for (key, want) in &expected {
        let parts: Vec<&str> = key.split_whitespace().collect();
        let [op, a, b] = parts.as_slice() else {
            panic!("malformed key {key:?}");
        };
        let args: Vec<Val> = if op.starts_with("i32") {
            vec![
                Val::I32(a.parse::<i32>().expect("i32 operand")),
                Val::I32(b.parse::<i32>().expect("i32 operand")),
            ]
        } else {
            vec![
                Val::I64(a.parse::<i64>().expect("i64 operand")),
                Val::I64(b.parse::<i64>().expect("i64 operand")),
            ]
        };
        let result_ty: ValType = if op.starts_with("i32") {
            ValType::I32
        } else {
            ValType::I64
        };
        let engine_value: String = match wasm_outcome(&mut sandbox, op, &args, result_ty) {
            Some(CmpVal::I32(v)) => v.to_string(),
            Some(CmpVal::I64(v)) => v.to_string(),
            other => panic!("{key}: the module must not trap on a non-trapping operand: {other:?}"),
        };
        if &engine_value != want {
            diverged.push(format!(
                "{key}: tabulated={want} wasmtime={engine_value} (the operand table is wrong)"
            ));
            continue;
        }
        match got.get(key) {
            Some(actual) if actual == want => {}
            Some(actual) => {
                diverged.push(format!("{key}: wasm={want} lifted-rust={actual}"));
            }
            None => diverged.push(format!("{key}: missing from the lifted output")),
        }
    }
    assert!(
        diverged.is_empty(),
        "the lifted divide/remainder helpers diverged on {} of {} case(s):\n{}",
        diverged.len(),
        expected.len(),
        diverged.join("\n")
    );
    eprintln!(
        "divide/remainder differential: {} non-trapping cases, lifted-rust == wasmtime on all",
        expected.len()
    );
}

#[cfg(feature = "sandbox")]
fn val_to_rust_arg_string(val: &Val) -> String {
    match val {
        Val::I32(v) => format!("{v}"),
        Val::I64(v) => format!("{v}"),
        Val::F32(bits) => format!("{bits}"),
        Val::F64(bits) => format!("{bits}"),
        _ => "0".to_owned(),
    }
}

#[cfg(feature = "sandbox")]
fn parse_cmp(line: &str) -> Option<CmpVal> {
    let (tag, rest): (&str, &str) = line.split_once(' ')?;
    match tag {
        "I32" => rest.parse::<i32>().ok().map(CmpVal::I32),
        "I64" => rest.parse::<i64>().ok().map(CmpVal::I64),
        "F32" => rest
            .parse::<u32>()
            .ok()
            .map(|b| CmpVal::F32Bits(canonical_f32(b))),
        "F64" => rest
            .parse::<u64>()
            .ok()
            .map(|b| CmpVal::F64Bits(canonical_f64(b))),
        _ => None,
    }
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn rust_execution_differential_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "rust_execution_differential`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
