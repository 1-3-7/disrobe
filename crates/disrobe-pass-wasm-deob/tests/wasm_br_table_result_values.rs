#![allow(clippy::panic)]

#[cfg(feature = "sandbox")]
use std::fs;
#[cfg(feature = "sandbox")]
use std::path::PathBuf;
#[cfg(feature = "sandbox")]
use std::process::Command;

#[cfg(feature = "sandbox")]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftTarget, ModuleSignatures, extract_signatures, lift_function_body,
    rust_runtime_prelude,
};
#[cfg(feature = "sandbox")]
use wasmparser::{FunctionBody, Parser, Payload};
#[cfg(feature = "sandbox")]
use wasmtime::{Engine, Linker, Module, Store, Val};

#[cfg(feature = "sandbox")]
const BR_TABLE_RESULT_VALUES: &str = r#"
(module
  (func (export "pick") (param $selector i32) (param $value i64) (result i64)
    block $outer (result i64)
      block $middle (result i64)
        block $inner (result i64)
          local.get $value
          local.get $selector
          br_table $inner $middle $outer $outer
        end
        i64.const 10
        i64.add
      end
      i64.const 100
      i64.add
    end))
"#;

#[cfg(feature = "sandbox")]
const LOOP_RESULT_LABEL: &str = r#"
(module
  (func (export "loop_result") (param $go i32)
    i32.const 99
    loop $again (result i64)
      local.get $go
      br_if $again
      i64.const 42
    end
    drop
    drop))
"#;

#[cfg(feature = "sandbox")]
fn first_body<'a>(bytes: &'a [u8]) -> Result<FunctionBody<'a>, String> {
    for payload in Parser::new(0).parse_all(bytes) {
        let payload: Payload<'a> = payload.map_err(|error| error.to_string())?;
        if let Payload::CodeSectionEntry(body) = payload {
            return Ok(body);
        }
    }
    Err("fixture has no defined function body".to_owned())
}

#[cfg(feature = "sandbox")]
fn callees(signatures: &ModuleSignatures, bytes: &[u8]) -> CalleeNames {
    CalleeNames::with_signatures(
        signatures.callee_names(),
        signatures.call_signatures(),
        signatures.call_signatures(),
    )
    .with_module_context(bytes)
}

#[cfg(feature = "sandbox")]
fn call_i64(
    engine: &Engine,
    bytes: &[u8],
    export: &str,
    selector: i32,
    value: i64,
) -> Result<i64, String> {
    let module: Module = Module::new(engine, bytes).map_err(|error| error.to_string())?;
    let mut store: Store<()> = Store::new(engine, ());
    let linker: Linker<()> = Linker::new(engine);
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .map_err(|error| error.to_string())?;
    let function: wasmtime::Func = instance
        .get_func(&mut store, export)
        .ok_or_else(|| format!("missing export `{export}`"))?;
    let mut results: [Val; 1] = [Val::I64(0)];
    function
        .call(
            &mut store,
            &[Val::I32(selector), Val::I64(value)],
            &mut results,
        )
        .map_err(|error| error.to_string())?;
    match results[0] {
        Val::I64(result) => Ok(result),
        ref other => Err(format!("export `{export}` returned {other:?}, wanted i64")),
    }
}

#[cfg(feature = "sandbox")]
fn call_void(engine: &Engine, bytes: &[u8], export: &str, argument: i32) -> Result<(), String> {
    let module: Module = Module::new(engine, bytes).map_err(|error| error.to_string())?;
    let mut store: Store<()> = Store::new(engine, ());
    let linker: Linker<()> = Linker::new(engine);
    let instance: wasmtime::Instance = linker
        .instantiate(&mut store, &module)
        .map_err(|error| error.to_string())?;
    let function: wasmtime::Func = instance
        .get_func(&mut store, export)
        .ok_or_else(|| format!("missing export `{export}`"))?;
    let mut results: [Val; 0] = [];
    function
        .call(&mut store, &[Val::I32(argument)], &mut results)
        .map_err(|error| error.to_string())
}

#[cfg(feature = "sandbox")]
const fn expected(selector: i32, value: i64) -> i64 {
    match selector {
        0 => value.wrapping_add(110),
        1 => value.wrapping_add(100),
        _ => value,
    }
}

#[cfg(feature = "sandbox")]
fn compile_recovered_wasm(source: &str) -> Result<Vec<u8>, String> {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_wasm_br_table_result_values")
            .map_err(|error: std::io::Error| error.to_string())?;
    let dir: PathBuf = scratch.path().to_path_buf();
    let rust: PathBuf = dir.join("recovered.rs");
    let wasm: PathBuf = dir.join("recovered.wasm");
    let result: Result<Vec<u8>, String> = (|| {
        fs::write(&rust, source).map_err(|error| error.to_string())?;
        let output: std::process::Output = Command::new("rustc")
            .args([
                "--edition",
                "2021",
                "--target",
                "wasm32-unknown-unknown",
                "--crate-type",
                "cdylib",
                "-C",
                "panic=abort",
                "-O",
                "-o",
            ])
            .arg(&wasm)
            .arg(&rust)
            .output()
            .map_err(|error| error.to_string())?;
        if !output.status.success() {
            return Err(format!(
                "rustc rejected recovered structured Rust (exit {:?})\n{}\n{source}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        fs::read(&wasm).map_err(|error| error.to_string())
    })();
    let cleanup: Result<(), String> = scratch
        .close()
        .map_err(|error: std::io::Error| error.to_string());
    match (result, cleanup) {
        (Ok(bytes), Ok(())) => Ok(bytes),
        (Ok(_), Err(error)) => Err(format!("could not remove fixture directory: {error}")),
        (Err(error), Ok(())) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(format!(
            "{error}\ncould not remove fixture directory: {cleanup_error}"
        )),
    }
}

#[cfg(feature = "sandbox")]
fn lift_fixture(wat_text: &str) -> Result<(Vec<u8>, String), String> {
    let original: Vec<u8> = wat::parse_str(wat_text).map_err(|error| error.to_string())?;
    wasmparser::validate(&original).map_err(|error| error.to_string())?;
    let signatures: ModuleSignatures =
        extract_signatures(&original).map_err(|error| error.to_string())?;
    let sig: &FunctionSig = signatures
        .defined()
        .first()
        .ok_or_else(|| "fixture has no function signature".to_owned())?;
    let body: FunctionBody<'_> = first_body(&original)?;
    let lifted = lift_function_body(
        &body,
        sig,
        &callees(&signatures, &original),
        LiftTarget::Rust,
    );
    if !lifted.coverage.fully_recovered() {
        return Err(format!(
            "structured lift left untranslated operators: {:?}",
            lifted.coverage.untranslated
        ));
    }
    let mut source: String = rust_runtime_prelude().to_owned();
    source.push('\n');
    source.push_str(&lifted.pseudo_source);
    Ok((original, source))
}

#[cfg(feature = "sandbox")]
#[test]
fn br_table_carries_i64_results_to_all_typed_label_targets() -> Result<(), String> {
    let (original, mut source): (Vec<u8>, String) = lift_fixture(BR_TABLE_RESULT_VALUES)?;
    source.push_str(
        "\n#[unsafe(no_mangle)]\npub extern \"C\" fn recovered_pick(selector: i32, value: i64) -> i64 {\n    pick(selector, value)\n}\n",
    );
    let recovered: Vec<u8> = compile_recovered_wasm(&source)?;
    wasmparser::validate(&recovered).map_err(|error| error.to_string())?;

    let engine: Engine = Engine::default();
    let selectors: [i32; 5] = [-1, 0, 1, 2, 3];
    let values: [i64; 3] = [-5, 0, 7];
    for selector in selectors {
        for value in values {
            let want: i64 = expected(selector, value);
            let original_result: i64 = call_i64(&engine, &original, "pick", selector, value)?;
            let recovered_result: i64 =
                call_i64(&engine, &recovered, "recovered_pick", selector, value)?;
            if original_result != want {
                return Err(format!(
                    "fixture result diverged for selector={selector}, value={value}: got {original_result}, wanted {want}"
                ));
            }
            if recovered_result != original_result {
                return Err(format!(
                    "structured result diverged for selector={selector}, value={value}: original={original_result}, recovered={recovered_result}"
                ));
            }
        }
    }
    Ok(())
}

#[cfg(feature = "sandbox")]
#[test]
fn loop_result_labels_do_not_consume_outer_stack_values() -> Result<(), String> {
    let (original, mut source): (Vec<u8>, String) = lift_fixture(LOOP_RESULT_LABEL)?;
    source.push_str(
        "\n#[unsafe(no_mangle)]\npub extern \"C\" fn recovered_loop_result(go: i32) {\n    loop_result(go);\n}\n",
    );
    let recovered: Vec<u8> = compile_recovered_wasm(&source)?;
    wasmparser::validate(&recovered).map_err(|error| error.to_string())?;
    let engine: Engine = Engine::default();
    call_void(&engine, &original, "loop_result", 0)?;
    call_void(&engine, &recovered, "recovered_loop_result", 0)?;
    Ok(())
}

#[cfg(not(feature = "sandbox"))]
#[test]
fn wasm_br_table_result_values_refuses_to_report_success_without_the_sandbox_feature() {
    panic!(concat!(
        "DR-WASMDEOB-SANDBOX: this target grades recovered output against a real ",
        "runtime. The missing prerequisite is the crate feature `sandbox`. Re-run ",
        "it as `cargo test -p disrobe-pass-wasm-deob --features sandbox --test ",
        "wasm_br_table_result_values`. Without that feature every graded test in this target is ",
        "compiled out and its `ok` result line grades nothing."
    ));
}
