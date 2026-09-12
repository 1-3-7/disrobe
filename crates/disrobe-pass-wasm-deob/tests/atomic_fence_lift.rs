#![allow(clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_wasm_deob::{
    LiftResult, LiftTarget, c_runtime_prelude, rust_runtime_prelude, try_lift_function_from_module,
    typescript_runtime_prelude,
};

const FENCE_WAT: &str = r#"(module (func (export "fence") atomic.fence))"#;
const FENCE_BYTES_DECLARATION: &str = "const WASM_ATOMIC_FENCE_MODULE_BYTES: readonly number[] = [";
const FENCE_IDENTITY_DRIVER: &str = r#"
const fenceShim: unknown = wasmAtomicFenceShim;
if (typeof fenceShim !== "function") { throw new TypeError("the fence call never cached a shim"); }
const shimSource: string = Function.prototype.toString.call(fenceShim);
const fenceExports: readonly WebAssembly.ModuleExportDescriptor[] = WebAssembly.Module.exports(
  new WebAssembly.Module(Uint8Array.from(WASM_ATOMIC_FENCE_MODULE_BYTES)),
);
const only: WebAssembly.ModuleExportDescriptor | undefined = fenceExports[0];
console.log(JSON.stringify([
  shimSource.includes("[native code]"),
  fenceExports.length,
  only === undefined ? "none" : only.name,
  only === undefined ? "none" : only.kind,
]));
"#;

fn fence_module() -> Vec<u8> {
    wat::parse_str(FENCE_WAT).expect("fence module must assemble")
}

fn tool(name: &str) -> Option<PathBuf> {
    let finder: &str = if cfg!(windows) { "where" } else { "which" };
    let output: Output = Command::new(finder).arg(name).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout.lines().next().map(PathBuf::from)
}

fn compile_rust(source: &str, directory: &Path) {
    let source_path: PathBuf = directory.join("fence.rs");
    std::fs::write(&source_path, source).expect("write Rust lift");
    let rustc: PathBuf = tool("rustc").expect("rustc is required for the fence lift gate");
    let output: Output = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--emit=metadata",
        ])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join("fence.rmeta"))
        .output()
        .expect("run rustc");
    assert!(
        output.status.success(),
        "rustc rejected the atomic fence lift: {}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn compile_c(source: &str, directory: &Path) {
    let source_path: PathBuf = directory.join("fence.c");
    std::fs::write(&source_path, source).expect("write C lift");
    let compiler: PathBuf = ["clang", "cc", "gcc"]
        .into_iter()
        .find_map(tool)
        .expect("a C compiler is required for the fence lift gate");
    let output: Output = Command::new(compiler)
        .args(["-std=c11", "-Werror", "-c"])
        .arg(&source_path)
        .arg("-o")
        .arg(directory.join("fence.o"))
        .output()
        .expect("run clang");
    assert!(
        output.status.success(),
        "the C compiler rejected the atomic fence lift: {}\n{source}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_typescript(source: &str, directory: &Path) -> Output {
    let source_path: PathBuf = directory.join("fence.ts");
    std::fs::write(&source_path, source).expect("write TypeScript lift");
    let node: PathBuf = tool("node").expect("node is required for the fence lift gate");
    Command::new(node)
        .args(["--experimental-strip-types", "--no-warnings"])
        .arg(&source_path)
        .output()
        .expect("run node")
}

fn embedded_fence_module_bytes() -> Vec<u8> {
    let prelude: &str = typescript_runtime_prelude();
    let start: usize = prelude
        .find(FENCE_BYTES_DECLARATION)
        .expect("the TypeScript runtime must embed the atomic fence module")
        + FENCE_BYTES_DECLARATION.len();
    let rest: &str = prelude.get(start..).expect("fence byte list start");
    let end: usize = rest.find(']').expect("fence byte list terminator");
    rest.get(..end)
        .expect("fence byte list body")
        .split(',')
        .map(|value: &str| {
            value
                .trim()
                .parse::<u8>()
                .expect("fence module byte must be a u8 literal")
        })
        .collect()
}

fn exported_function_name(lift: &str) -> &str {
    let start: usize = lift.find("function ").expect("lifted function keyword") + "function ".len();
    let rest: &str = lift.get(start..).expect("lifted function name start");
    let end: usize = rest.find('(').expect("lifted function name terminator");
    rest.get(..end).expect("lifted function name")
}

#[test]
fn every_lift_target_emits_a_real_seqcst_atomic_fence() {
    let bytes: Vec<u8> = fence_module();
    let rust: LiftResult = try_lift_function_from_module(&bytes, 0, LiftTarget::Rust)
        .expect("Rust fence lift must succeed");
    let c: LiftResult =
        try_lift_function_from_module(&bytes, 0, LiftTarget::C).expect("C fence lift must succeed");
    let typescript: LiftResult = try_lift_function_from_module(&bytes, 0, LiftTarget::TypeScript)
        .expect("TypeScript fence lift must succeed");
    assert!(rust.pseudo_source.contains("wasm_atomic_fence();"));
    assert!(c.pseudo_source.contains("wasm_atomic_fence();"));
    assert!(typescript.pseudo_source.contains("wasmAtomicFence();"));
    assert!(
        rust_runtime_prelude()
            .contains("std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst)")
    );
    assert!(c_runtime_prelude().contains("atomic_thread_fence(memory_order_seq_cst)"));

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("wasm-atomic-fence").expect("create scratch");
    compile_rust(
        &format!("{}\n{}", rust_runtime_prelude(), rust.pseudo_source),
        scratch.path(),
    );
    compile_c(
        &format!("{}\n{}", c_runtime_prelude(), c.pseudo_source),
        scratch.path(),
    );

    assert_eq!(
        embedded_fence_module_bytes(),
        bytes,
        "the TypeScript runtime must embed exactly the WebAssembly module the reference assembler \
         produces for {FENCE_WAT}"
    );

    let name: &str = exported_function_name(&typescript.pseudo_source);
    let program: String = format!(
        "{}\n{}\n{name}();\n{name}();\n{FENCE_IDENTITY_DRIVER}",
        typescript_runtime_prelude(),
        typescript
            .pseudo_source
            .replace("export function ", "function ")
    );
    let run: Output = run_typescript(&program, scratch.path());
    assert!(
        run.status.success(),
        "Node rejected the TypeScript fence lift: {}\n{program}",
        String::from_utf8_lossy(&run.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&run.stdout).trim(),
        r#"[true,1,"fence","function"]"#,
        "the cached TypeScript fence must be the engine's compiled WebAssembly export, not a \
         JavaScript function standing in for one"
    );
}
