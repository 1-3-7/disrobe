#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| panic!("read {rel}: {e}"))
}

fn decompile() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&bytes).expect("decompile Constructs.dll")
}

fn outer_body(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.signature.contains(needle)
                && !m.body.lines().next().unwrap_or_default().contains("<>c")
        })
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn cached_lambda_linq_chain_reconstructs_to_fluent_syntax() {
    let asm: DecompiledAssembly = decompile();
    let sumsq: String = outer_body(&asm, "int Sumsq");
    assert!(
        sumsq.contains("xs.Select(x => x * x).Sum()"),
        "the cached-lambda LINQ stub must reconstruct `xs.Select(x => x * x).Sum()`; got:\n{sumsq}"
    );
    assert!(
        !sumsq.contains("<>9__") && !sumsq.contains("__stack_underflow"),
        "no cached-delegate field or stack-underflow placeholder may survive; got:\n{sumsq}"
    );
    assert!(
        !sumsq.contains("Select(xs") && !sumsq.contains("Sum(Select"),
        "the static extension calls must reattach their receiver, not render as static calls; got:\n{sumsq}"
    );
}

#[test]
fn decompile_remains_lossless_after_linq_reconstruction() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after LINQ chain reconstruction; got {} failures",
        asm.methods_failed
    );
}
