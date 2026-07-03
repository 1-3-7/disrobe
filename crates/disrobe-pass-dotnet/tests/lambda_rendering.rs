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

fn body_of(asm: &DecompiledAssembly, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains(needle) && !m.signature.contains("b__"))
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn capturing_lambda_factory_reconstructs_to_arrow_syntax() {
    let asm: DecompiledAssembly = decompile();
    let make_adder: String = body_of(&asm, "MakeAdder");
    assert!(
        make_adder.contains("return x => x + delta;"),
        "the MakeAdder closure-factory stub must reconstruct `return x => x + delta;`; got:\n{make_adder}"
    );
    assert!(
        !make_adder.contains("<>c__DisplayClass") && !make_adder.contains("b__"),
        "no display-class construction or raw lambda-method reference may survive; got:\n{make_adder}"
    );
}

#[test]
fn decompile_remains_lossless_after_lambda_inlining() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after lambda inlining; got {} failures",
        asm.methods_failed
    );
}
