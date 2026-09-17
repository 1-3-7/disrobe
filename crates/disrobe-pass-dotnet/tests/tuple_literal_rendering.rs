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

fn combine_body(asm: &DecompiledAssembly) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains("Combine"))
        .map_or_else(|| panic!("Combine method not found"), |m| m.body.clone())
}

#[test]
fn value_tuple_ctor_renders_as_tuple_literal() {
    let asm: DecompiledAssembly = decompile();
    let body: String = combine_body(&asm);
    assert!(
        body.contains("return (a + b, a * b)") || body.contains("(a + b, a * b)"),
        "the ValueTuple ctor must render as a C# tuple literal `(a + b, a * b)`; got:\n{body}"
    );
    assert!(
        !body.contains("new ValueTuple"),
        "no raw `new ValueTuple(...)` construction may survive in a value position; got:\n{body}"
    );
}

#[test]
fn value_tuple_type_position_is_preserved() {
    let asm: DecompiledAssembly = decompile();
    let combine = asm
        .methods
        .iter()
        .find(|m| m.signature.contains("Combine"))
        .expect("Combine method");
    assert!(
        combine.signature.contains("ValueTuple<int, int>")
            || combine.signature.contains("ValueTuple<int,int>"),
        "a ValueTuple used as the return TYPE must be preserved, not turned into a literal; got:\n{}",
        combine.signature
    );
}

#[test]
fn decompile_remains_lossless_after_tuple_lowering() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after the tuple lowering; got {} failures",
        asm.methods_failed
    );
}
