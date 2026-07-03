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
                && !m.body.lines().next().unwrap_or_default().contains(">d__")
        })
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn iterator_factory_stub_reconstructs_to_the_yield_body() {
    let asm: DecompiledAssembly = decompile();
    let evens: String = outer_body(&asm, "IEnumerable<int> Evens");
    assert!(
        !evens.contains(">d__") && !evens.contains("new <Evens>"),
        "the Evens iterator factory stub must not leak the compiler state-machine construction; got:\n{evens}"
    );
    assert!(
        evens.contains("yield return i"),
        "the reconstructed Evens body must carry the yield from the recovered MoveNext; got:\n{evens}"
    );
    assert!(
        evens.contains("int i;"),
        "the hoisted loop variable must get a local declaration with its real type; got:\n{evens}"
    );
    assert!(
        !evens.contains("this.n"),
        "the hoisted parameter field this.n must resolve to the method parameter n; got:\n{evens}"
    );
    assert!(
        !evens.contains("if (i & 1)"),
        "an integer-as-bool condition must be normalized to a comparison, not left as `if (i & 1)`; got:\n{evens}"
    );
}

#[test]
fn decompile_remains_lossless_after_iterator_reconstruction() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "no method may fail to decompile after iterator-stub reconstruction; got {} failures",
        asm.methods_failed
    );
}
