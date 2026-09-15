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

fn edge_cases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn declaring_line(body: &str) -> String {
    body.lines()
        .nth(1)
        .unwrap_or_default()
        .trim_start()
        .to_owned()
}

#[test]
fn a_cached_delegate_resolves_to_the_lambda_of_its_own_method() {
    let asm: DecompiledAssembly = edge_cases();
    let doubled: String = body_of(&asm, " Doubled(");
    let even_squares: String = body_of(&asm, " EvenSquares(");
    assert!(
        doubled.contains("Select(x => x * 2)"),
        "CollectionPlayground.Doubled caches lambda 1_0, so it must inline that lambda:\n{doubled}"
    );
    assert!(
        even_squares.contains("Where(x => (x % 2) == 0)"),
        "LinqPlayground.EvenSquares caches lambda 0_0, so it must inline that lambda and not the one whose ordinal is a prefix of it:\n{even_squares}"
    );
    for body in [&doubled, &even_squares] {
        assert!(
            !body.contains("=> this."),
            "a static cached lambda has no receiver to capture, so no inlined arrow may reference one:\n{body}"
        );
    }
}

#[test]
fn a_method_named_after_a_query_operator_keeps_its_declaration() {
    let asm: DecompiledAssembly = edge_cases();
    let aggregate: String = body_of(&asm, " Aggregate(");
    assert_eq!(
        declaring_line(&aggregate),
        "public static System.Collections.Generic.Dictionary<string, double> Aggregate(System.Collections.Generic.IEnumerable<EdgeCases.User> users)",
        "rewriting a query operator into member position must not touch the method's own declaration:\n{aggregate}"
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
