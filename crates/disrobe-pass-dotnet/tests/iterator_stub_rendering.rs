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

fn edgecases() -> DecompiledAssembly {
    let bytes: Vec<u8> = load("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&bytes).expect("decompile EdgeCases.baseline.dll")
}

fn kickoff_body(asm: &DecompiledAssembly, declaring: &str, needle: &str) -> String {
    asm.methods
        .iter()
        .find(|m| {
            m.body
                .lines()
                .next()
                .unwrap_or_default()
                .contains(declaring)
                && m.signature.contains(needle)
        })
        .map_or_else(|| panic!("method {needle} not found"), |m| m.body.clone())
}

#[test]
fn an_unreversible_state_machine_states_the_refusal_instead_of_emitting_builder_plumbing() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.IteratorPlayground", " WithEarlyExit(");
    assert!(
        body.contains(disrobe_pass_dotnet::iterator_reverse::UNRECONSTRUCTED_STATE_MACHINE_MARKER),
        "a state machine the pass cannot reverse must say so; got:\n{body}"
    );
    for line in body.lines() {
        let statement: &str = line.trim();
        if statement.starts_with("//") {
            continue;
        }
        assert!(
            !statement.contains(">d__") && !statement.contains("<>"),
            "the refusal must not leave compiler plumbing as a live statement; got:\n{body}"
        );
    }
}

#[test]
fn an_async_kickoff_reverses_to_its_await_body_with_hoisted_locals_declared() {
    let asm: DecompiledAssembly = edgecases();
    let body: String = kickoff_body(&asm, "EdgeCases.AsyncPlayground", " SumAsync(");
    assert!(
        body.contains(" async "),
        "the reversed kickoff must carry the async modifier; got:\n{body}"
    );
    assert!(
        !body.contains("<>t__builder") && !body.contains(">d__"),
        "the reversed kickoff must not leak builder plumbing; got:\n{body}"
    );
    assert!(
        body.contains("await System.Threading.Tasks.Task.Yield();"),
        "the await from MoveNext must survive into the kickoff; got:\n{body}"
    );
    assert!(
        body.contains("System.Collections.Generic.IEnumerator<int> wrap2;"),
        "the compiler-hoisted enumerator field must come back as a typed local; got:\n{body}"
    );
    assert!(
        body.contains("wrap2 = source.GetEnumerator();"),
        "the hoisted parameter field must resolve to the method parameter; got:\n{body}"
    );
    assert!(
        body.contains("return local1;"),
        "the result register must still be returned; got:\n{body}"
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
