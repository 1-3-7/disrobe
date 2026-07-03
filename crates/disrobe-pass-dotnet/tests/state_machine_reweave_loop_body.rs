#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};
use disrobe_pass_dotnet::structurize::StructuredMethod;

fn decompile() -> DecompiledAssembly {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/megafile/EdgeCases.baseline.dll");
    decompile_assembly(&std::fs::read(&path).expect("read EdgeCases.baseline.dll"))
        .expect("decompile")
}

fn move_next_body(asm: &DecompiledAssembly, machine: &str) -> String {
    asm.methods
        .iter()
        .find(|m: &&StructuredMethod| {
            m.signature.contains(&format!("<{machine}>")) && m.signature.contains("MoveNext")
        })
        .map_or_else(
            || panic!("MoveNext for <{machine}> not found"),
            |m: &StructuredMethod| m.body.clone(),
        )
}

#[test]
fn async_foreach_await_keeps_the_loop_and_awaited_accumulate() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "SumAsync");
    assert!(
        body.contains("while (wrap2.MoveNext())"),
        "the foreach-over-enumerator must survive reweave as a real loop, not be cut:\n{body}"
    );
    assert!(
        body.contains("await System.Threading.Tasks.Task.Yield();"),
        "the awaited suspend inside the loop must survive:\n{body}"
    );
    assert!(
        body.contains("total = total + v"),
        "the awaited-result accumulate must sit inside the recovered loop:\n{body}"
    );
    assert!(
        body.contains("return local1;")
            && body.lines().any(|l: &str| l.trim() == "local1 = total;"),
        "the result binding must be recovered, not left as an unassigned `return localN;` cut tail:\n{body}"
    );
}

#[test]
fn async_using_await_with_catch_keeps_the_awaited_body() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "WithTimeoutAsync");
    assert!(
        body.contains("local2 = await local3;") || body.contains("await local3"),
        "the single await inside the using/try must survive reweave, not be cut:\n{body}"
    );
    assert!(
        body.contains("cts = new CancellationTokenSource(this.timeout);"),
        "the using-bound resource construction must survive:\n{body}"
    );
    assert!(
        !(body.lines().count() <= 8 && body.contains("return local1;")),
        "the body must not degenerate into the lossy `ctor; null; return localN;` cut form:\n{body}"
    );
}

#[test]
fn iterator_foreach_yield_keeps_the_loop_body_without_a_swallowing_catch() {
    let asm: DecompiledAssembly = decompile();
    for machine in ["Enumerated", "WithEarlyExit"] {
        let body: String = move_next_body(&asm, machine);
        assert!(
            body.contains("yield return"),
            "<{machine}> must retain its yield inside the recovered loop body:\n{body}"
        );
        assert!(
            body.contains("MoveNext()"),
            "<{machine}> must retain the enumerator drive loop:\n{body}"
        );
        assert!(
            !body.contains("catch"),
            "the iterator dispose fault must not render as a value-swallowing `catch` around the yield:\n{body}"
        );
    }
}
