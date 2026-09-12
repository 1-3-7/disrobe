#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_pass_dotnet::decompile::{DecompiledAssembly, decompile_assembly};

fn decompile() -> DecompiledAssembly {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("../../corpus/dotnet/constructs/Constructs.dll");
    decompile_assembly(&std::fs::read(&path).expect("read Constructs.dll")).expect("decompile")
}

fn move_next_body(asm: &DecompiledAssembly, machine: &str) -> String {
    asm.methods
        .iter()
        .find(|m| m.signature.contains(machine) && m.signature.contains("MoveNext"))
        .map_or_else(
            || panic!("MoveNext for {machine} not found"),
            |m| m.body.clone(),
        )
}

fn line_index(body: &str, needle: &str) -> Option<usize> {
    body.lines().position(|l: &str| l.contains(needle))
}

#[test]
fn iterator_movenext_has_no_leaked_control_flow_artifacts() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "Evens");
    assert!(
        !body.contains("goto IL_"),
        "Evens loop must reconstruct without a leaked goto; got:\n{body}"
    );
    assert!(
        !body.contains("{ }") && !body.contains("{\n    }") && !body.contains("{\n}"),
        "Evens must not leave an empty `if (){{}}` (the loop body hoisted out); got:\n{body}"
    );
}

#[test]
fn iterator_movenext_wraps_yield_in_a_loop() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "Evens");
    let loop_idx: usize = line_index(&body, "while")
        .or_else(|| line_index(&body, "for "))
        .unwrap_or_else(|| panic!("Evens must reconstruct a for/while loop; got:\n{body}"));
    let yield_idx: usize = line_index(&body, "yield return i")
        .unwrap_or_else(|| panic!("Evens must recover `yield return i`; got:\n{body}"));
    assert!(
        yield_idx > loop_idx,
        "`yield return i` must sit inside the reconstructed loop (after its header); got:\n{body}"
    );
    if let Some(brk) = line_index(&body, "yield break") {
        assert!(
            brk > yield_idx,
            "`yield break` must be placed after the loop body, not before it; got:\n{body}"
        );
    }
}

#[test]
fn async_movenext_wraps_accumulate_in_a_loop_around_await() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "SumAsync");
    let loop_idx: usize = line_index(&body, "while")
        .or_else(|| line_index(&body, "for "))
        .unwrap_or_else(|| panic!("SumAsync must reconstruct a for/while loop; got:\n{body}"));
    let accum_idx: usize = line_index(&body, "total = total + i")
        .unwrap_or_else(|| panic!("SumAsync must recover `total = total + i`; got:\n{body}"));
    assert!(
        accum_idx > loop_idx,
        "the accumulate `total = total + i` must sit inside the reconstructed loop; got:\n{body}"
    );
    assert!(
        !body.contains("(&local2).GetResult()") && !body.contains(".GetResult();"),
        "the bare unassigned await (Task.Yield GetResult) must fold to `await ...`, not leak; got:\n{body}"
    );
    assert!(
        body.contains("await System.Threading.Tasks.Task.Yield();"),
        "the void await of Task.Yield must collapse to a qualified `await ...Task.Yield();`, not leave an awaiter-deref temporary; got:\n{body}"
    );
    assert!(
        !body.contains("await (&local"),
        "no managed-ref awaiter deref `await (&localN)` may survive the void-await collapse; got:\n{body}"
    );
}

#[test]
fn state_machine_loop_recovery_holds_lossless_gate() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "loop reconstruction must not introduce any method decompile failure; got {}",
        asm.methods_failed
    );
}

#[test]
fn async_outer_stub_recompiles_with_async_shell() {
    let asm: DecompiledAssembly = decompile();
    let sum_async: String = asm
        .methods
        .iter()
        .find(|m| {
            m.signature.contains("Task<int> SumAsync")
                && !m.body.lines().next().unwrap_or_default().contains(">d__")
        })
        .map_or_else(
            || panic!("SumAsync outer stub not found"),
            |m| m.body.clone(),
        );
    assert!(
        sum_async.contains("async ") && sum_async.contains("Task<int>"),
        "the async outer stub must carry the `async` modifier on the Task<int> signature; got:\n{sum_async}"
    );
    assert!(
        sum_async.contains("await System.Threading.Tasks.Task.Yield();"),
        "the await must fully qualify the Task.Yield() static call; got:\n{sum_async}"
    );
    assert!(
        sum_async.contains("while (i <= n)") && sum_async.contains("total = total + i"),
        "the accumulate loop must reconstruct with a real exit condition; got:\n{sum_async}"
    );
    assert!(
        sum_async.contains("return total;"),
        "the SetResult value binding (local1 = total) must be recovered as `return total;`; got:\n{sum_async}"
    );
    assert!(
        !sum_async.contains(">d__")
            && !sum_async.contains("__builder")
            && !sum_async.contains("local1"),
        "no state-machine construction, builder plumbing, or leftover result temp may survive; got:\n{sum_async}"
    );
}
