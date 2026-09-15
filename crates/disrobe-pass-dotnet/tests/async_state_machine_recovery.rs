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

#[test]
fn async_movenext_drops_the_compiler_exception_capture_wrapper() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "SumAsync");
    assert!(
        !body.contains("catch (Exception"),
        "the async builder's compiler-generated try/catch(Exception) wrapper must be unwrapped; got:\n{body}"
    );
    assert!(
        !body.contains("SetException"),
        "the SetException plumbing must not surface; got:\n{body}"
    );
    assert!(
        body.contains("total = total + i"),
        "the recovered user statements must remain after unwrapping; got:\n{body}"
    );
    assert!(
        body.contains("return total") || body.contains("return local"),
        "SetResult must fold to a `return <value>` (directly or via the result local); got:\n{body}"
    );
}

#[test]
fn iterator_movenext_recovers_yield_points() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "Evens");
    assert!(
        body.contains("yield return i"),
        "the iterator MoveNext must recover `yield return i`; got:\n{body}"
    );
    let terminates_cleanly: bool = body.contains("yield break")
        || (!body.contains("return false") && !body.contains("return 0"));
    assert!(
        terminates_cleanly,
        "the iterator MoveNext must end as a loop falling off into yield break, not leak `return false/0` from the MoveNext bool contract; got:\n{body}"
    );
}

#[test]
fn state_machine_recovery_does_not_regress_the_lossless_gate() {
    let asm: DecompiledAssembly = decompile();
    assert_eq!(
        asm.methods_failed, 0,
        "async/iterator body recovery must not introduce any method decompile failure; got {}",
        asm.methods_failed
    );
}
