#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
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

fn type_check_blockers(body: &str) -> Vec<&'static str> {
    let mut reasons: Vec<&'static str> = Vec::new();
    if body.contains("__stack_underflow") {
        reasons.push("stack_underflow");
    }
    if body.contains("type(0x") || body.contains("__token") || body.contains("TypeSpec[") {
        reasons.push("unresolved_token");
    }
    let labels: BTreeSet<&str> = body
        .lines()
        .filter_map(|l: &str| {
            let t: &str = l.trim();
            t.strip_suffix(":;").or_else(|| t.strip_suffix(':'))
        })
        .filter(|s: &&str| s.starts_with("IL_"))
        .collect();
    for line in body.lines() {
        let t: &str = line.trim();
        if let Some(rest) = t.strip_prefix("goto ") {
            let target: &str = rest.trim_end_matches(';');
            if target.starts_with("IL_") && !labels.contains(target) {
                reasons.push("dangling_goto");
                break;
            }
        }
    }
    reasons
}

#[test]
fn await_foreach_movenext_bodies_are_type_checkable() {
    let asm: DecompiledAssembly = decompile();
    for machine in [
        "ConsumeAsync",
        "CountWithAsync",
        "BatchAsync",
        "WordsWithPrefix",
    ] {
        let body: String = move_next_body(&asm, machine);
        let blockers: Vec<&str> = type_check_blockers(&body);
        assert!(
            blockers.is_empty(),
            "<{machine}> MoveNext must be type-checkable (no dangling goto, no stack underflow); blockers={blockers:?}\n{body}"
        );
    }
}

#[test]
fn await_foreach_dispose_rethrow_recovers_the_captured_exception() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "ConsumeAsync");
    assert!(
        body.contains("if (local6 != null)\n        {\n            throw local6;\n        }"),
        "the <ConsumeAsync> DisposeAsync captured exception must rethrow as `throw local6;`:\n{body}"
    );
    assert!(
        !body.contains("Capture(__stack_underflow)"),
        "the DisposeAsync exception-dispatch-info rethrow must recover its captured exception, not lift to __stack_underflow:\n{body}"
    );
}

#[test]
fn async_iterator_yield_break_does_not_leak_movenext_bool_contract() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "RangeAsync");
    assert!(
        body.contains("yield break;"),
        "expected yield break:\n{body}"
    );
    assert!(
        !body.contains("return 0;") && !body.contains("return false;"),
        "async iterator MoveNext must not leak bool-contract returns after yield break:\n{body}"
    );
}

#[test]
fn every_emitted_goto_has_a_matching_label() {
    let asm: DecompiledAssembly = decompile();
    for m in &asm.methods {
        let body: &str = m.body.as_str();
        if !body.contains("goto IL_") {
            continue;
        }
        assert!(
            !type_check_blockers(body).contains(&"dangling_goto"),
            "method has a goto without a matching label:\n{body}"
        );
    }
}

#[test]
fn type_checkable_move_next_count_holds_or_climbs() {
    const FLOOR: usize = 29;
    let asm: DecompiledAssembly = decompile();
    let mut total: usize = 0;
    let mut clean: usize = 0;
    for m in &asm.methods {
        if !(m.signature.contains("state machine") && m.signature.contains("MoveNext")) {
            continue;
        }
        total += 1;
        if type_check_blockers(&m.body).is_empty() {
            clean += 1;
        }
    }
    assert!(
        clean >= FLOOR,
        "type-checkable MoveNext rate regressed: {clean}/{total} (floor {FLOOR})"
    );
}

#[test]
fn generic_iterator_lowers_var_placeholder_to_declared_type_parameter() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "Bfs");
    assert!(
        body.contains("new HashSet<T>()") && body.contains("default(T)"),
        "the <Bfs> iterator must render its !0 type-parameter as the declared name T:\n{body}"
    );
    assert!(
        !body.contains("!0") && !body.contains("HashSet<!"),
        "no raw !N generic-parameter placeholder may survive into the recovered body:\n{body}"
    );
}

#[test]
fn generic_mediator_lowers_method_and_type_parameters() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "SendAsync");
    assert!(
        body.contains("typeof(TRequest)"),
        "the mediator !0 placeholder must lower to TRequest:\n{body}"
    );
    assert!(
        !body.contains("!0") && !body.contains("!1"),
        "no placeholder residue:\n{body}"
    );
}

#[test]
fn static_calls_in_iterators_are_qualified_with_declaring_type() {
    let asm: DecompiledAssembly = decompile();
    let body: String = move_next_body(&asm, "RaceAsync");
    assert!(
        body.contains(".WhenAny("),
        "the unqualified Task.WhenAny static call must be qualified with its declaring type:\n{body}"
    );
    assert!(
        !body
            .lines()
            .any(|l: &str| l.trim_start().starts_with("local3 = WhenAny(")),
        "WhenAny must not be emitted as a bare unqualified call:\n{body}"
    );
}
