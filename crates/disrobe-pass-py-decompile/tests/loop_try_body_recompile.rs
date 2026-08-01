#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const WHILE_TRY_BREAK: &str = r"
def drain(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            break
        else:
            sink(item)
    sink('exhausted')
";

const FOR_GUARD_TRY_CONTINUE: &str = r"
def preserve_for_guard(values, guarded, read, sink):
    for value in values:
        if guarded(value):
            try:
                sink(read(value))
            except LookupError:
                sink(None)
            continue
        sink(value)
";

const WHILE_GUARD_TRY_CONTINUE: &str = r"
def preserve_while_guard(active, guarded, read, sink):
    while active():
        if guarded():
            try:
                sink(read())
            except LookupError:
                sink(None)
            continue
        sink('ready')
";

const WHILE_OR_GUARD_CONTINUE: &str = r"
def chained_guard(active, primary, secondary, sink):
    while active():
        if primary() or secondary():
            sink('guarded')
            continue
        sink('ready')
";

const WHILE_TRY_HANDLER_FALLTHROUGH: &str = r"
def retain_handler_fallthrough(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            sink(None)
        sink(item)
";

const WHILE_TRY_MIXED_HANDLER_FLOW: &str = r"
def retain_mixed_handler_flow(active, next_item, sink):
    while active():
        try:
            item = next_item()
        except LookupError:
            sink(None)
        except ValueError:
            break
        sink(item)
";

const PRE311_ALIASES: &[&str] = &["3.8", "3.9", "3.10"];

fn stable_interpreter() -> BandInterpreter {
    resolve_band(&["3.10"], &[])
        .into_iter()
        .next()
        .unwrap_or_else(|| {
            panic!(
                "no CPython 3.10 interpreter resolvable via uv; install it before running loop/try recovery proofs"
            )
        })
}

fn required_pre311_interpreters() -> Vec<BandInterpreter> {
    let interpreters: Vec<BandInterpreter> = resolve_band(PRE311_ALIASES, &[]);
    let resolved: Vec<&str> = interpreters
        .iter()
        .map(|interpreter: &BandInterpreter| interpreter.alias)
        .collect();
    assert_eq!(
        resolved.as_slice(),
        PRE311_ALIASES,
        "guarded-loop recovery requires CPython 3.8, 3.9, and 3.10; CI provisions all three"
    );
    interpreters
}

fn assert_recompile_equivalence(
    interpreter: &BandInterpreter,
    fixture: &str,
    label: &str,
) -> String {
    let scratch: PathBuf = band_scratch(label);
    let (outcome, recovered): (BandOutcome, String) =
        recompile_equiv_inline(interpreter, fixture, label, &scratch);
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "{label} must recompile equivalently, got {outcome:?}:\n{recovered}"
    );
    recovered
}

#[test]
fn while_try_except_break_recompiles_with_the_loop_intact() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_try_break_{}", interpreter.alias);
        let recovered: String = assert_recompile_equivalence(&interpreter, WHILE_TRY_BREAK, &label);

        assert_eq!(
            recovered.matches("while active():").count(),
            1,
            "the while header must remain outside the protected body:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("except LookupError:").count(),
            1,
            "the handler must remain nested in the loop:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("break").count(),
            1,
            "the handler must exit the loop instead of returning from the function:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("else:").count(),
            1,
            "the protected success arm must remain a try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the protected success arm must remain inside the try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(\"exhausted\")").count(),
            1,
            "the post-loop tail must remain reachable:\n{recovered}"
        );
        assert!(
            !recovered.contains("return None"),
            "the handler must not replace the loop break with a function return:\n{recovered}"
        );
    }
}

#[test]
fn pre311_handler_fallthrough_does_not_gain_try_else() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_handler_fallthrough_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_TRY_HANDLER_FALLTHROUGH, &label);

        assert_eq!(
            recovered.matches("else:").count(),
            0,
            "a handler that falls through must not become a try else branch:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the sibling statement must remain after the try:\n{recovered}"
        );
    }
}

#[test]
fn pre311_mixed_handler_flow_does_not_gain_try_else() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_mixed_handler_flow_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_TRY_MIXED_HANDLER_FLOW, &label);

        assert_eq!(
            recovered.matches("else:").count(),
            0,
            "a fallthrough handler must prevent promotion of the sibling to try else:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("sink(item)").count(),
            1,
            "the sibling statement must remain after the try:\n{recovered}"
        );
    }
}

#[test]
fn guarded_for_try_continue_recompiles_equivalently() {
    let interpreter: BandInterpreter = stable_interpreter();
    let for_recovered: String = assert_recompile_equivalence(
        &interpreter,
        FOR_GUARD_TRY_CONTINUE,
        "for_guard_try_continue",
    );

    assert_eq!(
        for_recovered.matches("for value in values:").count(),
        1,
        "the for-loop guard must not be consumed as a while header:\n{for_recovered}"
    );
    assert_eq!(
        for_recovered.matches("continue").count(),
        1,
        "the guarded protected arm must retain its back-edge:\n{for_recovered}"
    );
    assert!(
        !for_recovered.contains("else:"),
        "the tail must not become an else arm after a guarded continue:\n{for_recovered}"
    );
}

#[test]
fn guarded_while_try_continue_recompiles_equivalently() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_guard_try_continue_{}", interpreter.alias);
        let while_recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_GUARD_TRY_CONTINUE, &label);

        assert_eq!(
            while_recovered.matches("while active():").count(),
            1,
            "the nested guard must remain inside the while body:\n{while_recovered}"
        );
        assert_eq!(
            while_recovered.matches("continue").count(),
            1,
            "the guarded protected arm must retain its back-edge:\n{while_recovered}"
        );
        assert!(
            while_recovered.contains("sink(\"ready\")"),
            "the false arm must remain in the loop body:\n{while_recovered}"
        );
        assert!(
            !while_recovered.contains("else:"),
            "the tail must not become an else arm after a guarded continue:\n{while_recovered}"
        );
    }
}

#[test]
fn guarded_while_or_continue_recompiles_equivalently() {
    for interpreter in required_pre311_interpreters() {
        let label: String = format!("while_or_guard_continue_{}", interpreter.alias);
        let recovered: String =
            assert_recompile_equivalence(&interpreter, WHILE_OR_GUARD_CONTINUE, &label);

        assert_eq!(
            recovered.matches("while active():").count(),
            1,
            "the outer while header must remain separate from the OR guard:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("if primary() or secondary():").count(),
            1,
            "the OR guard must remain whole:\n{recovered}"
        );
        assert_eq!(
            recovered.matches("continue").count(),
            1,
            "the guarded arm must retain its back-edge:\n{recovered}"
        );
        assert!(
            recovered.contains("sink(\"ready\")"),
            "the false arm must remain in the loop body:\n{recovered}"
        );
    }
}
