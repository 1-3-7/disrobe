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

const MEMBERSHIP_GUARD_ELSE: &str = r"
def handle_existing(existing, child_loggers, disable_existing, root):
    for log in existing:
        logger = root.manager.loggerDict[log]
        if log in child_loggers:
            if not isinstance(logger, PlaceHolder):
                logger.setLevel(0)
                logger.handlers = []
                logger.propagate = True
        else:
            logger.disabled = disable_existing
";

const CALL_GUARD_ELSE: &str = r"
def script_from_pieces(pieces, out, comment_line):
    for piece in pieces:
        if isinstance(piece, Example):
            out.append(piece.source[:-1])
            want = piece.want
            if want:
                out.append('# Expected:')
                out += ['## ' + line for line in want.split('\n')[:-1]]
        else:
            out += [comment_line(line) for line in piece.split('\n')[:-1]]
";

const WHILE_TAIL_ELSE: &str = r"
def drain_pending(pending, ready, sink):
    while pending:
        item = pending.pop()
        if item in ready:
            sink.emit(item)
        else:
            sink.defer(item)
    return sink
";

const ALIASES: &[&str] = &["3.11", "3.12", "3.13", "3.14"];

fn required_interpreters() -> Vec<BandInterpreter> {
    let interpreters: Vec<BandInterpreter> = resolve_band(ALIASES, &[]);
    let resolved: Vec<&str> = interpreters
        .iter()
        .map(|interpreter: &BandInterpreter| interpreter.alias)
        .collect();
    assert_eq!(
        resolved.as_slice(),
        ALIASES,
        "loop-tail else-arm recovery requires CPython 3.11 through 3.14; CI provisions all four, \
         so an absent interpreter fails this run rather than quietly measuring less"
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

fn assert_every_band(fixture: &str, stem: &str) {
    for interpreter in required_interpreters() {
        let label: String = format!("{stem}_{}", interpreter.alias);
        let recovered: String = assert_recompile_equivalence(&interpreter, fixture, &label);
        assert!(
            recovered.contains("else:"),
            "{label} recovered the loop-tail pair without an else arm, so the arm reached by the \
             jump was folded into the loop body instead:\n{recovered}"
        );
    }
}

#[test]
fn membership_guard_keeps_its_else_arm() {
    assert_every_band(MEMBERSHIP_GUARD_ELSE, "membership_guard_else");
}

#[test]
fn call_guard_keeps_its_else_arm() {
    assert_every_band(CALL_GUARD_ELSE, "call_guard_else");
}

#[test]
fn while_tail_guard_keeps_its_else_arm() {
    assert_every_band(WHILE_TAIL_ELSE, "while_tail_else");
}
