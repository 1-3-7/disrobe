#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::print_stderr,
    clippy::print_stdout
)]

mod common;

use std::path::PathBuf;

use crate::common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_inline, resolve_band,
};

const QUOTED_PRINTABLE_LINE_ENDING: &str = r#"
def decode_line_shape(line):
    n = len(line)
    if n > 0 and line[n - 1:n] == b"\n":
        partial = 0
        n = n - 1
        while n > 0 and line[n - 1:n] in b" \t\r":
            n = n - 1
    else:
        partial = 1
    decoded = line[:n]
    if partial:
        return decoded
    return decoded + b"\n"
"#;

#[test]
fn pre311_if_else_keeps_its_while_in_the_then_arm() {
    let interpreters: Vec<BandInterpreter> = resolve_band(&["3.10"], &[]);
    assert_eq!(
        interpreters.len(),
        1,
        "CPython 3.10 is required for the pre-3.11 branch regression"
    );
    let interpreter: &BandInterpreter = &interpreters[0];
    let scratch: PathBuf = band_scratch("pre311_if_else_loop");
    let (outcome, recovered): (BandOutcome, String) = recompile_equiv_inline(
        interpreter,
        QUOTED_PRINTABLE_LINE_ENDING,
        "pre311_if_else_loop",
        &scratch,
    );
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "pre-3.11 if/else loop must recompile equivalently, got {outcome:?}:\n{recovered}"
    );
    assert!(
        recovered.contains("if n > 0 and line[n - 1:n] == b\"\\n\":"),
        "the compound condition must remain the if test:\n{recovered}"
    );
    assert!(
        recovered.contains("        while n > 0 and line[n - 1:n] in b\" \\t\\r\":"),
        "the trim loop must remain in the then arm:\n{recovered}"
    );
    assert!(
        recovered.contains("    else:\n        partial = 1"),
        "the partial fallback must remain the if else arm:\n{recovered}"
    );
    assert!(
        recovered.contains("return decoded + b\"\\n\""),
        "the shared continuation must retain the complete-line newline:\n{recovered}"
    );
}
