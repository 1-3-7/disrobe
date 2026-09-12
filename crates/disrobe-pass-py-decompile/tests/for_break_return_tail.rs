#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

mod common;

use std::path::PathBuf;

use common::band::{
    BandInterpreter, BandOutcome, band_scratch, recompile_equiv_construct, resolve_band,
};

const ALIASES: &[&str] = &["3.10", "3.12", "3.13", "3.14"];

#[test]
fn break_return_tail_recompiles_equiv() {
    let interpreters: Vec<BandInterpreter> = resolve_band(ALIASES, &[]);
    if interpreters.is_empty() {
        return;
    }
    let scratch: PathBuf = band_scratch("for_break_return_tail");
    let mut checked: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    for interp in &interpreters {
        checked += 1;
        match recompile_equiv_construct(interp, "for_break_return_tail", &scratch) {
            BandOutcome::RecompileEquiv => {}
            BandOutcome::SourceTokenMatch => {
                failures.push(format!(
                    "py{}: token-match where recompile-equiv required",
                    interp.alias
                ));
            }
            BandOutcome::Tolerated(detail) => {
                failures.push(format!(
                    "py{}: tolerated outcome unacceptable here: {detail}",
                    interp.alias
                ));
            }
            BandOutcome::Failed(e) => failures.push(e),
        }
    }
    assert!(
        failures.is_empty(),
        "break-with-inlined-return-tail must recompile to equivalent bytecode (the loop body branch \
         that inlines the loop's post-exit return is reconstructed as a `break`):\n{}",
        failures.join("\n")
    );
    assert!(
        checked > 0,
        "no 3.10/3.12+ interpreter to prove break-return-tail recovery"
    );
}
