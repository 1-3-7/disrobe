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

const CPYTHON_310: &[&str] = &["3.10"];
const HANDLER_CONTINUES_WITH_LOAD_FAST: &str = concat!(
    "def recover(value):\n",
    "    try:\n",
    "        value = parse(value)\n",
    "    except ValueError:\n",
    "        value = fallback(value)\n",
    "    return value\n",
);
const TYPED_HANDLER_CONTINUES_IN_INFINITE_LOOP: &str = concat!(
    "def recover(keys):\n",
    "    while True:\n",
    "        try:\n",
    "            return keys.pop()\n",
    "        except StopIteration:\n",
    "            return None\n",
    "        except KeyError:\n",
    "            continue\n",
);

#[test]
fn handler_pop_except_then_load_fast_recompiles_on_310() {
    let band: Vec<BandInterpreter> = resolve_band(CPYTHON_310, &[]);
    assert_eq!(
        band.len(),
        1,
        "CPython 3.10 is required to prove handler continuation after POP_EXCEPT"
    );
    let scratch: PathBuf = band_scratch("pre311-except-handler-continuation");
    let (outcome, source): (BandOutcome, String) = recompile_equiv_inline(
        &band[0],
        HANDLER_CONTINUES_WITH_LOAD_FAST,
        "pre311_except_handler_continuation",
        &scratch,
    );
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "CPython 3.10 handler continuation after POP_EXCEPT did not recompile equivalently: \
         {outcome:?}\n--- recovered:\n{source}"
    );
    assert!(
        source.contains("except ValueError:") && source.contains("return value"),
        "recovered source lost the handler continuation:\n{source}"
    );
}

#[test]
fn typed_handler_continue_after_pop_except_recompiles_on_310() {
    let band: Vec<BandInterpreter> = resolve_band(CPYTHON_310, &[]);
    assert_eq!(
        band.len(),
        1,
        "CPython 3.10 is required to prove handler continue after POP_EXCEPT"
    );
    let scratch: PathBuf = band_scratch("pre311-except-handler-continue");
    let (outcome, source): (BandOutcome, String) = recompile_equiv_inline(
        &band[0],
        TYPED_HANDLER_CONTINUES_IN_INFINITE_LOOP,
        "pre311_except_handler_continue",
        &scratch,
    );
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "CPython 3.10 typed handler continue did not recompile equivalently: {outcome:?}\n--- recovered:\n{source}"
    );
    assert!(
        source.contains("except KeyError:") && source.contains("continue"),
        "recovered source lost the typed handler continue:\n{source}"
    );
}
