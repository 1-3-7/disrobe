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

const BATCH_APPENDS: &str = r"
def _batch_appends(self, items, obj):
    save = self.save
    write = self.write

    if not self.bin:
        for i, x in enumerate(items):
            try:
                save(x)
            except BaseException as exc:
                exc.add_note(f'when serializing {_T(obj)} item {i}')
                raise
            write(APPEND)
        return

    start = 0
    for batch in batched(items, self._BATCHSIZE):
        batch_len = len(batch)
        if batch_len != 1:
            write(MARK)
            for i, x in enumerate(batch, start):
                try:
                    save(x)
                except BaseException as exc:
                    exc.add_note(f'when serializing {_T(obj)} item {i}')
                    raise
            write(APPENDS)
        else:
            try:
                save(batch[0])
            except BaseException as exc:
                exc.add_note(f'when serializing {_T(obj)} item {start}')
                raise
            write(APPEND)
        start += batch_len
";

#[test]
fn batch_appends_nested_for_try_recompiles_equivalent() {
    let band: Vec<BandInterpreter> = resolve_band(&["3.14"], &[]);
    let Some(interpreter): Option<&BandInterpreter> = band.first() else {
        panic!(
            "no CPython 3.14 interpreter resolvable via uv; install one before running this proof"
        );
    };
    let scratch: PathBuf = band_scratch("batch_appends_nested_for_try");
    let (outcome, source): (BandOutcome, String) =
        recompile_equiv_inline(interpreter, BATCH_APPENDS, "_batch_appends", &scratch);

    let outer_loop_count: usize = source
        .matches("for batch in batched(items, self._BATCHSIZE):")
        .count();
    assert_eq!(
        outer_loop_count, 1,
        "outer batch loop must be reconstructed exactly once:\n{source}"
    );
    let inner_loop_count: usize = source
        .matches("for i, x in enumerate(batch, start):")
        .count();
    assert_eq!(
        inner_loop_count, 1,
        "inner batch loop must be reconstructed exactly once:\n{source}"
    );
    assert!(
        !source.contains("if BaseException:"),
        "exception matching must not become a source guard:\n{source}"
    );
    assert!(
        matches!(&outcome, BandOutcome::RecompileEquiv),
        "_batch_appends must recompile equivalently, got {outcome:?}:\n{source}"
    );
}
