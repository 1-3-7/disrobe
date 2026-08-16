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
const LEADING_TERMINATING_GUARD_WITH: &str = concat!(
    "def gzip_encode(data):\n",
    "    if not gzip:\n",
    "        raise NotImplementedError\n",
    "    sink = BytesIO()\n",
    "    with gzip.GzipFile(mode='wb', fileobj=sink, compresslevel=1) as stream:\n",
    "        stream.write(data)\n",
    "    return sink.getvalue()\n",
);

#[test]
fn leading_terminating_guard_before_with_recompiles_on_310() {
    let band: Vec<BandInterpreter> = resolve_band(CPYTHON_310, &[]);
    assert_eq!(
        band.len(),
        1,
        "CPython 3.10 is required to prove the pre-3.11 guard and with-block recovery"
    );
    let scratch: PathBuf = band_scratch("pre311-terminating-guard-with");
    let (outcome, source): (BandOutcome, String) = recompile_equiv_inline(
        &band[0],
        LEADING_TERMINATING_GUARD_WITH,
        "pre311_terminating_guard_with",
        &scratch,
    );
    assert!(
        matches!(outcome, BandOutcome::RecompileEquiv),
        "CPython 3.10 leading guard before with-block did not recompile equivalently: \
         {outcome:?}\n--- recovered:\n{source}"
    );
    assert!(
        source.contains("if not gzip:") && source.contains("with gzip.GzipFile"),
        "recovered source lost the guarded with-block structure:\n{source}"
    );
}
