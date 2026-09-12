#![cfg(not(feature = "wasm"))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use common::{Run, run_disrobe};

#[test]
fn wasm_subcommand_reports_not_compiled_in_slim_build() {
    let r: Run = run_disrobe(&["wasm", "decompile", "does-not-exist.wasm"]);
    assert_ne!(
        r.code, 0,
        "slim wasm dispatch must fail; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stderr.contains("not compiled into this binary"),
        "slim wasm dispatch must report the missing pass; stderr={}",
        r.stderr
    );
    assert!(
        r.stderr.contains("wasm"),
        "slim wasm dispatch must name the feature; stderr={}",
        r.stderr
    );
}
