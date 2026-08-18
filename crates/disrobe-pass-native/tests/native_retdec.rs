#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{DecompilerBackend, Probe, probe};

#[test]
fn retdec_probe_returns_backend_identifier() {
    let p: Probe = probe(DecompilerBackend::Retdec);
    assert_eq!(p.backend, DecompilerBackend::Retdec);
}

#[test]
#[ignore = "toolchain: needs a retdec install on PATH, which no runner provisions"]
fn real_retdec_decompile_to_c() {}
