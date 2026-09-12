#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{DecompilerBackend, Probe, probe};

#[test]
fn rizin_probe_returns_backend_identifier() {
    let p: Probe = probe(DecompilerBackend::Rizin);
    assert_eq!(p.backend, DecompilerBackend::Rizin);
}

#[test]
#[ignore = "toolchain: needs a rizin install on PATH, which no runner provisions"]
fn real_rizin_pdc_round_trip() {}
