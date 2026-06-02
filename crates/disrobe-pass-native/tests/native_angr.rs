#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{DecompilerBackend, Probe, probe};

#[test]
fn angr_probe_returns_backend_identifier() {
    let p: Probe = probe(DecompilerBackend::Angr);
    assert_eq!(p.backend, DecompilerBackend::Angr);
}

#[test]
#[ignore = "FIXTURE PENDING: angr Python env + sample ELF required"]
fn real_angr_cfg_recovery() {}
