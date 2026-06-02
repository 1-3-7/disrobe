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
#[ignore = "FIXTURE PENDING: rizin installation + sample ELF needed for pdc round trip"]
fn real_rizin_pdc_round_trip() {}
