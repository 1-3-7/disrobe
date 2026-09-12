#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{DecompilerBackend, Probe, probe};

#[test]
fn ghidra_probe_resolves_to_missing_when_path_lacks_analyzeheadless() {
    let p: Probe = probe(DecompilerBackend::Ghidra);
    assert!(p.backend == DecompilerBackend::Ghidra);
}

#[test]
#[ignore = "toolchain: needs a Ghidra install on PATH, which no runner provisions"]
fn real_ghidra_headless_decompile_on_pe_fixture() {}
