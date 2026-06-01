#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{Error, summarize_pdb};

#[test]
fn pdb_summarize_rejects_random_bytes() {
    let bytes: Vec<u8> = vec![0u8; 4096];
    let err: Error = summarize_pdb(&bytes).expect_err("must reject non-pdb");
    assert!(matches!(err, Error::Pdb(_)));
}

#[test]
#[ignore = "FIXTURE PENDING: real Microsoft PDB file required (cannot synthesize valid MSF)"]
fn real_msvc_pdb_global_symbol_count() {}
