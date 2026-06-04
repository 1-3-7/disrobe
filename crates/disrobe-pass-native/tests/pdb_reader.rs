#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use disrobe_pass_native::{
    Error, PdbBinaryMatch, PdbRecovery, PdbSymbolInfo, recover_pdb, summarize_pdb,
};

#[test]
fn pdb_summarize_rejects_random_bytes() {
    let bytes: Vec<u8> = vec![0u8; 4096];
    let err: Error = summarize_pdb(&bytes).expect_err("must reject non-pdb");
    assert!(matches!(err, Error::Pdb(_)));
}

#[test]
fn pdb_recover_rejects_random_bytes() {
    let bytes: Vec<u8> = vec![0u8; 4096];
    let err: Error = recover_pdb(&bytes).expect_err("must reject non-pdb container");
    assert!(
        matches!(err, Error::Pdb(_)),
        "recover_pdb must surface an honest Pdb error on a non-MSF buffer, never a fabricated map",
    );
}

#[test]
fn pdb_age_cross_check_is_non_circular() {
    let rec: PdbRecovery = PdbRecovery {
        summary: disrobe_pass_native::PdbSummary {
            machine: None,
            module_count: 0,
            symbol_count: 0,
            age: 11,
            guid: String::new(),
        },
        symbols: Vec::<PdbSymbolInfo>::new(),
        types: Vec::new(),
    };
    assert_eq!(
        rec.match_binary_age(Some(11)),
        PdbBinaryMatch::AgeMatch,
        "a PDB whose age equals the binary's CodeView age belongs to that binary",
    );
    assert_eq!(rec.match_binary_age(Some(12)), PdbBinaryMatch::AgeMismatch);
    assert_eq!(rec.match_binary_age(None), PdbBinaryMatch::NoBinaryAge);
}

#[test]
#[ignore = "FIXTURE PENDING: real Microsoft PDB file required (cannot synthesize a valid MSF; \
            pdb::SymbolData/TypeData are #[non_exhaustive] so cannot be constructed in-test; \
            no download permitted). recover_pdb's S_PUB32/S_GPROC32/S_LPROC32 + TPI extraction \
            is exercised end-to-end the moment a real .pdb fixture is staged."]
fn real_msvc_pdb_global_symbol_count() {}
