#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::path::{Path, PathBuf};

use disrobe_pass_native::{
    Error, PdbBinaryMatch, PdbRecovery, PdbSymbolInfo, PdbTypeKind, recover_pdb, summarize_pdb,
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
fn real_msvc_pdb_global_symbol_count() {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("pdb_cxx_recovery.pdb");
    let bytes: Vec<u8> =
        std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture pdb at {path:?}: {e}"));
    let rec: PdbRecovery = recover_pdb(&bytes).expect("recover a real, freshly-compiled MSVC pdb");
    assert!(
        rec.summary.symbol_count > 0,
        "a real MSVC-linked pdb must expose at least one global/public/procedure symbol"
    );
    assert!(
        rec.named_symbol_count() > 0,
        "recovered symbols must include named entries, not just placeholders"
    );
    let has_node_class: bool = rec
        .types
        .iter()
        .any(|t| t.kind == PdbTypeKind::Struct && t.name == "Node");
    assert!(
        has_node_class,
        "TPI extraction must surface the fixture's Node struct: {:?}",
        rec.types
    );
}
