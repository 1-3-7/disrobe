#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_docs_in_private_items,
    clippy::print_stdout
)]

use std::path::{Path, PathBuf};

use disrobe_pass_native::debug_info::{
    PdbProvenanceError, PdbProvenanceField, PdbProvenanceSource,
};
use disrobe_pass_native::{
    Error, PdbBinaryMatch, PdbRecovery, PdbSymbolInfo, PdbTypeKind, recover_pdb, summarize_pdb,
};

const LLVM_PDBUTIL_EVIDENCE: &str = include_str!("fixtures/pdb_cxx_recovery.llvm-pdbutil.txt");

#[test]
fn pdb_provenance_error_remains_typed_at_public_boundary() {
    let error: Error = PdbProvenanceError::SubstringCycle { index: 0x1000 }.into();
    assert!(matches!(
        error,
        Error::PdbProvenance(PdbProvenanceError::SubstringCycle { index: 0x1000 })
    ));
}

fn evidence_value(key: &str) -> &str {
    LLVM_PDBUTIL_EVIDENCE
        .lines()
        .filter_map(|line: &str| line.split_once('='))
        .find(|(candidate, _value): &(&str, &str)| *candidate == key)
        .map_or_else(
            || panic!("missing llvm-pdbutil evidence key {key}"),
            |(_candidate, value): (&str, &str)| value,
        )
}

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
        provenance: disrobe_pass_native::debug_info::PdbBuildProvenance {
            guid_hex: String::new(),
            age: 11,
            dbi_version: disrobe_pass_native::debug_info::PdbVersion {
                major: 0,
                minor: 0,
                build: 0,
                qfe: None,
            },
            modules: Vec::new(),
        },
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

    assert_eq!(rec.summary.age.to_string(), evidence_value("age"));
    assert_eq!(rec.provenance.guid_hex, evidence_value("guid_hex"));
    assert_eq!(
        rec.provenance.dbi_version.to_string(),
        evidence_value("dbi_version")
    );

    let object_module = rec
        .provenance
        .modules
        .iter()
        .find(|module| {
            module.observations.iter().any(|observation| {
                observation.source == PdbProvenanceSource::SObjName
                    && observation.field == PdbProvenanceField::ObjectPath
                    && observation.value.utf8.as_deref() == Some(evidence_value("object"))
            })
        })
        .expect("fixture object module provenance");
    let compiler = object_module
        .compilers
        .iter()
        .find(|compiler| compiler.source == PdbProvenanceSource::SCompile3)
        .expect("fixture S_COMPILE3 compiler provenance");
    assert_eq!(
        compiler.frontend_version.to_string(),
        evidence_value("compiler_frontend")
    );
    assert_eq!(
        compiler.backend_version.to_string(),
        evidence_value("compiler_backend")
    );
    assert_eq!(
        compiler.version_string.utf8.as_deref(),
        Some(evidence_value("compiler_name"))
    );
    assert_eq!(
        compiler.flags.hot_patch.to_string(),
        evidence_value("compiler_hot_patch")
    );

    for (key, source, field) in [
        (
            "working_directory",
            PdbProvenanceSource::LfBuildInfo,
            PdbProvenanceField::WorkingDirectory,
        ),
        (
            "compiler_tool",
            PdbProvenanceSource::LfBuildInfo,
            PdbProvenanceField::ToolPath,
        ),
        (
            "source",
            PdbProvenanceSource::LfBuildInfo,
            PdbProvenanceField::SourcePath,
        ),
        (
            "compiler_pdb",
            PdbProvenanceSource::LfBuildInfo,
            PdbProvenanceField::ProgramDatabasePath,
        ),
        (
            "compiler_arguments",
            PdbProvenanceSource::LfBuildInfo,
            PdbProvenanceField::Arguments,
        ),
    ] {
        assert!(
            object_module.observations.iter().any(|observation| {
                observation.source == source
                    && observation.field == field
                    && observation.value.utf8.as_deref() == Some(evidence_value(key))
            }),
            "missing {source:?} {field:?} observation from llvm-pdbutil evidence"
        );
    }

    let linker_module = rec
        .provenance
        .modules
        .iter()
        .find(|module| module.module_name == "* Linker *")
        .expect("linker module provenance");
    let linker = linker_module
        .compilers
        .iter()
        .find(|compiler| compiler.source == PdbProvenanceSource::SCompile3)
        .expect("linker S_COMPILE3 provenance");
    assert_eq!(
        linker.frontend_version.to_string(),
        evidence_value("linker_frontend")
    );
    assert_eq!(
        linker.backend_version.to_string(),
        evidence_value("linker_backend")
    );
    for (key, field) in [
        ("working_directory", PdbProvenanceField::WorkingDirectory),
        ("linker_tool", PdbProvenanceField::ToolPath),
        ("linker_pdb", PdbProvenanceField::ProgramDatabasePath),
        ("linker_arguments", PdbProvenanceField::Arguments),
    ] {
        assert!(
            linker_module.observations.iter().any(|observation| {
                observation.source == PdbProvenanceSource::SEnvBlock
                    && observation.field == field
                    && observation.value.utf8.as_deref() == Some(evidence_value(key))
            }),
            "missing S_ENVBLOCK {field:?} observation from llvm-pdbutil evidence"
        );
    }
}
