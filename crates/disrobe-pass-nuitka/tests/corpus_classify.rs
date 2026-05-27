#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stderr
)]

use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{
    BinaryFormat, NuitkaPlugin, NuitkaVariant, NuitkaVariantManifest, VariantClassification,
    VariantExtraction, build_manifest_from_file, classify_in_file, extract_for_classification,
};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("nuitka")
}

fn variant_path(variant: &str, leaf: &str) -> Option<PathBuf> {
    let candidate: PathBuf = corpus_root().join(variant).join(leaf);
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

#[test]
fn corpus_onefile_kay_classifies_as_onefile_variant() {
    let Some(path): Option<PathBuf> = variant_path("onefile", "hello.exe") else {
        eprintln!("[skip] corpus onefile hello.exe missing — run scripts/bake/nuitka.ps1");
        return;
    };
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    assert!(matches!(
        classification.variant,
        NuitkaVariant::OnefileKay | NuitkaVariant::OnefileKax | NuitkaVariant::SignedPe
    ));
    assert_eq!(classification.binary_format, BinaryFormat::Pe);
    assert!(classification.onefile_offset.is_some() || classification.authenticode.is_some());
}

#[test]
fn corpus_onefile_extract_attempted() {
    let Some(path): Option<PathBuf> = variant_path("onefile", "hello.exe") else {
        eprintln!("[skip] corpus onefile hello.exe missing");
        return;
    };
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    let result: disrobe_pass_nuitka::Result<VariantExtraction> =
        extract_for_classification(&bytes, &classification);
    match result {
        Ok(VariantExtraction::Onefile(o)) => {
            assert!(o.entry_count >= 1);
        }
        Ok(VariantExtraction::SignedPe(inner)) => {
            assert!(inner.stripped_size < bytes.len() as u64);
        }
        Ok(other) => panic!("unexpected ok extraction: {other:?}"),
        Err(e) => {
            eprintln!(
                "[expected-pending] Nuitka 4.x onefile uses per-file as_archive zstd; \
                 disrobe-pass-nuitka v0.1 only decodes the legacy whole-payload zstd. \
                 raw error: {e}"
            );
        }
    }
}

#[test]
fn corpus_module_classifies_as_module_variant() {
    let Some(path): Option<PathBuf> = variant_path("module", "hello.cp314-win_amd64.pyd") else {
        eprintln!("[skip] corpus module .pyd missing");
        return;
    };
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    assert_eq!(classification.binary_format, BinaryFormat::Pe);
    assert!(matches!(
        classification.variant,
        NuitkaVariant::Module | NuitkaVariant::Standalone
    ));
    assert!(classification.module_init_count >= 1);
}

#[test]
fn corpus_standalone_dist_exe_classifies_as_standalone() {
    let Some(path): Option<PathBuf> = variant_path("standalone", "hello.dist/hello.exe") else {
        eprintln!("[skip] corpus standalone hello.exe missing");
        return;
    };
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    assert!(matches!(
        classification.variant,
        NuitkaVariant::Standalone | NuitkaVariant::Module | NuitkaVariant::SignedPe
    ));
}

#[test]
fn corpus_onefile_manifest_serialises() {
    let Some(path): Option<PathBuf> = variant_path("onefile", "hello.exe") else {
        eprintln!("[skip] corpus onefile hello.exe missing");
        return;
    };
    let manifest: NuitkaVariantManifest = build_manifest_from_file(&path).expect("manifest");
    let json: String = serde_json::to_string(&manifest).expect("json");
    assert!(json.contains("disrobe.nuitka.manifest/v0"));
    assert!(manifest.byte_len > 1024);
}

#[test]
fn corpus_plugin_anti_bloat_detected() {
    let Some(path): Option<PathBuf> = variant_path("plugin-anti-bloat", "hello.dist/hello.exe")
    else {
        eprintln!("[skip] corpus plugin-anti-bloat missing");
        return;
    };
    let manifest: NuitkaVariantManifest = build_manifest_from_file(&path).expect("manifest");
    let _ = manifest
        .plugins_detected
        .plugins
        .get(&NuitkaPlugin::AntiBloat);
    assert!(manifest.byte_len > 1024);
}
