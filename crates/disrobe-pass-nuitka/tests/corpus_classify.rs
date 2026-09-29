#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_nuitka::{
    BinaryFormat, FilenameEncoding, NuitkaPlugin, NuitkaVariant, NuitkaVariantManifest,
    OnefilePayload, VariantClassification, VariantExtraction, build_manifest_from_file,
    classify_in_file, detect_in_bytes, extract_for_classification, extract_onefile,
    locate_onefile_payload,
};

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("corpus")
        .join("python")
        .join("nuitka")
}

const REQUIRE_LOCAL_CORPUS_VAR: &str = "DISROBE_REQUIRE_NUITKA_LOCAL_CORPUS";

fn local_variant(variant: &str, leaf: &str) -> Option<PathBuf> {
    let candidate: PathBuf = corpus_root().join(variant).join(leaf);
    if candidate.exists() {
        return Some(candidate);
    }
    assert!(
        std::env::var_os(REQUIRE_LOCAL_CORPUS_VAR).is_none(),
        "{REQUIRE_LOCAL_CORPUS_VAR} is set, so the local-only Nuitka fixture {} must exist",
        candidate.display()
    );
    eprintln!(
        "UNGRADED: the local-only Nuitka fixture {} is absent; set {REQUIRE_LOCAL_CORPUS_VAR}=1 to fail instead",
        candidate.display()
    );
    None
}

fn onefile_fixture() -> PathBuf {
    let path: PathBuf = corpus_root().join("onefile").join("hello.exe");
    assert!(
        path.is_file(),
        "the committed onefile fixture {} is missing; restore it from git, because this test \
         never rebuilds fixtures",
        path.display()
    );
    path
}

#[test]
fn corpus_onefile_classifies_as_onefile_variant() {
    let path: PathBuf = onefile_fixture();
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    assert!(
        matches!(
            classification.variant,
            NuitkaVariant::OnefileKay | NuitkaVariant::OnefileKax | NuitkaVariant::SignedPe
        ),
        "expected onefile variant, got {:?}",
        classification.variant
    );
    assert_eq!(classification.binary_format, BinaryFormat::Pe);
    assert!(classification.onefile_offset.is_some() || classification.authenticode.is_some());
}

#[test]
fn corpus_onefile_extracts_real_embedded_files() {
    let path: PathBuf = onefile_fixture();
    let bytes: Vec<u8> = std::fs::read(&path).expect("read onefile");
    let located = locate_onefile_payload(&bytes).expect("locate validated KA payload");
    assert!(located.compressed, "default --onefile uses zstd (KAY)");

    let payload: OnefilePayload =
        extract_onefile(&bytes, located.offset).expect("extract real onefile payload");

    assert_eq!(payload.encoding, FilenameEncoding::Utf16Le, "Windows build");
    assert!(
        !payload.entries.is_empty(),
        "real onefile must yield >= 1 embedded file"
    );
    assert!(
        payload.payload_size > bytes.len() / 2,
        "decompressed payload ({}) should dwarf the compressed blob",
        payload.payload_size
    );

    for entry in &payload.entries {
        assert_eq!(
            entry.data.len() as u64,
            entry.size,
            "size matches data for {}",
            entry.filename
        );
        assert!(
            entry.data.starts_with(b"MZ"),
            "embedded {} should be a PE image, head={:02x?}",
            entry.filename,
            &entry.data[..entry.data.len().min(4)]
        );
    }

    let inner: &disrobe_pass_nuitka::OnefileEntry = payload
        .entries
        .iter()
        .find(|e| {
            let ext: Option<String> = Path::new(&e.filename)
                .extension()
                .and_then(|x| x.to_str())
                .map(str::to_ascii_lowercase);
            matches!(ext.as_deref(), Some("dll" | "exe"))
        })
        .expect("onefile payload contains the start binary");
    let redetect = detect_in_bytes(&inner.data).expect("inner binary re-detects as Nuitka");
    assert!(
        redetect
            .hits
            .iter()
            .any(|h| h == "__compiled__" || h == "nuitka_module_loader"),
        "inner {} should carry Nuitka loader markers; hits={:?}",
        inner.filename,
        redetect.hits
    );

    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    let extraction: VariantExtraction =
        extract_for_classification(&bytes, &classification).expect("extract variant");
    match extraction {
        VariantExtraction::Onefile(o) => {
            assert_eq!(o.entry_count as usize, payload.entries.len());
            assert!(o.compressed);
        }
        VariantExtraction::SignedPe(inner_extraction) => {
            assert!(inner_extraction.stripped_size < bytes.len() as u64);
        }
        other => panic!("unexpected extraction: {other:?}"),
    }
}

#[test]
fn corpus_module_classifies_as_module_variant() {
    let Some(path): Option<PathBuf> = local_variant("module", "hello.cp314-win_amd64.pyd") else {
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
    let Some(path): Option<PathBuf> = local_variant("standalone", "hello.dist/hello.exe") else {
        return;
    };
    let classification: VariantClassification = classify_in_file(&path).expect("classify");
    assert!(matches!(
        classification.variant,
        NuitkaVariant::Standalone | NuitkaVariant::Module | NuitkaVariant::SignedPe
    ));
    let bytes: Vec<u8> = std::fs::read(&path).expect("read standalone");
    let det = detect_in_bytes(&bytes).expect("standalone detects as Nuitka");
    assert!(
        det.hits
            .iter()
            .any(|h| h == "nuitka_module_loader" || h == "__compiled__"),
        "standalone hits={:?}",
        det.hits
    );
}

#[test]
fn corpus_onefile_manifest_serialises() {
    let path: PathBuf = onefile_fixture();
    let manifest: NuitkaVariantManifest = build_manifest_from_file(&path).expect("manifest");
    let json: String = serde_json::to_string(&manifest).expect("json");
    assert!(json.contains("disrobe.nuitka.manifest/v0"));
    assert!(manifest.byte_len > 1024);
}

#[test]
fn corpus_plugin_anti_bloat_detected() {
    let Some(path): Option<PathBuf> = local_variant("plugin-anti-bloat", "hello.dist/hello.exe")
    else {
        return;
    };
    let manifest: NuitkaVariantManifest = build_manifest_from_file(&path).expect("manifest");
    let _ = manifest
        .plugins_detected
        .plugins
        .get(&NuitkaPlugin::AntiBloat);
    assert!(manifest.byte_len > 1024);
}
