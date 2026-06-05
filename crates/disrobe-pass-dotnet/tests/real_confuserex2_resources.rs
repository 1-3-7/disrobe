#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Real ConfuserEx2 resource extraction against the in-repo confuserex2 fixtures.

use std::path::PathBuf;

use disrobe_pass_dotnet::PeelReport;
use disrobe_pass_dotnet::peel::{ConfuserExRecovery, PeelStrategy, peel_confuserex_resources};
use disrobe_pass_dotnet::peel_by;
use disrobe_pass_dotnet::protectors::Protector;

const HELLOAPP: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";
const EDGECASES: &str = "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll";
const HELLOAPP_BASELINE: &str = "../../corpus/dotnet/HelloAppLegacy.dll";

fn load(rel: &str) -> Vec<u8> {
    let mut path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(rel);
    std::fs::read(&path).unwrap_or_else(|e: std::io::Error| {
        panic!("read fixture {} ({}): {e}", rel, path.display())
    })
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s: String = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Byte-exact extraction of the encrypted ConfuserEx2 resource blob from `HelloAppLegacy.confuserex2.dll`.
#[test]
fn helloapp_confuserex2_extracts_encrypted_resource_blob_byte_exact() {
    let bytes: Vec<u8> = load(HELLOAPP);
    let recovery: ConfuserExRecovery =
        peel_confuserex_resources(&bytes).expect("peel confuserex resources");
    assert!(
        recovery.blob_located(),
        "blob must be located in HelloAppLegacy.confuserex2; got {recovery:?}"
    );
    let sha: [u8; 32] = recovery
        .blob_sha256()
        .expect("blob_sha256 present when blob located");
    assert_eq!(
        hex(&sha),
        "0e4ac46b30c70ff0e7683dc5f9ae47714a9151c3caaacdae399242e395a2922b",
        "encrypted blob bytes must hash to the stable real-fixture value"
    );
    match recovery {
        ConfuserExRecovery::BlobExtractedKeyedWall {
            blob_rva,
            blob_size,
            ..
        } => {
            assert_eq!(blob_rva, 0x2080, "blob RVA per ConfuserEx2 layout");
            assert_eq!(
                blob_size, 448,
                "blob size per ConfuserEx2 64-byte alignment"
            );
        }
        ConfuserExRecovery::FullyDecrypted { .. } => {}
        ConfuserExRecovery::NoEncryptedResourceFound => unreachable!(),
    }
}

/// Byte-exact blob extraction from the `EdgeCases.confuserex2.dll` megafile fixture.
#[test]
fn edgecases_confuserex2_extracts_encrypted_resource_blob_byte_exact() {
    let bytes: Vec<u8> = load(EDGECASES);
    let recovery: ConfuserExRecovery =
        peel_confuserex_resources(&bytes).expect("peel confuserex resources");
    assert!(
        recovery.blob_located(),
        "blob must be located in EdgeCases.confuserex2; got {recovery:?}"
    );
    let sha: [u8; 32] = recovery
        .blob_sha256()
        .expect("blob_sha256 present when blob located");
    assert_eq!(
        hex(&sha),
        "621c1b23909a4b3503d5fd3442ae257eece6611f45e6189006e0fe0dc9c6b1a1",
        "encrypted blob bytes must hash to the stable real-fixture value"
    );
}

/// The baseline `HelloAppLegacy.dll` must not yield a false-positive blob extraction.
#[test]
fn baseline_helloapp_yields_no_encrypted_resource() {
    let bytes: Vec<u8> = load(HELLOAPP_BASELINE);
    let recovery: ConfuserExRecovery =
        peel_confuserex_resources(&bytes).expect("peel ok on clean baseline");
    assert!(
        matches!(recovery, ConfuserExRecovery::NoEncryptedResourceFound),
        "baseline PE must not be reported as ConfuserEx2 encrypted; got {recovery:?}"
    );
}

/// End-to-end: `peel_by` routes ConfuserEx2 to the resource peeler and surfaces `EncryptedResourceExtracted`.
#[test]
fn peel_by_confuserex2_returns_encrypted_resource_strategy() {
    let bytes: Vec<u8> = load(HELLOAPP);
    let result: PeelReport = peel_by(Protector::ConfuserEx2, &bytes)
        .expect("ConfuserEx2 must be wired in peel_by")
        .expect("peel must succeed");
    assert_eq!(result.protector, Protector::ConfuserEx2);
    assert!(
        matches!(result.strategy, PeelStrategy::EncryptedResourceExtracted),
        "ConfuserEx2 peel must report EncryptedResourceExtracted; got {:?}",
        result.strategy
    );
    let note: &String = result.notes.first().expect("note recorded");
    assert!(
        note.contains("blob_rva=0x2080") && note.contains("size=448"),
        "note must carry the byte-exact extraction provenance; got: {note}"
    );
}

/// Commercial protectors must remain report-only-encrypted-resource (keyed wall).
#[test]
fn commercial_protectors_remain_report_only_encrypted_resource() {
    let dummy: Vec<u8> = load(HELLOAPP);
    for protector in [
        Protector::DotnetReactor,
        Protector::EazfuscatorNet,
        Protector::CryptoObfuscator,
        Protector::AgileNet,
        Protector::BabelDotnet,
        Protector::SmartAssembly,
    ] {
        let report: PeelReport = peel_by(protector, &dummy)
            .expect("protector wired")
            .expect("peel ok on managed PE");
        assert!(
            matches!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource),
            "{:?} must remain ReportOnlyEncryptedResource (commercial protector keyed wall); \
             got {:?}",
            protector,
            report.strategy
        );
    }
}
