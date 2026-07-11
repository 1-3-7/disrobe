#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

use std::path::PathBuf;

use disrobe_pass_dotnet::PeelReport;
use disrobe_pass_dotnet::peel::{
    ConfuserExRecovery, KeyDerivation, PeelStrategy, peel_confuserex_resources,
};
use disrobe_pass_dotnet::peel_by;
use disrobe_pass_dotnet::protectors::Protector;

const HELLOAPP: &str = "../../corpus/dotnet/HelloAppLegacy.confuserex2.dll";
const EDGECASES: &str = "../../corpus/dotnet/megafile/EdgeCases.confuserex2.dll";
const HELLOAPP_BASELINE: &str = "../../corpus/dotnet/HelloAppLegacy.dll";
const RESOURCE_ONLY: &str = "tests/fixtures/confuser_resources/ConfuserResources.confuserex2.dll";
const RESOURCE_PAYLOAD: &str = "tests/fixtures/confuser_resources/ConfuserResourcePayload.bin";

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
        ConfuserExRecovery::BlobExtractedUnknownKey {
            blob_rva,
            blob_size,
            runtime_key_derivation,
            ..
        } => {
            assert_eq!(blob_rva, 0x2080, "blob RVA per ConfuserEx2 layout");
            assert_eq!(
                blob_size, 448,
                "blob size per ConfuserEx2 64-byte alignment"
            );
            assert_eq!(
                runtime_key_derivation,
                KeyDerivation::AntiTamperEncryptedInitializer,
                "this fixture ships the full normal preset; anti-tamper encrypts the resource \
                 initializer, so its static seed remains unresolved"
            );
        }
        ConfuserExRecovery::FullyDecrypted { .. } => {}
        ConfuserExRecovery::NoEncryptedResourceFound => unreachable!(),
    }
}

#[test]
fn helloapp_resource_note_states_the_encrypted_initializer_reason() {
    let bytes: Vec<u8> = load(HELLOAPP);
    let report: PeelReport = peel_by(Protector::ConfuserEx2, &bytes)
        .expect("ConfuserEx2 wired")
        .expect("peel ok");
    let note: &String = report.notes.first().expect("note recorded");
    assert!(
        note.contains("anti-tamper") && note.contains("initializer"),
        "the note must name the encrypted initializer that hides the resource seed; got: {note}"
    );
    assert!(
        !note.to_lowercase().contains("wall"),
        "the note must not describe the result as a wall; got: {note}"
    );
}

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

#[test]
fn resource_only_confuserex2_recovers_embedded_payload_byte_for_byte() {
    let bytes: Vec<u8> = load(RESOURCE_ONLY);
    let expected: Vec<u8> = load(RESOURCE_PAYLOAD);
    let report: PeelReport = peel_by(Protector::ConfuserEx2, &bytes)
        .expect("ConfuserEx2 wired")
        .expect("resource recovery succeeds");
    assert_eq!(report.recovered_resources.len(), 1);
    assert_eq!(
        report.recovered_resources[0].name,
        "ConfuserResources.Payload.bin"
    );
    assert_eq!(report.recovered_resources[0].bytes, expected);
}

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
