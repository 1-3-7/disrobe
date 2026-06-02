#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    clippy::doc_markdown
)]

//! Real ConfuserEx2 resource extraction against the in-repo fixtures
//! `corpus/dotnet/HelloAppLegacy.confuserex2.dll` and
//! `corpus/dotnet/megafile/EdgeCases.confuserex2.dll`.
//!
//! Both fixtures were produced by ConfuserEx2 1.6.0 with the "normal" preset, which layers
//! Constants protection over Resources protection. The Constants encoder is invoked as a
//! writer-event hook ordered after the Resources protection's `IConstantService.ExcludeMethod`
//! registration, so in practice it rewrites the resources init `ldc.i4 keySeed` even though the
//! exclude API was called: static keySeed recovery against the layered "normal" preset is
//! therefore documented as keyed-wall in `peel/confuserex_resources.rs`. The honest, mutation-
//! proof real assertion here is that the encrypted resource blob is located and extracted
//! byte-exactly from the PE (the work-product), with a stable SHA-256 over the blob bytes.

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

/// Byte-exact extraction of the encrypted ConfuserEx2 resource blob from
/// `HelloAppLegacy.confuserex2.dll`. The recovered blob lives at field-RVA 0x2080 and is exactly
/// 448 bytes (= 7 blocks of 16 uint32) per the deterministic ConfuserEx2 layout
/// (`Confuser.Protections/Resources/MDPhase.cs::OnWriterEvent`: `compressedLen` rounded up to
/// `0x10` uint32 words). The SHA-256 below was computed once from the live fixture bytes and is
/// the load-bearing assertion - mutating the expected hex by a single nibble reds the test, so
/// the byte-exact recovery is mutation-proof.
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

/// Same as above but for the larger `EdgeCases.confuserex2.dll` megafile fixture. Blob lives at
/// RVA 0x2430, size 448.
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

/// Non-ConfuserEx2 fixture (the baseline `HelloAppLegacy.dll`) must NOT yield a false-positive
/// blob extraction: the shape predicate must reject every other managed PE.
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

/// End-to-end via the public `peel_by` dispatcher: ConfuserEx2 enum routes to the new
/// resource-aware peeler and surfaces the `EncryptedResourceExtracted` strategy when the blob is
/// present in the input.
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

/// Honest report-only for the commercial protectors must remain in place - they require a runtime
/// loader key (Reactor) / homomorphic VM (Eazfuscator) / native loader hook (Agile) and CANNOT be
/// statically decrypted. The test guards against any future regression that silently fakes
/// decryption.
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
