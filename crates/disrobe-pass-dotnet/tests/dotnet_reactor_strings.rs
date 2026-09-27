use std::error::Error;

use disrobe_pass_dotnet::peel::dotnet_reactor::peel_dotnet_reactor;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const FIXTURE: &[u8] = include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsCompat.dll");
const AMBIGUOUS_FIXTURE: &[u8] =
    include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsAmbiguous.dll");
const MIXED_INSTANCE_FIXTURE: &[u8] =
    include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsMixedInstance.dll");
const CATCH_FIXTURE: &[u8] =
    include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsCatch.dll");
const DISCARDED_FIXTURE: &[u8] =
    include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsDiscarded.dll");
const POST_SET_REVERSE_FIXTURE: &[u8] =
    include_bytes!("fixtures/dotnet_reactor_strings/ReactorStringsPostSetReverse.dll");
const EXPECTED_JSON: &str = include_str!("fixtures/dotnet_reactor_strings/expected.json");
const MANIFEST: &str = include_str!("fixtures/dotnet_reactor_strings/MANIFEST.toml");

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Deserialize)]
struct FixtureManifest {
    fixture: Vec<PinnedFixture>,
}

#[derive(Debug, Deserialize)]
struct PinnedFixture {
    name: String,
    sha256: String,
}

fn expected_strings() -> TestResult<Vec<String>> {
    Ok(serde_json::from_str(EXPECTED_JSON)?)
}

#[test]
fn reactor_static_strings_match_committed_clr_fixture() -> TestResult {
    let expected: Vec<String> = expected_strings()?;
    let report: PeelReport = peel_dotnet_reactor(FIXTURE)?;
    let recovered: Vec<String> = report
        .recovered_strings
        .iter()
        .map(|value| value.text.clone())
        .collect();
    assert_eq!(
        recovered, expected,
        "Reactor static string recovery must select the reachable resource/key/IV tuple and ignore the valid disconnected decoy tuple: {report:#?}"
    );
    assert!(
        report
            .recovered_strings
            .iter()
            .all(|value| value.method_name == "reactor-static-strings")
    );
    assert_eq!(report.strategy, PeelStrategy::EncryptedResourceExtracted);
    Ok(())
}

#[test]
fn reactor_two_reachable_tuples_remain_unknown() -> TestResult {
    let report: PeelReport = peel_dotnet_reactor(AMBIGUOUS_FIXTURE)?;
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("Unknown: Reactor static analysis found 2 distinct resource/key/IV tuples")
    }));
    Ok(())
}

#[test]
fn reactor_mixed_aes_instances_remain_unknown() -> TestResult {
    let report: PeelReport = peel_dotnet_reactor(MIXED_INSTANCE_FIXTURE)?;
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(report.notes.iter().any(|note: &String| {
        note.contains(
            "Unknown: Reactor System.Security.Cryptography.Aes::Create has 2 reachable calls",
        )
    }));
    Ok(())
}

#[test]
fn reactor_catch_path_remains_unknown() -> TestResult {
    let report: PeelReport = peel_dotnet_reactor(CATCH_FIXTURE)?;
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("Unknown: Reactor helper contains exception regions")
    }));
    Ok(())
}

#[test]
fn reactor_reachable_discarded_tuple_remains_unknown() -> TestResult {
    let report: PeelReport = peel_dotnet_reactor(DISCARDED_FIXTURE)?;
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(
        report.notes.iter().any(|note: &String| {
            note.contains("Unknown: Reactor string entry has 19 semantic instructions")
        }),
        "{report:#?}"
    );
    Ok(())
}

#[test]
fn reactor_post_set_iv_reversal_remains_unknown() -> TestResult {
    let report: PeelReport = peel_dotnet_reactor(POST_SET_REVERSE_FIXTURE)?;
    assert!(report.recovered_strings.is_empty());
    assert_eq!(report.strategy, PeelStrategy::ReportOnlyEncryptedResource);
    assert!(report.notes.iter().any(|note: &String| {
        note.contains("Unknown: Reactor decryption provenance does not dominate the returned bytes")
    }));
    Ok(())
}

#[test]
fn committed_fixtures_match_the_digests_their_manifest_pins() -> TestResult {
    let lf_expected_json: String = EXPECTED_JSON.replace("\r\n", "\n");
    let fixtures: [(&str, &[u8], &str); 7] = [
        (
            "expected.json",
            lf_expected_json.as_bytes(),
            "16c59ae88f6bedff6a6656afb6ba6dec47a4ebbc1a4c9671e5e54d1d6282b3d0",
        ),
        (
            "ReactorStringsCompat.dll",
            FIXTURE,
            "2dc53f5906042ffe72f72bf2c4d90c82dbac9e9a4d341516f9fac9fb12de6b4f",
        ),
        (
            "ReactorStringsAmbiguous.dll",
            AMBIGUOUS_FIXTURE,
            "8a5a68fbe657e23c7b7b98cad86c2091d43685be5b84e441a0bb58007fb90fb7",
        ),
        (
            "ReactorStringsMixedInstance.dll",
            MIXED_INSTANCE_FIXTURE,
            "2610d3ea0d62e6c37067a5076c4d2136423487025c0a0e01b5c97e07ca81abbd",
        ),
        (
            "ReactorStringsCatch.dll",
            CATCH_FIXTURE,
            "98acdc150f2d9151975c0264056ac7b557d04d530ab815aad3dd8f47f01939c1",
        ),
        (
            "ReactorStringsDiscarded.dll",
            DISCARDED_FIXTURE,
            "ade436fd2a3e0d5fffa83596bb2d2205609e57fc3d8ca7029e23f14f6a6210b8",
        ),
        (
            "ReactorStringsPostSetReverse.dll",
            POST_SET_REVERSE_FIXTURE,
            "89717d35f8b2ec98c95f9556bac584b235a74fa30a08fa760d68ad32ca839538",
        ),
    ];
    let manifest: FixtureManifest = toml::from_str(MANIFEST)?;
    for (name, bytes, pinned) in fixtures {
        let digest: String = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(
            digest, pinned,
            "{name} is not the build whose CLR output expected.json records; rebuild it with \
             build.ps1 and re-pin it here and in MANIFEST.toml"
        );
        let entry: &PinnedFixture = manifest
            .fixture
            .iter()
            .find(|entry: &&PinnedFixture| entry.name == name)
            .ok_or_else(|| format!("MANIFEST.toml has no [[fixture]] block named {name}"))?;
        assert_eq!(
            entry.sha256, pinned,
            "the [[fixture]] block for {name} in MANIFEST.toml must pin {pinned}"
        );
    }
    Ok(())
}

#[test]
fn malformed_input_remains_a_hard_error() {
    assert!(peel_dotnet_reactor(b"not a managed assembly").is_err());
}
