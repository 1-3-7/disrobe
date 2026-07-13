use std::error::Error;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::subprocess::{CapturedOutput, run_captured};
use disrobe_pass_dotnet::peel::dotnet_reactor::peel_dotnet_reactor;
use disrobe_pass_dotnet::peel::{PeelReport, PeelStrategy};

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

type TestResult<T = ()> = std::result::Result<T, Box<dyn Error>>;

const DOTNET_TIMEOUT: Duration = Duration::from_secs(90);
const DOTNET_CAPTURE_LIMIT: usize = 1024 * 1024;

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
fn committed_fixture_runtime_matches_fixed_ground_truth() -> TestResult {
    let runtime_args: [OsString; 1] = [OsString::from("--list-runtimes")];
    let runtimes: Option<CapturedOutput> = match run_captured(
        Path::new("dotnet"),
        &runtime_args,
        DOTNET_TIMEOUT,
        DOTNET_CAPTURE_LIMIT,
    ) {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    let Some(runtimes): Option<CapturedOutput> = runtimes else {
        return Ok(());
    };
    if runtimes.exit_code != Some(0)
        || !String::from_utf8_lossy(&runtimes.stdout)
            .lines()
            .any(|line: &str| line.starts_with("Microsoft.NETCore.App 9."))
    {
        return Ok(());
    }
    let fixture_dir: PathBuf =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dotnet_reactor_strings");
    for name in [
        "ReactorStringsCompat.dll",
        "ReactorStringsAmbiguous.dll",
        "ReactorStringsMixedInstance.dll",
        "ReactorStringsCatch.dll",
        "ReactorStringsDiscarded.dll",
        "ReactorStringsPostSetReverse.dll",
    ] {
        let args: [OsString; 1] = [fixture_dir.join(name).into_os_string()];
        let output: CapturedOutput = run_captured(
            Path::new("dotnet"),
            &args,
            DOTNET_TIMEOUT,
            DOTNET_CAPTURE_LIMIT,
        )?
        .ok_or_else(|| std::io::Error::other(format!("fixture runtime timed out for {name}")))?;
        if output.exit_code != Some(0) {
            return Err(std::io::Error::other(format!(
                "fixture runtime failed for {name}: {}",
                String::from_utf8_lossy(&output.stderr),
            ))
            .into());
        }
        let runtime: Vec<String> = serde_json::from_slice(&output.stdout)?;
        assert_eq!(runtime, expected_strings()?);
    }
    Ok(())
}

#[test]
fn malformed_input_remains_a_hard_error() {
    assert!(peel_dotnet_reactor(b"not a managed assembly").is_err());
}
