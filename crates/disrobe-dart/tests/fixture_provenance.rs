use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, Deserialize)]
struct ProvenanceOracle {
    perturbation: Perturbation,
    builds: Vec<ProvenanceBuild>,
}

#[derive(Debug, Clone, Deserialize)]
struct Perturbation {
    from: String,
    to: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ProvenanceBuild {
    name: String,
    source: String,
    artifact: String,
    sha256: String,
}

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("flutter_3_44_6")
        .join(name)
}

fn oracle() -> TestResult<ProvenanceOracle> {
    let bytes: Vec<u8> = fs::read(fixture("oracle.json"))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn oracle_build(oracle: &ProvenanceOracle, name: &str) -> TestResult<ProvenanceBuild> {
    oracle
        .builds
        .iter()
        .find(|build: &&ProvenanceBuild| build.name == name)
        .cloned()
        .ok_or_else(|| std::io::Error::other("oracle build is absent").into())
}

fn sha256(name: &str) -> TestResult<String> {
    let bytes: Vec<u8> = fs::read(fixture(name))?;
    let digest: sha2::digest::Output<Sha256> = Sha256::digest(bytes);
    Ok(format!("{digest:x}"))
}

#[test]
fn real_flutter_artifacts_match_recorded_hashes() -> TestResult {
    let oracle: ProvenanceOracle = oracle()?;
    for build in oracle.builds {
        assert_eq!(sha256(&build.artifact)?, build.sha256);
    }
    Ok(())
}

#[test]
fn perturbation_sources_differ_only_by_validator_name() -> TestResult {
    let oracle: ProvenanceOracle = oracle()?;
    let source_build: ProvenanceBuild = oracle_build(&oracle, "source")?;
    let renamed_build: ProvenanceBuild = oracle_build(&oracle, "renamed")?;
    let source: String = fs::read_to_string(fixture(&source_build.source))?;
    let renamed: String = fs::read_to_string(fixture(&renamed_build.source))?;
    assert!(source.contains(&oracle.perturbation.from));
    assert!(!source.contains(&oracle.perturbation.to));
    assert!(!renamed.contains(&oracle.perturbation.from));
    assert!(renamed.contains(&oracle.perturbation.to));
    assert_eq!(
        source.replace(&oracle.perturbation.from, &oracle.perturbation.to),
        renamed
    );
    Ok(())
}
