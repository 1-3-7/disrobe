#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/pinned_dart_graph_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod pinned_dart_graph_fixture;

use sha2::{Digest as _, Sha256};

use pinned_dart_graph_fixture::{
    RecoveryBuild, RecoveryOracle, oracle_build, read_tracked, read_tracked_text, recovery_oracle,
    relative,
};

fn sha256(name: &str) -> String {
    let bytes: Vec<u8> = read_tracked(name);
    let digest: sha2::digest::Output<Sha256> = Sha256::digest(bytes);
    format!("{digest:x}")
}

#[test]
fn real_flutter_artifacts_match_recorded_hashes() {
    let oracle: RecoveryOracle = recovery_oracle();
    for build in &oracle.builds {
        assert_eq!(
            sha256(&build.artifact),
            build.sha256,
            "{} is not the file every pinned figure was measured against; restore the committed \
             bytes, or re-measure every figure and re-pin this digest in the same change",
            relative(&build.artifact)
        );
    }
}

#[test]
fn perturbation_sources_differ_only_by_validator_name() {
    let oracle: RecoveryOracle = recovery_oracle();
    let source_build: RecoveryBuild = oracle_build(&oracle, "source");
    let renamed_build: RecoveryBuild = oracle_build(&oracle, "renamed");
    let source: String = read_tracked_text(&source_build.source);
    let renamed: String = read_tracked_text(&renamed_build.source);
    assert!(source.contains(&oracle.perturbation.from));
    assert!(!source.contains(&oracle.perturbation.to));
    assert!(!renamed.contains(&oracle.perturbation.from));
    assert!(renamed.contains(&oracle.perturbation.to));
    assert_eq!(
        source.replace(&oracle.perturbation.from, &oracle.perturbation.to),
        renamed
    );
}
