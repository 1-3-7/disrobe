#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/pyarmor_corpus_manifest.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod pyarmor_corpus_manifest;

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use pyarmor_corpus_manifest::{
    CorpusManifest, CorpusVersion, Fixture, ResolvedFixture, read_manifest, repo_root,
    verified_fixtures, verify_file_identity,
};

const EXPECTED_NAMED_TRIAL_WRAPPERS: usize = 72;

#[test]
fn typed_manifest_is_the_named_v8_v9_trial_wrapper_population() {
    let manifest: CorpusManifest = read_manifest();
    let fixtures: Vec<ResolvedFixture> = verified_fixtures(&manifest);
    assert_eq!(
        manifest.meta.license_type, "pyarmor-trial",
        "the public PyArmor evidence is scoped to the named committed trial-wrapper roster"
    );
    assert_eq!(
        manifest.meta.total_fixtures, EXPECTED_NAMED_TRIAL_WRAPPERS,
        "the named v8/v9 trial-wrapper denominator must remain pinned instead of shrinking with the manifest"
    );
    assert_eq!(
        fixtures.len(),
        EXPECTED_NAMED_TRIAL_WRAPPERS,
        "the typed manifest and committed v8/v9 wrapper tree must preserve the published named trial-wrapper population"
    );
    let versions: BTreeSet<CorpusVersion> = fixtures
        .iter()
        .map(|fixture| fixture.pyarmor_version)
        .collect();
    assert_eq!(
        versions,
        BTreeSet::from([CorpusVersion::V8, CorpusVersion::V9]),
        "the named structural corpus contains only the v8 and v9 trial-wrapper populations"
    );
}

#[test]
fn wrapper_identity_rejects_a_byte_mutation() {
    let manifest: CorpusManifest = read_manifest();
    let fixture: &Fixture = manifest
        .fixture
        .first()
        .expect("the pinned PyArmor corpus contains at least one fixture");
    let path: PathBuf = repo_root().join(&fixture.output_path);
    let mut bytes: Vec<u8> = fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!("{} is unreadable: {error}", path.display())
    });
    let last: usize = bytes
        .len()
        .checked_sub(1)
        .expect("the named wrapper has at least one byte");
    bytes[last] ^= 0x01;
    assert!(
        verify_file_identity(
            &fixture.output_path,
            &bytes,
            fixture.output_bytes,
            &fixture.output_sha256,
        )
        .is_err(),
        "the manifest identity grader must reject a one-byte mutation of a real named wrapper"
    );
}

#[test]
fn manifest_roster_rejects_a_coherently_shrunk_population() {
    let mut manifest: CorpusManifest = read_manifest();
    let removed: Fixture = manifest
        .fixture
        .pop()
        .expect("the pinned PyArmor corpus contains at least one fixture");
    manifest.meta.total_fixtures = manifest
        .meta
        .total_fixtures
        .checked_sub(1)
        .expect("the pinned PyArmor corpus has a positive fixture count");
    match removed.pyarmor_version {
        CorpusVersion::V8 => {
            manifest.meta.v8_fixtures = manifest
                .meta
                .v8_fixtures
                .checked_sub(1)
                .expect("the removed v8 fixture is represented in the pinned v8 count");
        }
        CorpusVersion::V9 => {
            manifest.meta.v9_fixtures = manifest
                .meta
                .v9_fixtures
                .checked_sub(1)
                .expect("the removed v9 fixture is represented in the pinned v9 count");
        }
    }
    let result: std::thread::Result<Vec<ResolvedFixture>> =
        std::panic::catch_unwind(|| verified_fixtures(&manifest));
    let failure: Box<dyn std::any::Any + Send> = result.expect_err(
        "the manifest/discovery equality gate must reject a coherently shrunk declared population",
    );
    let message: &str = failure
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| failure.downcast_ref::<&str>().copied())
        .expect("the roster gate must panic with a text message");
    assert!(
        message.contains(
            "corpus/python/pyarmor/MANIFEST.toml and the committed v8/v9 wrapper tree name different populations"
        ),
        "the coherently shrunk population must fail at declared/discovered roster equality, got: {message}"
    );
}
