#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/packer_fixture.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod packer_fixture;

use std::ffi::OsStr;

use packer_fixture::{
    COMMITTED_FIXTURES, CommittedFixture, FixtureRequirement, PackerFixture, REQUIRE_FIXTURES_VAR,
    committed_fixture_defect, enforce_fixture_requirement, requirement_from_value,
};

#[test]
fn an_absent_committed_fixture_is_fatal_when_the_requirement_is_set() {
    let fixture: PackerFixture<'static> = PackerFixture {
        decoder: "NSPack",
        family: "nspack",
        name: "hash.packed.nspack.exe",
    };
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(|| {
        enforce_fixture_requirement(&fixture, true, FixtureRequirement::Committed);
    });
    let Err(payload): std::thread::Result<()> = outcome else {
        panic!("an absent committed fixture was tolerated while {REQUIRE_FIXTURES_VAR} was set");
    };
    let message: &str = payload
        .downcast_ref::<String>()
        .map_or("", |text: &String| text.as_str());
    assert!(
        message.contains(REQUIRE_FIXTURES_VAR) && message.contains("hash.packed.nspack.exe"),
        "the panic must name the variable and the fixture that caused it, got {message:?}"
    );
}

#[test]
fn an_absent_local_only_fixture_skips_at_the_committed_level_and_fails_at_all() {
    let local_only: PackerFixture<'static> = PackerFixture {
        decoder: "NSPack",
        family: "nspack",
        name: "a-fixture-this-repo-never-commits.packed.nspack.exe",
    };
    enforce_fixture_requirement(&local_only, false, FixtureRequirement::Committed);
    let strict: std::thread::Result<()> = std::panic::catch_unwind(|| {
        enforce_fixture_requirement(&local_only, false, FixtureRequirement::Every);
    });
    assert!(
        strict.is_err(),
        "{REQUIRE_FIXTURES_VAR}=all must reject a fixture that is not committed"
    );
}

#[test]
fn requirement_levels_match_the_documented_spellings() {
    assert_eq!(requirement_from_value(None), FixtureRequirement::Optional);
    for falsey in ["", " ", "0", "false", "FALSE", "no", "off", "optional"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(falsey))),
            FixtureRequirement::Optional,
            "{falsey:?} must not enable the requirement"
        );
    }
    for committed in ["1", "true", "yes", "on", "committed"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(committed))),
            FixtureRequirement::Committed,
            "{committed:?} must require the committed fixtures"
        );
    }
    for every in ["all", "ALL", "every", "local"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(every))),
            FixtureRequirement::Every,
            "{every:?} must require every fixture"
        );
    }
}

#[test]
fn every_committed_packer_fixture_is_present_and_intact() {
    let failures: Vec<String> = COMMITTED_FIXTURES
        .iter()
        .filter_map(committed_fixture_defect)
        .collect();
    assert!(
        failures.is_empty(),
        "committed packer fixtures must be present and unmodified in every checkout: {}",
        failures.join("; ")
    );
}

#[test]
fn each_gated_family_declares_a_packed_sample_and_its_original() {
    for family in ["fsg", "nspack", "petite"] {
        let declared: Vec<&CommittedFixture> = COMMITTED_FIXTURES
            .iter()
            .filter(|f: &&CommittedFixture| f.family == family)
            .collect();
        assert!(
            declared.len() >= 2,
            "{family} must declare both a committed packed sample and the original its recovery \
             is measured against, else no byte figure reproduces from a clean checkout; declared \
             {declared:?}"
        );
    }
}
