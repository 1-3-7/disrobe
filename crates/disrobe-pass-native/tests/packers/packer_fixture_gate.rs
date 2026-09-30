#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use crate::packer_fixture;

use packer_fixture::{
    COMMITTED_FIXTURES, CommittedFixture, PackerFixture, committed_fixture_defect,
    enforce_fixture_requirement,
};

#[test]
fn an_absent_committed_fixture_is_always_fatal() {
    let fixture: PackerFixture<'static> = PackerFixture {
        decoder: "NSPack",
        family: "nspack",
        name: "hash.packed.nspack.exe",
    };
    let outcome: std::thread::Result<()> = std::panic::catch_unwind(|| {
        enforce_fixture_requirement(&fixture, true);
    });
    let Err(payload): std::thread::Result<()> = outcome else {
        panic!("an absent committed fixture was tolerated");
    };
    let message: &str = payload
        .downcast_ref::<String>()
        .map_or("", |text: &String| text.as_str());
    assert!(
        message.contains("tracked in git") && message.contains("hash.packed.nspack.exe"),
        "the panic must name the fixture that caused it and say it is tracked, got {message:?}"
    );
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
