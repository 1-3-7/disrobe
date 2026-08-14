#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::ffi::OsStr;

use ruby_toolchain::{
    MRI, MRI_MEASURED_SERIES, Toolchain, ToolchainBanner, ToolchainRequirement,
    require_measured_series, require_with_requirement, requirement_from_value,
};

const ABSENT: Toolchain = Toolchain {
    program: "disrobe-ruby-interpreter-that-is-not-installed",
    require_var: "DISROBE_REQUIRE_RUBY",
    install_hint: "nothing, this name exists only to stand in for an absent interpreter",
};

const PROOF_SUBJECT: &str = "this requirement proof";

fn panic_message(outcome: &std::thread::Result<Option<ToolchainBanner>>) -> String {
    let Err(payload): &std::thread::Result<Option<ToolchainBanner>> = outcome else {
        return String::new();
    };
    payload
        .downcast_ref::<String>()
        .map_or_else(String::new, Clone::clone)
}

#[test]
fn an_absent_interpreter_fails_the_run_when_the_variable_makes_it_mandatory() {
    let outcome: std::thread::Result<Option<ToolchainBanner>> = std::panic::catch_unwind(|| {
        require_with_requirement(
            &ABSENT,
            None,
            PROOF_SUBJECT,
            ToolchainRequirement::Mandatory,
        )
    });
    assert!(
        outcome.is_err(),
        "an absent interpreter was tolerated while {} made it mandatory, which is the exact silent \
         pass this requirement exists to remove",
        ABSENT.require_var
    );
    let message: String = panic_message(&outcome);
    assert!(
        message.contains(ABSENT.require_var),
        "the failure must name the variable that made the interpreter mandatory, got {message:?}"
    );
    assert!(
        message.contains(ABSENT.program),
        "the failure must name the interpreter it could not run, got {message:?}"
    );
    assert!(
        message.contains("must not report success"),
        "the failure must state plainly that the case cannot report success, got {message:?}"
    );
}

#[test]
fn an_absent_interpreter_still_skips_when_the_variable_is_unset() {
    assert!(
        require_with_requirement(&ABSENT, None, PROOF_SUBJECT, ToolchainRequirement::Optional)
            .is_none(),
        "a permitted skip must report the absence, never claim an interpreter it could not run"
    );
}

#[test]
fn a_version_outside_the_measured_series_fails_a_mandatory_run() {
    let present: Option<ToolchainBanner> =
        require_with_requirement(&MRI, None, PROOF_SUBJECT, ToolchainRequirement::Optional);
    let Some(banner): Option<ToolchainBanner> = present else {
        println!(
            "NOT MEASURED: the version-series check was not exercised because {} is absent here",
            MRI.program
        );
        return;
    };
    assert!(
        banner.banner.contains(MRI_MEASURED_SERIES),
        "the installed ruby reports `{}`, which is outside the {MRI_MEASURED_SERIES} series every \
         yarv expectation in this crate was measured against",
        banner.banner
    );
    let outcome: std::thread::Result<Option<ToolchainBanner>> = std::panic::catch_unwind(|| {
        require_with_requirement(
            &MRI,
            Some("ruby 0.0"),
            PROOF_SUBJECT,
            ToolchainRequirement::Mandatory,
        )
    });
    assert!(
        outcome.is_err(),
        "a ruby whose banner is outside the measured series must not satisfy a mandatory run"
    );
    let message: String = panic_message(&outcome);
    assert!(
        message.contains("ruby 0.0"),
        "the failure must name the series it required, got {message:?}"
    );
}

#[test]
fn a_present_interpreter_satisfies_a_mandatory_run() {
    let Some(banner): Option<ToolchainBanner> =
        require_with_requirement(&MRI, None, PROOF_SUBJECT, ToolchainRequirement::Optional)
    else {
        println!(
            "NOT MEASURED: {} is absent here, so a satisfied mandatory run could not be exercised",
            MRI.program
        );
        return;
    };
    let mandatory: Option<ToolchainBanner> = require_with_requirement(
        &MRI,
        Some(MRI_MEASURED_SERIES),
        PROOF_SUBJECT,
        ToolchainRequirement::Mandatory,
    );
    assert_eq!(
        mandatory.map(|found: ToolchainBanner| found.banner),
        Some(banner.banner),
        "a present interpreter in the measured series must satisfy a mandatory run"
    );
}

#[test]
fn a_series_allowlist_still_rejects_a_banner_outside_every_entry() {
    let present: Option<ToolchainBanner> =
        require_with_requirement(&MRI, None, PROOF_SUBJECT, ToolchainRequirement::Optional);
    let Some(banner): Option<ToolchainBanner> = present else {
        println!(
            "NOT MEASURED: the series-allowlist rejection was not exercised because {} is absent \
             here",
            MRI.program
        );
        return;
    };
    let outcome: std::thread::Result<Option<ToolchainBanner>> = std::panic::catch_unwind(|| {
        require_measured_series(
            &MRI,
            &["ruby 0.0", "ruby 0.1"],
            PROOF_SUBJECT,
            ToolchainRequirement::Mandatory,
        )
    });
    assert!(
        outcome.is_err(),
        "an allowlist that names no installed series must not be satisfied by `{}`; widening a \
         version pin to a list must never turn it into an accept-anything check",
        banner.banner
    );
    let message: String = panic_message(&outcome);
    for named in ["ruby 0.0", "ruby 0.1"] {
        assert!(
            message.contains(named),
            "the failure must name every series it would have accepted, got {message:?}"
        );
    }
    let accepted: Option<ToolchainBanner> = require_measured_series(
        &MRI,
        &["ruby 0.0", MRI_MEASURED_SERIES],
        PROOF_SUBJECT,
        ToolchainRequirement::Mandatory,
    );
    assert_eq!(
        accepted.map(|found: ToolchainBanner| found.banner),
        Some(banner.banner),
        "an allowlist that names the installed series must satisfy a mandatory run"
    );
}

#[test]
fn requirement_spellings_are_read_the_way_they_are_documented() {
    assert_eq!(requirement_from_value(None), ToolchainRequirement::Optional);
    for falsey in ["", " ", "0", "false", "FALSE", "no", "off", "optional"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(falsey))),
            ToolchainRequirement::Optional,
            "{falsey:?} must not make a toolchain mandatory"
        );
    }
    for truthy in ["1", "true", "yes", "on", "required", "all"] {
        assert_eq!(
            requirement_from_value(Some(OsStr::new(truthy))),
            ToolchainRequirement::Mandatory,
            "{truthy:?} must make a toolchain mandatory"
        );
    }
}
