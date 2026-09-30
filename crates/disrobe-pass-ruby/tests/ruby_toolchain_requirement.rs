#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/ruby_toolchain.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod ruby_toolchain;

use std::path::PathBuf;

use ruby_toolchain::{
    MRI, MRI_MEASURED_SERIES, MRI_RECOMPILE_VERSION, Toolchain, ToolchainBanner, require,
    require_measured_series, require_version,
};

const ABSENT: Toolchain = Toolchain {
    program: "disrobe-ruby-interpreter-that-is-not-installed",
    prerequisite: "disrobe-pass-ruby::interpreter-that-is-not-installed",
    install_hint: "nothing, this name exists only to stand in for an absent interpreter",
};

const PROOF_SUBJECT: &str = "this requirement proof";

const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

fn panic_message(outcome: &std::thread::Result<Option<ToolchainBanner>>) -> String {
    let Err(payload): &std::thread::Result<Option<ToolchainBanner>> = outcome else {
        return String::new();
    };
    payload
        .downcast_ref::<String>()
        .map_or_else(String::new, Clone::clone)
}

fn installed_mri() -> ToolchainBanner {
    require(&MRI, PROOF_SUBJECT).expect(
        "tests/optional.toml must not list the MRI prerequisite, because every CI test shard \
         provisions Ruby",
    )
}

#[test]
fn an_absent_interpreter_fails_the_run_by_name() {
    let outcome: std::thread::Result<Option<ToolchainBanner>> =
        std::panic::catch_unwind(|| require(&ABSENT, PROOF_SUBJECT));
    assert!(
        outcome.is_err(),
        "an absent interpreter was tolerated although tests/optional.toml does not list {}, which \
         is the exact silent pass this requirement exists to remove",
        ABSENT.prerequisite
    );
    let message: String = panic_message(&outcome);
    for named in [ABSENT.prerequisite, ABSENT.program, "tests/optional.toml"] {
        assert!(
            message.contains(named),
            "the failure must name `{named}`, got {message:?}"
        );
    }
}

#[test]
fn an_absent_interpreter_failure_says_how_to_install_it() {
    let outcome: std::thread::Result<Option<ToolchainBanner>> =
        std::panic::catch_unwind(|| require(&ABSENT, PROOF_SUBJECT));
    let message: String = panic_message(&outcome);
    assert!(
        message.contains(ABSENT.install_hint) && message.contains(PROOF_SUBJECT),
        "the failure must say what it grades and how to provide the interpreter, got {message:?}"
    );
}

#[test]
fn a_version_outside_the_measured_series_fails_the_run() {
    let banner: ToolchainBanner = installed_mri();
    assert!(
        banner.banner.contains(MRI_MEASURED_SERIES),
        "the installed ruby reports `{}`, which is outside the {MRI_MEASURED_SERIES} series every \
         yarv expectation in this crate was measured against",
        banner.banner
    );
    let outcome: std::thread::Result<Option<ToolchainBanner>> =
        std::panic::catch_unwind(|| require_version(&MRI, "ruby 0.0", PROOF_SUBJECT));
    assert!(
        outcome.is_err(),
        "a ruby whose banner is outside the measured series must not satisfy the requirement"
    );
    let message: String = panic_message(&outcome);
    assert!(
        message.contains("ruby 0.0"),
        "the failure must name the series it required, got {message:?}"
    );
}

#[test]
fn a_present_interpreter_in_the_measured_series_satisfies_the_requirement() {
    let banner: ToolchainBanner = installed_mri();
    let measured: Option<ToolchainBanner> =
        require_version(&MRI, MRI_MEASURED_SERIES, PROOF_SUBJECT);
    assert_eq!(
        measured.map(|found: ToolchainBanner| found.banner),
        Some(banner.banner),
        "a present interpreter in the measured series must satisfy the requirement"
    );
}

#[test]
fn a_series_allowlist_still_rejects_a_banner_outside_every_entry() {
    let banner: ToolchainBanner = installed_mri();
    let outcome: std::thread::Result<Option<ToolchainBanner>> = std::panic::catch_unwind(|| {
        require_measured_series(&MRI, &["ruby 0.0", "ruby 0.1"], PROOF_SUBJECT)
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
    let accepted: Option<ToolchainBanner> =
        require_measured_series(&MRI, &["ruby 0.0", MRI_MEASURED_SERIES], PROOF_SUBJECT);
    assert_eq!(
        accepted.map(|found: ToolchainBanner| found.banner),
        Some(banner.banner),
        "an allowlist that names the installed series must satisfy the requirement"
    );
}

#[test]
fn the_workflow_provisions_the_ruby_release_the_recompile_oracles_pin() {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(CI_WORKFLOW);
    let workflow: String = std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{CI_WORKFLOW} provisions the Ruby every recompile oracle requires, so its absence is \
             a damaged checkout: {error} ({})",
            path.display()
        )
    });
    let pinned: &str = MRI_RECOMPILE_VERSION
        .trim()
        .strip_prefix("ruby ")
        .expect("the recompile pin names a ruby release");
    let provisioned: Vec<&str> = workflow
        .lines()
        .filter_map(|line: &str| line.trim().strip_prefix("ruby-version:"))
        .map(|value: &str| value.trim().trim_matches('"'))
        .collect();
    assert!(
        !provisioned.is_empty(),
        "{CI_WORKFLOW} no longer sets up Ruby, so every test that requires it would fail in CI"
    );
    assert!(
        provisioned.iter().all(|version: &&str| *version == pinned),
        "{CI_WORKFLOW} provisions Ruby {provisioned:?} but the recompile oracles are pinned to \
         {pinned}, so CI would grade against a release the expectations were not measured with"
    );
}
