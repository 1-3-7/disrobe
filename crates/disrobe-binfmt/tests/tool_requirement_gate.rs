#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::ffi::OsStr;
use std::panic::AssertUnwindSafe;

use common::requirement::{
    MAKECAB, MAKENSIS, REQUIRE_ALL_VAR, Requirement, SEVEN_ZIP, Toolchain, WIX, enforce,
    required_fixture, requirement_from_values,
};

const GATED: [Toolchain; 4] = [MAKECAB, SEVEN_ZIP, WIX, MAKENSIS];

fn value(text: &str) -> &OsStr {
    OsStr::new(text)
}

fn panic_message(body: impl FnOnce()) -> String {
    let previous: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
        std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome: Result<(), Box<dyn std::any::Any + Send>> =
        std::panic::catch_unwind(AssertUnwindSafe(body));
    std::panic::set_hook(previous);
    let payload: Box<dyn std::any::Any + Send> = outcome.expect_err("the call must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|text: &&str| (*text).to_owned())
        })
        .expect("a panic payload carries its message")
}

#[test]
fn an_unset_variable_leaves_a_toolchain_optional() {
    assert_eq!(requirement_from_values(None, None), Requirement::Optional);
    for text in ["", " ", "0", "false", "no", "off", "optional", "OPTIONAL"] {
        assert_eq!(
            requirement_from_values(Some(value(text)), None),
            Requirement::Optional,
            "{text:?} must not make a toolchain mandatory"
        );
    }
}

#[test]
fn either_variable_makes_a_toolchain_mandatory() {
    for text in ["1", "true", "yes", "on", "all", "please"] {
        assert_eq!(
            requirement_from_values(Some(value(text)), None),
            Requirement::Mandatory,
            "the per-tool variable set to {text:?} must make the toolchain mandatory"
        );
        assert_eq!(
            requirement_from_values(None, Some(value(text))),
            Requirement::Mandatory,
            "the blanket variable set to {text:?} must make the toolchain mandatory"
        );
    }
    assert_eq!(
        requirement_from_values(Some(value("0")), Some(value("1"))),
        Requirement::Mandatory,
        "the blanket variable must not be overridden by an unset-looking per-tool value"
    );
}

#[test]
fn a_mandatory_toolchain_turns_an_unmeasured_case_into_a_failure() {
    for toolchain in GATED {
        let message: String = panic_message(|| {
            enforce(
                &toolchain,
                "the byte-exact recovery this case exists to measure",
                "the tool was not found",
                Requirement::Mandatory,
            );
        });
        assert!(
            message.contains(toolchain.require_var)
                && message.contains(REQUIRE_ALL_VAR)
                && message.contains("must not report success"),
            "the failure for {} must name both variables and say the case cannot pass: {message}",
            toolchain.program
        );
    }
}

#[test]
fn an_optional_toolchain_lets_an_unmeasured_case_continue() {
    for toolchain in GATED {
        enforce(
            &toolchain,
            "the byte-exact recovery this case exists to measure",
            "the tool was not found",
            Requirement::Optional,
        );
    }
}

#[test]
fn a_fixture_that_is_not_committed_is_never_treated_as_absent_by_choice() {
    let message: String = panic_message(|| {
        let _ignored: Vec<u8> = required_fixture("cython", "no-such-fixture.pyd");
    });
    assert!(
        message.contains("corpus/binfmt/cython/no-such-fixture.pyd")
            && message.contains("damaged checkout"),
        "a missing tracked fixture must name the path and refuse to pass: {message}"
    );
}

#[test]
fn a_committed_fixture_is_read_back_whole() {
    let bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");
    assert_eq!(
        bytes.get(..4),
        Some(&[0x7f, b'E', b'L', b'F'][..]),
        "the loader must return the fixture bytes, not an empty stand-in"
    );
}
