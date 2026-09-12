#![allow(dead_code, unreachable_pub, clippy::print_stderr, clippy::panic)]

use std::ffi::OsString;

pub const REQUIRE_AARCH64_ORACLES: &str = "DISROBE_REQUIRE_AARCH64_ORACLES";

pub fn demanded() -> bool {
    let Some(raw): Option<OsString> = std::env::var_os(REQUIRE_AARCH64_ORACLES) else {
        return false;
    };
    !matches!(
        raw.to_string_lossy().trim().to_ascii_lowercase().as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
}

pub fn unmeasured(graded: &str, absent: &str) {
    assert!(
        !demanded(),
        "{REQUIRE_AARCH64_ORACLES} makes this oracle mandatory for this run, so {graded} was \
         graded against nothing and this case must not report success: {absent}. Provision the \
         missing prerequisite, or clear {REQUIRE_AARCH64_ORACLES} to permit a run that grades \
         nothing here."
    );
    eprintln!("SKIP {graded}: {absent}");
}
