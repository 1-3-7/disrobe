#![allow(clippy::expect_used)]
use std::time::Instant;

use disrobe_core::format::test_helpers::run_subprocess;
use disrobe_core::format::{FormatConfig, FormatError, set_config};

#[cfg(windows)]
const SLEEPER_BINARY: &str = "ping";
#[cfg(windows)]
const SLEEPER_ARGS: &[&str] = &["127.0.0.1", "-n", "12"];

#[cfg(not(windows))]
const SLEEPER_BINARY: &str = "sleep";
#[cfg(not(windows))]
const SLEEPER_ARGS: &[&str] = &["10"];

#[test]
fn sleeper_subprocess_is_killed_after_timeout() {
    set_config(FormatConfig {
        enabled: true,
        timeout_secs: 1,
    });
    let started: Instant = Instant::now();
    let err: FormatError = run_subprocess(SLEEPER_BINARY, SLEEPER_ARGS, "", 1)
        .expect_err("sleeper must time out, not complete normally");
    let elapsed_secs: u64 = started.elapsed().as_secs();
    assert!(
        matches!(err, FormatError::Timeout | FormatError::ToolMissing(_)),
        "expected Timeout or ToolMissing, got {err:?}"
    );
    if matches!(err, FormatError::Timeout) {
        assert!(
            elapsed_secs <= 5,
            "timeout should fire well under 5s, elapsed {elapsed_secs}s"
        );
    }
    set_config(FormatConfig::default());
}
