#![allow(clippy::expect_used, clippy::panic)]

use std::process::Command;

#[test]
fn checked_push_grader_manifest_is_reachable_from_the_xtask_cli() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["push-graders", "check"])
        .output()
        .expect("starting xtask push-graders check");
    assert!(
        output.status.success(),
        "xtask push-graders check failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8(output.stdout).expect("xtask stdout is UTF-8"),
        "push-graders: 11 grader target(s), 6 uncovered ecosystem(s)\n"
    );
}
