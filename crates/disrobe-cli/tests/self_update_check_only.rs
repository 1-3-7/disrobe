#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use common::{Run, run_disrobe};

const RELEASES_URL: &str = "https://api.github.com/repos/1-3-7/disrobe/releases/latest";

#[test]
fn check_only_dry_run_exits_zero_offline() {
    let r: Run = run_disrobe(&["self-update", "--check-only", "--dry-run"]);
    assert_eq!(
        r.code, 0,
        "--check-only --dry-run must exit 0 with no network. stdout={} stderr={}",
        r.stdout, r.stderr
    );
}

#[test]
fn check_only_dry_run_json_reports_source_only_and_api_url() {
    let r: Run = run_disrobe(&["--json", "self-update", "--check-only", "--dry-run"]);
    assert_eq!(
        r.code, 0,
        "json --check-only --dry-run must exit 0. stdout={} stderr={}",
        r.stdout, r.stderr
    );
    let v: serde_json::Value =
        serde_json::from_str(&r.stdout).expect("self-update --json must emit valid json");
    assert_eq!(v["url"], RELEASES_URL);
    assert_eq!(v["status"], "source-only-distribution");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["latest_version"], serde_json::Value::Null);
}

#[test]
fn global_dry_run_flag_order_also_reaches_dry_run_branch() {
    let r: Run = run_disrobe(&["--dry-run", "self-update", "--check-only"]);
    assert_eq!(
        r.code, 0,
        "global --dry-run before subcommand must exit 0. stdout={} stderr={}",
        r.stdout, r.stderr
    );
}
