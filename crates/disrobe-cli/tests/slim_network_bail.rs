#![cfg(not(all(feature = "prowl", feature = "net-fetch", feature = "server")))]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use common::{Run, run_disrobe};

fn flat(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_whitespace() || c == '\u{2502}' {
                ' '
            } else {
                c
            }
        })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(not(feature = "prowl"))]
#[test]
fn prowl_names_the_prowl_feature_when_it_is_compiled_out() {
    let r: Run = run_disrobe(&["prowl", "example.invalid"]);
    assert_ne!(
        r.code, 0,
        "prowl dispatch must fail without the feature; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        flat(&r.stderr).contains("DR-CLI-0327"),
        "prowl dispatch must report the typed refusal; stderr={}",
        r.stderr
    );
    assert!(
        flat(&r.stderr).contains("`prowl`") && flat(&r.stderr).contains("--features prowl"),
        "prowl dispatch must name the feature and the build that has it; stderr={}",
        r.stderr
    );
}

#[cfg(not(feature = "net-fetch"))]
#[test]
fn install_deps_names_the_net_fetch_feature_when_it_is_compiled_out() {
    let r: Run = run_disrobe(&["install-deps", "ghidra"]);
    assert_ne!(
        r.code, 0,
        "install-deps must fail without an http client; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        flat(&r.stderr).contains("DR-CLI-0328"),
        "install-deps must report the typed refusal; stderr={}",
        r.stderr
    );
    assert!(
        flat(&r.stderr).contains("`net-fetch`") && flat(&r.stderr).contains("--features net-fetch"),
        "install-deps must name the feature and the build that has it; stderr={}",
        r.stderr
    );
}

#[cfg(not(feature = "net-fetch"))]
#[test]
fn install_deps_dry_run_still_reports_without_an_http_client() {
    let r: Run = run_disrobe(&["install-deps", "ghidra", "--dry-run"]);
    assert_eq!(
        r.code, 0,
        "the dry run needs no network and must still succeed; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("dry-run"),
        "the dry run must still emit its report; stdout={}",
        r.stdout
    );
}

#[cfg(not(feature = "server"))]
#[test]
fn serve_names_the_server_feature_when_it_is_compiled_out() {
    let r: Run = run_disrobe(&["serve", "--bind", "127.0.0.1:0"]);
    assert_ne!(
        r.code, 0,
        "serve dispatch must fail without the feature; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        flat(&r.stderr).contains("DR-CLI-0326"),
        "serve dispatch must report the typed refusal; stderr={}",
        r.stderr
    );
    assert!(
        flat(&r.stderr).contains("`server`") && flat(&r.stderr).contains("--features server"),
        "serve dispatch must name the feature and the build that has it; stderr={}",
        r.stderr
    );
}

#[cfg(not(feature = "server"))]
#[test]
fn serve_stays_listed_in_help_when_it_is_compiled_out() {
    let r: Run = run_disrobe(&["--help"]);
    assert_eq!(
        r.code, 0,
        "--help must succeed; stdout={} stderr={}",
        r.stdout, r.stderr
    );
    assert!(
        r.stdout.contains("serve"),
        "the grammar must not change with the feature set, so serve stays listed; stdout={}",
        r.stdout
    );
}
