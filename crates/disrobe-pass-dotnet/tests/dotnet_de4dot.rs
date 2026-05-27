#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

use disrobe_pass_dotnet::backends::Backend;

#[test]
fn de4dot_metadata_consistent() {
    assert_eq!(Backend::De4dot.binary_name(), "de4dot");
    assert_eq!(Backend::De4dot.override_env(), "DISROBE_EXTERNAL_DE4DOT");
}

#[test]
#[ignore = "FIXTURE PENDING: requires de4dot binary on PATH + protected sample"]
fn de4dot_round_trip_against_confuserex2_sample() {
    panic!("FIXTURE PENDING");
}
