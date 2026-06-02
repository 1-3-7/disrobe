#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

use disrobe_pass_dotnet::backends::{Backend, probe};

#[test]
fn ilspy_backend_metadata_consistent() {
    assert_eq!(Backend::Ilspy.binary_name(), "ilspycmd");
    assert_eq!(Backend::Ilspy.override_env(), "DISROBE_EXTERNAL_ILSPY");
    let _: bool = probe(Backend::Ilspy);
}

#[test]
#[ignore = "FIXTURE PENDING: requires ilspycmd installed locally + real .NET assembly fixture"]
fn ilspy_round_trip_decompile_against_real_assembly() {
    panic!("FIXTURE PENDING");
}
