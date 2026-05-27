#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_panics_doc,
    unused_must_use
)]

use disrobe_pass_dotnet::backends::Backend;

#[test]
fn dnspy_and_dnspy_ex_distinct_binaries() {
    assert_eq!(Backend::Dnspy.binary_name(), "dnSpy");
    assert_eq!(Backend::DnspyEx.binary_name(), "dnSpyEx");
}

#[test]
#[ignore = "FIXTURE PENDING: requires dnSpy or dnSpyEx binary on PATH"]
fn dnspy_round_trip_decompile() {
    panic!("FIXTURE PENDING");
}
