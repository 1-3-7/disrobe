//! de4dot external-backend metadata coverage.

#![allow(clippy::missing_panics_doc)]

use disrobe_pass_dotnet::backends::Backend;

#[test]
fn de4dot_metadata_consistent() {
    assert_eq!(Backend::De4dot.binary_name(), "de4dot");
    assert_eq!(Backend::De4dot.override_env(), "DISROBE_EXTERNAL_DE4DOT");
}
