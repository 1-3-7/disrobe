#![allow(clippy::missing_panics_doc)]
use disrobe_pass_dotnet::backends::{Backend, probe};

#[test]
fn ilspy_backend_metadata_consistent() {
    assert_eq!(Backend::Ilspy.binary_name(), "ilspycmd");
    assert_eq!(Backend::Ilspy.override_env(), "DISROBE_EXTERNAL_ILSPY");
    let _: bool = probe(Backend::Ilspy);
}
