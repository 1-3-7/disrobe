#![allow(clippy::missing_panics_doc)]
use disrobe_pass_dotnet::backends::Backend;

#[test]
fn dnspy_and_dnspy_ex_distinct_binaries() {
    assert_eq!(Backend::Dnspy.binary_name(), "dnSpy");
    assert_eq!(Backend::DnspyEx.binary_name(), "dnSpyEx");
}
