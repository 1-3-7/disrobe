#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

#[path = "support/macho_corpus.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod macho_corpus;

use disrobe_pass_swift_objc::macho::ParsedSlice;
use disrobe_pass_swift_objc::objc::{ObjcClassDump, class_dump};
use disrobe_pass_swift_objc::objc_records::ObjcInterface;

use macho_corpus::{SWIFT_HELLO_ORIGINAL, first_slice, read_tracked};

#[test]
fn an_imported_superclass_is_named_through_its_bind() {
    let bytes: Vec<u8> = read_tracked(SWIFT_HELLO_ORIGINAL);
    let (slice, parsed): (Vec<u8>, ParsedSlice) = first_slice(SWIFT_HELLO_ORIGINAL, &bytes);
    let dump: ObjcClassDump = class_dump(&slice, &parsed);
    let names: Vec<(&str, Option<&str>)> = dump
        .interfaces
        .iter()
        .map(|interface: &ObjcInterface| (interface.name.as_str(), interface.superclass.as_deref()))
        .collect();
    for class in [
        "_TtC10SwiftHello19LoginViewController",
        "_TtC10SwiftHello21AuthenticationService",
    ] {
        let superclass: Option<&str> = names
            .iter()
            .find(|(name, _): &&(&str, Option<&str>)| *name == class)
            .unwrap_or_else(|| panic!("{class} is in the class list: {names:?}"))
            .1;
        assert_eq!(
            superclass,
            Some("_TtCs12_SwiftObject"),
            "llvm-objdump --objc-meta-data binds {class}'s superclass to _OBJC_CLASS_$__TtCs12_SwiftObject"
        );
    }
}
