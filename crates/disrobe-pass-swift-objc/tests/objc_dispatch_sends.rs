#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::PathBuf;

use disrobe_pass_swift_objc::macho::{self, ParsedSlice};
use disrobe_pass_swift_objc::native_bodies::{
    FunctionBody, NativeBodyReport, recover_native_bodies,
};
use disrobe_pass_swift_objc::objc_dispatch::{
    DispatchArch, DispatchMaps, ObjcMessageSend, build_dispatch_maps,
};

fn fixture(name: &str) -> Vec<u8> {
    let path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("objc_dispatch")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read fixture {}: {e}", path.display()))
}

fn expected_sends() -> BTreeMap<&'static str, (&'static str, Option<&'static str>)> {
    BTreeMap::from([
        (
            "_make_greeting",
            ("stringWithUTF8String:", Some("NSString")),
        ),
        ("_first_element", ("objectAtIndex:", None)),
        ("_store", ("setValue:forKey:", None)),
        ("_text_length", ("length", None)),
        ("_fresh_object", ("init", Some("NSObject"))),
    ])
}

fn sends_by_function(report: &NativeBodyReport) -> BTreeMap<String, Vec<ObjcMessageSend>> {
    report
        .functions
        .iter()
        .map(|function: &FunctionBody| (function.native_name.clone(), function.objc_sends.clone()))
        .collect()
}

fn assert_recovers_every_send(fixture_name: &str, arch_label: &str) {
    let bytes: Vec<u8> = fixture(fixture_name);
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse stripped dylib");
    let report: NativeBodyReport = recover_native_bodies(&bytes, &parsed);

    let by_function: BTreeMap<String, Vec<ObjcMessageSend>> = sends_by_function(&report);
    let expected: BTreeMap<&str, (&str, Option<&str>)> = expected_sends();

    let mut resolved_sites: usize = 0;
    for (name, (selector, receiver)) in &expected {
        let sends: &Vec<ObjcMessageSend> = by_function.get(*name).unwrap_or_else(|| {
            panic!("{arch_label}: function {name} absent from recovered bodies")
        });
        assert_eq!(
            sends.len(),
            1,
            "{arch_label}: {name} must recover exactly one message send, got {sends:?}"
        );
        let send: &ObjcMessageSend = &sends[0];
        assert_eq!(
            send.send.selector, *selector,
            "{arch_label}: {name} recovered selector must match source"
        );
        assert_eq!(
            send.send.receiver_class.as_deref(),
            *receiver,
            "{arch_label}: {name} receiver class must match statically-determinable source class"
        );
        let body: &FunctionBody = report
            .functions
            .iter()
            .find(|f: &&FunctionBody| f.native_name == *name)
            .expect("recovered function body for expected send");
        assert!(
            send.call_site >= body.start && send.call_site < body.end,
            "{arch_label}: {name} call site {:#x} must fall inside [{:#x}, {:#x})",
            send.call_site,
            body.start,
            body.end
        );
        resolved_sites += 1;
    }

    let total_recovered: usize = by_function
        .values()
        .map(|sends: &Vec<ObjcMessageSend>| sends.len())
        .sum();
    assert_eq!(
        total_recovered, resolved_sites,
        "{arch_label}: recovered {total_recovered} sends but expected exactly {resolved_sites}; a spurious annotation is a soundness violation"
    );
}

#[test]
fn arm64_stripped_dylib_recovers_all_message_sends() {
    assert_recovers_every_send("dispatch_sends_arm64.macho", "arm64");
}

#[test]
fn x86_64_stripped_dylib_recovers_all_message_sends() {
    assert_recovers_every_send("dispatch_sends_x86_64.macho", "x86_64");
}

#[test]
fn arm64_renders_readable_message_expressions() {
    let bytes: Vec<u8> = fixture("dispatch_sends_arm64.macho");
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse dylib");
    let report: NativeBodyReport = recover_native_bodies(&bytes, &parsed);
    let by_function: BTreeMap<String, Vec<ObjcMessageSend>> = sends_by_function(&report);

    let rendered = |name: &str| -> String { by_function[name][0].send.rendered.clone() };
    assert_eq!(
        rendered("_make_greeting"),
        "[NSString stringWithUTF8String:x2]"
    );
    assert_eq!(rendered("_first_element"), "[x0 objectAtIndex:x2]");
    assert_eq!(rendered("_store"), "[x0 setValue:x2 forKey:x3]");
    assert_eq!(rendered("_text_length"), "[x0 length]");
    assert_eq!(rendered("_fresh_object"), "[[NSObject alloc] init]");
}

#[test]
fn selref_and_class_maps_resolve_independently_of_symbol_names() {
    let bytes: Vec<u8> = fixture("dispatch_sends_arm64.macho");
    let parsed: ParsedSlice = macho::parse_slice(&bytes).expect("parse dylib");
    let maps: DispatchMaps = build_dispatch_maps(&bytes, &parsed, DispatchArch::Arm64);

    let selectors: Vec<&String> = maps.selref_by_va.values().collect();
    for selector in [
        "stringWithUTF8String:",
        "objectAtIndex:",
        "setValue:forKey:",
        "length",
    ] {
        assert!(
            selectors.iter().any(|s: &&String| s.as_str() == selector),
            "selref map must resolve {selector} through __objc_selrefs -> __objc_methname"
        );
    }

    let classes: Vec<&String> = maps.classref_by_va.values().collect();
    for class in ["NSString", "NSObject"] {
        assert!(
            classes.iter().any(|c: &&String| c.as_str() == class),
            "classref map must resolve {class} through the bind table"
        );
    }

    let imports: Vec<&String> = maps.imports_by_addr.values().collect();
    assert!(
        imports
            .iter()
            .any(|s: &&String| s.as_str() == "_objc_msgSend"),
        "bind table must expose the _objc_msgSend dispatch entry point"
    );
}

#[test]
fn malformed_input_never_panics() {
    for junk in [
        vec![],
        vec![0u8; 3],
        vec![0xFFu8; 64],
        b"\xcf\xfa\xed\xfe garbage header bytes that are not a real mach-o".to_vec(),
    ] {
        let _ = macho::parse_slice(&junk).map(|parsed: ParsedSlice| {
            let _ = recover_native_bodies(&junk, &parsed);
            let _ = build_dispatch_maps(&junk, &parsed, DispatchArch::Arm64);
        });
    }
}
