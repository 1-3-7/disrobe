#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::plist_decode::{self, EntitlementValue, EntitlementsDecode};

use crate::fixtures::{build_entitlements_xml, wrap_in_code_signature_blob};

#[test]
fn entitlements_decoded_from_xml() {
    let xml: Vec<u8> = build_entitlements_xml();
    let decoded: EntitlementsDecode = plist_decode::decode_entitlements_xml(&xml).expect("decode");
    assert!(
        decoded
            .keys
            .iter()
            .any(|k: &String| k == "application-identifier")
    );
    let value: &EntitlementValue = decoded
        .typed
        .get("get-task-allow")
        .expect("get-task-allow key");
    assert!(matches!(value, EntitlementValue::Bool(true)));
}

#[test]
fn entitlements_decoded_from_code_signature_cms_blob() {
    let xml: Vec<u8> = build_entitlements_xml();
    let cms: Vec<u8> = wrap_in_code_signature_blob(&xml);
    let decoded: EntitlementsDecode =
        plist_decode::decode_entitlements_from_code_signature(&cms).expect("decode");
    assert!(decoded.typed.get("aps-environment").is_some_and(
        |v: &EntitlementValue| matches!(v, EntitlementValue::String(s) if s == "development")
    ));
}
