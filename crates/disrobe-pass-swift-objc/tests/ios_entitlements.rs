#![allow(clippy::expect_used, clippy::unwrap_used)]
mod fixtures;

use disrobe_pass_swift_objc::plist_decode::{self, EntitlementValue, EntitlementsDecode};

use crate::fixtures::build_entitlements_xml;

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
