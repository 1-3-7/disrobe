#![allow(clippy::expect_used, clippy::unwrap_used)]

mod fixtures;

use disrobe_pass_swift_objc::plist_decode::{self, InfoPlistSummary};

use crate::fixtures::build_binary_info_plist;

#[test]
fn binary_plist_decodes_to_summary() {
    let bytes: Vec<u8> = build_binary_info_plist();
    assert!(
        bytes.starts_with(b"bplist00"),
        "fixture should be bplist00 binary form"
    );
    let summary: InfoPlistSummary = plist_decode::parse_info_plist(&bytes).expect("decode");
    assert_eq!(
        summary.bundle_identifier.as_deref(),
        Some("com.example.app")
    );
    assert_eq!(summary.bundle_executable.as_deref(), Some("Example"));
    assert_eq!(summary.short_version.as_deref(), Some("1.0.0"));
    assert_eq!(summary.bundle_version.as_deref(), Some("42"));
    assert_eq!(summary.minimum_os_version.as_deref(), Some("15.0"));
    assert_eq!(summary.supported_platforms, vec!["iPhoneOS".to_owned()]);
    assert_eq!(summary.device_family, vec![1, 2]);
}
