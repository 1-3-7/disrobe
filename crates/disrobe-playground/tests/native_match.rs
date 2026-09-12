#![cfg(feature = "chain")]
#![allow(clippy::expect_used)]

use disrobe_pass_native::{NativeMatchOptions, match_native_images};
use disrobe_playground::{NativeMatchRequest, match_native_uploads};

const SAMPLE: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");

#[test]
fn playground_two_upload_match_is_the_shared_native_match_document() {
    let request = NativeMatchRequest {
        limit: Some(4),
        function: None,
        stage: None,
    };
    let playground =
        match_native_uploads(SAMPLE, SAMPLE, request).expect("match two committed uploaded images");
    let shared = match_native_images(
        "a",
        SAMPLE,
        "b",
        SAMPLE,
        NativeMatchOptions {
            limit: Some(4),
            function: None,
            stage: None,
        },
    )
    .expect("match through the shared native API");

    assert_eq!(
        serde_json::to_value(playground).expect("serialize playground report"),
        serde_json::to_value(shared).expect("serialize shared report")
    );
}

#[test]
fn playground_match_preserves_the_native_function_refusal() {
    let error = match_native_uploads(
        SAMPLE,
        SAMPLE,
        NativeMatchRequest {
            limit: None,
            function: Some(u64::MAX),
            stage: None,
        },
    )
    .expect_err("the requested function is absent");

    assert_eq!(
        error.to_string(),
        "DR-NATIVE-0208: no function at address 0xffffffffffffffff in either input"
    );
}
