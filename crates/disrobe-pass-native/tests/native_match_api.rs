#![allow(clippy::expect_used)]

use disrobe_pass_native::{NativeMatchOptions, match_native_images};

const SAMPLE: &[u8] =
    include_bytes!("../../../corpus/native/obfuscators/guardian-rs/sample.clean.exe");

#[test]
fn the_public_api_matches_two_real_images_with_the_shared_report_schema() {
    let report = match_native_images(
        "known",
        SAMPLE,
        "candidate",
        SAMPLE,
        NativeMatchOptions {
            limit: Some(3),
            function: None,
            stage: None,
        },
    )
    .expect("match the committed native image against itself");

    assert_eq!(report.schema, "disrobe.native.match/v2");
    assert_eq!(report.a, "known");
    assert_eq!(report.b, "candidate");
    assert!(report.pairs > 0);
    assert_eq!(report.listing.shown, 3);
    assert!(report.listing.withheld > 0);
    assert!(
        report
            .a_verdicts
            .iter()
            .all(|row| row.counterpart() == Some(row.subject))
    );
}

#[test]
fn the_public_api_preserves_empty_and_missing_function_refusal_codes() {
    let empty = match_native_images("known", SAMPLE, "empty", &[], NativeMatchOptions::default())
        .expect_err("empty bytes are not a native image");
    assert!(empty.to_string().contains("DR-NATIVE-0203"));

    let absent = match_native_images(
        "known",
        SAMPLE,
        "candidate",
        SAMPLE,
        NativeMatchOptions {
            limit: None,
            function: Some(u64::MAX),
            stage: None,
        },
    )
    .expect_err("the address is absent from both inputs");
    assert_eq!(
        absent.to_string(),
        "DR-NATIVE-0208: no function at address 0xffffffffffffffff in either input"
    );
}
