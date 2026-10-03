#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

#[path = "support/pyarmor_corpus_manifest.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod pyarmor_corpus_manifest;

use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_pyarmor::{
    Detection, HeaderModeFlags, NineProDetection, decode_mode_flags, detect_from_wrapper,
    detect_nine_pro,
};
use pyarmor_corpus_manifest::{CorpusManifest, ResolvedFixture, read_manifest, verified_fixtures};
use serde_json::Value;

const FIXED_FIXTURE_COUNT: usize = 72;
const HEADER_MODE_FIELDS: &[&str] = &[
    "restrict_mode",
    "advanced_restrict",
    "obf_module",
    "obf_code",
    "wrap_mode",
    "outer_runtime_key",
    "bcc_protection",
    "raw_mode_byte_0",
    "raw_mode_byte_1",
    "raw_mode_byte_2",
];
const NINE_PRO_FIELDS: &[&str] = &["is_nine_pro", "bind_mode", "bind_markers_found"];

fn assert_serialized_fields(value: &Value, expected: &[&str]) -> Result<(), String> {
    let Some(object): Option<&serde_json::Map<String, Value>> = value.as_object() else {
        return Err(format!("public value is not an object: {value}"));
    };
    let observed: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if observed == expected {
        Ok(())
    } else {
        Err(format!(
            "public fields were {observed:?}, expected {expected:?}"
        ))
    }
}

#[test]
fn manifest_verified_headers_publish_only_real_metadata() {
    let manifest: CorpusManifest = read_manifest();
    assert_eq!(manifest.meta.license_type, "pyarmor-trial");
    assert_eq!(
        manifest.meta.total_fixtures, FIXED_FIXTURE_COUNT,
        "the static oracle's fixture population changed"
    );
    let modes: BTreeMap<&str, &str> = manifest
        .fixture
        .iter()
        .map(|fixture| (fixture.output_path.as_str(), fixture.mode.as_str()))
        .collect();
    let fixtures: Vec<ResolvedFixture> = verified_fixtures(&manifest);
    assert_eq!(
        fixtures.len(),
        FIXED_FIXTURE_COUNT,
        "the manifest-verified v8/v9 wrapper population changed"
    );

    let mut header_mutation_checked: bool = false;
    let mut nine_pro_mutation_checked: bool = false;
    for fixture in fixtures {
        let mode: &str = modes
            .get(fixture.relative_id.as_str())
            .copied()
            .unwrap_or_else(|| panic!("{} has no manifest mode", fixture.relative_id));
        let wrapper: &str = std::str::from_utf8(&fixture.wrapper.bytes).unwrap_or_else(
            |error: std::str::Utf8Error| {
                panic!("{} is not UTF-8 wrapper text: {error}", fixture.relative_id)
            },
        );
        let (_, payload): (Detection, Vec<u8>) =
            detect_from_wrapper(wrapper).unwrap_or_else(|error| {
                panic!("{} wrapper detection failed: {error}", fixture.relative_id)
            });
        let flags: HeaderModeFlags = decode_mode_flags(&payload)
            .unwrap_or_else(|| panic!("{} has no mode header", fixture.relative_id));
        assert_eq!(
            flags.restrict_mode,
            mode == "restrict",
            "{} manifest mode {mode} disagrees with its decoded header",
            fixture.relative_id
        );

        let serialized_flags: Value = serde_json::to_value(&flags)
            .unwrap_or_else(|error: serde_json::Error| panic!("serialize header flags: {error}"));
        assert_serialized_fields(&serialized_flags, HEADER_MODE_FIELDS)
            .unwrap_or_else(|error: String| panic!("{}: {error}", fixture.relative_id));

        let nine_pro: NineProDetection = detect_nine_pro(&payload);
        assert!(
            !nine_pro.is_nine_pro,
            "{} is a manifest-verified trial build",
            fixture.relative_id
        );
        let serialized_nine_pro: Value = serde_json::to_value(&nine_pro)
            .unwrap_or_else(|error: serde_json::Error| panic!("serialize pro detection: {error}"));
        assert_serialized_fields(&serialized_nine_pro, NINE_PRO_FIELDS)
            .unwrap_or_else(|error: String| panic!("{}: {error}", fixture.relative_id));

        if !header_mutation_checked {
            let mut mutated: Value = serialized_flags.clone();
            mutated
                .as_object_mut()
                .expect("serialized header flags are an object")
                .insert("raw_restrict_byte".to_owned(), Value::from(0x80));
            assert!(
                assert_serialized_fields(&mutated, HEADER_MODE_FIELDS).is_err(),
                "a falsely labelled offset-16 field must be rejected by the public schema"
            );
            header_mutation_checked = true;
        }
        if !nine_pro_mutation_checked {
            let mut mutated: Value = serialized_nine_pro.clone();
            mutated
                .as_object_mut()
                .expect("serialized pro detection is an object")
                .insert("bind_flags".to_owned(), Value::from(1));
            assert!(
                assert_serialized_fields(&mutated, NINE_PRO_FIELDS).is_err(),
                "a falsely inferred bind-flags field must be rejected by the public schema"
            );
            nine_pro_mutation_checked = true;
        }
    }
    assert!(
        header_mutation_checked,
        "no verified headers were serialized"
    );
    assert!(
        nine_pro_mutation_checked,
        "no verified pro detections were serialized"
    );
}
