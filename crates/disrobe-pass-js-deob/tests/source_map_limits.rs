#![allow(clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    Error, RecoverOptions, RecoveryReport, SourceMap, SourceMapLimits, decode_data_url_json,
    decode_vlq, parse_source_map_with_limits, recover_source_map, recover_source_map_json,
};

const LIMITS: SourceMapLimits = SourceMapLimits {
    input_bytes: 4096,
    sources: 4,
    names: 32,
    sections: 4,
    depth: 4,
    generated_lines: 64,
    mapping_segments: 256,
    content_bytes: 2048,
    path_bytes: 2048,
};

#[test]
fn recovery_preserves_an_empty_original_file() {
    let report: RecoveryReport = recover_source_map_json(
        r#"{"version":3,"sources":["empty.ts"],"sourcesContent":[""],"names":[],"mappings":""}"#,
        RecoverOptions { emit_stubs: false },
    )
    .unwrap();
    assert_eq!(report.total_sources, 1);
    assert_eq!(report.with_content, 1);
    assert_eq!(report.reconstructed_stubs, 0);
    assert_eq!(report.files.len(), 1);
    assert_eq!(report.files[0].relative_path, "empty.ts");
    assert!(report.files[0].bytes.is_empty());
    assert!(!report.files[0].reconstructed);
}

#[test]
fn source_map_input_limits_are_inclusive() {
    let raw: &str = r#"{"version":3,"sources":[],"mappings":""}"#;
    assert!(
        parse_source_map_with_limits(
            raw,
            SourceMapLimits {
                input_bytes: raw.len(),
                ..LIMITS
            }
        )
        .is_ok()
    );
    assert!(matches!(
        parse_source_map_with_limits(
            raw,
            SourceMapLimits {
                input_bytes: raw.len() - 1,
                ..LIMITS
            }
        ),
        Err(Error::SyntaxLimit {
            kind: "source-map input bytes",
            ..
        })
    ));
}

#[test]
fn source_map_budgets_cover_nested_maps_and_expanded_roots() {
    let indexed: &str = r#"{"version":3,"sourceRoot":"not-inherited","sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sourceRoot":"first","sources":["empty.ts"],"sourcesContent":[""],"mappings":"AAAA"}},{"offset":{"line":10,"column":0},"map":{"version":3,"sourceRoot":"second","sources":["index.ts"],"sourcesContent":["export const answer = 42;"],"mappings":"AAAA"}}]}"#;
    let parsed: SourceMap = parse_source_map_with_limits(indexed, LIMITS).unwrap();
    let report: RecoveryReport = recover_source_map(&parsed, RecoverOptions { emit_stubs: false });
    assert_eq!(report.with_content, 2);
    assert_eq!(report.files[0].relative_path, "first/empty.ts");
    assert_eq!(report.files[1].relative_path, "second/index.ts");
    assert_eq!(report.mapped_segments, 2);
    for limits in [
        SourceMapLimits {
            sources: 1,
            ..LIMITS
        },
        SourceMapLimits {
            sections: 1,
            ..LIMITS
        },
        SourceMapLimits { depth: 1, ..LIMITS },
        SourceMapLimits {
            mapping_segments: 1,
            ..LIMITS
        },
        SourceMapLimits {
            generated_lines: 10,
            ..LIMITS
        },
        SourceMapLimits {
            content_bytes: 5,
            ..LIMITS
        },
        SourceMapLimits {
            path_bytes: 5,
            ..LIMITS
        },
    ] {
        assert!(matches!(
            parse_source_map_with_limits(indexed, limits),
            Err(Error::SyntaxLimit { .. })
        ));
    }
}

#[test]
fn source_map_rejects_bad_offsets_and_mappings_before_expansion() {
    for offset in ["-1", "4294967295", "9223372036854775807"] {
        let raw: String = format!(
            r#"{{"version":3,"sections":[{{"offset":{{"line":{offset},"column":0}},"map":{{"version":3,"sources":[],"mappings":"A"}}}}]}}"#
        );
        assert!(parse_source_map_with_limits(&raw, LIMITS).is_err());
    }
    for raw in [
        r#"{"version":2,"sources":[],"mappings":""}"#,
        r#"{"version":3,"sources":[],"mappings":"AAAA"}"#,
        r#"{"version":3,"sources":[],"mappings":"!"}"#,
        r#"{"version":3,"sources":[],"sourcesContent":["extra"],"mappings":""}"#,
    ] {
        assert!(parse_source_map_with_limits(raw, LIMITS).is_err());
    }
}

#[test]
fn inline_maps_require_utf8() {
    assert!(matches!(
        decode_data_url_json("data:application/json,%FF"),
        Err(Error::Utf8)
    ));
    assert_eq!(
        decode_data_url_json("data:application/json,%7B%7D").unwrap(),
        "{}"
    );
}

#[test]
fn overflowing_vlq_and_composed_columns_are_rejected() {
    assert!(decode_vlq("ggggggE").is_none());
    let raw: &str = r#"{"version":3,"sections":[{"offset":{"line":0,"column":2147483647},"map":{"version":3,"mappings":"C"}}]}"#;
    assert!(parse_source_map_with_limits(raw, LIMITS).is_err());
}

#[test]
fn nested_indexed_maps_cannot_drop_overflowing_mappings() {
    let raw: &str = r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sections":[{"offset":{"line":0,"column":2147483647},"map":{"version":3,"mappings":"C"}}]}}]}"#;
    assert!(parse_source_map_with_limits(raw, LIMITS).is_err());
    let valid: SourceMap =
        parse_source_map_with_limits(&raw.replace("2147483647", "0"), LIMITS).unwrap();
    assert_eq!(valid.mappings, "C");
}

#[test]
fn indexed_ignore_lists_keep_their_own_source_scope() {
    let raw: &str = r#"{"version":3,"sections":[{"offset":{"line":0,"column":0},"map":{"version":3,"sources":["vendor.js"],"sourcesContent":[""],"x_google_ignoreList":[0],"mappings":"AAAA"}},{"offset":{"line":1,"column":0},"map":{"version":3,"sources":["app.js"],"sourcesContent":[""],"mappings":"AAAA"}}]}"#;
    let map: SourceMap = parse_source_map_with_limits(raw, LIMITS).unwrap();
    let report: RecoveryReport = recover_source_map(&map, RecoverOptions { emit_stubs: false });
    assert!(report.files[0].ignored);
    assert!(!report.files[1].ignored);
    assert!(parse_source_map_with_limits(&raw.replace("[0]", "[1]"), LIMITS).is_err());
}

#[test]
fn path_budgets_include_only_applied_roots_and_separators() {
    let rooted: &str = r#"{"version":3,"sourceRoot":"src","sources":["a.js"],"sourcesContent":[""],"mappings":""}"#;
    assert!(
        parse_source_map_with_limits(
            rooted,
            SourceMapLimits {
                path_bytes: 8,
                ..LIMITS
            }
        )
        .is_ok()
    );
    assert!(matches!(
        parse_source_map_with_limits(
            rooted,
            SourceMapLimits {
                path_bytes: 7,
                ..LIMITS
            }
        ),
        Err(Error::SyntaxLimit {
            kind: "source-map path bytes",
            ..
        })
    ));
    let absolute: &str = r#"{"version":3,"sourceRoot":"not-applied","sources":["/a.js"],"sourcesContent":[""],"mappings":""}"#;
    assert!(
        parse_source_map_with_limits(
            absolute,
            SourceMapLimits {
                path_bytes: 5,
                ..LIMITS
            }
        )
        .is_ok()
    );
}

#[test]
fn bounded_esbuild_recovery_matches_each_original_file() {
    let map: SourceMap = parse_source_map_with_limits(
        include_str!("../../../corpus/js/esbuild/bundle.js.map"),
        LIMITS,
    )
    .unwrap();
    let report: RecoveryReport = recover_source_map(&map, RecoverOptions { emit_stubs: false });
    assert_eq!(report.total_sources, 4);
    assert_eq!(report.with_content, 4);
    assert_eq!(report.reconstructed_stubs, 0);
    for (name, expected) in [
        (
            "src/lazy.js",
            include_bytes!("../../../corpus/js/esbuild/src/lazy.js").as_slice(),
        ),
        (
            "src/util.js",
            include_bytes!("../../../corpus/js/esbuild/src/util.js").as_slice(),
        ),
        (
            "src/math.js",
            include_bytes!("../../../corpus/js/esbuild/src/math.js").as_slice(),
        ),
        (
            "src/index.js",
            include_bytes!("../../../corpus/js/esbuild/src/index.js").as_slice(),
        ),
    ] {
        let file = report
            .files
            .iter()
            .find(|file| file.relative_path == name)
            .unwrap();
        assert_eq!(file.bytes, expected, "{name}");
        assert!(!file.reconstructed);
    }
}
