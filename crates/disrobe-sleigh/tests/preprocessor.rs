use std::collections::BTreeMap;

use disrobe_sleigh::preprocessor::{PreprocessorLimits, preprocess_sources};

#[test]
fn expands_nested_includes_macros_and_conditionals() {
    let sources: BTreeMap<String, String> = BTreeMap::from([
        (
            "root.slaspec".to_owned(),
            "@define DATA_ENDIAN \"little\"\n@include \"defs.sinc\"\n".to_owned(),
        ),
        (
            "defs.sinc".to_owned(),
            "@ifdef DATA_ENDIAN\n@if DATA_ENDIAN == \"little\"\ndefine endian=$(DATA_ENDIAN);\n@else\ndefine endian=big;\n@endif\n@endif\n"
                .to_owned(),
        ),
    ]);

    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_ok(), "{result:?}");
    let output: String = result.unwrap_or_default();
    assert!(output.contains("define endian=little;"));
    assert!(!output.contains("define endian=big;"));
}

#[test]
fn rejects_recursive_includes() {
    let sources: BTreeMap<String, String> = BTreeMap::from([
        (
            "root.slaspec".to_owned(),
            "@include \"loop.sinc\"\n".to_owned(),
        ),
        (
            "loop.sinc".to_owned(),
            "@include \"root.slaspec\"\n".to_owned(),
        ),
    ]);

    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_err());
}

#[test]
fn enforces_expanded_source_limit() {
    let sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "define endian=little;\n".to_owned(),
    )]);
    let limits: PreprocessorLimits = PreprocessorLimits {
        expanded_bytes: 8,
        ..PreprocessorLimits::default()
    };

    let result: Result<String, _> = preprocess_sources("root.slaspec", &sources, limits);
    assert!(result.is_err());

    let macro_sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@define LONG 12345678901234567890\n$(LONG)\n".to_owned(),
    )]);
    let macro_limits: PreprocessorLimits = PreprocessorLimits {
        expanded_bytes: 10,
        ..PreprocessorLimits::default()
    };
    let macro_result: Result<String, _> =
        preprocess_sources("root.slaspec", &macro_sources, macro_limits);
    assert!(macro_result.is_err());
}

#[test]
fn enforces_input_bytes_and_conditional_depth() {
    let source_bytes: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@if MISSING\n@endif\n@if MISSING\n@endif\n".to_owned(),
    )]);
    let byte_limits: PreprocessorLimits = PreprocessorLimits {
        source_bytes: 16,
        ..PreprocessorLimits::default()
    };
    let byte_result: Result<String, _> =
        preprocess_sources("root.slaspec", &source_bytes, byte_limits);
    assert!(byte_result.is_err());

    let nested: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@if MISSING\n@if MISSING\n@if MISSING\n@endif\n@endif\n@endif\n".to_owned(),
    )]);
    let depth_limits: PreprocessorLimits = PreprocessorLimits {
        conditional_depth: 2,
        ..PreprocessorLimits::default()
    };
    let depth_result: Result<String, _> = preprocess_sources("root.slaspec", &nested, depth_limits);
    assert!(depth_result.is_err());
}

#[test]
fn accepts_indented_tab_directives_and_rejects_repeated_else() {
    let sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "\t@define\tMODE\t\"one\"\n  @if MODE == \"one\"\ndefine endian=little;\n  @else\ndefine endian=big;\n  @endif\n"
            .to_owned(),
    )]);
    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_ok(), "{result:?}");
    let output: String = result.unwrap_or_default();
    assert!(output.contains("define endian=little;"));

    let repeated: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@if MISSING\n@else\n@else\n@endif\n".to_owned(),
    )]);
    let repeated_result: Result<String, _> =
        preprocess_sources("root.slaspec", &repeated, PreprocessorLimits::default());
    assert!(repeated_result.is_err());
}

#[test]
fn rejects_trailing_tokens_after_quoted_directive_values() {
    for source in [
        "@include \"child.sinc\" garbage\n",
        "@define VALUE \"one\" garbage\n",
    ] {
        let sources: BTreeMap<String, String> = BTreeMap::from([
            ("root.slaspec".to_owned(), source.to_owned()),
            ("child.sinc".to_owned(), String::new()),
        ]);
        let result: Result<String, _> =
            preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
        assert!(result.is_err(), "{source}");
    }
}

#[test]
fn rejects_invalid_directive_arity() {
    for source in [
        "@if MISSING\n@else garbage\n@endif\n",
        "@if MISSING\n@endif garbage\n",
        "@undef NAME garbage\n",
        "@ifdef NAME garbage\n@endif\n",
        "@ifndef\n@endif\n",
    ] {
        let sources: BTreeMap<String, String> =
            BTreeMap::from([("root.slaspec".to_owned(), source.to_owned())]);
        let result: Result<String, _> =
            preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
        assert!(result.is_err(), "{source}");
    }
}

#[test]
fn permits_comments_after_argumentless_directives() {
    let sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@if MISSING\n@else # selected\ndefine endian=little;\n@endif # closed\n".to_owned(),
    )]);
    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn evaluates_boolean_conditions_used_by_arm_sources() {
    let sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        "@define SIMD 1\n@define VERSION_7 1\n@if (defined (SIMD) || defined(VFPv3)) && !defined(DISABLED)\nselected\n@else\nrejected\n@endif\n@if VERSION_7 == 1 && SIMD != 0\nversion\n@endif\n"
            .to_owned(),
    )]);
    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_ok(), "{result:?}");
    let output: String = result.unwrap_or_default();
    assert!(output.contains("selected"));
    assert!(output.contains("version"));
    assert!(!output.contains("rejected"));
}

#[test]
fn rejects_malformed_or_excessively_nested_boolean_conditions() {
    for condition in [
        "defined(NAME) ||",
        "defined(NAME) &&& defined(OTHER)",
        "(defined(NAME)",
        "defined()",
    ] {
        let sources: BTreeMap<String, String> = BTreeMap::from([(
            "root.slaspec".to_owned(),
            format!("@if {condition}\n@endif\n"),
        )]);
        let result: Result<String, _> =
            preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
        assert!(result.is_err(), "{condition}");
    }

    let nesting: String = format!("{}MISSING{}", "(".repeat(80), ")".repeat(80));
    let sources: BTreeMap<String, String> = BTreeMap::from([(
        "root.slaspec".to_owned(),
        format!("@if {nesting}\n@endif\n"),
    )]);
    let result: Result<String, _> =
        preprocess_sources("root.slaspec", &sources, PreprocessorLimits::default());
    assert!(result.is_err());
}
