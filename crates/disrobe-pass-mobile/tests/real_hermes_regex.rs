#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_mobile::{
    HermesModule, RecoveredRegExp, decompile_hermes_module, parse_hermes_module,
    recover_hermes_regexps,
};

const REGEX_HBC: &[u8] = include_bytes!("../../../corpus/mobile/hermes/regex/regexes.hbc.v96");
const EDGE_HBC: &[u8] = include_bytes!("../../../corpus/mobile/hermes/regex/edge.hbc.v96");
const NEST_HBC: &[u8] = include_bytes!("../../../corpus/mobile/hermes/regex/nest.hbc.v96");

fn recovered() -> Vec<RecoveredRegExp> {
    let module: HermesModule = parse_hermes_module(REGEX_HBC).expect("parse regex bundle");
    assert_eq!(module.header.version, 96, "expected HBC v96 fixture");
    assert_eq!(
        module.reg_exp_table.len(),
        23,
        "expected 23 compiled regexps"
    );
    recover_hermes_regexps(&module.reg_exp_table, &module.reg_exp_storage)
}

#[test]
fn recovers_every_regex_from_bytecode_blob() {
    let regexps: Vec<RecoveredRegExp> = recovered();
    let expected: &[(&str, &str, bool)] = &[
        ("abc", "", true),
        ("^abc$", "g", true),
        ("A.C", "i", true),
        ("\\d+", "", true),
        ("[a-z]+", "", true),
        ("[^0-9]", "", true),
        ("(foo)(bar)", "", true),
        ("a|b|c", "", true),
        ("colou?r", "", true),
        ("a{2,5}", "", true),
        ("\\bword\\b", "", true),
        ("(?:abc)+", "", true),
        ("foo(?=bar)", "", true),
        ("foo(?!bar)", "", true),
        ("(\\w)\\1", "", true),
        ("\\s*\\S+", "", true),
        ("ab*c", "", true),
        ("X{3}", "gi", true),
        ("a+?", "", true),
        ("[0-9A-Z_a-z]", "", true),
        ("hello world", "", true),
        ("\\.", "", true),
        ("[\\d\\s]", "", true),
    ];
    assert_eq!(regexps.len(), expected.len());
    for (i, (pattern, flags, modeled)) in expected.iter().enumerate() {
        let rx: &RecoveredRegExp = &regexps[i];
        assert_eq!(
            rx.pattern, *pattern,
            "regexp #{i} pattern mismatch (flags {})",
            rx.flags
        );
        assert_eq!(rx.flags, *flags, "regexp #{i} flags mismatch");
        assert_eq!(
            rx.fully_modeled, *modeled,
            "regexp #{i} modeled flag; pattern {}",
            rx.pattern
        );
    }
}

#[test]
fn capture_and_loop_counts_match_header() {
    let regexps: Vec<RecoveredRegExp> = recovered();
    assert_eq!(regexps[6].marked_count, 2, "(foo)(bar) has 2 groups");
    assert_eq!(regexps[14].marked_count, 1, "(\\w)\\1 has 1 group");
    assert_eq!(regexps[3].loop_count, 1, "\\d+ has 1 loop");
    assert_eq!(regexps[15].loop_count, 2, "\\s*\\S+ has 2 loops");
    assert_eq!(regexps[0].marked_count, 0, "abc has no groups");
}

#[test]
fn recovers_edge_constructs_from_bytecode_blob() {
    let module: HermesModule = parse_hermes_module(EDGE_HBC).expect("parse edge bundle");
    assert_eq!(module.reg_exp_table.len(), 8, "expected 8 edge regexps");
    let regexps: Vec<RecoveredRegExp> =
        recover_hermes_regexps(&module.reg_exp_table, &module.reg_exp_storage);
    let expected: &[(&str, &str, bool)] = &[
        ("(?<=foo)bar", "", true),
        ("(?<!foo)bar", "", true),
        ("\\Bx", "", true),
        ("(?:ab|cd)*", "", true),
        ("a(b(c))", "", true),
        ("[\\u00e9-\\u00ff]", "u", true),
        ("[^a-c]", "", true),
        ("x?", "", true),
    ];
    assert_eq!(regexps.len(), expected.len());
    for (i, (pattern, flags, modeled)) in expected.iter().enumerate() {
        let rx: &RecoveredRegExp = &regexps[i];
        assert_eq!(rx.pattern, *pattern, "edge regexp #{i} pattern mismatch");
        assert_eq!(rx.flags, *flags, "edge regexp #{i} flags mismatch");
        assert_eq!(rx.fully_modeled, *modeled, "edge regexp #{i} modeled flag");
    }
}

#[test]
fn recovers_nested_structural_constructs_from_bytecode_blob() {
    let module: HermesModule = parse_hermes_module(NEST_HBC).expect("parse nest bundle");
    assert_eq!(module.reg_exp_table.len(), 7, "expected 7 nested regexps");
    let regexps: Vec<RecoveredRegExp> =
        recover_hermes_regexps(&module.reg_exp_table, &module.reg_exp_storage);
    let expected: &[(&str, bool)] = &[
        ("(ab)+", true),
        ("(a|b)c", true),
        ("(x+)y", true),
        ("a(?:b|c)*d", true),
        ("((a)(b))+", true),
        ("^(\\d{3})-(\\d{4})$", true),
        ("(foo)+bar(baz)?", true),
    ];
    assert_eq!(regexps.len(), expected.len());
    for (i, (pattern, modeled)) in expected.iter().enumerate() {
        let rx: &RecoveredRegExp = &regexps[i];
        assert_eq!(rx.pattern, *pattern, "nested regexp #{i} pattern mismatch");
        assert_eq!(
            rx.fully_modeled, *modeled,
            "nested regexp #{i} modeled flag"
        );
    }
}

#[test]
fn create_regexp_lift_shows_literal_not_blob_index() {
    let module: HermesModule = parse_hermes_module(REGEX_HBC).expect("parse regex bundle");
    let report = decompile_hermes_module(&module);
    let bodies: String = report
        .functions
        .iter()
        .map(|f| f.source.as_str())
        .collect::<Vec<&str>>()
        .join("\n");
    for literal in ["/abc/", "/^abc$/g", "/\\d+/", "/(foo)(bar)/", "/colou?r/"] {
        assert!(
            bodies.contains(literal),
            "expected lifted source to contain {literal}; got:\n{bodies}"
        );
    }
    assert!(
        !bodies.contains("regexp #"),
        "no regexp should fall back to an opaque blob index; got:\n{bodies}"
    );
}
