#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_core::{YaraParseError, YaraStringKind, parse_yara_report, parse_yara_ruleset};

const SAMPLE: &str = r#"
import "pe"
// leading comment
rule Demo : malware trojan {
    meta:
        author = "x"
        score = 10
    strings:
        $s = "hi"
        $h = { AA BB ?? [2-4] (CC | DD) }
        $r = /re/i
    condition:
        $s and $h /* inline */ or $r
}
"#;

#[test]
fn parses_full_rule_all_string_kinds() {
    let ruleset: disrobe_core::YaraRuleset = parse_yara_ruleset(SAMPLE).expect("sample must parse");
    assert_eq!(ruleset.imports, vec!["pe".to_owned()]);
    assert_eq!(ruleset.rules.len(), 1);
    let rule: &disrobe_core::YaraRule = &ruleset.rules[0];
    assert_eq!(rule.name, "Demo");
    assert_eq!(rule.tags, vec!["malware".to_owned(), "trojan".to_owned()]);
    assert_eq!(rule.meta.get("author").map(String::as_str), Some("x"));
    assert_eq!(rule.meta.get("score").map(String::as_str), Some("10"));
    assert_eq!(rule.strings.len(), 3);

    assert_eq!(rule.strings[0].id, "$s");
    assert_eq!(rule.strings[0].kind, YaraStringKind::Text);
    assert_eq!(rule.strings[0].value, "hi");

    assert_eq!(rule.strings[1].id, "$h");
    assert_eq!(rule.strings[1].kind, YaraStringKind::Hex);
    assert!(rule.strings[1].value.contains("AA BB"));

    assert_eq!(rule.strings[2].id, "$r");
    assert_eq!(rule.strings[2].kind, YaraStringKind::Regex);
    assert_eq!(rule.strings[2].value, "re");
    assert_eq!(rule.strings[2].modifiers, vec!["i".to_owned()]);

    assert!(rule.condition.contains("$s and $h"));
    assert!(rule.condition.contains("$r"));
    assert!(!rule.condition.contains("inline"));
}

#[test]
fn parses_multi_rule_with_imports_and_modifiers() {
    let src: &str = r#"
import "pe"
rule First { condition: true }
private global rule Second { condition: false }
"#;
    let ruleset: disrobe_core::YaraRuleset = parse_yara_ruleset(src).expect("must parse");
    assert_eq!(ruleset.imports, vec!["pe".to_owned()]);
    assert_eq!(ruleset.rules.len(), 2);
    assert_eq!(ruleset.rules[0].name, "First");
    assert_eq!(ruleset.rules[1].name, "Second");
    assert_eq!(
        ruleset.rules[1].modifiers,
        vec!["private".to_owned(), "global".to_owned()]
    );
}

#[test]
fn text_string_modifiers_captured() {
    let src: &str = r#"rule A { strings: $a = "abc" nocase wide condition: $a }"#;
    let ruleset: disrobe_core::YaraRuleset = parse_yara_ruleset(src).expect("must parse");
    let rule: &disrobe_core::YaraRule = &ruleset.rules[0];
    assert_eq!(rule.strings[0].value, "abc");
    assert_eq!(
        rule.strings[0].modifiers,
        vec!["nocase".to_owned(), "wide".to_owned()]
    );
}

#[test]
fn strips_line_and_block_comments() {
    let src: &str = "
// foo
rule A /* bar */ {
    condition: true
}
";
    let ruleset: disrobe_core::YaraRuleset = parse_yara_ruleset(src).expect("must parse");
    assert_eq!(ruleset.rules[0].name, "A");
    assert_eq!(ruleset.rules[0].condition, "true");
}

#[test]
fn err_missing_rule_name() {
    let err: YaraParseError = parse_yara_ruleset("rule { condition: true }").expect_err("reject");
    assert!(matches!(err, YaraParseError::MissingRuleName { .. }));
}

#[test]
fn err_unbalanced_braces() {
    let err: YaraParseError = parse_yara_ruleset("rule A { condition: true").expect_err("reject");
    assert!(matches!(err, YaraParseError::UnbalancedBraces { .. }));
}

#[test]
fn err_missing_condition() {
    let err: YaraParseError =
        parse_yara_ruleset(r#"rule A { strings: $a = "x" }"#).expect_err("reject");
    assert!(matches!(err, YaraParseError::MissingCondition { .. }));
}

#[test]
fn err_malformed_string_assignment() {
    let err: YaraParseError =
        parse_yara_ruleset("rule A { strings: $a = condition: true }").expect_err("reject");
    assert!(matches!(
        err,
        YaraParseError::MalformedStringAssignment { .. }
    ));
}

#[test]
fn err_unterminated_text_string() {
    let err: YaraParseError =
        parse_yara_ruleset("rule A { strings: $a = \"oops\n condition: true }")
            .expect_err("reject");
    assert!(matches!(err, YaraParseError::UnterminatedValue { .. }));
}

#[test]
fn adversarial_multi_rule_real_grammar() {
    let src: &str = r#"
import "pe"
include "shared.yar"

private rule Alpha : banker dropper {
    meta:
        author = "fern"
        severity = 8
        active = true
    strings:
        $tok = "UPGRADE" nocase fullword
        $hx = { 6A 40 68 00 30 ?? [1-4] (FF | EE) }
        $rx = /https?:\/\/c2\.evil/i
    condition:
        $tok and ($hx or $rx)
}

global rule Beta {
    condition:
        Alpha and filesize < 100
}
"#;
    let ruleset: disrobe_core::YaraRuleset = parse_yara_ruleset(src).expect("must parse");
    assert_eq!(ruleset.imports, vec!["pe".to_owned()]);
    assert_eq!(ruleset.includes, vec!["shared.yar".to_owned()]);
    assert_eq!(ruleset.rules.len(), 2);

    let alpha: &disrobe_core::YaraRule = &ruleset.rules[0];
    assert_eq!(alpha.name, "Alpha");
    assert_eq!(alpha.modifiers, vec!["private".to_owned()]);
    assert_eq!(alpha.tags, vec!["banker".to_owned(), "dropper".to_owned()]);
    assert_eq!(alpha.meta.get("author").map(String::as_str), Some("fern"));
    assert_eq!(alpha.meta.get("severity").map(String::as_str), Some("8"));
    assert_eq!(alpha.meta.get("active").map(String::as_str), Some("true"));
    assert_eq!(alpha.strings.len(), 3);

    assert_eq!(alpha.strings[0].id, "$tok");
    assert_eq!(alpha.strings[0].kind, YaraStringKind::Text);
    assert_eq!(alpha.strings[0].value, "UPGRADE");
    assert_eq!(
        alpha.strings[0].modifiers,
        vec!["nocase".to_owned(), "fullword".to_owned()]
    );

    assert_eq!(alpha.strings[1].id, "$hx");
    assert_eq!(alpha.strings[1].kind, YaraStringKind::Hex);
    assert!(alpha.strings[1].value.contains("6A 40 68 00 30 ??"));
    assert!(alpha.strings[1].value.contains("(FF | EE)"));

    assert_eq!(alpha.strings[2].id, "$rx");
    assert_eq!(alpha.strings[2].kind, YaraStringKind::Regex);
    assert_eq!(alpha.strings[2].value, r"https?:\/\/c2\.evil");
    assert_eq!(alpha.strings[2].modifiers, vec!["i".to_owned()]);

    assert_eq!(alpha.condition, "$tok and ($hx or $rx)");

    let beta: &disrobe_core::YaraRule = &ruleset.rules[1];
    assert_eq!(beta.name, "Beta");
    assert_eq!(beta.modifiers, vec!["global".to_owned()]);
    assert!(beta.tags.is_empty());
    assert_eq!(beta.condition, "Alpha and filesize < 100");
}

#[test]
fn adversarial_rejects_garbage_and_truncation() {
    assert!(parse_yara_ruleset("this is not yara at all").is_err());
    assert!(matches!(
        parse_yara_ruleset(r#"rule Bad { strings: $a = "x" }"#).expect_err("no condition"),
        YaraParseError::MissingCondition { .. }
    ));
    assert!(matches!(
        parse_yara_ruleset("rule Open { condition: 1").expect_err("truncated"),
        YaraParseError::UnbalancedBraces { .. }
    ));
    assert!(matches!(
        parse_yara_ruleset(r"rule R { strings: $a = /unterminated").expect_err("regex"),
        YaraParseError::UnterminatedValue { .. } | YaraParseError::UnbalancedBraces { .. }
    ));
}

#[test]
fn report_roundtrips_json() {
    let report: disrobe_core::YaraLoaderReport =
        parse_yara_report(SAMPLE, Some("u.yar")).expect("must parse");
    assert_eq!(report.schema, "disrobe.yara.ruleset/v0");
    assert_eq!(report.rule_count, 1);
    let value: serde_json::Value = serde_json::to_value(&report).expect("must serialize");
    assert_eq!(
        value["schema"],
        serde_json::json!("disrobe.yara.ruleset/v0")
    );
    assert_eq!(value["rule_count"], serde_json::json!(1));
    let back: disrobe_core::YaraRuleset =
        serde_json::from_value(value["ruleset"].clone()).expect("must round-trip");
    assert_eq!(back.rules[0].name, "Demo");
    let keys: Vec<&String> = back.rules[0].meta.keys().collect();
    assert_eq!(keys, vec!["author", "score"]);
}
