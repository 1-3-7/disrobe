#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_mba::rules::{LoadError, RuleSet, load_str, mba_peephole_rules};

#[test]
fn shipped_rules_load_and_have_six_migrated_rules() {
    let set: RuleSet = mba_peephole_rules().expect("shipped rules load");
    assert_eq!(set.len(), 6);
    assert!(set.commutative_match);
}

#[test]
fn empty_rule_set_is_rejected() {
    let text: &str = "rules = []\n";
    assert!(matches!(load_str(text), Err(LoadError::Empty)));
}

#[test]
fn unbound_capture_in_rewrite_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "broken"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "use", expr = "y" }
"#;
    match load_str(text) {
        Err(LoadError::UnboundCapture { rule, capture }) => {
            assert_eq!(rule, "broken");
            assert_eq!(capture, "y");
        }
        other => panic!("expected UnboundCapture, got {other:?}"),
    }
}

#[test]
fn unbound_capture_in_condition_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "broken_cond"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "any_expr", bind = "y" } }
when = [{ check = "equal", left = "x", right = "z" }]
rewrite = { build = "use", expr = "x" }
"#;
    match load_str(text) {
        Err(LoadError::UnboundCapture { capture, .. }) => assert_eq!(capture, "z"),
        other => panic!("expected UnboundCapture, got {other:?}"),
    }
}

#[test]
fn duplicate_capture_binding_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "dup_bind"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "any_expr", bind = "x" } }
rewrite = { build = "use", expr = "x" }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::DuplicateCapture { .. })
    ));
}

#[test]
fn duplicate_rule_name_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "twin"
pattern = { kind = "var", index = 0 }
rewrite = { build = "const", value = 0 }

[[rules]]
name = "twin"
pattern = { kind = "var", index = 1 }
rewrite = { build = "const", value = 1 }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::DuplicateRuleName { .. })
    ));
}

#[test]
fn malformed_toml_is_rejected() {
    let text: &str = "this is not = valid toml [[[";
    assert!(matches!(load_str(text), Err(LoadError::Toml(_))));
}

#[test]
fn rule_set_round_trips_through_json() {
    let set: RuleSet = mba_peephole_rules().expect("shipped rules load");
    let json: String = serde_json::to_string(&set).expect("serialize");
    let back: RuleSet = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(set, back);
}
