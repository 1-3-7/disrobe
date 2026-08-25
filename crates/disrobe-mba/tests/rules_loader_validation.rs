#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_mba::rules::{LoadError, RuleSet, load_str, mba_peephole_rules};

#[test]
fn shipped_rules_load_and_have_thirty_four_migrated_rules() {
    let set: RuleSet = mba_peephole_rules().expect("shipped rules load");
    assert_eq!(set.len(), 34);
    assert!(set.commutative_match);
}

#[test]
fn a_rule_is_rejected_when_a_declared_width_fails_shared_equivalence() {
    let text: &str = r#"
[[rules]]
name = "neg_is_identity"
widths = [1, 2]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "unary", op = "neg", operand = { kind = "any_expr", bind = "x" } }
rewrite = { build = "use", expr = "x" }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::EquivalenceRejected { rule, width })
            if rule == "neg_is_identity" && width == 2
    ));
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
widths = [8]
proof = "shared_equivalence"
source = "test"
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
widths = [8]
proof = "shared_equivalence"
source = "test"
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
widths = [8]
proof = "shared_equivalence"
source = "test"
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
widths = [8]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "var", index = 0 }
rewrite = { build = "const", value = 0 }

[[rules]]
name = "twin"
widths = [8]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "var", index = 1 }
rewrite = { build = "const", value = 1 }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::DuplicateRuleName { .. })
    ));
}

#[test]
fn unconditional_rule_cycle_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "add_to_sub"
widths = [8]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "binary", op = "sub", left = { build = "use", expr = "x" }, right = { build = "const", value = 0 } }

[[rules]]
name = "sub_to_add"
widths = [8]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "binary", op = "sub", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "binary", op = "add", left = { build = "use", expr = "x" }, right = { build = "const", value = 0 } }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::RewriteCycle { .. })
    ));
}

#[test]
fn exact_self_rewrite_cycle_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "self_cycle"
widths = [8]
proof = "shared_equivalence"
source = "test"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "binary", op = "add", left = { build = "use", expr = "x" }, right = { build = "const", value = 0 } }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::RewriteCycle { .. })
    ));
}

#[test]
fn ungraded_rule_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "ungraded"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "use", expr = "x" }
"#;
    assert!(load_str(text).is_err());
}

#[test]
fn non_shared_proof_route_is_rejected() {
    let text: &str = r#"
[[rules]]
name = "wrong_proof_route"
widths = [8]
proof = "per_rule"
source = "test"
pattern = { kind = "binary", op = "add", left = { kind = "any_expr", bind = "x" }, right = { kind = "const", value = 0 } }
rewrite = { build = "use", expr = "x" }
"#;
    assert!(matches!(
        load_str(text),
        Err(LoadError::MissingProofRoute { .. })
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
