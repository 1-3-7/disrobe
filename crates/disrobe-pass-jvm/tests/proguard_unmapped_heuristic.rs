#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_jvm::{UnmappedHeuristics, heuristic_recover};

#[test]
fn recovers_only_short_mangled_names() {
    let names: Vec<String> = vec![
        "a".into(),
        "ab".into(),
        "xyz".into(),
        "longName".into(),
        "Foo".into(),
    ];
    let h: UnmappedHeuristics = heuristic_recover(&names);
    assert!(h.mapped.contains_key("a"));
    assert!(h.mapped.contains_key("ab"));
    assert!(h.mapped.contains_key("xyz"));
    assert!(!h.mapped.contains_key("longName"));
    assert!(!h.mapped.contains_key("Foo"));
}
