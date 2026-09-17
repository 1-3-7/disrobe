#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{VariableMaskingResult, reverse_variable_masking};

#[test]
fn single_proxy_to_console_resolves_through_call_site() {
    let src: &str = "var _$$_ = console;\nfunction boot(){ _$$_.log('ready'); }";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert!(r.proxies_eliminated >= 1, "stats: {r:?}");
    assert!(r.rewritten_source.contains("console.log('ready')"));
    assert!(!r.rewritten_source.contains("var _$$_"));
}

#[test]
fn two_level_alias_chain_collapses_to_root() {
    let src: &str =
        "var _$_$ = Math;\nvar _$$_ = _$_$;\nfunction work(){ return _$$_.floor(0.9); }";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert!(r.proxies_eliminated >= 1);
    assert!(r.rewritten_source.contains("Math.floor(0.9)"));
    assert!(!r.rewritten_source.contains("_$$_"));
    assert!(!r.rewritten_source.contains("_$_$"));
}

#[test]
fn three_level_alias_chain_collapses_to_root() {
    let src: &str = "var _$$_ = document;\nvar _$$$_ = _$$_;\nvar _$$$$_ = _$$$_;\nfunction g(){ return _$$$$_.getElementById('x'); }";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert!(r.proxies_eliminated >= 1);
    assert!(r.rewritten_source.contains("document.getElementById('x')"));
}

#[test]
fn does_not_rewrite_object_property_keys() {
    let src: &str = "var _$$_ = console;\nvar obj = { _$$_: 42 };\nuse(_$$_);";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert!(
        r.rewritten_source.contains("_$$_: 42"),
        "key clobbered: {r:?}"
    );
    assert!(r.rewritten_source.contains("use(console)"));
}

#[test]
fn leaves_non_proxy_identifiers_untouched() {
    let src: &str = "var data = compute();\nvar shadow = data;\nuse(shadow);";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert_eq!(r.proxies_eliminated, 0);
    assert_eq!(r.rewritten_source, src);
}
