#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{MovedDeclReversalResult, reverse_moved_declarations};

#[test]
fn rewrites_single_hoisted_var_to_first_assignment_site() {
    let src: &str = "var _tmp1;\nfunction main(){\n  _tmp1 = compute();\n  return _tmp1;\n}";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert!(r.decls_normalized >= 1, "stats: {r:?}");
    assert!(!r.rewritten_source.starts_with("var _tmp1;"));
    assert!(r.rewritten_source.contains("var _tmp1 = compute()"));
}

#[test]
fn rewrites_multiple_hoisted_vars_in_list_decl() {
    let src: &str = "var _tmp1, _tmp2;\nfunction main(){\n  _tmp1 = a();\n  _tmp2 = b(_tmp1);\n  return _tmp2;\n}";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert!(r.decls_normalized >= 1);
    assert!(r.rewritten_source.contains("var _tmp1 = a()"));
    assert!(r.rewritten_source.contains("var _tmp2 = b(_tmp1)"));
}

#[test]
fn handles_dollar_prefixed_hoisted_identifiers() {
    let src: &str = "var $hidden;\nfunction step(){\n  $hidden = 42;\n  log($hidden);\n}";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert!(r.decls_normalized >= 1);
    assert!(r.rewritten_source.contains("var $hidden = 42"));
}

#[test]
fn leaves_initialized_top_level_vars_alone() {
    let src: &str = "var data = compute();\nuse(data);";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert_eq!(r.decls_normalized, 0);
    assert_eq!(r.rewritten_source, src);
}

#[test]
fn skips_non_hoisted_looking_names() {
    let src: &str = "var counter;\nfunction inc(){ counter = counter + 1; }";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert_eq!(r.decls_normalized, 0);
    assert_eq!(r.rewritten_source, src);
}

#[test]
fn keeps_top_level_decl_when_nested_assignment_is_used_later() {
    let src: &str = "var __p_zIqX_SC;(function(){__p_zIqX_SC=function(index){return index;}})();console.log(__p_zIqX_SC(1));";
    let r: MovedDeclReversalResult = reverse_moved_declarations(src);
    assert_eq!(r.decls_normalized, 0);
    assert_eq!(r.rewritten_source, src);
}
