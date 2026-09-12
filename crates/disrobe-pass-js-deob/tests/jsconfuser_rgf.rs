#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{RgfReversalResult, reverse_rgf};

#[test]
fn reverses_single_entry_rgf() {
    let src: &str = "var _rgf_a = [new Function('return 1+2')]; var x = _rgf_a[0].apply(this, [_rgf_a, arguments]);";
    let result: RgfReversalResult = reverse_rgf(src);

    assert_eq!(result.array_id.as_deref(), Some("_rgf_a"));
    assert_eq!(result.entries_extracted, 1);
    assert_eq!(result.call_sites_inlined, 1);
    assert!(
        result
            .rewritten_source
            .contains("(function(){return 1+2})()"),
        "expected IIFE substitution, got: {}",
        result.rewritten_source
    );
    assert!(
        !result.rewritten_source.contains("_rgf_a ="),
        "rgf array declaration should be removed, got: {}",
        result.rewritten_source
    );
    assert!(
        !result.rewritten_source.contains("new Function"),
        "new Function literal should be gone, got: {}",
        result.rewritten_source
    );
}

#[test]
fn reverses_multi_entry_rgf_preserves_order() {
    let src: &str = r"var _rgf_x = [new Function('return 10'), new Function('return 20'), new Function('return 30')];
var a = _rgf_x[0].apply(this, [_rgf_x, arguments]);
var b = _rgf_x[1].apply(this, [_rgf_x, arguments]);
var c = _rgf_x[2].apply(this, [_rgf_x, arguments]);";
    let result: RgfReversalResult = reverse_rgf(src);

    assert_eq!(result.array_id.as_deref(), Some("_rgf_x"));
    assert_eq!(result.entries_extracted, 3);
    assert_eq!(result.call_sites_inlined, 3);

    let rewritten: &String = &result.rewritten_source;
    let pos_10: usize = rewritten
        .find("(function(){return 10})()")
        .expect("body 0 missing");
    let pos_20: usize = rewritten
        .find("(function(){return 20})()")
        .expect("body 1 missing");
    let pos_30: usize = rewritten
        .find("(function(){return 30})()")
        .expect("body 2 missing");
    assert!(
        pos_10 < pos_20 && pos_20 < pos_30,
        "body order must be preserved at indices 0,1,2; got positions {pos_10},{pos_20},{pos_30}"
    );
    assert!(
        !rewritten.contains("_rgf_x = ["),
        "array decl must be removed: {rewritten}"
    );
}

#[test]
fn leaves_non_matching_arrays_alone() {
    let src: &str = "var x = [1, 2, 3]; var y = x[0]; console.log(y);";
    let result: RgfReversalResult = reverse_rgf(src);

    assert!(result.array_id.is_none(), "no rgf array should be detected");
    assert_eq!(result.entries_extracted, 0);
    assert_eq!(result.call_sites_inlined, 0);
    assert_eq!(result.rewritten_source, src, "source must be untouched");
}

#[test]
fn handles_pretty_printed_whitespace() {
    let src: &str = r"var   _rgf_pretty  =  [
    new Function( 'return 42' ),
    new Function( 'return 99' )
];

var first  =   _rgf_pretty [ 0 ] . apply ( this , [ _rgf_pretty , arguments ] ) ;
var second =   _rgf_pretty[1].apply(this,[_rgf_pretty,arguments]);
";
    let result: RgfReversalResult = reverse_rgf(src);

    assert_eq!(result.array_id.as_deref(), Some("_rgf_pretty"));
    assert_eq!(result.entries_extracted, 2);
    assert_eq!(
        result.call_sites_inlined, 2,
        "both call-sites must inline even across pretty-print whitespace; got source: {}",
        result.rewritten_source
    );
    assert!(
        result
            .rewritten_source
            .contains("(function(){return 42})()"),
        "first body missing: {}",
        result.rewritten_source
    );
    assert!(
        result
            .rewritten_source
            .contains("(function(){return 99})()"),
        "second body missing: {}",
        result.rewritten_source
    );
}
