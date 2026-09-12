#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    DeobOptions, DeobOutput, IntegrityReversalResult, LockReversalResult, PackingReversalResult,
    StringCompressionResult, StringEncodingResult, VariableMaskingResult, deobfuscate_all,
    reverse_packing, reverse_string_compression, reverse_string_encoding, reverse_variable_masking,
    strip_integrity, strip_locks,
};

const MULTI_TRANSFORM: &str =
    include_str!("../../../corpus/src/javascript/jsconfuser-multi-transform.js");

#[test]
fn deobfuscate_all_applies_string_encoding_and_compression_and_lock() {
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(MULTI_TRANSFORM, &opts);
    assert!(out.string_literals_decoded >= 1, "encoding stats: {out:?}");
    assert!(out.string_compression_blocks_reversed >= 1);
    assert!(out.lock_guards_stripped >= 1, "lock stats: {out:?}");
    assert!(out.source.contains("\"hello\"") || out.source.contains("'hello'"));
    assert!(!out.source.contains("attacker.com"));
}

#[test]
fn variable_masking_resolves_alias_chain_into_target() {
    let src: &str = "var _$$_ = console;\nvar _$$$_ = _$$_;\nfunction main(){ _$$$_.log('done'); }";
    let r: VariableMaskingResult = reverse_variable_masking(src);
    assert!(r.proxies_eliminated >= 1);
    assert!(r.rewritten_source.contains("console.log('done')"));
}

#[test]
fn string_encoding_decodes_mixed_x_and_unicode() {
    let src: &str = "var s = '\\x68\\x69 \\u0041\\u0042';";
    let r: StringEncodingResult = reverse_string_encoding(src);
    assert_eq!(r.literals_decoded, 1);
    assert!(r.rewritten_source.contains("'hi AB'"));
}

#[test]
fn string_compression_expands_split_and_fromcharcode() {
    let src: &str = "var a = 'x|y|z'.split('|');\nvar b = String.fromCharCode(65, 66, 67);";
    let r: StringCompressionResult = reverse_string_compression(src);
    assert_eq!(r.blocks_reversed, 2);
    assert!(r.rewritten_source.contains("[\"x\", \"y\", \"z\"]"));
    assert!(r.rewritten_source.contains("\"ABC\""));
}

#[test]
fn full_pipeline_decodes_lzstring_string_compression() {
    let src: &str = "var LZString={decompressFromBase64:function(){},_decompress:function(){},_compress:function(){}};\nvar msg = LZString.decompressFromBase64(\"IYGwpgTgLgFAjASgNxA=\");";
    let opts: DeobOptions = DeobOptions::all();
    let out: DeobOutput = deobfuscate_all(src, &opts);
    assert_eq!(out.string_compression_blocks_reversed, 1);
    assert!(out.source.contains("var msg = \"alert(1);\";"));
}

#[test]
fn lock_strips_hostname_and_iframe_top_guards() {
    let src: &str = "function start(){\n  if (window.location.hostname !== 'good.com') { return; }\n  if (self !== window.top) { return; }\n  run();\n}";
    let r: LockReversalResult = strip_locks(src);
    assert!(r.guards_stripped >= 1, "expected ≥1 guard stripped");
    assert!(r.rewritten_source.contains("run()"));
}

#[test]
fn integrity_strips_setinterval_self_hash_check() {
    let src: &str = "setInterval(function(){ if(fn.toString().replace(/\\s/g,'').length !== 1000) { location.href = 'about:blank'; } }, 500);\nrun();";
    let r: IntegrityReversalResult = strip_integrity(src);
    assert_eq!(r.loops_stripped, 1);
    assert!(r.rewritten_source.contains("run()"));
}

#[test]
fn packing_expands_dean_edwards_payload() {
    let src: &str =
        "eval(function(p,a,c,k,e,d){return p}('1 0',10,2,'hi|bye'.split('|'),0,{}));\nfollowup();";
    let r: PackingReversalResult = reverse_packing(src);
    assert_eq!(r.blocks_expanded, 1);
    assert!(r.rewritten_source.contains("bye hi"));
    assert!(r.rewritten_source.contains("followup()"));
}
