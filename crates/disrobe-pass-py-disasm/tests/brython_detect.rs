#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_py_disasm::alt_runtimes::brython::{
    BrythonModule, JsDeobHandoff, detect, handoff, parse,
};

const BRYTHON_REAL_SHAPE: &str = r"
__BRYTHON__ = (function() {
    var $B = {};
    $B.modules = {};
    $B.imported = {};
    $B.modules['hello'] = (function() {
        var $locals_hello = {};
        $locals_hello.greet = function(){ return 'hi'; };
        return $locals_hello;
    })();
    $B.imported['hello'] = true;
    return $B;
})();
";

const PLAIN_JS: &str = "function add(a, b) { return a + b; } module.exports = add;";

#[test]
fn detects_brython_runtime_marker() {
    assert!(detect(BRYTHON_REAL_SHAPE.as_bytes()));
}

#[test]
fn rejects_plain_javascript() {
    assert!(!detect(PLAIN_JS.as_bytes()));
}

#[test]
fn parse_collects_all_present_markers() {
    let module: BrythonModule = parse(BRYTHON_REAL_SHAPE.as_bytes()).expect("parse");
    assert!(module.markers.len() >= 3);
}

#[test]
fn handoff_delegates_to_js_deob() {
    let h: JsDeobHandoff = handoff(BRYTHON_REAL_SHAPE.as_bytes()).expect("handoff");
    assert!(!h.family.is_empty());
    assert!(!h.brython_markers.is_empty());
    assert!(h.confidence_pct <= 100);
    assert!(h.source_len > 0);
}

#[test]
fn parse_on_plain_js_returns_not_detected() {
    let err: disrobe_pass_py_disasm::AltRuntimeError =
        parse(PLAIN_JS.as_bytes()).expect_err("must fail");
    assert!(matches!(
        err,
        disrobe_pass_py_disasm::AltRuntimeError::NotDetected(_)
    ));
}

#[test]
fn detects_brython_init_function_call() {
    let snippet: &str = "<script>window.onload = function() { brython({debug: 1}); };</script>";
    assert!(detect(snippet.as_bytes()));
}

const REAL_CORPUS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/brython/hello.brython.js");

#[test]
fn brython_real_corpus_make_package_detected() {
    assert!(
        detect(REAL_CORPUS),
        "real Brython 3.14.2 make_package output must be detected"
    );
    let obf: &str = std::str::from_utf8(REAL_CORPUS).expect("utf-8 brython package");
    assert!(
        obf.contains("__BRYTHON__.loadBrythonPackage("),
        "fixture must be the authentic make_package runtime-registration form"
    );
}

#[test]
fn brython_real_corpus_parse_and_handoff() {
    let module: BrythonModule = parse(REAL_CORPUS).expect("parse real brython package");
    assert!(
        module.markers.contains(&"__BRYTHON__".to_owned()),
        "the __BRYTHON__ runtime marker must be surfaced; markers={:?}",
        module.markers
    );

    let h: JsDeobHandoff = handoff(REAL_CORPUS).expect("handoff real brython package");
    assert!(!h.family.is_empty(), "js-deob family must be classified");
    assert!(
        h.brython_markers.contains(&"__BRYTHON__".to_owned()),
        "handoff must carry the brython marker for the JS pass"
    );
    assert!(h.confidence_pct <= 100);
    assert_eq!(
        usize::try_from(h.source_len).expect("source_len fits usize"),
        REAL_CORPUS.len(),
        "handoff source span must cover the whole real artifact"
    );
}

#[test]
fn brython_real_corpus_carries_inlined_python_source() {
    let obf: &str = std::str::from_utf8(REAL_CORPUS).expect("utf-8 brython package");
    for needle in ["def greet(name):", "class Greeter:", "def say(self,name):"] {
        assert!(
            obf.contains(needle),
            "make_package inlines the original Python source for runtime compile; missing {needle:?}"
        );
    }
}
