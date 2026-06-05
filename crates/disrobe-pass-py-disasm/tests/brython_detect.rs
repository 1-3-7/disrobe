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

#[test]
#[ignore = "requires the uncommitted corpus/python/alt_runtimes/brython/hello.brython.js fixture; run with --ignored once present"]
fn brython_real_corpus() {
    const CORPUS: &str = "../../corpus/python/alt_runtimes/brython/hello.brython.js";
    let path: std::path::PathBuf = std::env::current_dir().expect("cwd").join(CORPUS);
    assert!(
        path.exists(),
        "missing brython corpus fixture: {}",
        path.display()
    );
    let bytes: Vec<u8> = std::fs::read(&path).expect("read");
    assert!(detect(&bytes));
}
