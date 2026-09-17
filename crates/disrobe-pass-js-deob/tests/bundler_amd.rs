#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use disrobe_pass_js_deob::{
    BundlerDetection, BundlerKind, ChunkNode, ExtractedModule, ModuleGraph, UnbundleGraphResult,
    detect_amd, unbundle_with_graph,
};

const AMD_DEFINE: &str = include_str!("../corpus/bundlers/amd/define/bundle.js");

const SYNTHETIC_AMD: &str = r#"define("app/main", ["app/util", "jquery"], function (util, $) {
  return util.add(1, 2);
});
define("app/util", [], function () {
  return { add: function (a, b) { return a + b; } };
});
define(function (require, exports, module) {
  module.exports = require("app/main");
});"#;

const NON_AMD: &str = "function predefine(x) { return x; }
var registry = redefine({ a: 1 });
function define_helper() { return registry; }
console.log(predefine(define_helper()));";

#[test]
fn amd_detects_real_fixture() {
    let det: BundlerDetection = detect_amd(AMD_DEFINE);
    assert!(det.matched, "{det:?}");
    assert_eq!(det.kind, BundlerKind::Amd);
}

#[test]
fn amd_splits_real_fixture_into_named_modules() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Amd, AMD_DEFINE).expect("unbundle");
    let ids: Vec<&str> = result
        .modules
        .iter()
        .map(|m: &ExtractedModule| m.id.as_str())
        .collect();
    assert!(ids.contains(&"my/lib/core"), "ids: {ids:?}");
    assert!(ids.contains(&"my/lib/util"), "ids: {ids:?}");
    let core: &ExtractedModule = result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == "my/lib/core")
        .expect("core");
    assert_eq!(core.chunk_id.as_deref(), Some("deps:jquery,lodash"));
}

#[test]
fn amd_synthetic_resolves_dependency_graph() {
    let result: UnbundleGraphResult =
        unbundle_with_graph(BundlerKind::Amd, SYNTHETIC_AMD).expect("unbundle");
    assert_eq!(result.modules.len(), 3, "{:?}", result.modules);

    let graph: &ModuleGraph = &result.graph;
    let main: &ChunkNode = graph.chunks.get("app/main").expect("app/main chunk");
    assert_eq!(
        main.imports,
        vec!["app/util".to_owned(), "jquery".to_owned()],
        "main imports must resolve verbatim from the dep array"
    );

    let util: &ChunkNode = graph.chunks.get("app/util").expect("app/util chunk");
    assert!(
        util.imports.is_empty(),
        "util has no deps: {:?}",
        util.imports
    );

    let cjs_module: &ExtractedModule = result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == "module-2")
        .expect("anonymous cjs module");
    assert_eq!(
        cjs_module.chunk_id.as_deref(),
        Some("deps:require,exports,module"),
        "cjs sugar factory must recover the injected require/exports/module deps"
    );
    let cjs_chunk: &ChunkNode = graph.chunks.get("module-2").expect("module-2 chunk");
    assert!(
        cjs_chunk.imports.is_empty(),
        "reserved deps are excluded from graph imports: {:?}",
        cjs_chunk.imports
    );
}

#[test]
fn amd_leaves_non_amd_input_alone() {
    let det: BundlerDetection = detect_amd(NON_AMD);
    assert!(
        !det.matched,
        "lookalike identifiers must not match: {det:?}"
    );
    let outcome: Result<UnbundleGraphResult, disrobe_pass_js_deob::Error> =
        unbundle_with_graph(BundlerKind::Amd, NON_AMD);
    assert!(
        outcome.is_err(),
        "non-amd input yields no modules and no match"
    );
}
