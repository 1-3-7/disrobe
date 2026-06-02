#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_js_deob::{
    BundlerKind, ExtractedModule, UnbundleResult, auto_unbundle, detect_bun, detect_esbuild,
    detect_rollup, detect_turbopack, detect_vite, detect_webpack4, detect_webpack5, unbundle,
};

const WEBPACK4_SAMPLE: &str = include_str!("../../../corpus/src/javascript/webpack4-sample.js");
const WEBPACK5_SAMPLE: &str = include_str!("../../../corpus/src/javascript/webpack5-sample.js");
const VITE_SAMPLE: &str = include_str!("../../../corpus/src/javascript/vite-sample.js");
const ROLLUP_SAMPLE: &str = include_str!("../../../corpus/src/javascript/rollup-sample.js");
const ESBUILD_SAMPLE: &str = include_str!("../../../corpus/src/javascript/esbuild-sample.js");
const TURBOPACK_SAMPLE: &str = include_str!("../../../corpus/src/javascript/turbopack-sample.js");
const BUN_SAMPLE: &str = include_str!("../../../corpus/src/javascript/bun-sample.js");

#[test]
fn webpack4_sample_detects_and_extracts() {
    let det = detect_webpack4(WEBPACK4_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack4, WEBPACK4_SAMPLE).expect("unbundle");
    assert!(!result.modules.is_empty());
    assert!(
        result
            .modules
            .iter()
            .any(|m: &ExtractedModule| m.source.contains("module.exports"))
    );
}

#[test]
fn webpack5_sample_detects_and_extracts() {
    let det = detect_webpack5(WEBPACK5_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, WEBPACK5_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "./src/index.js"));
    assert!(result.modules.iter().any(|m| m.id == "./src/util.js"));
}

#[test]
fn vite_sample_detects_and_extracts_named_exports() {
    let det = detect_vite(VITE_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult = unbundle(BundlerKind::Vite, VITE_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "loadPage"));
    assert!(result.modules.iter().any(|m| m.id == "bootstrap"));
}

#[test]
fn rollup_sample_detects_and_extracts_named_exports() {
    let det = detect_rollup(ROLLUP_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult = unbundle(BundlerKind::Rollup, ROLLUP_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "VERSION"));
    assert!(result.modules.iter().any(|m| m.id == "greet"));
    assert!(result.modules.iter().any(|m| m.id == "Widget"));
}

#[test]
fn esbuild_sample_detects_and_extracts_commonjs() {
    let det = detect_esbuild(ESBUILD_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult = unbundle(BundlerKind::Esbuild, ESBUILD_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "./src/index.js"));
    assert!(result.modules.iter().any(|m| m.id == "./src/util.js"));
}

#[test]
fn turbopack_sample_detects_and_extracts() {
    let det = detect_turbopack(TURBOPACK_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult =
        unbundle(BundlerKind::Turbopack, TURBOPACK_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "./app/page.tsx"));
}

#[test]
fn bun_sample_detects_and_extracts() {
    let det = detect_bun(BUN_SAMPLE);
    assert!(det.matched, "{det:?}");
    let result: UnbundleResult = unbundle(BundlerKind::Bun, BUN_SAMPLE).expect("unbundle");
    assert!(result.modules.iter().any(|m| m.id == "./a.ts"));
    assert!(result.modules.iter().any(|m| m.id == "./b.ts"));
}

#[test]
fn auto_unbundle_picks_webpack5_over_webpack4() {
    let result: UnbundleResult = auto_unbundle(WEBPACK5_SAMPLE).expect("auto");
    assert_eq!(result.kind, BundlerKind::Webpack5);
}

#[test]
fn auto_unbundle_picks_esbuild() {
    let result: UnbundleResult = auto_unbundle(ESBUILD_SAMPLE).expect("auto");
    assert_eq!(result.kind, BundlerKind::Esbuild);
}
