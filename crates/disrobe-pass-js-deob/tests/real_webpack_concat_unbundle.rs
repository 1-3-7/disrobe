#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use disrobe_pass_js_deob::{
    BundlerKind, ExtractedModule, UnbundleResult, auto_unbundle, unbundle, write_modules,
};

fn corpus_path(rel: &str) -> PathBuf {
    let manifest: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .join("..")
        .join("..")
        .join("corpus")
        .join("js")
        .join(rel)
}

fn load(rel: &str) -> Option<String> {
    let p: PathBuf = corpus_path(rel);
    if !p.exists() {
        return None;
    }
    fs::read_to_string(&p).ok()
}

fn module_by_id<'a>(result: &'a UnbundleResult, id: &str) -> &'a ExtractedModule {
    result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == id)
        .unwrap_or_else(|| panic!("module {id} not extracted; got {:?}", ids(result)))
}

fn ids(result: &UnbundleResult) -> Vec<String> {
    result
        .modules
        .iter()
        .map(|m: &ExtractedModule| m.id.clone())
        .collect()
}

#[test]
fn real_webpack5_concat_bundle_splits_into_per_module_files() {
    let Some(src): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    assert!(
        src.contains(";// ./src/util.js"),
        "fixture precondition: bundle must use webpack module-concatenation path comments",
    );

    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, &src).expect("webpack5 unbundle must succeed");

    assert!(
        result.modules.len() >= 3,
        "expected at least the three source modules; got {:?}",
        ids(&result),
    );
    for expected in ["./src/util.js", "./src/math.js", "./src/index.js"] {
        let module: &ExtractedModule = module_by_id(&result, expected);
        assert!(
            !module.source.trim().is_empty(),
            "module {expected} must carry its source body",
        );
    }

    let util: &ExtractedModule = module_by_id(&result, "./src/util.js");
    assert!(
        util.source.contains("const greet") && util.source.contains("class Counter"),
        "util module must contain its real declarations; got:\n{}",
        util.source,
    );
    let math: &ExtractedModule = module_by_id(&result, "./src/math.js");
    assert!(
        math.source.contains("const add") && math.source.contains("factorial"),
        "math module must contain its real declarations; got:\n{}",
        math.source,
    );
    let index: &ExtractedModule = module_by_id(&result, "./src/index.js");
    assert!(
        index.source.contains("console.log") && index.source.contains("new Counter"),
        "index module must contain the program entry code; got:\n{}",
        index.source,
    );
    assert!(
        !index
            .source
            .contains("module.exports = __webpack_exports__"),
        "the webpack runtime tail must not leak into the last module; got:\n{}",
        index.source,
    );
}

#[test]
fn real_webpack5_auto_unbundle_picks_webpack_and_emits_module_map() {
    let Some(src): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    let result: UnbundleResult = auto_unbundle(&src).expect("auto unbundle must succeed");
    assert_eq!(result.kind, BundlerKind::Webpack5);
    assert!(result.detection.matched, "webpack5 must be detected");
    assert!(result.modules.len() >= 3, "auto path must extract modules");

    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-js-unbundle-{}-{}",
        std::process::id(),
        result.modules.len()
    ));
    let _ = fs::remove_dir_all(&dir);
    let written: BTreeMap<String, PathBuf> =
        write_modules(&dir, &result).expect("write_modules must succeed");
    assert_eq!(
        written.len(),
        result.modules.len(),
        "every extracted module must be written to its own file",
    );
    for path in written.values() {
        assert!(
            Path::new(path).exists(),
            "written module file must exist: {}",
            path.display()
        );
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn webpack5_crlf_bundle_extracts_every_module_with_bodies() {
    let Some(lf): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    let crlf: String = lf.replace("\r\n", "\n").replace('\n', "\r\n");
    assert!(crlf.contains('\r'), "fixture must be converted to CRLF");

    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, &crlf).expect("crlf webpack5 unbundle must succeed");
    assert!(
        result.modules.len() >= 3,
        "CRLF input must still split the three source modules; got {:?}",
        ids(&result),
    );
    for expected in ["./src/util.js", "./src/math.js", "./src/index.js"] {
        let module: &ExtractedModule = module_by_id(&result, expected);
        assert!(
            !module.source.trim().is_empty(),
            "CRLF module {expected} must carry its source body",
        );
    }
    let util: &ExtractedModule = module_by_id(&result, "./src/util.js");
    assert!(
        util.source.contains("const greet") && util.source.contains("class Counter"),
        "CRLF util module must contain its real declarations; got:\n{}",
        util.source,
    );
    let index: &ExtractedModule = module_by_id(&result, "./src/index.js");
    assert!(
        !index
            .source
            .contains("module.exports = __webpack_exports__"),
        "CRLF runtime tail must not leak into the last module; got:\n{}",
        index.source,
    );
}

#[test]
fn webpack5_unbundle_is_deterministic_across_repeated_calls() {
    let Some(src): Option<String> = load("webpack5/bundle.js") else {
        return;
    };
    let first: UnbundleResult =
        unbundle(BundlerKind::Webpack5, &src).expect("first unbundle must succeed");
    let second: UnbundleResult =
        unbundle(BundlerKind::Webpack5, &src).expect("second unbundle must succeed");
    assert_eq!(
        ids(&first),
        ids(&second),
        "module ids and order must be identical across calls",
    );
    let first_bodies: Vec<String> = first
        .modules
        .iter()
        .map(|m: &ExtractedModule| m.source.clone())
        .collect();
    let second_bodies: Vec<String> = second
        .modules
        .iter()
        .map(|m: &ExtractedModule| m.source.clone())
        .collect();
    assert_eq!(
        first_bodies, second_bodies,
        "module bodies must be identical across calls",
    );
}
