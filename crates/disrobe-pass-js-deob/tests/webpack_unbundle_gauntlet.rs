#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::print_stdout
)]

use disrobe_pass_js_deob::{
    BundlerDetection, BundlerKind, ExtractedModule, UnbundleResult, auto_unbundle, unbundle,
};

const BUNDLE: &str = include_str!("../../../corpus/js/webpack5/gauntlet/bundle.js");

const GEOMETRY_SRC: &str = include_str!("../../../corpus/js/webpack5/gauntlet/src/geometry.js");
const INVENTORY_SRC: &str = include_str!("../../../corpus/js/webpack5/gauntlet/src/inventory.js");
const INDEX_SRC: &str = include_str!("../../../corpus/js/webpack5/gauntlet/src/index.js");

const GEOMETRY_ID: &str = "./src/geometry.js";
const INVENTORY_ID: &str = "./src/inventory.js";

const GEOMETRY_TOKENS: [&str; 8] = [
    "PI_APPROX",
    "MAX_SIDES",
    "circleArea",
    "polygonPerimeter",
    "sideCount",
    "RangeError",
    "3.14159",
    "too many sides for polygon",
];

const INVENTORY_TOKENS: [&str; 8] = [
    "STORE_NAME",
    "Warehouse",
    "restock",
    "available",
    "summary",
    "this.stock",
    "new Map()",
    "disrobe-webpack-gauntlet",
];

fn module_by_id<'a>(result: &'a UnbundleResult, id: &str) -> &'a ExtractedModule {
    result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.id == id)
        .unwrap_or_else(|| panic!("module {id} not extracted; got {:?}", module_ids(result)))
}

fn module_ids(result: &UnbundleResult) -> Vec<String> {
    result
        .modules
        .iter()
        .map(|m: &ExtractedModule| m.id.clone())
        .collect()
}

fn token_recovery(body: &str, original: &str, tokens: &[&str], label: &str) -> usize {
    let mut hits: usize = 0usize;
    for token in tokens {
        assert!(
            original.contains(token),
            "guard: token '{token}' must exist in the clean original {label} source",
        );
        if body.contains(token) {
            hits += 1;
        } else {
            println!("webpack gauntlet: token '{token}' absent from recovered {label} module");
        }
    }
    hits
}

#[test]
fn webpack_gauntlet_detects_real_production_bundle() {
    let detection: BundlerDetection = {
        let result: UnbundleResult = auto_unbundle(BUNDLE).expect("auto unbundle must succeed");
        result.detection
    };
    assert_eq!(
        detection.kind,
        BundlerKind::Webpack5,
        "real webpack 5 production bundle must classify as Webpack5",
    );
    assert!(
        detection.matched,
        "webpack runtime must be detected; markers: {:?}",
        detection.markers,
    );
    assert!(
        detection
            .markers
            .iter()
            .any(|m: &String| m == "__webpack_modules__"),
        "the module-table marker must fire on a non-concatenated production bundle; got {:?}",
        detection.markers,
    );
}

#[test]
fn webpack_gauntlet_splits_bundle_into_named_source_modules() {
    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, BUNDLE).expect("webpack5 unbundle must succeed");
    assert_eq!(
        result.kind,
        BundlerKind::Webpack5,
        "unbundle must report Webpack5",
    );

    for expected in [GEOMETRY_ID, INVENTORY_ID] {
        let module: &ExtractedModule = module_by_id(&result, expected);
        assert!(
            !module.source.trim().is_empty(),
            "module {expected} must carry a non-empty source body",
        );
    }

    let geometry: &ExtractedModule = module_by_id(&result, GEOMETRY_ID);
    assert!(
        !geometry.source.contains("__webpack_module_cache__"),
        "the webpack runtime must not leak into the geometry module body:\n{}",
        geometry.source,
    );
    let inventory: &ExtractedModule = module_by_id(&result, INVENTORY_ID);
    assert!(
        !inventory.source.contains("function __webpack_require__"),
        "the webpack require function must not leak into the inventory module body:\n{}",
        inventory.source,
    );
}

#[test]
fn webpack_gauntlet_recovers_original_identifiers_and_strings() {
    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, BUNDLE).expect("webpack5 unbundle must succeed");

    let geometry: &ExtractedModule = module_by_id(&result, GEOMETRY_ID);
    let geo_hits: usize =
        token_recovery(&geometry.source, GEOMETRY_SRC, &GEOMETRY_TOKENS, "geometry");
    let geo_pct: f64 = 100.0 * geo_hits as f64 / GEOMETRY_TOKENS.len() as f64;
    println!(
        "webpack gauntlet: geometry token recovery {geo_hits}/{} = {geo_pct:.2}%",
        GEOMETRY_TOKENS.len(),
    );
    assert_eq!(
        geo_hits,
        GEOMETRY_TOKENS.len(),
        "every clean-source geometry token must reappear in the recovered module ({geo_pct:.2}%)",
    );

    let inventory: &ExtractedModule = module_by_id(&result, INVENTORY_ID);
    let inv_hits: usize = token_recovery(
        &inventory.source,
        INVENTORY_SRC,
        &INVENTORY_TOKENS,
        "inventory",
    );
    let inv_pct: f64 = 100.0 * inv_hits as f64 / INVENTORY_TOKENS.len() as f64;
    println!(
        "webpack gauntlet: inventory token recovery {inv_hits}/{} = {inv_pct:.2}%",
        INVENTORY_TOKENS.len(),
    );
    assert_eq!(
        inv_hits,
        INVENTORY_TOKENS.len(),
        "every clean-source inventory token must reappear in the recovered module ({inv_pct:.2}%)",
    );
}

#[test]
fn webpack_gauntlet_recovers_entry_module_program() {
    let result: UnbundleResult =
        unbundle(BundlerKind::Webpack5, BUNDLE).expect("webpack5 unbundle must succeed");

    let entry: Option<&ExtractedModule> = result
        .modules
        .iter()
        .find(|m: &&ExtractedModule| m.source.contains("function report"));
    let entry: &ExtractedModule = entry.unwrap_or_else(|| {
        panic!(
            "the entry program (function report) must be recovered in some module; got {:?}",
            module_ids(&result),
        )
    });
    assert!(
        INDEX_SRC.contains("function report"),
        "guard: clean index source must define report()",
    );
    for token in ["report", "console.log", "widget", "gadget"] {
        assert!(
            INDEX_SRC.contains(token),
            "guard: token '{token}' must exist in the clean original index source",
        );
        assert!(
            entry.source.contains(token),
            "entry program token '{token}' must survive unbundling; body:\n{}",
            entry.source,
        );
    }
}
