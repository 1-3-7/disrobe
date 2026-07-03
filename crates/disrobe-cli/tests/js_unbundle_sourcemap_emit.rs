#![cfg(feature = "js")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod common;

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use common::{Run, run_disrobe, temp_dir, temp_path, write_bytes};

const WEBPACK4_BUNDLE_HEAD: &str = "\
(function(modules){var installedModules={};function __webpack_require__(moduleId){\
if(installedModules[moduleId]){return installedModules[moduleId].exports;}\
var module=installedModules[moduleId]={i:moduleId,l:false,exports:{}};\
modules[moduleId].call(module.exports,module,module.exports,__webpack_require__);\
module.l=true;return module.exports;}\
return __webpack_require__(0);})([\
(function(module,exports){module.exports=\"alpha-module-payload\";}),\
(function(module,exports){module.exports=\"beta-module-payload\";})\
]);\n";

fn embedded_source_map_json() -> String {
    serde_json::to_string(&serde_json::json!({
        "version": 3,
        "file": "bundle.js",
        "sources": ["webpack:///./src/alpha.js", "webpack:///./src/beta.js"],
        "sourcesContent": ["export const ALPHA = 1;\n", "export const BETA = 2;\n"],
        "names": ["ALPHA", "BETA"],
        "mappings": "AAAA,MAAMA;ACAN,MAAMC"
    }))
    .expect("serialize oracle source map")
}

fn webpack4_bundle_with_embedded_map(oracle_map_json: &str) -> String {
    let b64: String = B64.encode(oracle_map_json.as_bytes());
    format!("{WEBPACK4_BUNDLE_HEAD}//# sourceMappingURL=data:application/json;base64,{b64}\n")
}

#[test]
fn js_unbundle_emit_sourcemap_writes_synthesized_and_embedded_maps() {
    let oracle_map_json: String = embedded_source_map_json();
    let bundle: String = webpack4_bundle_with_embedded_map(&oracle_map_json);

    let input: PathBuf = temp_path("webpack4-sourcemap", "js");
    write_bytes(&input, bundle.as_bytes());
    let out_dir: PathBuf = temp_dir("webpack4-sourcemap-out");

    let input_str: String = input.display().to_string();
    let out_str: String = out_dir.display().to_string();
    let run: Run = run_disrobe(&[
        "js",
        "unbundle",
        &input_str,
        "--out",
        &out_str,
        "--force",
        "--target",
        "webpack4",
        "--emit",
        "sourcemap",
    ]);
    assert_eq!(
        run.code, 0,
        "js unbundle --emit sourcemap must exit 0. stdout={} stderr={}",
        run.stdout, run.stderr
    );
    assert!(
        run.stdout.contains("sourcemaps:"),
        "stdout must report a sourcemaps summary line; got: {}",
        run.stdout
    );

    let maps_dir: PathBuf = out_dir.join("sourcemaps");
    assert!(
        maps_dir.is_dir(),
        "expected sourcemaps dir at {}",
        maps_dir.display()
    );

    let mut synth_maps: Vec<PathBuf> = Vec::new();
    let mut embedded_maps: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(&maps_dir).expect("reading sourcemaps dir") {
        let path: PathBuf = entry.expect("dir entry").path();
        let name: String = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_owned();
        if name.ends_with(".synth.map.json") {
            synth_maps.push(path);
        } else if name.ends_with(".embedded.map.json") {
            embedded_maps.push(path);
        }
    }

    assert!(
        !synth_maps.is_empty(),
        "expected at least one synthesized per-chunk source map in {}",
        maps_dir.display()
    );
    let synth_body: String = std::fs::read_to_string(&synth_maps[0]).expect("read synthesized map");
    let synth: serde_json::Value =
        serde_json::from_str(&synth_body).expect("synthesized map is valid json");
    assert_eq!(
        synth.get("version").and_then(serde_json::Value::as_u64),
        Some(3),
        "synthesized map must be a v3 source map"
    );
    let synth_sources: usize = synth
        .get("sources")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len);
    assert_eq!(
        synth_sources, 2,
        "synthesized map must carry both extracted webpack modules as sources; got {synth_sources}"
    );

    assert_eq!(
        embedded_maps.len(),
        1,
        "expected exactly one embedded (decoded data-url) source map"
    );
    let decoded_body: String =
        std::fs::read_to_string(&embedded_maps[0]).expect("read embedded map");
    let decoded: serde_json::Value =
        serde_json::from_str(&decoded_body).expect("embedded map is valid json");
    let oracle: serde_json::Value =
        serde_json::from_str(&oracle_map_json).expect("oracle map is valid json");
    assert_eq!(
        decoded, oracle,
        "embedded map must round-trip byte-for-byte to the independently authored data-url map \
         (non-circular oracle), got: {decoded_body}"
    );
}
