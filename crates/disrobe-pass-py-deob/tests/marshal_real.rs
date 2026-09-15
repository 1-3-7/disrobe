#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;

use disrobe_pass_py_deob::{PeelResult, peel};

fn variants_dir() -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut p: PathBuf = PathBuf::from(manifest_dir);
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("marshal");
    p.push("variants");
    p
}

const VERSIONS: [&str; 5] = ["py39", "py311", "py312", "py314", "py315"];
const WRAPPERS: [&str; 6] = [
    "exec_plain",
    "exec_zlib",
    "exec_b64",
    "exec_b64_zlib",
    "exec_import_dunder",
    "exec_hex",
];

fn greeter_markers(source: &str) -> bool {
    source.contains("def greet(name)")
        && source.contains("\"hello, \" + name")
        && source.contains("def add(a, b)")
        && source.contains("return a + b")
        && source.contains("add(greet(\"x\"), \"y\")")
}

fn loopcalc_markers(source: &str) -> bool {
    source.contains("def main()")
        && source.contains("for i in range(5)")
        && source.contains("total = total + i")
        && source.contains("return total")
}

fn boxcls_markers(source: &str) -> bool {
    source.contains("class Box")
        && source.contains("def __init__(self, v)")
        && source.contains("self.value = v")
        && source.contains("def get(self)")
        && source.contains("return self.value")
}

fn recover_or_skip(path: &PathBuf, test: &str) -> Option<PeelResult> {
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(path) else {
        eprintln!("skip: {test} (fixture absent: {})", path.display());
        return None;
    };
    Some(peel(&bytes).unwrap_or_else(|e| panic!("peel {}: {e:?}", path.display())))
}

fn assert_recovers(name: &str, marker: fn(&str) -> bool) -> usize {
    let dir: PathBuf = variants_dir();
    let mut checked: usize = 0;
    for version in VERSIONS {
        for wrapper in WRAPPERS {
            let path: PathBuf = dir.join(format!("{name}.{version}.{wrapper}.py"));
            let Some(result): Option<PeelResult> = recover_or_skip(&path, name) else {
                continue;
            };
            assert!(
                result.recovered,
                "{name}.{version}.{wrapper}: must recover, steps={:?}",
                result.steps
            );
            let marshal = result.marshal.as_ref().unwrap_or_else(|| {
                panic!("{name}.{version}.{wrapper}: expected marshal recovery metadata")
            });
            assert!(
                marshal.layers.iter().any(|l| l.recovered_directly),
                "{name}.{version}.{wrapper}: at least one layer must decompile to source"
            );
            assert!(
                marker(&result.final_source),
                "{name}.{version}.{wrapper}: recovered source missing markers:\n{}",
                result.final_source
            );
            checked += 1;
        }
    }
    checked
}

#[test]
fn greeter_all_wrappers_all_versions_recover() {
    assert!(
        assert_recovers("greeter", greeter_markers) > 0,
        "no greeter fixtures present"
    );
}

#[test]
fn loopcalc_all_wrappers_all_versions_recover() {
    assert!(
        assert_recovers("loopcalc", loopcalc_markers) > 0,
        "no loopcalc fixtures present"
    );
}

#[test]
fn boxcls_all_wrappers_all_versions_recover() {
    assert!(
        assert_recovers("boxcls", boxcls_markers) > 0,
        "no boxcls fixtures present"
    );
}

#[test]
fn bare_headerless_marshal_blob_recovers() {
    let dir: PathBuf = variants_dir();
    let mut checked: usize = 0;
    for version in VERSIONS {
        let path: PathBuf = dir.join(format!("greeter.{version}.bare.marshal"));
        let Some(result): Option<PeelResult> = recover_or_skip(&path, "bare_marshal") else {
            continue;
        };
        assert!(
            result.recovered,
            "greeter.{version}.bare: headerless marshal blob must recover"
        );
        let marshal = result.marshal.as_ref().expect("marshal recovery");
        assert_eq!(
            marshal.chain,
            vec!["marshal".to_owned()],
            "bare blob chain is just marshal"
        );
        assert!(
            greeter_markers(&result.final_source),
            "greeter.{version}.bare: recovered source missing markers:\n{}",
            result.final_source
        );
        checked += 1;
    }
    assert!(checked > 0, "no bare marshal fixtures present");
}

#[test]
fn version_inference_picks_correct_minor_when_decidable() {
    let dir: PathBuf = variants_dir();
    let cases: [(&str, u8, u8); 4] = [
        ("py311", 3, 11),
        ("py312", 3, 12),
        ("py314", 3, 14),
        ("py315", 3, 15),
    ];
    let mut checked: usize = 0;
    for (version, major, minor) in cases {
        for original in ["greeter", "loopcalc", "boxcls"] {
            let path: PathBuf = dir.join(format!("{original}.{version}.bare.marshal"));
            let Some(result): Option<PeelResult> = recover_or_skip(&path, "version_inference")
            else {
                continue;
            };
            let marshal = result.marshal.as_ref().expect("marshal recovery");
            assert!(
                marshal.version_inferred,
                "{original}.{version}.bare: version must be inferred (no hint)"
            );
            assert_eq!(
                (marshal.version_major, marshal.version_minor),
                (major, minor),
                "{original}.{version}.bare: 3.11+ inline-cache layout is version-distinct, \
                 inference must land the exact minor"
            );
            checked += 1;
        }
    }
    assert!(checked > 0, "no fixtures for version inference");
}

#[test]
fn version_hint_overrides_inference() {
    use disrobe_py_marshal::PyVersion;
    let dir: PathBuf = variants_dir();
    let path: PathBuf = dir.join("loopcalc.py39.bare.marshal");
    let Ok(bytes): std::io::Result<Vec<u8>> = std::fs::read(&path) else {
        eprintln!("skip: version_hint (fixture absent)");
        return;
    };
    let result: PeelResult =
        disrobe_pass_py_deob::peel_with_pyver(&bytes, Some(PyVersion::PY39)).expect("peel");
    let marshal = result.marshal.as_ref().expect("marshal recovery");
    assert!(
        !marshal.version_inferred,
        "an explicit --pyver hint must be honoured, not inferred"
    );
    assert_eq!((marshal.version_major, marshal.version_minor), (3, 9));
    assert!(
        loopcalc_markers(&result.final_source),
        "py39 hint must still decompile correctly:\n{}",
        result.final_source
    );
}
