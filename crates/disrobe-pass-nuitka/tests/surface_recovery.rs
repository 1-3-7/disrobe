#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, SurfaceFidelity, SurfaceFunction, SurfaceModule,
    build_surface_with_python_abi, decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const C_SRC: &str = include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const PYI: &str = include_str!("../../../corpus/python/nuitka/module/hello.pyi");
const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroundTruthParam {
    name: String,
    annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GroundTruthFunction {
    name: String,
    params: Vec<GroundTruthParam>,
    return_annotation: Option<String>,
}

fn parse_pyi_signature(def_line: &str) -> GroundTruthFunction {
    let trimmed: &str = def_line.trim();
    let after_def: &str = trimmed
        .strip_prefix("def ")
        .expect("def line must start with `def `");
    let open: usize = after_def.find('(').expect("signature needs `(`");
    let name: String = after_def[..open].trim().to_owned();

    let close: usize = after_def.rfind(')').expect("signature needs `)`");
    let params_blob: &str = after_def[open + 1..close].trim();

    let return_annotation: Option<String> = after_def[close + 1..]
        .trim()
        .trim_end_matches(':')
        .trim()
        .strip_prefix("->")
        .map(|r: &str| r.trim().to_owned())
        .filter(|r: &String| !r.is_empty());

    let params: Vec<GroundTruthParam> = if params_blob.is_empty() {
        Vec::new()
    } else {
        params_blob
            .split(',')
            .map(|raw: &str| {
                let part: &str = raw.trim();
                match part.split_once(':') {
                    Some((pname, ann)) => GroundTruthParam {
                        name: pname.trim().to_owned(),
                        annotation: Some(ann.trim().to_owned()),
                    },
                    None => GroundTruthParam {
                        name: part.to_owned(),
                        annotation: None,
                    },
                }
            })
            .collect()
    };

    GroundTruthFunction {
        name,
        params,
        return_annotation,
    }
}

fn ground_truth_from_pyi(pyi: &str) -> BTreeMap<String, GroundTruthFunction> {
    pyi.lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .map(|l: &str| {
            let f: GroundTruthFunction = parse_pyi_signature(l);
            (f.name.clone(), f)
        })
        .collect()
}

fn build() -> SurfaceModule {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(C_SRC, FIXTURE_PYTHON_ABI).expect("parse module.hello.c");
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode const blob");
    build_surface_with_python_abi(&cmod, &pool, Some(C_SRC), FIXTURE_PYTHON_ABI)
        .expect("build surface")
}

#[test]
fn recovered_surface_matches_pyi_ground_truth() {
    let ground: BTreeMap<String, GroundTruthFunction> = ground_truth_from_pyi(PYI);
    assert_eq!(
        ground.keys().cloned().collect::<Vec<String>>(),
        vec!["fib".to_owned(), "greet".to_owned(), "main".to_owned()],
        "pyi ground truth must contain exactly greet/fib/main"
    );

    let surface: SurfaceModule = build();
    assert_eq!(surface.fidelity, SurfaceFidelity::StructuredFromCSource);

    let recovered: BTreeMap<String, &SurfaceFunction> = surface
        .functions
        .iter()
        .map(|f: &SurfaceFunction| (f.name.clone(), f))
        .collect();

    assert_eq!(
        recovered.keys().cloned().collect::<Vec<String>>(),
        ground.keys().cloned().collect::<Vec<String>>(),
        "recovered function set must equal pyi function set"
    );

    for (name, gt) in &ground {
        let got: &SurfaceFunction = recovered
            .get(name)
            .unwrap_or_else(|| panic!("recovered surface missing function `{name}`"));

        assert_eq!(
            got.params.len(),
            gt.params.len(),
            "param count mismatch for `{name}`"
        );
        for (recovered_param, gt_param) in got.params.iter().zip(&gt.params) {
            assert_eq!(
                recovered_param.name, gt_param.name,
                "param name mismatch for `{name}`"
            );
            assert_eq!(
                recovered_param.annotation, gt_param.annotation,
                "param annotation mismatch for `{name}::{}`",
                gt_param.name
            );
            assert!(
                recovered_param.default.is_none(),
                "fixture has no defaults; `{name}::{}` must be default-free",
                gt_param.name
            );
        }

        assert_eq!(
            got.return_annotation, gt.return_annotation,
            "return annotation mismatch for `{name}`"
        );
        assert!(
            got.docstring.is_none(),
            "fixture functions carry no docstrings (`{name}`)"
        );
        let _ = got.body_recovered;
    }
}

#[test]
fn recovered_constants_pool_carries_user_identifiers() {
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode const blob");
    for needed in ["greet", "fib", "disrobe"] {
        assert!(
            pool.strings.contains(needed),
            "constants pool must contain user identifier `{needed}`; have {:?}",
            pool.strings
        );
    }
}

fn emitted_signature_lines(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .map(|l: &str| l.split_whitespace().collect::<Vec<&str>>().join(" "))
        .collect()
}

#[test]
fn emitted_python_signature_lines_equal_pyi() {
    let surface: SurfaceModule = build();
    let emitted: Vec<String> = emitted_signature_lines(&surface.python_source);
    let expected: Vec<String> = emitted_signature_lines(PYI);
    assert!(!expected.is_empty(), "pyi must yield signature lines");
    assert_eq!(
        emitted, expected,
        "emitted def lines must byte-equal the Nuitka .pyi def lines"
    );
}

#[test]
fn emitted_python_compiles_and_ast_matches_pyi_on_cpython_314() {
    let py: PathBuf = common::python314();

    let surface: SurfaceModule = build();
    let source: String = emit_python(&surface);

    let purpose: String = format!("disrobe-surface-recovery-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let file: PathBuf = dir.join("recovered_hello.py");
    std::fs::write(&file, source.as_bytes()).expect("write temp .py");

    let compile_out: Output = common::run_python(
        &py,
        "import sys; src=open(sys.argv[1], encoding='utf-8').read(); \
         compile(src, sys.argv[1], 'exec')",
        &[&file],
    );
    assert!(
        compile_out.status.success(),
        "py_compile gate failed: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let ast_out: Output = common::run_python(
        &py,
        common::SIGNATURE_PROBE,
        &[&file, &common::tracked("module/hello.pyi")],
    );
    assert!(
        ast_out.status.success(),
        "ast ground-truth gate failed: {}",
        String::from_utf8_lossy(&ast_out.stderr)
    );
}
