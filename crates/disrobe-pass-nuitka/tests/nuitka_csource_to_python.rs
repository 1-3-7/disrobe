#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFidelity, SurfaceModule, build_surface,
    build_surface_with_python_abi, decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const C_SRC: &str = include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const PYI: &str = include_str!("../../../corpus/python/nuitka/module/hello.pyi");
const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

#[derive(Debug, Clone, PartialEq, Eq)]
struct PyiParam {
    name: String,
    annotation: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PyiSignature {
    name: String,
    params: Vec<PyiParam>,
    return_annotation: Option<String>,
}

fn parse_pyi_signature(def_line: &str) -> PyiSignature {
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

    let params: Vec<PyiParam> = if params_blob.is_empty() {
        Vec::new()
    } else {
        params_blob
            .split(',')
            .map(|raw: &str| {
                let part: &str = raw.trim();
                match part.split_once(':') {
                    Some((pname, ann)) => PyiParam {
                        name: pname.trim().to_owned(),
                        annotation: Some(ann.trim().to_owned()),
                    },
                    None => PyiParam {
                        name: part.to_owned(),
                        annotation: None,
                    },
                }
            })
            .collect()
    };

    PyiSignature {
        name,
        params,
        return_annotation,
    }
}

fn pyi_ground_truth(pyi: &str) -> BTreeMap<String, PyiSignature> {
    pyi.lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .map(|l: &str| {
            let f: PyiSignature = parse_pyi_signature(l);
            (f.name.clone(), f)
        })
        .collect()
}

fn build() -> SurfaceModule {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(C_SRC, FIXTURE_PYTHON_ABI).expect("parse module.hello.c");
    let pool: ConstantsPool =
        decode_const_file(CONST, "module.hello.const", "hello").expect("decode const blob");
    build_surface_with_python_abi(&cmod, &pool, Some(C_SRC), FIXTURE_PYTHON_ABI)
        .expect("build surface")
}

#[test]
fn emitted_python_function_set_equals_independent_pyi() {
    let ground: BTreeMap<String, PyiSignature> = pyi_ground_truth(PYI);
    assert_eq!(
        ground.keys().cloned().collect::<Vec<String>>(),
        vec!["fib".to_owned(), "greet".to_owned(), "main".to_owned()],
        "independent Nuitka .pyi must declare exactly greet/fib/main"
    );

    let surface: SurfaceModule = build();
    assert_eq!(surface.fidelity, SurfaceFidelity::StructuredFromCSource);

    let emitted: String = emit_python(&surface);
    let emitted_defs: BTreeMap<String, PyiSignature> = emitted
        .lines()
        .map(str::trim)
        .filter(|l: &&str| l.starts_with("def ") && l.ends_with(':'))
        .map(|l: &str| {
            let f: PyiSignature = parse_pyi_signature(l);
            (f.name.clone(), f)
        })
        .collect();

    assert_eq!(
        emitted_defs.keys().cloned().collect::<Vec<String>>(),
        ground.keys().cloned().collect::<Vec<String>>(),
        "recovered .py function set must equal the independent .pyi function set"
    );

    for (name, gt) in &ground {
        let got: &PyiSignature = emitted_defs
            .get(name)
            .unwrap_or_else(|| panic!("recovered .py missing function `{name}`"));
        assert_eq!(
            got, gt,
            "recovered signature for `{name}` must byte-match the Nuitka .pyi signature"
        );
    }
}

#[test]
fn skeleton_emission_is_honest_when_c_source_absent() {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(C_SRC, FIXTURE_PYTHON_ABI).expect("parse module.hello.c");
    let pool: ConstantsPool =
        decode_const_file(CONST, "module.hello.const", "hello").expect("decode const blob");
    let surface: SurfaceModule =
        build_surface(&cmod, &pool, None).expect("build surface without c_source");

    for f in &surface.functions {
        assert!(
            !f.body_recovered,
            "function `{}` must keep body_recovered=false when bodies are unmodeled",
            f.name
        );
        assert_eq!(
            f.lift_fidelity,
            LiftFidelity::Skeleton,
            "function `{}` must report Skeleton fidelity without c_source",
            f.name
        );
    }

    let emitted: String = emit_python(&surface);
    assert!(
        emitted.contains("...  # disrobe: body not recovered"),
        "skeleton emission must declare unrecovered bodies, not fabricate them"
    );
    assert!(
        emitted.contains("def greet(name: str) -> str:"),
        "signatures stay 100% even when bodies are skeleton"
    );
    assert!(emitted.contains("def fib(n: int) -> int:"));
    assert!(emitted.contains("def main() -> int:"));
}

fn fib_reference(n: i64) -> i64 {
    if n < 2 {
        return n;
    }
    let (mut a, mut b): (i64, i64) = (0i64, 1i64);
    for _ in 0..(n - 1) {
        let next: i64 = a + b;
        a = b;
        b = next;
    }
    b
}

fn locate_python_314() -> Option<String> {
    let candidates: [(&str, &[&str]); 3] = [
        ("py", &["-3.14", "--version"]),
        ("python3.14", &["--version"]),
        ("python", &["--version"]),
    ];
    for (cmd, args) in candidates {
        let Ok(output): Result<Output, std::io::Error> = Command::new(cmd).args(args).output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let banner: String = String::from_utf8_lossy(&output.stdout).into_owned()
            + String::from_utf8_lossy(&output.stderr).as_ref();
        if banner.contains("3.14") || banner.contains("3.15") {
            return Some(cmd.to_owned());
        }
    }
    None
}

fn run_python_with_file(py: &str, code: &str, file: &Path) -> Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code, &file.to_string_lossy()]);
    cmd.output().expect("spawn cpython")
}

#[test]
fn recovered_python_fib_matches_handwritten_reference_on_cpython() {
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14 on PATH");
        return;
    };

    let surface: SurfaceModule = build();
    let source: String = emit_python(&surface);

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-nuitka-csource2py-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let file: PathBuf = dir.join("recovered_hello.py");
    std::fs::write(&file, source.as_bytes()).expect("write recovered.py");

    let compile_out: Output = run_python_with_file(
        &py,
        "import sys; src=open(sys.argv[1], encoding='utf-8').read(); \
         compile(src, sys.argv[1], 'exec')",
        &file,
    );
    assert!(
        compile_out.status.success(),
        "recovered .py must compile on CPython: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let probe: Output = run_python_with_file(
        &py,
        "import importlib.util, sys; \
         spec=importlib.util.spec_from_file_location('hello', sys.argv[1]); \
         mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod); \
         print('FIB10:'+str(mod.fib(10))); print('FIB20:'+str(mod.fib(20)))",
        &file,
    );
    assert!(
        probe.status.success(),
        "recovered fib probe failed: {}",
        String::from_utf8_lossy(&probe.stderr)
    );

    let stdout: String = String::from_utf8_lossy(&probe.stdout).into_owned();
    let labels: BTreeMap<String, String> = stdout
        .lines()
        .filter_map(|l: &str| l.split_once(':'))
        .map(|(k, v): (&str, &str)| (k.trim().to_owned(), v.trim().to_owned()))
        .collect();

    let fib10: &str = labels.get("FIB10").expect("FIB10 label");
    let fib20: &str = labels.get("FIB20").expect("FIB20 label");
    assert_eq!(
        fib10,
        fib_reference(10).to_string(),
        "fib(10) from recovered module must equal hand-written reference"
    );
    assert_eq!(
        fib20,
        fib_reference(20).to_string(),
        "fib(20) from recovered module must equal hand-written reference"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
