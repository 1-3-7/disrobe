#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout
)]

mod common;

use std::path::PathBuf;
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFunction, SurfaceModule,
    build_surface_with_python_abi, decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

fn build_era() -> SurfaceModule {
    let name: &str = "era_patterns";
    let c_src: String = common::read_tracked_text(&format!("module/{name}.build/module.{name}.c"));
    let const_bytes: Vec<u8> =
        common::read_tracked(&format!("module/{name}.build/module.{name}.const"));
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(&c_src, FIXTURE_PYTHON_ABI).expect("parse era_patterns c");
    let pool: ConstantsPool =
        decode_const_file(&const_bytes, &format!("module.{name}.const"), name)
            .expect("decode era_patterns const");
    build_surface_with_python_abi(&cmod, &pool, Some(&c_src), FIXTURE_PYTHON_ABI)
        .expect("build era_patterns surface")
}

fn function<'a>(surface: &'a SurfaceModule, name: &str) -> &'a SurfaceFunction {
    surface
        .functions
        .iter()
        .find(|f: &&SurfaceFunction| f.name == name)
        .unwrap_or_else(|| panic!("function {name} present in era_patterns"))
}

#[test]
fn gap_constructs_reach_full_body_and_emit_faithfully() {
    let surface: SurfaceModule = build_era();
    let emitted: String = emit_python(&surface);

    for name in ["set_comp", "gen_squares", "multi_except", "except_as"] {
        let f: &SurfaceFunction = function(&surface, name);
        assert_eq!(
            f.lift_fidelity,
            LiftFidelity::FullBody,
            "{name} must reach FullBody from real Nuitka C; unrecognized={:?}\nemitted:\n{emitted}",
            f.unrecognized_c_lines
        );
    }

    assert!(
        emitted.contains("return {i % 3 for i in range(n)}"),
        "set comprehension must restore the {{element for target in iter}} form:\n{emitted}"
    );
    assert!(
        emitted.contains("except ZeroDivisionError:")
            && emitted.contains("except TypeError:")
            && emitted.contains("return -1")
            && emitted.contains("return -2"),
        "multi-handler except chain must restore both clauses:\n{emitted}"
    );
    assert!(
        emitted.contains("except ZeroDivisionError as exc:")
            && emitted.contains("return type(exc).__name__"),
        "except-as binding plus type()/__name__ must restore:\n{emitted}"
    );
}

#[test]
fn generator_body_lifts_from_context_function_to_full_body() {
    let surface: SurfaceModule = build_era();
    let gen_fn: &SurfaceFunction = function(&surface, "gen_squares");
    assert_eq!(
        gen_fn.lift_fidelity,
        LiftFidelity::FullBody,
        "generator context body must reach FullBody; unrecognized={:?}",
        gen_fn.unrecognized_c_lines
    );
    let emitted: String = emit_python(&surface);
    assert!(
        emitted.contains("def gen_squares(n: int):")
            && emitted.contains("for i in range(n):")
            && emitted.contains("yield i * i"),
        "generator body must restore the for/yield form from the _context function:\n{emitted}"
    );
    assert!(
        !emitted.contains("UNRESOLVED:"),
        "emitted module must never carry a raw UNRESOLVED marker into source:\n{emitted}"
    );
    assert!(
        !emitted.contains("MAKE_GENERATOR_"),
        "raw Nuitka generator symbol must not leak into emitted source:\n{emitted}"
    );
}

const ORACLE_PROBE: &str = r"
import importlib.util, sys

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

orig = load('orig', sys.argv[1])
recov = load('recov', sys.argv[2])

CASES = {
    'set_comp': [(0,), (1,), (3,), (5,), (10,)],
    'multi_except': [(10, 2), (7, 0), (9, 3), (0, 5), (8, 0)],
    'except_as': [(2,), (0,), (5,), (1,)],
}
graded = matched = 0
for fn, cases in CASES.items():
    of = getattr(orig, fn)
    rf = getattr(recov, fn, None)
    if rf is None:
        print('MISSING', fn); sys.exit(1)
    for a in cases:
        graded += 1
        try:
            o = of(*a)
        except Exception as e:
            o = ('EXC', type(e).__name__)
        try:
            r = rf(*a)
        except Exception as e:
            r = ('EXC', type(e).__name__)
        if o == r:
            matched += 1
        else:
            print(f'MISMATCH {fn}{a}: orig={o!r} recov={r!r}')
print(f'ORACLE {matched}/{graded}')
if matched != graded:
    sys.exit(2)
";

#[test]
fn recovered_gap_constructs_match_original_on_cpython() {
    let py: PathBuf = common::python314();
    let surface: SurfaceModule = build_era();
    let orig_path: PathBuf = common::tracked("module/era_patterns.src.py");

    let recovered: String = emit_python(&surface);
    let purpose: String = format!("disrobe-era-oracle-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recov_path: PathBuf = dir.join("recovered_era_patterns.py");
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = common::run_python(&py, ORACLE_PROBE.trim(), &[&orig_path, &recov_path]);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "era_patterns gap-construct oracle (set comp, multi-except, except-as) must match \
         original on CPython:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    assert_eq!(
        stdout.trim(),
        "ORACLE 14/14",
        "all 14 graded cases must match"
    );
    println!("era_patterns gap constructs: {}", stdout.trim());
}

const GENERATOR_PROBE: &str = r"
import importlib.util, sys

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

orig = load('orig', sys.argv[1])
recov = load('recov', sys.argv[2])

import types
of = orig.gen_squares
rf = getattr(recov, 'gen_squares', None)
if rf is None:
    print('MISSING gen_squares'); sys.exit(1)

graded = matched = 0
for n in [0, 1, 2, 3, 5, 8, 12]:
    graded += 1
    og = of(n)
    rg = rf(n)
    if not isinstance(og, types.GeneratorType):
        print('ORIG_NOT_GENERATOR'); sys.exit(3)
    if not isinstance(rg, types.GeneratorType):
        print('RECOV_NOT_GENERATOR'); sys.exit(3)
    o = list(og)
    r = list(rg)
    if o == r:
        matched += 1
    else:
        print(f'MISMATCH gen_squares({n}): orig={o!r} recov={r!r}')
print(f'ORACLE {matched}/{graded}')
if matched != graded:
    sys.exit(2)
";

#[test]
fn recovered_generator_yields_match_original_on_cpython() {
    let py: PathBuf = common::python314();
    let surface: SurfaceModule = build_era();
    let orig_path: PathBuf = common::tracked("module/era_patterns.src.py");

    let recovered: String = emit_python(&surface);
    let purpose: String = format!("disrobe-era-gen-oracle-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recov_path: PathBuf = dir.join("recovered_era_patterns.py");
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = common::run_python(&py, GENERATOR_PROBE.trim(), &[&orig_path, &recov_path]);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "recovered gen_squares must be a real generator producing identical values as the \
         original on CPython:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    assert_eq!(
        stdout.trim(),
        "ORACLE 7/7",
        "all 7 generator materializations must match"
    );
    println!("era_patterns generator: {}", stdout.trim());
}
