#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFunction, SurfaceModule,
    build_surface_with_python_abi, decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

const MODULES: [&str; 8] = [
    "arith",
    "compares",
    "loops",
    "strops",
    "datastruct",
    "multi",
    "advanced",
    "era_patterns",
];

fn build_module(name: &str) -> SurfaceModule {
    let c_src: String = common::read_tracked_text(&format!("module/{name}.build/module.{name}.c"));
    let const_bytes: Vec<u8> =
        common::read_tracked(&format!("module/{name}.build/module.{name}.const"));
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(&c_src, FIXTURE_PYTHON_ABI).expect("parse c module");
    let pool: ConstantsPool =
        decode_const_file(&const_bytes, &format!("module.{name}.const"), name)
            .expect("decode const blob");
    build_surface_with_python_abi(&cmod, &pool, Some(&c_src), FIXTURE_PYTHON_ABI)
        .expect("build surface")
}

#[test]
fn widened_corpus_emits_and_prints_recovery_census() {
    let mut total: usize = 0;
    let mut full: usize = 0;
    let mut partial: Vec<String> = Vec::new();
    for module in MODULES {
        let surface: SurfaceModule = build_module(module);
        let original: String = common::read_tracked_text(&format!("module/{module}.src.py"));
        let original_names: Vec<&str> = original
            .lines()
            .filter_map(|line: &str| line.strip_prefix("def "))
            .filter_map(|rest: &str| rest.split_once('(').map(|(name, _): (&str, &str)| name))
            .collect();
        let recovered_names: Vec<&str> = surface
            .functions
            .iter()
            .map(|f: &SurfaceFunction| f.name.as_str())
            .collect();
        assert_eq!(
            recovered_names, original_names,
            "{module}: recovered functions must be exactly the top-level defs of {module}.src.py"
        );
        let emitted: String = emit_python(&surface);
        println!("===== module {module} =====");
        println!("{emitted}");
        for f in &surface.functions {
            total += 1;
            if f.body_recovered && matches!(f.lift_fidelity, LiftFidelity::FullBody) {
                full += 1;
            } else {
                partial.push(format!(
                    "{module}::{} fidelity={:?} unrecognized={:?}",
                    f.name, f.lift_fidelity, f.unrecognized_c_lines
                ));
            }
        }
    }
    println!("WIDENED CENSUS full_body={full}/{total}");
    assert_eq!(total, 37, "the widened corpus contributes 37 lifted bodies");
    assert_eq!(
        full, total,
        "every widened-corpus body must reach FullBody (behaviorally proven per module); \
         remaining partials: {partial:?}"
    );
}

fn function<'a>(surface: &'a SurfaceModule, name: &str) -> &'a SurfaceFunction {
    surface
        .functions
        .iter()
        .find(|f: &&SurfaceFunction| f.name == name)
        .unwrap_or_else(|| panic!("function {name} present"))
}

#[test]
fn arith_bodies_are_fully_recovered() {
    let surface: SurfaceModule = build_module("arith");
    for name in ["add", "sub", "mul", "addmul", "neg"] {
        let f: &SurfaceFunction = function(&surface, name);
        assert_eq!(
            f.lift_fidelity,
            LiftFidelity::FullBody,
            "{name} must fully recover; unrecognized={:?}",
            f.unrecognized_c_lines
        );
    }
    common::assert_functions_match_original_ast(&emit_python(&surface), "arith", &[]);
}

const ORACLE_PROBE: &str = r"
import importlib.util, sys, itertools

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

orig = load('orig_mod', sys.argv[1])
recov = load('recov_mod', sys.argv[2])

SAMPLES = {
    1: [(0,), (1,), (5,), (-3,), (-1,), (42,), (100,), (7,)],
    2: list(itertools.product([0, 1, -2, 5, 10, -7], repeat=2)),
    3: list(itertools.product([1, 2, -3, 4], repeat=3)),
}

STR_SAMPLES = {
    1: [('a',), ('hello',), ('',), ('Mixed',)],
    2: [('x', 0), ('count', 5), ('name', -2)],
}

LIST_SAMPLES = {
    1: [([3, 7],), ([10, -2],), ([0, 0],), ([5, 9],)],
}

shared = [n for n in dir(orig) if not n.startswith('_') and callable(getattr(orig, n))]
graded = 0
matched = 0
for fname in shared:
    of = getattr(orig, fname)
    rf = getattr(recov, fname, None)
    if rf is None:
        print('MISSING', fname); sys.exit(1)
    import inspect
    try:
        nargs = len(inspect.signature(of).parameters)
    except (ValueError, TypeError):
        nargs = 1
    ann = getattr(of, '__annotations__', {})
    pann = [v for k, v in ann.items() if k != 'return']
    str_typed = any(v is str or v == 'str' for v in pann)
    list_typed = any(v is list or v == 'list' for v in pann)
    if list_typed:
        pool = LIST_SAMPLES.get(nargs, [])
    elif str_typed:
        pool = STR_SAMPLES.get(nargs, [])
    else:
        pool = SAMPLES.get(nargs, [])
    for args in pool:
        graded += 1
        try:
            o = of(*args)
        except Exception as e:
            o = ('EXC', type(e).__name__)
        try:
            r = rf(*args)
        except Exception as e:
            r = ('EXC', type(e).__name__)
        if o == r:
            matched += 1
        else:
            print(f'MISMATCH {fname}{args}: orig={o!r} recov={r!r}')
print(f'ORACLE {matched}/{graded}')
if matched != graded:
    sys.exit(2)
";

fn run_behavioral_oracle(module: &str, cases: usize) {
    let py: PathBuf = common::python314();
    let surface: SurfaceModule = build_module(module);
    let orig_path: PathBuf = common::tracked(&format!("module/{module}.src.py"));

    let recovered: String = emit_python(&surface);
    let purpose: String = format!("disrobe-nuitka-oracle-{module}-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recov_path: PathBuf = dir.join(format!("recovered_{module}.py"));
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = common::run_python(&py, ORACLE_PROBE.trim(), &[&orig_path, &recov_path]);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "behavioral oracle for {module} failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    assert_eq!(
        stdout.trim(),
        format!("ORACLE {cases}/{cases}"),
        "the {module} oracle grades {cases} cases derived from {module}.src.py"
    );
    println!("module {module}: {}", stdout.trim());
}

#[test]
fn arith_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("arith", 180);
}

#[test]
fn compares_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("compares", 68);
}

#[test]
fn loops_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("loops", 24);
}

#[test]
fn strops_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("strops", 14);
}

#[test]
fn datastruct_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("datastruct", 91);
}

#[test]
fn multi_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("multi", 88);
}

const ADVANCED_PROBE: &str = r"
import importlib.util, sys, itertools

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

orig = load('orig_mod', sys.argv[1])
recov = load('recov_mod', sys.argv[2])

CASES = {
    'comp': [(0,), (1,), (3,), (5,)],
    'dict_comp': [(0,), (2,), (4,)],
    'safe_div': [(10, 2), (7, 0), (9, 3), (0, 5), (8, 0)],
    'with_default': [(5,), (5, 20), (1, 1)],
    'varargs': [(), (1,), (1, 2, 3), (5, 10, 15, 20)],
}

graded = 0
matched = 0
for fname, cases in CASES.items():
    of = getattr(orig, fname)
    rf = getattr(recov, fname, None)
    if rf is None:
        print('MISSING', fname); sys.exit(1)
    for args in cases:
        graded += 1
        try:
            o = of(*args)
        except Exception as e:
            o = ('EXC', type(e).__name__)
        try:
            r = rf(*args)
        except Exception as e:
            r = ('EXC', type(e).__name__)
        if o == r:
            matched += 1
        else:
            print(f'MISMATCH {fname}{args}: orig={o!r} recov={r!r}')
print(f'ORACLE {matched}/{graded}')
if matched != graded:
    sys.exit(2)
";

#[test]
fn advanced_body_faithful_subset_matches_original_on_cpython() {
    let py: PathBuf = common::python314();
    let surface: SurfaceModule = build_module("advanced");
    let orig_path: PathBuf = common::tracked("module/advanced.src.py");
    let recovered: String = emit_python(&surface);
    let purpose: String = format!("disrobe-nuitka-adv-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let recov_path: PathBuf = dir.join("recovered_advanced.py");
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = common::run_python(&py, ADVANCED_PROBE.trim(), &[&orig_path, &recov_path]);
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "advanced body-faithful subset (comprehensions, try/except, default args) must \
         match original on CPython:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    assert_eq!(
        stdout.trim(),
        "ORACLE 19/19",
        "the advanced oracle grades 19 cases derived from advanced.src.py"
    );
    println!("module advanced (body-faithful subset): {}", stdout.trim());
}

#[test]
fn varargs_star_signature_is_recovered() {
    let surface: SurfaceModule = build_module("advanced");
    common::assert_functions_match_original_ast(&emit_python(&surface), "advanced", &["varargs"]);
}

#[test]
fn closure_with_nested_def_matches_original_ast() {
    let surface: SurfaceModule = build_module("advanced");
    common::assert_functions_match_original_ast(&emit_python(&surface), "advanced", &["closure"]);
}
