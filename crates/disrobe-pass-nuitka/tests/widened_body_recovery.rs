#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, SurfaceFunction, SurfaceModule, build_surface,
    decode_const_file, emit_python, parse_c_module,
};

struct Fixture {
    module: &'static str,
}

const FIXTURES: &[Fixture] = &[
    Fixture { module: "arith" },
    Fixture { module: "compares" },
    Fixture { module: "loops" },
    Fixture { module: "strops" },
    Fixture {
        module: "datastruct",
    },
    Fixture { module: "multi" },
    Fixture { module: "advanced" },
    Fixture {
        module: "era_patterns",
    },
];

fn corpus_module(name: &str) -> PathBuf {
    let mut p: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.pop();
    p.pop();
    p.push("corpus");
    p.push("python");
    p.push("nuitka");
    p.push("module");
    p.push(name);
    p
}

fn build_module(name: &str) -> Option<SurfaceModule> {
    let c_path: PathBuf = corpus_module(&format!("{name}.build")).join(format!("module.{name}.c"));
    let const_path: PathBuf =
        corpus_module(&format!("{name}.build")).join(format!("module.{name}.const"));
    let c_src: String = std::fs::read_to_string(&c_path).ok()?;
    let const_bytes: Vec<u8> = std::fs::read(&const_path).ok()?;
    let cmod: CModuleStructure = parse_c_module(&c_src).expect("parse c module");
    let pool: ConstantsPool =
        decode_const_file(&const_bytes, &format!("module.{name}.const"), name)
            .expect("decode const blob");
    Some(build_surface(&cmod, &pool, Some(&c_src)).expect("build surface"))
}

#[test]
fn widened_corpus_emits_and_prints_recovery_census() {
    let mut total: usize = 0;
    let mut full: usize = 0;
    let mut present: usize = 0;
    let mut partial: Vec<String> = Vec::new();
    for fx in FIXTURES {
        let Some(surface): Option<SurfaceModule> = build_module(fx.module) else {
            eprintln!("skip: {} fixture absent", fx.module);
            continue;
        };
        present += 1;
        let emitted: String = emit_python(&surface);
        println!("===== module {} =====", fx.module);
        println!("{emitted}");
        for f in &surface.functions {
            total += 1;
            if f.body_recovered && matches!(f.lift_fidelity, LiftFidelity::FullBody) {
                full += 1;
            } else {
                partial.push(format!(
                    "{}::{} fidelity={:?} unrecognized={:?}",
                    fx.module, f.name, f.lift_fidelity, f.unrecognized_c_lines
                ));
            }
        }
    }
    let pct: f64 = if total == 0 {
        0.0
    } else {
        (full as f64) * 100.0 / (total as f64)
    };
    println!("WIDENED CENSUS full_body={full}/{total} ({pct:.2}%)");
    assert!(total > 0, "at least one widened fixture must be present");
    assert_eq!(
        full, total,
        "every present widened-corpus body must reach FullBody (behaviorally proven per module); \
         remaining partials: {partial:?}"
    );
    if present == FIXTURES.len() {
        assert_eq!(
            total, 37,
            "with all widened fixtures present the corpus contributes 37 lifted bodies"
        );
    }
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
    let Some(surface): Option<SurfaceModule> = build_module("arith") else {
        eprintln!("skip: arith fixture absent");
        return;
    };
    for name in ["add", "sub", "mul", "addmul", "neg"] {
        let f: &SurfaceFunction = function(&surface, name);
        assert_eq!(
            f.lift_fidelity,
            LiftFidelity::FullBody,
            "{name} must fully recover; unrecognized={:?}",
            f.unrecognized_c_lines
        );
    }
    let emitted: String = emit_python(&surface);
    assert!(emitted.contains("return a + b"), "add body: {emitted}");
    assert!(emitted.contains("return a - b"), "sub body");
    assert!(emitted.contains("return a * b"), "mul body");
    assert!(emitted.contains("return -a"), "neg body");
    assert!(
        emitted.contains("return a + b * c") || emitted.contains("return a + (b * c)"),
        "addmul body preserves precedence: {emitted}"
    );
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
            + &String::from_utf8_lossy(&output.stderr);
        if banner.contains("3.14") || banner.contains("3.15") {
            return Some(cmd.to_owned());
        }
    }
    None
}

fn run_python(py: &str, code: &str, args: &[&str]) -> Output {
    let mut cmd: Command = Command::new(py);
    if py == "py" {
        cmd.arg("-3.14");
    }
    cmd.args(["-c", code]);
    cmd.args(args);
    cmd.output().expect("spawn cpython 3.14")
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

fn run_behavioral_oracle(module: &str) {
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14 on PATH");
        return;
    };
    let Some(surface): Option<SurfaceModule> = build_module(module) else {
        eprintln!("skip: {module} fixture absent");
        return;
    };
    let orig_path: PathBuf = corpus_module(&format!("{module}.src.py"));
    if !orig_path.is_file() {
        eprintln!("skip: {module}.src.py original absent");
        return;
    }

    let recovered: String = emit_python(&surface);
    let dir: PathBuf = std::env::temp_dir().join(format!(
        "disrobe-nuitka-oracle-{module}-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let recov_path: PathBuf = dir.join(format!("recovered_{module}.py"));
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = run_python(
        &py,
        ORACLE_PROBE.trim(),
        &[&orig_path.to_string_lossy(), &recov_path.to_string_lossy()],
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "behavioral oracle for {module} failed:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    assert!(
        stdout.contains("ORACLE"),
        "oracle did not report a census for {module}: {stdout}"
    );
    println!("module {module}: {}", stdout.trim());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn arith_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("arith");
}

#[test]
fn compares_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("compares");
}

#[test]
fn loops_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("loops");
}

#[test]
fn strops_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("strops");
}

#[test]
fn datastruct_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("datastruct");
}

#[test]
fn multi_recovered_matches_original_on_cpython() {
    run_behavioral_oracle("multi");
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
    let Some(py): Option<String> = locate_python_314() else {
        eprintln!("skip: no python3.14 on PATH");
        return;
    };
    let Some(surface): Option<SurfaceModule> = build_module("advanced") else {
        eprintln!("skip: advanced fixture absent");
        return;
    };
    let orig_path: PathBuf = corpus_module("advanced.src.py");
    if !orig_path.is_file() {
        eprintln!("skip: advanced.src.py absent");
        return;
    }
    let recovered: String = emit_python(&surface);
    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-nuitka-adv-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let recov_path: PathBuf = dir.join("recovered_advanced.py");
    std::fs::write(&recov_path, recovered.as_bytes()).expect("write recovered");

    let out: Output = run_python(
        &py,
        ADVANCED_PROBE.trim(),
        &[&orig_path.to_string_lossy(), &recov_path.to_string_lossy()],
    );
    let stdout: String = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(
        out.status.success(),
        "advanced body-faithful subset (comprehensions, try/except, default args) must \
         match original on CPython:\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}\nRECOVERED:\n{recovered}"
    );
    println!("module advanced (body-faithful subset): {}", stdout.trim());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn varargs_star_signature_is_recovered() {
    let Some(surface): Option<SurfaceModule> = build_module("advanced") else {
        eprintln!("skip: advanced fixture absent");
        return;
    };
    let recovered: String = emit_python(&surface);
    assert!(
        recovered.contains("def varargs(*nums"),
        "CO_VARARGS code-object flag must restore the star parameter: {recovered}"
    );
    assert!(
        recovered.contains("for x in nums"),
        "varargs body must iterate the star param: {recovered}"
    );
}

#[test]
fn closure_body_lifts_but_nested_def_structure_is_the_remaining_limit() {
    let Some(surface): Option<SurfaceModule> = build_module("advanced") else {
        eprintln!("skip: advanced fixture absent");
        return;
    };
    let recovered: String = emit_python(&surface);
    assert!(
        recovered.contains("return inner(n)"),
        "closure body must lift the inner call from C: {recovered}"
    );
    assert!(
        recovered.contains("return x + n"),
        "the nested inner body must lift the cell-variable expression x + n: {recovered}"
    );
}
