#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::path::PathBuf;
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, LiftFidelity, SurfaceModule, build_surface, build_surface_with_python_abi,
    decode_const_file, emit_python, parse_c_module_with_python_abi,
};

const C_SRC: &str = include_str!("../../../corpus/python/nuitka/module/hello.build/module.hello.c");
const CONST: &[u8] =
    include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");
const FIXTURE_PYTHON_ABI: (u8, u8) = (3u8, 12u8);

fn build_with_lifting() -> SurfaceModule {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(C_SRC, FIXTURE_PYTHON_ABI).expect("parse c");
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode const");
    build_surface_with_python_abi(&cmod, &pool, Some(C_SRC), FIXTURE_PYTHON_ABI)
        .expect("build surface")
}

#[test]
fn fib_lifts_to_full_body() {
    let s: SurfaceModule = build_with_lifting();
    let fib: &disrobe_pass_nuitka::SurfaceFunction = &s.functions[1];
    assert_eq!(fib.name, "fib");
    assert_eq!(fib.lift_fidelity, LiftFidelity::FullBody);
    assert!(!fib.body_stmts.is_empty());
    assert!(
        fib.body_recovered,
        "fib must report body_recovered=true after lifting"
    );

    let py: &str = s.python_source.as_str();
    assert!(
        py.contains("if n < 2:"),
        "fib must contain `if n < 2:` - got:\n{py}"
    );
    assert!(
        py.contains("a, b = 0, 1"),
        "fib must contain `a, b = 0, 1` - got:\n{py}"
    );
    assert!(
        py.contains("for _ in range(n - 1):"),
        "fib must contain `for _ in range(n - 1):` - got:\n{py}"
    );
    assert!(
        py.contains("a, b = b, a + b"),
        "fib must contain `a, b = b, a + b` - got:\n{py}"
    );
    assert!(
        py.contains("return b"),
        "fib must contain `return b` - got:\n{py}"
    );
    assert!(
        !py.contains("...  # disrobe: body not recovered"),
        "fib body must be lifted; skeleton placeholder must not appear"
    );
}

#[test]
fn greet_lifts_to_at_least_partial_body() {
    let s: SurfaceModule = build_with_lifting();
    let greet: &disrobe_pass_nuitka::SurfaceFunction = &s.functions[0];
    assert_eq!(greet.name, "greet");
    assert!(
        matches!(
            greet.lift_fidelity,
            LiftFidelity::FullBody | LiftFidelity::PartialBody
        ),
        "greet must lift to at least PartialBody; got {:?}",
        greet.lift_fidelity
    );
    assert!(
        !greet.body_stmts.is_empty(),
        "greet must have non-empty body_stmts"
    );

    let py: &str = s.python_source.as_str();
    assert!(
        py.contains("return f\"hello, {name}\"") || py.contains("return"),
        "greet must contain a return statement - got:\n{py}"
    );
}

#[test]
fn main_lifts_to_full_body() {
    let s: SurfaceModule = build_with_lifting();
    let main_fn: &disrobe_pass_nuitka::SurfaceFunction = &s.functions[2];
    assert_eq!(main_fn.name, "main");
    assert_eq!(main_fn.lift_fidelity, LiftFidelity::FullBody);

    let py: &str = s.python_source.as_str();
    assert!(
        py.contains("print(greet('disrobe'))"),
        "main must contain `print(greet('disrobe'))` - got:\n{py}"
    );
    assert!(
        py.contains("print(fib(20))"),
        "main must contain `print(fib(20))` - got:\n{py}"
    );
    assert!(
        py.contains("return 0"),
        "main must contain `return 0` - got:\n{py}"
    );
}

#[test]
fn skeleton_functions_do_not_claim_body_recovered() {
    let cmod: CModuleStructure =
        parse_c_module_with_python_abi(C_SRC, FIXTURE_PYTHON_ABI).expect("parse c");
    let pool = decode_const_file(CONST, "module.hello.const", "hello").expect("decode const");
    let s: SurfaceModule = build_surface(&cmod, &pool, None).expect("build surface (no c_source)");
    for f in &s.functions {
        assert!(
            !f.body_recovered,
            "function `{}` must not claim body_recovered when c_source is None",
            f.name
        );
        assert_eq!(
            f.lift_fidelity,
            LiftFidelity::Skeleton,
            "function `{}` must have Skeleton fidelity when c_source is None",
            f.name
        );
    }
    let py: String = emit_python(&s);
    assert!(
        py.contains("...  # disrobe: body not recovered"),
        "skeleton surface must contain placeholder comment"
    );
}

fn parse_labeled_output(stdout: &str) -> std::collections::BTreeMap<String, String> {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for line in stdout.lines() {
        if let Some((key, val)) = line.split_once(':') {
            map.insert(key.trim().to_owned(), val.trim().to_owned());
        }
    }
    map
}

#[test]
fn behavioral_gate_fib_greet_main_against_cpython() {
    let py: PathBuf = common::python314();

    let s: SurfaceModule = build_with_lifting();
    let source: String = emit_python(&s);

    let purpose: String = format!("disrobe-body-lift-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let dir: PathBuf = scratch.path().to_path_buf();
    let file: PathBuf = dir.join("recovered_hello.py");
    std::fs::write(&file, source.as_bytes()).expect("write recovered.py");

    let compile_out: Output = common::run_python(
        &py,
        "import sys; \
         src = open(sys.argv[1], encoding='utf-8').read(); \
         compile(src, sys.argv[1], 'exec')",
        &[&file],
    );
    assert!(
        compile_out.status.success(),
        "recovered.py must compile cleanly on CPython 3.14: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let probe_code: &str = r"
import importlib.util, sys, io, contextlib, ast

spec = importlib.util.spec_from_file_location('hello', sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    r = mod.main()
print('MAIN_STDOUT:' + repr(buf.getvalue()))
print('FIB10:' + str(mod.fib(10)))
print('FIB20:' + str(mod.fib(20)))
print('GREET:' + mod.greet('world'))
print('MAIN_RET:' + str(r))

tree = ast.parse(open(sys.argv[1], encoding='utf-8').read())
fns = {f.name: f for f in tree.body if isinstance(f, ast.FunctionDef)}
fib_body = fns['fib'].body
has_if = any(isinstance(n, ast.If) for n in fib_body)
has_for = any(isinstance(n, ast.For) for n in fib_body)
is_stub = len(fib_body) == 1 and isinstance(fib_body[0], ast.Expr) and isinstance(fib_body[0].value, ast.Constant)
print('FIB_HAS_IF:' + str(has_if))
print('FIB_HAS_FOR:' + str(has_for))
print('FIB_IS_STUB:' + str(is_stub))
";

    let probe_out: Output = common::run_python(&py, probe_code.trim(), &[&file]);
    assert!(
        probe_out.status.success(),
        "behavioral probe failed: {}",
        String::from_utf8_lossy(&probe_out.stderr)
    );

    let stdout: String = String::from_utf8_lossy(&probe_out.stdout).into_owned();
    let labels: std::collections::BTreeMap<String, String> = parse_labeled_output(&stdout);

    let fib10: &str = labels
        .get("FIB10")
        .expect("FIB10 label missing from probe output");
    let fib20: &str = labels
        .get("FIB20")
        .expect("FIB20 label missing from probe output");
    let greet_result: &str = labels
        .get("GREET")
        .expect("GREET label missing from probe output");

    let expected_from_reference: Output = common::run_python(
        &py,
        r"
def fib_ref(n):
    if n < 2: return n
    a, b = 0, 1
    for _ in range(n - 1): a, b = b, a + b
    return b
print('FIB10:' + str(fib_ref(10)))
print('FIB20:' + str(fib_ref(20)))
print('GREET:hello, world')
print('MAIN_STDOUT:' + repr('hello, disrobe\n' + str(fib_ref(20)) + '\n'))
print('MAIN_RET:0')
"
        .trim(),
        &[],
    );

    assert!(
        expected_from_reference.status.success(),
        "reference fib failed"
    );
    let ref_stdout: String = String::from_utf8_lossy(&expected_from_reference.stdout).into_owned();
    let ref_labels: std::collections::BTreeMap<String, String> = parse_labeled_output(&ref_stdout);

    let reference = |label: &str| -> &str {
        ref_labels
            .get(label)
            .unwrap_or_else(|| panic!("reference {label} missing: {ref_stdout}"))
    };
    let ref_fib10: &str = reference("FIB10");
    let ref_fib20: &str = reference("FIB20");

    assert_eq!(
        fib10, ref_fib10,
        "fib(10) from recovered module must equal reference"
    );
    assert_eq!(
        fib20, ref_fib20,
        "fib(20) from recovered module must equal reference"
    );
    assert_eq!(
        greet_result,
        reference("GREET"),
        "greet('world') from recovered module must equal reference"
    );
    assert_eq!(
        labels.get("MAIN_STDOUT").map(String::as_str),
        Some(reference("MAIN_STDOUT")),
        "main() output from recovered module must equal reference"
    );
    assert_eq!(
        labels.get("MAIN_RET").map(String::as_str),
        Some(reference("MAIN_RET")),
        "main() return from recovered module must equal reference"
    );

    let fib_has_if: &str = labels.get("FIB_HAS_IF").expect("FIB_HAS_IF label missing");
    let fib_has_for: &str = labels
        .get("FIB_HAS_FOR")
        .expect("FIB_HAS_FOR label missing");
    let fib_is_stub: &str = labels
        .get("FIB_IS_STUB")
        .expect("FIB_IS_STUB label missing");

    assert_eq!(
        fib_has_if, "True",
        "fib AST must contain at least one ast.If node"
    );
    assert_eq!(
        fib_has_for, "True",
        "fib AST must contain at least one ast.For node"
    );
    assert_eq!(
        fib_is_stub, "False",
        "fib body must NOT be a single-statement ellipsis stub"
    );
}
