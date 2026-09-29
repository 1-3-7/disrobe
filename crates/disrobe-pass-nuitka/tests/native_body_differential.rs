#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    ConstantsPool, NativeBodyRecovery, NativeFunctionBody, NuitkaDecompilation, PythonExpr,
    PythonStmt, SurfaceFunction, SurfaceModule, decode_const_file, decompile_build_dir,
    decompile_bytes, lift_native_bodies, parse_constants,
};
use serde_json::{Value, json};

const MODULE_SOURCE: &str = r"
def echo(a):
    return a


def keepfirst(a, b):
    return a


def pick2(a, b):
    return b


def pick3(a, b, c):
    return c


def pick4(a, b, c, d):
    return d


def addmul(x, y):
    return x + y * x


def sign(n):
    if n < 0:
        return -1
    if n > 0:
        return 1
    return 0
";

const BYTES_SOURCE: &str = r#"
from __future__ import annotations


def marker():
    return None


def truth():
    return True


def falsity():
    return False


def ignored(value):
    return True


def payload():
    return b"\x00\xff'\\\n"


def text_payload():
    return "quote' slash\\ newline\n"


def control_text_payload():
    return "\x7f\u200b\U0001f600"


def keyword_payload(*, enabled=True):
    return b"\x00\xff'\\\n"


def structured_keyword_defaults(*, ratio=1.5, labels=frozenset({1, 2}), options={3, 4}):
    return True


def annotated_collection(values: list[int]) -> dict[str, int | None]:
    return None


def long_constant_return_function_name_for_digest_metadata(value):
    return b"\x00\xff'\\\n"
"#;

#[derive(Debug)]
struct TestDir {
    scratch: disrobe_core::scratch::ScratchDir,
}

impl TestDir {
    fn create(prefix: &str) -> Self {
        let scratch: disrobe_core::scratch::ScratchDir =
            disrobe_core::scratch::ScratchDir::create(prefix).expect("create scratch dir");
        Self { scratch }
    }

    fn path(&self) -> &Path {
        self.scratch.path()
    }
}

fn run_python(py: &Path, extra: &[&str]) -> Output {
    Command::new(py)
        .env("PYTHONIOENCODING", "utf-8")
        .args(extra)
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("spawn {}: {error}", py.display()))
}

fn nuitka_version(py: &Path) -> String {
    let output: Output = run_python(py, &["-m", "nuitka", "--version"]);
    assert!(
        output.status.success(),
        "`{} -m nuitka --version` failed: {}",
        py.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn shape_of(function: &NativeFunctionBody) -> Option<(u32, Option<usize>)> {
    if function.recovered_stmts.len() != 1 {
        return None;
    }
    match &function.recovered_stmts[0] {
        PythonStmt::Return(expr) => {
            let rendered: String = format!("{expr:?}");
            if let Some(rest) = rendered.strip_prefix("Name(\"arg") {
                let index: usize = rest.trim_end_matches("\")").parse().ok()?;
                Some((function.argcount, Some(index)))
            } else if rendered.contains("None") {
                Some((function.argcount, None))
            } else {
                None
            }
        }
        _ => None,
    }
}

#[test]
fn native_body_lift_behavioral_differential_against_cpython() {
    let Some(py): Option<PathBuf> = common::python314_with_nuitka() else {
        return;
    };
    assert_eq!(
        nuitka_version(&py),
        "4.1.1",
        "fresh producer test requires Nuitka 4.1.1"
    );

    let dir: TestDir = TestDir::create("disrobe-native-body");
    let src: PathBuf = dir.path().join("gradmod.py");
    std::fs::write(&src, MODULE_SOURCE.as_bytes()).expect("write source module");

    let out_dir: PathBuf = dir.path().join("out");
    let build: Output = run_python(
        &py,
        &[
            "-m",
            "nuitka",
            "--module",
            &src.to_string_lossy(),
            &format!("--output-dir={}", out_dir.to_string_lossy()),
            "--remove-output",
            "--no-pyi-file",
            "--assume-yes-for-downloads",
            "--quiet",
        ],
    );
    assert!(
        build.status.success(),
        "Nuitka build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let pyd: Option<PathBuf> = std::fs::read_dir(&out_dir).ok().and_then(|entries| {
        entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p: &PathBuf| p.extension().is_some_and(|x| x == "pyd" || x == "so"))
    });
    let Some(pyd): Option<PathBuf> = pyd else {
        panic!("nuitka produced no .pyd/.so in {}", out_dir.display());
    };

    let bytes: Vec<u8> = std::fs::read(&pyd).expect("read compiled module");
    let constants = parse_constants(&bytes);
    let recovery: NativeBodyRecovery = lift_native_bodies(&bytes, Some(&constants))
        .expect("native body recovery on real release pyd");

    let truth: BTreeMap<String, (u32, Option<usize>)> = probe_source_shapes(&py, &src);
    assert!(
        !truth.is_empty(),
        "ground-truth probe of the source module returned no pass-through functions"
    );
    for function in &recovery.functions {
        if function.recovered_stmts.is_empty() {
            continue;
        }
        let shape: (u32, Option<usize>) =
            shape_of(function).expect("reconstructed body must be a recognized pass-through/None");
        assert_eq!(
            truth.get(&function.name),
            Some(&shape),
            "{} was reconstructed as {shape:?}, which is not what its own source does",
            function.name
        );
    }

    let decompilation: NuitkaDecompilation =
        decompile_bytes(&bytes).expect("decompile the fresh Nuitka extension");
    let surface: &SurfaceModule = decompilation
        .surface
        .as_ref()
        .expect("the fresh extension yields a recovered surface");
    let recovered_names: BTreeSet<String> = surface
        .functions
        .iter()
        .filter(|function: &&SurfaceFunction| function.body_recovered)
        .map(|function: &SurfaceFunction| function.name.clone())
        .collect();
    let expected_names: BTreeSet<String> = truth.keys().cloned().collect();
    assert!(
        expected_names.is_subset(&recovered_names),
        "every pass-through or None-returning source function must be recovered from its native \
         body; expected {expected_names:?}, recovered {recovered_names:?}"
    );

    let recovered_src: PathBuf = dir.path().join("gradmod_recovered.py");
    std::fs::write(&recovered_src, surface.python_source.as_bytes())
        .expect("write the recovered module");
    let verdicts: BTreeMap<String, String> =
        compare_with_source(&py, &src, &recovered_src, &recovered_names, None);
    let differing: Vec<(&String, &String)> = verdicts
        .iter()
        .filter(|(_, verdict): &(&String, &String)| verdict.as_str() != "OK")
        .collect();
    assert!(
        differing.is_empty(),
        "recovered functions must behave as their source on the sentinel and integer batteries: \
         {differing:?}\n{}",
        surface.python_source
    );
    assert_eq!(
        verdicts.keys().cloned().collect::<BTreeSet<String>>(),
        recovered_names,
        "the comparison must grade every recovered function"
    );

    let mutated: &String = expected_names
        .iter()
        .find(|name: &&String| {
            truth.get(*name).is_some_and(|(argcount, returned)| {
                *argcount >= 2 && returned.is_some_and(|index: usize| index > 0)
            })
        })
        .expect("the source defines a function of two or more parameters returning a later one");
    let control: BTreeMap<String, String> =
        compare_with_source(&py, &src, &recovered_src, &recovered_names, Some(mutated));
    assert!(
        control
            .get(mutated)
            .is_some_and(|verdict: &String| verdict.starts_with("DIFF")),
        "replacing recovered {mutated} with a function returning its first argument must turn \
         the comparison red: {control:?}"
    );
}

#[test]
fn real_nuitka_bytes_constants_match_cpython_and_digest_symbol() {
    let Some(py): Option<PathBuf> = common::python314_with_nuitka() else {
        return;
    };
    assert_eq!(
        nuitka_version(&py),
        "4.1.1",
        "fresh producer test requires Nuitka 4.1.1"
    );

    let dir: TestDir = TestDir::create("disrobe-nuitka-bytes");
    let src: PathBuf = dir.path().join("bytesmod.py");
    std::fs::write(&src, BYTES_SOURCE.as_bytes()).expect("write source module");

    let source_probe: Output = run_python(
        &py,
        &[
            "-c",
            "import hashlib, inspect, runpy, sys; module = runpy.run_path(sys.argv[1]); value = module['payload'](); print(value.hex()); print(hashlib.md5(repr(value).encode('utf-8')).hexdigest()); print(repr(module['text_payload']())); print(hashlib.md5(repr(module['text_payload']()).encode('utf-8')).hexdigest()); print(repr(module['control_text_payload']())); print(hashlib.md5(repr(module['control_text_payload']()).encode('utf-8')).hexdigest()); print(module['marker']() is None); print(module['truth']()); print(module['falsity']()); print(module['ignored'](object())); print(module['keyword_payload']().hex()); print(module['structured_keyword_defaults']()); print(inspect.signature(module['structured_keyword_defaults'])); print(module['long_constant_return_function_name_for_digest_metadata'](object()).hex())",
            &src.to_string_lossy(),
        ],
    );
    assert!(
        source_probe.status.success(),
        "CPython source oracle failed: {}",
        String::from_utf8_lossy(&source_probe.stderr)
    );
    let oracle_stdout: String = String::from_utf8_lossy(&source_probe.stdout).into_owned();
    let oracle_lines: Vec<&str> = oracle_stdout.lines().collect();
    assert_eq!(
        oracle_lines,
        [
            "00ff275c0a",
            "4c0df53ab9b79e0a014eec37ba930444",
            "\"quote' slash\\\\ newline\\n\"",
            "b29780b2f746c359f51f8b02f50dc142",
            "'\\x7f\\u200b😀'",
            "f4be755113959eb08cb030715804ff97",
            "True",
            "True",
            "False",
            "True",
            "00ff275c0a",
            "True",
            "(*, ratio=1.5, labels=frozenset({1, 2}), options={3, 4})",
            "00ff275c0a",
        ]
    );

    let out_dir: PathBuf = dir.path().join("out");
    let build: Output = run_python(
        &py,
        &[
            "-m",
            "nuitka",
            "--module",
            &src.to_string_lossy(),
            &format!("--output-dir={}", out_dir.to_string_lossy()),
            "--no-pyi-file",
            "--assume-yes-for-downloads",
            "--quiet",
        ],
    );
    assert!(
        build.status.success(),
        "Nuitka build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );

    let build_dir: PathBuf = out_dir.join("bytesmod.build");
    let c_source: String = std::fs::read_to_string(build_dir.join("module.bytesmod.c"))
        .expect("read fresh Nuitka C source");
    assert!(
        c_source.contains("const_bytes_digest_4c0df53ab9b79e0a014eec37ba930444"),
        "fresh Nuitka C source must name the CPython-derived bytes digest"
    );
    assert!(
        c_source.contains("const_str_digest_b29780b2f746c359f51f8b02f50dc142"),
        "fresh Nuitka C source must name the CPython-derived string digest"
    );
    assert!(
        c_source.contains("const_str_digest_f4be755113959eb08cb030715804ff97"),
        "fresh Nuitka C source must name the CPython-derived control-string digest"
    );

    let const_bytes: Vec<u8> = std::fs::read(build_dir.join("module.bytesmod.const"))
        .expect("read fresh Nuitka constants blob");
    let pool: ConstantsPool = decode_const_file(&const_bytes, "module.bytesmod.const", "bytesmod")
        .expect("decode fresh Nuitka constants blob");
    let recovered: Value = serde_json::to_value(&pool).expect("serialize recovered constants");

    assert_eq!(
        recovered.get("bytes"),
        Some(&json!([[0, 255, 39, 92, 10]])),
        "decoded const pool must retain the source bytes exactly"
    );
    assert_eq!(
        recovered
            .get("digest_to_bytes")
            .and_then(Value::as_object)
            .and_then(|values| values.get("4c0df53ab9b79e0a014eec37ba930444")),
        Some(&json!([0, 255, 39, 92, 10])),
        "decoded const pool must index the exact bytes under Nuitka's emitted digest"
    );

    let decompilation: NuitkaDecompilation =
        decompile_build_dir(&build_dir).expect("decompile fresh Nuitka build directory");
    assert_eq!(
        decompilation.version.python_abi,
        Some((3, 14)),
        "versioned extension suffix must preserve the producer ABI"
    );
    let surface: &SurfaceModule = decompilation
        .surface
        .as_ref()
        .expect("fresh Nuitka build must produce a recovered surface");
    let function_names: BTreeSet<&str> = surface
        .functions
        .iter()
        .map(|function: &SurfaceFunction| function.name.as_str())
        .collect();
    let expected_names: BTreeSet<&str> = BTreeSet::from([
        "falsity",
        "ignored",
        "long_constant_return_function_name_for_digest_metadata",
        "marker",
        "payload",
        "text_payload",
        "truth",
        "keyword_payload",
        "control_text_payload",
        "structured_keyword_defaults",
        "annotated_collection",
    ]);
    assert_eq!(
        function_names, expected_names,
        "surface must recover every constant-return source function"
    );
    assert_eq!(
        surface.functions.len(),
        function_names.len(),
        "surface must not duplicate constant-return functions"
    );
    let payload: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "payload")
        .expect("recovered surface must contain payload");
    assert!(payload.body_recovered, "payload body must be recovered");
    assert_eq!(
        payload.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const(
            "b\"\\x00\\xff'\\\\\\n\"".to_owned()
        ))],
        "recovered payload body must retain the source bytes exactly"
    );
    let text_payload: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "text_payload")
        .expect("recovered surface must contain text_payload");
    assert!(
        text_payload.body_recovered,
        "text payload body must be recovered"
    );
    assert_eq!(
        text_payload.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const(
            "\"quote' slash\\\\ newline\\n\"".to_owned()
        ))],
        "recovered text payload body must retain the source string exactly"
    );
    let control_text_payload: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "control_text_payload")
        .expect("recovered surface must contain control_text_payload");
    assert_eq!(
        control_text_payload.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const(
            "'\\x7f\\u200b😀'".to_owned()
        ))],
        "recovered control text must retain the source codepoints exactly"
    );
    let marker: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "marker")
        .expect("recovered surface must contain marker");
    assert_eq!(
        marker.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("None".to_owned()))],
        "recovered marker body must retain the source singleton exactly"
    );
    let truth: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "truth")
        .expect("recovered surface must contain truth");
    assert_eq!(
        truth.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("True".to_owned()))],
        "recovered truth body must retain the source singleton exactly"
    );
    let falsity: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "falsity")
        .expect("recovered surface must contain falsity");
    assert_eq!(
        falsity.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("False".to_owned()))],
        "recovered falsity body must retain the source singleton exactly"
    );
    let ignored: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "ignored")
        .expect("recovered surface must contain ignored");
    let ignored_params: Vec<&str> = ignored
        .params
        .iter()
        .map(|param| param.name.as_str())
        .collect();
    assert_eq!(ignored_params, ["value"]);
    assert_eq!(
        ignored.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("True".to_owned()))],
        "recovered ignored body must retain the source singleton exactly"
    );
    let keyword_payload: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "keyword_payload")
        .expect("recovered surface must contain keyword_payload");
    assert_eq!(keyword_payload.params.len(), 1);
    assert_eq!(keyword_payload.params[0].name, "enabled");
    assert!(keyword_payload.params[0].keyword_only);
    assert_eq!(keyword_payload.params[0].default.as_deref(), Some("True"));
    assert_eq!(
        keyword_payload.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const(
            "b\"\\x00\\xff'\\\\\\n\"".to_owned()
        ))],
        "recovered keyword-only default function must retain its exact constant body"
    );
    let structured_defaults: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "structured_keyword_defaults")
        .expect("recovered surface must contain structured_keyword_defaults");
    assert_eq!(structured_defaults.params.len(), 3usize);
    assert_eq!(structured_defaults.params[0].name, "ratio");
    assert_eq!(
        structured_defaults.params[0].default.as_deref(),
        Some("1.5")
    );
    assert_eq!(
        structured_defaults.params[1].default.as_deref(),
        Some("frozenset({1, 2})")
    );
    assert_eq!(
        structured_defaults.params[2].default.as_deref(),
        Some("{3, 4}")
    );
    assert!(
        structured_defaults
            .params
            .iter()
            .all(|param| param.keyword_only)
    );
    assert_eq!(
        structured_defaults.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("True".to_owned()))],
        "recovered structured defaults function must retain its exact constant body"
    );
    let annotated_collection: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == "annotated_collection")
        .expect("recovered surface must contain annotated_collection");
    assert_eq!(annotated_collection.params.len(), 1usize);
    assert_eq!(annotated_collection.params[0].name, "values");
    assert_eq!(
        annotated_collection.params[0].annotation.as_deref(),
        Some("list[int]")
    );
    assert_eq!(
        annotated_collection.return_annotation.as_deref(),
        Some("dict[str, int | None]")
    );
    assert_eq!(
        annotated_collection.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const("None".to_owned()))],
        "recovered generic annotation function must retain its exact constant body"
    );
    let long_name: &str = "long_constant_return_function_name_for_digest_metadata";
    let long_constant: &SurfaceFunction = surface
        .functions
        .iter()
        .find(|function: &&SurfaceFunction| function.name == long_name)
        .expect("recovered surface must contain the digest-named function");
    assert_eq!(
        long_constant
            .params
            .iter()
            .map(|param| param.name.as_str())
            .collect::<Vec<&str>>(),
        ["value"],
        "digest-named code objects must retain their factory-linked signature"
    );
    assert_eq!(
        long_constant.body_stmts,
        vec![PythonStmt::Return(PythonExpr::Const(
            "b\"\\x00\\xff'\\\\\\n\"".to_owned()
        ))],
        "digest-named code objects must retain their exact constant body"
    );

    let recovered_source: PathBuf = dir.path().join("recovered.py");
    std::fs::write(&recovered_source, surface.python_source.as_bytes())
        .expect("write recovered source");
    let ast_check: Output = run_python(
        &py,
        &[
            "-c",
            "import ast, pathlib, runpy, sys\noriginal = pathlib.Path(sys.argv[1]).read_text(encoding='utf-8')\nrecovered = pathlib.Path(sys.argv[2]).read_text(encoding='utf-8')\ncompile(recovered, sys.argv[2], 'exec')\noriginal_tree = ast.parse(original)\nrecovered_tree = ast.parse(recovered)\ndef without_future(tree):\n    tree.body = [node for node in tree.body if not (isinstance(node, ast.ImportFrom) and node.module == '__future__' and any(alias.name == 'annotations' for alias in node.names))]\nwithout_future(original_tree)\nwithout_future(recovered_tree)\nif ast.dump(original_tree, include_attributes=False) != ast.dump(recovered_tree, include_attributes=False):\n    raise SystemExit('recovered module AST differs from known source')\ndef default_state(path):\n    function = runpy.run_path(path)['structured_keyword_defaults']\n    defaults = function.__kwdefaults__\n    before = (defaults['ratio'] == 1.5, defaults['labels'] == frozenset({1, 2}), defaults['options'] == {3, 4})\n    defaults['options'].add(5)\n    return before + (function.__kwdefaults__['options'] == {3, 4, 5},)\nif default_state(sys.argv[1]) != default_state(sys.argv[2]):\n    raise SystemExit('recovered keyword-default state differs from known source')",
            &src.to_string_lossy(),
            &recovered_source.to_string_lossy(),
        ],
    );
    assert!(
        ast_check.status.success(),
        "CPython AST oracle rejected recovered source: {}",
        String::from_utf8_lossy(&ast_check.stderr)
    );
}

fn probe_source_shapes(py: &Path, src: &Path) -> BTreeMap<String, (u32, Option<usize>)> {
    let code: &str = r#"
import importlib.util, sys, inspect
spec = importlib.util.spec_from_file_location("gradmod", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sentinels = [object() for _ in range(8)]
out = []
for name, fn in inspect.getmembers(mod, inspect.isfunction):
    try:
        n = len(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        continue
    args = sentinels[:n]
    try:
        result = fn(*args)
    except Exception:
        continue
    if result is None:
        out.append(f"{name}:{n}:none")
        continue
    for i, a in enumerate(args):
        if result is a:
            out.append(f"{name}:{n}:{i}")
            break
print("\n".join(out))
"#;
    let output: Output = run_python(py, &["-c", code, &src.to_string_lossy()]);
    assert!(
        output.status.success(),
        "ground-truth probe of the source module failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    stdout
        .lines()
        .map(|line: &str| {
            let fields: Vec<&str> = line.trim().split(':').collect();
            let [name, count, tail] = fields.as_slice() else {
                panic!("ground-truth probe row {line:?}");
            };
            let argcount: u32 = count
                .parse()
                .unwrap_or_else(|error: std::num::ParseIntError| panic!("{line:?}: {error}"));
            let target: Option<usize> = (*tail != "none").then(|| {
                tail.parse()
                    .unwrap_or_else(|error: std::num::ParseIntError| panic!("{line:?}: {error}"))
            });
            ((*name).to_owned(), (argcount, target))
        })
        .collect()
}

fn compare_with_source(
    py: &Path,
    src: &Path,
    recovered: &Path,
    names: &BTreeSet<String>,
    mutate: Option<&str>,
) -> BTreeMap<String, String> {
    let code: &str = r#"
import importlib.util, itertools, sys

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def outcome(function, args):
    try:
        result = function(*args)
    except Exception as error:
        return ("raise", type(error).__name__)
    for index, arg in enumerate(args):
        if result is arg:
            return ("arg", index)
    return ("value", repr(result))

original = load("gradmod_original", sys.argv[1])
recovered = load("gradmod_recovered", sys.argv[2])
mutate = sys.argv[4]
for name in sys.argv[3].split(","):
    source_function = getattr(original, name, None)
    recovered_function = getattr(recovered, name, None)
    if source_function is None or recovered_function is None:
        print(f"{name}\tMISSING")
        continue
    if name == mutate:
        recovered_function = lambda *args: args[0]
    count = source_function.__code__.co_argcount
    batteries = [[object() for _ in range(count)]]
    batteries += [list(values) for values in itertools.product([-3, 0, 2, 7], repeat=count)]
    verdict = "OK"
    for args in batteries:
        want = outcome(source_function, args)
        got = outcome(recovered_function, args)
        if want != got:
            verdict = f"DIFF {args!r}: source {want} recovered {got}"
            break
    print(f"{name}\t{verdict}")
"#;
    let joined: String = names.iter().cloned().collect::<Vec<String>>().join(",");
    let output: Output = run_python(
        py,
        &[
            "-c",
            code,
            &src.to_string_lossy(),
            &recovered.to_string_lossy(),
            &joined,
            mutate.unwrap_or(""),
        ],
    );
    assert!(
        output.status.success(),
        "the source-versus-recovered comparison failed to run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line: &str| {
            let (name, verdict): (&str, &str) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("comparison row {line:?}"));
            (name.to_owned(), verdict.to_owned())
        })
        .collect()
}
