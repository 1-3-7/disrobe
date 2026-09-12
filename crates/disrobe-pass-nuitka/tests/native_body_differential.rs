#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    ConstantsPool, NativeBodyRecovery, NativeFunctionBody, NuitkaDecompilation, PythonExpr,
    PythonStmt, SurfaceFunction, SurfaceModule, decode_const_file, decompile_build_dir,
    lift_native_bodies, parse_constants,
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

fn locate_python() -> Option<(String, Vec<String>)> {
    let candidates: [(&str, &[&str]); 3] = [("py", &["-3.14"]), ("python", &[]), ("python3", &[])];
    for (cmd, prefix) in candidates {
        let mut args: Vec<String> = prefix.iter().map(|s: &&str| (*s).to_owned()).collect();
        args.push("--version".to_owned());
        let Ok(output): Result<Output, std::io::Error> = Command::new(cmd).args(&args).output()
        else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let banner: String = String::from_utf8_lossy(&output.stdout).into_owned()
            + String::from_utf8_lossy(&output.stderr).as_ref();
        if banner.starts_with("Python 3.14.") {
            return Some((
                cmd.to_owned(),
                prefix.iter().map(|s: &&str| (*s).to_owned()).collect(),
            ));
        }
    }
    None
}

fn run_python(py: &(String, Vec<String>), extra: &[&str]) -> Option<Output> {
    let mut cmd: Command = Command::new(&py.0);
    cmd.env("PYTHONIOENCODING", "utf-8");
    cmd.args(&py.1);
    cmd.args(extra);
    cmd.output().ok()
}

fn nuitka_version(py: &(String, Vec<String>)) -> Option<String> {
    let output: Output = run_python(py, &["-m", "nuitka", "--version"])?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&output.stdout).into_owned()
        + String::from_utf8_lossy(&output.stderr).as_ref();
    text.lines()
        .next()
        .map(str::trim)
        .filter(|version: &&str| !version.is_empty())
        .map(str::to_owned)
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
    let Some(py): Option<(String, Vec<String>)> = locate_python() else {
        eprintln!("skip: no python 3.14 on PATH");
        return;
    };
    let Some(nuitka_version): Option<String> = nuitka_version(&py) else {
        eprintln!("skip: nuitka not importable in the located python");
        return;
    };
    assert_eq!(
        nuitka_version, "4.1.1",
        "fresh producer test requires Nuitka 4.1.1"
    );

    let dir: TestDir = TestDir::create("disrobe-native-body");
    let src: PathBuf = dir.path().join("gradmod.py");
    std::fs::write(&src, MODULE_SOURCE.as_bytes()).expect("write source module");

    let out_dir: PathBuf = dir.path().join("out");
    let build: Option<Output> = run_python(
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
    let Some(build): Option<Output> = build else {
        eprintln!("skip: could not spawn nuitka");
        return;
    };
    if !build.status.success() {
        eprintln!(
            "skip: nuitka build failed (no working C compiler?): {}",
            String::from_utf8_lossy(&build.stderr)
        );
        return;
    }

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

    let ground_truth: BTreeSet<(u32, Option<usize>)> = probe_source_shapes(&py, &src);
    assert!(
        !ground_truth.is_empty(),
        "ground-truth probe of the source module returned no pass-through shapes"
    );

    let mut reconstructed_shapes: Vec<(u32, Option<usize>)> = Vec::new();
    for function in &recovery.functions {
        if function.recovered_stmts.is_empty() {
            continue;
        }
        let shape: (u32, Option<usize>) =
            shape_of(function).expect("reconstructed body must be a recognized pass-through/None");
        assert!(
            ground_truth.contains(&shape),
            "SOUNDNESS VIOLATION: reconstructed shape {shape:?} for {} does not correspond to any \
             real source function behavior {ground_truth:?}",
            function.name
        );
        assert_behaviorally_equivalent(&py, function, shape);
        reconstructed_shapes.push(shape);
    }

    let unique: BTreeSet<(u32, Option<usize>)> = reconstructed_shapes.iter().copied().collect();
    eprintln!(
        "NATIVE BODY LIFT vs CPython: located {} impl(s); reconstructed {} behaviorally-exact \
         body/bodies ({} distinct shapes); ground-truth pass-through shapes in source: {}",
        recovery.located_impls,
        reconstructed_shapes.len(),
        unique.len(),
        ground_truth.len()
    );

    assert!(
        reconstructed_shapes.len() >= 2,
        "expected at least 2 behaviorally-exact native body reconstructions, got {}",
        reconstructed_shapes.len()
    );
}

#[test]
fn real_nuitka_bytes_constants_match_cpython_and_digest_symbol() {
    let Some(py): Option<(String, Vec<String>)> = locate_python() else {
        eprintln!("skip: no python 3.14 on PATH");
        return;
    };
    let Some(nuitka_version): Option<String> = nuitka_version(&py) else {
        eprintln!("skip: nuitka not importable in the located python");
        return;
    };
    assert_eq!(
        nuitka_version, "4.1.1",
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
    )
    .expect("run original source on CPython");
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
    )
    .expect("run nuitka");
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
    )
    .expect("run CPython AST comparison");
    assert!(
        ast_check.status.success(),
        "CPython AST oracle rejected recovered source: {}",
        String::from_utf8_lossy(&ast_check.stderr)
    );
}

fn probe_source_shapes(py: &(String, Vec<String>), src: &Path) -> BTreeSet<(u32, Option<usize>)> {
    let code: &str = r#"
import importlib.util, sys, inspect
spec = importlib.util.spec_from_file_location("gradmod", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
sentinels = [object() for _ in range(8)]
out = []
for name, fn in inspect.getmembers(mod, inspect.isfunction):
    try:
        sig = inspect.signature(fn)
        n = len(sig.parameters)
    except (TypeError, ValueError):
        continue
    args = sentinels[:n]
    try:
        result = fn(*args)
    except Exception:
        continue
    if result is None:
        out.append(f"{n}:none")
        continue
    idx = None
    for i, a in enumerate(args):
        if result is a:
            idx = i
            break
    if idx is not None:
        out.append(f"{n}:{idx}")
print("\n".join(out))
"#;
    let Some(output): Option<Output> = run_python(py, &["-c", code, &src.to_string_lossy()]) else {
        return BTreeSet::new();
    };
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let mut shapes: BTreeSet<(u32, Option<usize>)> = BTreeSet::new();
    for line in stdout.lines() {
        let Some((count, tail)): Option<(&str, &str)> = line.trim().split_once(':') else {
            continue;
        };
        let Ok(argcount): Result<u32, _> = count.parse() else {
            continue;
        };
        if tail == "none" {
            shapes.insert((argcount, None));
        } else if let Ok(index) = tail.parse::<usize>() {
            shapes.insert((argcount, Some(index)));
        }
    }
    shapes
}

fn assert_behaviorally_equivalent(
    py: &(String, Vec<String>),
    function: &NativeFunctionBody,
    shape: (u32, Option<usize>),
) {
    let (argcount, target): (u32, Option<usize>) = shape;
    let params: Vec<String> = (0..argcount).map(|i: u32| format!("a{i}")).collect();
    let body: String = target.map_or_else(
        || "return None".to_owned(),
        |index: usize| format!("return a{index}"),
    );
    let recovered: String = format!("def rec({}):\n    {body}\n", params.join(", "));
    let sentinels: Vec<String> = (0..argcount)
        .map(|i: u32| format!("{}", 1000 + i))
        .collect();
    let want: String = target.map_or_else(
        || "None".to_owned(),
        |index: usize| format!("{}", 1000 + index as u32),
    );
    let code: String = format!("{recovered}\nprint(repr(rec({})))\n", sentinels.join(", "));
    let output: Output = run_python(py, &["-c", &code]).expect("run recovered body");
    assert!(
        output.status.success(),
        "recovered body for {} failed to run: {}",
        function.name,
        String::from_utf8_lossy(&output.stderr)
    );
    let got: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert_eq!(
        got, want,
        "recovered body for {} produced {got:?}, expected {want:?}",
        function.name
    );
}
