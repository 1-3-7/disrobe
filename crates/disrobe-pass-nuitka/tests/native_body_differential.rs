#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_pass_nuitka::{
    NativeBodyRecovery, NativeFunctionBody, PythonStmt, lift_native_bodies, parse_constants,
};

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
        if banner.contains("3.1") {
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
    cmd.args(&py.1);
    cmd.args(extra);
    cmd.output().ok()
}

fn nuitka_available(py: &(String, Vec<String>)) -> bool {
    run_python(py, &["-m", "nuitka", "--version"]).is_some_and(|o: Output| o.status.success())
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
        eprintln!("skip: no python 3.1x on PATH");
        return;
    };
    if !nuitka_available(&py) {
        eprintln!("skip: nuitka not importable in the located python");
        return;
    }

    let dir: PathBuf =
        std::env::temp_dir().join(format!("disrobe-native-body-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let src: PathBuf = dir.join("gradmod.py");
    std::fs::write(&src, MODULE_SOURCE.as_bytes()).expect("write source module");

    let out_dir: PathBuf = dir.join("out");
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
        let _ = std::fs::remove_dir_all(&dir);
        return;
    };
    if !build.status.success() {
        eprintln!(
            "skip: nuitka build failed (no working C compiler?): {}",
            String::from_utf8_lossy(&build.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
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
    let recovery: NativeBodyRecovery =
        lift_native_bodies(&bytes, &constants).expect("native body recovery on real release pyd");

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

    let _ = std::fs::remove_dir_all(&dir);
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
