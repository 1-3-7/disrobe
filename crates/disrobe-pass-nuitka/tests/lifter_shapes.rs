#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Output;

use disrobe_pass_nuitka::{
    LiftFidelity, NuitkaDecompilation, SurfaceFunction, SurfaceModule,
    decompile_build_dir_with_python_abi,
};

const PYTHON_ABI: (u8, u8) = (3u8, 14u8);

const AUTHORED_FUNCTIONS: [&str; 7] = [
    "either_call",
    "grid_sum",
    "join_sign",
    "lookup",
    "make_scaler",
    "neg_cube",
    "neg_power",
];

const BATTERY: &str = r#"
import importlib.util, sys

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def outcome(thunk):
    try:
        return ("value", repr(thunk()))
    except Exception as error:
        return ("raise", type(error).__name__)

CASES = {
    "join_sign": [lambda m: m.join_sign(-3), lambda m: m.join_sign(0), lambda m: m.join_sign(5)],
    "grid_sum": [lambda m: m.grid_sum(0, 0), lambda m: m.grid_sum(2, 3), lambda m: m.grid_sum(3, 4), lambda m: m.grid_sum(4, 1)],
    "make_scaler": [
        lambda m: m.make_scaler(3, 4)(5),
        lambda m: m.make_scaler("a", "b")(2),
        lambda m: sorted(m.make_scaler(1, 2).__code__.co_freevars),
    ],
    "lookup": [
        lambda m: m.lookup({"a": "7"}, "a"),
        lambda m: m.lookup({}, "a"),
        lambda m: m.lookup({"a": "x"}, "a"),
        lambda m: m.lookup({"a": None}, "a"),
        lambda m: m.lookup([10], 0),
        lambda m: m.lookup([1], 5),
    ],
    "neg_cube": [lambda m: m.neg_cube()],
    "neg_power": [lambda m: m.neg_power(0), lambda m: m.neg_power(2), lambda m: m.neg_power(3)],
    "either_call": [
        lambda m: m.either_call(None, abs, -3),
        lambda m: m.either_call(str, abs, -3),
        lambda m: m.either_call(0, None, 1),
    ],
}

authored = load("shapes_authored", sys.argv[1])
recovered = load("shapes_recovered", sys.argv[2])
mutate = sys.argv[3]
if mutate == "neg_power":
    recovered.neg_power = lambda n: -2 ** n
for name in sorted(CASES):
    verdict = "OK"
    for index, case in enumerate(CASES[name]):
        want = outcome(lambda: case(authored))
        got = outcome(lambda: case(recovered))
        if want != got:
            verdict = f"DIFF case {index}: authored {want} recovered {got}"
            break
    print(f"{name}\t{verdict}")
"#;

fn decompile_shapes() -> NuitkaDecompilation {
    let build_dir: PathBuf = common::corpus_root().join("shapes").join("shapes.build");
    common::tracked("shapes/shapes.build/module.shapes.c");
    common::tracked("shapes/shapes.build/module.shapes.const");
    decompile_build_dir_with_python_abi(&build_dir, PYTHON_ABI)
        .expect("decompile the committed shapes build directory")
}

fn surface(decompilation: &NuitkaDecompilation) -> &SurfaceModule {
    decompilation
        .surface
        .as_ref()
        .unwrap_or_else(|| panic!("no surface recovered: {:?}", decompilation.notes))
}

fn fidelities(functions: &[SurfaceFunction], out: &mut BTreeMap<String, LiftFidelity>) {
    for function in functions {
        out.insert(function.name.clone(), function.lift_fidelity);
        fidelities(&function.nested, out);
    }
}

fn battery_verdicts(python: &Path, recovered: &Path, mutate: &str) -> BTreeMap<String, String> {
    let authored: PathBuf = common::tracked("shapes/shapes.src.py");
    let output: Output = std::process::Command::new(python)
        .env("PYTHONIOENCODING", "utf-8")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args(["-c", BATTERY])
        .arg(&authored)
        .arg(recovered)
        .arg(mutate)
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("spawn CPython 3.14 at {}: {error}", python.display())
        });
    assert!(
        output.status.success(),
        "the authored-versus-recovered battery failed to run: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line: &str| {
            let (name, verdict): (&str, &str) = line
                .split_once('\t')
                .unwrap_or_else(|| panic!("battery row {line:?}"));
            (name.to_owned(), verdict.to_owned())
        })
        .collect()
}

#[test]
fn the_manifest_pins_every_committed_shapes_fixture_to_nuitka_411_output() {
    let python: PathBuf = common::python314();
    let manifest: PathBuf = common::tracked("shapes/MANIFEST.toml");
    let output: Output = common::run_python(&python, MANIFEST_PROBE, &[&manifest]);
    assert!(
        output.status.success(),
        "the shapes manifest must pin every committed fixture: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    for c_file in [
        "shapes/shapes.build/module.shapes.c",
        "shapes/pkgsurf.build/module.pkgsurf.c",
        "shapes/pkgsurf.build/module.pkgsurf.tools.c",
    ] {
        assert!(
            common::read_tracked_text(c_file).contains("created by Nuitka version 4.1.1"),
            "{c_file} must be verbatim Nuitka 4.1.1 output"
        );
    }
}

const MANIFEST_PROBE: &str = r#"
import hashlib, pathlib, sys, tomllib
manifest = pathlib.Path(sys.argv[1])
root = manifest.parent
record = tomllib.loads(manifest.read_text(encoding="utf-8"))
assert record["tool_version"] == "4.1.1", record["tool_version"]
assert record["python_runtime"].startswith("CPython 3.14."), record["python_runtime"]
listed = set()
for fixture in record["fixtures"]:
    path = root / fixture["file"]
    data = path.read_bytes()
    assert len(data) == fixture["bytes"], (fixture["file"], len(data))
    assert hashlib.sha256(data).hexdigest() == fixture["sha256"], fixture["file"]
    listed.add(fixture["file"])
present = {
    p.relative_to(root).as_posix()
    for p in root.rglob("*")
    if p.is_file() and p != manifest and "__pycache__" not in p.parts
}
assert present == listed, (sorted(present - listed), sorted(listed - present))
"#;

#[test]
fn every_authored_shape_lifts_to_a_full_body_without_dropped_lines() {
    let decompilation: NuitkaDecompilation = decompile_shapes();
    let surface: &SurfaceModule = surface(&decompilation);
    let top_level: BTreeSet<&str> = surface
        .functions
        .iter()
        .map(|function: &SurfaceFunction| function.name.as_str())
        .collect();
    assert_eq!(
        top_level,
        AUTHORED_FUNCTIONS.into_iter().collect::<BTreeSet<&str>>(),
        "the recovered module must define exactly the authored functions"
    );
    let mut lifted: BTreeMap<String, LiftFidelity> = BTreeMap::new();
    fidelities(&surface.functions, &mut lifted);
    let short: Vec<(&String, &LiftFidelity)> = lifted
        .iter()
        .filter(|(_, fidelity): &(&String, &LiftFidelity)| **fidelity != LiftFidelity::FullBody)
        .collect();
    assert!(
        short.is_empty(),
        "every authored function, including the closure `apply`, must lift to a full body; \
         short of it: {short:?}; notes: {:?}\n{}",
        decompilation.notes,
        surface.python_source
    );
    assert!(
        lifted.contains_key("apply"),
        "the closure `apply` must be recovered nested in make_scaler: {lifted:?}"
    );
    assert!(
        !decompilation
            .notes
            .iter()
            .any(|note: &String| note.contains("unrecognized C line")),
        "no function may drop C lines: {:?}",
        decompilation.notes
    );
    assert!(
        !surface.python_source.contains("body not recovered"),
        "no body may fall back to the placeholder:\n{}",
        surface.python_source
    );
}

#[test]
fn every_authored_shape_behaves_as_the_authored_program_on_cpython_314() {
    let python: PathBuf = common::python314();
    let decompilation: NuitkaDecompilation = decompile_shapes();
    let surface: &SurfaceModule = surface(&decompilation);

    let purpose: String = format!("disrobe-nuitka-shapes-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let recovered: PathBuf = scratch.path().join("shapes_recovered.py");
    std::fs::write(&recovered, surface.python_source.as_bytes())
        .expect("write the recovered module");

    let verdicts: BTreeMap<String, String> = battery_verdicts(&python, &recovered, "");
    assert_eq!(
        verdicts.keys().map(String::as_str).collect::<Vec<&str>>(),
        AUTHORED_FUNCTIONS.to_vec(),
        "the battery must grade every authored function"
    );
    let differing: Vec<(&String, &String)> = verdicts
        .iter()
        .filter(|(_, verdict): &(&String, &String)| verdict.as_str() != "OK")
        .collect();
    assert!(
        differing.is_empty(),
        "recovered functions must behave as the authored program: {differing:?}\n{}",
        surface.python_source
    );

    let control: BTreeMap<String, String> = battery_verdicts(&python, &recovered, "neg_power");
    assert!(
        control
            .get("neg_power")
            .is_some_and(|verdict: &String| verdict.starts_with("DIFF")),
        "replacing the recovered neg_power with `-2 ** n` must turn the battery red: {control:?}"
    );
}
