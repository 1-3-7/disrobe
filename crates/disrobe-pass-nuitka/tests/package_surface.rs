#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Output;

use disrobe_pass_nuitka::{
    CModuleStructure, ConstantsPool, LiftFidelity, NuitkaDecompilation, SurfaceFunction,
    SurfaceModule, build_surface_with_python_abi, decode_const_file, decompile_build_dir,
    decompile_build_dir_with_python_abi, parse_c_module_with_python_abi,
};

const PYTHON_ABI: (u8, u8) = (3u8, 14u8);
const C_SOURCE_CAP_BYTES: u64 = 64 * 1024 * 1024;

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
    "gather": [
        lambda m: m.gather(1),
        lambda m: m.gather(1, 2, 3),
        lambda m: m.gather(1, 2, zeta=3, alpha=4),
        lambda m: m.gather(first=5, extra=6),
        lambda m: m.gather(),
    ],
    "either": [
        lambda m: m.either(0, 5),
        lambda m: m.either(3, 5),
        lambda m: m.either("", None),
        lambda m: m.either([], [1]),
        lambda m: m.either([2], [1]),
    ],
}

authored = load("tools_authored", sys.argv[1])
recovered = load("tools_recovered", sys.argv[2])
if sys.argv[3] == "either":
    recovered.either = lambda a, b: a and b
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

fn pkgsurf_build_dir() -> PathBuf {
    common::tracked("shapes/pkgsurf.build/module.pkgsurf.c");
    common::tracked("shapes/pkgsurf.build/module.pkgsurf.tools.c");
    common::corpus_root().join("shapes").join("pkgsurf.build")
}

fn submodule_surface() -> SurfaceModule {
    let c_source: String = common::read_tracked_text("shapes/pkgsurf.build/module.pkgsurf.tools.c");
    let const_bytes: Vec<u8> =
        common::read_tracked("shapes/pkgsurf.build/module.pkgsurf.tools.const");
    let module: CModuleStructure = parse_c_module_with_python_abi(&c_source, PYTHON_ABI)
        .expect("parse the committed submodule C source");
    let pool: ConstantsPool =
        decode_const_file(&const_bytes, "module.pkgsurf.tools.const", "pkgsurf.tools")
            .expect("decode the committed submodule constants");
    build_surface_with_python_abi(&module, &pool, Some(&c_source), PYTHON_ABI)
        .expect("build the submodule surface")
}

fn write_recovered(
    scratch: &disrobe_core::scratch::ScratchDir,
    name: &str,
    source: &str,
) -> PathBuf {
    let path: PathBuf = scratch.path().join(name);
    std::fs::write(&path, source.as_bytes()).expect("write the recovered module");
    path
}

fn assert_signatures_match(python: &Path, recovered: &Path, authored: &str) {
    let authored: PathBuf = common::tracked(authored);
    let output: Output =
        common::run_python(python, common::SIGNATURE_PROBE, &[recovered, &authored]);
    assert!(
        output.status.success(),
        "recovered signatures must be AST-equal to {}: {}",
        authored.display(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn battery_verdicts(python: &Path, recovered: &Path, mutate: &str) -> BTreeMap<String, String> {
    let authored: PathBuf = common::tracked("shapes/pkgsurf/tools.src.py");
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
fn a_package_build_surfaces_its_root_and_names_the_submodule_it_leaves_out() {
    let python: PathBuf = common::python314();
    let decompilation: NuitkaDecompilation =
        decompile_build_dir_with_python_abi(&pkgsurf_build_dir(), PYTHON_ABI)
            .expect("decompile the committed package build directory");
    let surface: &SurfaceModule = decompilation
        .surface
        .as_ref()
        .unwrap_or_else(|| panic!("no package surface: {:?}", decompilation.notes));
    assert_eq!(surface.module_name, "pkgsurf");
    assert!(
        decompilation
            .constants
            .pools
            .get("module.pkgsurf.tools.const")
            .is_some_and(|pool: &ConstantsPool| pool.strings.contains("gather")),
        "the submodule constants must be decoded: {:?}",
        decompilation
            .constants
            .pools
            .keys()
            .collect::<Vec<&String>>()
    );
    assert!(
        decompilation.notes.iter().any(|note: &String| note
            == "modules not surfaced, their decoded constants kept (the surface covers module \
                pkgsurf only): pkgsurf.tools"),
        "a submodule the surface leaves out must be named in the notes: {:?}",
        decompilation.notes
    );
    assert!(
        decompilation.notes.iter().any(|note: &String| note
            == "module globals bound by module code the surface does not lift: either, gather"),
        "the re-export `from .tools import either, gather` is not lifted, so its names must be \
         refused in the notes: {:?}",
        decompilation.notes
    );

    let purpose: String = format!("disrobe-nuitka-pkgsurf-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let recovered: PathBuf =
        write_recovered(&scratch, "pkgsurf_recovered.py", &surface.python_source);
    assert_signatures_match(&python, &recovered, "shapes/pkgsurf/__init__.src.py");
}

#[test]
fn the_submodule_surface_recovers_star_parameters_and_an_or_return() {
    let python: PathBuf = common::python314();
    let surface: SurfaceModule = submodule_surface();
    assert_eq!(surface.module_name, "pkgsurf$tools");
    for function in &surface.functions {
        assert_eq!(
            function.lift_fidelity,
            LiftFidelity::FullBody,
            "{} must lift to a full body:\n{}",
            function.name,
            surface.python_source
        );
    }
    let names: Vec<&str> = surface
        .functions
        .iter()
        .map(|function: &SurfaceFunction| function.name.as_str())
        .collect();
    assert_eq!(names, ["gather", "either"]);

    let purpose: String = format!("disrobe-nuitka-pkgsurf-tools-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    let recovered: PathBuf =
        write_recovered(&scratch, "tools_recovered.py", &surface.python_source);
    assert_signatures_match(&python, &recovered, "shapes/pkgsurf/tools.src.py");

    let verdicts: BTreeMap<String, String> = battery_verdicts(&python, &recovered, "");
    assert_eq!(
        verdicts.keys().map(String::as_str).collect::<Vec<&str>>(),
        ["either", "gather"],
        "the battery must grade every authored submodule function"
    );
    assert!(
        verdicts.values().all(|verdict: &String| verdict == "OK"),
        "recovered submodule functions must behave as the authored ones: {verdicts:?}\n{}",
        surface.python_source
    );
    let control: BTreeMap<String, String> = battery_verdicts(&python, &recovered, "either");
    assert!(
        control
            .get("either")
            .is_some_and(|verdict: &String| verdict.starts_with("DIFF")),
        "replacing the recovered `a or b` with `a and b` must turn the battery red: {control:?}"
    );
}

#[test]
fn an_oversized_c_source_keeps_the_decoded_constants_and_notes_the_cap() {
    let purpose: String = format!("disrobe-nuitka-oversized-c-{}", std::process::id());
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir");
    std::fs::write(
        scratch.path().join("module.shapes.const"),
        common::read_tracked("shapes/shapes.build/module.shapes.const"),
    )
    .expect("copy the committed constants blob");
    let oversized: std::fs::File = std::fs::File::create(scratch.path().join("module.shapes.c"))
        .expect("create the oversized C source");
    oversized
        .set_len(C_SOURCE_CAP_BYTES + 1u64)
        .expect("extend the C source one byte past the cap");
    drop(oversized);

    let decompilation: NuitkaDecompilation = decompile_build_dir(scratch.path())
        .expect("a C source above the cap must not abort the build-directory decompile");
    assert!(decompilation.surface.is_none());
    assert!(
        decompilation
            .constants
            .pools
            .get("module.shapes.const")
            .is_some_and(|pool: &ConstantsPool| pool.strings.contains("join_sign")
                && pool.strings.contains("neg_power")),
        "the decoded constants must be kept: {:?}",
        decompilation
            .constants
            .pools
            .keys()
            .collect::<Vec<&String>>()
    );
    let cap_note: String = format!(
        "C source has {} bytes, above the {C_SOURCE_CAP_BYTES}-byte parsing cap",
        C_SOURCE_CAP_BYTES + 1u64
    );
    assert!(
        decompilation.notes.iter().any(|note: &String| {
            note.starts_with("module.shapes.c not used") && note.contains(&cap_note)
        }),
        "the cap must be recorded as a note naming the C source: {:?}",
        decompilation.notes
    );
}
