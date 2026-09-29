#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::{ObjectTally, find_interpreter, measure_per_object};
use disrobe_pass_py_decompile::DecompileError;
use disrobe_pass_py_decompile::bytecode::version::PyVersion as DecompileVersion;
use disrobe_pass_py_decompile::engine::{
    RecoveredSource, build_recovered_source, marshal_to_decompile,
};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const VERSIONS: &[&str] = &["3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14"];

const SOURCE: &str = "\
import math

PRECISION = 3


def area(r):
    return round(math.pi * r * r, PRECISION)


def broken(obj, value):
    obj.field = value
    return obj


class Shape:
    def __init__(self, sides):
        self.sides = sides

    def rename(self, target, label):
        target.label = label
        return self

    def describe(self):
        return str(self.sides) + ' sides'


def total(xs):
    acc = 0
    for x in xs:
        if x > 0:
            acc += x
    return acc


settings.mode = 'fast'
";

const REFUSAL: &str =
    "decompile-error: recovery left an unresolved reconstruction placeholder (UNRESOLVED_ATTR)";

const POISONED_NAME_INDEX: u8 = 0xFF;

#[derive(Debug, Clone, Copy)]
enum Target {
    Function,
    Method,
    ModuleBody,
}

impl Target {
    const fn label(self) -> &'static str {
        match self {
            Self::Function => "module-level function `broken`",
            Self::Method => "method `Shape.rename`",
            Self::ModuleBody => "module body",
        }
    }

    const fn path(self) -> &'static [&'static str] {
        match self {
            Self::Function => &["broken"],
            Self::Method => &["Shape", "rename"],
            Self::ModuleBody => &[],
        }
    }

    const fn qualname(self) -> &'static str {
        match self {
            Self::Function => "<module>.broken",
            Self::Method => "<module>.Shape.rename",
            Self::ModuleBody => "<module>",
        }
    }

    const fn def_line(self) -> &'static str {
        match self {
            Self::Function => "def broken(obj, value):",
            Self::Method => "def rename(self, target, label):",
            Self::ModuleBody => "",
        }
    }
}

fn run_python(interpreter: &Path, args: &[&str]) -> Result<String, String> {
    let output: std::process::Output = Command::new(interpreter)
        .args(args)
        .env("PYTHONHASHSEED", "0")
        .env_remove("FORCE_COLOR")
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn {}: {e}", interpreter.display()))?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    run_python(
        interpreter,
        &[
            "-c",
            "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)",
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ],
    )
    .map(|_stdout: String| ())
}

fn store_attr_opcode(interpreter: &Path) -> Result<u8, String> {
    let printed: String = run_python(
        interpreter,
        &["-c", "import dis;print(dis.opmap['STORE_ATTR'])"],
    )?;
    printed
        .parse::<u8>()
        .map_err(|e: std::num::ParseIntError| format!("STORE_ATTR opcode `{printed}`: {e}"))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let version: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, version)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

const fn code_name(code: &CodeObject) -> Option<&str> {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value.as_str()),
        _ => None,
    }
}

fn nested_mut<'a>(code: &'a mut CodeObject, path: &[&str]) -> Option<&'a mut CodeObject> {
    let Some((first, rest)): Option<(&&str, &[&str])> = path.split_first() else {
        return Some(code);
    };
    let child: &mut CodeObject =
        code.consts
            .iter_mut()
            .find_map(|value: &mut Object| match value {
                Object::Code(boxed) if code_name(boxed) == Some(*first) => Some(boxed.as_mut()),
                _ => None,
            })?;
    nested_mut(child, rest)
}

fn poison_store_attr(code: &mut CodeObject, store_attr: u8) -> Result<(), String> {
    let sites: Vec<usize> = (0..code.code.len().saturating_sub(1))
        .step_by(2)
        .filter(|&offset: &usize| code.code[offset] == store_attr)
        .collect();
    let [site]: [usize; 1] = sites
        .as_slice()
        .try_into()
        .map_err(|_| format!("expected one STORE_ATTR, found {}", sites.len()))?;
    if usize::from(POISONED_NAME_INDEX) < code.names.len() {
        return Err(format!(
            "name index {POISONED_NAME_INDEX} is inside co_names ({} entries)",
            code.names.len()
        ));
    }
    code.code[site + 1] = POISONED_NAME_INDEX;
    Ok(())
}

fn recompile(
    interpreter: &Path,
    source: &str,
    scratch: &Path,
    stem: &str,
) -> Result<CodeObject, String> {
    let source_path: PathBuf = scratch.join(format!("{stem}.py"));
    fs::write(&source_path, source).map_err(|e: std::io::Error| format!("write: {e}"))?;
    let pyc_path: PathBuf = scratch.join(format!("{stem}.pyc"));
    compile_source(interpreter, &source_path, &pyc_path)?;
    read_code(&pyc_path).map(|(code, _): (CodeObject, MarshalVersion)| code)
}

fn failed_qualnames(tally: &ObjectTally) -> BTreeSet<String> {
    tally
        .failures
        .iter()
        .map(|failure| failure.qualname.clone())
        .collect()
}

fn stub_follows(source: &str, def_line: &str) -> bool {
    let lines: Vec<&str> = source.lines().collect();
    let Some(at): Option<usize> = lines.iter().position(|line: &&str| line.trim() == def_line)
    else {
        return false;
    };
    let docstring: &str = lines.get(at + 1).map_or("", |line: &&str| line.trim());
    let body: &str = lines.get(at + 2).map_or("", |line: &&str| line.trim());
    docstring.contains(REFUSAL) && body == "pass"
}

#[test]
fn a_failing_nested_code_object_is_refused_alone_and_its_siblings_recover() {
    let scratch: PathBuf = PathBuf::from(concat!(
        env!("CARGO_TARGET_TMPDIR"),
        "/py-per-code-object-fallback"
    ));
    fs::create_dir_all(&scratch).expect("scratch");

    let mut failures: Vec<String> = Vec::new();
    for &alias in VERSIONS {
        let interpreter: PathBuf = find_interpreter(alias).unwrap_or_else(|| {
            panic!(
                "CPython {alias} is required to grade per-code-object fallback and was not found; \
                 `uv python install {alias}` provides it"
            )
        });
        let source_path: PathBuf = scratch.join(format!("module.{alias}.py"));
        fs::write(&source_path, SOURCE).expect("write fixture");
        let pyc_path: PathBuf = scratch.join(format!("module.{alias}.pyc"));
        compile_source(&interpreter, &source_path, &pyc_path)
            .unwrap_or_else(|e| panic!("py{alias} compile: {e}"));
        let (original, marshal_version): (CodeObject, MarshalVersion) =
            read_code(&pyc_path).unwrap_or_else(|e| panic!("py{alias} read: {e}"));
        let version: DecompileVersion = marshal_to_decompile(marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} version map: {e:?}"));
        let store_attr: u8 = store_attr_opcode(&interpreter)
            .unwrap_or_else(|e| panic!("py{alias} opcode lookup: {e}"));

        let clean: RecoveredSource = build_recovered_source(&original, &version, marshal_version)
            .unwrap_or_else(|e| panic!("py{alias} clean decompile: {e}"));
        let clean_recompiled: CodeObject = recompile(
            &interpreter,
            &clean.source,
            &scratch,
            &format!("clean.{alias}"),
        )
        .unwrap_or_else(|e| panic!("py{alias} recompile clean: {e}\n{}", clean.source));
        let clean_tally: ObjectTally =
            measure_per_object(&original, &clean_recompiled, marshal_version);
        assert!(
            clean.stubbed_scopes == 0
                && clean_tally.failures.is_empty()
                && clean_tally.ok == clean_tally.total,
            "py{alias}: the unmutated module must recover every code object, otherwise the \
             comparisons below grade one wrong answer against another: {:?}\n{}",
            clean_tally.failures,
            clean.source
        );

        for target in [Target::Function, Target::Method, Target::ModuleBody] {
            let mut hostile: CodeObject = original.clone();
            let poisoned: &mut CodeObject = nested_mut(&mut hostile, target.path())
                .unwrap_or_else(|| panic!("py{alias}: no code object at {:?}", target.path()));
            poison_store_attr(poisoned, store_attr)
                .unwrap_or_else(|e| panic!("py{alias}/{}: {e}", target.label()));

            let outcome: Result<RecoveredSource, DecompileError> =
                build_recovered_source(&hostile, &version, marshal_version);

            if matches!(target, Target::ModuleBody) {
                match outcome {
                    Err(DecompileError::UnresolvedMarker { stem, .. })
                        if stem == "UNRESOLVED_ATTR" => {}
                    Err(other) => failures.push(format!(
                        "py{alias}/{}: refused for the wrong reason: {other}",
                        target.label()
                    )),
                    Ok(recovered) => failures.push(format!(
                        "py{alias}/{}: a placeholder outside every nested code object must \
                         refuse the module, but it recovered:\n{}",
                        target.label(),
                        recovered.source
                    )),
                }
                continue;
            }

            let recovered: RecoveredSource = match outcome {
                Ok(recovered) => recovered,
                Err(e) => {
                    failures.push(format!(
                        "py{alias}/{}: the whole module failed instead of the one code object \
                         that holds the placeholder: {e}",
                        target.label()
                    ));
                    continue;
                }
            };
            if recovered.source.contains("__DR_") {
                failures.push(format!(
                    "py{alias}/{}: a placeholder reached the recovered source\n{}",
                    target.label(),
                    recovered.source
                ));
                continue;
            }
            if recovered.stubbed_scopes != 1 || !stub_follows(&recovered.source, target.def_line())
            {
                failures.push(format!(
                    "py{alias}/{}: expected exactly one refusal stub (`{}` then the refusal \
                     docstring and `pass`), stubbed_scopes={}\n{}",
                    target.label(),
                    target.def_line(),
                    recovered.stubbed_scopes,
                    recovered.source
                ));
                continue;
            }
            let recompiled: CodeObject = match recompile(
                &interpreter,
                &recovered.source,
                &scratch,
                &format!("hostile.{alias}.{}", target.path().join(".")),
            ) {
                Ok(code) => code,
                Err(e) => {
                    failures.push(format!(
                        "py{alias}/{}: the partially refused module does not compile: {e}\n{}",
                        target.label(),
                        recovered.source
                    ));
                    continue;
                }
            };
            let tally: ObjectTally = measure_per_object(&original, &recompiled, marshal_version);
            let expected: BTreeSet<String> = BTreeSet::from([target.qualname().to_owned()]);
            if failed_qualnames(&tally) != expected || tally.ok != tally.total.saturating_sub(1) {
                failures.push(format!(
                    "py{alias}/{}: every code object except {} must recompile equal to the \
                     original; {} of {} did, failures {:?}\n{}",
                    target.label(),
                    target.qualname(),
                    tally.ok,
                    tally.total,
                    tally.failures,
                    recovered.source
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} per-code-object fallback failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
