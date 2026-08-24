#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use common::band::find_interpreter;
use disrobe_pass_py_decompile::bytecode::version::PyVersion;
use disrobe_pass_py_decompile::decompile_pyc;
use disrobe_pass_py_decompile::engine::{build_real_source, marshal_to_decompile};
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

const MARKER_PREFIX: &str = "__DR_";

const SPECIAL_NAMES: [&str; 4] = ["__enter__", "__exit__", "__aenter__", "__aexit__"];

const ALL: &[&str] = &["3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15"];
const TABLE_ERA: &[&str] = &["3.11", "3.12", "3.13", "3.14", "3.15"];

#[derive(Debug, Clone, Copy)]
struct WithCase {
    label: &'static str,
    source: &'static str,
    equivalent_on: &'static [&'static str],
    open_reason: &'static str,
}

const CASES: &[WithCase] = &[
    WithCase {
        label: "no_as",
        source: "def f(m):\n    with m():\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "attr_target",
        source: "def f(m, o):\n    with m() as o.x:\n        g()\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "subscript_target",
        source: "def f(m, o):\n    with m() as o[0]:\n        g()\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "slice_target",
        source: "def f(m, o):\n    with m() as o[1:2]:\n        g()\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "tuple_target",
        source: "def f(m):\n    with m() as (a, b):\n        g(a, b)\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "nested_tuple_target",
        source: "def f(m):\n    with m() as (a, (b, c)):\n        g(a, b, c)\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "star_target",
        source: "def f(m):\n    with m() as (a, *b):\n        g(a, b)\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "literal_none",
        source: "def f():\n    with None:\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "paren_multi",
        source: "def f(a, b):\n    with (a(), b()):\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "multi_as",
        source: "def f(a, b):\n    with a() as x, b() as y:\n        g(x, y)\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "nested",
        source: "def f(a, b):\n    with a() as x:\n        with b() as y:\n            g(x, y)\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "body_pass",
        source: "def f(a):\n    with a():\n        pass\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "body_break",
        source: "def f(a, xs):\n    for i in xs:\n        with a():\n            break\n",
        equivalent_on: &[],
        open_reason: "a break out of a with body is the loop and region ownership gap",
    },
    WithCase {
        label: "body_continue",
        source: "def f(a, xs):\n    for i in xs:\n        with a():\n            continue\n",
        equivalent_on: &["3.12", "3.13", "3.14", "3.15"],
        open_reason: "3.9 through 3.11 duplicate the cleanup along the continue edge",
    },
    WithCase {
        label: "body_return",
        source: "def f(a):\n    with a():\n        return 1\n",
        equivalent_on: &["3.9", "3.10"],
        open_reason: "a return inside the body is lifted past the region on the table era",
    },
    WithCase {
        label: "body_raise",
        source: "def f(a):\n    with a():\n        raise ValueError(1)\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "body_yield",
        source: "def f(a):\n    with a():\n        yield 1\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "body_try",
        source: "def f(a):\n    with a():\n        try:\n            g()\n        except OSError:\n            h()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "body_loop",
        source: "def f(a, xs):\n    with a():\n        for i in xs:\n            g(i)\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "with_tail",
        source: "def f(a):\n    with a() as x:\n        g(x)\n    h()\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower with through the block stack, which this lane leaves alone",
    },
    WithCase {
        label: "ctx_name",
        source: "def f(m):\n    with m:\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "ctx_attr",
        source: "def f(m):\n    with m.a.b:\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "ctx_sub",
        source: "def f(m):\n    with m[0]:\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "ctx_or",
        source: "def f(a, b):\n    with (a or b):\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "ctx_and",
        source: "def f(a, b):\n    with (a and b):\n        g()\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "ctx_cond",
        source: "def f(m, n, c):\n    with (m if c else n):\n        g()\n",
        equivalent_on: &[],
        open_reason: "a conditional context expression spans a branch the linear setup walk cannot cross",
    },
    WithCase {
        label: "ctx_walrus",
        source: "def f(m):\n    with (x := m()):\n        g(x)\n",
        equivalent_on: &["3.9", "3.10"],
        open_reason: "a walrus in the context expression splits the setup prologue on the table era",
    },
    WithCase {
        label: "async_with",
        source: "async def f(m):\n    async with m() as x:\n        await g(x)\n",
        equivalent_on: TABLE_ERA,
        open_reason: "3.9 and 3.10 lower async with through the block stack",
    },
    WithCase {
        label: "async_gen",
        source: "async def f(m):\n    async with m() as x:\n        yield x\n",
        equivalent_on: ALL,
        open_reason: "",
    },
    WithCase {
        label: "mixed_nest",
        source: "async def f(a, b):\n    async with a() as x:\n        with b() as y:\n            await g(x, y)\n",
        equivalent_on: &[],
        open_reason: "a sync with nested in an async with is the nested region lane",
    },
];

fn compile_source(interpreter: &Path, source_path: &Path, pyc_path: &Path) -> Result<(), String> {
    let script: &str =
        "import py_compile,sys;py_compile.compile(sys.argv[1],cfile=sys.argv[2],doraise=True)";
    let output: std::process::Output = Command::new(interpreter)
        .args([
            "-c",
            script,
            source_path.to_str().unwrap_or(""),
            pyc_path.to_str().unwrap_or(""),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e: std::io::Error| format!("spawn: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "exit={:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn read_code(pyc_path: &Path) -> Result<(CodeObject, MarshalVersion), String> {
    let bytes: Vec<u8> = fs::read(pyc_path).map_err(|e: std::io::Error| format!("read: {e}"))?;
    let pyc: PycFile = read_pyc(&bytes).map_err(|e| format!("read_pyc: {e}"))?;
    let ver: MarshalVersion = pyc.header.version;
    match pyc.code {
        Object::Code(boxed) => Ok((*boxed, ver)),
        other => Err(format!("top-level not code: {other:?}")),
    }
}

fn special_lookup_leak(recovered: &str) -> Option<String> {
    SPECIAL_NAMES
        .into_iter()
        .find(|name: &&str| recovered.contains(*name))
        .map(str::to_owned)
}

#[test]
fn public_decompile_keeps_the_module_and_names_the_nested_with_refusal() {
    let interpreter: PathBuf = find_interpreter("3.14").expect(
        "CPython 3.14 is required to exercise LOAD_SPECIAL through the public decompile caller",
    );
    let case: &WithCase = CASES
        .iter()
        .find(|case: &&WithCase| case.label == "mixed_nest")
        .expect("the mixed nested with fixture is the LOAD_SPECIAL refusal probe");
    let scratch: PathBuf = PathBuf::from("../../target/py-with-public-refusal");
    fs::create_dir_all(&scratch).expect("scratch");
    let source_path: PathBuf = scratch.join("mixed-nest.py");
    let pyc_path: PathBuf = scratch.join("mixed-nest.pyc");
    fs::write(&source_path, case.source).expect("write fixture");
    compile_source(&interpreter, &source_path, &pyc_path).expect("compile fixture");

    let bytes: Vec<u8> = fs::read(&pyc_path).expect("read fixture");
    let recovered = decompile_pyc(&bytes).expect("the public caller reads the compiled fixture");

    assert!(
        recovered.recovered_directly,
        "the nested failure must remain a function-level refusal, not a module fallback: {:?}",
        recovered.fallback_reason
    );
    assert!(
        recovered.fallback_reason.is_none(),
        "the public caller reported a module refusal instead of retaining the surrounding source"
    );
    assert!(
        recovered.source.contains("async def f(a, b):"),
        "the surrounding function disappeared from the public output:\n{}",
        recovered.source
    );
    assert!(
        recovered.source.contains("decompile-error:"),
        "the nested function must carry a function-level refusal:\n{}",
        recovered.source
    );
    assert!(
        recovered
            .source
            .contains("the with-exit lookup reached linear expression recovery"),
        "the function-level refusal must name the unresolved with-exit role:\n{}",
        recovered.source
    );
    assert!(
        !recovered.source.contains(MARKER_PREFIX),
        "the public output must not carry an internal marker:\n{}",
        recovered.source
    );
}

#[test]
fn with_regions_never_emit_a_plausible_placeholder() {
    let scratch: PathBuf = PathBuf::from("../../target/py-with-input-space");
    fs::create_dir_all(&scratch).expect("scratch");

    let mut graded: usize = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut skipped: Vec<&str> = Vec::new();

    for &alias in ALL {
        let Some(interpreter): Option<PathBuf> = find_interpreter(alias) else {
            skipped.push(alias);
            continue;
        };
        for case in CASES {
            let label: &str = case.label;
            let source_path: PathBuf = scratch.join(format!("{label}.{alias}.py"));
            fs::write(&source_path, case.source).expect("write fixture");
            let orig_pyc: PathBuf = scratch.join(format!("{label}.{alias}.pyc"));
            if let Err(e) = compile_source(&interpreter, &source_path, &orig_pyc) {
                assert!(
                    !case.equivalent_on.contains(&alias),
                    "py{alias}/{label} is pinned equivalent but CPython rejects the fixture: {e}"
                );
                continue;
            }
            let (original, marshal_version): (CodeObject, MarshalVersion) =
                read_code(&orig_pyc).unwrap_or_else(|e| panic!("py{alias}/{label} read: {e}"));
            let version: PyVersion = marshal_to_decompile(marshal_version)
                .unwrap_or_else(|e| panic!("py{alias}/{label} version map: {e:?}"));
            let recovered: String = match build_real_source(&original, &version, marshal_version) {
                Ok(source) => source,
                Err(refusal) => {
                    graded += 1;
                    if case.equivalent_on.contains(&alias) {
                        failures.push(format!(
                            "py{alias}/{label}: pinned equivalent and instead refused: {refusal}"
                        ));
                    }
                    continue;
                }
            };

            graded += 1;

            let source_has_none_manager: bool = case.source.contains("with None");
            if !source_has_none_manager && recovered.contains("with None") {
                failures.push(format!(
                    "py{alias}/{label}: a context manager the builder could not resolve was \
                     rendered as the literal None, which reads as real source\n{recovered}"
                ));
            }
            if recovered.contains("__exit__(None, None, None)") {
                failures.push(format!(
                    "py{alias}/{label}: the with cleanup call leaked into recovered \
                     source\n{recovered}"
                ));
            }
            if let Some(name) = special_lookup_leak(&recovered) {
                failures.push(format!(
                    "py{alias}/{label}: the {name} lookup reached recovered source, where it \
                     reads as ordinary attribute access the program never wrote. A with region \
                     that cannot be structured is refused, not rendered\n{recovered}"
                ));
            }
            if recovered.contains(MARKER_PREFIX) {
                failures.push(format!(
                    "py{alias}/{label}: an internal reconstruction placeholder reached recovered \
                     source, which a caller may read, save or feed to a tool\n{recovered}"
                ));
            }

            let recovered_path: PathBuf = scratch.join(format!("{label}.rec.{alias}.py"));
            fs::write(&recovered_path, &recovered).expect("write recovered");
            let recompiled_pyc: PathBuf = scratch.join(format!("{label}.rec.{alias}.pyc"));
            let parses: bool =
                compile_source(&interpreter, &recovered_path, &recompiled_pyc).is_ok();
            let equivalent: bool = parses
                && read_code(&recompiled_pyc).is_ok_and(|(recompiled, _)| {
                    matches!(
                        semantic_equiv(&original, &recompiled, marshal_version),
                        Verdict::Perfect | Verdict::Semantic
                    )
                });

            if case.equivalent_on.contains(&alias) && !equivalent {
                failures.push(format!(
                    "py{alias}/{label}: pinned equivalent and is not\n{recovered}"
                ));
            }
            if !case.equivalent_on.contains(&alias) {
                assert!(
                    !case.open_reason.is_empty(),
                    "py{alias}/{label} is not pinned equivalent and states no reason"
                );
            }
        }
    }

    if !skipped.is_empty() {
        println!("NOT MEASURED on {skipped:?}: `uv python install <version>` resolves them");
    }
    assert!(
        graded > 0,
        "no CPython 3.9 through 3.15 interpreter resolved, so this case graded nothing"
    );
    assert!(
        failures.is_empty(),
        "{} with-region failures:\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
