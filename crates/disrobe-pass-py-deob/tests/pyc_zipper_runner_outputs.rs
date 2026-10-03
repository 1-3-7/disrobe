#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use disrobe_core::scratch::ScratchDir;
use disrobe_pass_py_deob::obfuscators::{DetectReport, PeelOutcome, Quality};
use disrobe_pass_py_deob::{ObfuscatorPass, PycZipperPass, recover_pyc_zipper};
use disrobe_py_marshal::{CodeObject, Object, PycFile, read_pyc, write_pyc};
use disrobe_testkit::{CommandSpec, ToolOutput, tool_output};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const RECORDS_SCHEMA: &str = "disrobe.real-tool-outputs/v1";
const RUNNER_OUTPUTS: usize = 30;
const CPYTHON_312_MAGIC: [u8; 4] = [0xcb, 0x0d, 0x0d, 0x0a];
const PYTHON_TIMEOUT: Duration = Duration::from_mins(1);

const NOT_REEXECUTING: &[&str] = &[
    "generators_yield_from.bz2.pyc",
    "generators_yield_from.lzma.pyc",
    "generators_yield_from.obfuscate.pyc",
    "generators_yield_from.obfuscate_lzma.pyc",
    "generators_yield_from.zlib.pyc",
];

const BEHAVIOUR_DRIVER: &str = r"
import sys

program, path = sys.argv[1], sys.argv[2]
ns = {'__name__': 'pyc_zipper_graded'}
exec(compile(open(path, encoding='utf-8').read(), path, 'exec'), ns)

def attempt(label, thunk):
    try:
        print(label, repr(thunk()))
    except Exception as error:
        print(label, type(error).__name__, error)

def sample():
    print('greet', ns['greet']('zed'))
    print('main', ns['main']())

def bank_account_ledger():
    account, insufficient = ns['Account'], ns['InsufficientFunds']
    a, b = account('ann', '50'), account('bob')
    print(a.number - b.number, a.deposit('25.10'), a.withdraw('80'), a.withdraw('70'))
    attempt('overdraw', lambda: a.withdraw('500'))
    attempt('negative', lambda: b.deposit('-1'))
    print(issubclass(insufficient, Exception))
    print(ns['transfer'](a, b, '10'), ns['transfer'](a, b, '1000'))
    print(a.statement())
    print(b.statement())

def closures_nonlocal_global():
    advance, reset = ns['counter'](5, 2)
    print(advance(), advance())
    reset()
    print(advance())
    print([ns['track'](name) for name in 'abc'])
    print([f(3) for f in ns['make_multipliers'](4)])
    add, snapshot = ns['accumulator']()
    add(3)
    add(4)
    print(snapshot())
    calls = []
    def square(n):
        calls.append(n)
        return n * n
    cached = ns['memoize'](square)
    print(cached(4), cached(4), cached(5), calls, sorted(cached.cache.items()))
    print(ns['outer_chain'](2)(3)(4))
    ns['reset_globals']()
    print(ns['track']('z'))

def class_inheritance_super():
    build = ns['build']
    shapes = [build('rectangle', 2, 3), build('square', 4), build('triangle', 3, 5), build('labelledsquare', 2)]
    for shape in shapes:
        print(type(shape).__name__, shape.describe())
    print(ns['total_area'](shapes + [object()]))
    print(sorted(ns['Shape'].registry))
    attempt('abstract', lambda: ns['Shape']('blob').area())

def generators_yield_from():
    print(list(ns['countdown'](4)))
    print(list(ns['chunks'](range(7), 3)))
    print(list(ns['flatten']([1, [2, (3, [4])], 5])))
    results = []
    delegate = ns['delegate'](results)
    print(next(delegate), [delegate.send(v) for v in (10, 20, None, 5, None)], results)
    print(list(ns['pairs']([1, 2, 3], [4])))
    print(ns['take'](ns['countdown'](10), 3))
    guarded = ns['guarded']([1, 2])
    print(next(guarded), next(guarded), list(guarded))
    closing = ns['guarded']([1, 2, 3])
    next(closing)
    attempt('close', closing.close)

def expression_evaluator():
    for text in ('1 + 2 * 3', '(1 + 2) * 3', '2 ^ 3 ^ 2', '10 % 4 - 7 / 2', '1 / 0', '2 $ 3', ''):
        attempt(text, lambda: ns['evaluate'](text))
    print(ns['to_postfix'](ns['split_tokens']('3 + 4 * 2 / (1 - 5)')))

globals()[program]()
";

const CODE_ORACLE: &str = r#"
import sys, marshal, dis, io, re, types

ADDR = re.compile(r' at 0x[0-9A-Fa-f]+')

def code_of(path):
    raw = open(path, 'rb').read()
    return marshal.loads(raw[16:])

def listing(co):
    out = io.StringIO()
    dis.dis(co, file=out)
    return ADDR.sub(' at 0x', out.getvalue())

def defined(co):
    return {c.co_qualname.rsplit('.', 1)[-1] for c in co.co_consts if isinstance(c, types.CodeType)}

STRICT = ('co_code', 'co_exceptiontable', 'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount',
          'co_flags', 'co_stacksize', 'co_nlocals', 'co_qualname', 'co_name')

def compare(rec, ref, where, module_defs, enclosing_defs, tally):
    for field in STRICT:
        if getattr(rec, field) != getattr(ref, field):
            return f'{where}: {field} {getattr(rec, field)!r} != {getattr(ref, field)!r}'
    own_defs = defined(ref)
    unrecoverable = {
        'co_names': (r'g\d+', module_defs),
        'co_varnames': (r'l\d+', own_defs),
        'co_cellvars': (r'l\d+', own_defs),
        'co_freevars': (r'l\d+', enclosing_defs),
    }
    for field, (pattern, defs) in unrecoverable.items():
        got, want = getattr(rec, field), getattr(ref, field)
        if len(got) != len(want):
            return f'{where}: {field} {got!r} != {want!r}'
        for a, b in zip(got, want):
            if a == b:
                tally['kept'] += 1
            elif re.fullmatch(pattern, a) and b not in defs:
                tally['placeholder'] += 1
            else:
                return f'{where}: {field} holds {a!r} where the source has {b!r}'
    if len(rec.co_consts) != len(ref.co_consts):
        return f'{where}: {len(rec.co_consts)} constants != {len(ref.co_consts)}'
    for index, (a, b) in enumerate(zip(rec.co_consts, ref.co_consts)):
        if isinstance(a, types.CodeType) and isinstance(b, types.CodeType):
            error = compare(a, b, f'{where}/{b.co_qualname}', module_defs, enclosing_defs | own_defs, tally)
            if error:
                return error
        elif type(a) is not type(b) or repr(a) != repr(b):
            return f'{where}: co_consts[{index}] {a!r} != {b!r}'
    return None

mode, recovered_path, source_path, filename = sys.argv[1:5]
recovered = code_of(recovered_path)
reference = compile(open(source_path, encoding='utf-8').read(), filename, 'exec')
if mode == 'exact':
    got, want = listing(recovered), listing(reference)
    if got == want:
        print('EQUAL')
    else:
        for index, (a, b) in enumerate(zip(got.splitlines(), want.splitlines())):
            if a != b:
                print(f'MISMATCH line {index}: {a!r} != {b!r}')
                break
        else:
            print('MISMATCH length')
else:
    tally = {'kept': 0, 'placeholder': 0}
    error = compare(recovered, reference, '<module>', defined(reference), set(), tally)
    print(f'MISMATCH {error}' if error else f"EQUAL kept={tally['kept']} placeholder={tally['placeholder']}")
"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Records {
    schema: String,
    tool: String,
    tool_url: String,
    tool_version: String,
    runtime: String,
    recipe: String,
    repository_commit: String,
    runner_image: String,
    workflow_run: String,
    output: Vec<RunnerOutput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunnerOutput {
    path: String,
    sha256: String,
    bytes: u64,
    input: String,
    input_sha256: String,
    command: String,
    behaviour: String,
    runner_difference: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Zlib,
    Bz2,
    Lzma,
    Obfuscate,
    ObfuscateLzma,
}

impl Mode {
    fn of(path: &str) -> Self {
        let label: &str = path
            .strip_suffix(".pyc")
            .and_then(|stem: &str| stem.rsplit_once('.'))
            .map_or_else(
                || panic!("{path} does not name its pyc-zipper mode"),
                |(_, label): (&str, &str)| label,
            );
        match label {
            "zlib" => Self::Zlib,
            "bz2" => Self::Bz2,
            "lzma" => Self::Lzma,
            "obfuscate" => Self::Obfuscate,
            "obfuscate_lzma" => Self::ObfuscateLzma,
            other => panic!("{path} names the unknown pyc-zipper mode {other}"),
        }
    }

    const fn compressor(self) -> Option<&'static str> {
        match self {
            Self::Zlib => Some("zlib"),
            Self::Bz2 => Some("bz2"),
            Self::Lzma | Self::ObfuscateLzma => Some("lzma"),
            Self::Obfuscate => None,
        }
    }

    const fn obfuscated(self) -> bool {
        matches!(self, Self::Obfuscate | Self::ObfuscateLzma)
    }

    const fn loader_imports_zlib_only(self) -> bool {
        matches!(self, Self::Zlib | Self::Obfuscate)
    }
}

struct Fixture {
    record: RunnerOutput,
    bytes: Vec<u8>,
    mode: Mode,
}

impl Fixture {
    fn input_path(&self) -> PathBuf {
        repo_root().join(&self.record.input)
    }

    fn program(&self) -> String {
        self.compile_filename().strip_suffix(".py").map_or_else(
            || panic!("{} is not a .py source", self.record.input),
            str::to_owned,
        )
    }

    fn compile_filename(&self) -> String {
        Path::new(&self.record.input)
            .file_name()
            .and_then(|name: &std::ffi::OsStr| name.to_str())
            .map_or_else(
                || panic!("{} has no file name", self.record.input),
                str::to_owned,
            )
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn fixture_dir() -> PathBuf {
    repo_root()
        .join("corpus")
        .join("python")
        .join("pyc_zipper")
        .join("real")
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn load_records() -> Records {
    let path: PathBuf = fixture_dir().join("records.toml");
    let text: String = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{} is unreadable ({e}); restore it with git checkout",
            path.display()
        )
    });
    toml::from_str(&text).unwrap_or_else(|e| panic!("{} does not parse: {e}", path.display()))
}

fn fixtures() -> Vec<Fixture> {
    load_records()
        .output
        .into_iter()
        .map(|record: RunnerOutput| {
            let path: PathBuf = fixture_dir().join(&record.path);
            let bytes: Vec<u8> = std::fs::read(&path).unwrap_or_else(|e| {
                panic!(
                    "the runner output {} is unreadable ({e}); restore it with git checkout",
                    path.display()
                )
            });
            assert_eq!(
                sha256_hex(&bytes),
                record.sha256,
                "{} differs from the bytes the runner recorded; refusing to grade it",
                record.path
            );
            let mode: Mode = Mode::of(&record.path);
            Fixture {
                record,
                bytes,
                mode,
            }
        })
        .collect()
}

fn python_312() -> PathBuf {
    common::require_python_312()
}

fn run_python(python: &Path, script: &Path, args: &[&Path]) -> ToolOutput {
    let mut spec: CommandSpec = CommandSpec::new(python, PYTHON_TIMEOUT)
        .arg("-X")
        .arg("utf8")
        .arg(script)
        .current_dir(repo_root())
        .env("PYTHONHASHSEED", "0")
        .env("PYTHONDONTWRITEBYTECODE", "1");
    for arg in args {
        spec = spec.arg(*arg);
    }
    tool_output(spec).unwrap_or_else(|e| panic!("running {} failed: {e}", script.display()))
}

fn code_oracle(python: &Path, mode: &str, recovered_pyc: &[u8], fixture: &Fixture) -> String {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pycz_real").expect("scratch dir");
    let recovered_path: PathBuf = scratch.path().join("recovered.pyc");
    let oracle_path: PathBuf = scratch.path().join("code_oracle.py");
    std::fs::write(&recovered_path, recovered_pyc).expect("write recovered pyc");
    std::fs::write(&oracle_path, CODE_ORACLE).expect("write oracle");
    let filename: PathBuf = PathBuf::from(fixture.compile_filename());
    let mode_arg: PathBuf = PathBuf::from(mode);
    let output: ToolOutput = run_python(
        python,
        &oracle_path,
        &[
            mode_arg.as_path(),
            recovered_path.as_path(),
            fixture.input_path().as_path(),
            filename.as_path(),
        ],
    );
    assert!(
        output.success,
        "the code oracle failed on {}: {}\n{}",
        fixture.record.path,
        output.stdout_text(),
        output.stderr_text()
    );
    output.stdout_text().trim().to_owned()
}

fn drive(python: &Path, fixture: &Fixture, source: &Path) -> (bool, String) {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pycz_driver").expect("scratch dir");
    let driver_path: PathBuf = scratch.path().join("driver.py");
    std::fs::write(&driver_path, BEHAVIOUR_DRIVER).expect("write driver");
    let program: PathBuf = PathBuf::from(fixture.program());
    let output: ToolOutput = run_python(python, &driver_path, &[program.as_path(), source]);
    (output.success, output.stdout_text())
}

fn reexecutes_like_original(python: &Path, fixture: &Fixture, recovered_source: &str) -> bool {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pycz_reexec").expect("scratch dir");
    let recovered_path: PathBuf = scratch.path().join(fixture.compile_filename());
    std::fs::write(&recovered_path, recovered_source).expect("write recovered source");
    let expected: (bool, String) = drive(python, fixture, &fixture.input_path());
    assert!(
        expected.0 && expected.1.lines().count() >= 3,
        "the behaviour driver must run the authored program {} cleanly under CPython 3.12 and print its results: {}",
        fixture.record.input,
        expected.1
    );
    drive(python, fixture, &recovered_path) == expected
}

fn mutate_first_literal(code: &mut CodeObject) -> bool {
    for konst in &mut code.consts {
        match konst {
            Object::Code(inner) => {
                if mutate_first_literal(inner) {
                    return true;
                }
            }
            Object::Int(value) => {
                *value = value.wrapping_add(1);
                return true;
            }
            Object::ShortAscii { value, .. }
            | Object::Unicode { value, .. }
            | Object::String { value, .. }
                if !value.is_empty() =>
            {
                value.insert(0, '#');
                return true;
            }
            _ => {}
        }
    }
    false
}

fn with_mutated_literal(pyc: &[u8]) -> Vec<u8> {
    let mut file: PycFile = read_pyc(pyc).expect("recovered pyc parses");
    let Object::Code(code) = &mut file.code else {
        panic!("recovered pyc holds no code object");
    };
    assert!(mutate_first_literal(code), "no literal to mutate");
    write_pyc(&file).expect("mutated pyc writes")
}

fn compiler_generated_deep_scope(python: &Path) -> CodeObject {
    let scratch: ScratchDir = ScratchDir::create("disrobe_pycz_depth").expect("scratch dir");
    let source_path: PathBuf = scratch.path().join("deep_scope.py");
    let pyc_path: PathBuf = scratch.path().join("deep_scope.pyc");
    let source: String = format!("deep = {}0\n", "lambda: ".repeat(65));
    std::fs::write(&source_path, source).expect("write authored deep-scope source");
    let script_path: PathBuf = scratch.path().join("compile.py");
    std::fs::write(
        &script_path,
        "import py_compile, sys\nfrom pathlib import Path\nsource, output = sys.argv[1:]\ncompile(Path(source).read_text(encoding='utf-8'), source, 'exec')\npy_compile.compile(source, cfile=output, doraise=True)\n",
    )
    .expect("write compiler oracle");
    let output: ToolOutput = run_python(python, &script_path, &[&source_path, &pyc_path]);
    assert!(
        output.success,
        "CPython must compile the authored deep-scope fixture: {}\n{}",
        output.stdout_text(),
        output.stderr_text()
    );
    let file: PycFile = read_pyc(&std::fs::read(&pyc_path).expect("read compiler pyc"))
        .expect("compiler pyc parses");
    let Object::Code(code) = file.code else {
        panic!("compiler pyc holds no code object");
    };
    *code
}

#[test]
fn records_pin_every_runner_output_and_its_input() {
    let records: Records = load_records();
    assert_eq!(records.schema, RECORDS_SCHEMA);
    assert_eq!(records.tool, "pyc-zipper");
    assert!(
        records
            .tool_url
            .starts_with("https://pypi.org/project/pyc-zipper/")
    );
    assert!(records.tool_version.contains("pyc-zipper 1.0.8"));
    assert!(records.runtime.starts_with("Python 3.12."));
    assert!(repo_root().join(&records.recipe).is_file());
    assert_eq!(records.repository_commit.len(), 40);
    assert!(!records.runner_image.is_empty());
    assert!(records.workflow_run.starts_with("https://github.com/"));

    let fixtures: Vec<Fixture> = fixtures();
    assert_eq!(fixtures.len(), RUNNER_OUTPUTS);
    let recorded: BTreeSet<String> = fixtures
        .iter()
        .map(|f: &Fixture| f.record.path.clone())
        .collect();
    let on_disk: BTreeSet<String> = std::fs::read_dir(fixture_dir())
        .expect("list fixture dir")
        .map(|entry: std::io::Result<std::fs::DirEntry>| {
            entry
                .expect("dir entry")
                .file_name()
                .into_string()
                .expect("utf-8 name")
        })
        .filter(|name: &String| name != "records.toml")
        .collect();
    assert_eq!(
        on_disk, recorded,
        "every file beside records.toml must be a recorded runner output"
    );
    for fixture in &fixtures {
        let record: &RunnerOutput = &fixture.record;
        assert_eq!(fixture.bytes.len() as u64, record.bytes, "{}", record.path);
        assert_eq!(
            fixture.bytes.get(..4),
            Some(CPYTHON_312_MAGIC.as_slice()),
            "{} is not a CPython 3.12 pyc",
            record.path
        );
        let input: Vec<u8> = std::fs::read(fixture.input_path())
            .unwrap_or_else(|e| panic!("input {} unreadable: {e}", record.input));
        assert_eq!(
            sha256_hex(&input),
            record.input_sha256,
            "{} changed since the runner obfuscated it, so it no longer grades {}",
            record.input,
            record.path
        );
        assert!(record.command.starts_with("pyc-zipper "));
        let expected_behaviour: &str = if fixture.mode.loader_imports_zlib_only() {
            "same"
        } else {
            "differs"
        };
        assert_eq!(record.behaviour, expected_behaviour, "{}", record.path);
        assert_eq!(
            record.runner_difference.is_some(),
            record.behaviour == "differs",
            "{}",
            record.path
        );
    }
}

#[test]
fn every_runner_output_is_detected_with_its_layers() {
    for fixture in fixtures() {
        let report: DetectReport = PycZipperPass.detect(&fixture.bytes);
        assert!(
            report.matched,
            "{} not detected: {report:?}",
            fixture.record.path
        );
        let expected: String = fixture.mode.compressor().map_or_else(
            || "pyc-obfuscation".to_owned(),
            |c: &str| format!("{c}-decompress"),
        );
        assert!(
            report.markers.contains(&expected),
            "{} lacks marker {expected}: {report:?}",
            fixture.record.path
        );
        let outcome: PeelOutcome = PycZipperPass
            .peel(&fixture.bytes)
            .unwrap_or_else(|e| panic!("{} peel failed: {e:?}", fixture.record.path));
        let stages: &[String] = &outcome.stages_applied;
        assert_eq!(
            stages.iter().any(|s: &String| s == "restore-def-names"),
            fixture.mode.obfuscated(),
            "{} stages {stages:?}",
            fixture.record.path
        );
        if let Some(compressor) = fixture.mode.compressor() {
            assert!(
                stages.iter().any(|s: &String| s == compressor),
                "{} stages {stages:?}",
                fixture.record.path
            );
        }
        if fixture.mode.obfuscated() {
            assert_eq!(outcome.quality, Quality::Partial, "{}", fixture.record.path);
            assert!(
                outcome
                    .lossy_notes
                    .iter()
                    .any(|note: &String| note.contains("line table")),
                "{} must report the deleted line table: {:?}",
                fixture.record.path,
                outcome.lossy_notes
            );
        }
    }
}

#[test]
fn deep_compiler_scope_reports_the_reverse_depth_limit() {
    let python: PathBuf = python_312();
    let fixture: Fixture = fixtures()
        .into_iter()
        .find(|fixture: &Fixture| fixture.record.path == "sample.obfuscate.pyc")
        .expect("recorded direct pyc-zipper obfuscation fixture");
    let baseline: PeelOutcome = PycZipperPass
        .peel(&fixture.bytes)
        .unwrap_or_else(|error| panic!("{} peel failed: {error:?}", fixture.record.path));
    assert_eq!(
        baseline
            .diagnostics
            .get("reverse_depth_limited")
            .map(String::as_str)
            .unwrap_or("false"),
        "false",
        "the unmodified real-tool fixture must not exhaust the nested-code budget"
    );

    let mut file: PycFile = read_pyc(&fixture.bytes).expect("recorded pyc parses");
    let Object::Code(code) = &mut file.code else {
        panic!("recorded pyc holds no code object");
    };
    code.consts
        .push(Object::Code(Box::new(compiler_generated_deep_scope(
            &python,
        ))));
    let mutated: Vec<u8> = write_pyc(&file).expect("mutated pyc writes");
    let outcome: PeelOutcome = PycZipperPass
        .peel(&mutated)
        .expect("deep-scope mutation must remain a readable pyc-zipper input");

    assert_eq!(outcome.quality, Quality::Partial);
    assert_eq!(
        outcome
            .diagnostics
            .get("reverse_depth_limited")
            .map(String::as_str),
        Some("true")
    );
    assert!(
        outcome
            .lossy_notes
            .iter()
            .any(|note: &String| note.contains("nested-code depth limit")),
        "depth-limited reversal needs an explicit partial-recovery reason: {:?}",
        outcome.lossy_notes
    );
}

#[test]
fn compressed_outputs_unpack_to_the_cpython_312_compile_of_their_source() {
    let python: PathBuf = python_312();
    let mut graded: usize = 0;
    for fixture in fixtures()
        .iter()
        .filter(|f: &&Fixture| !f.mode.obfuscated())
    {
        let recovered: Vec<u8> = recover_pyc_zipper(&fixture.bytes)
            .unwrap_or_else(|e| panic!("{} recover failed: {e:?}", fixture.record.path));
        let verdict: String = code_oracle(&python, "exact", &recovered, fixture);
        assert_eq!(verdict, "EQUAL", "{}", fixture.record.path);
        graded += 1;
    }
    assert_eq!(graded, 18);
}

#[test]
fn obfuscated_outputs_match_their_source_except_unrecoverable_names() {
    let python: PathBuf = python_312();
    let mut graded: usize = 0;
    for fixture in fixtures().iter().filter(|f: &&Fixture| f.mode.obfuscated()) {
        let recovered: Vec<u8> = recover_pyc_zipper(&fixture.bytes)
            .unwrap_or_else(|e| panic!("{} recover failed: {e:?}", fixture.record.path));
        let verdict: String = code_oracle(&python, "names", &recovered, fixture);
        assert!(
            verdict.starts_with("EQUAL kept="),
            "{}: {verdict}",
            fixture.record.path
        );
        graded += 1;
    }
    assert_eq!(graded, 12);
}

#[test]
fn recovered_source_reexecutes_like_the_original_under_cpython_312() {
    let python: PathBuf = python_312();
    let mut failing: BTreeSet<String> = BTreeSet::new();
    for fixture in fixtures() {
        let outcome: PeelOutcome = PycZipperPass
            .peel(&fixture.bytes)
            .unwrap_or_else(|e| panic!("{} peel failed: {e:?}", fixture.record.path));
        if !reexecutes_like_original(&python, &fixture, &outcome.recovered_source) {
            failing.insert(fixture.record.path.clone());
        }
    }
    let pinned: BTreeSet<String> = NOT_REEXECUTING
        .iter()
        .map(|name: &&str| (*name).to_owned())
        .collect();
    assert_eq!(
        failing, pinned,
        "NOT_REEXECUTING only shrinks: remove a fixture once its recovered source prints what the original prints, and never add one"
    );
}

#[test]
fn mutation_controls_turn_each_grader_red() {
    let python: PathBuf = python_312();
    let all: Vec<Fixture> = fixtures();
    let pick = |path: &str| -> &Fixture {
        all.iter()
            .find(|f: &&Fixture| f.record.path == path)
            .unwrap_or_else(|| panic!("{path} missing"))
    };

    let zlib: &Fixture = pick("sample.zlib.pyc");
    let recovered: Vec<u8> = recover_pyc_zipper(&zlib.bytes).expect("recover zlib");
    assert_eq!(code_oracle(&python, "exact", &recovered, zlib), "EQUAL");
    let mutated: Vec<u8> = with_mutated_literal(&recovered);
    assert!(
        code_oracle(&python, "exact", &mutated, zlib).starts_with("MISMATCH"),
        "the exact oracle must reject a changed literal"
    );

    let obfuscated: &Fixture = pick("closures_nonlocal_global.obfuscate.pyc");
    assert!(
        code_oracle(&python, "names", &obfuscated.bytes, obfuscated).starts_with("MISMATCH"),
        "the names oracle must reject the tool output before disrobe strips its dead return and restores def names"
    );
    let recovered: Vec<u8> = recover_pyc_zipper(&obfuscated.bytes).expect("recover obfuscated");
    assert!(code_oracle(&python, "names", &recovered, obfuscated).starts_with("EQUAL"));
    let mutated: Vec<u8> = with_mutated_literal(&recovered);
    assert!(
        code_oracle(&python, "names", &mutated, obfuscated).starts_with("MISMATCH"),
        "the names oracle must reject a changed literal"
    );

    let outcome: PeelOutcome = PycZipperPass.peel(&zlib.bytes).expect("peel zlib");
    assert!(reexecutes_like_original(
        &python,
        zlib,
        &outcome.recovered_source
    ));
    let broken: String = outcome.recovered_source.replacen("hello, ", "hullo, ", 1);
    assert_ne!(
        broken, outcome.recovered_source,
        "the sample prints hello, "
    );
    assert!(
        !reexecutes_like_original(&python, zlib, &broken),
        "the re-execution grader must reject a changed literal"
    );
}

#[test]
fn compiler_output_is_never_claimed_as_pyc_zipper() {
    let compiled: PathBuf = repo_root()
        .join("corpus")
        .join("python")
        .join("decompile")
        .join("authored")
        .join("compiled");
    let mut checked: usize = 0;
    for entry in std::fs::read_dir(&compiled).expect("list compiled authored pycs") {
        let path: PathBuf = entry.expect("dir entry").path();
        if path.extension().and_then(|e: &std::ffi::OsStr| e.to_str()) != Some("pyc") {
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(&path).expect("read compiled pyc");
        let report: DetectReport = PycZipperPass.detect(&bytes);
        assert!(
            !report.matched,
            "{} is plain CPython output but was claimed as pyc-zipper: {report:?}",
            path.display()
        );
        assert!(PycZipperPass.peel(&bytes).is_err(), "{}", path.display());
        checked += 1;
    }
    assert!(checked >= 200, "only {checked} compiled pycs were checked");
}
