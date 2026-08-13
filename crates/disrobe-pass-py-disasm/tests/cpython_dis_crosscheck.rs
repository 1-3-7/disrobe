#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_disasm::{Instruction, disassemble};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, read_pyc};

const CORPUS_PY3: &str = r#"
from os import *

GLOBAL_X = range(10)


def comparisons(a, b):
    p = a is b
    q = a is not None
    r = a in (1, 2, 3)
    s = a not in {4, 5}
    t = a < b
    u = a >= b
    return p and q and r and s and t and u


def control_flow(n):
    total = 0
    for i in range(n):
        if i % 2 == 0:
            total += i
        elif i > 5:
            total -= i
        else:
            continue
    while total > 100:
        total //= 2
    return total


def comprehensions(items):
    a = [x * 2 for x in items if x > 0]
    b = {k: len(k) for k in items}
    c = {y for y in items}
    return a, b, c


def guarded(values):
    acc = 0
    for v in values:
        try:
            acc += int(v)
        except ValueError:
            acc -= 1
        finally:
            acc += 0
    return acc


def formatting(value, width):
    return f"{value!r:>{width}}"


def with_defaults(a, b=10, *args, **kwargs):
    return a + b


class Widget:
    kind = "default"

    def __init__(self, name):
        self.name = name

    def render(self):
        return self.name.upper()


def complex_constants():
    return (2j, 3 - 4j, 0j, complex(0.0, -0.0), 2.5 + 0j, 0.5 + 0.25j)


def main():
    w = Widget("box")
    return comparisons(1, 2), control_flow(20), comprehensions([1, 2]), w.render()


def closure_maker(seed):
    accumulated = seed * 2

    def bump(step):
        nonlocal accumulated
        accumulated += step
        return accumulated + seed

    def dropper():
        nonlocal accumulated
        accumulated = 0
        del accumulated

    class Recorder:
        tag = seed
        span = accumulated

        def read(self):
            return seed + accumulated

    return bump, dropper, Recorder


def three_level(alpha):
    def middle(beta):
        combined = alpha + beta

        def inner(gamma):
            return alpha + combined + gamma

        return inner, combined

    return middle


def wide_expression(alpha, beta, gamma, delta, epsilon, zeta, eta, theta):
    narrow = alpha + beta
    medium = (alpha + beta) * (gamma - delta) + (epsilon * zeta) - eta
    wide = (alpha + beta) * (gamma - delta) + (epsilon * zeta) - (eta / theta) + (alpha * gamma) - (beta * delta) + (epsilon - zeta)
    return narrow, medium, wide


class BaseUnit:
    def label(self, value):
        return ("base", value)


class DerivedUnit(BaseUnit):
    def label(self, value):
        return super().label(value) + super(DerivedUnit, self).label(value)
"#;

const CORPUS_PY2: &str = r"
GLOBAL_X = range(10)


def comparisons(a, b):
    p = a is b
    q = a is not None
    r = a in (1, 2, 3)
    t = a < b
    return p and q and r and t


def control_flow(n):
    total = 0
    for i in range(n):
        if i == 0:
            total += i
        else:
            continue
    while total > 100:
        total = total / 2
    return total


class Widget:
    def render(self):
        return self.name


def closure_maker(seed):
    accumulated = seed * 2

    def bump(step):
        return accumulated + seed + step

    return bump


def three_level(alpha):
    def middle(beta):
        combined = alpha + beta

        def inner(gamma):
            return alpha + combined + gamma

        return inner, combined

    return middle
";

const DUMPER: &str = r#"
import dis
import json
import marshal
import struct
import sys


def write_pyc(code, path):
    data = marshal.dumps(code)
    with open(path, "wb") as handle:
        try:
            import importlib.util as ilu
            magic = ilu.MAGIC_NUMBER
        except Exception:
            magic = struct.pack("<H", 62211) + b"\r\n"
        handle.write(magic)
        info = sys.version_info
        if info[0] > 3 or (info[0] == 3 and info[1] >= 7):
            handle.write(struct.pack("<I", 0))
        handle.write(struct.pack("<I", 0))
        if info[0] > 3 or (info[0] == 3 and info[1] >= 3):
            handle.write(struct.pack("<I", len(data) & 0xFFFFFFFF))
        handle.write(data)


def walk(code, path):
    result = [(path, code)]
    index = 0
    for const in code.co_consts:
        if hasattr(const, "co_code"):
            child = "%s/%s#%d" % (path, getattr(const, "co_name", index), index)
            result.extend(walk(const, child))
        index += 1
    return result


def normalize_line(ins):
    starts = getattr(ins, "starts_line", None)
    if isinstance(starts, bool):
        return getattr(ins, "line_number", None) if starts else None
    return starts


def modern_block(code):
    items = []
    for ins in dis.get_instructions(code):
        items.append(
            {
                "offset": ins.offset,
                "opname": ins.opname,
                "arg": ins.arg,
                "argrepr": ins.argrepr,
                "starts_line": normalize_line(ins),
                "is_jump_target": ins.is_jump_target,
            }
        )
    return items


def legacy_block(code):
    have_argument = dis.HAVE_ARGUMENT
    extended_arg = dis.EXTENDED_ARG
    hasjrel = set(dis.hasjrel)
    hasjabs = set(dis.hasjabs)
    hasname = set(dis.hasname)
    haslocal = set(dis.haslocal)
    hasconst = set(dis.hasconst)
    hascompare = set(dis.hascompare)
    blob = code.co_code
    size = len(blob)
    starts = dict(dis.findlinestarts(code))
    targets = set()
    i = 0
    extended = 0
    while i < size:
        op = ord(blob[i])
        nxt = i + 1
        if op >= have_argument:
            arg = ord(blob[i + 1]) + ord(blob[i + 2]) * 256 + extended
            nxt = i + 3
            extended = arg * 65536 if op == extended_arg else 0
            if op in hasjrel:
                targets.add(nxt + (arg & 0xFFFF))
            elif op in hasjabs:
                targets.add(arg & 0xFFFF)
        i = nxt
    items = []
    i = 0
    extended = 0
    last_line = None
    while i < size:
        op = ord(blob[i])
        offset = i
        name = dis.opname[op]
        arg = None
        argrepr = ""
        nxt = i + 1
        if op >= have_argument:
            raw = ord(blob[i + 1]) + ord(blob[i + 2]) * 256
            arg = raw + extended
            nxt = i + 3
            extended = arg * 65536 if op == extended_arg else 0
            if op in hasconst:
                argrepr = repr(code.co_consts[arg])
            elif op in hasname:
                argrepr = code.co_names[arg]
            elif op in haslocal:
                argrepr = code.co_varnames[arg]
            elif op in hascompare:
                argrepr = dis.cmp_op[arg]
        line = starts.get(offset)
        mark = None
        if line is not None and line != last_line:
            mark = line
            last_line = line
        items.append(
            {
                "offset": offset,
                "opname": name,
                "arg": arg,
                "argrepr": argrepr,
                "starts_line": mark,
                "is_jump_target": offset in targets,
            }
        )
        i = nxt
    return items


def main():
    src_path = sys.argv[1]
    pyc_path = sys.argv[2]
    json_path = sys.argv[3]
    source = open(src_path).read()
    code = compile(source, "<corpus>", "exec")
    write_pyc(code, pyc_path)
    use_modern = hasattr(dis, "get_instructions")
    blocks = []
    for path, co in walk(code, "<module>"):
        block = modern_block(co) if use_modern else legacy_block(co)
        blocks.append({"path": path, "instructions": block})
    payload = {"version": list(sys.version_info[:2]), "blocks": blocks}
    with open(json_path, "w") as handle:
        json.dump(payload, handle)
    sys.stdout.write("ok %d.%d\n" % (sys.version_info[0], sys.version_info[1]))


main()
"#;

#[derive(Debug, Clone)]
struct Interpreter {
    label: String,
    path: PathBuf,
    version: (u8, u8),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Expected {
    offset: usize,
    opname: String,
    arg: Option<u64>,
    argrepr: String,
    starts_line: Option<u64>,
    is_jump_target: bool,
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

fn uv_python_store(home: &Path) -> PathBuf {
    if cfg!(windows) {
        home.join("AppData/Roaming/uv/python")
    } else {
        home.join(".local/share/uv/python")
    }
}

fn python_exe_name(minor: u8) -> String {
    if cfg!(windows) {
        format!("python3.{minor}{}", std::env::consts::EXE_SUFFIX)
    } else {
        format!("python3.{minor}")
    }
}

fn probe_version(path: &Path) -> Option<(u8, u8)> {
    let output = Command::new(path)
        .args([
            "-c",
            "import sys;print('%d.%d'%(sys.version_info[0],sys.version_info[1]))",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let (major, minor): (&str, &str) = text.split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

fn push_candidate(out: &mut Vec<Interpreter>, label: String, path: PathBuf) {
    if out.iter().any(|i: &Interpreter| i.path == path) {
        return;
    }
    if !path.exists() {
        return;
    }
    let probed: Option<(u8, u8)> = probe_version(&path);
    let Some(version): Option<(u8, u8)> = probed else {
        return;
    };
    if out.iter().any(|i: &Interpreter| i.version == version) {
        return;
    }
    out.push(Interpreter {
        label,
        path,
        version,
    });
}

fn find_via_uv(version: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("uv")
        .args(["python", "find", version])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let raw: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let path: PathBuf = PathBuf::from(raw);
    path.is_file().then_some(path)
}

fn discover_interpreters() -> Vec<Interpreter> {
    let mut out: Vec<Interpreter> = Vec::new();

    for minor in 6u8..=15 {
        let version: String = format!("3.{minor}");
        if let Some(path) = find_via_uv(&version) {
            push_candidate(&mut out, format!("uv-3.{minor}"), path);
        }
    }

    let Some(home): Option<PathBuf> = home_dir() else {
        return out;
    };

    let uv_root: PathBuf = uv_python_store(&home);
    if let Ok(entries) = std::fs::read_dir(&uv_root) {
        let mut dirs: Vec<PathBuf> = entries
            .filter_map(|entry| entry.ok().map(|e| e.path()))
            .filter(|p: &PathBuf| {
                p.is_dir()
                    && p.file_name()
                        .and_then(|n| n.to_str())
                        .is_some_and(|n: &str| n.starts_with("cpython-"))
            })
            .collect();
        dirs.sort();
        for dir in dirs {
            let exe: PathBuf = dir.join(format!("python{}", std::env::consts::EXE_SUFFIX));
            let label: String = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("uv")
                .to_owned();
            push_candidate(&mut out, label, exe);
        }
    }

    if !cfg!(windows) {
        let local_bin: PathBuf = home.join(".local/bin");
        for minor in 6u8..=15 {
            let exe: PathBuf = local_bin.join(python_exe_name(minor));
            push_candidate(&mut out, format!("local-3.{minor}"), exe);
        }
        for minor in 6u8..=15 {
            let exe: PathBuf = PathBuf::from(format!("/usr/bin/python3.{minor}"));
            push_candidate(&mut out, format!("usr-3.{minor}"), exe);
        }
        for minor in 6u8..=15 {
            let exe: PathBuf = PathBuf::from(format!("/usr/local/bin/python3.{minor}"));
            push_candidate(&mut out, format!("usrlocal-3.{minor}"), exe);
        }
    }

    for version in [
        "2.7", "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15",
    ] {
        let resolved: Option<PathBuf> = resolve_py_launcher(version);
        if let Some(path) = resolved {
            push_candidate(&mut out, format!("py-{version}"), path);
        }
    }

    out.sort_by_key(|i: &Interpreter| i.version);
    out
}

fn resolve_py_launcher(version: &str) -> Option<PathBuf> {
    let output = Command::new("py")
        .args([
            &format!("-{version}"),
            "-c",
            "import sys;print(sys.executable)",
        ])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if text.is_empty() {
        return None;
    }
    Some(PathBuf::from(text))
}

fn collect_codes<'a>(co: &'a CodeObject, path: String, out: &mut Vec<(String, &'a CodeObject)>) {
    out.push((path.clone(), co));
    for (index, konst) in co.consts.iter().enumerate() {
        if let Object::Code(child) = konst {
            let name: String = code_name(child).unwrap_or_else(|| index.to_string());
            collect_codes(child, format!("{path}/{name}#{index}"), out);
        }
    }
}

fn code_name(co: &CodeObject) -> Option<String> {
    match &co.name {
        Object::String { value, .. } | Object::ShortAscii { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn parse_expected(block: &serde_json::Value) -> Vec<Expected> {
    block["instructions"]
        .as_array()
        .expect("instructions array")
        .iter()
        .map(|item: &serde_json::Value| Expected {
            offset: item["offset"].as_u64().expect("offset") as usize,
            opname: item["opname"].as_str().expect("opname").to_owned(),
            arg: item["arg"].as_u64(),
            argrepr: item["argrepr"].as_str().unwrap_or("").to_owned(),
            starts_line: item["starts_line"].as_u64(),
            is_jump_target: item["is_jump_target"].as_bool().expect("is_jump_target"),
        })
        .collect()
}

fn argrepr_is_checked(opname: &str) -> bool {
    matches!(
        opname,
        "IS_OP"
            | "CONTAINS_OP"
            | "LOAD_GLOBAL"
            | "LOAD_ATTR"
            | "LOAD_NAME"
            | "STORE_NAME"
            | "COMPARE_OP"
            | "FORMAT_VALUE"
            | "MAKE_FUNCTION"
            | "SET_FUNCTION_ATTRIBUTE"
            | "LOAD_FAST"
            | "STORE_FAST"
    ) || argrepr_names_a_binding(opname)
}

fn argrepr_names_a_binding(opname: &str) -> bool {
    matches!(
        opname,
        "DELETE_ATTR"
            | "DELETE_DEREF"
            | "DELETE_FAST"
            | "DELETE_GLOBAL"
            | "DELETE_NAME"
            | "IMPORT_FROM"
            | "IMPORT_NAME"
            | "LOAD_CLASSDEREF"
            | "LOAD_CLOSURE"
            | "LOAD_DEREF"
            | "LOAD_FAST_AND_CLEAR"
            | "LOAD_FAST_BORROW"
            | "LOAD_FAST_BORROW_LOAD_FAST_BORROW"
            | "LOAD_FAST_CHECK"
            | "LOAD_FAST_LOAD_FAST"
            | "LOAD_FROM_DICT_OR_DEREF"
            | "LOAD_FROM_DICT_OR_GLOBALS"
            | "LOAD_METHOD"
            | "LOAD_SUPER_ATTR"
            | "MAKE_CELL"
            | "STORE_ATTR"
            | "STORE_DEREF"
            | "STORE_FAST_LOAD_FAST"
            | "STORE_FAST_STORE_FAST"
            | "STORE_GLOBAL"
    )
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ArgreprTally {
    checked: usize,
    matched: usize,
}

fn merge_tallies(into: &mut BTreeMap<String, ArgreprTally>, from: &BTreeMap<String, ArgreprTally>) {
    for (opname, tally) in from {
        let slot: &mut ArgreprTally = into.entry(opname.clone()).or_default();
        slot.checked += tally.checked;
        slot.matched += tally.matched;
    }
}

fn tally_line(tallies: &BTreeMap<String, ArgreprTally>) -> String {
    tallies
        .iter()
        .map(|(opname, tally): (&String, &ArgreprTally)| {
            format!("{opname} {}/{}", tally.matched, tally.checked)
        })
        .collect::<Vec<String>>()
        .join(", ")
}

struct InterpreterOutcome {
    failures: Vec<String>,
    resolved_ops: Vec<String>,
    tallies: BTreeMap<String, ArgreprTally>,
}

fn run_interpreter(interp: &Interpreter, work: &Path, corpus_path: &Path) -> InterpreterOutcome {
    let pyc: PathBuf = work.join(format!(
        "corpus_{}_{}.pyc",
        interp.version.0, interp.version.1
    ));
    let json: PathBuf = work.join(format!(
        "expect_{}_{}.json",
        interp.version.0, interp.version.1
    ));
    let status = Command::new(&interp.path)
        .arg(work.join("dumper.py"))
        .arg(corpus_path)
        .arg(&pyc)
        .arg(&json)
        .output()
        .expect("spawn interpreter dumper");
    assert!(
        status.status.success(),
        "{} dumper failed: {}",
        interp.label,
        String::from_utf8_lossy(&status.stderr)
    );

    let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
    let parsed = read_pyc(&bytes).unwrap_or_else(|error| {
        panic!("{} read_pyc failed: {error:?}", interp.label);
    });
    let version: PyVersion = parsed.header.version;
    assert_eq!(
        (version.major, version.minor),
        interp.version,
        "{} pyc version mismatch",
        interp.label
    );
    let Object::Code(root): &Object = &parsed.code else {
        panic!("{} top-level object is not code", interp.label);
    };

    let mut codes: Vec<(String, &CodeObject)> = Vec::new();
    collect_codes(root, "<module>".to_owned(), &mut codes);
    let by_path: BTreeMap<&str, &CodeObject> = codes
        .iter()
        .map(|(p, c): &(String, &CodeObject)| (p.as_str(), *c))
        .collect();

    let expected_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json).expect("read json")).expect("parse json");
    let blocks: &Vec<serde_json::Value> = expected_json["blocks"].as_array().expect("blocks array");

    let mut failures: Vec<String> = Vec::new();
    let mut resolved_ops: Vec<String> = Vec::new();
    let mut tallies: BTreeMap<String, ArgreprTally> = BTreeMap::new();

    for block in blocks {
        let path: &str = block["path"].as_str().expect("path");
        let Some(co): Option<&&CodeObject> = by_path.get(path) else {
            failures.push(format!(
                "{} [{path}] missing code object on rust side",
                interp.label
            ));
            continue;
        };
        let expected: Vec<Expected> = parse_expected(block);
        let got: Vec<Instruction> = disassemble(co, version);
        let got_by_offset: BTreeMap<usize, &Instruction> =
            got.iter().map(|i: &Instruction| (i.offset, i)).collect();

        for exp in &expected {
            resolved_ops.push(exp.opname.clone());
            let Some(actual): Option<&&Instruction> = got_by_offset.get(&exp.offset) else {
                failures.push(format!(
                    "{} [{path}] off {} {}: missing on rust side",
                    interp.label, exp.offset, exp.opname
                ));
                continue;
            };

            let cpython_hidden: bool = exp.opname.starts_with('<') && exp.opname.ends_with('>');
            if !cpython_hidden && actual.opname != exp.opname {
                failures.push(format!(
                    "{} [{path}] off {}: opname rust={} cpython={}",
                    interp.label, exp.offset, actual.opname, exp.opname
                ));
            }

            let actual_arg: Option<u64> = actual.arg.map(u64::from);
            if actual_arg != exp.arg {
                failures.push(format!(
                    "{} [{path}] off {} {}: arg rust={actual_arg:?} cpython={:?}",
                    interp.label, exp.offset, exp.opname, exp.arg
                ));
            }

            let actual_line: Option<u64> = actual.line.map(u64::from);
            if actual_line != exp.starts_line {
                failures.push(format!(
                    "{} [{path}] off {} {}: line rust={actual_line:?} cpython={:?}",
                    interp.label, exp.offset, exp.opname, exp.starts_line
                ));
            }

            if actual.is_jump_target != exp.is_jump_target {
                failures.push(format!(
                    "{} [{path}] off {} {}: jump_target rust={} cpython={}",
                    interp.label, exp.offset, exp.opname, actual.is_jump_target, exp.is_jump_target
                ));
            }

            if !cpython_hidden && argrepr_is_checked(&exp.opname) {
                let actual_repr: &str = actual.argrepr.as_deref().unwrap_or("");
                let tally: &mut ArgreprTally = tallies.entry(exp.opname.clone()).or_default();
                tally.checked += 1;
                if actual_repr == exp.argrepr {
                    tally.matched += 1;
                } else {
                    failures.push(format!(
                        "{} [{path}] off {} {}: argrepr rust={actual_repr:?} cpython={:?}",
                        interp.label, exp.offset, exp.opname, exp.argrepr
                    ));
                }
            }

            if !cpython_hidden && exp.opname == "LOAD_CONST" && exp.argrepr.ends_with('j') {
                resolved_ops.push("LOAD_CONST_COMPLEX".to_owned());
                let actual_repr: &str = actual.argrepr.as_deref().unwrap_or("");
                if actual_repr != exp.argrepr {
                    failures.push(format!(
                        "{} [{path}] off {} LOAD_CONST complex: argrepr rust={actual_repr:?} cpython={:?}",
                        interp.label, exp.offset, exp.argrepr
                    ));
                }
            }
        }
    }

    InterpreterOutcome {
        failures,
        resolved_ops,
        tallies,
    }
}

#[test]
fn disassembler_matches_cpython_dis_across_versions() {
    let interpreters: Vec<Interpreter> = discover_interpreters();
    assert!(
        !interpreters.is_empty(),
        "no CPython interpreters discovered (uv toolchains, ~/.local/bin, or py launcher); \
         install one to run this cross-check"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_dis_xcheck").expect("create work dir");
    let work: PathBuf = scratch.path().to_path_buf();
    std::fs::write(work.join("dumper.py"), DUMPER).expect("write dumper");
    let corpus_py3: PathBuf = work.join("corpus_py3.py");
    let corpus_py2: PathBuf = work.join("corpus_py2.py");
    std::fs::write(&corpus_py3, CORPUS_PY3).expect("write py3 corpus");
    std::fs::write(&corpus_py2, CORPUS_PY2).expect("write py2 corpus");

    let mut all_failures: Vec<String> = Vec::new();
    let mut checked: Vec<(u8, u8)> = Vec::new();
    let mut tallies: BTreeMap<String, ArgreprTally> = BTreeMap::new();
    let mut saw_is_op: bool = false;
    let mut saw_intrinsic: bool = false;
    let mut saw_compare: bool = false;
    let mut saw_complex_const: bool = false;

    for interp in &interpreters {
        let corpus: &PathBuf = if interp.version.0 >= 3 {
            &corpus_py3
        } else {
            &corpus_py2
        };
        let outcome: InterpreterOutcome = run_interpreter(interp, &work, corpus);
        let InterpreterOutcome {
            failures,
            resolved_ops: ops,
            tallies: interpreter_tallies,
        }: InterpreterOutcome = outcome;
        merge_tallies(&mut tallies, &interpreter_tallies);
        if ops.iter().any(|o: &String| o == "IS_OP") {
            saw_is_op = true;
        }
        if ops.iter().any(|o: &String| o == "CALL_INTRINSIC_1") {
            saw_intrinsic = true;
        }
        if ops.iter().any(|o: &String| o == "COMPARE_OP") {
            saw_compare = true;
        }
        if ops.iter().any(|o: &String| o == "LOAD_CONST_COMPLEX") {
            saw_complex_const = true;
        }
        all_failures.extend(failures);
        checked.push(interp.version);
    }

    assert!(
        all_failures.is_empty(),
        "cross-check mismatches against CPython dis ({} total), argrepr matched/checked: {}\n{}",
        all_failures.len(),
        tally_line(&tallies),
        all_failures.join("\n")
    );

    let has_pre_311: bool = checked
        .iter()
        .any(|&(major, minor): &(u8, u8)| major < 3 || (major == 3 && minor < 11));
    if has_pre_311 {
        for opname in [
            "LOAD_DEREF",
            "STORE_DEREF",
            "LOAD_CLOSURE",
            "LOAD_CLASSDEREF",
        ] {
            let tally: ArgreprTally = tallies.get(opname).copied().unwrap_or_default();
            assert!(
                tally.checked > 0,
                "corpus never produced {opname} on a pre-3.11 interpreter, so the \
                 cell-and-free name table is unverified there; matched/checked: {}",
                tally_line(&tallies)
            );
        }
    }
    let has_super_attr_opcode: bool = checked
        .iter()
        .any(|&(major, minor): &(u8, u8)| major > 3 || (major == 3 && minor >= 12));
    if has_super_attr_opcode {
        let tally: ArgreprTally = tallies.get("LOAD_SUPER_ATTR").copied().unwrap_or_default();
        assert!(
            tally.checked > 0,
            "corpus never produced LOAD_SUPER_ATTR on a 3.12+ interpreter, so its name and \
             NULL|self rendering is unverified; matched/checked: {}",
            tally_line(&tallies)
        );
    }

    let has_311_plus: bool = checked
        .iter()
        .any(|&(major, minor): &(u8, u8)| major > 3 || (major == 3 && minor >= 11));
    if has_311_plus {
        assert!(
            saw_is_op,
            "corpus never produced IS_OP on a 3.11+ interpreter; the IS_OP table fix is unverified"
        );
    }
    let has_312_plus: bool = checked
        .iter()
        .any(|&(major, minor): &(u8, u8)| major > 3 || (major == 3 && minor >= 12));
    if has_312_plus {
        assert!(
            saw_intrinsic,
            "corpus never produced CALL_INTRINSIC_1 on a 3.12+ interpreter; that table fix is unverified"
        );
    }
    assert!(
        saw_compare,
        "corpus never produced COMPARE_OP on any interpreter"
    );
    let has_three: bool = checked.iter().any(|&(major, _): &(u8, u8)| major >= 3);
    if has_three {
        assert!(
            saw_complex_const,
            "corpus never produced a complex LOAD_CONST on a 3.x interpreter; \
             the complex-repr fix is unverified"
        );
    }
    assert!(
        checked.len() >= 2,
        "expected at least two interpreter versions, saw {checked:?}"
    );
}
