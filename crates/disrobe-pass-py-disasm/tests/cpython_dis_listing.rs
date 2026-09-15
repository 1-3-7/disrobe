#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_disasm::{Instruction, disassemble, render_listing};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, read_pyc};

const CORPUS_BASE: &str = r#"
from math import *

GLOBAL_X = range(10)


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


def constants():
    return (
        3.14,
        2.0,
        0.5,
        100.0,
        0.0001,
        1e100,
        -0.0,
        b"raw\x00bytes",
        "quote'mix",
        (1, 2, 3),
        (7,),
        {"k": 1},
        None,
        True,
        10_000_000_000,
    )


def formatting(value, width):
    return f"{value!r:>{width}}"


def unary_positive(x):
    return +x


def unpack_to_tuple(a, b):
    return (*a, *b, 1)


def call_with_stars(func, a, b):
    return func(*a, *b)


def generator_series(n):
    total = 0
    for i in range(n):
        received = yield i * 2
        if received is not None:
            total += received
    return total


async def async_reader(source):
    results = []
    async with source as handle:
        async for chunk in handle:
            results.append(await chunk)
    return results


async def async_stream(source):
    async for item in source:
        yield item + 1


class Widget:
    kind = "default"

    def __init__(self, name):
        self.name = name

    def render(self):
        return self.name.upper()


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

const CORPUS_MATCH: &str = r#"

def match_shape(node):
    match node:
        case [1, 2, *rest]:
            return rest
        case {"kind": kind, "value": value}:
            return (kind, value)
        case str() | bytes():
            return "scalar"
        case _:
            return None
"#;

const CORPUS_EXCEPT_STAR: &str = r#"

def group_guard(work):
    label = "ok"
    try:
        work()
    except* ValueError:
        label = "value"
    except* (TypeError, KeyError):
        label = "type"
    return label
"#;

const CORPUS_PEP695: &str = r"

type IntList[T] = list[T]


def generic_fn[T, U: int, *Ts, **P](value: T) -> U:
    return value


class Container[T: (int, str)]:
    item: T

    def unwrap(self) -> T:
        return self.item
";

const CORPUS_PEP696: &str = r"

def defaulted[T = int](value: T) -> T:
    return value


class Boxed[T = str]:
    slot: T


type DefaultAlias[T = bytes] = list[T]
";

const CORPUS_TSTRING: &str = r#"

def make_template(value, width):
    return t"{value!r:>{width}} tail {value}"
"#;

fn corpus_for(version: (u8, u8)) -> String {
    let mut src: String = String::from(CORPUS_BASE);
    if version >= (3, 10) {
        src.push_str(CORPUS_MATCH);
    }
    if version >= (3, 11) {
        src.push_str(CORPUS_EXCEPT_STAR);
    }
    if version >= (3, 12) {
        src.push_str(CORPUS_PEP695);
    }
    if version >= (3, 13) {
        src.push_str(CORPUS_PEP696);
    }
    if version >= (3, 14) {
        src.push_str(CORPUS_TSTRING);
    }
    src
}

const DUMPER: &str = r#"
import dis
import json
import marshal
import struct
import sys


def write_pyc(code, path):
    data = marshal.dumps(code)
    with open(path, "wb") as handle:
        import importlib.util as ilu
        magic = ilu.MAGIC_NUMBER
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


def main():
    src_path = sys.argv[1]
    pyc_path = sys.argv[2]
    json_path = sys.argv[3]
    source = open(src_path).read()
    code = compile(source, "<corpus>", "exec")
    write_pyc(code, pyc_path)
    blocks = []
    for path, co in walk(code, "<module>"):
        text = dis.Bytecode(co).dis()
        blocks.append({"path": path, "listing": text})
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
    let Some(version): Option<(u8, u8)> = probe_version(&path) else {
        return;
    };
    if version.0 < 3 || (version.0 == 3 && version.1 < 6) {
        return;
    }
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

fn discover_interpreters() -> Vec<Interpreter> {
    let mut out: Vec<Interpreter> = Vec::new();

    for minor in 6u8..=15 {
        let version: String = format!("3.{minor}");
        if let Some(path) = find_via_uv(&version) {
            push_candidate(&mut out, format!("uv-3.{minor}"), path);
        }
    }

    if let Some(home) = home_dir() {
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
                push_candidate(
                    &mut out,
                    format!("local-3.{minor}"),
                    local_bin.join(python_exe_name(minor)),
                );
            }
            for minor in 6u8..=15 {
                push_candidate(
                    &mut out,
                    format!("usr-3.{minor}"),
                    PathBuf::from(format!("/usr/bin/python3.{minor}")),
                );
            }
        }
    }

    for version in [
        "3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15",
    ] {
        if let Some(path) = resolve_py_launcher(version) {
            push_candidate(&mut out, format!("py-{version}"), path);
        }
    }

    out.sort_by_key(|i: &Interpreter| i.version);
    out
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

fn run_interpreter(interp: &Interpreter, work: &Path) -> Vec<String> {
    let corpus_path: PathBuf = work.join(format!(
        "corpus_{}_{}.py",
        interp.version.0, interp.version.1
    ));
    std::fs::write(&corpus_path, corpus_for(interp.version)).expect("write corpus");
    let pyc: PathBuf = work.join(format!(
        "listing_{}_{}.pyc",
        interp.version.0, interp.version.1
    ));
    let json: PathBuf = work.join(format!(
        "listing_{}_{}.json",
        interp.version.0, interp.version.1
    ));
    let status = Command::new(&interp.path)
        .arg(work.join("dumper.py"))
        .arg(&corpus_path)
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
    for block in blocks {
        let path: &str = block["path"].as_str().expect("path");
        let expected: &str = block["listing"].as_str().expect("listing");
        let Some(co): Option<&&CodeObject> = by_path.get(path) else {
            failures.push(format!(
                "{} [{path}] missing code object on rust side",
                interp.label
            ));
            continue;
        };
        let got: Vec<Instruction> = disassemble(co, version);
        let actual: String = render_listing(&got, co, version);
        if normalize(&actual) != normalize(expected) {
            failures.push(format!(
                "{} [{path}] listing mismatch:\n--- cpython ---\n{}\n--- disrobe ---\n{}",
                interp.label,
                expected.trim_end(),
                actual.trim_end()
            ));
        }
    }
    failures
}

fn normalize(text: &str) -> String {
    let unified: String = text.replace("\r\n", "\n");
    mask_code_addresses(&unified).trim_end().to_owned()
}

fn mask_code_addresses(text: &str) -> String {
    let mut out: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    let marker: &str = " at 0x";
    while let Some(index) = rest.find(marker) {
        let (head, tail): (&str, &str) = rest.split_at(index + marker.len());
        out.push_str(head);
        let hex_len: usize = tail
            .char_indices()
            .take_while(|(_, c): &(usize, char)| c.is_ascii_hexdigit())
            .count();
        out.push_str("ADDR");
        rest = &tail[hex_len..];
    }
    out.push_str(rest);
    out
}

#[test]
fn render_listing_matches_cpython_dis_text_across_versions() {
    let interpreters: Vec<Interpreter> = discover_interpreters();
    assert!(
        !interpreters.is_empty(),
        "no CPython interpreters discovered for the dis-text listing oracle"
    );

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_dis_listing").expect("create work dir");
    let work: PathBuf = scratch.path().to_path_buf();
    std::fs::write(work.join("dumper.py"), DUMPER).expect("write dumper");

    let mut all_failures: Vec<String> = Vec::new();
    let mut checked: Vec<(u8, u8)> = Vec::new();
    for interp in &interpreters {
        all_failures.extend(run_interpreter(interp, &work));
        checked.push(interp.version);
    }

    assert!(
        all_failures.is_empty(),
        "dis-text listing mismatches against CPython ({} blocks):\n\n{}",
        all_failures.len(),
        all_failures.join("\n\n")
    );
    assert!(
        checked.len() >= 2,
        "expected at least two interpreter versions for the listing oracle, saw {checked:?}"
    );
}
