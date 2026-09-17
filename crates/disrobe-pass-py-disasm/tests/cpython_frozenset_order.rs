#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use std::path::{Path, PathBuf};
use std::process::Command;

use disrobe_pass_py_disasm::{Instruction, disassemble, render_listing};
use disrobe_py_marshal::{CodeObject, Object, PyVersion, read_pyc};

const CORPUS: &str = r"
def set_probe(v):
    if v in {7, 8}:
        return 1
    if v in {5, 13, 21, 29}:
        return 2
    if v in {100, 7, 42, 3, 999}:
        return 3
    if v in {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19}:
        return 4
    if v in {-1, -2, -3, 1000000, 5}:
        return 5
    return 0
";

const DUMPER: &str = r#"
import dis
import json
import marshal
import struct
import sys
import importlib.util as ilu


def write_pyc(code, path):
    data = marshal.dumps(code)
    with open(path, "wb") as handle:
        handle.write(ilu.MAGIC_NUMBER)
        info = sys.version_info
        if info[0] > 3 or (info[0] == 3 and info[1] >= 7):
            handle.write(struct.pack("<I", 0))
        handle.write(struct.pack("<I", 0))
        if info[0] > 3 or (info[0] == 3 and info[1] >= 3):
            handle.write(struct.pack("<I", len(data) & 0xFFFFFFFF))
        handle.write(data)


def find(code, name):
    for const in code.co_consts:
        if hasattr(const, "co_code") and getattr(const, "co_name", "") == name:
            return const
    return None


def main():
    src_path, pyc_path, json_path = sys.argv[1], sys.argv[2], sys.argv[3]
    source = open(src_path).read()
    code = compile(source, "<corpus>", "exec")
    write_pyc(code, pyc_path)
    reloaded = marshal.loads(marshal.dumps(code))
    target = find(reloaded, "set_probe")
    text = dis.Bytecode(target).dis()
    payload = {"version": list(sys.version_info[:2]), "listing": text}
    with open(json_path, "w") as handle:
        json.dump(payload, handle)


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

fn probe_version(path: &Path) -> Option<(u8, u8)> {
    let output: std::process::Output = Command::new(path)
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
    if out.iter().any(|i: &Interpreter| i.path == path) || !path.exists() {
        return;
    }
    let Some(version): Option<(u8, u8)> = probe_version(&path) else {
        return;
    };
    if version.0 != 3 || version.1 < 6 {
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

fn resolve_py_launcher(version: &str) -> Option<PathBuf> {
    let output: std::process::Output = Command::new("py")
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
    (!text.is_empty()).then(|| PathBuf::from(text))
}

fn discover_interpreters() -> Vec<Interpreter> {
    let mut out: Vec<Interpreter> = Vec::new();
    if let Some(home) = home_dir() {
        let uv_root: PathBuf = if cfg!(windows) {
            home.join("AppData/Roaming/uv/python")
        } else {
            home.join(".local/share/uv/python")
        };
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
    }
    for minor in 6u8..=15 {
        let version: String = format!("3.{minor}");
        if let Some(path) = resolve_py_launcher(&version) {
            push_candidate(&mut out, format!("py-{version}"), path);
        }
    }
    out.sort_by_key(|i: &Interpreter| i.version);
    out
}

fn find_named<'a>(co: &'a CodeObject, name: &str) -> Option<&'a CodeObject> {
    for konst in &co.consts {
        if let Object::Code(child) = konst {
            if code_name(child).as_deref() == Some(name) {
                return Some(child);
            }
            if let Some(found) = find_named(child, name) {
                return Some(found);
            }
        }
    }
    None
}

fn code_name(co: &CodeObject) -> Option<String> {
    match &co.name {
        Object::String { value, .. }
        | Object::ShortAscii { value, .. }
        | Object::Unicode { value, .. } => Some(value.clone()),
        _ => None,
    }
}

fn extract_frozensets(text: &str) -> Vec<String> {
    let bytes: &[u8] = text.as_bytes();
    let needle: &str = "frozenset(";
    let mut found: Vec<String> = Vec::new();
    let mut search_from: usize = 0;
    while let Some(relative) = text[search_from..].find(needle) {
        let start: usize = search_from + relative;
        let mut depth: i32 = 0;
        let mut end: usize = start + needle.len();
        for (offset, &byte) in bytes[start + needle.len() - 1..].iter().enumerate() {
            match byte {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = start + needle.len() - 1 + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        found.push(text[start..end].to_owned());
        search_from = end;
    }
    found
}

fn run_interpreter(interp: &Interpreter, work: &Path) -> Option<String> {
    let tag: String = format!("{}_{}", interp.version.0, interp.version.1);
    let corpus_path: PathBuf = work.join(format!("frozenset_{tag}.py"));
    std::fs::write(&corpus_path, CORPUS).expect("write corpus");
    let pyc: PathBuf = work.join(format!("frozenset_{tag}.pyc"));
    let json: PathBuf = work.join(format!("frozenset_{tag}.json"));
    let output: std::process::Output = Command::new(&interp.path)
        .arg(work.join("dumper.py"))
        .arg(&corpus_path)
        .arg(&pyc)
        .arg(&json)
        .output()
        .expect("spawn dumper");
    assert!(
        output.status.success(),
        "{} dumper failed: {}",
        interp.label,
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
    let parsed = read_pyc(&bytes).unwrap_or_else(|error| {
        panic!("{} read_pyc failed: {error:?}", interp.label);
    });
    let version: PyVersion = parsed.header.version;
    let Object::Code(root): &Object = &parsed.code else {
        panic!("{} top-level object is not code", interp.label);
    };
    let target: &CodeObject = find_named(root, "set_probe").expect("set_probe code object");
    let instructions: Vec<Instruction> = disassemble(target, version);
    let actual: String = render_listing(&instructions, target, version);

    let expected_json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&json).expect("read json")).expect("parse json");
    let expected: &str = expected_json["listing"].as_str().expect("listing");

    let expected_sets: Vec<String> = extract_frozensets(expected);
    let actual_sets: Vec<String> = extract_frozensets(&actual);
    assert!(
        !expected_sets.is_empty(),
        "{} produced no frozenset consts to compare",
        interp.label
    );
    (expected_sets != actual_sets).then(|| {
        format!(
            "{} [set_probe] frozenset ordering mismatch:\n--- cpython (reloaded pyc) ---\n{:#?}\n--- disrobe ---\n{:#?}",
            interp.label, expected_sets, actual_sets
        )
    })
}

#[test]
fn frozenset_const_order_matches_reloaded_pyc_dis() {
    let interpreters: Vec<Interpreter> = discover_interpreters();
    if interpreters.is_empty() {
        eprintln!("no CPython interpreters discovered; skipping reloaded-pyc frozenset oracle");
        return;
    }

    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create("disrobe_frozenset_order")
            .expect("create work dir");
    let work: PathBuf = scratch.path().to_path_buf();
    std::fs::write(work.join("dumper.py"), DUMPER).expect("write dumper");

    let mut failures: Vec<String> = Vec::new();
    for interp in &interpreters {
        if let Some(failure) = run_interpreter(interp, &work) {
            failures.push(failure);
        }
    }
    assert!(
        failures.is_empty(),
        "frozenset const ordering mismatches ({}):\n\n{}",
        failures.len(),
        failures.join("\n\n")
    );
}
