#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_binfmt::chain_detector::{CYTHON_PASS, CythonDetector};
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::{ChildArtifact, DetectContext, DetectVerdict, Detector, Pass};

use common::requirement::{PYTHON, describe_run, locate, required_fixture, unmeasured};

const FORMAT_DIR: &str = "cython";

const STUB_SIGNATURES: &str = r#"
import ast, json, sys
tree = ast.parse(sys.stdin.read())
out = {}
def args_of(fn):
    a = fn.args
    positional = a.posonlyargs + a.args
    defaults = [None] * (len(positional) - len(a.defaults)) + [ast.unparse(d) for d in a.defaults]
    return [[p.arg, d] for p, d in zip(positional, defaults)]
for node in tree.body:
    if isinstance(node, ast.FunctionDef):
        out[node.name] = args_of(node)
    elif isinstance(node, ast.ClassDef):
        for item in node.body:
            if isinstance(item, ast.FunctionDef):
                out[node.name + "." + item.name] = args_of(item)
print(json.dumps(out, sort_keys=True))
"#;

type Signatures = BTreeMap<String, Vec<(String, Option<String>)>>;

fn pyx_reference() -> Signatures {
    let path: PathBuf = common::fixture_path(FORMAT_DIR, "mod.pyx");
    let source: String = std::fs::read_to_string(&path).expect("read mod.pyx");
    let mut signatures: Signatures = BTreeMap::new();
    let mut class: Option<String> = None;
    for line in source.lines() {
        let indented: bool = line.starts_with(' ');
        if !indented && !line.trim().is_empty() {
            class = line
                .strip_prefix("cdef class ")
                .and_then(|rest: &str| rest.strip_suffix(':'))
                .map(str::to_owned);
        }
        let trimmed: &str = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("def ")
            .or_else(|| trimmed.strip_prefix("cpdef "))
        else {
            continue;
        };
        let open: usize = rest.find('(').expect("signature opens");
        let close: usize = rest.rfind(')').expect("signature closes");
        let name: &str = rest[..open].split_whitespace().last().expect("name");
        let params: Vec<(String, Option<String>)> = rest[open + 1..close]
            .split(',')
            .filter(|p: &&str| !p.trim().is_empty())
            .map(|p: &str| {
                let (declaration, default): (&str, Option<String>) = match p.split_once('=') {
                    Some((d, v)) => (d.trim(), Some(v.trim().to_owned())),
                    None => (p.trim(), None),
                };
                let param: &str = declaration.split_whitespace().last().expect("param");
                (param.to_owned(), default)
            })
            .collect();
        let key: String = match (&class, indented) {
            (Some(owner), true) => format!("{owner}.{name}"),
            _ => name.to_owned(),
        };
        signatures.insert(key, params);
    }
    signatures
}

fn stub_signatures(stub: &str) -> Option<Signatures> {
    let python: PathBuf = match locate(&PYTHON) {
        Ok(path) => path,
        Err(reason) => {
            unmeasured(
                &PYTHON,
                "CPython's parse of the recovered Cython stub against the authored .pyx",
                &reason,
            );
            return None;
        }
    };
    let mut child: std::process::Child = Command::new(&python)
        .args(["-c", STUB_SIGNATURES])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("start python");
    std::io::Write::write_all(child.stdin.as_mut().expect("stdin"), stub.as_bytes())
        .expect("write stub");
    let output: Output = child.wait_with_output().expect("python output");
    assert!(
        output.status.success(),
        "CPython rejected the stub:\n{stub}\n{}",
        describe_run(&python, &["-c", "<stub signatures>"], &output)
    );
    let parsed: BTreeMap<String, Vec<(String, Option<String>)>> =
        serde_json::from_slice(&output.stdout).expect("signature json");
    Some(parsed)
}

fn grade(reference: &Signatures, recovered: &Signatures) -> Result<(), String> {
    let mut mismatches: Vec<String> = Vec::new();
    for (name, params) in reference {
        match recovered.get(name) {
            None => mismatches.push(format!("{name} is missing")),
            Some(found) => {
                let found_params: Vec<(String, Option<String>)> = if name.contains('.') {
                    found.iter().skip(1).cloned().collect()
                } else {
                    found.clone()
                };
                let expected_params: Vec<(String, Option<String>)> = if name.contains('.') {
                    params.iter().skip(1).cloned().collect()
                } else {
                    params.clone()
                };
                if found_params != expected_params {
                    mismatches.push(format!(
                        "{name}: recovered {found_params:?}, authored {expected_params:?}"
                    ));
                }
            }
        }
    }
    if mismatches.is_empty() {
        Ok(())
    } else {
        Err(mismatches.join("; "))
    }
}

fn stub_for(file: &str) -> String {
    let bytes: Vec<u8> = required_fixture(FORMAT_DIR, file);
    let verdict: DetectVerdict = CythonDetector
        .detect(&DetectContext {
            bytes: &bytes,
            path_hint: None,
            parent_hint: None,
            depth: 0,
        })
        .expect("the Cython detector claims the module");
    assert_eq!(verdict.format_tag, "cython-extension");
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<ChildArtifact> = CYTHON_PASS
        .extract_children(&artifact)
        .expect("cython surface children");
    let stub: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "mod.pyi")
        .expect("mod.pyi child");
    String::from_utf8(stub.bytes.clone()).expect("utf-8 stub")
}

#[test]
fn the_unstripped_module_stub_declares_every_authored_signature() {
    let stub: String = stub_for("mod.unstripped.pyd");
    let Some(recovered) = stub_signatures(&stub) else {
        return;
    };
    let reference: Signatures = pyx_reference();
    assert!(reference.len() >= 6, "{reference:?}");
    if let Err(mismatch) = grade(&reference, &recovered) {
        panic!("{mismatch}\n{stub}");
    }
}

#[test]
fn the_stripped_module_stub_names_every_authored_function() {
    let stub: String = stub_for("mod.stripped.pyd");
    let Some(recovered) = stub_signatures(&stub) else {
        return;
    };
    for name in pyx_reference()
        .keys()
        .filter(|name: &&String| !name.ends_with(".__init__"))
    {
        assert!(
            recovered.contains_key(name),
            "{name} missing from the stripped stub:\n{stub}"
        );
    }
}

#[test]
fn a_dropped_default_turns_the_signature_grade_red() {
    let stub: String = stub_for("mod.unstripped.pyd");
    let mutated: String = stub.replacen("count: int = 1", "count: int", 1);
    assert_ne!(mutated, stub, "the mutation must hit the stub");
    let Some(recovered) = stub_signatures(&mutated) else {
        return;
    };
    assert!(grade(&pyx_reference(), &recovered).is_err());
}
