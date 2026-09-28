#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
use std::path::PathBuf;
use std::process::{Command, Output};

use disrobe_core::scratch::ScratchDir;
use disrobe_core::{Artifact, Pass, Rung};
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;

const SOURCE: &str = "\
def outer(x):
    def inner(y):
        return [z * 2 for z in range(y)]
    return inner(x)


class Keeper:
    def method(self):
        return lambda q: q + 1


VALUE = {k: v for k, v in zip('ab', 'cd')}
";

const COMPILE: &str =
    "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True)";
const DIS: &str = "import dis, marshal, sys; data = open(sys.argv[1], 'rb').read(); dis.dis(marshal.loads(data[16:]))";
const HEADER: &str = "Disassembly of <code object ";

fn python() -> String {
    for candidate in ["python3", "python"] {
        let probe: Option<Output> = Command::new(candidate)
            .args(["-c", "import sys; assert sys.version_info >= (3, 8)"])
            .output()
            .ok();
        if probe.is_some_and(|output: Output| output.status.success()) {
            return candidate.to_owned();
        }
    }
    panic!("CPython 3.8 or newer must be on PATH as python3 or python: it is the reference dis")
}

fn nested_headers(listing: &str) -> Vec<String> {
    listing
        .lines()
        .filter_map(|line: &str| line.strip_prefix(HEADER))
        .map(|rest: &str| rest.split(" at ").next().unwrap_or(rest).to_owned())
        .collect()
}

#[test]
fn every_nested_code_object_dis_lists_is_listed_in_the_same_order() {
    let interpreter: String = python();
    let scratch: ScratchDir = ScratchDir::create("py-disasm-nested").expect("scratch");
    let source: PathBuf = scratch.path().join("nested.py");
    let pyc: PathBuf = scratch.path().join("nested.pyc");
    std::fs::write(&source, SOURCE).expect("write source");
    let compiled: Output = Command::new(&interpreter)
        .args(["-c", COMPILE])
        .arg(&source)
        .arg(&pyc)
        .output()
        .expect("run py_compile");
    assert!(compiled.status.success(), "{compiled:?}");
    let reference: Output = Command::new(&interpreter)
        .args(["-c", DIS])
        .arg(&pyc)
        .output()
        .expect("run dis");
    assert!(reference.status.success(), "{reference:?}");
    let expected: Vec<String> = nested_headers(&String::from_utf8_lossy(&reference.stdout));
    assert!(
        expected.len() >= 5,
        "the authored module nests functions, a class, a lambda and comprehensions: {expected:?}"
    );

    let bytes: Vec<u8> = std::fs::read(&pyc).expect("read pyc");
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let listed: Artifact = PY_DISASM_PASS.run(&artifact).expect("py.disasm runs");
    let listing: String = String::from_utf8(listed.envelope).expect("utf-8 listing");
    assert_eq!(nested_headers(&listing), expected, "{listing}");
}
