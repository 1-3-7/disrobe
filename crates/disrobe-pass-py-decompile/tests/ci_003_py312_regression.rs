#![allow(clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::{Path, PathBuf};

use common::band::{
    BandInterpreter, CorpusMeasurement, band_scratch, find_interpreter, measure_corpus_file,
};
use common::stdlib_measure::interpreter_stdlib;
use disrobe_pass_py_decompile::roundtrip::{Verdict, semantic_equiv};
use disrobe_py_marshal::{CodeObject, Object, PyVersion as MarshalVersion, PycFile, read_pyc};

fn read_code(path: &Path) -> (CodeObject, MarshalVersion) {
    let bytes: Vec<u8> = fs::read(path).expect("read pyc");
    let pyc: PycFile = read_pyc(&bytes).expect("parse pyc");
    let version: MarshalVersion = pyc.header.version;
    let Object::Code(code): Object = pyc.code else {
        panic!("top-level object is not code");
    };
    (*code, version)
}

fn code_name(code: &CodeObject) -> Option<&str> {
    match &code.name {
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => Some(value),
        _ => None,
    }
}

fn nested_code<'a>(code: &'a CodeObject, names: &[&str]) -> Option<&'a CodeObject> {
    let Some((name, tail)): Option<(&&str, &[&str])> = names.split_first() else {
        return Some(code);
    };
    code.consts
        .iter()
        .find_map(|constant: &Object| match constant {
            Object::Code(child) if code_name(child) == Some(*name) => nested_code(child, tail),
            _ => None,
        })
}

#[test]
fn zipfile_testzip_recompiles_on_cpython_312() {
    let path: PathBuf = find_interpreter("3.12.13").expect("CPython 3.12.13");
    let lib: PathBuf = interpreter_stdlib(&path).expect("CPython stdlib");
    let interpreter = BandInterpreter {
        alias: "3.12",
        path,
        is_prerelease: false,
    };
    let scratch: PathBuf = band_scratch("ci-003-py312-zipfile-testzip");
    let CorpusMeasurement::Measured(tally) = measure_corpus_file(
        &interpreter,
        &lib.join("zipfile/__init__.py"),
        "zipfile-testzip",
        &scratch,
    ) else {
        panic!("zipfile corpus source was not measurable");
    };
    let (original, marshal_version): (CodeObject, MarshalVersion) =
        read_code(&scratch.join("zipfile-testzip.3.12.orig.pyc"));
    let (recompiled, _): (CodeObject, MarshalVersion) =
        read_code(&scratch.join("zipfile-testzip.3.12.dec.pyc"));
    let original_testzip: &CodeObject = nested_code(&original, &["ZipFile", "testzip"])
        .expect("original ZipFile.testzip code object");
    let recompiled_testzip: &CodeObject = nested_code(&recompiled, &["ZipFile", "testzip"])
        .expect("recompiled ZipFile.testzip code object");
    assert!(
        matches!(
            semantic_equiv(original_testzip, recompiled_testzip, marshal_version),
            Verdict::Perfect | Verdict::Semantic
        ),
        "ZipFile.testzip was graded and is not equivalent"
    );
    assert!(
        !tally
            .failures
            .iter()
            .any(|failure| failure.qualname == "<module>.ZipFile.testzip"),
        "zipfile.ZipFile.testzip regressed: {:?}",
        tally.failures
    );
}
