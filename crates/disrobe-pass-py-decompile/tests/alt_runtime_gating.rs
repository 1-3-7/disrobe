#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use miette::Diagnostic;

use disrobe_pass_py_decompile::error::DecompileError;
use disrobe_pass_py_decompile::pass::{AltRuntime, DecompilePass, detect_runtime};

const ERROR_CODE: &str = "DR-PYDEC-AltRuntimeUnsupported";

const MICROPYTHON_MAGIC: u32 = 0x0000_054D;
const JYTHON_CLASSFILE_MAGIC: u32 = 0xCAFE_BABE;
const IRONPYTHON_PE_MAGIC: u32 = 0x0001_5A4D;
const BRYTHON_MAGIC: u32 = 0x4252_5954;
const CPYTHON_311_MAGIC: u32 = 3495u32;
const PYPY_310_MAGIC: u32 = 0xA1B2_0000 | 0x0000_0D6Fu32;

fn code_string(err: &DecompileError) -> String {
    err.code().map_or_else(String::new, |c| c.to_string())
}

fn assert_alt_unsupported(magic: u32, expected_runtime: &str) {
    let runtime: AltRuntime = detect_runtime(magic);
    let err: DecompileError =
        DecompilePass::dispatch_runtime(runtime).expect_err("must reject alt runtime");
    let DecompileError::AltRuntimeUnsupported {
        runtime,
        suggestion,
    } = &err
    else {
        panic!("expected AltRuntimeUnsupported, got {err:?}");
    };
    assert_eq!(*runtime, expected_runtime);
    assert!(
        !suggestion.is_empty(),
        "suggestion must point at the correct downstream pass"
    );
    assert_eq!(code_string(&err), ERROR_CODE);
}

#[test]
fn micropython_returns_alt_runtime_unsupported() {
    let runtime: AltRuntime = detect_runtime(MICROPYTHON_MAGIC);
    assert_eq!(runtime, AltRuntime::MicroPython);
    assert_alt_unsupported(MICROPYTHON_MAGIC, "micropython");
}

#[test]
fn jython_returns_alt_runtime_unsupported() {
    let runtime: AltRuntime = detect_runtime(JYTHON_CLASSFILE_MAGIC);
    assert_eq!(runtime, AltRuntime::Jython);
    assert_alt_unsupported(JYTHON_CLASSFILE_MAGIC, "jython");
}

#[test]
fn ironpython_returns_alt_runtime_unsupported() {
    let runtime: AltRuntime = detect_runtime(IRONPYTHON_PE_MAGIC);
    assert_eq!(runtime, AltRuntime::IronPython);
    assert_alt_unsupported(IRONPYTHON_PE_MAGIC, "ironpython");
}

#[test]
fn brython_returns_alt_runtime_unsupported() {
    let runtime: AltRuntime = detect_runtime(BRYTHON_MAGIC);
    assert_eq!(runtime, AltRuntime::Brython);
    assert_alt_unsupported(BRYTHON_MAGIC, "brython");
}

#[test]
fn cpython_passes_dispatch() {
    let runtime: AltRuntime = detect_runtime(CPYTHON_311_MAGIC);
    assert_eq!(runtime, AltRuntime::CPython);
    DecompilePass::dispatch_runtime(runtime).expect("CPython must not be gated");
}

#[test]
fn pypy_passes_dispatch() {
    let runtime: AltRuntime = detect_runtime(PYPY_310_MAGIC);
    assert_eq!(runtime, AltRuntime::PyPy);
    DecompilePass::dispatch_runtime(runtime).expect("PyPy must not be gated");
}

#[test]
fn alt_runtime_error_code_matches_spec() {
    let err: DecompileError = DecompileError::AltRuntimeUnsupported {
        runtime: "micropython",
        suggestion: "use disrobe-pass-py-disasm",
    };
    assert_eq!(code_string(&err), ERROR_CODE);
}
