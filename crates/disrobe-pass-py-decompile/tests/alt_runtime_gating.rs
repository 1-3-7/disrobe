#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::missing_const_for_fn
)]

use disrobe_core::{Artifact, LegacyPass, Rung};
use disrobe_pass_py_decompile::pass::{AltRuntime, DecompilePass, RuntimeRoute, detect_runtime};

const MICROPYTHON_MAGIC: u32 = 0x0000_054D;
const JYTHON_CLASSFILE_MAGIC: u32 = 0xCAFE_BABE;
const IRONPYTHON_PE_MAGIC: u32 = 0x0001_5A4D;
const BRYTHON_MAGIC: u32 = 0x4252_5954;
const CPYTHON_311_MAGIC: u32 = 3495u32;
const PYPY_310_MAGIC: u32 = 0xA1B2_0000 | 0x0000_0D6Fu32;

const MICROPYTHON_BYTECODE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_bytecode.mpy");
const JYTHON_CLASS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/jython/greet_mod$py.class");
const IRONPYTHON_DLL: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/ironpython/greet_ip.dll");
const BRYTHON_JS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/brython/hello.brython.js");

fn run_on(bytes: &[u8]) -> String {
    let input: Artifact = Artifact::new(Rung::Disasm, bytes.to_vec(), [0u8; 32]);
    let out: Artifact = DecompilePass::new()
        .run(&input)
        .expect("alt runtime routes");
    String::from_utf8_lossy(out.envelope.as_slice()).into_owned()
}

#[test]
fn micropython_routes_to_source_recovery() {
    let runtime: AltRuntime = detect_runtime(MICROPYTHON_MAGIC);
    assert_eq!(runtime, AltRuntime::MicroPython);
    assert_eq!(
        DecompilePass::dispatch_runtime(runtime),
        RuntimeRoute::NativeMarshal
    );
    let text: String = run_on(MICROPYTHON_BYTECODE);
    assert!(text.contains("def add"), "got: {text}");
    assert!(text.contains("print"), "got: {text}");
}

#[test]
fn jython_routes_to_java_source() {
    let runtime: AltRuntime = detect_runtime(JYTHON_CLASSFILE_MAGIC);
    assert_eq!(runtime, AltRuntime::Jython);
    let text: String = run_on(JYTHON_CLASS);
    assert!(text.contains("via java decompilation"), "got: {text}");
    assert!(text.contains("class"));
}

#[test]
fn ironpython_routes_to_csharp_source() {
    let runtime: AltRuntime = detect_runtime(IRONPYTHON_PE_MAGIC);
    assert_eq!(runtime, AltRuntime::IronPython);
    let text: String = run_on(IRONPYTHON_DLL);
    assert!(text.contains("via csharp decompilation"), "got: {text}");
}

#[test]
fn brython_routes_to_js_deob_handoff() {
    let runtime: AltRuntime = detect_runtime(BRYTHON_MAGIC);
    assert_eq!(runtime, AltRuntime::Brython);
    let text: String = run_on(BRYTHON_JS);
    assert!(text.contains("js-deob handoff"), "got: {text}");
}

#[test]
fn cpython_routes_to_native_marshal() {
    let runtime: AltRuntime = detect_runtime(CPYTHON_311_MAGIC);
    assert_eq!(runtime, AltRuntime::CPython);
    assert_eq!(
        DecompilePass::dispatch_runtime(runtime),
        RuntimeRoute::NativeMarshal
    );
}

#[test]
fn pypy_routes_to_native_marshal() {
    let runtime: AltRuntime = detect_runtime(PYPY_310_MAGIC);
    assert_eq!(runtime, AltRuntime::PyPy);
    assert_eq!(
        DecompilePass::dispatch_runtime(runtime),
        RuntimeRoute::NativeMarshal
    );
}
