#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::Pass;
use disrobe_core::chain::detection::ChildArtifact;
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;

const X64_NATIVE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy");

#[test]
fn chain_recovers_native_mpy_not_just_detection() {
    let artifact: Artifact = Artifact::new(Rung::Raw, X64_NATIVE.to_vec(), [9u8; 32]);
    let out: Artifact = PY_DISASM_PASS.run(&artifact).expect("chain run");
    let text: String = String::from_utf8(out.envelope.as_slice().to_vec()).expect("utf8");
    assert!(
        !text.contains("native disassembly not implemented"),
        "chain mode must no longer wall native mpy at detection: {text}"
    );
    assert!(
        text.contains("micropython native module"),
        "chain mode must emit a real native listing: {text}"
    );
    assert!(
        text.contains("push"),
        "chain mode native listing must carry real x86 mnemonics: {text}"
    );
}

#[test]
fn chain_native_listing_includes_viper_child() {
    let artifact: Artifact = Artifact::new(Rung::Raw, X64_NATIVE.to_vec(), [9u8; 32]);
    let out: Artifact = PY_DISASM_PASS.run(&artifact).expect("chain run");
    let text: String = String::from_utf8(out.envelope.as_slice().to_vec()).expect("utf8");
    assert!(
        text.contains("native-viper"),
        "the viper-emitted mul() function must appear in the native listing: {text}"
    );
}

const CPYTHON_PYC_311: &[u8] =
    include_bytes!("../../../corpus/python/decompile/legacy/compiled/binary_ops.3.11.pyc");

#[test]
fn chain_cpython_pyc_emits_dis_json_sidecar_child() {
    let artifact: Artifact = Artifact::new(Rung::Raw, CPYTHON_PYC_311.to_vec(), [9u8; 32]);
    let kind: disrobe_core::chain::OutputKind = {
        let out: Artifact = PY_DISASM_PASS.run(&artifact).expect("chain run");
        PY_DISASM_PASS.output_kind(&out)
    };
    assert!(
        kind.is_mixed(),
        "a recovered cpython pyc must report Mixed so the runner reaches extract_children"
    );

    let children: Vec<ChildArtifact> = PY_DISASM_PASS
        .extract_children(&artifact)
        .expect("extract children");
    let sidecar: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path.ends_with(".dis.json"))
        .expect("auto/chain must emit a .dis.json sidecar child to match the dedicated CLI");

    let value: serde_json::Value =
        serde_json::from_slice(&sidecar.bytes).expect("sidecar is valid json");
    assert_eq!(value["runtime"], "cpython", "sidecar records the runtime");
    assert_eq!(
        value["py_version"], "3.11",
        "sidecar records the py version"
    );
    let count: u64 = value["instruction_count"]
        .as_u64()
        .expect("instruction_count");
    assert!(count > 0, "sidecar carries a real instruction count");
    let instructions: &Vec<serde_json::Value> = value["instructions"]
        .as_array()
        .expect("instructions array");
    assert_eq!(
        instructions.len() as u64,
        count,
        "instruction vec length matches instruction_count"
    );
    let first: &serde_json::Value = &instructions[0];
    assert!(
        first.get("opname").is_some() && first.get("offset").is_some(),
        "each instruction carries offset/opname like the dedicated dis.json"
    );
}

#[cfg(feature = "alt-runtimes-native")]
const JYTHON_CLASS: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/jython/greet_mod$py.class");
#[cfg(feature = "alt-runtimes-native")]
const IRONPYTHON_DLL: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/ironpython/greet_ip.dll");

#[cfg(feature = "alt-runtimes-native")]
#[test]
fn chain_jython_classfile_emits_recovered_java_source_child() {
    let artifact: Artifact = Artifact::new(Rung::Raw, JYTHON_CLASS.to_vec(), [9u8; 32]);
    let children: Vec<ChildArtifact> = PY_DISASM_PASS
        .extract_children(&artifact)
        .expect("extract children");
    let java: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| {
            std::path::Path::new(&c.handle.relative_path)
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("java"))
        })
        .expect(
            "chain must recover the embedded jython classfile as real java source, not drop it",
        );
    let text: String = String::from_utf8(java.bytes.clone()).expect("utf8 java source");
    assert!(
        text.contains("class"),
        "recovered java source must contain a class declaration: {text}"
    );
}

#[cfg(feature = "alt-runtimes-native")]
#[test]
fn chain_ironpython_dll_emits_recovered_csharp_source_child() {
    let artifact: Artifact = Artifact::new(Rung::Raw, IRONPYTHON_DLL.to_vec(), [9u8; 32]);
    let children: Vec<ChildArtifact> = PY_DISASM_PASS
        .extract_children(&artifact)
        .expect("extract children");
    let cs: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| {
            std::path::Path::new(&c.handle.relative_path)
                .extension()
                .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("cs"))
        })
        .expect(
            "chain must recover the embedded ironpython assembly as real c# source, not drop it",
        );
    assert!(
        !cs.bytes.is_empty(),
        "recovered c# source must be non-empty"
    );
}
