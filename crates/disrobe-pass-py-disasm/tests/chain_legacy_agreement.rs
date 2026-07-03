#![cfg(feature = "chain")]
#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_core::chain::Pass;
use disrobe_core::{Artifact, Capability, LegacyPass, Rung};
use disrobe_ir::{Envelope, RawPayload, encode_raw};
use disrobe_pass_py_disasm::chain_detector::PY_DISASM_PASS;
use disrobe_pass_py_disasm::pass::{
    PASS_INPUT_PATH_CAP, PyDisasmPass as LegacyDisasmPass, PyDisasmPassReport,
};

const X64_NATIVE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_x64.mpy");
const ARMV7M_NATIVE: &[u8] =
    include_bytes!("../../../corpus/python/alt_runtimes/micropython/hello_native_armv7m.mpy");

fn legacy_report(bytes: &[u8]) -> PyDisasmPassReport {
    let raw: RawPayload = RawPayload {
        source_path: "fixture.mpy".to_owned(),
        source_bytes: bytes.to_vec(),
        source_hash: [0u8; 32],
        detected_format: None,
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
    let envelope: Vec<u8> = Envelope::new(Rung::Raw, hot, vec![])
        .encode()
        .expect("encode envelope");
    let input: Artifact = Artifact::with_capabilities(
        Rung::Raw,
        envelope,
        [Capability::produces(PASS_INPUT_PATH_CAP, 1)],
        [7u8; 32],
    );
    let out: Artifact = LegacyDisasmPass.run(&input).expect("legacy run");
    serde_json::from_slice(&out.envelope).expect("decode report")
}

fn chain_disasm_text(bytes: &[u8]) -> String {
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes.to_vec(), [9u8; 32]);
    let out: Artifact = PY_DISASM_PASS.run(&artifact).expect("chain run");
    String::from_utf8(out.envelope.as_slice().to_vec()).expect("utf8")
}

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
fn chain_and_legacy_emit_identical_native_listing() {
    for fixture in [X64_NATIVE, ARMV7M_NATIVE] {
        let legacy: PyDisasmPassReport = legacy_report(fixture);
        let chain_text: String = chain_disasm_text(fixture);
        assert_eq!(
            legacy.runtime, "micropython-native",
            "legacy must label the runtime"
        );
        assert_eq!(
            legacy.disasm_text, chain_text,
            "chain mode and legacy mode must produce byte-identical native disassembly"
        );
        assert!(
            legacy.instruction_count > 0,
            "legacy must recover real instructions, not wall"
        );
    }
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
    use disrobe_core::chain::detection::ChildArtifact;

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
