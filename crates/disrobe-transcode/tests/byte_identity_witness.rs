#![allow(clippy::expect_used, clippy::panic)]

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use disrobe_core::{Rung, scratch::ScratchDir};
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, RawPayload, encode_disasm, encode_raw,
};
use disrobe_ir::{Envelope, Sidecar, WitnessError, WitnessSidecar, WitnessVerification};

const WITNESS_MAGIC: &[u8; 8] = b"DRWITNS\0";
const WITNESS_VERSION: u16 = 1;
const WITNESS_BYTES: usize = 82;

fn workspace_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn corpus_path() -> PathBuf {
    let root: PathBuf = workspace_root();
    for relative in [
        "corpus/jvm/stringer/uh.class",
        "corpus/lua/luau/edge_cases.luau.bin",
        "corpus/dotnet/HelloApp.r2r.exe",
    ] {
        let candidate: PathBuf = root.join(relative);
        if candidate.is_file() {
            return candidate;
        }
    }
    panic!("no committed real corpus fixture is available")
}

fn append_witness_extension(path: &Path) -> PathBuf {
    let mut name: OsString = path.as_os_str().to_owned();
    name.push(".witness");
    PathBuf::from(name)
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    let field: [u8; 2] = bytes[at..at + 2].try_into().expect("two-byte field");
    u16::from_le_bytes(field)
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    let field: [u8; 4] = bytes[at..at + 4].try_into().expect("four-byte field");
    u32::from_le_bytes(field)
}

fn root_at(bytes: &[u8], at: usize) -> [u8; 32] {
    bytes[at..at + 32].try_into().expect("thirty-two-byte root")
}

fn input_envelope(path: &Path) -> Vec<u8> {
    let source_bytes: Vec<u8> = std::fs::read(path).expect("read real corpus fixture");
    let raw: RawPayload = RawPayload {
        source_path: path.display().to_string(),
        source_hash: *blake3::hash(&source_bytes).as_bytes(),
        source_bytes,
        detected_format: Some("application/java-vm".to_owned()),
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw payload");
    let cold: Vec<u8> = Sidecar::default().encode().expect("encode legacy sidecar");
    Envelope::new(Rung::Raw, hot, cold)
        .encode()
        .expect("encode input envelope")
}

fn disasm_input_envelope(path: &Path) -> Vec<u8> {
    let source_bytes: Vec<u8> = std::fs::read(path).expect("read real corpus fixture");
    let disasm: DisasmPayload = DisasmPayload {
        source_hash: *blake3::hash(&source_bytes).as_bytes(),
        instructions: vec![DisasmInstruction {
            offset: 0,
            bytes: source_bytes.into_iter().take(16).collect(),
            mnemonic: "fixture".to_owned(),
            ..DisasmInstruction::default()
        }],
        symbol_table: Vec::new(),
    };
    let hot: Vec<u8> = encode_disasm(&disasm).expect("encode disasm payload");
    let cold: Vec<u8> = Sidecar::default().encode().expect("encode legacy sidecar");
    Envelope::new(Rung::Disasm, hot, cold)
        .encode()
        .expect("encode input envelope")
}

fn independently_reproduces(witness: &[u8], input: &[u8], output: &[u8]) -> bool {
    witness.len() == WITNESS_BYTES
        && &witness[..8] == WITNESS_MAGIC
        && u16_at(witness, 8) == WITNESS_VERSION
        && u32_at(witness, 10) == 1
        && witness[14..18] == [0, 3, 0, 0]
        && root_at(witness, 18) == *blake3::hash(input).as_bytes()
        && root_at(witness, 50) == *blake3::hash(output).as_bytes()
        && input == output
}

fn run_transcode(input: &Path, output: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_disrobe-transcode"))
        .arg(input)
        .arg(output)
        .arg("--verify")
        .output()
        .expect("run trusted transcode binary")
}

#[test]
fn command_emits_an_exact_byte_identity_witness_for_a_real_corpus_envelope() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-transcode-byte-witness").expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("input.dr");
    let output_path: PathBuf = scratch.path().join("output.dr");
    let witness_path: PathBuf = append_witness_extension(&output_path);
    let input_bytes: Vec<u8> = input_envelope(&corpus_path());
    std::fs::write(&input_path, &input_bytes).expect("write input envelope");

    let command: Output = run_transcode(&input_path, &output_path);
    assert!(
        command.status.success(),
        "transcode failed: {}",
        String::from_utf8_lossy(&command.stderr)
    );
    assert!(
        String::from_utf8_lossy(&command.stdout)
            .contains(&format!("witness={}", witness_path.display())),
        "witness path is not discoverable: {}",
        String::from_utf8_lossy(&command.stdout)
    );
    let output_bytes: Vec<u8> = std::fs::read(&output_path).expect("read transcoded envelope");
    let witness_bytes: Vec<u8> = std::fs::read(&witness_path).expect("read emitted witness");

    assert_eq!(witness_bytes.len(), WITNESS_BYTES);
    assert_eq!(&witness_bytes[..8], WITNESS_MAGIC);
    assert_eq!(u16_at(&witness_bytes, 8), WITNESS_VERSION);
    assert_eq!(u32_at(&witness_bytes, 10), 1);
    assert_eq!(&witness_bytes[14..18], &[0, 3, 0, 0]);
    assert_eq!(
        root_at(&witness_bytes, 18),
        *blake3::hash(&input_bytes).as_bytes()
    );
    assert_eq!(
        root_at(&witness_bytes, 50),
        *blake3::hash(&output_bytes).as_bytes()
    );
    assert_eq!(
        input_bytes, output_bytes,
        "an exact witness requires byte identity"
    );
    assert!(independently_reproduces(
        &witness_bytes,
        &input_bytes,
        &output_bytes
    ));

    let repeated: Output = run_transcode(&input_path, &output_path);
    assert!(repeated.status.success());
    let repeated_witness: Vec<u8> = std::fs::read(&witness_path).expect("read overwritten witness");
    assert_eq!(repeated_witness, witness_bytes);
    let entries: usize = std::fs::read_dir(scratch.path())
        .expect("read scratch directory")
        .count();
    assert_eq!(entries, 3, "transaction left staging or backup files");
}

#[test]
fn command_emits_an_exact_witness_for_a_disasm_envelope() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-transcode-disasm-witness").expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("input.dr");
    let output_path: PathBuf = scratch.path().join("output.dr");
    let input_bytes: Vec<u8> = disasm_input_envelope(&corpus_path());
    std::fs::write(&input_path, &input_bytes).expect("write disasm envelope");

    let command: Output = run_transcode(&input_path, &output_path);
    assert!(command.status.success());
    let output_bytes: Vec<u8> = std::fs::read(&output_path).expect("read disasm output");
    let witness_bytes: Vec<u8> =
        std::fs::read(append_witness_extension(&output_path)).expect("read disasm witness");
    assert!(independently_reproduces(
        &witness_bytes,
        &input_bytes,
        &output_bytes
    ));
}

#[test]
fn verifier_refuses_an_independently_tampered_transcode_output() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-transcode-tampered-witness").expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("input.dr");
    let output_path: PathBuf = scratch.path().join("output.dr");
    let input_bytes: Vec<u8> = input_envelope(&corpus_path());
    std::fs::write(&input_path, &input_bytes).expect("write input envelope");
    let command: Output = run_transcode(&input_path, &output_path);
    assert!(command.status.success());
    let mut output_bytes: Vec<u8> = std::fs::read(&output_path).expect("read transcoded envelope");
    let witness_bytes: Vec<u8> =
        std::fs::read(append_witness_extension(&output_path)).expect("read emitted witness");
    let witness: WitnessSidecar =
        WitnessSidecar::decode(&witness_bytes).expect("decode emitted witness");
    assert_eq!(
        witness
            .verify(&input_bytes, &output_bytes)
            .expect("verify exact output"),
        WitnessVerification::Reproduced
    );

    let last: usize = output_bytes.len() - 1;
    output_bytes[last] ^= 0x01;
    assert!(!independently_reproduces(
        &witness_bytes,
        &input_bytes,
        &output_bytes
    ));
    assert_eq!(
        witness
            .verify(&input_bytes, &output_bytes)
            .expect("classify tampered output"),
        WitnessVerification::NotReproduced
    );
}

#[test]
fn command_does_not_publish_output_when_the_witness_target_is_invalid() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-transcode-witness-failure").expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("input.dr");
    let output_path: PathBuf = scratch.path().join("output.dr");
    let witness_path: PathBuf = append_witness_extension(&output_path);
    let input_bytes: Vec<u8> = input_envelope(&corpus_path());
    std::fs::write(&input_path, input_bytes).expect("write input envelope");
    std::fs::create_dir(&witness_path).expect("create invalid witness target");

    let command: Output = run_transcode(&input_path, &output_path);
    assert!(!command.status.success());
    assert!(!output_path.exists());
    assert!(witness_path.is_dir());
}

#[test]
fn decoder_refuses_empty_and_oversized_witness_sets_before_record_allocation() {
    let mut empty: Vec<u8> = Vec::from(WITNESS_MAGIC.as_slice());
    empty.extend_from_slice(&WITNESS_VERSION.to_le_bytes());
    empty.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(WitnessSidecar::decode(&empty), Err(WitnessError::Empty));

    let mut oversized: Vec<u8> = Vec::from(WITNESS_MAGIC.as_slice());
    oversized.extend_from_slice(&WITNESS_VERSION.to_le_bytes());
    oversized.extend_from_slice(&65_537u32.to_le_bytes());
    assert_eq!(
        WitnessSidecar::decode(&oversized),
        Err(WitnessError::RecordLimit {
            actual: 65_537,
            max: 65_536,
        })
    );
}

#[test]
fn command_refuses_to_claim_exact_identity_for_trailing_input_bytes() {
    let scratch: ScratchDir =
        ScratchDir::create("disrobe-transcode-trailing-witness").expect("create scratch directory");
    let input_path: PathBuf = scratch.path().join("input.dr");
    let output_path: PathBuf = scratch.path().join("output.dr");
    let mut input_bytes: Vec<u8> = input_envelope(&corpus_path());
    input_bytes.push(0xA5);
    std::fs::write(&input_path, input_bytes).expect("write noncanonical input envelope");

    let command: Output = run_transcode(&input_path, &output_path);
    assert!(!command.status.success());
    assert!(
        String::from_utf8_lossy(&command.stderr)
            .contains("byte-identity witness input and output differ"),
        "unexpected refusal: {}",
        String::from_utf8_lossy(&command.stderr)
    );
    assert!(!output_path.exists());
    assert!(!append_witness_extension(&output_path).exists());
}
