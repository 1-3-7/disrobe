#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use disrobe_core::Rung;
use disrobe_ir::io::mmap_envelope_view;
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, InsnEncoding, InsnFlow,
    InsnSegments, IsaTag, MemUse, RawPayload, RegAccess, RegUse, RflagsEffect, StackEffect,
    decode_disasm, decode_raw, encode_disasm, encode_raw,
};
use disrobe_ir::sidecar::Sidecar;
use disrobe_ir::{ENVELOPE_FORMAT_VERSION, Envelope, EnvelopeError, compute_root_hash};
use disrobe_transcode::{
    TRANSCODED_FORMAT_VERSION, TranscodeError, transcode_bytes, transcode_envelope,
    verify_transcode, verify_transcode_envelope,
};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir
}

fn temp_path(stem: &str) -> PathBuf {
    let id: u64 = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    let pid: u32 = std::process::id();
    std::env::temp_dir().join(format!("disrobe-transcode-{stem}-{pid}-{id}.dr"))
}

fn real_corpus_bytes() -> Vec<u8> {
    let root: PathBuf = workspace_root();
    let candidates: [&str; 3] = [
        "corpus/jvm/stringer/uh.class",
        "corpus/lua/luau/edge_cases.luau.bin",
        "corpus/dotnet/HelloApp.r2r.exe",
    ];
    for rel in candidates {
        let p: PathBuf = root.join(rel);
        if p.is_file() {
            let bytes: Vec<u8> = std::fs::read(&p).expect("read corpus fixture");
            assert!(!bytes.is_empty(), "corpus fixture {rel} is empty");
            return bytes;
        }
    }
    panic!("no real corpus fixture found under {}", root.display());
}

fn corpus_path() -> PathBuf {
    let root: PathBuf = workspace_root();
    for rel in [
        "corpus/jvm/stringer/uh.class",
        "corpus/lua/luau/edge_cases.luau.bin",
        "corpus/dotnet/HelloApp.r2r.exe",
    ] {
        let p: PathBuf = root.join(rel);
        if p.is_file() {
            return p;
        }
    }
    panic!("no corpus fixture");
}

fn blake3_of(path: &Path) -> [u8; 32] {
    let bytes: Vec<u8> = std::fs::read(path).expect("read for hash");
    *blake3::hash(&bytes).as_bytes()
}

fn raw_envelope_from_real_bytes() -> (Envelope, RawPayload) {
    let source_bytes: Vec<u8> = real_corpus_bytes();
    let raw: RawPayload = RawPayload {
        source_path: corpus_path().display().to_string(),
        source_bytes,
        source_hash: blake3_of(&corpus_path()),
        detected_format: Some("application/java-vm".to_owned()),
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw");
    let sidecar: Sidecar = Sidecar {
        produced_by: "disrobe-transcode-oracle".to_owned(),
        produced_by_version: "0.9.0".to_owned(),
        capabilities: vec![disrobe_core::Capability::produces("raw-ingest", 1)],
        provenance: std::collections::BTreeMap::from([(
            "fixture".to_owned(),
            "real-corpus".to_owned(),
        )]),
    };
    let cold: Vec<u8> = sidecar.encode().expect("encode sidecar");
    (Envelope::new(Rung::Raw, hot, cold), raw)
}

fn disasm_envelope_from_real_bytes() -> (Envelope, DisasmPayload) {
    let real: Vec<u8> = real_corpus_bytes();
    let source_hash: [u8; 32] = blake3_of(&corpus_path());
    let disasm: DisasmPayload = DisasmPayload {
        source_hash,
        instructions: vec![
            DisasmInstruction {
                offset: 0,
                bytes: real.iter().copied().take(8).collect(),
                mnemonic: "header".to_owned(),
                operands: vec!["magic".to_owned(), "minor".to_owned()],
                flow: InsnFlow::Sequential,
                branch_target: None,
                reg_uses: vec![
                    RegUse {
                        register: "EAX".to_owned(),
                        access: RegAccess::ReadWrite,
                    },
                    RegUse {
                        register: "EBX".to_owned(),
                        access: RegAccess::Read,
                    },
                ],
                mem_uses: vec![MemUse {
                    segment: "SS".to_owned(),
                    base: "RSP".to_owned(),
                    index: "None".to_owned(),
                    scale: 1,
                    displacement: 0xFFFF_FFFF_FFFF_FFF8,
                    memory_size: "UInt64".to_owned(),
                    access: RegAccess::Write,
                }],
                rflags: RflagsEffect {
                    read: 0,
                    written: RflagsEffect::OF | RflagsEffect::CF | RflagsEffect::ZF,
                    cleared: 0,
                    set: 0,
                    undefined: RflagsEffect::AF,
                },
                isa: IsaTag {
                    cpuid_features: vec!["AVX".to_owned(), "AVX2".to_owned()],
                    encoding: InsnEncoding::Vex,
                },
                stack_effect: StackEffect {
                    sp_delta: -8,
                    is_stack: true,
                    fpu_increment: 0,
                    fpu_writes_top: false,
                    fpu_conditional: false,
                },
                segments: InsnSegments {
                    legacy_prefix: 0,
                    opcode: 3,
                    modrm: 1,
                    sib: 0,
                    displacement: 0,
                    immediate: 4,
                },
            },
            DisasmInstruction {
                offset: 8,
                bytes: real.iter().copied().skip(8).take(4).collect(),
                mnemonic: "const_pool".to_owned(),
                operands: vec![],
                flow: InsnFlow::Sequential,
                branch_target: None,
                ..DisasmInstruction::default()
            },
        ],
        symbol_table: vec![
            DisasmSymbol {
                address: 0,
                name: "<clinit>".to_owned(),
                kind: DisasmSymbolKind::Function,
            },
            DisasmSymbol {
                address: 8,
                name: "CONSTANT_pool".to_owned(),
                kind: DisasmSymbolKind::Data,
            },
        ],
    };
    let hot: Vec<u8> = encode_disasm(&disasm).expect("encode disasm");
    let cold: Vec<u8> = Sidecar::default().encode().expect("encode sidecar");
    (Envelope::new(Rung::Disasm, hot, cold), disasm)
}

#[test]
fn raw_transcode_opens_with_canonical_envelope_and_payload_readers() {
    let (env, original_payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode input envelope");

    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode raw");
    assert_eq!(transcoded.source_version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(transcoded.target_version, TRANSCODED_FORMAT_VERSION);
    assert_eq!(transcoded.target_version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(transcoded.rung, Rung::Raw);

    let decoded_env: Envelope = Envelope::decode(&transcoded.bytes).expect("canonical decode");
    assert_eq!(decoded_env.version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(decoded_env.rung, Rung::Raw);
    assert_eq!(decoded_env.cold, env.cold);
    assert_eq!(
        decoded_env.root_hash,
        compute_root_hash(&decoded_env.hot, &decoded_env.cold)
    );

    let recovered: RawPayload = decode_raw(&decoded_env.hot).expect("canonical raw decode");
    assert_eq!(recovered, original_payload);
}

#[test]
fn disasm_transcode_opens_with_canonical_envelope_and_payload_readers() {
    let (env, original_payload): (Envelope, DisasmPayload) = disasm_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode input envelope");

    let transcoded: disrobe_transcode::Transcoded =
        transcode_bytes(&input).expect("transcode disasm");
    assert_eq!(transcoded.rung, Rung::Disasm);
    assert_eq!(transcoded.target_version, ENVELOPE_FORMAT_VERSION);

    let decoded_env: Envelope = Envelope::decode(&transcoded.bytes).expect("canonical decode");
    assert_eq!(decoded_env.version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(decoded_env.rung, Rung::Disasm);
    assert_eq!(decoded_env.cold, env.cold);

    let recovered: DisasmPayload =
        decode_disasm(&decoded_env.hot).expect("canonical disasm decode");
    assert_eq!(recovered, original_payload);
}

#[test]
fn verify_path_uses_canonical_envelope_decode() {
    let (env, _payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    verify_transcode(&input, &transcoded).expect("verify must pass on real corpus");
}

#[test]
fn envelope_path_transcodes_without_rereading_the_source_bytes() {
    let (env, original_payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let transcoded: disrobe_transcode::Transcoded =
        transcode_envelope(&env).expect("transcode envelope");
    verify_transcode_envelope(&env, &transcoded).expect("verify envelope");
    let decoded_env: Envelope = Envelope::decode(&transcoded.bytes).expect("canonical decode");
    let recovered: RawPayload = decode_raw(&decoded_env.hot).expect("canonical raw decode");
    assert_eq!(recovered, original_payload);
    assert_eq!(decoded_env.cold, env.cold);
}

#[test]
fn canonical_mmap_view_opens_transcoded_output() {
    let (env, original_payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    let path: PathBuf = temp_path("mmap");
    std::fs::write(&path, &transcoded.bytes).expect("write transcoded");

    let view: disrobe_ir::io::MmapView = mmap_envelope_view(&path).expect("mmap canonical output");
    assert_eq!(view.version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(view.rung, Rung::Raw);
    assert_eq!(view.cold(), env.cold.as_slice());
    let recovered: RawPayload = decode_raw(view.hot()).expect("decode mmap hot");
    assert_eq!(recovered, original_payload);

    drop(view);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn cold_segment_is_never_touched() {
    let (env, _payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    let decoded_env: Envelope = Envelope::decode(&transcoded.bytes).expect("canonical decode");
    assert_eq!(decoded_env.cold, env.cold);
    assert_eq!(decoded_env.cold.len(), env.cold.len());
}

#[test]
fn verify_rejects_tampered_length_metadata() {
    let (env, _payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let mut transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    transcoded.new_hot_len = transcoded.new_hot_len.saturating_add(1);
    let err: TranscodeError =
        verify_transcode_envelope(&env, &transcoded).expect_err("length metadata mismatch");
    assert!(matches!(err, TranscodeError::VerifyLengthMismatch));
}

#[test]
fn verify_rejects_tampered_version_metadata() {
    let (env, _payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let mut transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    transcoded.target_version = transcoded.target_version.saturating_add(1);
    let err: TranscodeError =
        verify_transcode_envelope(&env, &transcoded).expect_err("target version mismatch");
    assert!(matches!(err, TranscodeError::VerifyTargetVersionMismatch));
}

#[test]
fn unsupported_rung_hard_fails() {
    let env: Envelope = Envelope::new(Rung::Mir, vec![1, 2, 3], vec![4, 5]);
    let input: Vec<u8> = env.encode().expect("encode");
    let err: TranscodeError = transcode_bytes(&input).expect_err("mir has no hot codec");
    assert!(matches!(err, TranscodeError::UnsupportedRung(Rung::Mir)));
}

#[test]
fn oracle_has_teeth_changed_hot_payload_fails_verify() {
    let (env, original_payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let mut changed_payload: RawPayload = original_payload;
    changed_payload.source_path.push_str(".changed");
    let changed_hot: Vec<u8> = encode_raw(&changed_payload).expect("encode changed");
    let changed_env: Envelope = Envelope::new(Rung::Raw, changed_hot, env.cold);
    let mut transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    transcoded.new_hot_len = changed_env.hot.len();
    transcoded.cold_len = changed_env.cold.len();
    transcoded.bytes = changed_env.encode().expect("encode changed envelope");

    let err: TranscodeError =
        verify_transcode(&input, &transcoded).expect_err("changed hot must fail");
    assert!(matches!(err, TranscodeError::VerifyHotPayloadMismatch));
}

#[test]
fn every_canonical_reader_accepts_the_transcoded_version() {
    let (env, original_payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode input");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");

    assert_eq!(TRANSCODED_FORMAT_VERSION, ENVELOPE_FORMAT_VERSION);
    assert_eq!(transcoded.target_version, ENVELOPE_FORMAT_VERSION);

    let via_decode: Envelope =
        Envelope::decode(&transcoded.bytes).expect("in-memory reader accepts transcoded version");
    assert_eq!(via_decode.version, ENVELOPE_FORMAT_VERSION);

    let path: PathBuf = temp_path("readpath");
    std::fs::write(&path, &transcoded.bytes).expect("write transcoded");
    let via_path: Envelope =
        Envelope::read_from_path(&path).expect("path reader accepts transcoded version");
    assert_eq!(via_path.version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(via_path.rung, Rung::Raw);
    let recovered: RawPayload = decode_raw(&via_path.hot).expect("path reader hot decodes");
    assert_eq!(recovered, original_payload);
    let _ = std::fs::remove_file(&path);

    let mut forged: Vec<u8> = transcoded.bytes;
    let version_lo: usize = 8;
    let version_hi: usize = 9;
    forged[version_lo] = 2;
    forged[version_hi] = 0;
    let err: EnvelopeError =
        Envelope::decode(&forged).expect_err("a non-canonical version must be rejected");
    assert!(matches!(err, EnvelopeError::BadVersion(2)));
}

#[test]
#[ignore = "writes a real .dr fixture to a temp path for the bin smoke test"]
fn emit_real_dr_fixture() {
    let (env, _payload): (Envelope, RawPayload) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let out: PathBuf = std::env::temp_dir().join("disrobe_transcode_smoke_in.dr");
    std::fs::write(&out, &input).expect("write fixture");
    println!("WROTE {}", out.display());
}
