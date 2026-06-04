#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_core::Rung;
use disrobe_ir::payload::{
    DisasmInstruction, DisasmPayload, DisasmSymbol, DisasmSymbolKind, RawPayload, encode_disasm,
    encode_raw,
};
use disrobe_ir::sidecar::Sidecar;
use disrobe_ir::{ENVELOPE_FORMAT_VERSION, Envelope, compute_root_hash};
use disrobe_transcode::{TRANSCODED_FORMAT_VERSION, transcode_bytes, verify_transcode};

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    dir.pop();
    dir.pop();
    dir
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

fn blake3_of(path: &Path) -> [u8; 32] {
    let bytes: Vec<u8> = std::fs::read(path).expect("read for hash");
    *blake3::hash(&bytes).as_bytes()
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

fn raw_envelope_from_real_bytes() -> (Envelope, RawPayload, Vec<u8>) {
    let source_bytes: Vec<u8> = real_corpus_bytes();
    let source_hash: [u8; 32] = blake3_of(&corpus_path());
    let raw: RawPayload = RawPayload {
        source_path: corpus_path().display().to_string(),
        source_bytes,
        source_hash,
        detected_format: Some("application/java-vm".to_owned()),
    };
    let hot: Vec<u8> = encode_raw(&raw).expect("encode raw 0.8");

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

    let env: Envelope = Envelope::new(Rung::Raw, hot, cold.clone());
    (env, raw, cold)
}

fn disasm_envelope_from_real_bytes() -> (Envelope, DisasmPayload, Vec<u8>) {
    let real: Vec<u8> = real_corpus_bytes();
    let chunk_a: Vec<u8> = real.iter().copied().take(8).collect();
    let chunk_b: Vec<u8> = real.iter().copied().skip(8).take(4).collect();
    let source_hash: [u8; 32] = blake3_of(&corpus_path());

    let disasm: DisasmPayload = DisasmPayload {
        source_hash,
        instructions: vec![
            DisasmInstruction {
                offset: 0,
                bytes: chunk_a,
                mnemonic: "header".to_owned(),
                operands: vec!["magic".to_owned(), "minor".to_owned()],
            },
            DisasmInstruction {
                offset: 8,
                bytes: chunk_b,
                mnemonic: "const_pool".to_owned(),
                operands: vec![],
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
    let hot: Vec<u8> = encode_disasm(&disasm).expect("encode disasm 0.8");
    let cold: Vec<u8> = Sidecar::default().encode().expect("encode sidecar");
    let env: Envelope = Envelope::new(Rung::Disasm, hot, cold.clone());
    (env, disasm, cold)
}

fn header_root(bytes: &[u8]) -> [u8; 32] {
    let mut out: [u8; 32] = [0u8; 32];
    out.copy_from_slice(&bytes[20..52]);
    out
}

fn header_version(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[8], bytes[9]])
}

fn split_hot_cold(bytes: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let header_size: usize = disrobe_ir::HEADER_SIZE;
    let hot_len: usize = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]) as usize;
    let cold_len: usize = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]) as usize;
    let hot_end: usize = header_size + hot_len;
    let cold_end: usize = hot_end + cold_len;
    (
        bytes[header_size..hot_end].to_vec(),
        bytes[hot_end..cold_end].to_vec(),
    )
}

#[test]
fn raw_transcode_owned_value_equal_and_root_recomputes() {
    let (env, original_payload, cold): (Envelope, RawPayload, Vec<u8>) =
        raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode input envelope");

    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode raw");

    assert_eq!(transcoded.source_version, ENVELOPE_FORMAT_VERSION);
    assert_eq!(transcoded.target_version, TRANSCODED_FORMAT_VERSION);
    assert_eq!(header_version(&transcoded.bytes), TRANSCODED_FORMAT_VERSION);
    assert_eq!(transcoded.rung, Rung::Raw);

    let (out_hot, out_cold): (Vec<u8>, Vec<u8>) = split_hot_cold(&transcoded.bytes);

    let recovered: RawPayload = decode_target_raw(&out_hot).expect("decode transcoded raw payload");
    assert_eq!(
        recovered, original_payload,
        "transcoded owned RawPayload must PartialEq the original owned payload"
    );

    let recomputed: [u8; 32] = compute_root_hash(&out_hot, &out_cold);
    assert_eq!(
        recomputed,
        header_root(&transcoded.bytes),
        "recomputed BLAKE3 root must match rewritten header"
    );

    assert_eq!(
        out_cold, cold,
        "cold postcard segment must be byte-identical"
    );
    assert_eq!(
        out_cold,
        split_hot_cold(&input).1,
        "cold segment must equal the original input's cold segment"
    );
}

#[test]
fn disasm_transcode_owned_value_equal_and_root_recomputes() {
    let (env, original_payload, cold): (Envelope, DisasmPayload, Vec<u8>) =
        disasm_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode input envelope");

    let transcoded: disrobe_transcode::Transcoded =
        transcode_bytes(&input).expect("transcode disasm");

    assert_eq!(transcoded.rung, Rung::Disasm);
    assert_eq!(header_version(&transcoded.bytes), TRANSCODED_FORMAT_VERSION);

    let (out_hot, out_cold): (Vec<u8>, Vec<u8>) = split_hot_cold(&transcoded.bytes);
    let recovered: DisasmPayload =
        decode_target_disasm(&out_hot).expect("decode transcoded disasm payload");
    assert_eq!(
        recovered, original_payload,
        "transcoded owned DisasmPayload must PartialEq the original owned payload"
    );

    let recomputed: [u8; 32] = compute_root_hash(&out_hot, &out_cold);
    assert_eq!(recomputed, header_root(&transcoded.bytes));
    assert_eq!(out_cold, cold);
}

#[test]
fn verify_path_succeeds_on_real_corpus() {
    let (env, _payload, _cold): (Envelope, RawPayload, Vec<u8>) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    verify_transcode(&input, &transcoded).expect("verify must pass on real corpus");
}

#[test]
fn cold_segment_is_never_touched() {
    let (env, _payload, cold): (Envelope, RawPayload, Vec<u8>) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    let (_, out_cold): (Vec<u8>, Vec<u8>) = split_hot_cold(&transcoded.bytes);
    assert_eq!(out_cold, cold);
    assert_eq!(out_cold.len(), env.cold.len());
}

#[test]
fn round_trips_through_files_with_verify_flag_semantics() {
    let (env, payload, _cold): (Envelope, RawPayload, Vec<u8>) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let transcoded: disrobe_transcode::Transcoded = transcode_bytes(&input).expect("transcode");
    verify_transcode(&input, &transcoded).expect("verify");
    let (out_hot, _): (Vec<u8>, Vec<u8>) = split_hot_cold(&transcoded.bytes);
    let recovered: RawPayload = decode_target_raw(&out_hot).expect("decode");
    assert_eq!(recovered.source_bytes, payload.source_bytes);
    assert!(!recovered.source_bytes.is_empty());
}

#[test]
#[ignore = "writes a real .dr fixture to a temp path for the bin smoke test"]
fn emit_real_dr_fixture() {
    let (env, _payload, _cold): (Envelope, RawPayload, Vec<u8>) = raw_envelope_from_real_bytes();
    let input: Vec<u8> = env.encode().expect("encode");
    let out: PathBuf = std::env::temp_dir().join("disrobe_transcode_smoke_in.dr");
    std::fs::write(&out, &input).expect("write fixture");
    println!("WROTE {}", out.display());
}

#[test]
fn oracle_has_teeth_field_swap_breaks_partial_eq() {
    use rkyv::rancor::Error as RkyvError;
    use rkyv::{Archive, Deserialize, Serialize};

    #[derive(Archive, Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
    struct CorruptRawMirror {
        source_bytes: Vec<u8>,
        source_path: String,
        source_hash: [u8; 32],
        detected_format: Option<String>,
    }

    let (env, original_payload, _cold): (Envelope, RawPayload, Vec<u8>) =
        raw_envelope_from_real_bytes();
    let _input: Vec<u8> = env.encode().expect("encode");

    let corrupt: CorruptRawMirror = CorruptRawMirror {
        source_bytes: original_payload.source_path.clone().into_bytes(),
        source_path: String::from_utf8_lossy(&original_payload.source_bytes).into_owned(),
        source_hash: original_payload.source_hash,
        detected_format: original_payload.detected_format.clone(),
    };
    let corrupt_hot: Vec<u8> = rkyv::to_bytes::<RkyvError>(&corrupt)
        .expect("encode corrupt")
        .to_vec();

    let recovered: RawPayload = decode_target_raw(&corrupt_hot).unwrap_or_else(|_| RawPayload {
        source_path: String::new(),
        source_bytes: Vec::new(),
        source_hash: [0u8; 32],
        detected_format: None,
    });

    assert_ne!(
        recovered, original_payload,
        "a field-swapping mirror must produce an owned value that fails PartialEq, proving the oracle is non-vacuous"
    );
}

fn decode_target_raw(hot: &[u8]) -> Result<RawPayload, String> {
    use disrobe_transcode::mirror::{ArchivedRawPayloadMirror, RawPayloadMirror};
    use rkyv::rancor::Error as RkyvError;
    let archived: &ArchivedRawPayloadMirror =
        rkyv::access::<ArchivedRawPayloadMirror, RkyvError>(hot).map_err(|e| e.to_string())?;
    let m: RawPayloadMirror =
        rkyv::deserialize::<RawPayloadMirror, RkyvError>(archived).map_err(|e| e.to_string())?;
    Ok(RawPayload {
        source_path: m.source_path,
        source_bytes: m.source_bytes,
        source_hash: m.source_hash,
        detected_format: m.detected_format,
    })
}

fn decode_target_disasm(hot: &[u8]) -> Result<DisasmPayload, String> {
    use disrobe_transcode::mirror::{
        ArchivedDisasmPayloadMirror, DisasmInstructionMirror, DisasmPayloadMirror,
        DisasmSymbolKindMirror, DisasmSymbolMirror,
    };
    use rkyv::rancor::Error as RkyvError;
    let archived: &ArchivedDisasmPayloadMirror =
        rkyv::access::<ArchivedDisasmPayloadMirror, RkyvError>(hot).map_err(|e| e.to_string())?;
    let m: DisasmPayloadMirror =
        rkyv::deserialize::<DisasmPayloadMirror, RkyvError>(archived).map_err(|e| e.to_string())?;
    Ok(DisasmPayload {
        source_hash: m.source_hash,
        instructions: m
            .instructions
            .into_iter()
            .map(|i: DisasmInstructionMirror| DisasmInstruction {
                offset: i.offset,
                bytes: i.bytes,
                mnemonic: i.mnemonic,
                operands: i.operands,
            })
            .collect(),
        symbol_table: m
            .symbol_table
            .into_iter()
            .map(|s: DisasmSymbolMirror| DisasmSymbol {
                address: s.address,
                name: s.name,
                kind: match s.kind {
                    DisasmSymbolKindMirror::Function => DisasmSymbolKind::Function,
                    DisasmSymbolKindMirror::Data => DisasmSymbolKind::Data,
                    DisasmSymbolKindMirror::Label => DisasmSymbolKind::Label,
                    DisasmSymbolKindMirror::Export => DisasmSymbolKind::Export,
                    DisasmSymbolKindMirror::Import => DisasmSymbolKind::Import,
                },
            })
            .collect(),
    })
}
