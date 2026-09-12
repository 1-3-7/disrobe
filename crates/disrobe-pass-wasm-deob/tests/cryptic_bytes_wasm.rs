#![allow(clippy::expect_used, clippy::unwrap_used)]
use disrobe_pass_wasm_deob::{
    CrypticBytesDetection, CrypticBytesPeel, detect_cryptic_bytes, peel_cryptic_bytes,
};
use walrus::{Module, ModuleConfig};
use wasmparser::{Parser, Payload};

const CRYPTIC_WAT: &str = r#"
    (module
      (memory 1)
      (data (i32.const 0) "randomx-cryptonight-monero")
      (func (export "decrypt") (param i32) (result i32)
        (local i32)
        local.get 0
        local.set 1
        i32.const 0xCAFEBABE
        drop
        (loop $l
          local.get 1
          i32.const 0x42
          i32.xor
          local.set 1
          local.get 1
          i32.const 0
          i32.ne
          br_if $l)
        local.get 1))
"#;

#[test]
fn detects_cafebabe_xor_loop_and_xmr_keywords() {
    let bytes: Vec<u8> = wat::parse_str(CRYPTIC_WAT).expect("parse wat");
    let det: CrypticBytesDetection = detect_cryptic_bytes(&bytes).expect("detect");
    assert!(det.matched, "cryptic-bytes signature must match: {det:?}");
    assert!(det.cafe_constant_hits >= 1);
    assert!(det.xor_loops_detected >= 1);
    assert!(det.xmr_keyword_hits.get("randomx").copied().unwrap_or(0) >= 1);
    assert!(det.xor_keys.contains(&0x42));
}

fn parse_module(wasm: &[u8]) -> Module {
    let mut config: ModuleConfig = ModuleConfig::new();
    config.generate_producers_section(false);
    Module::from_buffer_with_config(wasm, &config).expect("walrus parse")
}

fn data_segment_bytes(wasm: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for payload in Parser::new(0).parse_all(wasm) {
        if let Payload::DataSection(reader) = payload.expect("payload") {
            for seg in reader {
                out.extend_from_slice(seg.expect("data segment").data);
            }
        }
    }
    out
}

#[test]
fn peel_xor_layer_recovers_byte_exact_plaintext_module() {
    const XOR_KEY: u8 = 0x42u8;
    let plaintext: Vec<u8> = {
        let parsed: Vec<u8> = wat::parse_str(CRYPTIC_WAT).expect("parse wat");
        parse_module(&parsed).emit_wasm()
    };

    let encrypted: Vec<u8> = {
        let mut module: Module = parse_module(&plaintext);
        let data_ids: Vec<walrus::DataId> = module.data.iter().map(walrus::Data::id).collect();
        for did in data_ids {
            let data: &mut walrus::Data = module.data.get_mut(did);
            for byte in &mut data.value {
                *byte ^= XOR_KEY;
            }
        }
        module.emit_wasm()
    };
    assert_ne!(
        plaintext, encrypted,
        "encrypting the payload must change the bytes"
    );

    let peel: CrypticBytesPeel = peel_cryptic_bytes(&encrypted).expect("peel");
    assert!(peel.peeled_layer_bytes > 0);
    assert_eq!(
        peel.cleaned_bytes, plaintext,
        "peeled module must be byte-identical to the original plaintext module"
    );
    wasmparser::validate(&peel.cleaned_bytes).expect("recovered module must validate as wasm");
    assert!(
        data_segment_bytes(&peel.cleaned_bytes)
            .windows(b"randomx".len())
            .any(|w: &[u8]| w == b"randomx"),
        "decrypted data segment must expose the original miner payload"
    );
}
