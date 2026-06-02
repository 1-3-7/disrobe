#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_wasm_deob::{
    CrypticBytesDetection, CrypticBytesPeel, detect_cryptic_bytes, peel_cryptic_bytes,
};

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

#[test]
fn peel_xor_layer_emits_cleaned_module_bytes() {
    let bytes: Vec<u8> = wat::parse_str(CRYPTIC_WAT).expect("parse wat");
    let peel: CrypticBytesPeel = peel_cryptic_bytes(&bytes).expect("peel");
    assert!(peel.peeled_layer_bytes > 0);
    assert_eq!(&peel.cleaned_bytes[..4], b"\0asm");
}
