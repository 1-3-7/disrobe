#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_wasm_deob::{WasmDetection, detect};

const WAT: &str = r#"
(module
  (func $add (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add)
  (export "add" (func $add))
)
"#;

fn build_module() -> Vec<u8> {
    let bytes: Vec<u8> = wat::parse_str(WAT).expect("wat parse");
    assert_eq!(
        &bytes[..4],
        b"\0asm",
        "wat output must carry the wasm magic"
    );
    bytes
}

#[test]
fn intact_module_detects() {
    let module: Vec<u8> = build_module();
    let det: WasmDetection = detect(&module).expect("intact module must detect");
    assert_eq!(det.export_count, 1);
    assert_eq!(det.function_count, 1);
}

#[test]
fn zeroed_magic_module_still_detects_via_section_stream() {
    let module: Vec<u8> = build_module();
    let baseline: WasmDetection = detect(&module).expect("intact module must detect");

    let mut zeroed: Vec<u8> = module;
    zeroed[0..4].copy_from_slice(&[0u8; 4]);
    assert_ne!(&zeroed[..4], b"\0asm");

    let det: WasmDetection = detect(&zeroed)
        .expect("zeroed-magic wasm must still detect via the section id/size stream");
    assert_eq!(det.export_count, baseline.export_count);
    assert_eq!(det.function_count, baseline.function_count);
}

#[test]
fn flipped_magic_module_still_detects() {
    let module: Vec<u8> = build_module();
    let baseline: WasmDetection = detect(&module).expect("intact module must detect");

    let mut flipped: Vec<u8> = module;
    for b in &mut flipped[0..4] {
        *b ^= 0xFF;
    }
    let det: WasmDetection = detect(&flipped).expect("flipped-magic wasm must still detect");
    assert_eq!(det.function_count, baseline.function_count);
}

#[test]
fn non_wasm_bytes_are_still_rejected() {
    let junk: Vec<u8> = vec![0u8; 64];
    assert!(
        detect(&junk).is_err(),
        "zeroed junk that is not a valid section stream must be rejected, not falsely detected"
    );
    let mut almost: Vec<u8> = vec![0xAA, 0xBB, 0xCC, 0xDD];
    almost.extend_from_slice(&2u32.to_le_bytes());
    assert!(
        detect(&almost).is_err(),
        "wrong wasm version with scrambled magic must not be accepted"
    );
}
