#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
use disrobe_pass_wasm_deob::{
    CalleeNames, FunctionSig, LiftResult, LiftTarget, analyze_module, lift_function_body,
    recover_gc_types, scan_simd, scan_threads,
};
use wasmparser::{FunctionBody, Parser, Payload, ValType};

#[test]
fn truncated_magic_is_err_not_panic() {
    for n in 0..8usize {
        let bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00][..n].to_vec();
        let _ = analyze_module(&bytes);
    }
}

#[test]
fn oversized_section_length_is_err() {
    let mut bytes: Vec<u8> = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
    bytes.push(0x01);
    bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);
    let r = analyze_module(&bytes);
    assert!(r.is_err(), "oversized vec must error, got {r:?}");
}

#[test]
fn random_bytes_never_panic() {
    let mut state: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..200 {
        let len: usize = (state % 256) as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(len + 8);
        buf.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            buf.push((state >> 33) as u8);
        }
        let _ = analyze_module(&buf);
        let _ = recover_gc_types(&buf);
        let _ = scan_simd(&buf);
        let _ = scan_threads(&buf);
    }
}

#[test]
fn deeply_nested_expression_lift_does_not_overflow_stack() {
    let depth: usize = 30_000;
    let mut wat: String = String::from("(module (func (param i32) (result i32) local.get 0");
    for _ in 0..depth {
        wat.push_str(" i32.const 1 i32.add");
    }
    wat.push_str("))");
    let bytes: Vec<u8> = wat::parse_str(&wat).expect("wat");
    let sig: FunctionSig = FunctionSig {
        name: "deep".to_owned(),
        params: vec![ValType::I32],
        results: vec![ValType::I32],
        exported: false,
        imported: false,
        local_names: Vec::new(),
    };
    let callees: CalleeNames = CalleeNames::new(Vec::new());
    for payload in Parser::new(0).parse_all(&bytes) {
        if let Ok(Payload::CodeSectionEntry(body)) = payload {
            let body: FunctionBody<'_> = body;
            for t in [LiftTarget::Rust, LiftTarget::Wat, LiftTarget::C] {
                let out: LiftResult = lift_function_body(&body, &sig, &callees, t);
                assert!(!out.pseudo_source.is_empty());
            }
        }
    }
}

#[test]
fn deeply_nested_blocks_do_not_overflow_stack() {
    let depth: usize = 5_000;
    let mut wat: String = String::from("(module (func");
    for _ in 0..depth {
        wat.push_str(" block");
    }
    for _ in 0..depth {
        wat.push_str(" end");
    }
    wat.push_str("))");
    if let Ok(bytes) = wat::parse_str(&wat) {
        let _ = analyze_module(&bytes);
        let _ = recover_gc_types(&bytes);
    }
}
