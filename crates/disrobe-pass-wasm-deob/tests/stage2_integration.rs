#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    clippy::cast_possible_truncation
)]

use disrobe_pass_wasm_deob::{
    BaseOrigin, FunctionCfg, RecoveredType, SsaFunction, build_function_cfg, build_ssa,
    recover_types,
};
use wasmparser::{Parser, Payload, ValType};

fn sum_struct_module() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    out.extend_from_slice(&[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]);
    out.extend_from_slice(&[0x01, 0x06, 0x01, 0x60, 0x01, 0x7f, 0x01, 0x7f]);
    out.extend_from_slice(&[0x03, 0x02, 0x01, 0x00]);
    out.extend_from_slice(&[0x05, 0x03, 0x01, 0x00, 0x01]);
    let body: [u8; 19] = [
        0x00, 0x20, 0x00, 0x28, 0x02, 0x00, 0x20, 0x00, 0x28, 0x02, 0x04, 0x6a, 0x20, 0x00, 0x28,
        0x02, 0x08, 0x6a, 0x0b,
    ];
    out.extend_from_slice(&[0x0a, 0x15, 0x01]);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}

#[test]
fn end_to_end_sum_struct_recovers_three_field_aggregate() {
    let bytes: Vec<u8> = sum_struct_module();
    let mut visited_body: bool = false;

    for payload in Parser::new(0).parse_all(&bytes) {
        let payload: Payload<'_> = payload.expect("payload parses");
        if let Payload::CodeSectionEntry(body) = payload {
            let cfg: FunctionCfg = build_function_cfg(&body).expect("cfg builds");
            assert!(!cfg.blocks.is_empty(), "cfg must yield at least one block");

            let params: &[ValType] = &[ValType::I32];
            let ssa: SsaFunction = build_ssa(&cfg, &body, params).expect("ssa builds");
            assert!(!ssa.blocks.is_empty(), "ssa must yield at least one block");
            assert!(
                ssa.values
                    .iter()
                    .any(|v| matches!(v, disrobe_pass_wasm_deob::ValueDef::Load { .. })),
                "ssa must contain at least one Load value"
            );

            let recovered: Vec<(BaseOrigin, RecoveredType)> =
                recover_types(&ssa).expect("type recovery accepts the tracked SSA");
            assert!(!recovered.is_empty(), "must recover at least one aggregate");

            let param_aggregate: &RecoveredType = recovered
                .iter()
                .find(|(b, _)| matches!(b, BaseOrigin::Param(0)))
                .map(|(_, rt)| rt)
                .or_else(|| recovered.first().map(|(_, rt)| rt))
                .expect("must have aggregate over param 0 or first cluster");

            match param_aggregate {
                RecoveredType::Struct { fields } => {
                    assert_eq!(fields.len(), 3, "expected 3 fields, got {fields:?}");
                    let mut offsets: Vec<i32> = fields.iter().map(|f| f.offset).collect();
                    offsets.sort_unstable();
                    assert_eq!(offsets, vec![0, 4, 8]);
                    assert!(
                        fields.iter().all(|f| f.width == 4),
                        "every field must be 4-byte (i32)"
                    );
                }
                RecoveredType::Array {
                    elem_size: 4,
                    count: Some(3),
                } => {}
                other => panic!("expected Struct of 3 i32s or Array(i32, 3), got {other:?}"),
            }
            visited_body = true;
        }
    }
    assert!(visited_body, "module must contain a code body");
}
