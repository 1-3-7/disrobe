#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{LeafRecovery, PseudoScalarType as ScalarType, recover_aarch64_function};
use std::collections::BTreeMap;

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");

const RECOVERY_FLOOR: usize = 290;

#[test]
fn aarch64_recovery_corpus_meets_the_floor() {
    let mut recovered: usize = 0;
    let mut rejects: BTreeMap<String, usize> = BTreeMap::new();
    for (opt, name, bytes) in CASES {
        match recover_aarch64_function(bytes, 0) {
            Ok(_) => recovered += 1,
            Err(error) => {
                let message: String = format!("{error:?}");
                let tail: &str = message.split("aarch64 reject: ").nth(1).unwrap_or(&message);
                let bucket: String = tail
                    .split(" `")
                    .next()
                    .unwrap_or(tail)
                    .chars()
                    .take(64)
                    .collect();
                *rejects.entry(bucket).or_default() += 1;
                let reason: String = tail.chars().take(90).collect();
                eprintln!("REJECT {opt} {name}: {reason}");
            }
        }
    }
    eprintln!(
        "=== aarch64 recovery {recovered}/{} (non-rejection rate, NOT a correctness claim; see aarch64_recovery_grade) ===",
        CASES.len()
    );
    let mut ordered: Vec<(&String, &usize)> = rejects.iter().collect();
    ordered.sort_by(|left: &(&String, &usize), right: &(&String, &usize)| right.1.cmp(left.1));
    for (bucket, count) in ordered {
        eprintln!("  {count}x  {bucket}");
    }
    assert!(
        recovered >= RECOVERY_FLOOR,
        "aarch64 recovery {recovered}/{} regressed below the floor {RECOVERY_FLOOR}",
        CASES.len()
    );
}

#[test]
fn scalar_fp_increment_one_forms_recover() {
    let move_out: [u8; 8] = [0x00, 0x00, 0x66, 0x9e, 0xc0, 0x03, 0x5f, 0xd6];
    let move_out_recovery: LeafRecovery =
        recover_aarch64_function(&move_out, 0).expect("fmov x0, d0");
    assert_eq!(move_out_recovery.fp_params, vec![ScalarType::Double]);
    assert_eq!(move_out_recovery.returns_fp, None);
    assert_eq!(move_out_recovery.return_width_bits, 64);

    let immediate_d: [u8; 8] = [0x00, 0x10, 0x6e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let immediate_d_recovery: LeafRecovery =
        recover_aarch64_function(&immediate_d, 0).expect("fmov d0, #1.0");
    assert!(immediate_d_recovery.fp_params.is_empty());
    assert_eq!(immediate_d_recovery.returns_fp, Some(ScalarType::Double));

    let immediate_s: [u8; 8] = [0x00, 0x10, 0x2e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let immediate_s_recovery: LeafRecovery =
        recover_aarch64_function(&immediate_s, 0).expect("fmov s0, #1.0");
    assert!(immediate_s_recovery.fp_params.is_empty());
    assert_eq!(immediate_s_recovery.returns_fp, Some(ScalarType::Float));

    let unscaled: [u8; 12] = [
        0x20, 0xc0, 0x5f, 0xbc, 0x20, 0x80, 0x00, 0xfc, 0xc0, 0x03, 0x5f, 0xd6,
    ];
    let unscaled_recovery: LeafRecovery =
        recover_aarch64_function(&unscaled, 0).expect("ldur s0 and stur d0");
    assert_eq!(unscaled_recovery.return_width_bits, 0);
    assert_eq!(unscaled_recovery.returns_fp, None);

    let pair_load: [u8; 8] = [0x20, 0x04, 0xc1, 0x6c, 0xc0, 0x03, 0x5f, 0xd6];
    let pair_load_recovery: LeafRecovery =
        recover_aarch64_function(&pair_load, 0).expect("ldp d0, d1 post-indexed");
    assert_eq!(pair_load_recovery.returns_fp, Some(ScalarType::Double));

    let pair_store: [u8; 8] = [0x40, 0x04, 0xbf, 0x2d, 0xc0, 0x03, 0x5f, 0xd6];
    let pair_store_recovery: LeafRecovery =
        recover_aarch64_function(&pair_store, 0).expect("stp s0, s1 pre-indexed");
    assert_eq!(
        pair_store_recovery.fp_params,
        vec![ScalarType::Float, ScalarType::Float, ScalarType::Int]
    );
    assert_eq!(pair_store_recovery.return_width_bits, 0);
}

#[test]
fn every_scalar_vfp_expand_immediate_decodes_exactly() {
    let forms: [(u32, ScalarType); 2] = [
        (0x1e20_1000_u32, ScalarType::Float),
        (0x1e60_1000_u32, ScalarType::Double),
    ];
    for (base, scalar_type) in forms {
        for imm8 in 0_u8..=u8::MAX {
            let word: u32 = base | (u32::from(imm8) << 13);
            let mut code: Vec<u8> = word.to_le_bytes().to_vec();
            code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
            let recovery: LeafRecovery =
                recover_aarch64_function(&code, 0).expect("legal VFPExpandImm");
            assert_eq!(recovery.returns_fp, Some(scalar_type), "imm8={imm8:#04x}");
        }
    }
}

#[test]
fn scalar_fp_increment_one_boundaries_reject() {
    let cases: [(&[u8], &str); 6] = [
        (&[0x00, 0x41, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6], "v8..v15"),
        (
            &[0x00, 0x42, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6],
            "outside v0..v15",
        ),
        (
            &[0xe0, 0x03, 0x40, 0xfd, 0xc0, 0x03, 0x5f, 0xd6],
            "incoming stack argument",
        ),
        (
            &[
                0x00, 0x00, 0x00, 0xbd, 0x20, 0x00, 0x00, 0xfd, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            "conflicting widths",
        ),
        (
            &[0x00, 0x28, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6],
            "unsupported instruction",
        ),
        (
            &[0xe0, 0x07, 0xbf, 0xad, 0xc0, 0x03, 0x5f, 0xd6],
            "bulk q0..q7",
        ),
    ];
    for (bytes, expected) in cases {
        let error: String = format!(
            "{:?}",
            recover_aarch64_function(bytes, 0).expect_err("form must sound-reject")
        );
        assert!(
            error.contains(expected),
            "unexpected rejection for {bytes:02x?}: {error}"
        );
    }
}
