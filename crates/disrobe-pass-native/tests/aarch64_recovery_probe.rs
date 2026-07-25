#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoScalarType as ScalarType, disassemble,
    recover_aarch64_function,
};
use std::collections::BTreeMap;

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");

const RECOVERY_FLOOR: usize = 360;

type ConversionCase = (
    u32,
    &'static [ScalarType],
    Option<ScalarType>,
    u32,
    &'static str,
);

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
            &[0x00, 0x40, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6],
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

#[test]
fn yaxpeax_scalar_fp_increment_two_rendering_is_faithful() {
    let words: [u32; 19] = [
        0x1e22_2820,
        0x1e65_3883,
        0x1e28_08e6,
        0x1e6b_1949,
        0x1e60_3820,
        0x1e22_0020,
        0x9e62_0062,
        0x1e23_00a4,
        0x9e63_00e6,
        0x1e38_0128,
        0x9e78_016a,
        0x1e39_01ac,
        0x9e79_01ee,
        0x1e22_c020,
        0x1e62_4062,
        0x1e42_e4a4,
        0x1e18_f4e6,
        0x1e23_c020,
        0x1ee2_4062,
    ];
    let bytes: Vec<u8> = words
        .iter()
        .flat_map(|word: &u32| word.to_le_bytes())
        .collect();
    let instructions: Vec<DisasmInsn> =
        disassemble(Arch::Aarch64, 0, &bytes).expect("known scalar fp encodings");
    for insn in &instructions {
        eprintln!("{} {}", insn.mnemonic, insn.operands);
    }
    let rendered: Vec<(&str, &str)> = instructions
        .iter()
        .map(|insn: &DisasmInsn| (insn.mnemonic.as_str(), insn.operands.as_str()))
        .collect();
    let expected: [(&str, &str); 19] = [
        ("fadd", "s0, s1, s2"),
        ("fsub", "d3, d4, d5"),
        ("fmul", "s6, s7, s8"),
        ("fdiv", "d9, d10, d11"),
        ("fsub", "d0, d1, d0"),
        ("scvtf", "s0, w1"),
        ("scvtf", "d2, x3"),
        ("ucvtf", "s4, w5"),
        ("ucvtf", "d6, x7"),
        ("fcvtzs", "w8, s9"),
        ("fcvtzs", "x10, d11"),
        ("fcvtzu", "w12, s13"),
        ("fcvtzu", "x14, d15"),
        ("fcvt", "d0, s1"),
        ("fcvt", "s2, d3"),
        ("scvtf", "d4, w5, #0x7"),
        ("fcvtzs", "w6, s7, #0x3"),
        ("fcvt", "h0, s1"),
        ("fcvt", "s2, h3"),
    ];
    assert_eq!(rendered, expected);
}

#[test]
fn scalar_fp_increment_two_arithmetic_recovers_three_operands() {
    let cases: [(u32, &str, ScalarType); 4] = [
        (
            0x1e21_2800,
            "(fp_f_from_bits((uint32_t)x_xmm0) + fp_f_from_bits((uint32_t)x_xmm1))",
            ScalarType::Float,
        ),
        (
            0x1e60_3820,
            "(fp_d_from_bits(x_xmm1) - fp_d_from_bits(x_xmm0))",
            ScalarType::Double,
        ),
        (
            0x1e61_0800,
            "(fp_d_from_bits(x_xmm0) * fp_d_from_bits(x_xmm1))",
            ScalarType::Double,
        ),
        (
            0x1e61_1800,
            "(fp_d_from_bits(x_xmm0) / fp_d_from_bits(x_xmm1))",
            ScalarType::Double,
        ),
    ];
    for (word, expression, scalar_type) in cases {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("scalar fp arithmetic");
        assert_eq!(
            recovery.fp_params,
            vec![scalar_type, scalar_type],
            "{expression}: {}",
            recovery.source
        );
        assert_eq!(recovery.returns_fp, Some(scalar_type));
        assert!(
            recovery.source.contains(expression),
            "missing `{expression}` in {}",
            recovery.source
        );
    }
}

#[test]
fn scalar_fp_increment_two_conversions_recover_signedness_and_widths() {
    let conversions: [ConversionCase; 10] = [
        (
            0x1e62_0000,
            &[ScalarType::Int],
            Some(ScalarType::Double),
            64,
            "(double)((int32_t)r_rax)",
        ),
        (
            0x1e23_0000,
            &[ScalarType::Int],
            Some(ScalarType::Float),
            32,
            "(float)((uint32_t)r_rax)",
        ),
        (
            0x9e62_0000,
            &[ScalarType::Int],
            Some(ScalarType::Double),
            64,
            "(double)((int64_t)r_rax)",
        ),
        (
            0x9e63_0000,
            &[ScalarType::Int],
            Some(ScalarType::Double),
            64,
            "(double)((uint64_t)r_rax)",
        ),
        (
            0x1e38_0000,
            &[ScalarType::Float],
            None,
            32,
            "(int32_t)(fp_f_from_bits((uint32_t)x_xmm0))",
        ),
        (
            0x1e39_0000,
            &[ScalarType::Float],
            None,
            32,
            "(uint32_t)(fp_f_from_bits((uint32_t)x_xmm0))",
        ),
        (
            0x9e78_0000,
            &[ScalarType::Double],
            None,
            64,
            "(int64_t)(fp_d_from_bits(x_xmm0))",
        ),
        (
            0x9e79_0000,
            &[ScalarType::Double],
            None,
            64,
            "(uint64_t)(fp_d_from_bits(x_xmm0))",
        ),
        (
            0x1e22_c000,
            &[ScalarType::Float],
            Some(ScalarType::Double),
            64,
            "(double)(fp_f_from_bits((uint32_t)x_xmm0))",
        ),
        (
            0x1e62_4000,
            &[ScalarType::Double],
            Some(ScalarType::Float),
            32,
            "(float)(fp_d_from_bits(x_xmm0))",
        ),
    ];
    for (word, params, returns_fp, return_width_bits, expression) in conversions {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("scalar fp conversion");
        assert_eq!(recovery.fp_params, params, "{}", recovery.source);
        assert_eq!(recovery.returns_fp, returns_fp, "{}", recovery.source);
        assert_eq!(
            recovery.return_width_bits, return_width_bits,
            "{}",
            recovery.source
        );
        assert!(
            recovery.source.contains(expression),
            "missing `{expression}` in {}",
            recovery.source
        );
    }
}

#[test]
fn scalar_fp_increment_two_o0_cross_class_returns_recover() {
    let cases: [(&str, u32); 3] = [
        ("fp_to_int_s", 32),
        ("fp_to_uint_s", 32),
        ("fp_to_ulong_d", 64),
    ];
    for (name, return_width_bits) in cases {
        let case: &(&str, &str, &[u8]) = CASES
            .iter()
            .find(|(opt, candidate, _): &&(&str, &str, &[u8])| *opt == "O0" && *candidate == name)
            .expect("generated O0 scalar fp conversion");
        let recovery: LeafRecovery =
            recover_aarch64_function(case.2, 0).expect("O0 scalar fp conversion");
        assert_eq!(recovery.returns_fp, None, "{}", recovery.source);
        assert_eq!(
            recovery.return_width_bits, return_width_bits,
            "{}",
            recovery.source
        );
    }
}

#[test]
fn scalar_fp_increment_two_fixed_point_and_half_forms_reject() {
    let cases: [(u32, &str); 6] = [
        (0x1e42_e400, "fixed-point"),
        (0x1e03_ec00, "fixed-point"),
        (0x1e18_f400, "fixed-point"),
        (0x9e59_dc00, "fixed-point"),
        (0x1e23_c000, "F16"),
        (0x1ee2_4000, "F16"),
    ];
    for (word, reason) in cases {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let error: String = format!(
            "{:?}",
            recover_aarch64_function(&code, 0).expect_err("form must sound-reject")
        );
        assert!(
            error.contains(reason),
            "missing `{reason}` in rejection: {error}"
        );
    }
}

#[test]
fn scalar_fp_increment_two_optimized_average_recovers() {
    let optimization_levels: [&str; 4] = ["O1", "O2", "O3", "Os"];
    for opt in optimization_levels {
        let case: &(&str, &str, &[u8]) = CASES
            .iter()
            .find(
                |(candidate_opt, candidate_name, _): &&(&str, &str, &[u8])| {
                    *candidate_opt == opt && *candidate_name == "fp_iavg"
                },
            )
            .expect("generated optimized fp_iavg");
        let recovery: LeafRecovery =
            recover_aarch64_function(case.2, 0).expect("optimized fp_iavg");
        assert_eq!(recovery.returns_fp, Some(ScalarType::Double));
        assert_eq!(recovery.return_width_bits, 64);
    }
}
