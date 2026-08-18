#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use disrobe_pass_native::{
    Arch, DisasmInsn, LeafRecovery, PseudoScalarType as ScalarType, disassemble,
    recover_aarch64_function,
};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::process::Command;

const CASES: &[(&str, &str, &[u8])] = &include!("aarch64_recovery_corpus.inc");

const RECOVERY_FLOOR: usize = 1247;

type ConversionCase = (
    u32,
    &'static [ScalarType],
    Option<ScalarType>,
    u32,
    &'static str,
);

fn host_c_compiler() -> String {
    ["gcc", "clang", "cc"]
        .into_iter()
        .find(|candidate: &&str| {
            Command::new(candidate)
                .arg("--version")
                .output()
                .is_ok_and(|output: std::process::Output| output.status.success())
        })
        .map(str::to_owned)
        .expect("F16 compiler grade requires clang, gcc, or cc")
}

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
    assert_eq!(
        move_out_recovery.signature.parameter_types(),
        vec![ScalarType::Double]
    );
    assert_eq!(move_out_recovery.returns_fp, None);
    assert_eq!(move_out_recovery.return_width_bits, 64);

    let immediate_d: [u8; 8] = [0x00, 0x10, 0x6e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let immediate_d_recovery: LeafRecovery =
        recover_aarch64_function(&immediate_d, 0).expect("fmov d0, #1.0");
    assert!(immediate_d_recovery.signature.parameter_types().is_empty());
    assert_eq!(immediate_d_recovery.returns_fp, Some(ScalarType::Double));

    let immediate_s: [u8; 8] = [0x00, 0x10, 0x2e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];
    let immediate_s_recovery: LeafRecovery =
        recover_aarch64_function(&immediate_s, 0).expect("fmov s0, #1.0");
    assert!(immediate_s_recovery.signature.parameter_types().is_empty());
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
        pair_store_recovery.signature.parameter_types(),
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
fn scalar_fp_increment_one_boundaries_are_classified() {
    let cases: [(&[u8], &str); 5] = [
        (
            &[0x00, 0x41, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6],
            "volatile scratch rather than an argument register",
        ),
        (
            &[0x00, 0x42, 0x60, 0x1e, 0xc0, 0x03, 0x5f, 0xd6],
            "volatile scratch rather than an argument register",
        ),
        (
            &[0xe0, 0x03, 0x40, 0xfd, 0xc0, 0x03, 0x5f, 0xd6],
            "stack floating parameters require a complete v0-v7 argument prefix",
        ),
        (
            &[
                0x00, 0x00, 0x00, 0xbd, 0x20, 0x00, 0x00, 0xfd, 0xc0, 0x03, 0x5f, 0xd6,
            ],
            "conflicting widths",
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

    let recovery: LeafRecovery =
        recover_aarch64_function(&[0x00, 0x48, 0x61, 0x1e, 0xc0, 0x03, 0x5f, 0xd6], 0)
            .expect("scalar fmax must recover");
    assert_eq!(
        recovery.signature.parameter_types(),
        vec![ScalarType::Double, ScalarType::Double]
    );
    assert_eq!(recovery.returns_fp, Some(ScalarType::Double));
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
            recovery.signature.parameter_types(),
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
            "fpx_cvtsat_i32_f32((fp_f_from_bits((uint32_t)x_xmm0)))",
        ),
        (
            0x1e39_0000,
            &[ScalarType::Float],
            None,
            32,
            "fpx_cvtsat_u32_f32((fp_f_from_bits((uint32_t)x_xmm0)))",
        ),
        (
            0x9e78_0000,
            &[ScalarType::Double],
            None,
            64,
            "fpx_cvtsat_i64_f64((fp_d_from_bits(x_xmm0)))",
        ),
        (
            0x9e79_0000,
            &[ScalarType::Double],
            None,
            64,
            "fpx_cvtsat_u64_f64((fp_d_from_bits(x_xmm0)))",
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
        assert_eq!(
            recovery.signature.parameter_types(),
            params,
            "{}",
            recovery.source
        );
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
fn scalar_fp_half_precision_arithmetic_recovers() {
    let mut code: Vec<u8> = 0x1e23_c000_u32.to_le_bytes().to_vec();
    code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    let recovery: LeafRecovery =
        recover_aarch64_function(&code, 0).expect("F16 scalar arithmetic must recover");
    assert!(recovery.source.contains("_Float16"), "{}", recovery.source);
}

#[test]
fn scalar_fp_half_precision_conversion_recovers() {
    let mut code: Vec<u8> = 0x1ee2_4000_u32.to_le_bytes().to_vec();
    code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
    let recovery: LeafRecovery =
        recover_aarch64_function(&code, 0).expect("F16 scalar conversion must recover");
    assert!(
        recovery
            .source
            .contains("fp_f_to_bits((float)(fp_h_from_bits((uint16_t)x_xmm0)))"),
        "{}",
        recovery.source
    );
    let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
    assert!(rust_source.contains("fp_h_from_bits"), "{rust_source}");
}

#[test]
fn scalar_fp_half_precision_semantics_helpers_are_emitted() {
    let cases: [(u32, &str, &str); 4] = [
        (
            0x1fc1_0800,
            "static inline _Float16 fpx_fma_f16",
            "fn fpx_fma_f16",
        ),
        (
            0x1ee1_4800,
            "static inline _Float16 fpx_max_f16",
            "fn fpx_max_f16",
        ),
        (
            0x1ee1_c000,
            "static inline _Float16 fpx_sqrt_f16",
            "fn fpx_sqrt_f16",
        ),
        (
            0x1ee4_4000,
            "static inline _Float16 fpx_rintn_f16",
            "fn fpx_rintn_f16",
        ),
    ];
    for (word, c_helper, rust_helper) in cases {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("F16 scalar operation must recover");
        assert!(
            recovery.source.contains(c_helper),
            "{c_helper}: {}",
            recovery.source
        );
        let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
        assert!(
            rust_source.contains(rust_helper),
            "{rust_helper}: {rust_source}"
        );
        if matches!(word, 0x1fc1_0800 | 0x1ee1_c000) {
            assert!(rust_source.contains("fp_h_bits_from_f64"), "{rust_source}");
        }
    }
}

#[test]
fn scalar_fp_half_precision_to_integer_uses_bounded_conversion() {
    for (word, required_helper) in [
        (0x1ef8_0000_u32, "static inline int32_t fpx_cvtsat_i32_f16"),
        (0x1ee0_0000_u32, "static inline _Float16 fpx_rintn_f16"),
        (0x1ee1_0000_u32, "static inline _Float16 fpx_rintn_f16"),
    ] {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("F16 to integer conversion must recover");
        assert!(
            recovery.source.contains(required_helper),
            "{required_helper}: {}",
            recovery.source
        );
    }
}

const FJCVTZS_LIVE_EXACTNESS_FLAGS: [u8; 12] = [
    0x00, 0x00, 0x7e, 0x1e, 0xe1, 0x17, 0x9f, 0x1a, 0xc0, 0x03, 0x5f, 0xd6,
];
const FJCVTZS_DEAD_EXACTNESS_FLAGS: [u8; 8] = [0x00, 0x00, 0x7e, 0x1e, 0xc0, 0x03, 0x5f, 0xd6];

fn decoded_mnemonics(bytes: &[u8]) -> Vec<(String, String)> {
    disassemble(Arch::Aarch64, 0, bytes)
        .expect("aarch64 decode")
        .iter()
        .map(|insn: &DisasmInsn| (insn.mnemonic.clone(), insn.operands.trim().to_owned()))
        .collect()
}

#[test]
fn fp_forms_requiring_unmodeled_architectural_state_reject_distinctly() {
    let cases: [(&[u8], &str); 1] = [(
        &FJCVTZS_LIVE_EXACTNESS_FLAGS,
        "javascript float-to-integer exactness flags remain live",
    )];
    assert_eq!(
        decoded_mnemonics(&FJCVTZS_LIVE_EXACTNESS_FLAGS),
        vec![
            ("fjcvtzs".to_owned(), "w0, d0".to_owned()),
            ("cset".to_owned(), "w1, eq".to_owned()),
            ("ret".to_owned(), String::new()),
        ],
        "the conditional-set tail is what keeps the exactness flags live"
    );
    for (code, reason) in cases {
        let error: disrobe_pass_native::Error =
            recover_aarch64_function(code, 0).expect_err("unsupported stateful FP form");
        assert!(
            format!("{error:?}").contains(reason),
            "{code:02x?}: {error:?}"
        );
    }

    assert_eq!(
        decoded_mnemonics(&FJCVTZS_DEAD_EXACTNESS_FLAGS),
        vec![
            ("fjcvtzs".to_owned(), "w0, d0".to_owned()),
            ("ret".to_owned(), String::new()),
        ],
        "the bare return is what lets the exactness flags die"
    );
    let recovery: LeafRecovery = recover_aarch64_function(&FJCVTZS_DEAD_EXACTNESS_FLAGS, 0)
        .expect("a javascript conversion whose exactness flags die at the return is modelled");
    assert!(
        recovery.source.contains("fpx_js_i32_f64"),
        "{}",
        recovery.source
    );
}

#[test]
fn memory_only_half_precision_emits_boundary_helpers() {
    let code: Vec<u8> = [0x7d40_0000_u32, 0x1ef8_0000_u32, 0xd65f_03c0_u32]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let recovery: LeafRecovery =
        recover_aarch64_function(&code, 0).expect("memory-backed F16 conversion");
    let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
    assert!(
        rust_source.contains("fn fp_h_from_bits(bits: u16) -> f32"),
        "{rust_source}"
    );
}

#[test]
fn non_half_rust_recovery_does_not_emit_binary16_helpers() {
    let code: Vec<u8> = [0x1e21_2800_u32, 0xd65f_03c0_u32]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let recovery: LeafRecovery = recover_aarch64_function(&code, 0).expect("binary32 addition");
    let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
    assert!(!rust_source.contains("fp_h_from_bits"), "{rust_source}");
    assert!(!rust_source.contains("fp_h_bits_from_f64"), "{rust_source}");
    assert!(!recovery.source.contains("_Float16"), "{}", recovery.source);
    assert!(
        !recovery.source.contains("fp_h_from_bits"),
        "{}",
        recovery.source
    );
}

#[test]
fn scalar_fp_half_precision_rust_rendering_compiles() {
    let words: [u32; 16] = [
        0x1e23_c000,
        0x1ee2_4000,
        0x1fc1_0800,
        0x1ee1_4800,
        0x1ee1_c000,
        0x1ef8_0000,
        0x1ee0_c000,
        0x1ee1_4000,
        0x1ee0_0000,
        0x1ee1_0000,
        0x1ec2_c000,
        0x1ed8_c000,
        0x9ec3_0000,
        0x9ed8_8000,
        0x1ee7_0000,
        0x1ee6_0000,
    ];
    let mut unit: String = String::new();
    for (index, word) in words.into_iter().enumerate() {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("F16 scalar operation must recover");
        let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
        let boundary_test: &str = if index == 0 {
            r"
#[test]
fn direct_binary16_rounding_boundaries() {
    assert_eq!(fp_h_bits_from_f64(2.0_f64.powi(-25)), 0x0000);
    assert_eq!(fp_h_bits_from_f64(f64::from_bits(2.0_f64.powi(-25).to_bits() + 1)), 0x0001);
    assert_eq!(fp_h_bits_from_f64(1.0 + 2.0_f64.powi(-11)), 0x3c00);
    assert_eq!(fp_h_bits_from_f64(f64::from_bits((1.0 + 2.0_f64.powi(-11)).to_bits() + 1)), 0x3c01);
    assert_eq!(fp_h_bits_from_f64(1.0 + 3.0 * 2.0_f64.powi(-11)), 0x3c02);
    assert_eq!(fp_h_bits_from_f64(65_520.0), 0x7c00);
}
"
        } else if word == 0x1ec2_c000 {
            r"
#[test]
fn fixed_integer_to_half_uses_a_wide_intermediate() {
    assert_eq!(recovered(65_536), 0x3c00);
}
"
        } else if word == 0x1ed8_c000 {
            r"
#[test]
fn fixed_half_to_integer_uses_a_wide_scale() {
    assert_eq!(recovered(0x3c00), 65_536);
}
"
        } else if word == 0x9ec3_0000 {
            r"
#[test]
fn fixed_large_integer_to_half_rounds_from_exact_bits() {
    assert_eq!(recovered(9_227_875_636_482_146_305), 0x3801);
}
"
        } else if word == 0x9ed8_8000 {
            r"
#[test]
fn fixed_half_to_wide_integer_does_not_narrow_the_scale() {
    assert_eq!(recovered(0x3c00), 4_294_967_296);
    assert_eq!(recovered(0x0001), 256);
}
"
        } else {
            ""
        };
        let _ = writeln!(
            unit,
            "mod case_{index} {{\n{rust_source}\n{boundary_test}\n}}"
        );
    }
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary Rust crate");
    let source_path: std::path::PathBuf = directory.path().join("half.rs");
    let output_path: std::path::PathBuf = directory.path().join("half_tests.exe");
    fs::write(&source_path, unit).expect("write generated Rust");
    let output: std::process::Output = Command::new("rustc")
        .args(["--edition", "2021", "--test", "-D", "warnings"])
        .arg(&source_path)
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("invoke rustc");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let execution: std::process::Output = Command::new(&output_path)
        .output()
        .expect("execute generated Rust tests");
    assert!(
        execution.status.success(),
        "{}",
        String::from_utf8_lossy(&execution.stderr)
    );
}

#[test]
fn scalar_fp_half_precision_c_rendering_compiles() {
    let words: [u32; 17] = [
        0x1e23_c000,
        0x1ee2_4000,
        0x1e63_c000,
        0x1fc1_0800,
        0x1ee1_4800,
        0x1ee1_c000,
        0x1ef8_0000,
        0x1ee0_c000,
        0x1ee1_4000,
        0x1ee0_0000,
        0x1ee1_0000,
        0x1ec2_c000,
        0x1ed8_c000,
        0x9ec3_0000,
        0x9ed8_8000,
        0x1ee7_0000,
        0x1ee6_0000,
    ];
    let compiler: String = host_c_compiler();
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary C sources");
    for (index, word) in words.into_iter().enumerate() {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("F16 scalar operation must recover");
        let source_path: std::path::PathBuf = directory.path().join(format!("half_{index}.c"));
        let boundary_main: &str = match word {
            0x1ee2_4000 => {
                "\nint main(void) { return fp_f_to_bits(recovered(fp_h_from_bits(0x7c01))) == 0x7fc02000 ? 0 : 1; }\n"
            }
            0x1e63_c000 => {
                "\nint main(void) { return fp_h_to_bits(recovered(fp_d_from_bits(UINT64_C(0x7ff0040000000000)))) == 0x7e01 ? 0 : 1; }\n"
            }
            0x1ec2_c000 => {
                "\nint main(void) { return fp_h_to_bits(recovered(65536)) == 0x3c00 ? 0 : 1; }\n"
            }
            0x1ed8_c000 => {
                "\nint main(void) { return recovered(fp_h_from_bits(0x3c00)) == 65536 ? 0 : 1; }\n"
            }
            0x9ec3_0000 => {
                "\nint main(void) { return fp_h_to_bits(recovered(UINT64_C(9227875636482146305))) == 0x3801 ? 0 : 1; }\n"
            }
            0x9ed8_8000 => {
                "\nint main(void) { return recovered(fp_h_from_bits(0x3c00)) == UINT64_C(4294967296) && recovered(fp_h_from_bits(0x0001)) == 256 ? 0 : 1; }\n"
            }
            _ => "",
        };
        let source: String = format!("{}{boundary_main}", recovery.source);
        fs::write(&source_path, source).expect("write generated C");
        let executable_path: std::path::PathBuf =
            directory.path().join(format!("half_{index}.exe"));
        let mut command: Command = Command::new(&compiler);
        command.args(["-std=c11", "-Werror"]);
        if boundary_main.is_empty() {
            command.arg("-fsyntax-only");
        } else {
            command.arg("-o").arg(&executable_path);
        }
        let output: std::process::Output = command
            .arg(&source_path)
            .output()
            .expect("invoke C compiler");
        assert!(
            output.status.success(),
            "case {index}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if !boundary_main.is_empty() {
            let execution: std::process::Output = Command::new(&executable_path)
                .output()
                .expect("execute generated C boundary test");
            assert!(
                execution.status.success(),
                "case {index} returned a mismatched value"
            );
        }
    }
}

#[test]
fn half_rust_paths_preserve_or_quiet_bits_as_required() {
    let cases: [(Vec<u32>, &str); 12] = [
        (
            vec![0x1ee0_4000],
            "for bits in u16::MIN..=u16::MAX { assert_eq!(recovered(bits), bits); }",
        ),
        (
            vec![0x7d40_0000],
            "for bits in u16::MIN..=u16::MAX { assert_eq!(recovered((&bits as *const u16) as u64), bits); }",
        ),
        (
            vec![0x1ee0_c000],
            "for bits in u16::MIN..=u16::MAX { assert_eq!(recovered(bits), bits & 0x7fff); }",
        ),
        (
            vec![0x1ee1_4000],
            "for bits in u16::MIN..=u16::MAX { assert_eq!(recovered(bits), bits ^ 0x8000); }",
        ),
        (
            vec![0x1ee1_2000, 0x1ee1_0c00],
            "assert_eq!(recovered(0x3c00, 0x7c01), 0x7c01);",
        ),
        (
            vec![0x1e63_c000],
            "assert_eq!(recovered(f64::from_bits(0x7ff0_0400_0000_0000)), 0x7e01); assert_eq!(recovered(f64::from_bits(0x7ff8_0400_0000_0000)), 0x7e01);",
        ),
        (
            vec![0x1ee2_4000],
            "assert_eq!(recovered(0x7c01).to_bits(), 0x7fc0_2000); assert_eq!(recovered(0x7e01).to_bits(), 0x7fc0_2000);",
        ),
        (
            vec![0x1ee1_c000],
            "assert_eq!(recovered(0xfc00), 0x7e00); assert_eq!(recovered(0x8000), 0x8000); assert_eq!(recovered(0x7c00), 0x7c00);",
        ),
        (
            vec![0x1ee1_2800],
            "assert_eq!(recovered(0x7c01, 0x3c00), 0x7e01); assert_eq!(recovered(0x3c00, 0x7c01), 0x7e01); assert_eq!(recovered(0x7e11, 0x7e22), 0x7e11); assert_eq!(recovered(0x7c00, 0xfc00), 0x7e00);",
        ),
        (
            vec![0x1ee1_1800],
            "assert_eq!(recovered(0x0000, 0x0000), 0x7e00); assert_eq!(recovered(0x7c00, 0x7c00), 0x7e00);",
        ),
        (
            vec![0x1e23_c000],
            "assert_eq!(recovered(f32::from_bits(0x7f80_2000)), 0x7e01); assert_eq!(recovered(f32::from_bits(0x7fc0_2000)), 0x7e01);",
        ),
        (
            vec![0x1ee2_c000],
            "assert_eq!(recovered(0x7c01).to_bits(), 0x7ff8_0400_0000_0000); assert_eq!(recovered(0x7e01).to_bits(), 0x7ff8_0400_0000_0000);",
        ),
    ];
    let mut unit: String = String::new();
    for (index, (mut words, assertion)) in cases.into_iter().enumerate() {
        words.push(0xd65f_03c0);
        let code: Vec<u8> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("bit-preserving half operation");
        let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
        let _ = writeln!(
            unit,
            "mod case_{index} {{\n{rust_source}\n#[test]\nfn preserves_bits() {{ {assertion} }}\n}}"
        );
    }
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary Rust crate");
    let source_path: std::path::PathBuf = directory.path().join("half_bits.rs");
    let output_path: std::path::PathBuf = directory.path().join("half_bits.exe");
    fs::write(&source_path, unit).expect("write generated Rust");
    let built: std::process::Output = Command::new("rustc")
        .args(["--edition", "2021", "--test", "-D", "warnings"])
        .arg(&source_path)
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("compile generated Rust");
    assert!(
        built.status.success(),
        "{}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed: std::process::Output = Command::new(&output_path)
        .output()
        .expect("execute generated Rust");
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn half_c_sign_operations_preserve_every_payload_across_compilers() {
    let cases: [(u32, &str); 2] = [
        (0x1ee0_c000, "(bits & 0x7fffu)"),
        (0x1ee1_4000, "(bits ^ 0x8000u)"),
    ];
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary C sources");
    let mut executions: usize = 0;
    for compiler in ["gcc", "clang"] {
        if !Command::new(compiler)
            .arg("--version")
            .output()
            .is_ok_and(|output: std::process::Output| output.status.success())
        {
            continue;
        }
        for (index, (word, expected)) in cases.into_iter().enumerate() {
            let code: Vec<u8> = [word, 0xd65f_03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect();
            let recovery: LeafRecovery =
                recover_aarch64_function(&code, 0).expect("half sign operation");
            let source: String = format!(
                "{}\nint main(void) {{ for (uint32_t bits = 0; bits <= 0xffffu; bits++) {{ if (fp_h_to_bits(recovered(fp_h_from_bits((uint16_t)bits))) != {expected}) return 1; }} return 0; }}\n",
                recovery.source
            );
            let source_path: std::path::PathBuf = directory
                .path()
                .join(format!("half_sign_{compiler}_{index}.c"));
            let executable_path: std::path::PathBuf = directory
                .path()
                .join(format!("half_sign_{compiler}_{index}.exe"));
            fs::write(&source_path, source).expect("write generated C");
            let built: std::process::Output = Command::new(compiler)
                .args(["-std=c11", "-O0", "-Werror", "-o"])
                .arg(&executable_path)
                .arg(&source_path)
                .output()
                .expect("compile generated C");
            assert!(
                built.status.success(),
                "{compiler}: {}{}",
                String::from_utf8_lossy(&built.stdout),
                String::from_utf8_lossy(&built.stderr)
            );
            let executed: std::process::Output = Command::new(&executable_path)
                .output()
                .expect("execute generated C");
            assert!(executed.status.success(), "{compiler} case {index}");
            executions += 1;
        }
    }
    assert!(executions >= cases.len());
}

#[test]
fn half_store_through_mixed_union_writes_raw_bits() {
    let code: Vec<u8> = [0x7d00_0000_u32, 0x7940_0000, 0xd65f_03c0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect();
    let recovery: LeafRecovery =
        recover_aarch64_function(&code, 0).expect("mixed half and integer slot");
    let rust_source: &str = recovery.rust_source.as_deref().expect("Rust recovery");
    let unit: String = format!(
        "{rust_source}\n#[test]\nfn stores_bits() {{ let mut slot: u16 = 0; let result: u64 = recovered(0x7c01, (&raw mut slot) as u64); assert_eq!(slot, 0x7c01); assert_eq!(result, 0x7c01); }}\n"
    );
    let directory: tempfile::TempDir = tempfile::tempdir().expect("temporary Rust crate");
    let source_path: std::path::PathBuf = directory.path().join("half_union.rs");
    let output_path: std::path::PathBuf = directory.path().join("half_union.exe");
    fs::write(&source_path, unit).expect("write generated Rust");
    let built: std::process::Output = Command::new("rustc")
        .args(["--edition", "2024", "--test", "-D", "warnings"])
        .arg(&source_path)
        .arg("-o")
        .arg(&output_path)
        .output()
        .expect("compile generated Rust");
    assert!(
        built.status.success(),
        "{}\n{rust_source}",
        String::from_utf8_lossy(&built.stderr)
    );
    let executed: std::process::Output = Command::new(&output_path)
        .output()
        .expect("execute generated Rust");
    assert!(
        executed.status.success(),
        "{}",
        String::from_utf8_lossy(&executed.stderr)
    );
}

#[test]
fn scalar_fp_fixed_point_forms_recover_with_their_scale() {
    let cases: [(u32, &str); 5] = [
        (0x1e42_e400, "(double)((double)(int32_t)r_rax / 0x1p7)"),
        (0x1e03_ec00, "(float)((float)(uint32_t)r_rax / 0x1p5f)"),
        (
            0x1e18_f400,
            "fpx_cvtsat_i32_f32((fp_f_from_bits((uint32_t)x_xmm0) * 0x1p3f))",
        ),
        (
            0x9e59_dc00,
            "fpx_cvtsat_u64_f64((fp_d_from_bits(x_xmm0) * 0x1p9))",
        ),
        (0x1ec2_c000, "fp_h_bits_from_scaled_i64((int32_t)r_rax, 16)"),
    ];
    for (word, expected) in cases {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let recovery: LeafRecovery =
            recover_aarch64_function(&code, 0).expect("fixed-point conversion must recover");
        assert!(
            recovery.source.contains(expected),
            "missing `{expected}` in recovered source:\n{}",
            recovery.source
        );
    }
}

#[test]
fn vector_fixed_point_conversion_forms_reject() {
    let cases: [(u32, &str); 4] = [
        (0x4f39_e420, "unsupported instruction"),
        (0x6f39_e420, "unsupported instruction"),
        (0x5f39_e420, "source is not w or x"),
        (0x7f39_e420, "source is not w or x"),
    ];
    for (word, reason) in cases {
        let mut code: Vec<u8> = word.to_le_bytes().to_vec();
        code.extend_from_slice(&[0xc0, 0x03, 0x5f, 0xd6]);
        let error: String = format!(
            "{:?}",
            recover_aarch64_function(&code, 0).expect_err("vector form must sound-reject")
        );
        assert!(
            error.contains(reason),
            "missing `{reason}` in rejection of {word:#010x}: {error}"
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

const FRAMELESS_POST_INDEX_RELEASE: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xb9, 0xe1, 0x03, 0x00, 0xb9, 0xe2, 0x0f, 0x40, 0xb9,
    0xe0, 0x07, 0x41, 0xb8, 0x00, 0x00, 0x02, 0x0b, 0xc0, 0x03, 0x5f, 0xd6,
];
const TWO_EPILOGUES: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xb9, 0x1f, 0x00, 0x01, 0x6b, 0xad, 0x00, 0x00, 0x54,
    0xe1, 0x0f, 0x00, 0xb9, 0xe0, 0x0f, 0x40, 0xb9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
    0xe0, 0x0f, 0x40, 0xb9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];
const SAVED_REGISTER_ROUND_TRIP: &[u8] = &[
    0xff, 0x83, 0x00, 0xd1, 0xf3, 0x0b, 0x00, 0xf9, 0xe0, 0x0f, 0x00, 0xb9, 0xf3, 0x03, 0x00, 0x2a,
    0x60, 0x06, 0x00, 0x11, 0xe0, 0x0f, 0x00, 0xb9, 0xe0, 0x0f, 0x40, 0xb9, 0xf3, 0x0b, 0x40, 0xf9,
    0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];
const DYNAMIC_ALLOCATION: &[u8] = &[
    0xff, 0x63, 0x20, 0xcb, 0xe1, 0x0f, 0x00, 0xb9, 0xe0, 0x0f, 0x40, 0xb9, 0xff, 0x63, 0x20, 0x8b,
    0xc0, 0x03, 0x5f, 0xd6,
];
const UNINITIALIZED_SLOT_READ: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x0f, 0x40, 0xb9, 0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];
const ESCAPING_FRAME_ADDRESS: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe8, 0x03, 0x00, 0x91, 0x00, 0x01, 0x00, 0xb9, 0xe0, 0x03, 0x40, 0xb9,
    0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];
const UNBALANCED_RELEASE: &[u8] = &[
    0xff, 0x83, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xb9, 0xe0, 0x0f, 0x40, 0xb9, 0xff, 0x43, 0x00, 0x91,
    0xc0, 0x03, 0x5f, 0xd6,
];
const CLOBBERED_LINK_REGISTER: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x0f, 0x00, 0xb9, 0xfe, 0x03, 0x00, 0xaa, 0xe0, 0x0f, 0x40, 0xb9,
    0xff, 0x43, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn balanced_frames_without_a_prologue_template_recover() {
    let released: LeafRecovery = recover_aarch64_function(FRAMELESS_POST_INDEX_RELEASE, 0)
        .expect("a post-indexed load may release the frame");
    assert!(
        released.source.contains("unsigned char stack_frame[16]"),
        "the released frame must still back the slot as a local: {}",
        released.source
    );
    assert!(
        !released.source.contains("r_rsp = r_rsp"),
        "the absorbed writeback must not mutate the modelled frame base: {}",
        released.source
    );

    let split: LeafRecovery =
        recover_aarch64_function(TWO_EPILOGUES, 0).expect("both exits release the same frame");
    assert!(
        split.source.contains("unsigned char stack_frame[16]"),
        "a two-exit frame must still back its slot as a local: {}",
        split.source
    );

    let saved: LeafRecovery = recover_aarch64_function(SAVED_REGISTER_ROUND_TRIP, 0)
        .expect("a mid-body callee-saved round trip is frame management");
    assert!(
        saved.source.contains("unsigned char stack_frame[16]")
            && !saved.source.contains("*(uint64_t*)(uintptr_t)(r_rsp"),
        "a proven callee-saved round trip must be skipped, not modelled as a slot: {}",
        saved.source
    );
}

const MULTI_DEPTH_INCOMING_READ: &[u8] = &[
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x0b, 0x40, 0xf9, 0xff, 0x43, 0x00, 0xd1, 0xe1, 0x13, 0x40, 0xf9,
    0xff, 0x83, 0x00, 0x91, 0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn untrackable_frames_still_reject() {
    let cases: [(&[u8], &str); 6] = [
        (
            DYNAMIC_ALLOCATION,
            "stack pointer is used outside a modelled frame adjustment",
        ),
        (
            UNINITIALIZED_SLOT_READ,
            "a stack slot is read before every path has written it",
        ),
        (
            ESCAPING_FRAME_ADDRESS,
            "stack pointer is used outside a modelled frame adjustment",
        ),
        (
            UNBALANCED_RELEASE,
            "stack pointer does not return to its entry value before the return",
        ),
        (
            CLOBBERED_LINK_REGISTER,
            "a callee-saved register is not provably restored at the return",
        ),
        (
            MULTI_DEPTH_INCOMING_READ,
            "stack slots are accessed at more than one stack-pointer offset",
        ),
    ];
    for (bytes, expected) in cases {
        let error: String = format!(
            "{:?}",
            recover_aarch64_function(bytes, 0).expect_err("form must sound-reject")
        );
        assert!(
            error.contains(expected),
            "missing `{expected}` in rejection: {error}"
        );
    }
}
