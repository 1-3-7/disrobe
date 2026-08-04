#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr,
    clippy::too_many_lines
)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};

#[path = "support/aarch64_callsite_cases.rs"]
mod aarch64_callsite_cases;
#[path = "aarch64_grade/battery.rs"]
mod battery;

use battery::{
    CASES, EXTERNS, FP_DRIVER_HELPERS, FpExpectation, ORACLE_FLAGS, build_ground_truth_object, cc,
    compare_block, expected_arity, fp_expectation, rename_recovered, run_with_watchdog,
    shared_prelude,
};

const INCREMENT_TWO_FP_FUNCTIONS: &[&str] = &[
    "fp_add_f",
    "fp_sub_d",
    "fp_mul_d",
    "fp_div_d",
    "fp_div_f",
    "fp_axpy",
    "fp_to_int_s",
    "fp_to_uint_s",
    "fp_to_ulong_d",
    "fp_from_int",
    "fp_from_uint",
    "fp_widen",
    "fp_narrow",
    "fp_iavg",
];
const CORPUS_OPTIMIZATION_LEVELS: &[&str] = &["O0", "O1", "O2", "O3", "Os"];
const INCREMENT_TWO_EXPECTED_CASES: usize = 70;
const INCREMENT_ONE_EXPECTED_FP_CASES: usize = 32;
const EXPECTED_INTEGER_CASES: usize = 295;

fn is_increment_two_fp(name: &str) -> bool {
    INCREMENT_TWO_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_THREE_FP_FUNCTIONS: &[&str] = &[
    "fp_floor_d",
    "fp_ceil_f",
    "fp_trunc_d",
    "fp_round_d",
    "fp_rint_d",
];
const INCREMENT_THREE_EXPECTED_CASES: usize = 25;

fn is_increment_three_fp(name: &str) -> bool {
    INCREMENT_THREE_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_FOUR_FP_FUNCTIONS: &[&str] =
    &["fp_max_f", "fp_min_f", "fp_max_d", "fp_min_d", "fp_clamp_f"];
const INCREMENT_FOUR_EXPECTED_CASES: usize = 25;

fn is_increment_four_fp(name: &str) -> bool {
    INCREMENT_FOUR_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_FIVE_FP_FUNCTIONS: &[&str] = &[
    "fma_madd_f",
    "fma_msub_f",
    "fma_nmadd_f",
    "fma_nmsub_f",
    "fma_madd_d",
    "fma_msub_d",
    "fma_nmadd_d",
    "fma_nmsub_d",
    "mul_add_unfused_f",
    "mul_add_unfused_d",
    "sub_mul_unfused_f",
    "sub_mul_unfused_d",
];
const INCREMENT_FIVE_EXPECTED_CASES: usize = 60;

fn is_increment_five_fp(name: &str) -> bool {
    INCREMENT_FIVE_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_SIX_FP_FUNCTIONS: &[&str] = &[
    "fma_mixed_f",
    "fma_mixed_d",
    "fma_chained_f",
    "fma_chained_d",
];
const INCREMENT_SIX_EXPECTED_CASES: usize = 20;

fn is_increment_six_fp(name: &str) -> bool {
    INCREMENT_SIX_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_SEVEN_FP_FUNCTIONS: &[&str] = &[
    "fc_lt_f",
    "fc_le_f",
    "fc_gt_f",
    "fc_ge_f",
    "fc_eq_f",
    "fc_ne_f",
    "fc_nlt_f",
    "fc_nle_f",
    "fc_ngt_f",
    "fc_nge_f",
    "fc_isnan_f",
    "fc_lt_d",
    "fc_le_d",
    "fc_gt_d",
    "fc_ge_d",
    "fc_eq_d",
    "fc_ne_d",
    "fc_nlt_d",
    "fc_nle_d",
    "fc_ngt_d",
    "fc_nge_d",
    "fc_isnan_d",
    "fc_sel_f",
    "fc_tmin_f",
    "fc_tmax_f",
    "fc_pickeq_f",
    "fc_sel_d",
    "fc_tmin_d",
    "fc_tmax_d",
    "fc_pickeq_d",
    "fc_seland_f",
];
const INCREMENT_SEVEN_EXPECTED_CASES: usize = 155;

fn is_increment_seven_fp(name: &str) -> bool {
    INCREMENT_SEVEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_EIGHT_FP_FUNCTIONS: &[&str] = &[
    "fu_neg_f",
    "fu_neg_d",
    "fu_abs_f",
    "fu_abs_d",
    "fu_nabs_f",
    "fu_nabs_d",
];
const INCREMENT_EIGHT_EXPECTED_CASES: usize = 30;

fn is_increment_eight_fp(name: &str) -> bool {
    INCREMENT_EIGHT_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_NINE_FP_FUNCTIONS: &[&str] = &[
    "fcvt_floor_s",
    "fcvt_ceil_s",
    "fcvt_away_s",
    "fcvt_floor_us",
    "fcvt_ceil_us",
    "fcvt_away_us",
    "fcvt_floor_d",
    "fcvt_ceil_d",
    "fcvt_away_d",
    "fcvt_floor_ud",
];
const INCREMENT_NINE_EXPECTED_CASES: usize = 50;

fn is_increment_nine_fp(name: &str) -> bool {
    INCREMENT_NINE_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_TEN_FP_FUNCTIONS: &[&str] = &[
    "fz_relu_f",
    "fz_relu_d",
    "fz_nrelu_f",
    "fz_nrelu_d",
    "fz_mulz_f",
    "fz_mulz_d",
    "fz_zsub_f",
    "fz_zsub_d",
    "fz_addz_f",
    "fz_addz_d",
];
const INCREMENT_TEN_EXPECTED_CASES: usize = 50;

fn is_increment_ten_fp(name: &str) -> bool {
    INCREMENT_TEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_ELEVEN_FP_FUNCTIONS: &[&str] = &[
    "fabsdiff_f",
    "fabsdiff_d",
    "fnegmul_f",
    "fnegmul_d",
    "fnabsdiff_f",
    "fnabsdiff_d",
];
const INCREMENT_ELEVEN_EXPECTED_CASES: usize = 30;

fn is_increment_eleven_fp(name: &str) -> bool {
    INCREMENT_ELEVEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_TWELVE_FP_FUNCTIONS: &[&str] = &[
    "kadd_f", "kadd_d", "kmul_f", "kmul_d", "kmadd_f", "kmadd_d", "ksub_f", "ksub_d",
];
const INCREMENT_TWELVE_EXPECTED_CASES: usize = 40;

fn is_increment_twelve_fp(name: &str) -> bool {
    INCREMENT_TWELVE_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_THIRTEEN_FP_FUNCTIONS: &[&str] = &[
    "ret1_f",
    "ret2_f",
    "ret25_f",
    "rethalf_f",
    "retn1_f",
    "ret1_d",
    "ret25_d",
    "rethalf_d",
    "retn3_d",
    "retn1_d",
];
const INCREMENT_THIRTEEN_EXPECTED_CASES: usize = 50;

fn is_increment_thirteen_fp(name: &str) -> bool {
    INCREMENT_THIRTEEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_FOURTEEN_FP_FUNCTIONS: &[&str] =
    &["tclamp0_f", "tclamp0_d", "tclamp1_f", "tclamp1_d"];
const INCREMENT_FOURTEEN_EXPECTED_CASES: usize = 20;

fn is_increment_fourteen_fp(name: &str) -> bool {
    INCREMENT_FOURTEEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_FIFTEEN_FP_FUNCTIONS: &[&str] = &["tsel_f", "tsel_d", "tsel2_f", "tsel2_d"];
const INCREMENT_FIFTEEN_EXPECTED_CASES: usize = 20;

fn is_increment_fifteen_fp(name: &str) -> bool {
    INCREMENT_FIFTEEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_SIXTEEN_FP_FUNCTIONS: &[&str] = &[
    "fs_sqrt_f",
    "fs_sqrt_d",
    "fs_hypot_f",
    "fs_norm3_d",
    "fs_rsqrt_f",
    "fs_sqrt_sum_d",
    "fs_sqrt_scaled_f",
    "fs_sqrt_diff_d",
];
const INCREMENT_SIXTEEN_EXPECTED_CASES: usize = 40;

fn is_increment_sixteen_fp(name: &str) -> bool {
    INCREMENT_SIXTEEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_SEVENTEEN_FP_FUNCTIONS: &[&str] = &[
    "fb_ge_f",
    "fb_ge_d",
    "fb_le_f",
    "fb_le_d",
    "fb_ne_f",
    "fb_ne_d",
    "fb_nlt_f",
    "fb_nlt_d",
    "fb_nle_f",
    "fb_nle_d",
    "fb_ngt_f",
    "fb_ngt_d",
    "fb_nge_f",
    "fb_nge_d",
    "fb_ord_f",
    "fb_ord_d",
    "fb_uno_f",
    "fb_uno_d",
    "fc_selor_f",
    "fc_selor_d",
    "fc_seland_d",
    "fc_selor3_f",
    "fc_seland3_f",
    "fc_seland3_mix_f",
    "fb_and3_f",
];
const INCREMENT_SEVENTEEN_EXPECTED_CASES: usize = 125;

fn is_increment_seventeen_fp(name: &str) -> bool {
    INCREMENT_SEVENTEEN_FP_FUNCTIONS.contains(&name)
}

const INCREMENT_EIGHTEEN_FUNCTIONS: &[&str] = &["vol_four_slots", "vol_two_guards"];
const INCREMENT_EIGHTEEN_EXPECTED_CASES: usize = 10;

fn is_increment_eighteen(name: &str) -> bool {
    INCREMENT_EIGHTEEN_FUNCTIONS.contains(&name)
}

const INCREMENT_NINETEEN_FP_FUNCTIONS: &[&str] = &[
    "fx_scvtf_f_w",
    "fx_scvtf_d_w",
    "fx_scvtf_f_x",
    "fx_scvtf_d_x",
    "fx_ucvtf_f_w",
    "fx_ucvtf_d_w",
    "fx_ucvtf_f_x",
    "fx_ucvtf_d_x",
    "fx_fcvtzs_w_f",
    "fx_fcvtzs_w_d",
    "fx_fcvtzs_x_f",
    "fx_fcvtzs_x_d",
    "fx_fcvtzu_w_f",
    "fx_fcvtzu_w_d",
    "fx_fcvtzu_x_f",
    "fx_fcvtzu_x_d",
];
const INCREMENT_NINETEEN_EXPECTED_CASES: usize = 80;

fn is_increment_nineteen_fp(name: &str) -> bool {
    INCREMENT_NINETEEN_FP_FUNCTIONS.contains(&name)
}

#[test]
#[ignore = "recompile-differential over the whole corpus; needs a host c compiler and is codegen-sensitive, so it is opt-in via --ignored until the ci platform matrix is verified green"]
fn corpus_grade_report() {
    let compiler: String =
        cc().unwrap_or_else(|| panic!("corpus grade requires a host C compiler on PATH"));
    assert!(
        !ORACLE_FLAGS
            .iter()
            .any(|flag: &&str| matches!(*flag, "-ffast-math" | "-Ofast")),
        "oracle flags must preserve strict floating-point behavior"
    );
    assert!(
        ORACLE_FLAGS.contains(&"-ffp-contract=off"),
        "oracle flags must keep multiply and add as two rounded operations"
    );
    let increment_two_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_two_fp(name))
        .count();
    assert_eq!(
        increment_two_corpus_cases, INCREMENT_TWO_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-2 function"
    );
    for required_name in INCREMENT_TWO_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-2 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_four_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_four_fp(name))
        .count();
    assert_eq!(
        increment_four_corpus_cases, INCREMENT_FOUR_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-4 function"
    );
    for required_name in INCREMENT_FOUR_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-4 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_five_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_five_fp(name))
        .count();
    assert_eq!(
        increment_five_corpus_cases, INCREMENT_FIVE_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-5 function"
    );
    for required_name in INCREMENT_FIVE_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-5 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_six_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_six_fp(name))
        .count();
    assert_eq!(
        increment_six_corpus_cases, INCREMENT_SIX_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-6 function"
    );
    for required_name in INCREMENT_SIX_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-6 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_seven_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_seven_fp(name))
        .count();
    assert_eq!(
        increment_seven_corpus_cases, INCREMENT_SEVEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-7 function"
    );
    for required_name in INCREMENT_SEVEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-7 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_eight_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_eight_fp(name))
        .count();
    assert_eq!(
        increment_eight_corpus_cases, INCREMENT_EIGHT_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-8 function"
    );
    for required_name in INCREMENT_EIGHT_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-8 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_nine_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_nine_fp(name))
        .count();
    assert_eq!(
        increment_nine_corpus_cases, INCREMENT_NINE_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-9 function"
    );
    for required_name in INCREMENT_NINE_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-9 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_ten_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_ten_fp(name))
        .count();
    assert_eq!(
        increment_ten_corpus_cases, INCREMENT_TEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-10 function"
    );
    for required_name in INCREMENT_TEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-10 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_eleven_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_eleven_fp(name))
        .count();
    assert_eq!(
        increment_eleven_corpus_cases, INCREMENT_ELEVEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-11 function"
    );
    for required_name in INCREMENT_ELEVEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-11 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_twelve_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_twelve_fp(name))
        .count();
    assert_eq!(
        increment_twelve_corpus_cases, INCREMENT_TWELVE_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-12 function"
    );
    for required_name in INCREMENT_TWELVE_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-12 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_thirteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_thirteen_fp(name))
        .count();
    assert_eq!(
        increment_thirteen_corpus_cases, INCREMENT_THIRTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-13 function"
    );
    for required_name in INCREMENT_THIRTEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-13 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_fourteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_fourteen_fp(name))
        .count();
    assert_eq!(
        increment_fourteen_corpus_cases, INCREMENT_FOURTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-14 function"
    );
    for required_name in INCREMENT_FOURTEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-14 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_fifteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_fifteen_fp(name))
        .count();
    assert_eq!(
        increment_fifteen_corpus_cases, INCREMENT_FIFTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-15 function"
    );
    for required_name in INCREMENT_FIFTEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-15 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_sixteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_sixteen_fp(name))
        .count();
    assert_eq!(
        increment_sixteen_corpus_cases, INCREMENT_SIXTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-16 function"
    );
    for required_name in INCREMENT_SIXTEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-16 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_seventeen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_seventeen_fp(name))
        .count();
    assert_eq!(
        increment_seventeen_corpus_cases, INCREMENT_SEVENTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-17 function"
    );
    for required_name in INCREMENT_SEVENTEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-17 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }
    let increment_eighteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_eighteen(name))
        .count();
    assert_eq!(
        increment_eighteen_corpus_cases, INCREMENT_EIGHTEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-18 function"
    );
    for required_name in INCREMENT_EIGHTEEN_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-18 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }

    let increment_nineteen_corpus_cases: usize = CASES
        .iter()
        .filter(|(_, name, _): &&(&str, &str, &[u8])| is_increment_nineteen_fp(name))
        .count();
    assert_eq!(
        increment_nineteen_corpus_cases, INCREMENT_NINETEEN_EXPECTED_CASES,
        "the generated corpus must contain exactly five rows per increment-19 function"
    );
    for required_name in INCREMENT_NINETEEN_FP_FUNCTIONS {
        for required_opt in CORPUS_OPTIMIZATION_LEVELS {
            assert!(
                CASES.iter().any(|(opt, name, _): &(&str, &str, &[u8])| {
                    opt == required_opt && name == required_name
                }),
                "required increment-19 case `{required_opt} {required_name}` is absent from the generated corpus"
            );
        }
    }

    let dir: tempfile::TempDir = tempfile::tempdir().expect("scratch dir");
    let battery_o: PathBuf =
        build_ground_truth_object(&compiler, dir.path()).unwrap_or_else(|error: String| {
            panic!("host compiler `{compiler}` could not build the ground-truth battery:\n{error}")
        });

    let mut attempted: usize = 0;
    let mut recovered: usize = 0;
    let mut driven: usize = 0;
    let mut fp_recovered: usize = 0;
    let mut fp_driven: usize = 0;
    let mut increment_two_recovered: usize = 0;
    let mut increment_two_driven: usize = 0;
    let mut increment_three_recovered: usize = 0;
    let mut increment_three_driven: usize = 0;
    let mut increment_four_recovered: usize = 0;
    let mut increment_four_driven: usize = 0;
    let mut increment_five_recovered: usize = 0;
    let mut increment_five_driven: usize = 0;
    let mut increment_six_recovered: usize = 0;
    let mut increment_six_driven: usize = 0;
    let mut increment_seven_recovered: usize = 0;
    let mut increment_seven_driven: usize = 0;
    let mut increment_eight_recovered: usize = 0;
    let mut increment_eight_driven: usize = 0;
    let mut increment_nine_recovered: usize = 0;
    let mut increment_nine_driven: usize = 0;
    let mut increment_ten_recovered: usize = 0;
    let mut increment_ten_driven: usize = 0;
    let mut increment_eleven_recovered: usize = 0;
    let mut increment_eleven_driven: usize = 0;
    let mut increment_twelve_recovered: usize = 0;
    let mut increment_twelve_driven: usize = 0;
    let mut increment_thirteen_recovered: usize = 0;
    let mut increment_thirteen_driven: usize = 0;
    let mut increment_fourteen_recovered: usize = 0;
    let mut increment_fourteen_driven: usize = 0;
    let mut increment_fifteen_recovered: usize = 0;
    let mut increment_fifteen_driven: usize = 0;
    let mut increment_sixteen_recovered: usize = 0;
    let mut increment_sixteen_driven: usize = 0;
    let mut increment_seventeen_recovered: usize = 0;
    let mut increment_seventeen_driven: usize = 0;
    let mut increment_eighteen_recovered: usize = 0;
    let mut increment_eighteen_driven: usize = 0;
    let mut increment_nineteen_recovered: usize = 0;
    let mut increment_nineteen_driven: usize = 0;
    let mut skips: Vec<(String, String, String)> = Vec::new();
    let mut decls: String = String::new();
    let mut blocks: String = String::new();

    for (index, (opt, name, bytes)) in CASES.iter().enumerate() {
        attempted += 1;
        let required_increment_two: bool = is_increment_two_fp(name);
        let required_increment_three: bool = is_increment_three_fp(name);
        let required_increment_four: bool = is_increment_four_fp(name);
        let required_increment_five: bool = is_increment_five_fp(name);
        let required_increment_six: bool = is_increment_six_fp(name);
        let required_increment_seven: bool = is_increment_seven_fp(name);
        let required_increment_eight: bool = is_increment_eight_fp(name);
        let required_increment_nine: bool = is_increment_nine_fp(name);
        let required_increment_ten: bool = is_increment_ten_fp(name);
        let required_increment_eleven: bool = is_increment_eleven_fp(name);
        let required_increment_twelve: bool = is_increment_twelve_fp(name);
        let required_increment_thirteen: bool = is_increment_thirteen_fp(name);
        let required_increment_fourteen: bool = is_increment_fourteen_fp(name);
        let required_increment_fifteen: bool = is_increment_fifteen_fp(name);
        let required_increment_sixteen: bool = is_increment_sixteen_fp(name);
        let required_increment_seventeen: bool = is_increment_seventeen_fp(name);
        let required_increment_eighteen: bool = is_increment_eighteen(name);
        let required_increment_nineteen: bool = is_increment_nineteen_fp(name);
        let recovery: LeafRecovery = match recover_aarch64_function(bytes, 0) {
            Ok(value) => value,
            Err(error) => {
                if required_increment_two {
                    skips.push((
                        (*opt).to_owned(),
                        (*name).to_owned(),
                        format!("required increment-2 recovery rejected: {error}"),
                    ));
                }
                continue;
            }
        };
        recovered += 1;
        if required_increment_two {
            increment_two_recovered += 1;
        }
        if required_increment_three {
            increment_three_recovered += 1;
        }
        if required_increment_four {
            increment_four_recovered += 1;
        }
        if required_increment_five {
            increment_five_recovered += 1;
        }
        if required_increment_six {
            increment_six_recovered += 1;
        }
        if required_increment_seven {
            increment_seven_recovered += 1;
        }
        if required_increment_eight {
            increment_eight_recovered += 1;
        }
        if required_increment_nine {
            increment_nine_recovered += 1;
        }
        if required_increment_ten {
            increment_ten_recovered += 1;
        }
        if required_increment_eleven {
            increment_eleven_recovered += 1;
        }
        if required_increment_twelve {
            increment_twelve_recovered += 1;
        }
        if required_increment_thirteen {
            increment_thirteen_recovered += 1;
        }
        if required_increment_fourteen {
            increment_fourteen_recovered += 1;
        }
        if required_increment_fifteen {
            increment_fifteen_recovered += 1;
        }
        if required_increment_sixteen {
            increment_sixteen_recovered += 1;
        }
        if required_increment_seventeen {
            increment_seventeen_recovered += 1;
        }
        if required_increment_eighteen {
            increment_eighteen_recovered += 1;
        }
        if required_increment_nineteen {
            increment_nineteen_recovered += 1;
        }

        let expected_fp: Option<FpExpectation> = fp_expectation(name);
        if let Some(expectation) = expected_fp {
            fp_recovered += 1;
            if recovery.fp_params.as_slice() != expectation.params
                || recovery.returns_fp != expectation.returns
                || recovery.return_width_bits != expectation.return_width_bits
            {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    format!(
                        "fp signature mismatch (recovered {:?} -> {:?}/{} bits, expected {:?} -> {:?}/{} bits)",
                        recovery.fp_params,
                        recovery.returns_fp,
                        recovery.return_width_bits,
                        expectation.params,
                        expectation.returns,
                        expectation.return_width_bits
                    ),
                ));
                continue;
            }
        } else {
            let Some(expected): Option<usize> = expected_arity(name) else {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "no driver descriptor".to_owned(),
                ));
                continue;
            };
            if recovery.returns_fp.is_some() || !recovery.fp_params.is_empty() {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    "unexpected floating-point signature".to_owned(),
                ));
                continue;
            }
            if recovery.params.len() != expected {
                skips.push((
                    (*opt).to_owned(),
                    (*name).to_owned(),
                    format!(
                        "arity mismatch (recovered {}, expected {expected})",
                        recovery.params.len()
                    ),
                ));
                continue;
            }
        }

        let rec_symbol: String = format!("rec_{opt}_{name}");
        let seed: u64 = 0x9E37_79B9_7F4A_7C15u64
            ^ (index as u64)
                .wrapping_add(1)
                .wrapping_mul(0x0000_0100_0000_01B3);
        let seed: u64 = if seed == 0 {
            0xDEAD_BEEF_CAFE_F00D
        } else {
            seed
        };
        let Some(block): Option<String> = compare_block(opt, name, &rec_symbol, seed) else {
            skips.push((
                (*opt).to_owned(),
                (*name).to_owned(),
                "no driver descriptor".to_owned(),
            ));
            continue;
        };

        decls.push_str(&rename_recovered(&recovery.source, &rec_symbol));
        decls.push('\n');
        blocks.push_str(&block);
        driven += 1;
        if expected_fp.is_some() {
            fp_driven += 1;
        }
        if required_increment_two {
            increment_two_driven += 1;
        }
        if required_increment_three {
            increment_three_driven += 1;
        }
        if required_increment_four {
            increment_four_driven += 1;
        }
        if required_increment_five {
            increment_five_driven += 1;
        }
        if required_increment_six {
            increment_six_driven += 1;
        }
        if required_increment_seven {
            increment_seven_driven += 1;
        }
        if required_increment_eight {
            increment_eight_driven += 1;
        }
        if required_increment_nine {
            increment_nine_driven += 1;
        }
        if required_increment_ten {
            increment_ten_driven += 1;
        }
        if required_increment_eleven {
            increment_eleven_driven += 1;
        }
        if required_increment_twelve {
            increment_twelve_driven += 1;
        }
        if required_increment_thirteen {
            increment_thirteen_driven += 1;
        }
        if required_increment_fourteen {
            increment_fourteen_driven += 1;
        }
        if required_increment_fifteen {
            increment_fifteen_driven += 1;
        }
        if required_increment_sixteen {
            increment_sixteen_driven += 1;
        }
        if required_increment_seventeen {
            increment_seventeen_driven += 1;
        }
        if required_increment_eighteen {
            increment_eighteen_driven += 1;
        }
        if required_increment_nineteen {
            increment_nineteen_driven += 1;
        }
    }

    assert!(
        driven != 0,
        "corpus grade produced no recovered case with a runnable driver descriptor"
    );

    let prelude: String = shared_prelude();
    let driver: String = format!(
        "#include <stdint.h>\n#include <stdio.h>\n#include <string.h>\n#include <stddef.h>\n\
         #define BUFN 16\n#define ITER 400\n\
         {EXTERNS}\n\
         static uint64_t xs(uint64_t *st) {{ uint64_t x = *st; x ^= x << 13; x ^= x >> 7; x ^= x << 17; *st = x; return x; }}\n\
         {FP_DRIVER_HELPERS}\n\
         {prelude}\n\
         static long long passed = 0;\n\
         static long long fails = 0;\n\
         {decls}\n\
         int main(void) {{\n\
         {blocks}\
         \x20   printf(\"GRADEDONE passed=%lld fails=%lld\\n\", passed, fails);\n\
         \x20   return 0;\n\
         }}\n"
    );

    let driver_c: PathBuf = dir.path().join("grade_driver.c");
    std::fs::write(&driver_c, driver.as_bytes()).expect("write grade driver");
    let harness_exe: PathBuf = dir
        .path()
        .join(if cfg!(windows) { "grade.exe" } else { "grade" });
    let link: std::process::Output = Command::new(&compiler)
        .args(ORACLE_FLAGS)
        .args(["-o"])
        .arg(&harness_exe)
        .arg(&driver_c)
        .arg(&battery_o)
        .output()
        .expect("invoke cc to link grade harness");
    assert!(
        link.status.success(),
        "grade harness failed to compile/link ({driven} driven cases): {}\n--- driver head ---\n{}",
        String::from_utf8_lossy(&link.stderr),
        driver.lines().take(40).collect::<Vec<&str>>().join("\n")
    );

    let Some(output): Option<std::process::Output> =
        run_with_watchdog(&harness_exe, Duration::from_secs(100))
    else {
        panic!("grade harness exceeded the watchdog window; a recovered loop is non-terminating");
    };
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();

    let mut wrong: Vec<(String, String, String)> = Vec::new();
    let mut graded_done: Option<(i64, i64)> = None;
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("FAIL ") {
            let mut parts = rest.splitn(3, ' ');
            let opt: &str = parts.next().unwrap_or("?");
            let name: &str = parts.next().unwrap_or("?");
            let detail: &str = parts.next().unwrap_or("");
            wrong.push((opt.to_owned(), name.to_owned(), detail.to_owned()));
        } else if let Some(rest) = line.strip_prefix("GRADEDONE ") {
            let mut p: i64 = 0;
            let mut f: i64 = 0;
            for token in rest.split_whitespace() {
                if let Some(v) = token.strip_prefix("passed=") {
                    p = v.parse().unwrap_or(0);
                } else if let Some(v) = token.strip_prefix("fails=") {
                    f = v.parse().unwrap_or(0);
                }
            }
            graded_done = Some((p, f));
        }
    }

    let Some((passed, driver_fails)): Option<(i64, i64)> = graded_done else {
        panic!(
            "grade harness produced no GRADEDONE summary; run did not complete:\nstdout:\n{stdout}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };

    let graded_equivalent: i64 = passed;
    let increment_one_fp_recovered: usize = fp_recovered
        .checked_sub(increment_two_recovered)
        .and_then(|value: usize| value.checked_sub(increment_three_recovered))
        .and_then(|value: usize| value.checked_sub(increment_four_recovered))
        .and_then(|value: usize| value.checked_sub(increment_five_recovered))
        .and_then(|value: usize| value.checked_sub(increment_six_recovered))
        .and_then(|value: usize| value.checked_sub(increment_seven_recovered))
        .and_then(|value: usize| value.checked_sub(increment_eight_recovered))
        .and_then(|value: usize| value.checked_sub(increment_nine_recovered))
        .and_then(|value: usize| value.checked_sub(increment_ten_recovered))
        .and_then(|value: usize| value.checked_sub(increment_eleven_recovered))
        .and_then(|value: usize| value.checked_sub(increment_twelve_recovered))
        .and_then(|value: usize| value.checked_sub(increment_thirteen_recovered))
        .and_then(|value: usize| value.checked_sub(increment_fourteen_recovered))
        .and_then(|value: usize| value.checked_sub(increment_fifteen_recovered))
        .and_then(|value: usize| value.checked_sub(increment_sixteen_recovered))
        .and_then(|value: usize| value.checked_sub(increment_seventeen_recovered))
        .and_then(|value: usize| value.checked_sub(increment_nineteen_recovered))
        .expect("later-increment fp recovery counts cannot exceed the fp total");
    let increment_one_fp_driven: usize = fp_driven
        .checked_sub(increment_two_driven)
        .and_then(|value: usize| value.checked_sub(increment_three_driven))
        .and_then(|value: usize| value.checked_sub(increment_four_driven))
        .and_then(|value: usize| value.checked_sub(increment_five_driven))
        .and_then(|value: usize| value.checked_sub(increment_six_driven))
        .and_then(|value: usize| value.checked_sub(increment_seven_driven))
        .and_then(|value: usize| value.checked_sub(increment_eight_driven))
        .and_then(|value: usize| value.checked_sub(increment_nine_driven))
        .and_then(|value: usize| value.checked_sub(increment_ten_driven))
        .and_then(|value: usize| value.checked_sub(increment_eleven_driven))
        .and_then(|value: usize| value.checked_sub(increment_twelve_driven))
        .and_then(|value: usize| value.checked_sub(increment_thirteen_driven))
        .and_then(|value: usize| value.checked_sub(increment_fourteen_driven))
        .and_then(|value: usize| value.checked_sub(increment_fifteen_driven))
        .and_then(|value: usize| value.checked_sub(increment_sixteen_driven))
        .and_then(|value: usize| value.checked_sub(increment_seventeen_driven))
        .and_then(|value: usize| value.checked_sub(increment_nineteen_driven))
        .expect("later-increment fp driven counts cannot exceed the fp total");
    let integer_recovered: usize = recovered
        .checked_sub(fp_recovered)
        .expect("fp recovery count cannot exceed the total");
    let integer_driven: usize = driven
        .checked_sub(fp_driven)
        .expect("fp driven count cannot exceed the total");
    eprintln!("================ AARCH64 CORPUS GRADE ================");
    eprintln!("attempted            {attempted}");
    eprintln!("recovered            {recovered}   (non-rejection; NOT a correctness claim)");
    eprintln!("driven (graded)      {driven}");
    eprintln!("fp recovered         {fp_recovered}");
    eprintln!("fp driven (graded)   {fp_driven}");
    eprintln!("increment-1 fp recovered {increment_one_fp_recovered}");
    eprintln!("increment-1 fp graded    {increment_one_fp_driven}");
    eprintln!("integer recovered    {integer_recovered}");
    eprintln!("integer graded       {integer_driven}");
    eprintln!("increment-2 recovered {increment_two_recovered}/{INCREMENT_TWO_EXPECTED_CASES}");
    eprintln!("increment-2 graded    {increment_two_driven}/{INCREMENT_TWO_EXPECTED_CASES}");
    eprintln!("increment-3 recovered {increment_three_recovered}/{INCREMENT_THREE_EXPECTED_CASES}");
    eprintln!("increment-3 graded    {increment_three_driven}/{INCREMENT_THREE_EXPECTED_CASES}");
    eprintln!("increment-4 recovered {increment_four_recovered}/{INCREMENT_FOUR_EXPECTED_CASES}");
    eprintln!("increment-4 graded    {increment_four_driven}/{INCREMENT_FOUR_EXPECTED_CASES}");
    eprintln!("increment-5 recovered {increment_five_recovered}/{INCREMENT_FIVE_EXPECTED_CASES}");
    eprintln!("increment-5 graded    {increment_five_driven}/{INCREMENT_FIVE_EXPECTED_CASES}");
    eprintln!("increment-6 recovered {increment_six_recovered}/{INCREMENT_SIX_EXPECTED_CASES}");
    eprintln!("increment-6 graded    {increment_six_driven}/{INCREMENT_SIX_EXPECTED_CASES}");
    eprintln!("increment-7 recovered {increment_seven_recovered}/{INCREMENT_SEVEN_EXPECTED_CASES}");
    eprintln!("increment-7 graded    {increment_seven_driven}/{INCREMENT_SEVEN_EXPECTED_CASES}");
    eprintln!("increment-8 recovered {increment_eight_recovered}/{INCREMENT_EIGHT_EXPECTED_CASES}");
    eprintln!("increment-8 graded    {increment_eight_driven}/{INCREMENT_EIGHT_EXPECTED_CASES}");
    eprintln!("increment-9 recovered {increment_nine_recovered}/{INCREMENT_NINE_EXPECTED_CASES}");
    eprintln!("increment-9 graded    {increment_nine_driven}/{INCREMENT_NINE_EXPECTED_CASES}");
    eprintln!("increment-10 recovered {increment_ten_recovered}/{INCREMENT_TEN_EXPECTED_CASES}");
    eprintln!("increment-10 graded    {increment_ten_driven}/{INCREMENT_TEN_EXPECTED_CASES}");
    eprintln!(
        "increment-11 recovered {increment_eleven_recovered}/{INCREMENT_ELEVEN_EXPECTED_CASES}"
    );
    eprintln!("increment-11 graded    {increment_eleven_driven}/{INCREMENT_ELEVEN_EXPECTED_CASES}");
    eprintln!(
        "increment-12 recovered {increment_twelve_recovered}/{INCREMENT_TWELVE_EXPECTED_CASES}"
    );
    eprintln!("increment-12 graded    {increment_twelve_driven}/{INCREMENT_TWELVE_EXPECTED_CASES}");
    eprintln!(
        "increment-13 recovered {increment_thirteen_recovered}/{INCREMENT_THIRTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-13 graded    {increment_thirteen_driven}/{INCREMENT_THIRTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-14 recovered {increment_fourteen_recovered}/{INCREMENT_FOURTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-14 graded    {increment_fourteen_driven}/{INCREMENT_FOURTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-15 recovered {increment_fifteen_recovered}/{INCREMENT_FIFTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-15 graded    {increment_fifteen_driven}/{INCREMENT_FIFTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-16 recovered {increment_sixteen_recovered}/{INCREMENT_SIXTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-16 graded    {increment_sixteen_driven}/{INCREMENT_SIXTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-17 recovered {increment_seventeen_recovered}/{INCREMENT_SEVENTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-17 graded    {increment_seventeen_driven}/{INCREMENT_SEVENTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-18 recovered {increment_eighteen_recovered}/{INCREMENT_EIGHTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-18 graded    {increment_eighteen_driven}/{INCREMENT_EIGHTEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-19 recovered {increment_nineteen_recovered}/{INCREMENT_NINETEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "increment-19 graded    {increment_nineteen_driven}/{INCREMENT_NINETEEN_EXPECTED_CASES}"
    );
    eprintln!(
        "graded-equivalent    {graded_equivalent}   (recompiled + behaviorally matched on directed and random inputs)"
    );
    eprintln!(
        "recovered-but-wrong  {driver_fails}   (recovered, driven, diverged from ground truth)"
    );
    eprintln!("skipped-from-grading {}", skips.len());

    if !wrong.is_empty() {
        eprintln!("---- recovered-but-wrong (CORRECTNESS BUGS) ----");
        for (opt, name, detail) in &wrong {
            eprintln!("  WRONG {opt} {name}  {detail}");
        }
    }
    if !skips.is_empty() {
        eprintln!("---- skipped-from-grading (with reason) ----");
        let mut reason_counts: BTreeMap<String, usize> = BTreeMap::new();
        for (opt, name, reason) in &skips {
            eprintln!("  SKIP {opt} {name}: {reason}");
            *reason_counts.entry(reason.clone()).or_default() += 1;
        }
        eprintln!("  reason tally:");
        for (reason, count) in &reason_counts {
            eprintln!("    {count}x  {reason}");
        }
    }
    eprintln!("=====================================================");

    assert_eq!(
        i64::try_from(driven).unwrap_or(-1),
        passed + driver_fails,
        "every driven case must be accounted for as pass or fail"
    );
    assert_eq!(
        driver_fails as usize,
        wrong.len(),
        "driver fail count must match the enumerated recovered-but-wrong list"
    );
    assert_eq!(
        driver_fails, 0,
        "every driven recovery must be behaviorally equivalent"
    );
    assert_eq!(
        increment_one_fp_recovered, INCREMENT_ONE_EXPECTED_FP_CASES,
        "all increment-1 fp cases must remain recovered"
    );
    assert_eq!(
        increment_one_fp_driven, INCREMENT_ONE_EXPECTED_FP_CASES,
        "all increment-1 fp cases must remain graded"
    );
    assert_eq!(
        integer_recovered, EXPECTED_INTEGER_CASES,
        "all previously recovered integer cases must remain recovered"
    );
    assert_eq!(
        integer_driven, EXPECTED_INTEGER_CASES,
        "all previously graded integer cases must remain graded"
    );
    assert_eq!(
        increment_two_recovered, INCREMENT_TWO_EXPECTED_CASES,
        "every increment-2 corpus case must recover"
    );
    assert_eq!(
        increment_three_recovered, INCREMENT_THREE_EXPECTED_CASES,
        "every increment-3 corpus case must recover"
    );
    assert_eq!(
        increment_three_driven, INCREMENT_THREE_EXPECTED_CASES,
        "every increment-3 corpus case must be graded"
    );
    assert_eq!(
        increment_two_driven, INCREMENT_TWO_EXPECTED_CASES,
        "every increment-2 corpus case must be graded"
    );
    assert_eq!(
        increment_four_recovered, INCREMENT_FOUR_EXPECTED_CASES,
        "every increment-4 corpus case must recover"
    );
    assert_eq!(
        increment_four_driven, INCREMENT_FOUR_EXPECTED_CASES,
        "every increment-4 corpus case must be graded"
    );
    assert_eq!(
        increment_five_recovered, INCREMENT_FIVE_EXPECTED_CASES,
        "every increment-5 corpus case must recover"
    );
    assert_eq!(
        increment_five_driven, INCREMENT_FIVE_EXPECTED_CASES,
        "every increment-5 corpus case must be graded"
    );
    assert_eq!(
        increment_six_recovered, INCREMENT_SIX_EXPECTED_CASES,
        "every increment-6 corpus case must recover"
    );
    assert_eq!(
        increment_six_driven, INCREMENT_SIX_EXPECTED_CASES,
        "every increment-6 corpus case must be graded"
    );
    assert_eq!(
        increment_seven_recovered, INCREMENT_SEVEN_EXPECTED_CASES,
        "every increment-7 corpus case must recover"
    );
    assert_eq!(
        increment_seven_driven, INCREMENT_SEVEN_EXPECTED_CASES,
        "every increment-7 corpus case must be graded"
    );
    assert_eq!(
        increment_eight_recovered, INCREMENT_EIGHT_EXPECTED_CASES,
        "every increment-8 corpus case must recover"
    );
    assert_eq!(
        increment_eight_driven, INCREMENT_EIGHT_EXPECTED_CASES,
        "every increment-8 corpus case must be graded"
    );
    assert_eq!(
        increment_nine_recovered, INCREMENT_NINE_EXPECTED_CASES,
        "every increment-9 corpus case must recover"
    );
    assert_eq!(
        increment_nine_driven, INCREMENT_NINE_EXPECTED_CASES,
        "every increment-9 corpus case must be graded"
    );
    assert_eq!(
        increment_ten_recovered, INCREMENT_TEN_EXPECTED_CASES,
        "every increment-10 corpus case must recover"
    );
    assert_eq!(
        increment_ten_driven, INCREMENT_TEN_EXPECTED_CASES,
        "every increment-10 corpus case must be graded"
    );
    assert_eq!(
        increment_eleven_recovered, INCREMENT_ELEVEN_EXPECTED_CASES,
        "every increment-11 corpus case must recover"
    );
    assert_eq!(
        increment_eleven_driven, INCREMENT_ELEVEN_EXPECTED_CASES,
        "every increment-11 corpus case must be graded"
    );
    assert_eq!(
        increment_twelve_recovered, INCREMENT_TWELVE_EXPECTED_CASES,
        "every increment-12 corpus case must recover"
    );
    assert_eq!(
        increment_twelve_driven, INCREMENT_TWELVE_EXPECTED_CASES,
        "every increment-12 corpus case must be graded"
    );
    assert_eq!(
        increment_thirteen_recovered, INCREMENT_THIRTEEN_EXPECTED_CASES,
        "every increment-13 corpus case must recover"
    );
    assert_eq!(
        increment_thirteen_driven, INCREMENT_THIRTEEN_EXPECTED_CASES,
        "every increment-13 corpus case must be graded"
    );
    assert_eq!(
        increment_fourteen_recovered, INCREMENT_FOURTEEN_EXPECTED_CASES,
        "every increment-14 corpus case must recover"
    );
    assert_eq!(
        increment_fourteen_driven, INCREMENT_FOURTEEN_EXPECTED_CASES,
        "every increment-14 corpus case must be graded"
    );
    assert_eq!(
        increment_fifteen_recovered, INCREMENT_FIFTEEN_EXPECTED_CASES,
        "every increment-15 corpus case must recover"
    );
    assert_eq!(
        increment_fifteen_driven, INCREMENT_FIFTEEN_EXPECTED_CASES,
        "every increment-15 corpus case must be graded"
    );
    assert_eq!(
        increment_sixteen_recovered, INCREMENT_SIXTEEN_EXPECTED_CASES,
        "every increment-16 corpus case must recover"
    );
    assert_eq!(
        increment_seventeen_recovered, INCREMENT_SEVENTEEN_EXPECTED_CASES,
        "every increment-17 corpus case must recover"
    );
    assert_eq!(
        increment_seventeen_driven, INCREMENT_SEVENTEEN_EXPECTED_CASES,
        "every increment-17 corpus case must be graded"
    );
    assert_eq!(
        increment_eighteen_recovered, INCREMENT_EIGHTEEN_EXPECTED_CASES,
        "every increment-18 corpus case must recover"
    );
    assert_eq!(
        increment_eighteen_driven, INCREMENT_EIGHTEEN_EXPECTED_CASES,
        "every increment-18 corpus case must be graded"
    );
    assert_eq!(
        increment_sixteen_driven, INCREMENT_SIXTEEN_EXPECTED_CASES,
        "every increment-16 corpus case must be graded"
    );
    assert_eq!(
        increment_nineteen_recovered, INCREMENT_NINETEEN_EXPECTED_CASES,
        "every increment-19 corpus case must recover"
    );
    assert_eq!(
        increment_nineteen_driven, INCREMENT_NINETEEN_EXPECTED_CASES,
        "every increment-19 corpus case must be graded"
    );
    assert!(
        skips.is_empty(),
        "every recovered case must have a runnable, signature-matched driver"
    );
}

#[test]
fn corpus_grade_fails_when_host_compiler_is_unavailable() {
    let test_binary: PathBuf = std::env::current_exe().expect("current test binary");
    let output: std::process::Output = Command::new(test_binary)
        .args([
            "--ignored",
            "--exact",
            "corpus_grade_report",
            "--test-threads=1",
        ])
        .env("PATH", "")
        .output()
        .expect("run corpus grade without a host compiler");
    let stdout: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr: String = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        !output.status.success(),
        "the corpus grade passed without a host compiler; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        format!("{stdout}\n{stderr}").contains("corpus grade requires a host C compiler on PATH"),
        "the corpus grade failed for an unrelated reason; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}
