#![allow(clippy::panic)]

use std::collections::BTreeMap;

use disrobe_pass_native::{LeafRecovery, recover_aarch64_function};

include!("aarch64_fp_sweep_corpus.inc");

const GENERIC_REJECTS: &[&str] = &["unsupported instruction", "unsupported wide move"];

const EXPECTED_ABSTENTIONS: &[(&str, &str)] = &[
    (
        "g_frint32x_d",
        "range-limited rounding uses the untracked FPCR rounding mode",
    ),
    (
        "g_frint64x_s",
        "range-limited rounding uses the untracked FPCR rounding mode",
    ),
    (
        "g_frinti_d",
        "round to integral uses the untracked FPCR rounding mode",
    ),
    (
        "g_frinti_h",
        "round to integral uses the untracked FPCR rounding mode",
    ),
    (
        "g_frintx_d",
        "round to integral uses the untracked FPCR rounding mode",
    ),
    (
        "g_frintx_h",
        "round to integral uses the untracked FPCR rounding mode",
    ),
    (
        "h_fmov_top_half",
        "vector-lane floating-point move is outside scalar floating-point recovery",
    ),
    (
        "i_ldr_lit_s",
        "floating-point literal bytes are unavailable from the image context",
    ),
    (
        "i_ldr_lit_d",
        "floating-point literal bytes are unavailable from the image context",
    ),
    (
        "j_stp_d",
        "result-free return is ambiguous across integer, floating-point, and void signatures",
    ),
    (
        "j_str_d_pre",
        "result-free return is ambiguous across integer, floating-point, and void signatures",
    ),
];

const PSEUDO_RUST_GAPS: &[&str] = &[];

const GATED_ENCODINGS: &[&str] = &[
    "fjcvtzs",
    "frint32x",
    "frint64x",
    "frint32z",
    "frint64z",
    "fadd h0, h0, h1",
    "fmov h0, h1",
    "fcvt h0, d0",
    "fmov x0, h0",
    "fmov h0, x0",
];

fn abstentions() -> BTreeMap<&'static str, String> {
    SWEEP_CASES
        .iter()
        .filter_map(|(name, bytes, _): &(&str, &[u8], &str)| {
            recover_aarch64_function(bytes, 0)
                .err()
                .map(|error| (*name, error.to_string()))
        })
        .collect()
}

#[test]
fn the_assembled_sweep_still_carries_every_feature_gated_encoding() {
    assert!(
        SWEEP_CASES.len() >= 156,
        "the assembled sweep shrank to {} cases; a rebuild dropped encodings",
        SWEEP_CASES.len()
    );
    let listing: String = SWEEP_CASES
        .iter()
        .map(|(_, _, reference): &(&str, &[u8], &str)| *reference)
        .collect::<Vec<&str>>()
        .join(" ; ");
    for encoding in GATED_ENCODINGS {
        assert!(
            listing.contains(encoding),
            "the reference disassembly no longer contains {encoding}; the assembler dropped a gated feature"
        );
    }
    for (name, bytes, reference) in SWEEP_CASES {
        assert!(
            bytes.len() % 4 == 0 && !bytes.is_empty(),
            "{name} is not a whole number of aarch64 words"
        );
        assert!(!reference.is_empty(), "{name} has no reference disassembly");
    }
}

#[test]
fn every_declared_scalar_form_recovers_except_the_recorded_abstentions() {
    let observed: BTreeMap<&'static str, String> = abstentions();
    let expected: BTreeMap<&'static str, &'static str> =
        EXPECTED_ABSTENTIONS.iter().copied().collect();
    let observed_names: Vec<&&str> = observed.keys().collect();
    let expected_names: Vec<&&str> = expected.keys().collect();
    assert_eq!(
        observed_names, expected_names,
        "the abstention inventory moved; observed reasons: {observed:#?}"
    );
    for (name, reason) in &observed {
        let required: &str = expected
            .get(name)
            .unwrap_or_else(|| panic!("{name} abstained without a recorded reason"));
        assert!(
            reason.contains(required),
            "{name} must abstain naming {required}, got: {reason}"
        );
    }
}

#[test]
fn no_scalar_form_abstains_through_a_generic_catch_all() {
    for (name, reason) in abstentions() {
        for generic in GENERIC_REJECTS {
            assert!(
                !reason.contains(generic),
                "{name} abstains through the catch-all {generic:?} instead of a specific reason: {reason}"
            );
        }
    }
}

fn mentions_a_vector_register(reference: &str) -> bool {
    reference
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .any(|token: &str| match token.split_at_checked(1) {
            Some(("q" | "v", digits)) => {
                !digits.is_empty() && digits.bytes().all(|byte: u8| byte.is_ascii_digit())
            }
            _ => false,
        })
}

#[test]
fn recovered_scalar_forms_reach_both_emitted_backends() {
    let expected: BTreeMap<&'static str, &'static str> =
        EXPECTED_ABSTENTIONS.iter().copied().collect();
    let mut recovered: usize = 0;
    let mut scalar_with_rust: usize = 0;
    for (name, bytes, reference) in SWEEP_CASES {
        if expected.contains_key(name) {
            continue;
        }
        let recovery: LeafRecovery = recover_aarch64_function(bytes, 0)
            .unwrap_or_else(|error| panic!("{name} ({reference}) must recover: {error}"));
        assert!(
            !recovery.source.is_empty(),
            "{name} recovered without emitted c"
        );
        recovered += 1;
        if mentions_a_vector_register(reference) {
            continue;
        }
        let Some(rust): Option<&str> = recovery.rust_source.as_deref() else {
            assert!(
                PSEUDO_RUST_GAPS.contains(name),
                "{name} ({reference}) recovered c but no pseudo-rust, and is not a recorded gap"
            );
            continue;
        };
        assert!(
            !PSEUDO_RUST_GAPS.contains(name),
            "{name} now reaches pseudo-rust; drop it from the recorded gaps"
        );
        assert!(!rust.is_empty(), "{name} recovered an empty pseudo-rust");
        scalar_with_rust += 1;
    }
    assert!(
        recovered + EXPECTED_ABSTENTIONS.len() == SWEEP_CASES.len(),
        "every sweep case must be classified"
    );
    assert!(
        scalar_with_rust >= 143,
        "only {scalar_with_rust} scalar forms reached pseudo-rust; the second backend regressed"
    );
}

const UNTYPED_CALLEE_SAVED_STORE: [u8; 8] = [0x08, 0x00, 0x00, 0xfd, 0xc0, 0x03, 0x5f, 0xd6];
const FRAMED_VECTOR_STACK_ARGUMENT: [u8; 20] = [
    0xff, 0x43, 0x00, 0xd1, 0xe0, 0x07, 0xc0, 0x3d, 0x00, 0x84, 0xa0, 0x4e, 0xff, 0x43, 0x00, 0x91,
    0xc0, 0x03, 0x5f, 0xd6,
];

#[test]
fn a_callee_saved_store_outside_a_prologue_still_refuses() {
    let Err(error) = recover_aarch64_function(&UNTYPED_CALLEE_SAVED_STORE, 0) else {
        panic!("an untyped d8 store through a pointer is not a frame spill");
    };
    assert!(
        error
            .to_string()
            .contains("an untyped d-register store is outside the scalar argument registers"),
        "{error:?}"
    );
}

#[test]
fn an_incoming_stack_argument_read_as_a_vector_refuses_rather_than_inventing_a_signature() {
    let Err(error) = recover_aarch64_function(&FRAMED_VECTOR_STACK_ARGUMENT, 0) else {
        panic!("the vector path does not model an incoming stack argument");
    };
    assert!(
        error
            .to_string()
            .contains("outside the [0, 16) bytes this frame owns"),
        "{error:?}"
    );
}
