#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{DecompiledClass, decompile_classfile_bytes};

const SKID_CLASS: &[u8] =
    include_bytes!("../../../corpus/jvm/obfuscators/skidfuscator/Sample-skid.class");

fn classify_then_branch(body: &str) -> String {
    let classify: &str = body
        .split("classify")
        .nth(1)
        .expect("classify method present in decompiled output");
    classify
        .split("else")
        .next()
        .unwrap_or(classify)
        .to_string()
}

#[test]
fn real_skidfuscator_integer_obfuscation_folds_to_literals() {
    let class: DecompiledClass = decompile_classfile_bytes(SKID_CLASS).expect("decompile");
    let then: String = classify_then_branch(&class.source);
    assert!(
        then.contains("= 10"),
        "the real Skidfuscator XOR-seed encoded `n > 10` threshold must fold back to the literal 10; \
         before the constant-fold pass it rendered as `(449603618 ^ var11)`: {then}"
    );
    assert!(
        then.contains("* var") && then.contains("= 2"),
        "the encoded `n * 2` factor must fold back to the literal 2 (used in the multiply): {then}"
    );
}

#[test]
fn real_skidfuscator_raw_xor_seed_constants_do_not_survive_in_the_recovered_branch() {
    let class: DecompiledClass = decompile_classfile_bytes(SKID_CLASS).expect("decompile");
    let then: String = classify_then_branch(&class.source);
    assert!(
        !then.contains("449603618") && !then.contains("2096576427"),
        "the XOR-seed encoding constants must be folded out of the recovered then-branch, \
         not left raw: {then}"
    );
}
