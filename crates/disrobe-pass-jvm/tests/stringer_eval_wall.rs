#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use disrobe_pass_jvm::{ClassFile, parse_classfile, recover_reflective_self_hash_empty_fold};

const UH: &[u8] = include_bytes!("../../../corpus/jvm/stringer/uh.class");
const DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");

const EMPTY_FOLD_DECOY: i64 = 2_202_906_307_356_721_367;
const GENUINE_RUNTIME_FOLD: i64 = 1_738_644_257_434_835_613;

#[test]
fn real_stringer_flow_class_parses_despite_invalid_modified_utf8() {
    let cf: ClassFile = parse_classfile(UH).expect(
        "Stringer emits unpaired surrogates in its encrypted pool constants; the tolerant \
                 modified-utf8 decoder must parse the class rather than reject the whole artifact",
    );
    assert_eq!(cf.this_class_name().ok(), Some("ube/tms/uh"));
    assert!(
        cf.methods.iter().any(|m| cf
            .utf8_at(m.descriptor_index)
            .is_ok_and(|d: &str| d == "(JJ[B)J")),
        "the SipHash-2-4 fold method O(long,long,byte[]) is present in the parsed class"
    );
}

#[test]
fn self_tamper_empty_fold_is_a_decoy_not_the_runtime_key_word() {
    let cf: ClassFile = parse_classfile(UH).expect("uh.class parses");
    let empty_fold: Option<i64> = recover_reflective_self_hash_empty_fold(&cf);
    assert_eq!(
        empty_fold,
        Some(EMPTY_FOLD_DECOY),
        "disrobe evaluates the class's own O(long,long,byte[]) fold over an EMPTY input and gets \
         abs(SipHash-2-4(seed, seed, [])) = 2202906307356721367. This equals ube.tms.uh.O(0,0,[]) \
         under a JVM, but it is NOT the key that decrypts the constants"
    );
    assert_ne!(
        empty_fold,
        Some(GENUINE_RUNTIME_FOLD),
        "the genuine ube.tms.uh.B() returns 1738644257434835613 when run from the full 305 KB \
         jar: its reflective getResourceAsStream/ZipInputStream walk folds the enclosing jar's \
         ZIP directory (every sibling entry's name and size, 3539 bytes on the real sample), not \
         an empty stream. That directory is absent from this committed few-class artifact, so the \
         self-tamper word (AES key word 2) and therefore the cleartext are an information-\
         theoretic wall here. Ground truth captured under Temurin JDK 8 from the CC0 \
         huzpsb/JavaObfuscatorTest Stringer.jar: pack.tests.basics.accu.Digi constants #27/#50/#52 \
         decrypt to PASS/FAIL/FAIL, and both ube.tms.uh.B() and pack.tests.basics.accu.d.y() \
         return 1738644257434835613 in the sealed-jar runtime"
    );
}

#[test]
fn stringer_caller_class_without_self_hash_reports_no_empty_fold() {
    let cf: ClassFile = parse_classfile(DIGI).expect("Digi.class parses");
    assert_eq!(
        recover_reflective_self_hash_empty_fold(&cf),
        None,
        "Digi is a caller carrying encrypted constants, not the decryptor; it has no reflective \
         self-tamper fold, so no fold value is produced for it"
    );
}
