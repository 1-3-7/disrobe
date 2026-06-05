#![allow(clippy::expect_used, clippy::unwrap_used)]

use disrobe_pass_jvm::stringer_protector::{self, count_residual_encrypted_strings};
use disrobe_pass_jvm::{
    ClassFile, ConstantPoolEntry, PeelStatus, ProtectorPeelReport, parse_classfile,
};

const DIGI: &[u8] = include_bytes!("../../../corpus/jvm/stringer/Digi.class");

const DECRYPT_SIG: &str = "(Ljava/lang/Object;I)Ljava/lang/String;";

fn descriptors_present(cf: &ClassFile) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::NameAndType {
            descriptor_index, ..
        } = entry
            && let Ok(desc) = cf.utf8_at(*descriptor_index)
        {
            out.push(desc.to_owned());
        }
    }
    out
}

fn has_named_method_ref(cf: &ClassFile, name: &str, descriptor: &str) -> bool {
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::NameAndType {
            name_index,
            descriptor_index,
        } = entry
            && let Ok(n) = cf.utf8_at(*name_index)
            && let Ok(d) = cf.utf8_at(*descriptor_index)
            && n == name
            && d == descriptor
        {
            return true;
        }
    }
    false
}

#[test]
fn real_stringer_digi_class_is_honest_detect_only() {
    let Ok(cf): Result<ClassFile, _> = parse_classfile(DIGI) else {
        unreachable!("real Stringer Digi.class must parse")
    };

    let descriptors: Vec<String> = descriptors_present(&cf);
    assert!(
        descriptors.iter().any(|d: &String| d == DECRYPT_SIG),
        "Digi.class must carry the real Stringer decrypt call signature {DECRYPT_SIG}"
    );

    assert!(
        has_named_method_ref(&cf, "toCharArray", "()[C"),
        "the encrypted constant is loaded via String.toCharArray() before the decrypt call"
    );

    assert_eq!(
        count_residual_encrypted_strings(&cf),
        3,
        "the three high-code-unit encrypted constants must stay opaque"
    );

    let report: ProtectorPeelReport =
        stringer_protector::peel(&cf, "pack/tests/basics/accu/Digi", "J");
    assert_eq!(
        report.status,
        PeelStatus::DetectOnly,
        "Stringer's stack-trace-keyed cipher cannot be statically reproduced; peel must stay detect-only"
    );
    assert!(
        report.strings_recovered.is_empty(),
        "detect-only peel must not fabricate plaintext for the real protected class"
    );
    assert_eq!(report.strings_residual, 3);
}
