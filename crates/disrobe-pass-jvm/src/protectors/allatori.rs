use std::collections::BTreeMap;

use crate::bytecode::{self, Instruction, Operands};
use crate::bytecode_eval::{CallerContext, DecryptMethod, evaluate_decrypt, find_decrypt_methods};
use crate::classfile::{ClassFile, ConstantPoolEntry, MethodInfo};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[must_use]
pub fn looks_like_encrypted(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let len: usize = s.chars().count();
    if len < 3 {
        return false;
    }
    let high_or_ctrl: usize = s
        .chars()
        .filter(|c: &char| {
            let v: u32 = *c as u32;
            v < 0x20 || v > 0x7E
        })
        .count();
    (high_or_ctrl as f64 / len as f64) > 0.35
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WatermarkStrip {
    pub fields_removed: Vec<String>,
    pub strings_removed: Vec<String>,
}

#[must_use]
pub fn strip_watermarks(cf: &ClassFile) -> WatermarkStrip {
    let mut out: WatermarkStrip = WatermarkStrip::default();
    for f in &cf.fields {
        if let Ok(name) = cf.utf8_at(f.name_index)
            && (name.starts_with("AllatoriWM")
                || name == "ALLATORI_WATERMARK"
                || name.starts_with("AWM_"))
        {
            out.fields_removed.push(name.to_string());
        }
    }
    for s in cf.collect_strings().values() {
        if s.starts_with("AllatoriWatermark:")
            || s.starts_with("WM:")
            || s.starts_with("[ALLATORI]")
        {
            out.strings_removed.push(s.clone());
        }
    }
    out
}

pub fn peel(cf: &ClassFile, _class_name: &str, _default_method: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::Allatori);
    let via_stub: usize = crate::protectors::recover_via_embedded_stub(cf, &mut report);
    let via_scheme: usize = recover_via_char_array_scheme(cf, &mut report);
    if via_stub + via_scheme > 0 {
        report.strings_residual = count_residual_encrypted_strings(cf);
        return finish_allatori(cf, report);
    }
    if crate::protectors::recover_via_name_keyed_fallback(
        cf,
        &mut report,
        crate::protectors::name_keyed::NameKeyedCipher::Allatori,
    ) > 0
    {
        report.strings_residual = count_residual_encrypted_strings(cf);
        return finish_allatori(cf, report);
    }
    report.status = PeelStatus::DetectOnly;
    report.strings_residual = count_residual_encrypted_strings(cf);
    if cf.this_class_name().map(str::is_empty).unwrap_or(true) {
        report.notes.push(
            "no embedded decrypt method reachable from a static call site and the class carries no \
             retained this_class name to supply as the caller frame; the Allatori string cipher \
             cannot be exercised statically"
                .to_owned(),
        );
    } else if char_array_decrypt_methods(cf).is_empty() {
        report.notes.push(
            "the encrypted literals are decrypted by a method that lives in a sibling class; the \
             per-class peel sees no local decryptor body to exercise against them"
                .to_owned(),
        );
    }
    finish_allatori(cf, report)
}

fn recover_via_char_array_scheme(cf: &ClassFile, report: &mut ProtectorPeelReport) -> usize {
    let methods: Vec<DecryptMethod> = char_array_decrypt_methods(cf);
    if methods.is_empty() {
        return 0;
    }
    let owner: String = cf
        .this_class_name()
        .map_or_else(|_| String::new(), str::to_owned);
    let caller: CallerContext = CallerContext::new(owner, "decrypt".to_owned());
    let strings: BTreeMap<u16, String> = cf.collect_strings();

    let mut recovered: usize = 0;
    for (utf8_idx, cipher) in &strings {
        if report.strings_recovered.contains_key(utf8_idx) {
            continue;
        }
        if cipher.is_empty() || !has_nonprintable_unit(cipher) {
            continue;
        }
        for method in &methods {
            let Ok(plain): Result<String, crate::bytecode_eval::EvalError> =
                evaluate_decrypt(cf, method, cipher, i32::from(*utf8_idx), &caller)
            else {
                continue;
            };
            if plain != *cipher && is_plausibly_readable(&plain) {
                report.strings_recovered.insert(*utf8_idx, plain);
                recovered += 1;
                break;
            }
        }
    }

    if recovered > 0 {
        if report.status == PeelStatus::DetectOnly {
            report.status = PeelStatus::CipherRecovered;
        }
        report.notes.push(format!(
            "recovered {recovered} string(s) by executing the class's injected char-array decrypt \
             method against the encrypted constant pool: the two byte masks are folded from the \
             method's own constant prologue and applied as an alternating XOR walked from the last \
             code unit toward the first"
        ));
    }
    recovered
}

#[must_use]
fn has_nonprintable_unit(s: &str) -> bool {
    s.chars().any(|c: char| {
        let v: u32 = c as u32;
        (v < 0x20 && c != '\t' && c != '\n' && c != '\r') || v > 0x7E
    })
}

#[must_use]
fn char_array_decrypt_methods(cf: &ClassFile) -> Vec<DecryptMethod> {
    find_decrypt_methods(cf)
        .into_iter()
        .filter(|m: &DecryptMethod| {
            !m.takes_int && method_has_char_array_xor_shape(cf, m.method_index)
        })
        .collect()
}

#[must_use]
fn method_has_char_array_xor_shape(cf: &ClassFile, method_index: usize) -> bool {
    let Some(method): Option<&MethodInfo> = cf.methods.get(method_index) else {
        return false;
    };
    let Some(code): Option<bytecode::CodeAttribute> = method_code(cf, method) else {
        return false;
    };
    let Ok(insns): Result<Vec<Instruction>, crate::error::Error> =
        bytecode::disassemble(&code.code)
    else {
        return false;
    };

    let mut new_char_array: bool = false;
    let mut char_at: bool = false;
    let mut xor: bool = false;
    let mut castore: bool = false;
    let mut descending_index: bool = false;
    let mut string_from_chars: bool = false;

    for insn in &insns {
        match insn.opcode {
            0xBC => {
                if matches!(insn.operands, Operands::NewArray(5)) {
                    new_char_array = true;
                }
            }
            0x82 => xor = true,
            0x55 => castore = true,
            0x84 => {
                if let Operands::Iinc { delta, .. } = insn.operands
                    && delta < 0
                {
                    descending_index = true;
                }
            }
            0xB6..=0xB9 => {
                let (Operands::ConstPool(cp) | Operands::InvokeInterface { index: cp, .. }) =
                    insn.operands
                else {
                    continue;
                };
                let Some(sig): Option<String> = bytecode::resolve_ref(cf, cp) else {
                    continue;
                };
                if sig.starts_with("java/lang/String.charAt:") {
                    char_at = true;
                } else if sig.starts_with("java/lang/String.<init>:([C)") {
                    string_from_chars = true;
                }
            }
            _ => {}
        }
    }

    new_char_array && char_at && xor && castore && descending_index && string_from_chars
}

fn method_code(cf: &ClassFile, method: &MethodInfo) -> Option<bytecode::CodeAttribute> {
    for attr in &method.attributes {
        let Ok(name): Result<&str, crate::error::Error> = cf.utf8_at(attr.name_index) else {
            continue;
        };
        if name == "Code"
            && let Ok(code) = bytecode::parse_code_attribute(&attr.info)
        {
            return Some(code);
        }
    }
    None
}

#[must_use]
pub fn count_residual_encrypted_strings(cf: &ClassFile) -> usize {
    cf.collect_strings()
        .values()
        .filter(|s: &&String| !is_plausibly_readable(s))
        .count()
}

fn finish_allatori(cf: &ClassFile, mut report: ProtectorPeelReport) -> ProtectorPeelReport {
    let wm: WatermarkStrip = strip_watermarks(cf);
    for name in wm.fields_removed {
        report.watermarks_stripped.push(format!("field:{name}"));
    }
    for s in wm.strings_removed {
        report.watermarks_stripped.push(format!("string:{s}"));
    }

    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::Utf8(s) = entry
            && (s.to_lowercase().contains("allatori") || s.to_lowercase().contains("smardec"))
        {
            report.notes.push(format!("allatori-marker: {s}"));
        }
    }
    report
}

#[must_use]
pub fn is_plausibly_readable(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let printable: usize = s
        .chars()
        .filter(|c: &char| c.is_ascii_graphic() || *c == ' ' || *c == '\t' || *c == '\n')
        .count();
    let ratio: f64 = printable as f64 / s.chars().count() as f64;
    ratio > 0.85
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    const REAL_ALLATORI: &[u8] =
        include_bytes!("../../../../corpus/jvm/allatori/AllatoriStrings.class");

    const REAL_ORACLE: &[&str] = &[
        "jdbc:postgresql://10.4.2.9:5432/ledger_main",
        "sk-live-7f3a9c1d-2b8e-4f60-a1d2-payments-prod",
        "/opt/disrobe/conf/keystore.p12",
        "s3://disrobe-artifacts/build/release",
        "config-key=disrobe-static-test-marker",
    ];

    #[test]
    fn char_array_scheme_alone_recovers_real_sample_plaintext() {
        let cf: ClassFile = crate::classfile::parse(REAL_ALLATORI).expect("real sample parses");
        assert!(
            !char_array_decrypt_methods(&cf).is_empty(),
            "the injected char-array decryptor must be fingerprinted in the real sample"
        );
        let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::Allatori);
        let recovered: usize = recover_via_char_array_scheme(&cf, &mut report);
        assert!(recovered >= REAL_ORACLE.len());
        assert_eq!(report.status, PeelStatus::CipherRecovered);
        for want in REAL_ORACLE {
            assert!(
                report
                    .strings_recovered
                    .values()
                    .any(|s: &String| s == want),
                "the dedicated scheme must recover {want:?} on its own; got {:?}",
                report.strings_recovered
            );
        }
    }

    #[test]
    fn looks_like_encrypted_flags_explicit_high_entropy() {
        let high_entropy: &str = "\u{0001}\u{0002}\u{0003}\u{00FF}\u{00AB}\u{0014}";
        assert!(looks_like_encrypted(high_entropy));
        assert!(!looks_like_encrypted("plain ascii text"));
    }

    #[test]
    fn watermark_field_collected() {
        let mut cp: Vec<ConstantPoolEntry> = vec![ConstantPoolEntry::Placeholder];
        cp.push(ConstantPoolEntry::Utf8("AllatoriWM_0".into()));
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: vec![crate::classfile::FieldInfo {
                access_flags: 0,
                name_index: 1,
                descriptor_index: 1,
                attributes: Vec::new(),
            }],
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let w: WatermarkStrip = strip_watermarks(&cf);
        assert_eq!(w.fields_removed.len(), 1);
    }

    #[test]
    fn empty_class_peels_detect_only_without_fabricating() {
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![ConstantPoolEntry::Placeholder],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let report: ProtectorPeelReport = peel(&cf, "", "");
        assert_eq!(report.family, ProtectorFamily::Allatori);
        assert_eq!(report.status, PeelStatus::DetectOnly);
        assert!(report.strings_recovered.is_empty());
    }
}
