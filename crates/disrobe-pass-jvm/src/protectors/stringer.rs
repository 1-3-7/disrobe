use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[must_use]
pub fn looks_like_encrypted(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let len: usize = s.chars().count();
    if len < 4 {
        return false;
    }
    let weird: usize = s
        .chars()
        .filter(|c: &char| {
            let v: u32 = *c as u32;
            v == 0 || (v < 0x20 && v != u32::from(b'\n') && v != u32::from(b'\t')) || v > 0x7E
        })
        .count();
    (weird as f64 / len as f64) > 0.40
}

#[must_use]
pub fn has_runtime_key_signature(cf: &ClassFile) -> bool {
    const STRINGER_DECRYPT_DESC: &str = "(Ljava/lang/Object;I)Ljava/lang/String;";
    let has_decrypt_stub_descriptor: bool = cf
        .constant_pool
        .iter()
        .any(|entry| matches!(entry, ConstantPoolEntry::Utf8(s) if s == STRINGER_DECRYPT_DESC));
    if !has_decrypt_stub_descriptor {
        return false;
    }
    cf.collect_strings()
        .values()
        .any(|s: &String| looks_like_encrypted(s))
}

pub fn peel(cf: &ClassFile, _class_name: &str, _method_name: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::Stringer);
    let recovered: usize = crate::protectors::recover_via_embedded_stub(cf, &mut report);
    report.strings_residual = count_residual_encrypted_strings(cf);
    if recovered == 0 {
        report.status = PeelStatus::DetectOnly;
        if has_runtime_key_signature(cf) {
            report.notes.push(
                "Stringer flow mode keys its AES-128 stream decrypt on a per-call-site int, the \
                 calling class+method hashCode (caller identity is fixed at each call site and \
                 statically known), a threaded BigInteger-built key/T-table/S-box table, and a \
                 self-tamper checksum XORed into AES key word 2. The checksum is the SipHash-2-4 \
                 fold the decryptor computes at runtime by reflectively locating a \
                 getResourceAsStream method, invoking it, and walking the resulting \
                 ZipInputStream: it consumes the enclosing jar's ZIP directory (every sibling \
                 entry's name and size in central-directory order), not an empty stream. On the \
                 real bundled sample the genuine fold is 1738644257434835613 (verified against \
                 ube.tms.uh.B() run from the full 305 KB jar under a JVM); the empty-input fold \
                 disrobe can evaluate is a different value (2202906307356721367) that does not \
                 decrypt the constants. That jar directory is absent from the committed \
                 few-class static artifact, so word 2 of the AES key, and therefore the \
                 cleartext, is an information-theoretic wall for this sample: recovery would need \
                 the full original jar's entry table. Given the whole jar it becomes static \
                 again (fold the jar directory directly)"
                    .to_owned(),
            );
        }
    }
    finish_stringer(cf, report)
}

#[must_use]
pub fn count_residual_encrypted_strings(cf: &ClassFile) -> usize {
    cf.collect_strings()
        .values()
        .filter(|s: &&String| !is_plausibly_readable(s))
        .count()
}

fn finish_stringer(cf: &ClassFile, mut report: ProtectorPeelReport) -> ProtectorPeelReport {
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::Utf8(s) = entry
            && (s.contains("Stringer") || s.contains("Licel"))
        {
            report.notes.push(format!("stringer-marker: {s}"));
        }
    }
    for m in &cf.methods {
        if let Ok(name) = cf.utf8_at(m.name_index)
            && (name.starts_with("\u{0}") || name.starts_with("ↁ") || name == "ⁱ")
        {
            report
                .notes
                .push(format!("stringer-unicode-method: {name:?}"));
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

    #[test]
    fn encrypted_string_detected_as_encrypted() {
        let high_entropy: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}\u{0011}";
        assert!(looks_like_encrypted(high_entropy));
        assert!(!looks_like_encrypted("this is plaintext data"));
    }

    fn classfile_with(cp: Vec<ConstantPoolEntry>) -> ClassFile {
        ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: cp,
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        }
    }

    #[test]
    fn decrypt_descriptor_with_encrypted_constant_trips_runtime_key_guard() {
        let cf: ClassFile = classfile_with(vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("(Ljava/lang/Object;I)Ljava/lang/String;".into()),
            ConstantPoolEntry::Utf8(
                "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}\u{0011}".into(),
            ),
        ]);
        assert!(has_runtime_key_signature(&cf));
    }

    #[test]
    fn decrypt_descriptor_without_encrypted_constant_does_not_trip() {
        let cf: ClassFile = classfile_with(vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("(Ljava/lang/Object;I)Ljava/lang/String;".into()),
            ConstantPoolEntry::Utf8("this is a plain readable constant".into()),
        ]);
        assert!(!has_runtime_key_signature(&cf));
    }

    #[test]
    fn stock_reflection_strings_do_not_trip_runtime_key_guard() {
        let cf: ClassFile = classfile_with(vec![
            ConstantPoolEntry::Placeholder,
            ConstantPoolEntry::Utf8("getStackTrace".into()),
            ConstantPoolEntry::Utf8("currentThread".into()),
            ConstantPoolEntry::Utf8("java/lang/StackTraceElement".into()),
            ConstantPoolEntry::Utf8("getDeclaredMethod".into()),
            ConstantPoolEntry::Utf8("forName".into()),
        ]);
        assert!(!has_runtime_key_signature(&cf));
    }
}
