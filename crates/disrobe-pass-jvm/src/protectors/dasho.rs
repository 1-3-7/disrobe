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
    let non_ascii_print: usize = s
        .chars()
        .filter(|c: &char| {
            let v: u32 = *c as u32;
            v < 0x20 || v > 0x7E
        })
        .count();
    (non_ascii_print as f64 / len as f64) > 0.40
}

pub fn peel(cf: &ClassFile, _class_name: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::DashO);
    if crate::protectors::recover_via_embedded_stub(cf, &mut report) > 0 {
        report.strings_residual = count_residual_encrypted_strings(cf);
        annotate_reflection_targets(cf, &mut report);
        return finish_dasho(cf, report);
    }
    if crate::protectors::recover_via_name_keyed_fallback(
        cf,
        &mut report,
        crate::protectors::name_keyed::NameKeyedCipher::DashO,
    ) > 0
    {
        report.strings_residual = count_residual_encrypted_strings(cf);
        annotate_reflection_targets(cf, &mut report);
        return finish_dasho(cf, report);
    }
    report.status = PeelStatus::DetectOnly;
    report.strings_residual = count_residual_encrypted_strings(cf);
    if cf.this_class_name().map(str::is_empty).unwrap_or(true) {
        report.notes.push(
            "no embedded decrypt method reachable from a static call site and the class carries no \
             retained this_class name to seed the per-class key; the DashO string cipher cannot be \
             exercised statically"
                .to_owned(),
        );
    }
    finish_dasho(cf, report)
}

fn annotate_reflection_targets(cf: &ClassFile, report: &mut ProtectorPeelReport) {
    if !uses_reflection(cf) {
        return;
    }
    let mut resolved: Vec<String> = report
        .strings_recovered
        .values()
        .filter(|s: &&String| is_reflection_member_name(s))
        .cloned()
        .collect();
    resolved.sort();
    resolved.dedup();
    if resolved.is_empty() {
        return;
    }
    report.notes.push(format!(
        "DashO reflection hiding: {} decrypted constant(s) name reflective members \
         (Class.forName / getMethod / getDeclaredField targets resolved through the constant \
         pool): {}",
        resolved.len(),
        resolved.join(", ")
    ));
}

fn uses_reflection(cf: &ClassFile) -> bool {
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::Utf8(s) = entry
            && (s == "java/lang/Class"
                || s == "java/lang/reflect/Method"
                || s == "java/lang/reflect/Field"
                || s == "forName"
                || s == "getMethod"
                || s == "getDeclaredMethod"
                || s == "getDeclaredField"
                || s == "getField")
        {
            return true;
        }
    }
    false
}

fn is_reflection_member_name(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    let dotted_type: bool = s.contains('.')
        && s.split('.').all(|seg: &str| {
            !seg.is_empty()
                && seg
                    .chars()
                    .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        });
    let bare_member: bool = !s.contains('.')
        && s.chars()
            .all(|c: char| c.is_ascii_alphanumeric() || c == '_' || c == '$')
        && s.chars().next().is_some_and(|c: char| !c.is_ascii_digit());
    dotted_type || bare_member
}

#[must_use]
pub fn count_residual_encrypted_strings(cf: &ClassFile) -> usize {
    cf.collect_strings()
        .values()
        .filter(|s: &&String| !is_plausibly_readable(s))
        .count()
}

fn finish_dasho(cf: &ClassFile, mut report: ProtectorPeelReport) -> ProtectorPeelReport {
    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::Utf8(s) = entry {
            let l: String = s.to_lowercase();
            if l.contains("dasho") || l.contains("preemptive") {
                report.notes.push(format!("dasho-marker: {s}"));
            }
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
    fn encrypted_detection_flags_obfuscated_text() {
        let mixed_control: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}";
        assert!(looks_like_encrypted(mixed_control));
        assert!(!looks_like_encrypted("regular ascii"));
    }

    #[test]
    fn reflection_member_name_recognizes_dotted_type_and_bare_member() {
        assert!(is_reflection_member_name("java.lang.System"));
        assert!(is_reflection_member_name("getProperty"));
        assert!(is_reflection_member_name("com.example.Foo$Bar"));
        assert!(!is_reflection_member_name("hello world"));
        assert!(!is_reflection_member_name("/etc/passwd"));
        assert!(!is_reflection_member_name("9notIdent"));
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
        let report: ProtectorPeelReport = peel(&cf, "");
        assert_eq!(report.family, ProtectorFamily::DashO);
        assert_eq!(report.status, PeelStatus::DetectOnly);
        assert!(report.strings_recovered.is_empty());
    }
}
