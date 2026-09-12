use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[must_use]
pub fn looks_like_encrypted_string(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let len: usize = s.chars().count();
    let non_print: usize = s
        .chars()
        .filter(|c: &char| !c.is_ascii_graphic() && !c.is_whitespace())
        .count();
    let high_bmp: usize = s.chars().filter(|c: &char| (*c as u32) > 0x7F).count();
    let ratio_non_print: f64 = non_print as f64 / len as f64;
    let ratio_high: f64 = high_bmp as f64 / len as f64;
    (ratio_non_print > 0.4 || ratio_high > 0.7) && len >= 4
}

#[must_use]
pub fn count_residual_encrypted_strings(cf: &ClassFile) -> usize {
    cf.collect_strings()
        .values()
        .filter(|s: &&String| !is_plausibly_readable(s))
        .count()
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

pub fn peel(cf: &ClassFile) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport =
        ProtectorPeelReport::new(ProtectorFamily::ZelixKlassMaster);
    let recovered: usize = crate::protectors::recover_via_embedded_stub(cf, &mut report);
    report.strings_residual = count_residual_encrypted_strings(cf);
    if recovered == 0 {
        report.status = PeelStatus::DetectOnly;
    }

    let cff: crate::protectors::unflatten::CffReport =
        crate::protectors::unflatten::unflatten_class(cf);
    report.cff_methods_unflattened = cff.methods_fully_structured;
    report.cff_branches_recovered = cff.edges_redirected;
    if cff.flattened_methods > 0 {
        report.notes.push(format!(
            "control-flow-flattening: {} of {} state-dispatcher method(s) un-flattened and \
             re-structured to fully reducible straight-line control flow ({} dispatcher edge(s) \
             rewired to their resolved successors)",
            cff.methods_fully_structured, cff.flattened_methods, cff.edges_redirected
        ));
    }

    for entry in &cf.constant_pool {
        if let ConstantPoolEntry::Utf8(s) = entry
            && (s.contains("ZKM") || s.contains("KlassMaster") || s.contains("Zelix"))
        {
            report.notes.push(format!("zelix-marker: {s}"));
        }
    }
    report
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_string_classified_correctly() {
        let high_entropy: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}\u{0011}";
        assert!(looks_like_encrypted_string(high_entropy));
        assert!(!looks_like_encrypted_string("select * from users"));
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
        let report: ProtectorPeelReport = peel(&cf);
        assert_eq!(report.family, ProtectorFamily::ZelixKlassMaster);
        assert_eq!(report.status, PeelStatus::DetectOnly);
        assert!(report.strings_recovered.is_empty());
        assert_eq!(report.cff_methods_unflattened, 0);
    }
}
