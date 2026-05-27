use std::collections::BTreeMap;

use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllatoriKey {
    pub method_hash: i32,
    pub class_hash: i32,
}

impl AllatoriKey {
    #[inline]
    #[must_use]
    pub const fn new(method_hash: i32, class_hash: i32) -> Self {
        Self {
            method_hash,
            class_hash,
        }
    }
}

#[must_use]
pub fn allatori_string_hash(input: &str) -> i32 {
    let mut h: i32 = 0;
    for ch in input.chars() {
        h = h.wrapping_mul(31).wrapping_add(ch as i32);
    }
    h
}

#[must_use]
pub fn derive_key(class_name: &str, method_name: &str) -> AllatoriKey {
    AllatoriKey {
        method_hash: allatori_string_hash(method_name),
        class_hash: allatori_string_hash(class_name),
    }
}

pub fn allatori_xor_codeunits(units: &[u16], key: AllatoriKey) -> Vec<u16> {
    let mut state: i32 = key.method_hash ^ key.class_hash;
    let mut out: Vec<u16> = Vec::with_capacity(units.len());
    for u in units {
        let mixed: u16 = u16::try_from((state & 0x7F) as u32).unwrap_or(0);
        out.push(*u ^ mixed);
        state = state
            .wrapping_mul(0x10003)
            .wrapping_add(0x7F4A_7C15_u32 as i32);
    }
    out
}

pub fn allatori_decrypt(ciphertext: &str, key: AllatoriKey) -> String {
    let units: Vec<u16> = ciphertext.encode_utf16().collect();
    let out: Vec<u16> = allatori_xor_codeunits(&units, key);
    String::from_utf16_lossy(&out)
}

pub fn allatori_encrypt(plaintext: &str, key: AllatoriKey) -> Vec<u16> {
    let units: Vec<u16> = plaintext.encode_utf16().collect();
    allatori_xor_codeunits(&units, key)
}

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

pub fn peel(cf: &ClassFile, class_name: &str, default_method: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::Allatori);
    let key: AllatoriKey = derive_key(class_name, default_method);
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let mut residual: usize = 0;
    for (idx, s) in &strings {
        let candidate: String = allatori_decrypt(s, key);
        let candidate_readable: bool = is_plausibly_readable(&candidate);
        let original_readable: bool = is_plausibly_readable(s);
        if candidate_readable && !original_readable {
            report.strings_recovered.insert(*idx, candidate);
        } else if original_readable {
            report.strings_recovered.insert(*idx, s.clone());
        } else if candidate_readable {
            report.strings_recovered.insert(*idx, candidate);
        } else {
            residual += 1;
        }
    }
    report.strings_residual = residual;

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

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(allatori_string_hash("hello"), allatori_string_hash("hello"));
        assert_ne!(allatori_string_hash("a"), allatori_string_hash("b"));
    }

    #[test]
    fn decrypt_then_encrypt_roundtrips_for_simple_input() {
        let key: AllatoriKey = derive_key("com/example/Foo", "decrypt");
        let plain: &str = "sql connection string";
        let cipher_units: Vec<u16> = allatori_encrypt(plain, key);
        let back_units: Vec<u16> = allatori_xor_codeunits(&cipher_units, key);
        let back: String = String::from_utf16(&back_units).expect("roundtrip valid utf16");
        assert_eq!(back, plain);
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
}
