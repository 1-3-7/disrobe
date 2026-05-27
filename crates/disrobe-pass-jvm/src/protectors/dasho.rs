use std::collections::BTreeMap;

use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DashOKey {
    pub seed_a: u32,
    pub seed_b: u32,
}

impl DashOKey {
    #[inline]
    #[must_use]
    pub const fn new(seed_a: u32, seed_b: u32) -> Self {
        Self { seed_a, seed_b }
    }
}

#[must_use]
pub fn derive_key(class_name: &str) -> DashOKey {
    let mut a: u32 = 0xA5A5_A5A5;
    let mut b: u32 = 0x5A5A_5A5A;
    for (i, byte) in class_name.bytes().enumerate() {
        a ^= u32::from(byte).rotate_left((i & 31) as u32);
        b = b.wrapping_mul(2654435761).wrapping_add(u32::from(byte));
    }
    DashOKey {
        seed_a: a,
        seed_b: b,
    }
}

pub fn dasho_xor_codeunits(units: &[u16], key: DashOKey) -> Vec<u16> {
    let mut state: u32 = key.seed_a;
    let mut out: Vec<u16> = Vec::with_capacity(units.len());
    for u in units {
        let mask: u16 = u16::try_from((state ^ key.seed_b) & 0x7F).unwrap_or(0);
        out.push(*u ^ mask);
        state = state.wrapping_add(key.seed_b).rotate_left(7);
    }
    out
}

pub fn dasho_decrypt(ciphertext: &str, key: DashOKey) -> String {
    let units: Vec<u16> = ciphertext.encode_utf16().collect();
    let out: Vec<u16> = dasho_xor_codeunits(&units, key);
    String::from_utf16_lossy(&out)
}

pub fn dasho_encrypt(plaintext: &str, key: DashOKey) -> Vec<u16> {
    let units: Vec<u16> = plaintext.encode_utf16().collect();
    dasho_xor_codeunits(&units, key)
}

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

pub fn peel(cf: &ClassFile, class_name: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::DashO);
    let key: DashOKey = derive_key(class_name);
    let strings: BTreeMap<u16, String> = cf.collect_strings();
    let mut residual: usize = 0;
    for (idx, s) in &strings {
        let candidate: String = dasho_decrypt(s, key);
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
    fn encrypt_decrypt_is_involution() {
        let key: DashOKey = derive_key("com/example/Service");
        let plain: &str = "https://api.example.com/v1/token";
        let cipher_units: Vec<u16> = dasho_encrypt(plain, key);
        let back_units: Vec<u16> = dasho_xor_codeunits(&cipher_units, key);
        let back: String = String::from_utf16(&back_units).expect("roundtrip valid utf16");
        assert_eq!(back, plain);
    }

    #[test]
    fn encrypted_detection_flags_obfuscated_text() {
        let mixed_control: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}";
        assert!(looks_like_encrypted(mixed_control));
        assert!(!looks_like_encrypted("regular ascii"));
    }
}
