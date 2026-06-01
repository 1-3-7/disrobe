use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringerKey {
    pub class_id: u64,
    pub method_id: u64,
}

impl StringerKey {
    #[inline]
    #[must_use]
    pub const fn new(class_id: u64, method_id: u64) -> Self {
        Self {
            class_id,
            method_id,
        }
    }
}

#[must_use]
pub fn class_key(name: &str) -> u64 {
    let mut h: u64 = 0xCBF2_9CE4_8422_2325;
    for b in name.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

/// Synthetic reference transform for tests only; not the proprietary Licel
/// Stringer algorithm. Real recovery emulates the embedded decrypt stub via
/// [`crate::protectors::recover_via_embedded_stub`].
pub fn stringer_xor_codeunits(units: &[u16], key: StringerKey) -> Vec<u16> {
    let mut keystream: u64 = key.class_id ^ key.method_id ^ 0xDEAD_BEEF_FEED_FACE;
    let mut out: Vec<u16> = Vec::with_capacity(units.len());
    for u in units {
        let mask: u16 = u16::try_from(keystream & 0x7F).unwrap_or(0);
        out.push(*u ^ mask);
        keystream = keystream
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
    }
    out
}

pub fn stringer_encrypt(plaintext: &str, key: StringerKey) -> Vec<u16> {
    let units: Vec<u16> = plaintext.encode_utf16().collect();
    stringer_xor_codeunits(&units, key)
}

pub fn stringer_decrypt(ciphertext: &str, key: StringerKey) -> String {
    let units: Vec<u16> = ciphertext.encode_utf16().collect();
    let out: Vec<u16> = stringer_xor_codeunits(&units, key);
    String::from_utf16_lossy(&out)
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
    let weird: usize = s
        .chars()
        .filter(|c: &char| {
            let v: u32 = *c as u32;
            v == 0 || (v < 0x20 && v != u32::from(b'\n') && v != u32::from(b'\t')) || v > 0x7E
        })
        .count();
    (weird as f64 / len as f64) > 0.40
}

/// Detect and structurally characterise a Licel Stringer-protected class.
///
/// String recovery is only attempted by emulating the class's own embedded
/// decrypt stub via [`crate::protectors::recover_via_embedded_stub`]. The Stringer
/// string algorithm is proprietary and opaque without that stub, so when no stub
/// is present this returns [`PeelStatus::DetectOnly`]: markers and Unicode-named
/// decrypt methods are logged and residual encrypted strings counted, but no
/// string plaintext is claimed. `class_name`/`method_name` are retained for the
/// synthetic self-consistency fixtures only.
pub fn peel(cf: &ClassFile, _class_name: &str, _method_name: &str) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport = ProtectorPeelReport::new(ProtectorFamily::Stringer);
    if crate::protectors::recover_via_embedded_stub(cf, &mut report) > 0 {
        return finish_stringer(cf, report);
    }
    report.status = PeelStatus::DetectOnly;
    report.strings_residual = count_residual_encrypted_strings(cf);
    finish_stringer(cf, report)
}

/// Count constant-pool strings that remain opaque (honest detect-only metric).
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

    /// Self-consistency (involution) of the synthetic reference transform only.
    /// NOT real Stringer-sample recovery.
    #[test]
    fn synthetic_transform_is_involution() {
        let key: StringerKey = StringerKey::new(class_key("com/Foo"), class_key("bar"));
        let plain: &str = "API_KEY=abcdef0123456789";
        let cipher_units: Vec<u16> = stringer_encrypt(plain, key);
        let back_units: Vec<u16> = stringer_xor_codeunits(&cipher_units, key);
        let back: String = String::from_utf16(&back_units).expect("roundtrip valid utf16");
        assert_eq!(back, plain);
    }

    #[test]
    fn encrypted_string_detected_as_encrypted() {
        let high_entropy: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}\u{0011}";
        assert!(looks_like_encrypted(high_entropy));
        assert!(!looks_like_encrypted("this is plaintext data"));
    }
}
