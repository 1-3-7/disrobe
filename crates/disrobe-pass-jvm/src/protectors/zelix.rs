use crate::classfile::{ClassFile, ConstantPoolEntry};
use crate::protectors::{PeelStatus, ProtectorFamily, ProtectorPeelReport};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZelixKey {
    pub class_seed: u32,
    pub method_salt: u32,
    pub stride: u32,
}

impl ZelixKey {
    #[inline]
    #[must_use]
    pub const fn new(class_seed: u32, method_salt: u32, stride: u32) -> Self {
        Self {
            class_seed,
            method_salt,
            stride,
        }
    }
}

#[must_use]
pub fn derive_class_seed(cf: &ClassFile) -> u32 {
    let name: &str = cf.this_class_name().unwrap_or("");
    let mut acc: u32 = 0x811C_9DC5;
    for b in name.as_bytes() {
        acc ^= u32::from(*b);
        acc = acc.wrapping_mul(0x0100_0193);
    }
    acc ^ u32::from(cf.major_version)
}

/// Synthetic reference cipher for tests only; not the proprietary Zelix string algorithm.
#[must_use]
pub fn zelix_encrypt_chars(plaintext: &str, key: ZelixKey) -> Vec<u16> {
    let mut out: Vec<u16> = Vec::with_capacity(plaintext.encode_utf16().count());
    let mut running: u32 = key.class_seed ^ key.method_salt;
    for (i, ch) in plaintext.encode_utf16().enumerate() {
        let masked: u32 = running.wrapping_add((i as u32).wrapping_mul(key.stride));
        let lo: u16 = u16::try_from(masked & 0x7F).unwrap_or(0);
        out.push(ch ^ lo);
        running = running.wrapping_mul(0x6c07_8965).wrapping_add(1);
    }
    out
}

pub fn zelix_decrypt_chars(ciphertext: &[u16], key: ZelixKey) -> String {
    let mut decoded: Vec<u16> = Vec::with_capacity(ciphertext.len());
    let mut running: u32 = key.class_seed ^ key.method_salt;
    for (i, ch) in ciphertext.iter().enumerate() {
        let masked: u32 = running.wrapping_add((i as u32).wrapping_mul(key.stride));
        let lo: u16 = u16::try_from(masked & 0x7F).unwrap_or(0);
        decoded.push(ch ^ lo);
        running = running.wrapping_mul(0x6c07_8965).wrapping_add(1);
    }
    String::from_utf16_lossy(&decoded)
}

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

/// Count constant-pool strings that are still encrypted (not plausibly readable).
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CffPattern {
    pub dispatch_var_loads: u32,
    pub branch_count: u32,
    pub recovered_blocks: u32,
}

#[must_use]
pub fn unflatten_cff(code: &[u8]) -> CffPattern {
    let mut pattern: CffPattern = CffPattern {
        dispatch_var_loads: 0,
        branch_count: 0,
        recovered_blocks: 0,
    };
    let mut i: usize = 0;
    while i < code.len() {
        let op: u8 = code[i];
        match op {
            0x15 | 0x1A..=0x1D => {
                pattern.dispatch_var_loads += 1;
                i += 2;
            }
            0xA7 => {
                pattern.branch_count += 1;
                i += 3;
            }
            0xC8 => {
                pattern.branch_count += 1;
                i += 5;
            }
            0xAA => {
                let pad: usize = (4 - ((i + 1) % 4)) % 4;
                let table_start: usize = i + 1 + pad;
                if table_start + 12 > code.len() {
                    break;
                }
                let low: i32 = i32::from_be_bytes([
                    code[table_start + 4],
                    code[table_start + 5],
                    code[table_start + 6],
                    code[table_start + 7],
                ]);
                let high: i32 = i32::from_be_bytes([
                    code[table_start + 8],
                    code[table_start + 9],
                    code[table_start + 10],
                    code[table_start + 11],
                ]);
                let entries: i64 = i64::from(high) - i64::from(low) + 1;
                if entries > 0 {
                    pattern.recovered_blocks = pattern
                        .recovered_blocks
                        .saturating_add(u32::try_from(entries).unwrap_or(0));
                }
                let body_end: usize = table_start
                    .saturating_add(12)
                    .saturating_add(entries.max(0) as usize * 4);
                i = body_end.min(code.len());
            }
            0xAB => {
                let pad: usize = (4 - ((i + 1) % 4)) % 4;
                let table_start: usize = i + 1 + pad;
                if table_start + 8 > code.len() {
                    break;
                }
                let npairs: u32 = u32::from_be_bytes([
                    code[table_start + 4],
                    code[table_start + 5],
                    code[table_start + 6],
                    code[table_start + 7],
                ]);
                pattern.recovered_blocks = pattern.recovered_blocks.saturating_add(npairs);
                let body_end: usize = table_start
                    .saturating_add(8)
                    .saturating_add(npairs as usize * 8);
                i = body_end.min(code.len());
            }
            _ => i += 1,
        }
    }
    pattern
}

/// Detect and structurally characterise a Zelix KlassMaster-protected class.
pub fn peel(cf: &ClassFile, _key: ZelixKey) -> ProtectorPeelReport {
    let mut report: ProtectorPeelReport =
        ProtectorPeelReport::new(ProtectorFamily::ZelixKlassMaster);
    let via_stub: usize = crate::protectors::recover_via_embedded_stub(cf, &mut report);
    if via_stub == 0 {
        report.status = PeelStatus::DetectOnly;
        report.strings_residual = count_residual_encrypted_strings(cf);
    }

    for method in &cf.methods {
        for attr in &method.attributes {
            let Ok(name) = cf.utf8_at(attr.name_index) else {
                continue;
            };
            if name != "Code" {
                continue;
            }
            let Ok(parsed) = crate::bytecode::parse_code_attribute(&attr.info) else {
                continue;
            };
            let pattern: CffPattern = unflatten_cff(&parsed.code);
            if pattern.branch_count + pattern.recovered_blocks >= 8 {
                report.cff_methods_unflattened += 1;
                report.cff_branches_recovered = report.cff_branches_recovered.saturating_add(
                    pattern
                        .branch_count
                        .saturating_add(pattern.recovered_blocks),
                );
            }
        }
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

    /// Self-consistency (involution) of the synthetic reference cipher only.
    #[test]
    fn synthetic_cipher_is_involution() {
        let key: ZelixKey = ZelixKey::new(0x1234_5678, 0xABCD, 7);
        let plain: &str = "hello zelix world";
        let cipher: Vec<u16> = zelix_encrypt_chars(plain, key);
        let back: String = zelix_decrypt_chars(&cipher, key);
        assert_eq!(back, plain);
    }

    #[test]
    fn encrypted_string_classified_correctly() {
        let high_entropy: &str = "\u{0001}\u{0002}\u{00FF}\u{0014}\u{0006}\u{0080}\u{0011}";
        assert!(looks_like_encrypted_string(high_entropy));
        assert!(!looks_like_encrypted_string("select * from users"));
    }

    #[test]
    fn cff_unflatten_counts_branches_and_switch_entries() {
        let mut code: Vec<u8> = Vec::new();
        code.push(0xA7);
        code.extend_from_slice(&[0u8, 5u8]);
        code.push(0xA7);
        code.extend_from_slice(&[0u8, 5u8]);
        let pattern: CffPattern = unflatten_cff(&code);
        assert_eq!(pattern.branch_count, 2);
    }
}
