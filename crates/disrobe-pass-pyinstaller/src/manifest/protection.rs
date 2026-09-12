use serde::{Deserialize, Serialize};

use crate::extract::ExtractOutput;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProtectionSignal {
    UnencryptedDefault,
    LegacyAesCtrKeyed,
    LegacyAesCtrKeyMissing,
    Pyiboot01BootstrapAes,
    UpxCompressedWrapper,
    PossiblyNestedWrapper,
    PycZipperRecompressed,
}

impl ProtectionSignal {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::UnencryptedDefault => "unencrypted-default",
            Self::LegacyAesCtrKeyed => "legacy-aes-ctr-keyed",
            Self::LegacyAesCtrKeyMissing => "legacy-aes-ctr-key-missing",
            Self::Pyiboot01BootstrapAes => "pyiboot01-bootstrap-aes",
            Self::UpxCompressedWrapper => "upx-compressed-wrapper",
            Self::PossiblyNestedWrapper => "possibly-nested-wrapper",
            Self::PycZipperRecompressed => "pyc-zipper-recompressed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtectionReport {
    pub signals: Vec<ProtectionSignal>,
    pub key_recovered: bool,
    pub key_hex: Option<String>,
    pub decrypted_entry_count: usize,
    pub encrypted_entry_count: usize,
    pub notes: Vec<String>,
}

pub(super) fn build_protection(image: &[u8], output: &ExtractOutput) -> ProtectionReport {
    let mut signals: Vec<ProtectionSignal> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut decrypted: usize = 0usize;
    let mut encrypted: usize = 0usize;

    let has_crypto_key: bool = output
        .entries
        .iter()
        .any(|e| e.toc.name == "pyimod00_crypto_key");

    if has_crypto_key {
        if output.encryption_key.is_some() {
            signals.push(ProtectionSignal::LegacyAesCtrKeyed);
        } else {
            signals.push(ProtectionSignal::LegacyAesCtrKeyMissing);
            notes.push(
                "pyimod00_crypto_key module present but 16-byte literal not extractable".to_owned(),
            );
        }
    } else {
        signals.push(ProtectionSignal::UnencryptedDefault);
    }

    let has_bootstrap: bool = output
        .entries
        .iter()
        .any(|e| e.toc.name.starts_with("pyiboot01_bootstrap"));
    if has_bootstrap && contains_aes_bootstrap_marker(output) {
        signals.push(ProtectionSignal::Pyiboot01BootstrapAes);
        notes.push(
            "pyiboot01_bootstrap references AES routines (PyInstaller 6+ key embedding pattern)"
                .to_owned(),
        );
    }

    for entry in &output.entries {
        if entry.decrypted {
            decrypted += 1;
        }
        let raw_starts_with_zlib_zeros: bool = entry.data.len() >= 2
            && entry.data[0] != 0x78
            && output.encryption_key.is_some()
            && entry.toc.compressed_flag == 1;
        if raw_starts_with_zlib_zeros && !entry.decrypted {
            encrypted += 1;
        }
    }

    if looks_upx(image) {
        signals.push(ProtectionSignal::UpxCompressedWrapper);
        notes.push("UPX section names detected in image header".to_owned());
    }

    if has_nested_wrapper_marker(output) {
        signals.push(ProtectionSignal::PossiblyNestedWrapper);
        notes.push(
            "PyInstaller archive nested inside another freezer wrapper (cx_Freeze / Briefcase / py2app suspected)"
                .to_owned(),
        );
    }

    if output.pyc_unzipped_count > 0 {
        signals.push(ProtectionSignal::PycZipperRecompressed);
        notes.push(format!(
            "pyc-zipper recompression layer peeled off {} module(s); recovered the original .pyc bytes",
            output.pyc_unzipped_count
        ));
    }

    let key_hex: Option<String> = output.encryption_key.map(|k| hex_lowercase(&k));

    ProtectionReport {
        signals,
        key_recovered: output.encryption_key.is_some(),
        key_hex,
        decrypted_entry_count: decrypted,
        encrypted_entry_count: encrypted,
        notes,
    }
}

fn contains_aes_bootstrap_marker(output: &ExtractOutput) -> bool {
    output
        .entries
        .iter()
        .filter(|e| e.toc.name.starts_with("pyiboot01_bootstrap"))
        .any(|e| {
            let needle: &[u8; 3] = b"AES";
            e.data.windows(needle.len()).any(|w| w == needle)
        })
}

fn looks_upx(image: &[u8]) -> bool {
    let head: &[u8] = &image[..image.len().min(8192)];
    head.windows(4).any(|w| w == b"UPX!")
        || head.windows(4).any(|w| w == b"UPX0")
        || head.windows(4).any(|w| w == b"UPX1")
}

fn has_nested_wrapper_marker(output: &ExtractOutput) -> bool {
    output.entries.iter().any(|e| {
        let n: &String = &e.toc.name;
        n.contains("py2app") || n.contains("Briefcase") || n.contains("cx_Freeze")
    })
}

fn hex_lowercase(bytes: &[u8]) -> String {
    let mut s: String = String::with_capacity(hex_capacity(bytes.len()));
    for b in bytes {
        let hi: u8 = (b >> 4) & 0x0f;
        let lo: u8 = b & 0x0f;
        s.push(hex_nibble(hi));
        s.push(hex_nibble(lo));
    }
    s
}

const fn hex_capacity(len: usize) -> usize {
    len.saturating_mul(2usize)
}

const fn hex_nibble(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'a' + n - 10) as char,
        _ => '?',
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn hex_capacity_saturates() {
        assert_eq!(hex_capacity(16usize), 32usize);
        assert_eq!(hex_capacity(usize::MAX), usize::MAX);
    }
}
