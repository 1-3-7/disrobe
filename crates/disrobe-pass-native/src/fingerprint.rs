use serde::{Deserialize, Serialize};

use crate::crypto_consts::{CryptoConstHit, detect_crypto_constants};
use crate::flirt::{FlirtMatch, FlirtSig, match_flirt};

pub const ASCII_XREF_MIN_LEN: usize = 4;
pub const ASCII_XREF_MAX_VALUE_LEN: usize = 256;
pub const ASCII_XREF_MAX_COUNT: usize = 4096;

pub const FINGERPRINT_SCHEMA: &str = "disrobe.native.fingerprints/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringXref {
    pub offset: u64,
    pub value: String,
    pub len: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FingerprintSidecar {
    pub schema: &'static str,
    pub input: String,
    pub byte_count: u64,
    pub crypto: Vec<CryptoConstHit>,
    pub flirt: Vec<FlirtMatch>,
    pub strings: Vec<StringXref>,
}

impl FingerprintSidecar {
    #[must_use]
    pub fn build(input_label: &str, bytes: &[u8], flirt: Option<&FlirtSig>) -> Self {
        let crypto: Vec<CryptoConstHit> = detect_crypto_constants(bytes);
        let flirt: Vec<FlirtMatch> =
            flirt.map_or_else(Vec::new, |sig: &FlirtSig| match_flirt(sig, bytes));
        let strings: Vec<StringXref> = extract_ascii_xrefs(bytes, ASCII_XREF_MIN_LEN);
        Self {
            schema: FINGERPRINT_SCHEMA,
            input: input_label.to_owned(),
            byte_count: bytes.len() as u64,
            crypto,
            flirt,
            strings,
        }
    }
}

#[must_use]
pub fn extract_ascii_xrefs(bytes: &[u8], min_len: usize) -> Vec<StringXref> {
    let mut out: Vec<StringXref> = Vec::new();
    let mut run_start: usize = 0;
    let mut in_run: bool = false;
    let total: usize = bytes.len();
    let mut idx: usize = 0;
    while idx < total {
        let b: u8 = bytes[idx];
        let printable: bool = (0x20..=0x7e).contains(&b);
        if printable {
            if !in_run {
                run_start = idx;
                in_run = true;
            }
        } else if in_run {
            if let Some(xref) = emit_run(bytes, run_start, idx, min_len) {
                out.push(xref);
                if out.len() == ASCII_XREF_MAX_COUNT {
                    return out;
                }
            }
            in_run = false;
        }
        idx += 1;
    }
    if in_run && let Some(xref) = emit_run(bytes, run_start, total, min_len) {
        out.push(xref);
    }
    out
}

#[must_use]
fn emit_run(bytes: &[u8], start: usize, end: usize, min_len: usize) -> Option<StringXref> {
    let run_len: usize = end - start;
    if run_len < min_len {
        return None;
    }
    let value_end: usize = start + run_len.min(ASCII_XREF_MAX_VALUE_LEN);
    let value: String = bytes[start..value_end]
        .iter()
        .map(|&b: &u8| b as char)
        .collect();
    Some(StringXref {
        offset: start as u64,
        value,
        len: run_len,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::crypto_consts::{CryptoConstConfidence, CryptoPrimitive};
    use crate::flirt::{
        FlirtArch, FlirtHeader, FlirtModule, FlirtPattern, FlirtPublicName, crc16_flirt,
    };

    const AES_TE0_LE: [u8; 32] = [
        0xa5, 0x63, 0x63, 0xc6, 0x84, 0x7c, 0x7c, 0xf8, 0x99, 0x77, 0x77, 0xee, 0x8d, 0x7b, 0x7b,
        0xf6, 0x0d, 0xf2, 0xf2, 0xff, 0xbd, 0x6b, 0x6b, 0xd6, 0xb1, 0x6f, 0x6f, 0xde, 0x54, 0xc5,
        0xc5, 0x91,
    ];

    #[test]
    fn extract_ascii_xrefs_finds_planted_string_at_real_offset() {
        let mut buf: Vec<u8> = vec![0x00; 3];
        buf.extend_from_slice(b"DisrobeRocks");
        buf.extend_from_slice(&[0x00; 2]);
        buf.extend_from_slice(b"AB");
        let xrefs: Vec<StringXref> = extract_ascii_xrefs(&buf, ASCII_XREF_MIN_LEN);
        assert_eq!(xrefs.len(), 1);
        assert_eq!(xrefs[0].offset, 3);
        assert_eq!(xrefs[0].value, "DisrobeRocks");
        assert_eq!(xrefs[0].len, 12);
    }

    #[test]
    fn extract_ascii_xrefs_rejects_binary_noise() {
        let buf: [u8; 5] = [0xff, 0x01, 0x80, 0x7f, 0x00];
        assert!(extract_ascii_xrefs(&buf, ASCII_XREF_MIN_LEN).is_empty());
    }

    #[test]
    fn extract_ascii_xrefs_terminates_on_nonprint() {
        let buf: &[u8] = b"good\x00bad!";
        let xrefs: Vec<StringXref> = extract_ascii_xrefs(buf, ASCII_XREF_MIN_LEN);
        assert_eq!(xrefs.len(), 2);
        assert_eq!(xrefs[0].offset, 0);
        assert_eq!(xrefs[0].value, "good");
        assert_eq!(xrefs[1].offset, 5);
        assert_eq!(xrefs[1].value, "bad!");
    }

    #[test]
    fn build_fingerprints_real_chacha20_sigma() {
        let mut buf: Vec<u8> = vec![0u8; 8];
        buf.extend_from_slice(b"expand 32-byte k");
        let sidecar: FingerprintSidecar = FingerprintSidecar::build("t", &buf, None);
        let chacha: Vec<&CryptoConstHit> = sidecar
            .crypto
            .iter()
            .filter(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::Chacha20Sigma)
            .collect();
        assert_eq!(chacha.len(), 1);
        assert_eq!(chacha[0].offset, 8);
        assert_eq!(chacha[0].confidence, CryptoConstConfidence::High);
        assert_eq!(chacha[0].matched_len, 16);
    }

    #[test]
    fn build_fingerprints_real_aes_te0() {
        let mut buf: Vec<u8> = vec![0u8; 16];
        buf.extend_from_slice(&AES_TE0_LE);
        let sidecar: FingerprintSidecar = FingerprintSidecar::build("t", &buf, None);
        let aes: Vec<&CryptoConstHit> = sidecar
            .crypto
            .iter()
            .filter(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::AesTtableEnc)
            .collect();
        assert_eq!(aes.len(), 1);
        assert_eq!(aes[0].offset, 16);
        assert_eq!(aes[0].matched_len, 32);
        assert_eq!(aes[0].confidence, CryptoConstConfidence::High);
    }

    #[test]
    fn build_flirt_match_real_offset() {
        let crc16: u16 = crc16_flirt(&[]);
        let sig: FlirtSig = FlirtSig {
            header: FlirtHeader {
                version: 10,
                arch: FlirtArch::X86_64,
                file_types: 0,
                os_types: 0,
                app_types: 0,
                feature_flags: 0,
                old_n_functions: 0,
                crc16: 0,
                ctype: [0u8; 12],
                library_name: "t".to_owned(),
                n_functions: 1,
            },
            modules: vec![FlirtModule {
                pattern: FlirtPattern {
                    bytes: vec![0x55, 0x8B, 0xEC],
                    variant_mask: 0,
                    len: 3,
                },
                crc16_len: 0,
                crc16,
                total_length: 3,
                public_names: vec![FlirtPublicName {
                    offset: 0,
                    is_local: false,
                    is_collision: false,
                    name: "_start".to_owned(),
                }],
                tail_bytes: vec![],
                referenced: vec![],
            }],
        };
        let img: Vec<u8> = vec![0x90, 0x90, 0x55, 0x8B, 0xEC];
        let sidecar: FingerprintSidecar = FingerprintSidecar::build("t", &img, Some(&sig));
        assert_eq!(
            sidecar.flirt,
            vec![FlirtMatch {
                module_index: 0,
                image_offset: 2,
                name: "_start".to_owned(),
            }]
        );
    }

    #[test]
    fn sidecar_round_trips_serde() {
        let mut buf: Vec<u8> = vec![0u8; 8];
        buf.extend_from_slice(b"expand 32-byte k");
        buf.extend_from_slice(b"\x00PlantedXref\x00");
        let sidecar: FingerprintSidecar = FingerprintSidecar::build("rt", &buf, None);
        let json: &'static str = Box::leak(
            serde_json::to_string(&sidecar)
                .expect("serialize")
                .into_boxed_str(),
        );
        let back: FingerprintSidecar = serde_json::from_str(json).expect("deserialize");
        assert_eq!(sidecar, back);
    }
}
