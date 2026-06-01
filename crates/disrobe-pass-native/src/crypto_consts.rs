use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoPrimitive {
    AesTtableEnc,
    AesTtableDec,
    AesSbox,
    Sha256Iv,
    Sha256K,
    Sha1Iv,
    Md5K,
    Chacha20Sigma,
}

impl CryptoPrimitive {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::AesTtableEnc => "aes-ttable-enc",
            Self::AesTtableDec => "aes-ttable-dec",
            Self::AesSbox => "aes-sbox",
            Self::Sha256Iv => "sha256-iv",
            Self::Sha256K => "sha256-k",
            Self::Sha1Iv => "sha1-iv",
            Self::Md5K => "md5-k",
            Self::Chacha20Sigma => "chacha20-sigma",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CryptoConstConfidence {
    Low,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CryptoConstHit {
    pub primitive: CryptoPrimitive,
    pub offset: u64,
    pub matched_len: usize,
    pub confidence: CryptoConstConfidence,
}

const AES_TE0: [u32; 8] = [
    0xc663_63a5,
    0xf87c_7c84,
    0xee77_7799,
    0xf67b_7b8d,
    0xfff2_f20d,
    0xd66b_6bbd,
    0xde6f_6fb1,
    0x91c5_c554,
];

const AES_TD0: [u32; 8] = [
    0x51f4_a750,
    0x7e41_6553,
    0x1a17_a4c3,
    0x3a27_5e96,
    0x3bab_6bcb,
    0x1f9d_45f1,
    0xacfa_58ab,
    0x4be3_0393,
];

const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

const SHA256_H: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

const SHA1_H: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

const MD5_K: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

const CHACHA20_SIGMA: &[u8; 16] = b"expand 32-byte k";

const MD5_K_ANCHOR_WORDS: usize = 4;
const SHA256_K_ANCHOR_WORDS: usize = 8;

fn words_le(table: &[u32]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(table.len() * 4);
    for word in table {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn memmem(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|w: &[u8]| w == needle)
}

fn detect_full_table(
    bytes: &[u8],
    primitive: CryptoPrimitive,
    table: &[u32],
    out: &mut Vec<CryptoConstHit>,
) {
    let needle: Vec<u8> = words_le(table);
    if let Some(pos) = memmem(bytes, &needle) {
        out.push(CryptoConstHit {
            primitive,
            offset: pos as u64,
            matched_len: needle.len(),
            confidence: CryptoConstConfidence::High,
        });
    }
}

fn detect_anchored_table(
    bytes: &[u8],
    primitive: CryptoPrimitive,
    table: &[u32],
    anchor_words: usize,
    out: &mut Vec<CryptoConstHit>,
) {
    let anchor: Vec<u8> = words_le(&table[..anchor_words]);
    let full: Vec<u8> = words_le(table);
    let Some(pos): Option<usize> = memmem(bytes, &anchor) else {
        return;
    };
    let extends_full: bool =
        bytes.len() >= pos + full.len() && bytes[pos..pos + full.len()] == full[..];
    let (matched_len, confidence): (usize, CryptoConstConfidence) = if extends_full {
        (full.len(), CryptoConstConfidence::High)
    } else {
        (anchor.len(), CryptoConstConfidence::Low)
    };
    out.push(CryptoConstHit {
        primitive,
        offset: pos as u64,
        matched_len,
        confidence,
    });
}

fn detect_literal(
    bytes: &[u8],
    primitive: CryptoPrimitive,
    needle: &[u8],
    out: &mut Vec<CryptoConstHit>,
) {
    if let Some(pos) = memmem(bytes, needle) {
        out.push(CryptoConstHit {
            primitive,
            offset: pos as u64,
            matched_len: needle.len(),
            confidence: CryptoConstConfidence::High,
        });
    }
}

#[must_use]
pub fn detect_crypto_constants(bytes: &[u8]) -> Vec<CryptoConstHit> {
    let mut out: Vec<CryptoConstHit> = Vec::new();
    detect_full_table(bytes, CryptoPrimitive::AesTtableEnc, &AES_TE0, &mut out);
    detect_full_table(bytes, CryptoPrimitive::AesTtableDec, &AES_TD0, &mut out);
    detect_literal(bytes, CryptoPrimitive::AesSbox, &AES_SBOX, &mut out);
    detect_full_table(bytes, CryptoPrimitive::Sha256Iv, &SHA256_H, &mut out);
    detect_anchored_table(
        bytes,
        CryptoPrimitive::Sha256K,
        &SHA256_K,
        SHA256_K_ANCHOR_WORDS,
        &mut out,
    );
    detect_full_table(bytes, CryptoPrimitive::Sha1Iv, &SHA1_H, &mut out);
    detect_anchored_table(
        bytes,
        CryptoPrimitive::Md5K,
        &MD5_K,
        MD5_K_ANCHOR_WORDS,
        &mut out,
    );
    detect_literal(
        bytes,
        CryptoPrimitive::Chacha20Sigma,
        CHACHA20_SIGMA,
        &mut out,
    );
    out
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn aes_sbox_constants_match_fips197() {
        assert_eq!(AES_SBOX[0], 0x63);
        assert_eq!(AES_SBOX[1], 0x7c);
        assert_eq!(AES_SBOX[255], 0x16);
    }

    #[test]
    fn aes_te0_anchor_matches_fips197() {
        assert_eq!(AES_TE0[0], 0xc663_63a5);
        assert_eq!(AES_TE0[1], 0xf87c_7c84);
    }

    #[test]
    fn aes_td0_anchor_matches_fips197() {
        assert_eq!(AES_TD0[0], 0x51f4_a750);
    }

    #[test]
    fn sha256_h0_matches_fips180_4() {
        assert_eq!(SHA256_H[0], 0x6a09_e667);
        assert_eq!(SHA256_H[7], 0x5be0_cd19);
    }

    #[test]
    fn sha256_k0_matches_fips180_4() {
        assert_eq!(SHA256_K[0], 0x428a_2f98);
        assert_eq!(SHA256_K[63], 0xc671_78f2);
    }

    #[test]
    fn sha1_iv_matches_spec() {
        assert_eq!(
            SHA1_H,
            [
                0x6745_2301,
                0xefcd_ab89,
                0x98ba_dcfe,
                0x1032_5476,
                0xc3d2_e1f0
            ]
        );
    }

    #[test]
    fn md5_k0_matches_rfc1321() {
        let derived: u32 = (2f64.powi(32) * (1.0_f64).sin().abs()).floor() as u32;
        assert_eq!(MD5_K[0], 0xd76a_a478);
        assert_eq!(MD5_K[0], derived);
    }

    #[test]
    fn chacha20_sigma_matches_rfc8439() {
        assert_eq!(CHACHA20_SIGMA, b"expand 32-byte k");
    }

    #[test]
    fn zero_buffer_yields_no_hits() {
        let buf: Vec<u8> = vec![0u8; 65536];
        assert!(detect_crypto_constants(&buf).is_empty());
    }

    #[test]
    fn lone_md5_k0_word_is_not_emitted() {
        let mut buf: Vec<u8> = vec![0u8; 4096];
        buf[512..516].copy_from_slice(&MD5_K[0].to_le_bytes());
        let hits: Vec<CryptoConstHit> = detect_crypto_constants(&buf);
        assert!(
            hits.iter()
                .all(|h: &CryptoConstHit| h.primitive != CryptoPrimitive::Md5K)
        );
    }

    #[test]
    fn embedded_te0_table_detected_high() {
        let mut buf: Vec<u8> = vec![0u8; 4096];
        let needle: Vec<u8> = words_le(&AES_TE0);
        buf[1024..1024 + needle.len()].copy_from_slice(&needle);
        let hits: Vec<CryptoConstHit> = detect_crypto_constants(&buf);
        let hit: &CryptoConstHit = hits
            .iter()
            .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::AesTtableEnc)
            .expect("te0 detected");
        assert_eq!(hit.offset, 1024);
        assert_eq!(hit.confidence, CryptoConstConfidence::High);
        assert_eq!(hit.matched_len, AES_TE0.len() * 4);
    }

    #[test]
    fn md5_four_contiguous_words_emitted() {
        let mut buf: Vec<u8> = vec![0u8; 4096];
        let needle: Vec<u8> = words_le(&MD5_K[..MD5_K_ANCHOR_WORDS]);
        buf[256..256 + needle.len()].copy_from_slice(&needle);
        let hits: Vec<CryptoConstHit> = detect_crypto_constants(&buf);
        let hit: &CryptoConstHit = hits
            .iter()
            .find(|h: &&CryptoConstHit| h.primitive == CryptoPrimitive::Md5K)
            .expect("md5 anchor detected");
        assert_eq!(hit.offset, 256);
        assert_eq!(hit.confidence, CryptoConstConfidence::Low);
    }
}
