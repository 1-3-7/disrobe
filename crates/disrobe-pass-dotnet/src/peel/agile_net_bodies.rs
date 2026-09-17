use serde::{Deserialize, Serialize};

use crate::pe::{ClrHeader, PeImage, parse, parse_clr_header};

pub const SIGNATURE_LEN: usize = 16;
pub const KEY_LEN: usize = 16;
pub const CODE_HEADER_SIZE: usize = 0x30;

const SIG_OLD: [u8; SIGNATURE_LEN] = [
    0x1F, 0x68, 0x9D, 0x2B, 0x07, 0x4A, 0xA6, 0x4A, 0x92, 0xBB, 0x31, 0x7E, 0x60, 0x7F, 0xD7, 0xCD,
];
const SIG_NORMAL: [u8; SIGNATURE_LEN] = [
    0x08, 0x44, 0x65, 0xE1, 0x8C, 0x82, 0x13, 0x4C, 0x9C, 0x85, 0xB4, 0x17, 0xDA, 0x51, 0xAD, 0x25,
];
const SIG_PRO: [u8; SIGNATURE_LEN] = [
    0x68, 0xA0, 0xBB, 0x60, 0x13, 0x65, 0x5F, 0x41, 0xAE, 0x42, 0xAB, 0x42, 0x9B, 0x6B, 0x4E, 0xC1,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CliSecureVariant {
    Old,
    Normal,
    Pro,
}

impl CliSecureVariant {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Old => "CliSecure <=4.5 (single-XOR)",
            Self::Normal => "CliSecure 5.0 (dual-XOR)",
            Self::Pro => "CliSecure 5.4 Pro (XTEA)",
        }
    }

    fn from_signature(sig: &[u8]) -> Option<Self> {
        if sig == SIG_OLD {
            Some(Self::Old)
        } else if sig == SIG_NORMAL {
            Some(Self::Normal)
        } else if sig == SIG_PRO {
            Some(Self::Pro)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgileCodeHeader {
    pub variant: CliSecureVariant,
    pub file_offset: u32,
    pub key: [u8; KEY_LEN],
    pub total_code_size: u32,
    pub method_count: u32,
    pub method_table_offset: u32,
    pub method_element_size: u32,
}

fn read_u32_le(bytes: &[u8], at: usize) -> Option<u32> {
    let slice: &[u8] = bytes.get(at..at + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[must_use]
pub fn end_of_metadata(image: &[u8]) -> Option<u32> {
    let pe: PeImage = parse(image).ok()?;
    let clr: ClrHeader = parse_clr_header(image, &pe).ok()?;
    let end_rva: u32 = clr.metadata.rva.checked_add(clr.metadata.size)?;
    let off: usize = pe.rva_to_offset(end_rva)?;
    u32::try_from(off).ok()
}

#[must_use]
pub fn locate_agile_code_header(image: &[u8]) -> Option<AgileCodeHeader> {
    let eom: u32 = end_of_metadata(image)?;
    let start: usize = eom as usize;
    let header: &[u8] = image.get(start..start + CODE_HEADER_SIZE)?;
    let variant: CliSecureVariant = CliSecureVariant::from_signature(&header[..SIGNATURE_LEN])?;
    let mut key: [u8; KEY_LEN] = [0u8; KEY_LEN];
    key.copy_from_slice(&header[0x10..0x10 + KEY_LEN]);
    Some(AgileCodeHeader {
        variant,
        file_offset: eom,
        key,
        total_code_size: read_u32_le(header, 0x20)?,
        method_count: read_u32_le(header, 0x24)?,
        method_table_offset: read_u32_le(header, 0x28)?,
        method_element_size: read_u32_le(header, 0x2C)?,
    })
}

#[must_use]
pub fn decrypt_body_single_xor(key: &[u8; KEY_LEN], code_offs: u32, data: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, byte): (usize, &u8)| {
            let idx: usize = (code_offs as usize).wrapping_sub(0x28).wrapping_add(i) % KEY_LEN;
            *byte ^ key[idx]
        })
        .collect()
}

#[must_use]
pub fn decrypt_body_dual_xor(
    key: &[u8; KEY_LEN],
    code_offs: u32,
    code_header_size: u32,
    data: &[u8],
) -> Vec<u8> {
    let base: usize = (code_offs as usize).wrapping_sub(code_header_size as usize);
    data.iter()
        .enumerate()
        .map(|(i, byte): (usize, &u8)| {
            let a: usize = base.wrapping_add(i) % KEY_LEN;
            let b: usize = base.wrapping_add(i).wrapping_add(7) % KEY_LEN;
            *byte ^ key[a] ^ key[b]
        })
        .collect()
}

fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[must_use]
pub fn xtea_key_be(key16: &[u8; KEY_LEN]) -> [u32; 4] {
    [
        read_u32_be(key16, 0),
        read_u32_be(key16, 4),
        read_u32_be(key16, 8),
        read_u32_be(key16, 12),
    ]
}

#[must_use]
pub fn decrypt_body_pro_xtea(key16: &[u8; KEY_LEN], data: &[u8]) -> Vec<u8> {
    const MAGIC: u32 = 0x9E37_79B8;
    let key: [u32; 4] = xtea_key_be(key16);
    let mut out: Vec<u8> = data.to_vec();
    let qwords: usize = out.len() / 8;
    for i in 0..qwords {
        let offset: usize = i * 8;
        let mut q0: u32 = read_u32_be(&out, offset);
        let mut q1: u32 = read_u32_be(&out, offset + 4);
        let mut val: u32 = 0xC6EF_3700;
        for _ in 0..32 {
            q1 = q1.wrapping_sub(
                (q0.wrapping_shl(4).wrapping_add(key[2]))
                    ^ (val.wrapping_add(q0))
                    ^ (q0.wrapping_shr(5).wrapping_add(key[3])),
            );
            q0 = q0.wrapping_sub(
                (q1.wrapping_shl(4).wrapping_add(key[0]))
                    ^ (val.wrapping_add(q1))
                    ^ (q1.wrapping_shr(5).wrapping_add(key[1])),
            );
            val = val.wrapping_sub(MAGIC);
        }
        out[offset..offset + 4].copy_from_slice(&q0.to_be_bytes());
        out[offset + 4..offset + 8].copy_from_slice(&q1.to_be_bytes());
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn encrypt_pro_xtea(key16: &[u8; KEY_LEN], plain: &[u8]) -> Vec<u8> {
        const MAGIC: u32 = 0x9E37_79B8;
        let key: [u32; 4] = xtea_key_be(key16);
        let mut out: Vec<u8> = plain.to_vec();
        let qwords: usize = out.len() / 8;
        for i in 0..qwords {
            let offset: usize = i * 8;
            let mut q0: u32 = read_u32_be(&out, offset);
            let mut q1: u32 = read_u32_be(&out, offset + 4);
            let mut val: u32 = 0xC6EF_3700u32.wrapping_sub(MAGIC.wrapping_mul(32));
            for _ in 0..32 {
                val = val.wrapping_add(MAGIC);
                q0 = q0.wrapping_add(
                    (q1.wrapping_shl(4).wrapping_add(key[0]))
                        ^ (val.wrapping_add(q1))
                        ^ (q1.wrapping_shr(5).wrapping_add(key[1])),
                );
                q1 = q1.wrapping_add(
                    (q0.wrapping_shl(4).wrapping_add(key[2]))
                        ^ (val.wrapping_add(q0))
                        ^ (q0.wrapping_shr(5).wrapping_add(key[3])),
                );
            }
            out[offset..offset + 4].copy_from_slice(&q0.to_be_bytes());
            out[offset + 4..offset + 8].copy_from_slice(&q1.to_be_bytes());
        }
        out
    }

    #[test]
    fn single_xor_round_trips_against_the_de4dot_index_formula() {
        let key: [u8; KEY_LEN] = *b"AgileNetXORKey16";
        let plain: &[u8] = b"this is plaintext CIL body bytes for a method body here";
        let code_offs: u32 = 0x140;
        let cipher: Vec<u8> = decrypt_body_single_xor(&key, code_offs, plain);
        assert_ne!(cipher.as_slice(), plain);
        let back: Vec<u8> = decrypt_body_single_xor(&key, code_offs, &cipher);
        assert_eq!(back.as_slice(), plain);
    }

    #[test]
    fn dual_xor_round_trips_against_the_de4dot_index_formula() {
        let key: [u8; KEY_LEN] = *b"AgileNetXORKey16";
        let plain: &[u8] = b"dual-xor plaintext body bytes here for a different method";
        let code_offs: u32 = 0x200;
        let hsz: u32 = CODE_HEADER_SIZE as u32;
        let cipher: Vec<u8> = decrypt_body_dual_xor(&key, code_offs, hsz, plain);
        assert_ne!(cipher.as_slice(), plain);
        let back: Vec<u8> = decrypt_body_dual_xor(&key, code_offs, hsz, &cipher);
        assert_eq!(back.as_slice(), plain);
    }

    #[test]
    fn pro_xtea_decrypt_inverts_the_additive_be_encrypt() {
        let key16: [u8; KEY_LEN] = *b"XTEA-Pro-Key-16b";
        let plain: [u8; 16] = *b"0123456789ABCDEF";
        let cipher: Vec<u8> = encrypt_pro_xtea(&key16, &plain);
        assert_ne!(cipher.as_slice(), &plain[..]);
        let back: Vec<u8> = decrypt_body_pro_xtea(&key16, &cipher);
        assert_eq!(back.as_slice(), &plain[..]);
    }

    #[test]
    fn unrecognized_signature_yields_no_header() {
        let mut image: Vec<u8> = vec![0u8; 0x100];
        image[0x40..0x40 + 16].copy_from_slice(&[0xAB; 16]);
        assert!(CliSecureVariant::from_signature(&image[0x40..0x40 + 16]).is_none());
    }
}
