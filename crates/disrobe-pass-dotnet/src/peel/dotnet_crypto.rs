#![allow(clippy::many_single_char_names)]
use cbc::Decryptor;
use cbc::cipher::block_padding::NoPadding;
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use des::TdesEde3;
use sha1::Sha1;
use sha2::Digest;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    BadKeyLength,
    BadBlockAlignment,
    Empty,
}

#[must_use]
pub fn rc4_apply(key: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    if key.is_empty() || key.len() > 256 {
        return None;
    }
    Some(disrobe_core::codec::cipher::rc4_apply(key, data))
}

#[must_use]
pub fn sha1_digest(data: &[u8]) -> [u8; 20] {
    let mut hasher: Sha1 = Sha1::new();
    hasher.update(data);
    let digest: sha1::digest::Output<Sha1> = hasher.finalize();
    let mut out: [u8; 20] = [0u8; 20];
    out.copy_from_slice(&digest);
    out
}

#[must_use]
pub fn rc4_sha1_keyed(key_material: &[u8], data: &[u8]) -> Option<Vec<u8>> {
    let key: [u8; 20] = sha1_digest(key_material);
    rc4_apply(&key, data)
}

pub fn aes128_cbc_decrypt_no_pad(
    key: &[u8; 16],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Empty);
    }
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::BadBlockAlignment);
    }
    disrobe_core::codec::aes_cbc_decrypt(key, iv, data, disrobe_core::codec::CbcPadding::NoPadding)
        .map_err(|_| CryptoError::BadBlockAlignment)
}

pub fn aes256_cbc_decrypt_no_pad(
    key: &[u8; 32],
    iv: &[u8; 16],
    data: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Empty);
    }
    if !data.len().is_multiple_of(16) {
        return Err(CryptoError::BadBlockAlignment);
    }
    disrobe_core::codec::aes_cbc_decrypt(key, iv, data, disrobe_core::codec::CbcPadding::NoPadding)
        .map_err(|_| CryptoError::BadBlockAlignment)
}

#[must_use]
pub fn strip_pkcs7(data: &[u8], block: usize) -> Option<Vec<u8>> {
    if block == 0 || data.is_empty() || !data.len().is_multiple_of(block) {
        return None;
    }
    let pad_len: usize = usize::from(*data.last()?);
    if pad_len == 0 || pad_len > block || pad_len > data.len() {
        return None;
    }
    let start: usize = data.len() - pad_len;
    data.get(start..)?
        .iter()
        .all(|&b: &u8| usize::from(b) == pad_len)
        .then(|| data[..start].to_vec())
}

pub fn tdes_cbc_decrypt(key: &[u8; 24], iv: [u8; 8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Empty);
    }
    if !data.len().is_multiple_of(8) {
        return Err(CryptoError::BadBlockAlignment);
    }
    let mut buf: Vec<u8> = data.to_vec();
    Decryptor::<TdesEde3>::new(key.into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CryptoError::BadBlockAlignment)?;
    Ok(buf)
}

pub fn des_cbc_decrypt(key: [u8; 8], iv: [u8; 8], data: &[u8]) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Empty);
    }
    if !data.len().is_multiple_of(8) {
        return Err(CryptoError::BadBlockAlignment);
    }
    let mut buf: Vec<u8> = data.to_vec();
    Decryptor::<des::Des>::new((&key).into(), (&iv).into())
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CryptoError::BadBlockAlignment)?;
    Ok(buf)
}

#[derive(Debug, Clone)]
pub struct Blowfish {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Blowfish {
    #[must_use]
    pub fn new(key: &[u8]) -> Option<Self> {
        if key.is_empty() || key.len() > 56 {
            return None;
        }
        let mut bf: Self = Self {
            p: BLOWFISH_P,
            s: BLOWFISH_S,
        };
        let mut j: usize = 0;
        for entry in &mut bf.p {
            let mut word: u32 = 0;
            for _ in 0..4 {
                word = (word << 8) | u32::from(key[j]);
                j = (j + 1) % key.len();
            }
            *entry ^= word;
        }
        let mut l: u32 = 0;
        let mut r: u32 = 0;
        let mut i: usize = 0;
        while i < 18 {
            let (nl, nr): (u32, u32) = bf.encrypt_block(l, r);
            l = nl;
            r = nr;
            bf.p[i] = l;
            bf.p[i + 1] = r;
            i += 2;
        }
        for box_idx in 0..4 {
            let mut k: usize = 0;
            while k < 256 {
                let (nl, nr): (u32, u32) = bf.encrypt_block(l, r);
                l = nl;
                r = nr;
                bf.s[box_idx][k] = l;
                bf.s[box_idx][k + 1] = r;
                k += 2;
            }
        }
        Some(bf)
    }

    const fn feistel(&self, x: u32) -> u32 {
        let a: u32 = self.s[0][(x >> 24) as usize];
        let b: u32 = self.s[1][((x >> 16) & 0xFF) as usize];
        let c: u32 = self.s[2][((x >> 8) & 0xFF) as usize];
        let d: u32 = self.s[3][(x & 0xFF) as usize];
        (a.wrapping_add(b) ^ c).wrapping_add(d)
    }

    fn encrypt_block(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            l ^= self.p[i];
            r ^= self.feistel(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r);
        r ^= self.p[16];
        l ^= self.p[17];
        (l, r)
    }

    #[must_use]
    pub fn cfb_decrypt(&self, iv: [u8; 8], data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        let mut feedback_l: u32 = u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]);
        let mut feedback_r: u32 = u32::from_be_bytes([iv[4], iv[5], iv[6], iv[7]]);
        for chunk in data.chunks(8) {
            let (kl, kr): (u32, u32) = self.encrypt_block(feedback_l, feedback_r);
            let mut keystream: [u8; 8] = [0u8; 8];
            keystream[..4].copy_from_slice(&kl.to_be_bytes());
            keystream[4..].copy_from_slice(&kr.to_be_bytes());
            let mut block: [u8; 8] = [0u8; 8];
            block[..chunk.len()].copy_from_slice(chunk);
            for (i, &c) in chunk.iter().enumerate() {
                out.push(c ^ keystream[i]);
            }
            feedback_l = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
            feedback_r = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        }
        out
    }
}

const BLOWFISH_P: [u32; 18] = [
    0x243F_6A88,
    0x85A3_08D3,
    0x1319_8A2E,
    0x0370_7344,
    0xA409_3822,
    0x299F_31D0,
    0x082E_FA98,
    0xEC4E_6C89,
    0x4528_21E6,
    0x38D0_1377,
    0xBE54_66CF,
    0x34E9_0C6C,
    0xC0AC_29B7,
    0xC97C_50DD,
    0x3F84_D5B5,
    0xB547_0917,
    0x9216_D5D9,
    0x8979_FB1B,
];

const BLOWFISH_S: [[u32; 256]; 4] = [
    crate::peel::blowfish_tables::S0,
    crate::peel::blowfish_tables::S1,
    crate::peel::blowfish_tables::S2,
    crate::peel::blowfish_tables::S3,
];

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use aes::Aes128;

    use super::*;

    #[test]
    fn rc4_matches_published_test_vector() {
        let out: Vec<u8> = rc4_apply(b"Key", b"Plaintext").expect("rc4");
        assert_eq!(out, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn rc4_wikipedia_vector_second() {
        let out: Vec<u8> = rc4_apply(b"Wiki", b"pedia").expect("rc4");
        assert_eq!(out, [0x10, 0x21, 0xBF, 0x04, 0x20]);
    }

    #[test]
    fn rc4_is_involutive_for_stream() {
        let key: &[u8] = b"secret-key";
        let plain: &[u8] = b"connection=Server=db;Password=hunter2";
        let cipher: Vec<u8> = rc4_apply(key, plain).expect("enc");
        assert_ne!(cipher, plain);
        let back: Vec<u8> = rc4_apply(key, &cipher).expect("dec");
        assert_eq!(back, plain);
    }

    #[test]
    fn sha1_matches_empty_vector() {
        let d: [u8; 20] = sha1_digest(b"");
        assert_eq!(
            d,
            [
                0xDA, 0x39, 0xA3, 0xEE, 0x5E, 0x6B, 0x4B, 0x0D, 0x32, 0x55, 0xBF, 0xEF, 0x95, 0x60,
                0x18, 0x90, 0xAF, 0xD8, 0x07, 0x09
            ]
        );
    }

    #[test]
    fn sha1_matches_abc_vector() {
        let d: [u8; 20] = sha1_digest(b"abc");
        assert_eq!(
            d,
            [
                0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
                0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D
            ]
        );
    }

    #[test]
    fn blowfish_matches_published_zero_key_ecb_vector() {
        let key: [u8; 8] = [0u8; 8];
        let bf: Blowfish = Blowfish::new(&key).expect("bf");
        let (l, r): (u32, u32) = bf.encrypt_block(0x0000_0000, 0x0000_0000);
        assert_eq!(l, 0x4EF9_9745);
        assert_eq!(r, 0x6198_DD78);
    }

    #[test]
    fn blowfish_cfb_round_trips_against_self_encrypt() {
        let key: &[u8] = b"a-blowfish-key";
        let iv: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
        let bf: Blowfish = Blowfish::new(key).expect("bf");
        let plain: &[u8] = b"the quick brown fox jumps over 13";
        let cipher: Vec<u8> = cfb_encrypt_reference(&bf, iv, plain);
        let recovered: Vec<u8> = bf.cfb_decrypt(iv, &cipher);
        assert_eq!(recovered, plain);
    }

    fn cfb_encrypt_reference(bf: &Blowfish, iv: [u8; 8], data: &[u8]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(data.len());
        let mut fl: u32 = u32::from_be_bytes([iv[0], iv[1], iv[2], iv[3]]);
        let mut fr: u32 = u32::from_be_bytes([iv[4], iv[5], iv[6], iv[7]]);
        for chunk in data.chunks(8) {
            let (kl, kr): (u32, u32) = bf.encrypt_block(fl, fr);
            let mut ks: [u8; 8] = [0u8; 8];
            ks[..4].copy_from_slice(&kl.to_be_bytes());
            ks[4..].copy_from_slice(&kr.to_be_bytes());
            let mut block: [u8; 8] = [0u8; 8];
            for (i, &c) in chunk.iter().enumerate() {
                let e: u8 = c ^ ks[i];
                out.push(e);
                block[i] = e;
            }
            fl = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
            fr = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        }
        out
    }

    #[test]
    fn tdes_cbc_round_trips_against_known_construction() {
        let key: [u8; 24] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD,
            0xEF, 0x01, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23,
        ];
        let iv: [u8; 8] = [0u8; 8];
        let plain: [u8; 16] = *b"0123456789ABCDEF";
        let cipher: Vec<u8> = tdes_cbc_encrypt_reference(&key, iv, &plain);
        let recovered: Vec<u8> = tdes_cbc_decrypt(&key, iv, &cipher).expect("dec");
        assert_eq!(recovered, plain);
    }

    fn tdes_cbc_encrypt_reference(key: &[u8; 24], iv: [u8; 8], data: &[u8]) -> Vec<u8> {
        use cbc::Encryptor;
        use cbc::cipher::BlockEncryptMut;
        let mut buf: Vec<u8> = data.to_vec();
        Encryptor::<TdesEde3>::new(key.into(), (&iv).into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
            .expect("enc");
        buf
    }

    #[test]
    fn aes128_cbc_round_trips() {
        let key: [u8; 16] = *b"0123456789abcdef";
        let iv: [u8; 16] = *b"fedcba9876543210";
        let plain: [u8; 32] = *b"Server=prod;User=svc;Pwd=topsecr";
        let cipher: Vec<u8> = aes128_cbc_encrypt_reference(&key, &iv, &plain);
        let recovered: Vec<u8> = aes128_cbc_decrypt_no_pad(&key, &iv, &cipher).expect("dec");
        assert_eq!(recovered, plain);
    }

    fn aes128_cbc_encrypt_reference(key: &[u8; 16], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
        use cbc::Encryptor;
        use cbc::cipher::BlockEncryptMut;
        let mut buf: Vec<u8> = data.to_vec();
        Encryptor::<Aes128>::new(key.into(), iv.into())
            .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
            .expect("enc");
        buf
    }

    #[test]
    fn pkcs7_strip_removes_valid_padding() {
        let mut data: Vec<u8> = b"hello".to_vec();
        data.extend_from_slice(&[3, 3, 3]);
        assert_eq!(strip_pkcs7(&data, 8).as_deref(), Some(&b"hello"[..]));
    }

    #[test]
    fn pkcs7_strip_rejects_invalid_padding() {
        let mut inconsistent: Vec<u8> = b"hello".to_vec();
        inconsistent.extend_from_slice(&[3, 2, 3]);
        assert_eq!(strip_pkcs7(&inconsistent, 8), None);

        let mut zero_pad: Vec<u8> = b"hellowor".to_vec();
        zero_pad.extend_from_slice(&[0u8; 8]);
        assert_eq!(strip_pkcs7(&zero_pad, 8), None);

        let mut over_block: Vec<u8> = b"hi".to_vec();
        over_block.extend_from_slice(&[9u8; 6]);
        assert_eq!(strip_pkcs7(&over_block, 8), None);

        assert_eq!(strip_pkcs7(b"", 8), None);
        assert_eq!(strip_pkcs7(&[1u8; 7], 8), None);
        assert_eq!(strip_pkcs7(&[1u8; 8], 0), None);
    }
}
