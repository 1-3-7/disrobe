use aes::Aes256;
use aes::cipher::{BlockEncrypt, KeyInit};

use crate::error::{Error, Result};
use crate::kdf::AES_KEY_LEN;
use crate::modern_gcm::{GCM_NONCE_LEN, GCM_TAG_LEN};

pub(crate) const GCM_BLOCK_LEN: usize = 16;

const GHASH_REDUCTION: u128 = 0xE100_0000_0000_0000_0000_0000_0000_0000;
const MAX_GCM_CIPHERTEXT_BYTES: u64 = (1u64 << 36) - 32;
const MAX_GCM_AAD_BYTES: u64 = (1u64 << 61) - 1;

const fn gf_mul(operand: u128, multiplier: u128) -> u128 {
    let mut product: u128 = 0;
    let mut running: u128 = multiplier;
    let mut bit: u32 = 0;
    while bit < 128 {
        let selector: u128 = 0u128.wrapping_sub((operand >> (127 - bit)) & 1);
        product ^= running & selector;
        let carry: u128 = 0u128.wrapping_sub(running & 1);
        running = (running >> 1) ^ (GHASH_REDUCTION & carry);
        bit += 1;
    }
    product
}

struct Ghash {
    subkey: u128,
    accumulator: u128,
}

impl Ghash {
    const fn new(subkey: u128) -> Self {
        Self {
            subkey,
            accumulator: 0,
        }
    }

    const fn absorb_block(&mut self, block: u128) {
        self.accumulator = gf_mul(self.accumulator ^ block, self.subkey);
    }

    fn absorb_zero_padded(&mut self, data: &[u8]) {
        let mut blocks = data.chunks_exact(GCM_BLOCK_LEN);
        for chunk in blocks.by_ref() {
            let mut whole: [u8; GCM_BLOCK_LEN] = [0u8; GCM_BLOCK_LEN];
            whole.copy_from_slice(chunk);
            self.absorb_block(u128::from_be_bytes(whole));
        }
        let tail: &[u8] = blocks.remainder();
        if !tail.is_empty() {
            let mut padded: [u8; GCM_BLOCK_LEN] = [0u8; GCM_BLOCK_LEN];
            for (slot, byte) in padded.iter_mut().zip(tail.iter()) {
                *slot = *byte;
            }
            self.absorb_block(u128::from_be_bytes(padded));
        }
    }

    const fn finish(self) -> u128 {
        self.accumulator
    }
}

fn encrypt_block(cipher: &Aes256, block: u128) -> u128 {
    let mut buffer: aes::Block = aes::Block::from(block.to_be_bytes());
    cipher.encrypt_block(&mut buffer);
    u128::from_be_bytes(buffer.into())
}

fn ensure_within(surface: &'static str, observed: usize, limit: u64) -> Result<()> {
    if observed as u64 > limit {
        return Err(Error::InputLimit {
            surface,
            observed,
            limit: usize::try_from(limit).unwrap_or(usize::MAX),
        });
    }
    Ok(())
}

pub(crate) fn gcm_tag(
    key: &[u8; AES_KEY_LEN],
    nonce: &[u8; GCM_NONCE_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<[u8; GCM_TAG_LEN]> {
    ensure_within(
        "aes-gcm ciphertext",
        ciphertext.len(),
        MAX_GCM_CIPHERTEXT_BYTES,
    )?;
    ensure_within("aes-gcm associated data", aad.len(), MAX_GCM_AAD_BYTES)?;

    let cipher: Aes256 = Aes256::new(key.into());
    let mut state: Ghash = Ghash::new(encrypt_block(&cipher, 0));
    state.absorb_zero_padded(aad);
    state.absorb_zero_padded(ciphertext);
    let aad_bits: u128 = (aad.len() as u128) << 3;
    let ciphertext_bits: u128 = (ciphertext.len() as u128) << 3;
    state.absorb_block((aad_bits << 64) | ciphertext_bits);

    let mut counter_zero: [u8; GCM_BLOCK_LEN] = [0u8; GCM_BLOCK_LEN];
    for (slot, byte) in counter_zero.iter_mut().zip(nonce.iter()) {
        *slot = *byte;
    }
    let j0: u128 = u128::from_be_bytes(counter_zero) | 1;
    Ok((state.finish() ^ encrypt_block(&cipher, j0)).to_be_bytes())
}

pub(crate) fn tags_match(left: &[u8; GCM_TAG_LEN], right: &[u8; GCM_TAG_LEN]) -> bool {
    let mut difference: u8 = 0;
    for (a, b) in left.iter().zip(right.iter()) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::codec::{hex_decode, hex_encode};

    struct PublishedVector {
        name: &'static str,
        key: &'static str,
        nonce: &'static str,
        aad: &'static str,
        ciphertext: &'static str,
        tag: &'static str,
    }

    const ZERO_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000000";
    const SPEC_KEY: &str = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";
    const SPEC_NONCE: &str = "cafebabefacedbaddecaf888";

    const TEST_CASE_13: PublishedVector = PublishedVector {
        name: "gcm-spec test case 13 (aes-256, empty plaintext, empty aad)",
        key: ZERO_KEY,
        nonce: "000000000000000000000000",
        aad: "",
        ciphertext: "",
        tag: "530f8afbc74536b9a963b4f1c4cb738b",
    };

    const TEST_CASE_14: PublishedVector = PublishedVector {
        name: "gcm-spec test case 14 (aes-256, one zero block, empty aad)",
        key: ZERO_KEY,
        nonce: "000000000000000000000000",
        aad: "",
        ciphertext: "cea7403d4d606b6e074ec5d3baf39d18",
        tag: "d0d1c8a799996bf0265b98b5d48ab919",
    };

    const TEST_CASE_15: PublishedVector = PublishedVector {
        name: "gcm-spec test case 15 (aes-256, 64-byte ciphertext, empty aad)",
        key: SPEC_KEY,
        nonce: SPEC_NONCE,
        aad: "",
        ciphertext: concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        ),
        tag: "b094dac5d93471bdec1a502270e3cc6c",
    };

    const TEST_CASE_16: PublishedVector = PublishedVector {
        name: "gcm-spec test case 16 (aes-256, 60-byte ciphertext, 20-byte aad)",
        key: SPEC_KEY,
        nonce: SPEC_NONCE,
        aad: "feedfacedeadbeeffeedfacedeadbeefabaddad2",
        ciphertext: concat!(
            "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa",
            "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        ),
        tag: "76fc6ece0f4e1768cddf8853bb2d551b",
    };

    const PUBLISHED_AES256_GCM_VECTORS: [&PublishedVector; 4] =
        [&TEST_CASE_13, &TEST_CASE_14, &TEST_CASE_15, &TEST_CASE_16];

    fn fixed_key(hex: &str) -> [u8; AES_KEY_LEN] {
        let raw: Vec<u8> = hex_decode(hex.as_bytes()).expect("vector key hex");
        raw.try_into().expect("vector key is 32 bytes")
    }

    fn fixed_nonce(hex: &str) -> [u8; GCM_NONCE_LEN] {
        let raw: Vec<u8> = hex_decode(hex.as_bytes()).expect("vector nonce hex");
        raw.try_into().expect("vector nonce is 12 bytes")
    }

    fn vector_bytes(hex: &str) -> Vec<u8> {
        if hex.is_empty() {
            return Vec::new();
        }
        hex_decode(hex.as_bytes()).expect("vector hex")
    }

    fn tag_of(vector: &PublishedVector) -> [u8; GCM_TAG_LEN] {
        gcm_tag(
            &fixed_key(vector.key),
            &fixed_nonce(vector.nonce),
            &vector_bytes(vector.aad),
            &vector_bytes(vector.ciphertext),
        )
        .expect("published vector is within the gcm length bounds")
    }

    #[test]
    fn every_published_aes256_gcm_vector_reproduces_its_tag() {
        let mut reproduced: usize = 0;
        for vector in PUBLISHED_AES256_GCM_VECTORS {
            assert_eq!(
                hex_encode(&tag_of(vector)),
                vector.tag,
                "{} must reproduce the published authentication tag",
                vector.name
            );
            reproduced += 1;
        }
        assert_eq!(
            reproduced,
            PUBLISHED_AES256_GCM_VECTORS.len(),
            "every entry in the published vector table must be exercised"
        );
        assert_eq!(
            PUBLISHED_AES256_GCM_VECTORS.len(),
            4,
            "the published vector table must not shrink silently"
        );
    }

    #[test]
    fn a_flipped_ciphertext_bit_changes_the_tag() {
        let key: [u8; AES_KEY_LEN] = fixed_key(TEST_CASE_15.key);
        let nonce: [u8; GCM_NONCE_LEN] = fixed_nonce(TEST_CASE_15.nonce);
        let ciphertext: Vec<u8> = vector_bytes(TEST_CASE_15.ciphertext);
        let mut tampered: Vec<u8> = ciphertext.clone();
        let Some(first): Option<&mut u8> = tampered.first_mut() else {
            panic!("the vector ciphertext is not empty")
        };
        *first ^= 0x01;

        let original: [u8; GCM_TAG_LEN] = gcm_tag(&key, &nonce, &[], &ciphertext).expect("tag");
        let mutated: [u8; GCM_TAG_LEN] = gcm_tag(&key, &nonce, &[], &tampered).expect("tag");
        assert_ne!(original, mutated);
        assert!(!tags_match(&original, &mutated));
        assert!(tags_match(&original, &original));
    }

    #[test]
    fn a_wrong_key_produces_a_different_tag_over_identical_ciphertext() {
        let nonce: [u8; GCM_NONCE_LEN] = fixed_nonce(TEST_CASE_15.nonce);
        let ciphertext: Vec<u8> = vector_bytes(TEST_CASE_15.ciphertext);
        let correct: [u8; GCM_TAG_LEN] =
            gcm_tag(&fixed_key(TEST_CASE_15.key), &nonce, &[], &ciphertext).expect("tag");
        let wrong: [u8; GCM_TAG_LEN] =
            gcm_tag(&[0xFFu8; AES_KEY_LEN], &nonce, &[], &ciphertext).expect("tag");
        assert!(!tags_match(&correct, &wrong));
        assert_eq!(hex_encode(&correct), TEST_CASE_15.tag);
    }

    #[test]
    fn associated_data_is_authenticated_separately_from_ciphertext() {
        let key: [u8; AES_KEY_LEN] = fixed_key(TEST_CASE_16.key);
        let nonce: [u8; GCM_NONCE_LEN] = fixed_nonce(TEST_CASE_16.nonce);
        let ciphertext: Vec<u8> = vector_bytes(TEST_CASE_16.ciphertext);
        let aad: Vec<u8> = vector_bytes(TEST_CASE_16.aad);

        let with_aad: [u8; GCM_TAG_LEN] = gcm_tag(&key, &nonce, &aad, &ciphertext).expect("tag");
        let without_aad: [u8; GCM_TAG_LEN] = gcm_tag(&key, &nonce, &[], &ciphertext).expect("tag");
        assert_ne!(
            with_aad, without_aad,
            "the trailing length block must cover the aad length, not only the ciphertext length"
        );
        assert_eq!(hex_encode(&with_aad), TEST_CASE_16.tag);
    }

    #[test]
    fn the_ghash_subkey_is_the_published_value_for_an_all_zero_key() {
        let cipher: Aes256 = Aes256::new((&[0u8; AES_KEY_LEN]).into());
        let subkey: u128 = encrypt_block(&cipher, 0);
        assert_eq!(
            hex_encode(&subkey.to_be_bytes()),
            "dc95c078a2408989ad48a21492842087",
            "H = E_K(0^128) under the all-zero aes-256 key is a published gcm-spec value"
        );
    }

    #[test]
    fn galois_multiplication_is_commutative_with_an_identity_and_a_zero() {
        let left: u128 = 0x0388_dace_60b6_a392_f328_c2b9_71b2_fe78;
        let right: u128 = 0x66e9_4bd4_ef8a_2c3b_884c_fa59_ca34_2b2e;
        assert_eq!(gf_mul(left, right), gf_mul(right, left));
        assert_eq!(gf_mul(left, 0), 0);
        assert_eq!(
            gf_mul(left, 0x8000_0000_0000_0000_0000_0000_0000_0000),
            left,
            "the leading bit is the multiplicative identity in the gcm bit order"
        );
    }
}
