use aes::{Aes128, Aes256};
use cbc::Decryptor;
use cipher::block_padding::{NoPadding, Pkcs7};
use cipher::{BlockDecryptMut, KeyIvInit};

use super::DecodeError;

const AES_BLOCK: usize = 16;
const AES_IV_LEN: usize = 16;
const AES128_KEY_LEN: usize = 16;
const AES256_KEY_LEN: usize = 32;
const MAX_AES_INPUT: usize = 1 << 26;

type Aes128CbcDec = Decryptor<Aes128>;
type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbcPadding {
    NoPadding,
    Pkcs7,
}

pub fn aes_cbc_decrypt(
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    padding: CbcPadding,
) -> Result<Vec<u8>, DecodeError> {
    if iv.len() != AES_IV_LEN {
        return Err(DecodeError::BadLength { len: iv.len() });
    }
    if ciphertext.len() > MAX_AES_INPUT {
        return Err(DecodeError::TooLarge {
            len: ciphertext.len(),
        });
    }
    if !ciphertext.len().is_multiple_of(AES_BLOCK) {
        return Err(DecodeError::BadLength {
            len: ciphertext.len(),
        });
    }
    let mut buffer: Vec<u8> = ciphertext.to_vec();
    let plain: &[u8] = match (key.len(), padding) {
        (AES128_KEY_LEN, CbcPadding::Pkcs7) => {
            let engine: Aes128CbcDec = new_engine(key, iv)?;
            engine
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| DecodeError::BadPadding)?
        }
        (AES128_KEY_LEN, CbcPadding::NoPadding) => {
            let engine: Aes128CbcDec = new_engine(key, iv)?;
            engine
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| DecodeError::BadPadding)?
        }
        (AES256_KEY_LEN, CbcPadding::Pkcs7) => {
            let engine: Aes256CbcDec = new_engine(key, iv)?;
            engine
                .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                .map_err(|_| DecodeError::BadPadding)?
        }
        (AES256_KEY_LEN, CbcPadding::NoPadding) => {
            let engine: Aes256CbcDec = new_engine(key, iv)?;
            engine
                .decrypt_padded_mut::<NoPadding>(&mut buffer)
                .map_err(|_| DecodeError::BadPadding)?
        }
        (other, _) => return Err(DecodeError::BadLength { len: other }),
    };
    Ok(plain.to_vec())
}

fn new_engine<E: KeyIvInit>(key: &[u8], iv: &[u8]) -> Result<E, DecodeError> {
    E::new_from_slices(key, iv).map_err(|_| DecodeError::BadLength { len: key.len() })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn unhex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i: usize| u8::from_str_radix(&text[i..i + 2], 16).expect("valid hex pair"))
            .collect()
    }

    #[test]
    fn aes128_cbc_nopadding_nist_sp800_38a() {
        let key: Vec<u8> = unhex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv: Vec<u8> = unhex("000102030405060708090a0b0c0d0e0f");
        let ciphertext: Vec<u8> = unhex(
            "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7",
        );
        let expected: Vec<u8> = unhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        assert_eq!(
            aes_cbc_decrypt(&key, &iv, &ciphertext, CbcPadding::NoPadding).unwrap(),
            expected
        );
    }

    #[test]
    fn aes256_cbc_nopadding_nist_sp800_38a() {
        let key: Vec<u8> =
            unhex("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
        let iv: Vec<u8> = unhex("000102030405060708090a0b0c0d0e0f");
        let ciphertext: Vec<u8> = unhex(
            "f58c4c04d6e5f1ba779eabfb5f7bfbd69cfc4e967edb808d679f777bc6702c7d39f23369a9d9bacfa530e26304231461b2eb05e2c39be9fcda6c19078c6a9d1b",
        );
        let expected: Vec<u8> = unhex(
            "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710",
        );
        assert_eq!(
            aes_cbc_decrypt(&key, &iv, &ciphertext, CbcPadding::NoPadding).unwrap(),
            expected
        );
    }

    #[test]
    fn aes128_cbc_pkcs7_openssl_vector() {
        let key: Vec<u8> = unhex("00112233445566778899aabbccddeeff");
        let iv: Vec<u8> = unhex("0f0e0d0c0b0a09080706050403020100");
        let ciphertext: Vec<u8> = unhex(
            "06f98323111bcf51eb4e9f33aa73d7d5b44b2f4df84340cc72ac53e3346aebcbe537b2fd9fb933b86f33edb84b5e3b18",
        );
        assert_eq!(
            aes_cbc_decrypt(&key, &iv, &ciphertext, CbcPadding::Pkcs7).unwrap(),
            b"disrobe aes-cbc canonical helper"
        );
    }

    #[test]
    fn rejects_bad_iv_length() {
        let key: Vec<u8> = vec![0u8; 16];
        assert!(matches!(
            aes_cbc_decrypt(&key, &[0u8; 8], &[0u8; 16], CbcPadding::NoPadding),
            Err(DecodeError::BadLength { len: 8 })
        ));
    }

    #[test]
    fn rejects_bad_key_length() {
        assert!(matches!(
            aes_cbc_decrypt(&[0u8; 24], &[0u8; 16], &[0u8; 16], CbcPadding::NoPadding),
            Err(DecodeError::BadLength { len: 24 })
        ));
    }

    #[test]
    fn rejects_misaligned_ciphertext() {
        assert!(matches!(
            aes_cbc_decrypt(&[0u8; 16], &[0u8; 16], &[0u8; 20], CbcPadding::NoPadding),
            Err(DecodeError::BadLength { len: 20 })
        ));
    }

    #[test]
    fn rejects_corrupt_pkcs7_padding() {
        let key: Vec<u8> = unhex("00112233445566778899aabbccddeeff");
        let iv: Vec<u8> = unhex("0f0e0d0c0b0a09080706050403020100");
        let mut ciphertext: Vec<u8> = unhex(
            "06f98323111bcf51eb4e9f33aa73d7d5b44b2f4df84340cc72ac53e3346aebcbe537b2fd9fb933b86f33edb84b5e3b18",
        );
        let last: usize = ciphertext.len() - 1;
        ciphertext[last] ^= 0xff;
        assert!(matches!(
            aes_cbc_decrypt(&key, &iv, &ciphertext, CbcPadding::Pkcs7),
            Err(DecodeError::BadPadding)
        ));
    }
}
