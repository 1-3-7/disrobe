use aes::cipher::block_padding::{NoPadding, Pkcs7};
use aes::cipher::{
    BlockCipher, BlockDecrypt, BlockDecryptMut, BlockEncrypt, BlockEncryptMut, KeyInit, KeyIvInit,
};
use sha2::Digest as _;

use super::SkipReason;

pub(super) const MAX_PBKDF2_ITERATIONS: i32 = 100_000;
pub(super) const MAX_CIPHER_INPUT: usize = 1 << 20;
const ENCRYPT_MODE: i32 = 1;
const DECRYPT_MODE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Aes,
    Des,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Ecb,
    Cbc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Transformation {
    algorithm: Algorithm,
    mode: Mode,
    padded: bool,
}

fn parse_transformation(text: &str) -> Option<Transformation> {
    let mut parts = text.split('/');
    let algorithm: Algorithm = match parts.next()?.trim().to_ascii_uppercase().as_str() {
        "AES" => Algorithm::Aes,
        "DES" => Algorithm::Des,
        _ => return None,
    };
    let mode: Mode = match parts.next().map(|m: &str| m.trim().to_ascii_uppercase()) {
        None => Mode::Ecb,
        Some(m) if m == "ECB" => Mode::Ecb,
        Some(m) if m == "CBC" => Mode::Cbc,
        Some(_) => return None,
    };
    let padded: bool = match parts.next().map(|p: &str| p.trim().to_ascii_uppercase()) {
        None => true,
        Some(p) if p == "PKCS5PADDING" || p == "PKCS7PADDING" => true,
        Some(p) if p == "NOPADDING" => false,
        Some(_) => return None,
    };
    if parts.next().is_some() {
        return None;
    }
    Some(Transformation {
        algorithm,
        mode,
        padded,
    })
}

pub(super) fn derive_pbkdf2(
    algorithm: &str,
    password: &[u16],
    salt: &[u8],
    iterations: i32,
    key_bits: i32,
) -> Result<Vec<u8>, SkipReason> {
    if !(1..=MAX_PBKDF2_ITERATIONS).contains(&iterations) {
        return Err(SkipReason::BudgetExhausted);
    }
    if key_bits <= 0 || key_bits > 512 || key_bits % 8 != 0 {
        return Err(SkipReason::Unsound);
    }
    let rounds: u32 = u32::try_from(iterations).map_err(|_| SkipReason::Unsound)?;
    let password: String = String::from_utf16_lossy(password);
    let mut out: Vec<u8> = vec![0u8; (key_bits / 8) as usize];
    match algorithm {
        "PBKDF2WithHmacSHA1" => {
            pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password.as_bytes(), salt, rounds, &mut out);
        }
        "PBKDF2WithHmacSHA256" => {
            pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password.as_bytes(), salt, rounds, &mut out);
        }
        other => {
            return Err(SkipReason::UnsupportedCall(format!(
                "SecretKeyFactory {other}"
            )));
        }
    }
    Ok(out)
}

pub(super) fn digest(algorithm: &str, data: &[u8]) -> Result<Vec<u8>, SkipReason> {
    match algorithm.to_ascii_uppercase().replace('-', "").as_str() {
        "MD5" => Ok(md5::compute(data).0.to_vec()),
        "SHA1" => Ok(sha1::Sha1::digest(data).to_vec()),
        "SHA256" => Ok(sha2::Sha256::digest(data).to_vec()),
        _ => Err(SkipReason::UnsupportedCall(format!(
            "MessageDigest {algorithm}"
        ))),
    }
}

pub(super) fn run_cipher(
    transformation: &str,
    mode: i32,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, SkipReason> {
    let spec: Transformation = parse_transformation(transformation)
        .ok_or_else(|| SkipReason::UnsupportedCall(format!("Cipher {transformation}")))?;
    if input.len() > MAX_CIPHER_INPUT {
        return Err(SkipReason::OutputTooLarge);
    }
    let decrypt: bool = match mode {
        DECRYPT_MODE => true,
        ENCRYPT_MODE => false,
        _ => return Err(SkipReason::Unsound),
    };
    match (spec.algorithm, key.len()) {
        (Algorithm::Aes, 16) => run::<aes::Aes128>(spec, decrypt, key, iv, input),
        (Algorithm::Aes, 24) => run::<aes::Aes192>(spec, decrypt, key, iv, input),
        (Algorithm::Aes, 32) => run::<aes::Aes256>(spec, decrypt, key, iv, input),
        (Algorithm::Des, 8) => run::<des::Des>(spec, decrypt, key, iv, input),
        _ => Err(SkipReason::Unsound),
    }
}

fn run<C>(
    spec: Transformation,
    decrypt: bool,
    key: &[u8],
    iv: &[u8],
    input: &[u8],
) -> Result<Vec<u8>, SkipReason>
where
    C: BlockCipher + BlockDecrypt + BlockEncrypt + BlockDecryptMut + BlockEncryptMut + KeyInit,
{
    let block: usize = <C as aes::cipher::BlockSizeUser>::block_size();
    match (spec.mode, decrypt) {
        (Mode::Ecb, true) => {
            if !input.len().is_multiple_of(block) {
                return Err(SkipReason::Unsound);
            }
            let cipher: C = C::new_from_slice(key).map_err(|_| SkipReason::Unsound)?;
            let mut out: Vec<u8> = input.to_vec();
            for chunk in out.chunks_exact_mut(block) {
                cipher.decrypt_block(chunk.into());
            }
            if spec.padded {
                strip_pkcs7(&mut out, block)?;
            }
            Ok(out)
        }
        (Mode::Ecb, false) => {
            let cipher: C = C::new_from_slice(key).map_err(|_| SkipReason::Unsound)?;
            let mut out: Vec<u8> = input.to_vec();
            if spec.padded {
                add_pkcs7(&mut out, block);
            } else if !out.len().is_multiple_of(block) {
                return Err(SkipReason::Unsound);
            }
            for chunk in out.chunks_exact_mut(block) {
                cipher.encrypt_block(chunk.into());
            }
            Ok(out)
        }
        (Mode::Cbc, true) => {
            if !input.len().is_multiple_of(block) {
                return Err(SkipReason::Unsound);
            }
            let decryptor: cbc::Decryptor<C> =
                cbc::Decryptor::<C>::new_from_slices(key, iv).map_err(|_| SkipReason::Unsound)?;
            let mut buffer: Vec<u8> = input.to_vec();
            let plain: &[u8] = if spec.padded {
                decryptor
                    .decrypt_padded_mut::<Pkcs7>(&mut buffer)
                    .map_err(|_| SkipReason::Unsound)?
            } else {
                decryptor
                    .decrypt_padded_mut::<NoPadding>(&mut buffer)
                    .map_err(|_| SkipReason::Unsound)?
            };
            Ok(plain.to_vec())
        }
        (Mode::Cbc, false) => {
            let encryptor: cbc::Encryptor<C> =
                cbc::Encryptor::<C>::new_from_slices(key, iv).map_err(|_| SkipReason::Unsound)?;
            let mut buffer: Vec<u8> = input.to_vec();
            buffer.resize(input.len() + block, 0);
            let sealed: &[u8] = if spec.padded {
                encryptor
                    .encrypt_padded_mut::<Pkcs7>(&mut buffer, input.len())
                    .map_err(|_| SkipReason::Unsound)?
            } else {
                encryptor
                    .encrypt_padded_mut::<NoPadding>(&mut buffer, input.len())
                    .map_err(|_| SkipReason::Unsound)?
            };
            Ok(sealed.to_vec())
        }
    }
}

fn strip_pkcs7(data: &mut Vec<u8>, block: usize) -> Result<(), SkipReason> {
    let pad: usize = usize::from(*data.last().ok_or(SkipReason::Unsound)?);
    if pad == 0 || pad > block || pad > data.len() {
        return Err(SkipReason::Unsound);
    }
    let start: usize = data.len() - pad;
    if data[start..].iter().any(|&b: &u8| usize::from(b) != pad) {
        return Err(SkipReason::Unsound);
    }
    data.truncate(start);
    Ok(())
}

fn add_pkcs7(data: &mut Vec<u8>, block: usize) {
    let pad: usize = block - data.len() % block;
    data.extend(std::iter::repeat_n(pad as u8, pad));
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn aes_ecb_round_trip_with_pkcs7_padding() {
        let key: [u8; 16] = [7u8; 16];
        let sealed: Vec<u8> =
            run_cipher("AES/ECB/PKCS5Padding", ENCRYPT_MODE, &key, &[], b"hello").expect("encrypt");
        assert_eq!(sealed.len(), 16);
        let plain: Vec<u8> = run_cipher("AES", DECRYPT_MODE, &key, &[], &sealed).expect("decrypt");
        assert_eq!(plain, b"hello");
    }

    #[test]
    fn aes_cbc_round_trip_and_bad_padding_is_refused() {
        let key: [u8; 32] = [3u8; 32];
        let iv: [u8; 16] = [9u8; 16];
        let sealed: Vec<u8> = run_cipher(
            "AES/CBC/PKCS5Padding",
            ENCRYPT_MODE,
            &key,
            &iv,
            b"sixteen bytes!!!",
        )
        .expect("encrypt");
        assert_eq!(sealed.len(), 32);
        let plain: Vec<u8> =
            run_cipher("AES/CBC/PKCS5Padding", DECRYPT_MODE, &key, &iv, &sealed).expect("decrypt");
        assert_eq!(plain, b"sixteen bytes!!!");
        let wrong: [u8; 32] = [4u8; 32];
        assert_eq!(
            run_cipher("AES/CBC/PKCS5Padding", DECRYPT_MODE, &wrong, &iv, &sealed),
            Err(SkipReason::Unsound)
        );
    }

    #[test]
    fn des_ecb_decrypts_what_it_encrypts() {
        let key: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
        let sealed: Vec<u8> =
            run_cipher("DES/ECB/PKCS5Padding", ENCRYPT_MODE, &key, &[], b"abc").expect("encrypt");
        assert_eq!(sealed.len(), 8);
        assert_eq!(
            run_cipher("DES", DECRYPT_MODE, &key, &[], &sealed).expect("decrypt"),
            b"abc"
        );
    }

    #[test]
    fn pbkdf2_sha1_matches_the_rfc_6070_vector() {
        let password: Vec<u16> = "password".encode_utf16().collect();
        let key: Vec<u8> =
            derive_pbkdf2("PBKDF2WithHmacSHA1", &password, b"salt", 2, 160).expect("derive");
        assert_eq!(
            key,
            [
                0xea, 0x6c, 0x01, 0x4d, 0xc7, 0x2d, 0x6f, 0x8c, 0xcd, 0x1e, 0xd9, 0x2a, 0xce, 0x1d,
                0x41, 0xf0, 0xd8, 0xde, 0x89, 0x57
            ]
        );
        assert_eq!(
            derive_pbkdf2(
                "PBKDF2WithHmacSHA1",
                &password,
                b"salt",
                MAX_PBKDF2_ITERATIONS + 1,
                128
            ),
            Err(SkipReason::BudgetExhausted)
        );
    }

    #[test]
    fn digests_match_known_values() {
        assert_eq!(
            digest("MD5", b"abc").expect("md5"),
            [
                0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
                0x7f, 0x72
            ]
        );
        assert_eq!(
            digest("SHA-1", b"abc").expect("sha1")[..4],
            [0xa9, 0x99, 0x3e, 0x36]
        );
        assert_eq!(
            digest("SHA-256", b"abc").expect("sha256")[..4],
            [0xba, 0x78, 0x16, 0xbf]
        );
        assert!(digest("SHA-512", b"abc").is_err());
    }

    #[test]
    fn unknown_transformations_are_refused_by_name() {
        assert_eq!(
            run_cipher(
                "RSA/ECB/PKCS1Padding",
                DECRYPT_MODE,
                &[0u8; 16],
                &[],
                &[0u8; 16]
            ),
            Err(SkipReason::UnsupportedCall(
                "Cipher RSA/ECB/PKCS1Padding".to_owned()
            ))
        );
        assert_eq!(
            run_cipher(
                "AES/GCM/NoPadding",
                DECRYPT_MODE,
                &[0u8; 16],
                &[],
                &[0u8; 16]
            ),
            Err(SkipReason::UnsupportedCall(
                "Cipher AES/GCM/NoPadding".to_owned()
            ))
        );
    }
}
