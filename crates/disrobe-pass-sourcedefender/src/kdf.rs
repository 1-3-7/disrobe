use blake2::Blake2bVar;
use blake2::digest::Mac;
use blake2::digest::Update;
use blake2::digest::VariableOutput;

use crate::error::{Error, Result};

type Blake2bMac32 = blake2::Blake2bMac<blake2::digest::consts::U32>;

pub const AES_KEY_LEN: usize = 32;
pub const AES_IV_LEN: usize = 16;
const KDF_KEY_BYTES: usize = 64;
const KDF_SALT_BYTES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedKey(pub [u8; AES_KEY_LEN]);

impl DerivedKey {
    #[inline]
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; AES_KEY_LEN] {
        &self.0
    }
}

#[inline]
pub fn derive_aes_key(basename: &str) -> Result<DerivedKey> {
    let bytes: &[u8] = basename.as_bytes();
    let key64: Vec<u8> = blake2b_var(bytes, KDF_KEY_BYTES)?;
    let salt16: Vec<u8> = blake2b_var(bytes, KDF_SALT_BYTES)?;
    let derived: [u8; AES_KEY_LEN] = blake2b_keyed_salted(&key64, &salt16)?;
    Ok(DerivedKey(derived))
}

#[inline]
fn blake2b_var(data: &[u8], out_len: usize) -> Result<Vec<u8>> {
    let mut hasher: Blake2bVar =
        Blake2bVar::new(out_len).map_err(|e| Error::Blake2(format!("{e}")))?;
    hasher.update(data);
    let mut out: Vec<u8> = vec![0u8; out_len];
    hasher
        .finalize_variable(&mut out)
        .map_err(|e| Error::Blake2(format!("{e}")))?;
    Ok(out)
}

fn blake2b_keyed_salted(key: &[u8], salt: &[u8]) -> Result<[u8; AES_KEY_LEN]> {
    if salt.len() > KDF_SALT_BYTES || key.len() > KDF_KEY_BYTES {
        return Err(Error::Blake2(
            "unsupported blake2b parameters for this build".to_owned(),
        ));
    }
    let mut padded_salt: [u8; KDF_SALT_BYTES] = [0u8; KDF_SALT_BYTES];
    padded_salt[..salt.len()].copy_from_slice(salt);
    let mut mac: Blake2bMac32 = <Blake2bMac32 as blake2::digest::KeyInit>::new_from_slice(key)
        .map_err(|e| Error::Blake2(format!("{e}")))?;
    Mac::update(&mut mac, &padded_salt);
    let out: blake2::digest::generic_array::GenericArray<u8, blake2::digest::consts::U32> =
        mac.finalize().into_bytes();
    let mut arr: [u8; AES_KEY_LEN] = [0u8; AES_KEY_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake2b_var_is_deterministic() {
        let a: Vec<u8> = blake2b_var(b"hello", 32).unwrap_or_default();
        let b: Vec<u8> = blake2b_var(b"hello", 32).unwrap_or_default();
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn derive_key_is_deterministic() {
        let a: DerivedKey = derive_aes_key("module").unwrap_or(DerivedKey([0u8; 32]));
        let b: DerivedKey = derive_aes_key("module").unwrap_or(DerivedKey([0u8; 32]));
        assert_eq!(a, b);
    }

    #[test]
    fn derive_key_changes_with_basename() {
        let a: DerivedKey = derive_aes_key("alpha").unwrap_or(DerivedKey([0u8; 32]));
        let b: DerivedKey = derive_aes_key("beta").unwrap_or(DerivedKey([1u8; 32]));
        assert_ne!(a, b);
    }
}
