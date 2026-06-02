use aes::Aes128;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::detect::Detection;
use crate::error::{Error, Result};
use crate::key::scan_v6v7_rdata_for_key;
use crate::runtime::RuntimeLocation;

#[derive(Debug, Clone)]
pub(crate) struct V6V7DecryptedPayload {
    pub(crate) key: [u8; 16],
    pub(crate) plaintext: Vec<u8>,
}

pub(crate) fn decrypt(
    payload: &[u8],
    detection: &Detection,
    runtime: &RuntimeLocation,
) -> Result<V6V7DecryptedPayload> {
    let runtime_bytes: Vec<u8> = std::fs::read(&runtime.path)?;
    let key: [u8; 16] = scan_v6v7_rdata_for_key(&runtime_bytes)?;

    let mut iv: [u8; 16] = [0u8; 16];
    iv[15] = 0x02;

    let offset: usize = detection.payload_offset_in_payload;
    let size: usize = detection.payload_size_in_payload;
    if offset + size > payload.len() {
        return Err(Error::HeaderTruncated {
            need: offset + size,
            got: payload.len(),
        });
    }
    let mut ciphertext: Vec<u8> = payload[offset..offset + size].to_vec();

    let mut cipher: Ctr128BE<Aes128> = Ctr128BE::<Aes128>::new(&key.into(), &iv.into());
    cipher.apply_keystream(&mut ciphertext);

    Ok(V6V7DecryptedPayload {
        key,
        plaintext: ciphertext,
    })
}
