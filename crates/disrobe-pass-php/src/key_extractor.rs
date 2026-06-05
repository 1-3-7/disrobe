use crate::encoder::EncoderFamily;
use memchr::memmem;
use serde::{Deserialize, Serialize};

/// How a recovered (or unrecovered) decryption key relates to its envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyProvenance {
    /// The key (or enough of it to decrypt) is embedded in the envelope and was recovered.
    StaticEmbedded,
    /// The envelope embeds an asymmetric blob, but the symmetric key is derived at load time.
    LoaderDerivedRsa,
    /// The key is derived at runtime from a license / handshake; nothing static to recover.
    RuntimeDerived,
}

/// The outcome of scanning an encoder envelope for statically recoverable key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyScan {
    pub family: EncoderFamily,
    pub provenance: KeyProvenance,
    /// Recovered key bytes when [`KeyProvenance::StaticEmbedded`]; empty otherwise.
    pub key: Vec<u8>,
    /// Offset of the key material or asymmetric blob, when located.
    pub key_offset: Option<usize>,
    /// Human-facing note describing what was (or was not) recoverable and why.
    pub note: &'static str,
}

/// AES forward S-box, transcribed from FIPS-197.
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

/// First eight AES key-schedule round constants (`Rcon`), from FIPS-197.
const AES_RCON: [u8; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];

/// PEM / DER markers that flag an embedded asymmetric public-key blob (ionCube licensing).
const RSA_MARKERS: &[&[u8]] = &[
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
    b"\x30\x82",
    b"ssl-key",
];

/// Zend Guard legacy XOR-key length in the payload header.
const ZG_XOR_KEY_LEN: usize = 8;

/// Scans an encoder envelope for statically recoverable key material, dispatching by family.
#[must_use]
pub fn scan(bytes: &[u8], family: EncoderFamily) -> KeyScan {
    match family {
        EncoderFamily::IonCube => scan_ioncube(bytes),
        EncoderFamily::SourceGuardian => scan_sourceguardian(bytes),
        EncoderFamily::ZendGuard => scan_zend_guard(bytes),
    }
}

fn scan_ioncube(bytes: &[u8]) -> KeyScan {
    let blob_offset: Option<usize> = RSA_MARKERS
        .iter()
        .filter_map(|m: &&[u8]| memmem::find(bytes, m))
        .min();
    KeyScan {
        family: EncoderFamily::IonCube,
        provenance: KeyProvenance::LoaderDerivedRsa,
        key: Vec::new(),
        key_offset: blob_offset,
        note: "ionCube derives the symmetric key inside the closed loader via an RSA/license handshake; only the asymmetric blob is static. No symmetric key is recoverable from the file alone.",
    }
}

fn scan_sourceguardian(bytes: &[u8]) -> KeyScan {
    let sbox_offset: Option<usize> = memmem::find(bytes, &AES_SBOX);
    let has_rcon: bool = memmem::find(bytes, &AES_RCON).is_some();
    let note: &'static str = if sbox_offset.is_some() && has_rcon {
        "SourceGuardian embeds an AES S-box and key schedule; the AES round pipeline is located, but the session key is derived at runtime, so no static key is recovered."
    } else if sbox_offset.is_some() {
        "SourceGuardian AES S-box located (decrypt-only table); session key is runtime-derived and not statically recoverable."
    } else {
        "No embedded AES round table located; SourceGuardian session keys are runtime-derived and not statically recoverable."
    };
    KeyScan {
        family: EncoderFamily::SourceGuardian,
        provenance: KeyProvenance::RuntimeDerived,
        key: Vec::new(),
        key_offset: sbox_offset,
        note,
    }
}

fn scan_zend_guard(bytes: &[u8]) -> KeyScan {
    if let Some((offset, key_bytes)) = recover_zend_guard_xor_key(bytes) {
        return KeyScan {
            family: EncoderFamily::ZendGuard,
            provenance: KeyProvenance::StaticEmbedded,
            key: key_bytes,
            key_offset: Some(offset),
            note: "Zend Guard legacy build: payload XOR key recovered from the fixed header offset past the @Zend; banner.",
        };
    }
    KeyScan {
        family: EncoderFamily::ZendGuard,
        provenance: KeyProvenance::RuntimeDerived,
        key: Vec::new(),
        key_offset: None,
        note: "Zend Guard envelope present but no static XOR header recognized; modern builds gate behind runtime-derived keys.",
    }
}

/// Recovers a legacy Zend Guard payload XOR key from the documented header slot.
fn recover_zend_guard_xor_key(bytes: &[u8]) -> Option<(usize, Vec<u8>)> {
    const BANNER: &[u8] = b"<?php @Zend;\n";
    let banner_at: usize = memmem::find(bytes, BANNER)?;
    let version_at: usize = banner_at.checked_add(BANNER.len())?;
    let version: u8 = *bytes.get(version_at)?;
    if !matches!(version, b'2' | b'3' | b'4') {
        return None;
    }
    let key_start: usize = version_at.checked_add(2)?;
    let key_end: usize = key_start.checked_add(ZG_XOR_KEY_LEN)?;
    let region: &[u8] = bytes.get(key_start..key_end)?;
    if region.iter().all(|b: &u8| *b == 0) {
        return None;
    }
    Some((key_start, region.to_vec()))
}

/// Decrypts a Zend Guard legacy payload by repeating-key XOR with a recovered key.
#[must_use]
pub fn xor_decrypt(ciphertext: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return ciphertext.to_vec();
    }
    ciphertext
        .iter()
        .enumerate()
        .map(|(i, b): (usize, &u8)| b ^ key[i % key.len()])
        .collect()
}

/// Result of attempting AES-CBC decryption with a caller-supplied key and IV.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AesOutcome {
    /// Decryption succeeded and padding validated.
    Plaintext(Vec<u8>),
    /// The key/IV did not produce valid PKCS7 padding (wrong key, or not AES-CBC).
    PaddingError,
    /// Inputs were structurally invalid (bad key/IV length, or ciphertext not block-aligned).
    BadInput,
}

/// Decrypts an AES-CBC blob with a caller-supplied 16/24/32-byte key and 16-byte IV.
#[must_use]
pub fn aes_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> AesOutcome {
    use cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

    if iv.len() != 16 || ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
        return AesOutcome::BadInput;
    }
    let mut buf: Vec<u8> = ciphertext.to_vec();
    let plaintext: Option<Result<Vec<u8>, ()>> = match key.len() {
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .ok()
            .map(|d: cbc::Decryptor<aes::Aes128>| {
                d.decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map(<[u8]>::to_vec)
                    .map_err(drop)
            }),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv)
            .ok()
            .map(|d: cbc::Decryptor<aes::Aes192>| {
                d.decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map(<[u8]>::to_vec)
                    .map_err(drop)
            }),
        32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .ok()
            .map(|d: cbc::Decryptor<aes::Aes256>| {
                d.decrypt_padded_mut::<Pkcs7>(&mut buf)
                    .map(<[u8]>::to_vec)
                    .map_err(drop)
            }),
        _ => return AesOutcome::BadInput,
    };
    match plaintext {
        Some(Ok(plain)) => AesOutcome::Plaintext(plain),
        Some(Err(())) => AesOutcome::PaddingError,
        None => AesOutcome::BadInput,
    }
}
