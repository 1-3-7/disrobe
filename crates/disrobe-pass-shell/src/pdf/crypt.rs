use aes::Aes128;
use cbc::Decryptor;
use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, KeyIvInit};
use md5::{Digest, Md5};

use super::object::{EncryptionStatus, PdfDict, PdfDocument, PdfObject};

type Aes128CbcDec = Decryptor<Aes128>;

const PAD: [u8; 32] = [
    0x28, 0xBF, 0x4E, 0x5E, 0x4E, 0x75, 0x8A, 0x41, 0x64, 0x00, 0x4E, 0x56, 0xFF, 0xFA, 0x01, 0x08,
    0x2E, 0x2E, 0x00, 0xB6, 0xD0, 0x68, 0x3E, 0x80, 0x2F, 0x0C, 0xA9, 0xFE, 0x64, 0x53, 0x69, 0x7A,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Rc4,
    AesV2,
    Unsupported,
}

#[derive(Debug, Clone)]
pub struct Encryption {
    cipher: Cipher,
    file_key: Vec<u8>,
    encrypt_number: Option<u32>,
    encrypt_metadata: bool,
    handler: String,
}

impl Encryption {
    #[must_use]
    pub fn handler(&self) -> String {
        self.handler.clone()
    }

    #[must_use]
    pub const fn is_supported(&self) -> bool {
        !matches!(self.cipher, Cipher::Unsupported)
    }
}

#[must_use]
pub fn detect(doc: &PdfDocument) -> Option<Encryption> {
    let encrypt_ref: &PdfObject = doc.trailer.get(b"Encrypt")?;
    let encrypt_number: Option<u32> = encrypt_ref
        .as_reference()
        .map(|(number, _): (u32, u16)| number);
    let dict: PdfDict = doc.resolve(encrypt_ref).as_dict()?.clone();
    let filter: Option<&[u8]> = dict.get(b"Filter").and_then(PdfObject::as_name);
    if filter != Some(b"Standard") {
        return Some(Encryption {
            cipher: Cipher::Unsupported,
            file_key: Vec::new(),
            encrypt_number,
            encrypt_metadata: true,
            handler: filter.map_or_else(
                || "non-standard".to_owned(),
                |name: &[u8]| String::from_utf8_lossy(name).into_owned(),
            ),
        });
    }
    let version: i64 = dict.get(b"V").and_then(PdfObject::as_i64).unwrap_or(0);
    let revision: i64 = dict.get(b"R").and_then(PdfObject::as_i64).unwrap_or(0);
    let length_bits: i64 = dict
        .get(b"Length")
        .and_then(PdfObject::as_i64)
        .unwrap_or(40);
    let owner: &[u8] = dict.get(b"O").and_then(PdfObject::as_string)?;
    let permissions: i64 = dict.get(b"P").and_then(PdfObject::as_i64).unwrap_or(0);
    let encrypt_metadata: bool = dict
        .get(b"EncryptMetadata")
        .is_none_or(|obj: &PdfObject| !matches!(obj, PdfObject::Boolean(false)));
    let id0: Vec<u8> = doc
        .trailer
        .get(b"ID")
        .and_then(PdfObject::as_array)
        .and_then(|items: &[PdfObject]| items.first())
        .and_then(PdfObject::as_string)
        .map(<[u8]>::to_vec)
        .unwrap_or_default();
    if version >= 5 {
        return Some(Encryption {
            cipher: Cipher::Unsupported,
            file_key: Vec::new(),
            encrypt_number,
            encrypt_metadata,
            handler: format!("standard-v{version}-aesv3"),
        });
    }
    let cipher: Cipher = if version == 4 {
        crypt_filter_method(&dict)
    } else {
        Cipher::Rc4
    };
    let key_length: usize = if revision == 2 {
        5
    } else {
        (usize::try_from(length_bits).unwrap_or(40) / 8).clamp(5, 16)
    };
    let file_key: Vec<u8> = compute_file_key(
        owner,
        permissions,
        &id0,
        revision,
        key_length,
        encrypt_metadata,
    );
    let handler: String = match cipher {
        Cipher::Rc4 => format!("standard-v{version}-r{revision}-rc4"),
        Cipher::AesV2 => format!("standard-v{version}-r{revision}-aesv2"),
        Cipher::Unsupported => format!("standard-v{version}-r{revision}-unknown-cfm"),
    };
    Some(Encryption {
        cipher,
        file_key,
        encrypt_number,
        encrypt_metadata,
        handler,
    })
}

fn crypt_filter_method(dict: &PdfDict) -> Cipher {
    let Some(cf): Option<&PdfDict> = dict.get(b"CF").and_then(PdfObject::as_dict) else {
        return Cipher::Rc4;
    };
    let Some(std_cf): Option<&PdfDict> = cf.get(b"StdCF").and_then(PdfObject::as_dict) else {
        return Cipher::Rc4;
    };
    match std_cf.get(b"CFM").and_then(PdfObject::as_name) {
        Some(b"AESV2") => Cipher::AesV2,
        Some(b"V2" | b"Identity") | None => Cipher::Rc4,
        Some(_) => Cipher::Unsupported,
    }
}

fn compute_file_key(
    owner: &[u8],
    permissions: i64,
    id0: &[u8],
    revision: i64,
    key_length: usize,
    encrypt_metadata: bool,
) -> Vec<u8> {
    let mut hasher: Md5 = Md5::new();
    hasher.update(PAD);
    hasher.update(owner);
    let permissions32: u32 = (permissions as i32) as u32;
    hasher.update(permissions32.to_le_bytes());
    hasher.update(id0);
    if revision >= 4 && !encrypt_metadata {
        hasher.update([0xFF, 0xFF, 0xFF, 0xFF]);
    }
    let mut digest: [u8; 16] = hasher.finalize().into();
    if revision >= 3 {
        for _ in 0..50 {
            let mut round: Md5 = Md5::new();
            round.update(&digest[..key_length.min(16)]);
            digest = round.finalize().into();
        }
    }
    digest[..key_length.min(16)].to_vec()
}

fn object_key(file_key: &[u8], number: u32, generation: u16, aes: bool) -> Vec<u8> {
    let mut hasher: Md5 = Md5::new();
    hasher.update(file_key);
    hasher.update(&number.to_le_bytes()[..3]);
    hasher.update(&generation.to_le_bytes()[..2]);
    if aes {
        hasher.update(b"sAlT");
    }
    let digest: [u8; 16] = hasher.finalize().into();
    let length: usize = (file_key.len() + 5).min(16);
    digest[..length].to_vec()
}

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return data.to_vec();
    }
    let mut state: [u8; 256] = [0; 256];
    for (index, slot) in state.iter_mut().enumerate() {
        *slot = index as u8;
    }
    let mut j: u8 = 0;
    for index in 0..256 {
        j = j
            .wrapping_add(state[index])
            .wrapping_add(key[index % key.len()]);
        state.swap(index, usize::from(j));
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut a: u8 = 0;
    let mut b: u8 = 0;
    for &byte in data {
        a = a.wrapping_add(1);
        b = b.wrapping_add(state[usize::from(a)]);
        state.swap(usize::from(a), usize::from(b));
        let index: u8 = state[usize::from(a)].wrapping_add(state[usize::from(b)]);
        out.push(byte ^ state[usize::from(index)]);
    }
    out
}

fn aes_cbc_decrypt(key: &[u8], data: &[u8]) -> Vec<u8> {
    if key.len() != 16 || data.len() < 16 {
        return data.to_vec();
    }
    let (iv, cipher_text): (&[u8], &[u8]) = data.split_at(16);
    let usable: usize = cipher_text.len() - (cipher_text.len() % 16);
    if usable == 0 {
        return Vec::new();
    }
    let mut buffer: Vec<u8> = cipher_text[..usable].to_vec();
    let Ok(decryptor): Result<Aes128CbcDec, _> = Aes128CbcDec::new_from_slices(key, iv) else {
        return buffer;
    };
    match decryptor.decrypt_padded_mut::<Pkcs7>(&mut buffer) {
        Ok(plain) => plain.to_vec(),
        Err(_) => buffer,
    }
}

pub fn decrypt_document(doc: &mut PdfDocument, encryption: &Encryption) {
    if !encryption.is_supported() {
        doc.encryption = Some(EncryptionStatus {
            handler: encryption.handler(),
            decrypted: false,
        });
        return;
    }
    let numbers: Vec<u32> = doc.objects.keys().copied().collect();
    let aes: bool = matches!(encryption.cipher, Cipher::AesV2);
    for number in numbers {
        if Some(number) == encryption.encrypt_number {
            continue;
        }
        let Some((generation, object)): Option<&mut (u16, PdfObject)> =
            doc.objects.get_mut(&number)
        else {
            continue;
        };
        if is_unencrypted(object, encryption.encrypt_metadata) {
            continue;
        }
        let generation: u16 = *generation;
        let key: Vec<u8> = object_key(&encryption.file_key, number, generation, aes);
        decrypt_in_place(object, &key, aes);
    }
    doc.encryption = Some(EncryptionStatus {
        handler: encryption.handler(),
        decrypted: true,
    });
}

fn is_unencrypted(object: &PdfObject, encrypt_metadata: bool) -> bool {
    let Some(stream) = object.as_stream() else {
        return false;
    };
    match stream.dict.type_name() {
        Some(b"XRef") => true,
        Some(b"Metadata") => !encrypt_metadata,
        _ => false,
    }
}

fn decrypt_in_place(object: &mut PdfObject, key: &[u8], aes: bool) {
    match object {
        PdfObject::String(bytes) => {
            *bytes = decrypt_bytes(key, bytes, aes);
        }
        PdfObject::Array(items) => {
            for item in items {
                decrypt_in_place(item, key, aes);
            }
        }
        PdfObject::Dictionary(dict) => {
            for value in dict.values_mut() {
                decrypt_in_place(value, key, aes);
            }
        }
        PdfObject::Stream(stream) => {
            for value in stream.dict.values_mut() {
                decrypt_in_place(value, key, aes);
            }
            stream.raw = decrypt_bytes(key, &stream.raw, aes);
        }
        _ => {}
    }
}

fn decrypt_bytes(key: &[u8], data: &[u8], aes: bool) -> Vec<u8> {
    if aes {
        aes_cbc_decrypt(key, data)
    } else {
        rc4(key, data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_matches_published_vector() {
        let out: Vec<u8> = rc4(b"Key", b"Plaintext");
        assert_eq!(out, [0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3]);
    }

    #[test]
    fn rc4_is_involutive_with_same_key() {
        let cipher_text: Vec<u8> = rc4(b"secret", b"attack at dawn");
        assert_eq!(rc4(b"secret", &cipher_text), b"attack at dawn");
    }
}
