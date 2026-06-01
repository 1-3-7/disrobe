use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::codec::{base85_decode_rfc1924, basename_of, hex_encode, strip_extension};
use crate::error::{Error, Result};
use crate::kdf::{AES_IV_LEN, AES_KEY_LEN, DerivedKey, derive_aes_key};

pub const PYE_BEGIN_MARKER: &str = "BEGIN PYE FILE";
pub const PYE_END_MARKER: &str = "END PYE FILE";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptedPye {
    pub filename: String,
    pub key_hex: String,
    pub iv_hex: String,
    pub plaintext_msgpack: Vec<u8>,
    pub envelope: Option<PyeEnvelope>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyeEnvelope {
    pub original_code: PyeCodePayload,
    pub deadline: Option<i64>,
    pub eol: Option<i64>,
    pub other_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PyeCodePayload {
    Source(String),
    MarshalledBytes(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PyeFrame {
    pub iv: [u8; AES_IV_LEN],
    pub ciphertext: Vec<u8>,
}

#[inline]
pub fn decrypt_pye(input: &[u8], filename: &str) -> Result<DecryptedPye> {
    if filename.is_empty() {
        return Err(Error::EmptyFilename);
    }
    let basename: &str = strip_extension(basename_of(filename));
    let key: DerivedKey = derive_aes_key(basename)?;
    let text: &str = core::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let frame: PyeFrame = parse_pye_frame(text)?;
    Ok(decrypt_frame(&frame, &key, filename))
}

#[inline]
pub fn decrypt_pye_with_key(
    input: &[u8],
    filename: &str,
    key: &DerivedKey,
) -> Result<DecryptedPye> {
    if filename.is_empty() {
        return Err(Error::EmptyFilename);
    }
    let text: &str = core::str::from_utf8(input).map_err(|_| Error::NotUtf8)?;
    let frame: PyeFrame = parse_pye_frame(text)?;
    Ok(decrypt_frame(&frame, key, filename))
}

#[inline]
#[must_use]
pub fn decrypt_frame(frame: &PyeFrame, key: &DerivedKey, filename: &str) -> DecryptedPye {
    let mut buf: Vec<u8> = frame.ciphertext.clone();
    apply_aes_ctr(&mut buf, key.as_bytes(), &frame.iv);
    let envelope: Option<PyeEnvelope> = parse_msgpack_envelope(&buf).ok();
    DecryptedPye {
        filename: filename.to_owned(),
        key_hex: hex_encode(key.as_bytes()),
        iv_hex: hex_encode(&frame.iv),
        plaintext_msgpack: buf,
        envelope,
    }
}

#[inline]
pub fn apply_aes_ctr(buf: &mut [u8], key: &[u8; AES_KEY_LEN], iv: &[u8; AES_IV_LEN]) {
    let mut cipher: Ctr128BE<Aes256> = Ctr128BE::<Aes256>::new(key.into(), iv.into());
    cipher.apply_keystream(buf);
}

#[inline]
pub fn parse_pye_frame(text: &str) -> Result<PyeFrame> {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    if lines.len() < 4 {
        return Err(Error::NotPye);
    }
    let first: &str = lines.first().copied().unwrap_or_default();
    let last: &str = lines.last().copied().unwrap_or_default();
    if !first.contains(PYE_BEGIN_MARKER) || !last.contains(PYE_END_MARKER) {
        return Err(Error::NotPye);
    }
    let iv_line: &str = lines.get(1).copied().unwrap_or_default();
    let ciphertext_lines: &[&str] = &lines[2..lines.len() - 1];
    let iv_bytes: Vec<u8> = base85_decode_rfc1924(iv_line.as_bytes()).map_err(|e| match e {
        Error::Base85 { message, .. } => Error::Base85 {
            field: "iv".to_owned(),
            message,
        },
        other => other,
    })?;
    if iv_bytes.len() != AES_IV_LEN {
        return Err(Error::BadIv(iv_bytes.len()));
    }
    let mut joined: String = String::with_capacity(ciphertext_lines.iter().map(|s| s.len()).sum());
    for line in ciphertext_lines {
        joined.push_str(line);
    }
    let ciphertext: Vec<u8> = base85_decode_rfc1924(joined.as_bytes()).map_err(|e| match e {
        Error::Base85 { message, .. } => Error::Base85 {
            field: "ciphertext".to_owned(),
            message,
        },
        other => other,
    })?;
    let mut iv: [u8; AES_IV_LEN] = [0u8; AES_IV_LEN];
    iv.copy_from_slice(&iv_bytes);
    Ok(PyeFrame { iv, ciphertext })
}

#[inline]
pub fn parse_msgpack_envelope(bytes: &[u8]) -> Result<PyeEnvelope> {
    let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let value: rmpv::Value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e| Error::Msgpack(format!("decode failed: {e}")))?;
    let rmpv::Value::Map(map) = value else {
        return Err(Error::Msgpack("root is not a map".to_owned()));
    };
    let mut original_code: Option<PyeCodePayload> = None;
    let mut deadline: Option<i64> = None;
    let mut eol: Option<i64> = None;
    let mut other_fields: Vec<String> = Vec::new();
    for (k, v) in map {
        let key_str: Option<String> = value_to_str(&k);
        match key_str.as_deref() {
            Some("original_code" | "code") => match v {
                rmpv::Value::String(s) => {
                    if let Some(plain) = s.as_str() {
                        original_code = Some(PyeCodePayload::Source(plain.to_owned()));
                    } else {
                        original_code = Some(PyeCodePayload::MarshalledBytes(s.into_bytes()));
                    }
                }
                rmpv::Value::Binary(b) => {
                    original_code = Some(PyeCodePayload::MarshalledBytes(b));
                }
                other => other_fields.push(format!("original_code:{other:?}")),
            },
            Some(name @ ("deadline" | "eol")) => {
                if let rmpv::Value::Integer(i) = v {
                    let v_i64: i64 = i.as_i64().unwrap_or(0);
                    if name == "deadline" {
                        deadline = Some(v_i64);
                    } else {
                        eol = Some(v_i64);
                    }
                }
            }
            Some(name) => other_fields.push(name.to_owned()),
            None => other_fields.push(format!("non_string_key:{k:?}")),
        }
    }
    let original_code: PyeCodePayload =
        original_code.ok_or_else(|| Error::Msgpack("map missing original_code".to_owned()))?;
    Ok(PyeEnvelope {
        original_code,
        deadline,
        eol,
        other_fields,
    })
}

#[inline]
fn value_to_str(v: &rmpv::Value) -> Option<String> {
    match v {
        rmpv::Value::String(s) => s.as_str().map(ToOwned::to_owned),
        rmpv::Value::Binary(b) => core::str::from_utf8(b).ok().map(ToOwned::to_owned),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_filename() {
        let r: Result<DecryptedPye> =
            decrypt_pye(b"---BEGIN PYE FILE---\niv\nct\n---END PYE FILE---", "");
        assert!(matches!(r, Err(Error::EmptyFilename)));
    }

    #[test]
    fn rejects_missing_markers() {
        let r: Result<DecryptedPye> = decrypt_pye(b"no markers here", "module.pye");
        assert!(matches!(r, Err(Error::NotPye)));
    }

    #[test]
    fn rejects_non_utf8() {
        let r: Result<DecryptedPye> = decrypt_pye(&[0xff, 0xfe, 0xfd, 0xfc], "module.pye");
        assert!(matches!(r, Err(Error::NotUtf8)));
    }

    #[test]
    fn rejects_short_input() {
        let r: Result<DecryptedPye> =
            decrypt_pye(b"---BEGIN PYE FILE---\n---END PYE FILE---", "module.pye");
        assert!(matches!(r, Err(Error::NotPye)));
    }
}
