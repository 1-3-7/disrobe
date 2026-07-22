use aes::Aes256;
use ctr::Ctr128BE;
use ctr::cipher::{KeyIvInit, StreamCipher};

use crate::codec::{basename_of, decode_armored_line, hex_encode, strip_extension};
use crate::error::{Error, Result};
use crate::kdf::{AES_IV_LEN, AES_KEY_LEN, DerivedKey, derive_aes_key, validate_filename};

pub const PYE_BEGIN_MARKER: &str = "BEGIN SOURCEDEFENDER FILE";
pub const PYE_END_MARKER: &str = "END SOURCEDEFENDER FILE";
pub(crate) const PYE_ALT_BEGIN_MARKER: &str = "BEGIN PYE FILE";
pub(crate) const PYE_ALT_END_MARKER: &str = "END PYE FILE";
const MAX_PYE_FRAME_LINES: usize = 32_768;
const MAX_PYE_ARMORED_CIPHERTEXT_CHARS: usize = 96 * 1024 * 1024;
const MAX_PYE_FRAME_TEXT_BYTES: usize = MAX_PYE_ARMORED_CIPHERTEXT_CHARS + 64 * 1024;
const MAX_MSGPACK_ENVELOPE_BYTES: usize = 64 * 1024 * 1024;
const MAX_MSGPACK_CONTAINER_ITEMS: usize = 4096;
const MAX_MSGPACK_STRING_BYTES: usize = 32 * 1024 * 1024;
const MAX_MSGPACK_BINARY_BYTES: usize = 64 * 1024 * 1024;
const MAX_MSGPACK_DEPTH: usize = 64;

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
    validate_filename(filename)?;
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
    validate_filename(filename)?;
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
fn line_has_marker(line: &str, primary: &str, alternate: &str) -> bool {
    line.contains(primary) || line.contains(alternate)
}

#[inline]
pub fn parse_pye_frame(text: &str) -> Result<PyeFrame> {
    if text.len() > MAX_PYE_FRAME_TEXT_BYTES {
        return Err(Error::InputLimit {
            surface: "pye frame text",
            observed: text.len(),
            limit: MAX_PYE_FRAME_TEXT_BYTES,
        });
    }
    let mut lines = text.lines().map(str::trim).filter(|l: &&str| !l.is_empty());
    let Some(first): Option<&str> = lines.next() else {
        return Err(Error::NotPye);
    };
    if !line_has_marker(first, PYE_BEGIN_MARKER, PYE_ALT_BEGIN_MARKER) {
        return Err(Error::NotPye);
    }
    let Some(iv_line): Option<&str> = lines.next() else {
        return Err(Error::NotPye);
    };
    let mut line_count: usize = 2;
    let mut pending: Option<&str> = None;
    let mut joined: String = String::new();
    for line in lines {
        line_count = line_count.checked_add(1).ok_or_else(|| Error::Base85 {
            field: "frame".to_owned(),
            message: "line count overflow".to_owned(),
        })?;
        if line_count > MAX_PYE_FRAME_LINES {
            return Err(Error::Base85 {
                field: "frame".to_owned(),
                message: format!("line count exceeds cap {MAX_PYE_FRAME_LINES}"),
            });
        }
        if let Some(previous) = pending.replace(line) {
            let next_len: usize =
                joined
                    .len()
                    .checked_add(previous.len())
                    .ok_or_else(|| Error::Base85 {
                        field: "frame".to_owned(),
                        message: "ciphertext armor length overflow".to_owned(),
                    })?;
            if next_len > MAX_PYE_ARMORED_CIPHERTEXT_CHARS {
                return Err(Error::Base85 {
                    field: "frame".to_owned(),
                    message: format!(
                        "ciphertext armor length exceeds cap {MAX_PYE_ARMORED_CIPHERTEXT_CHARS}"
                    ),
                });
            }
            joined.push_str(previous);
        }
    }
    let Some(last): Option<&str> = pending else {
        return Err(Error::NotPye);
    };
    if !line_has_marker(last, PYE_END_MARKER, PYE_ALT_END_MARKER) || joined.is_empty() {
        return Err(Error::NotPye);
    }
    let iv_bytes: Vec<u8> = decode_armored_line(iv_line.as_bytes()).map_err(|e| match e {
        Error::Base85 { message, .. } => Error::Base85 {
            field: "iv".to_owned(),
            message,
        },
        other => other,
    })?;
    if iv_bytes.len() != AES_IV_LEN {
        return Err(Error::BadIv(iv_bytes.len()));
    }
    let ciphertext: Vec<u8> = decode_armored_line(joined.as_bytes()).map_err(|e| match e {
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
    validate_msgpack_bounds(bytes)?;
    let mut cursor: std::io::Cursor<&[u8]> = std::io::Cursor::new(bytes);
    let value: rmpv::Value = rmpv::decode::read_value(&mut cursor)
        .map_err(|e| Error::Msgpack(format!("decode failed: {e}")))?;
    ensure_msgpack_consumed(cursor.position(), bytes.len())?;
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
                    let Some(v_i64): Option<i64> = i.as_i64() else {
                        return Err(Error::Msgpack(format!("{name} does not fit i64")));
                    };
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

pub(crate) fn validate_msgpack_bounds(bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_MSGPACK_ENVELOPE_BYTES {
        return Err(Error::Msgpack(format!(
            "envelope length {} exceeds cap {MAX_MSGPACK_ENVELOPE_BYTES}",
            bytes.len()
        )));
    }
    let mut cursor: MsgpackBoundsCursor<'_> = MsgpackBoundsCursor { bytes, pos: 0 };
    cursor.value(0)?;
    if cursor.pos != bytes.len() {
        return Err(Error::Msgpack(
            "trailing bytes after msgpack value".to_owned(),
        ));
    }
    Ok(())
}

fn ensure_msgpack_consumed(position: u64, input_len: usize) -> Result<()> {
    let expected: u64 = u64::try_from(input_len)
        .map_err(|_| Error::Msgpack("input length exceeds u64".to_owned()))?;
    if position != expected {
        return Err(Error::Msgpack(
            "trailing bytes after msgpack value".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Debug)]
struct MsgpackBoundsCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl MsgpackBoundsCursor<'_> {
    fn value(&mut self, depth: usize) -> Result<()> {
        if depth > MAX_MSGPACK_DEPTH {
            return Err(Error::Msgpack(format!(
                "msgpack nesting exceeds cap {MAX_MSGPACK_DEPTH}"
            )));
        }
        let marker: u8 = self.take_u8()?;
        match marker {
            0x00..=0x7f | 0xc0 | 0xc2 | 0xc3 | 0xe0..=0xff => Ok(()),
            0x80..=0x8f => self.map(usize::from(marker & 0x0f), depth),
            0x90..=0x9f => self.array(usize::from(marker & 0x0f), depth),
            0xa0..=0xbf => self.skip_str(usize::from(marker & 0x1f)),
            0xc4 => {
                let len: usize = usize::from(self.take_u8()?);
                self.skip_bin(len)
            }
            0xc5 => {
                let len: usize = usize::from(self.take_u16()?);
                self.skip_bin(len)
            }
            0xc6 => {
                let len: usize = self.take_u32_as_usize()?;
                self.skip_bin(len)
            }
            0xc7 => {
                let len: usize = usize::from(self.take_u8()?);
                self.skip_ext(len)
            }
            0xc8 => {
                let len: usize = usize::from(self.take_u16()?);
                self.skip_ext(len)
            }
            0xc9 => {
                let len: usize = self.take_u32_as_usize()?;
                self.skip_ext(len)
            }
            0xca => self.skip(4, "float32"),
            0xcb => self.skip(8, "float64"),
            0xcc | 0xd0 => self.skip(1, "int8"),
            0xcd | 0xd1 => self.skip(2, "int16"),
            0xce | 0xd2 => self.skip(4, "int32"),
            0xcf | 0xd3 => self.skip(8, "int64"),
            0xd4 => self.skip_ext(1),
            0xd5 => self.skip_ext(2),
            0xd6 => self.skip_ext(4),
            0xd7 => self.skip_ext(8),
            0xd8 => self.skip_ext(16),
            0xd9 => {
                let len: usize = usize::from(self.take_u8()?);
                self.skip_str(len)
            }
            0xda => {
                let len: usize = usize::from(self.take_u16()?);
                self.skip_str(len)
            }
            0xdb => {
                let len: usize = self.take_u32_as_usize()?;
                self.skip_str(len)
            }
            0xdc => {
                let count: usize = usize::from(self.take_u16()?);
                self.array(count, depth)
            }
            0xdd => {
                let count: usize = self.take_u32_as_usize()?;
                self.array(count, depth)
            }
            0xde => {
                let count: usize = usize::from(self.take_u16()?);
                self.map(count, depth)
            }
            0xdf => {
                let count: usize = self.take_u32_as_usize()?;
                self.map(count, depth)
            }
            _ => Err(Error::Msgpack(format!(
                "unsupported msgpack marker 0x{marker:02x}"
            ))),
        }
    }

    fn array(&mut self, count: usize, depth: usize) -> Result<()> {
        Self::check_container_count(count)?;
        let next_depth: usize = depth
            .checked_add(1)
            .ok_or_else(|| Error::Msgpack("msgpack nesting depth overflow".to_owned()))?;
        for _ in 0..count {
            self.value(next_depth)?;
        }
        Ok(())
    }

    fn map(&mut self, count: usize, depth: usize) -> Result<()> {
        Self::check_container_count(count)?;
        let next_depth: usize = depth
            .checked_add(1)
            .ok_or_else(|| Error::Msgpack("msgpack nesting depth overflow".to_owned()))?;
        for _ in 0..count {
            self.value(next_depth)?;
            self.value(next_depth)?;
        }
        Ok(())
    }

    fn check_container_count(count: usize) -> Result<()> {
        if count > MAX_MSGPACK_CONTAINER_ITEMS {
            return Err(Error::Msgpack(format!(
                "container count {count} exceeds cap {MAX_MSGPACK_CONTAINER_ITEMS}"
            )));
        }
        Ok(())
    }

    fn skip_str(&mut self, len: usize) -> Result<()> {
        if len > MAX_MSGPACK_STRING_BYTES {
            return Err(Error::Msgpack(format!(
                "string length {len} exceeds cap {MAX_MSGPACK_STRING_BYTES}"
            )));
        }
        self.skip(len, "string")
    }

    fn skip_bin(&mut self, len: usize) -> Result<()> {
        if len > MAX_MSGPACK_BINARY_BYTES {
            return Err(Error::Msgpack(format!(
                "binary length {len} exceeds cap {MAX_MSGPACK_BINARY_BYTES}"
            )));
        }
        self.skip(len, "binary")
    }

    fn skip_ext(&mut self, len: usize) -> Result<()> {
        if len > MAX_MSGPACK_BINARY_BYTES {
            return Err(Error::Msgpack(format!(
                "extension length {len} exceeds cap {MAX_MSGPACK_BINARY_BYTES}"
            )));
        }
        self.skip(1, "extension type")?;
        self.skip(len, "extension payload")
    }

    fn skip(&mut self, len: usize, label: &str) -> Result<()> {
        let end: usize = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::Msgpack(format!("{label} length overflow")))?;
        if end > self.bytes.len() {
            return Err(Error::Msgpack(format!(
                "{label} length {len} exceeds remaining input"
            )));
        }
        self.pos = end;
        Ok(())
    }

    fn take_u8(&mut self) -> Result<u8> {
        let Some(value): Option<&u8> = self.bytes.get(self.pos) else {
            return Err(Error::Msgpack("truncated msgpack envelope".to_owned()));
        };
        self.pos = self
            .pos
            .checked_add(1)
            .ok_or_else(|| Error::Msgpack("msgpack position overflow".to_owned()))?;
        Ok(*value)
    }

    fn take_u16(&mut self) -> Result<u16> {
        let raw: [u8; 2] = self
            .take_exact(2)?
            .try_into()
            .map_err(|_| Error::Msgpack("invalid msgpack u16 length".to_owned()))?;
        Ok(u16::from_be_bytes(raw))
    }

    fn take_u32_as_usize(&mut self) -> Result<usize> {
        let raw: [u8; 4] = self
            .take_exact(4)?
            .try_into()
            .map_err(|_| Error::Msgpack("invalid msgpack u32 length".to_owned()))?;
        let value: u32 = u32::from_be_bytes(raw);
        usize::try_from(value).map_err(|_| Error::Msgpack("u32 length exceeds usize".to_owned()))
    }

    fn take_exact(&mut self, len: usize) -> Result<&[u8]> {
        let end: usize = self
            .pos
            .checked_add(len)
            .ok_or_else(|| Error::Msgpack("msgpack length overflow".to_owned()))?;
        let Some(raw): Option<&[u8]> = self.bytes.get(self.pos..end) else {
            return Err(Error::Msgpack("truncated msgpack envelope".to_owned()));
        };
        self.pos = end;
        Ok(raw)
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

    #[test]
    fn msgpack_map_declared_count_over_cap_rejects_before_decode() {
        let mut bytes: Vec<u8> = vec![0xdf];
        bytes.extend_from_slice(&4097u32.to_be_bytes());
        let result: Result<PyeEnvelope> = parse_msgpack_envelope(&bytes);
        assert!(result.is_err(), "oversized map declaration must fail");
        let Err(err): Result<PyeEnvelope> = result else {
            return;
        };
        assert!(matches!(err, Error::Msgpack(msg) if msg.contains("container count")));
    }

    #[test]
    fn pye_frame_rejects_line_flood_before_join() {
        let mut text: String =
            String::from("-----BEGIN SOURCEDEFENDER FILE-----\nGhOt7h7Jm.?sE?I;!%a(cCM6@0X(^n\n");
        for _ in 0..70_000 {
            text.push_str("00000\n");
        }
        text.push_str("-----END SOURCEDEFENDER FILE-----\n");

        let result: Result<PyeFrame> = parse_pye_frame(&text);

        assert!(matches!(
            result,
            Err(Error::Base85 { field, message })
                if field == "frame" && message.contains("line count")
        ));
    }
}
