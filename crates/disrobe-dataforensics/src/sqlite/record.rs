use serde::Serialize;

use super::format::{TextEncoding, varint};

const MAX_COLUMNS: usize = 32_767;
const MAX_INLINE_TEXT: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "kebab-case")]
pub enum SqlValue {
    Null,
    Integer(i64),
    Real(f64),
    Text(String),
    Blob(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SerialType {
    Null,
    Int(usize),
    Real,
    Zero,
    One,
    Blob(usize),
    Text(usize),
}

impl SerialType {
    pub(super) fn from_code(code: u64) -> Option<Self> {
        Some(match code {
            0 => Self::Null,
            1 => Self::Int(1),
            2 => Self::Int(2),
            3 => Self::Int(3),
            4 => Self::Int(4),
            5 => Self::Int(6),
            6 => Self::Int(8),
            7 => Self::Real,
            8 => Self::Zero,
            9 => Self::One,
            10 | 11 => return None,
            n if n % 2 == 0 => Self::Blob(usize::try_from((n - 12) / 2).ok()?),
            n => Self::Text(usize::try_from((n - 13) / 2).ok()?),
        })
    }

    pub(super) const fn size(self) -> usize {
        match self {
            Self::Null | Self::Zero | Self::One => 0,
            Self::Int(width) => width,
            Self::Real => 8,
            Self::Blob(len) | Self::Text(len) => len,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct RecordHeader {
    pub(super) header_len: usize,
    pub(super) types: Vec<SerialType>,
    pub(super) body_len: usize,
}

pub(super) fn parse_header(payload: &[u8], max_columns: usize) -> Option<RecordHeader> {
    let (header_len, first): (u64, usize) = varint(payload)?;
    let header_len: usize = usize::try_from(header_len).ok()?;
    if header_len < first || header_len > payload.len() {
        return None;
    }
    let header: &[u8] = payload.get(..header_len)?;
    let mut types: Vec<SerialType> = Vec::new();
    let mut at: usize = first;
    let mut body_len: usize = 0;
    while at < header_len {
        let (code, used): (u64, usize) = varint(header.get(at..)?)?;
        at += used;
        let serial: SerialType = SerialType::from_code(code)?;
        body_len = body_len.checked_add(serial.size())?;
        types.push(serial);
        if types.len() > max_columns.min(MAX_COLUMNS) {
            return None;
        }
    }
    (at == header_len).then_some(RecordHeader {
        header_len,
        types,
        body_len,
    })
}

pub(super) fn decode_record(
    payload: &[u8],
    encoding: TextEncoding,
    max_columns: usize,
) -> Option<Vec<SqlValue>> {
    let header: RecordHeader = parse_header(payload, max_columns)?;
    if header.header_len.checked_add(header.body_len)? > payload.len() {
        return None;
    }
    decode_body(&payload[header.header_len..], &header.types, encoding)
}

pub(super) fn decode_body(
    body: &[u8],
    types: &[SerialType],
    encoding: TextEncoding,
) -> Option<Vec<SqlValue>> {
    let mut values: Vec<SqlValue> = Vec::with_capacity(types.len());
    let mut at: usize = 0;
    for serial in types {
        let size: usize = serial.size();
        let field: &[u8] = body.get(at..at.checked_add(size)?)?;
        at += size;
        values.push(match serial {
            SerialType::Null => SqlValue::Null,
            SerialType::Zero => SqlValue::Integer(0),
            SerialType::One => SqlValue::Integer(1),
            SerialType::Int(_) => SqlValue::Integer(signed_be(field)),
            SerialType::Real => {
                let raw: [u8; 8] = <[u8; 8]>::try_from(field).ok()?;
                SqlValue::Real(f64::from_be_bytes(raw))
            }
            SerialType::Blob(_) => SqlValue::Blob(hex(field)),
            SerialType::Text(_) => SqlValue::Text(decode_text(field, encoding)?),
        });
    }
    Some(values)
}

fn signed_be(field: &[u8]) -> i64 {
    let mut value: i64 = if field.first().is_some_and(|b: &u8| b & 0x80 != 0) {
        -1
    } else {
        0
    };
    for byte in field {
        value = (value << 8) | i64::from(*byte);
    }
    value
}

fn decode_text(field: &[u8], encoding: TextEncoding) -> Option<String> {
    if field.len() > MAX_INLINE_TEXT {
        return None;
    }
    match encoding {
        TextEncoding::Utf8 => String::from_utf8(field.to_vec()).ok(),
        TextEncoding::Utf16le | TextEncoding::Utf16be => {
            if !field.len().is_multiple_of(2) {
                return None;
            }
            let units: Vec<u16> = field
                .chunks_exact(2)
                .map(|pair: &[u8]| {
                    let raw: [u8; 2] = [pair[0], pair[1]];
                    if encoding == TextEncoding::Utf16le {
                        u16::from_le_bytes(raw)
                    } else {
                        u16::from_be_bytes(raw)
                    }
                })
                .collect();
            String::from_utf16(&units).ok()
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_record_with_every_serial_class_decodes() {
        let payload: Vec<u8> = vec![
            0x08, 0x00, 0x01, 0x02, 0x07, 0x08, 0x09, 0x13, 0xff, 0xfe, 0x01, 0x40, 0x09, 0x21,
            0xfb, 0x54, 0x44, 0x2d, 0x18, b'a', b'b', b'c',
        ];
        let values: Vec<SqlValue> =
            decode_record(&payload, TextEncoding::Utf8, 64).expect("decodes");
        assert_eq!(
            values,
            vec![
                SqlValue::Null,
                SqlValue::Integer(-1),
                SqlValue::Integer(-511),
                SqlValue::Real(std::f64::consts::PI),
                SqlValue::Integer(0),
                SqlValue::Integer(1),
                SqlValue::Text("abc".to_owned()),
            ]
        );
    }

    #[test]
    fn reserved_serial_types_and_short_bodies_are_refused() {
        assert_eq!(decode_record(&[0x02, 0x0a], TextEncoding::Utf8, 8), None);
        assert_eq!(
            decode_record(&[0x02, 0x06, 0x00], TextEncoding::Utf8, 8),
            None
        );
        assert_eq!(decode_record(&[0x05, 0x00], TextEncoding::Utf8, 8), None);
    }
}
