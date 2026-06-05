use serde::{Deserialize, Serialize};

/// Tag-type nibble values from Hermes `SerializedLiteralGenerator` (`tag & 0x70`).
const TAG_MASK: u8 = 0x70;
const TAG_NULL_OR_PRIVATE_NAME: u8 = 0 << 4;
const TAG_TRUE: u8 = 1 << 4;
const TAG_FALSE: u8 = 2 << 4;
const TAG_NUMBER: u8 = 3 << 4;
const TAG_LONG_STRING: u8 = 4 << 4;
const TAG_SHORT_STRING: u8 = 5 << 4;
const TAG_UNDEFINED: u8 = 6 << 4;
const TAG_INTEGER: u8 = 7 << 4;

/// Upper bound on serialized-literal elements decoded from one buffer slice.
const MAX_DECODED_LITERALS: usize = 1 << 20;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind", content = "value")]
pub enum LiteralValue {
    Null,
    PrivateName,
    Undefined,
    Bool(bool),
    Number(f64),
    Integer(i32),
    StringId(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferKind {
    Key,
    Value,
}

/// Decodes `count` serialized literals from `buffer` per Hermes `SerializedLiteralParser::parseImpl`.
#[must_use]
pub fn decode_literals(
    buffer: &[u8],
    start: usize,
    count: usize,
    kind: BufferKind,
) -> Vec<LiteralValue> {
    let capped: usize = count.min(MAX_DECODED_LITERALS);
    let mut out: Vec<LiteralValue> = Vec::with_capacity(capped.min(buffer.len()));
    let mut idx: usize = start;
    let mut remaining: usize = count;
    while remaining > 0 && idx < buffer.len() && out.len() < MAX_DECODED_LITERALS {
        let tag: u8 = buffer[idx];
        idx += 1;
        let seq_len: usize = if tag & 0x80 != 0 {
            let Some(low): Option<&u8> = buffer.get(idx) else {
                break;
            };
            idx += 1;
            (((tag & 0x0f) as usize) << 8) | (*low as usize)
        } else {
            (tag & 0x0f) as usize
        };
        let to_read: usize = remaining.min(seq_len);
        remaining -= to_read;
        let ty: u8 = tag & TAG_MASK;
        for _ in 0..to_read {
            if out.len() >= MAX_DECODED_LITERALS {
                return out;
            }
            let value: LiteralValue = match decode_element(buffer, &mut idx, ty, kind) {
                Some(v) => v,
                None => return out,
            };
            out.push(value);
        }
    }
    out
}

#[must_use]
fn decode_element(
    buffer: &[u8],
    idx: &mut usize,
    ty: u8,
    kind: BufferKind,
) -> Option<LiteralValue> {
    match ty {
        TAG_NULL_OR_PRIVATE_NAME => Some(match kind {
            BufferKind::Key => LiteralValue::PrivateName,
            BufferKind::Value => LiteralValue::Null,
        }),
        TAG_TRUE => Some(LiteralValue::Bool(true)),
        TAG_FALSE => Some(LiteralValue::Bool(false)),
        TAG_UNDEFINED => Some(LiteralValue::Undefined),
        TAG_NUMBER => {
            let raw: [u8; 8] = read_n::<8>(buffer, idx)?;
            Some(LiteralValue::Number(f64::from_le_bytes(raw)))
        }
        TAG_INTEGER => {
            let raw: [u8; 4] = read_n::<4>(buffer, idx)?;
            Some(LiteralValue::Integer(i32::from_le_bytes(raw)))
        }
        TAG_LONG_STRING => {
            let raw: [u8; 4] = read_n::<4>(buffer, idx)?;
            Some(LiteralValue::StringId(u32::from_le_bytes(raw)))
        }
        TAG_SHORT_STRING => {
            let raw: [u8; 2] = read_n::<2>(buffer, idx)?;
            Some(LiteralValue::StringId(u16::from_le_bytes(raw) as u32))
        }
        _ => None,
    }
}

#[must_use]
fn read_n<const N: usize>(buffer: &[u8], idx: &mut usize) -> Option<[u8; N]> {
    let end: usize = idx.checked_add(N)?;
    if end > buffer.len() {
        return None;
    }
    let mut out: [u8; N] = [0u8; N];
    out.copy_from_slice(&buffer[*idx..end]);
    *idx = end;
    Some(out)
}

/// Renders a decoded value-buffer literal as a JavaScript value.
#[must_use]
pub fn render_value<F>(value: &LiteralValue, resolve_string: &F) -> String
where
    F: Fn(u32) -> String,
{
    match value {
        LiteralValue::Null => "null".to_owned(),
        LiteralValue::PrivateName => "#private".to_owned(),
        LiteralValue::Undefined => "undefined".to_owned(),
        LiteralValue::Bool(b) => b.to_string(),
        LiteralValue::Number(n) => render_number(*n),
        LiteralValue::Integer(i) => i.to_string(),
        LiteralValue::StringId(id) => resolve_string(*id),
    }
}

/// Renders a decoded key-buffer literal as an object property key.
#[must_use]
pub fn render_key<F>(value: &LiteralValue, resolve_ident: &F) -> String
where
    F: Fn(u32) -> String,
{
    match value {
        LiteralValue::StringId(id) => resolve_ident(*id),
        LiteralValue::Integer(i) => i.to_string(),
        LiteralValue::Number(n) => render_number(*n),
        LiteralValue::PrivateName | LiteralValue::Null => "#private".to_owned(),
        LiteralValue::Bool(b) => b.to_string(),
        LiteralValue::Undefined => "undefined".to_owned(),
    }
}

#[must_use]
fn render_number(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn put_short_string_run(buf: &mut Vec<u8>, ids: &[u16]) {
        assert!(ids.len() <= 0x0f);
        buf.push(TAG_SHORT_STRING | (ids.len() as u8));
        for id in ids {
            buf.extend_from_slice(&id.to_le_bytes());
        }
    }

    fn put_number_run(buf: &mut Vec<u8>, nums: &[f64]) {
        assert!(nums.len() <= 0x0f);
        buf.push(TAG_NUMBER | (nums.len() as u8));
        for n in nums {
            buf.extend_from_slice(&n.to_le_bytes());
        }
    }

    fn put_integer_run(buf: &mut Vec<u8>, ints: &[i32]) {
        buf.push(TAG_INTEGER | (ints.len() as u8));
        for i in ints {
            buf.extend_from_slice(&i.to_le_bytes());
        }
    }

    #[test]
    fn decode_short_string_keys() {
        let mut buf: Vec<u8> = Vec::new();
        put_short_string_run(&mut buf, &[3, 7]);
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, 2, BufferKind::Key);
        assert_eq!(
            out,
            vec![LiteralValue::StringId(3), LiteralValue::StringId(7)]
        );
    }

    #[test]
    fn decode_mixed_value_run() {
        let mut buf: Vec<u8> = Vec::new();
        put_number_run(&mut buf, &[1.5, 2.0]);
        put_integer_run(&mut buf, &[42]);
        buf.push(TAG_TRUE | 1);
        buf.push(TAG_NULL_OR_PRIVATE_NAME | 1);
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, 5, BufferKind::Value);
        assert_eq!(
            out,
            vec![
                LiteralValue::Number(1.5),
                LiteralValue::Number(2.0),
                LiteralValue::Integer(42),
                LiteralValue::Bool(true),
                LiteralValue::Null,
            ]
        );
    }

    #[test]
    fn null_tag_is_private_name_in_key_buffer() {
        let buf: Vec<u8> = vec![TAG_NULL_OR_PRIVATE_NAME | 1];
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, 1, BufferKind::Key);
        assert_eq!(out, vec![LiteralValue::PrivateName]);
    }

    #[test]
    fn long_run_uses_two_byte_length() {
        let mut buf: Vec<u8> = Vec::new();
        let count: usize = 20;
        buf.push(0x80 | TAG_INTEGER | (((count >> 8) & 0x0f) as u8));
        buf.push((count & 0xff) as u8);
        for i in 0..count {
            buf.extend_from_slice(&(i as i32).to_le_bytes());
        }
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, count, BufferKind::Value);
        assert_eq!(out.len(), count);
        assert_eq!(out[19], LiteralValue::Integer(19));
    }

    #[test]
    fn count_smaller_than_run_stops_early() {
        let mut buf: Vec<u8> = Vec::new();
        put_integer_run(&mut buf, &[1, 2, 3, 4, 5]);
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, 2, BufferKind::Value);
        assert_eq!(
            out,
            vec![LiteralValue::Integer(1), LiteralValue::Integer(2)]
        );
    }

    #[test]
    fn truncated_buffer_returns_partial_without_panic() {
        let mut buf: Vec<u8> = Vec::new();
        buf.push(TAG_NUMBER | 2);
        buf.extend_from_slice(&1.0f64.to_le_bytes());
        buf.extend_from_slice(&[0u8; 3]);
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, 2, BufferKind::Value);
        assert_eq!(out, vec![LiteralValue::Number(1.0)]);
    }

    #[test]
    fn forged_count_is_bounded() {
        let buf: Vec<u8> = vec![TAG_TRUE | 0x0f; 4];
        let out: Vec<LiteralValue> = decode_literals(&buf, 0, usize::MAX, BufferKind::Value);
        assert!(out.len() <= MAX_DECODED_LITERALS);
    }

    #[test]
    fn render_object_pair_round_trip() {
        let key: LiteralValue = LiteralValue::StringId(0);
        let val: LiteralValue = LiteralValue::Integer(7);
        let resolve_ident = |id: u32| format!("k{id}");
        let resolve_str = |id: u32| format!("\"s{id}\"");
        assert_eq!(render_key(&key, &resolve_ident), "k0");
        assert_eq!(render_value(&val, &resolve_str), "7");
    }
}
