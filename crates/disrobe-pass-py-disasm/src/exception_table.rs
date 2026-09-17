use serde::Serialize;

const ENTRY_START_BIT: u8 = 0x80;
const CONTINUATION_BIT: u8 = 0x40;
const VARINT_DATA_MASK: u8 = 0x3F;
const VARINT_CHUNK_BITS: u32 = 6;
const FIELDS_PER_ENTRY: usize = 4;
const BYTECODE_UNIT_BYTES: u32 = 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DecodeError {
    #[error("exception-table byte stream truncated at offset {at}")]
    Truncated { at: usize },
    #[error("expected entry-start marker at offset {at}, got 0x{byte:02x}")]
    MissingStartMarker { at: usize, byte: u8 },
    #[error("varint chunk count exceeded sanity limit at offset {at}")]
    VarintOverflow { at: usize },
    #[error("exception-table offset overflow computing {field}")]
    OffsetOverflow { field: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExceptionEntry {
    pub start_offset: u32,
    pub end_offset: u32,
    pub target_offset: u32,
    pub stack_depth: u32,
    pub last_i: bool,
}

pub fn decode_exception_table(bytes: &[u8]) -> Result<Vec<ExceptionEntry>, DecodeError> {
    let mut out: Vec<ExceptionEntry> = Vec::with_capacity(bytes.len() / 4);
    let mut cursor: usize = 0;
    while cursor < bytes.len() {
        if bytes[cursor] & ENTRY_START_BIT == 0 {
            return Err(DecodeError::MissingStartMarker {
                at: cursor,
                byte: bytes[cursor],
            });
        }
        let mut fields: [u32; FIELDS_PER_ENTRY] = [0; FIELDS_PER_ENTRY];
        for (field_index, slot) in fields.iter_mut().enumerate() {
            let (value, new_cursor): (u32, usize) = read_varint(bytes, cursor, field_index == 0)?;
            *slot = value;
            cursor = new_cursor;
        }
        let start_units: u32 = fields[0];
        let length_units: u32 = fields[1];
        let target_units: u32 = fields[2];
        let depth_and_lasti: u32 = fields[3];
        let start_offset: u32 = units_to_bytes(start_units, "start")?;
        let end_units: u32 = start_units
            .checked_add(length_units)
            .ok_or(DecodeError::OffsetOverflow { field: "end" })?;
        let end_offset: u32 = units_to_bytes(end_units, "end")?;
        let target_offset: u32 = units_to_bytes(target_units, "target")?;
        out.push(ExceptionEntry {
            start_offset,
            end_offset,
            target_offset,
            stack_depth: depth_and_lasti >> 1,
            last_i: (depth_and_lasti & 1) == 1,
        });
    }
    Ok(out)
}

fn units_to_bytes(units: u32, field: &'static str) -> Result<u32, DecodeError> {
    units
        .checked_mul(BYTECODE_UNIT_BYTES)
        .ok_or(DecodeError::OffsetOverflow { field })
}

fn read_varint(
    bytes: &[u8],
    mut cursor: usize,
    expect_start: bool,
) -> Result<(u32, usize), DecodeError> {
    let first: u8 = *bytes
        .get(cursor)
        .ok_or(DecodeError::Truncated { at: cursor })?;
    let start_set: bool = (first & ENTRY_START_BIT) != 0;
    if expect_start && !start_set {
        return Err(DecodeError::MissingStartMarker {
            at: cursor,
            byte: first,
        });
    }
    let mut byte: u8 = first;
    let mut value: u32 = u32::from(byte & VARINT_DATA_MASK);
    cursor += 1;
    let mut chunks: u32 = 1;
    while (byte & CONTINUATION_BIT) != 0 {
        if chunks > 5 {
            return Err(DecodeError::VarintOverflow { at: cursor });
        }
        byte = *bytes
            .get(cursor)
            .ok_or(DecodeError::Truncated { at: cursor })?;
        value = (value << VARINT_CHUNK_BITS) | u32::from(byte & VARINT_DATA_MASK);
        cursor += 1;
        chunks += 1;
    }
    Ok((value, cursor))
}

#[must_use]
pub fn render_exception_table(entries: &[ExceptionEntry]) -> String {
    let mut out: String = String::with_capacity(entries.len() * 64);
    out.push_str("Exception table:\n");
    if entries.is_empty() {
        out.push_str("  <empty>\n");
        return out;
    }
    out.push_str("  start  end  target  depth  lasti\n");
    for entry in entries {
        crate::push_string_fmt(
            &mut out,
            format_args!(
                "  {:>5}  {:>3}  {:>6}  {:>5}  {}\n",
                entry.start_offset,
                entry.end_offset,
                entry.target_offset,
                entry.stack_depth,
                if entry.last_i { "yes" } else { "no" }
            ),
        );
    }
    out
}

pub fn render_exception_table_json(
    entries: &[ExceptionEntry],
) -> Result<String, serde_json::Error> {
    serde_json::to_string(entries)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn encode_varint(value: u32, is_start: bool) -> Vec<u8> {
        let mut chunks: Vec<u8> = Vec::new();
        let mut remaining: u32 = value;
        loop {
            let chunk: u8 = u8::try_from(remaining & u32::from(VARINT_DATA_MASK)).unwrap_or(0);
            chunks.push(chunk);
            remaining >>= VARINT_CHUNK_BITS;
            if remaining == 0 {
                break;
            }
        }
        chunks.reverse();
        let last_index: usize = chunks.len() - 1;
        let mut out: Vec<u8> = Vec::with_capacity(chunks.len());
        for (i, chunk) in chunks.iter().enumerate() {
            let mut b: u8 = *chunk;
            if i != last_index {
                b |= CONTINUATION_BIT;
            }
            if i == 0 && is_start {
                b |= ENTRY_START_BIT;
            }
            out.push(b);
        }
        out
    }

    fn encode_entry(start: u32, length: u32, target: u32, depth: u32, last_i: bool) -> Vec<u8> {
        let mut out: Vec<u8> = encode_varint(start, true);
        out.extend(encode_varint(length, false));
        out.extend(encode_varint(target, false));
        let combined: u32 = (depth << 1) | u32::from(last_i);
        out.extend(encode_varint(combined, false));
        out
    }

    #[test]
    fn empty_table_decodes_to_no_entries() {
        let entries: Vec<ExceptionEntry> = decode_exception_table(&[]).expect("empty ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn single_small_entry_round_trip() {
        let raw: Vec<u8> = encode_entry(2, 4, 10, 3, false);
        let entries: Vec<ExceptionEntry> = decode_exception_table(&raw).expect("decode ok");
        assert_eq!(entries.len(), 1);
        let entry: ExceptionEntry = entries[0];
        assert_eq!(entry.start_offset, 2 * BYTECODE_UNIT_BYTES);
        assert_eq!(entry.end_offset, (2 + 4) * BYTECODE_UNIT_BYTES);
        assert_eq!(entry.target_offset, 10 * BYTECODE_UNIT_BYTES);
        assert_eq!(entry.stack_depth, 3);
        assert!(!entry.last_i);
    }

    #[test]
    fn multi_byte_varint_decodes_large_value() {
        let raw: Vec<u8> = encode_entry(1000, 200, 5000, 7, true);
        let entries: Vec<ExceptionEntry> = decode_exception_table(&raw).expect("decode ok");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].start_offset, 1000 * BYTECODE_UNIT_BYTES);
        assert_eq!(entries[0].target_offset, 5000 * BYTECODE_UNIT_BYTES);
        assert_eq!(entries[0].stack_depth, 7);
        assert!(entries[0].last_i);
    }

    #[test]
    fn oversized_unit_offset_returns_error() {
        let raw: Vec<u8> = encode_entry(u32::MAX / BYTECODE_UNIT_BYTES + 1, 1, 0, 0, false);
        let err: DecodeError = decode_exception_table(&raw).expect_err("should error");
        assert!(matches!(
            err,
            DecodeError::OffsetOverflow { field: "start" }
        ));
    }

    #[test]
    fn multiple_entries_decode_in_order() {
        let mut raw: Vec<u8> = encode_entry(0, 4, 20, 0, false);
        raw.extend(encode_entry(8, 4, 30, 1, false));
        raw.extend(encode_entry(16, 4, 40, 2, true));
        let entries: Vec<ExceptionEntry> = decode_exception_table(&raw).expect("decode ok");
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].target_offset, 40 * BYTECODE_UNIT_BYTES);
        assert!(entries[2].last_i);
    }

    #[test]
    fn truncated_table_returns_error() {
        let raw: Vec<u8> = vec![ENTRY_START_BIT | CONTINUATION_BIT | 0x01];
        let err: DecodeError = decode_exception_table(&raw).expect_err("should error");
        assert!(matches!(err, DecodeError::Truncated { .. }));
    }

    #[test]
    fn missing_start_marker_returns_error() {
        let raw: Vec<u8> = vec![0x10, 0x20];
        let err: DecodeError = decode_exception_table(&raw).expect_err("should error");
        assert!(matches!(err, DecodeError::MissingStartMarker { .. }));
    }

    #[test]
    fn render_table_includes_header_and_columns() {
        let entries: Vec<ExceptionEntry> = vec![ExceptionEntry {
            start_offset: 4,
            end_offset: 12,
            target_offset: 16,
            stack_depth: 2,
            last_i: false,
        }];
        let rendered: String = render_exception_table(&entries);
        assert!(rendered.starts_with("Exception table:"));
        assert!(rendered.contains("start"));
        assert!(rendered.contains("16"));
    }

    #[test]
    fn render_empty_table_emits_placeholder() {
        let rendered: String = render_exception_table(&[]);
        assert!(rendered.contains("<empty>"));
    }

    #[test]
    fn render_json_round_trips_through_serde() {
        let entries: Vec<ExceptionEntry> = vec![ExceptionEntry {
            start_offset: 0,
            end_offset: 8,
            target_offset: 32,
            stack_depth: 1,
            last_i: true,
        }];
        let json: String = render_exception_table_json(&entries).expect("serialize ok");
        assert!(json.contains("\"start_offset\":0"));
        assert!(json.contains("\"last_i\":true"));
    }
}
