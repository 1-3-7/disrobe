use disrobe_bytes::{read_i32_le_at, read_u16_le_at, read_u32_le_at};

use super::decode_metadata_unsigned;

const MAX_HASHTABLE_BUCKETS: usize = 65_536;

pub(super) type Invalid = fn(usize, &'static str) -> crate::error::Error;

pub(super) fn decode_signed(
    bytes: &[u8],
    at: usize,
    invalid: Invalid,
) -> crate::error::Result<(i32, usize)> {
    let byte_at = |index: usize| -> crate::error::Result<u8> {
        let position: usize = at
            .checked_add(index)
            .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?;
        bytes
            .get(position)
            .copied()
            .ok_or_else(|| invalid(at, "signed integer is truncated"))
    };
    let first: u8 = byte_at(0)?;
    if first & 1 == 0 {
        return Ok((i32::from(first as i8) >> 1, 1));
    }
    if first & 3 == 1 {
        let second: i32 = i32::from(byte_at(1)? as i8);
        return Ok((i32::from(first >> 2) | (second << 6), 2));
    }
    if first & 7 == 3 {
        let second: i32 = i32::from(byte_at(1)?);
        let third: i32 = i32::from(byte_at(2)? as i8);
        return Ok((i32::from(first >> 3) | (second << 5) | (third << 13), 3));
    }
    if first & 15 == 7 {
        let second: i32 = i32::from(byte_at(1)?);
        let third: i32 = i32::from(byte_at(2)?);
        let fourth: i32 = i32::from(byte_at(3)? as i8);
        return Ok((
            i32::from(first >> 4) | (second << 4) | (third << 12) | (fourth << 20),
            4,
        ));
    }
    if first & 31 == 15 {
        let value: i32 = read_i32_le_at(
            bytes,
            at.checked_add(1)
                .ok_or_else(|| invalid(at, "signed integer offset overflowed"))?,
        )
        .map_err(|_: disrobe_bytes::ByteReadError| invalid(at, "signed integer is truncated"))?;
        return Ok((value, 5));
    }
    Err(invalid(at, "signed integer prefix is unsupported"))
}

pub(super) fn decode_unsigned(
    bytes: &[u8],
    at: &mut usize,
    invalid: Invalid,
) -> crate::error::Result<u32> {
    let (value, width): (u32, usize) = decode_metadata_unsigned(bytes, *at)
        .ok_or_else(|| invalid(*at, "unsigned integer is malformed"))?;
    *at = at
        .checked_add(width)
        .ok_or_else(|| invalid(*at, "unsigned integer cursor overflowed"))?;
    Ok(value)
}

fn read_bucket_index(
    bytes: &[u8],
    at: usize,
    width: usize,
    invalid: Invalid,
) -> crate::error::Result<usize> {
    let value: u32 = match width {
        1 => u32::from(
            *bytes
                .get(at)
                .ok_or_else(|| invalid(at, "bucket index is truncated"))?,
        ),
        2 => u32::from(
            read_u16_le_at(bytes, at).map_err(|_: disrobe_bytes::ByteReadError| {
                invalid(at, "bucket index is truncated")
            })?,
        ),
        4 => read_u32_le_at(bytes, at)
            .map_err(|_: disrobe_bytes::ByteReadError| invalid(at, "bucket index is truncated"))?,
        _ => return Err(invalid(at, "bucket index width is unsupported")),
    };
    usize::try_from(value)
        .map_err(|_: std::num::TryFromIntError| invalid(at, "bucket index does not fit usize"))
}

pub(super) fn entry_offsets(
    bytes: &[u8],
    max_entries: usize,
    invalid: Invalid,
) -> crate::error::Result<Vec<usize>> {
    let header: u8 = *bytes
        .first()
        .ok_or_else(|| invalid(0, "hashtable is empty"))?;
    let shift: u32 = u32::from(header >> 2);
    let bucket_count: usize = 1usize
        .checked_shl(shift)
        .ok_or_else(|| invalid(0, "hashtable bucket count overflowed"))?;
    if bucket_count > MAX_HASHTABLE_BUCKETS {
        return Err(invalid(0, "hashtable bucket count exceeds parser limit"));
    }
    let width: usize = 1usize
        .checked_shl(u32::from(header & 3))
        .ok_or_else(|| invalid(0, "hashtable bucket index width overflowed"))?;
    if width > 4 {
        return Err(invalid(0, "hashtable bucket index width is unsupported"));
    }
    let index_count: usize = bucket_count
        .checked_add(1)
        .ok_or_else(|| invalid(0, "hashtable bucket index count overflowed"))?;
    let table_bytes: usize = index_count
        .checked_mul(width)
        .ok_or_else(|| invalid(0, "hashtable bucket table size overflowed"))?;
    let entry_floor: usize = 1usize
        .checked_add(table_bytes)
        .ok_or_else(|| invalid(0, "hashtable bucket table end overflowed"))?;
    if entry_floor > bytes.len() {
        return Err(invalid(0, "hashtable bucket table is truncated"));
    }
    let capacity: usize = bytes.len().saturating_sub(entry_floor).min(max_entries);
    let mut offsets: Vec<usize> = Vec::new();
    offsets
        .try_reserve_exact(capacity)
        .map_err(|_| invalid(0, "hashtable entry allocation failed"))?;
    for bucket in 0..bucket_count {
        let start_at: usize = 1usize
            .checked_add(
                bucket
                    .checked_mul(width)
                    .ok_or_else(|| invalid(0, "hashtable bucket offset overflowed"))?,
            )
            .ok_or_else(|| invalid(0, "hashtable bucket offset overflowed"))?;
        let end_at: usize = start_at
            .checked_add(width)
            .ok_or_else(|| invalid(start_at, "hashtable bucket end offset overflowed"))?;
        let start: usize = 1usize
            .checked_add(read_bucket_index(bytes, start_at, width, invalid)?)
            .ok_or_else(|| invalid(start_at, "hashtable bucket start overflowed"))?;
        let end: usize = 1usize
            .checked_add(read_bucket_index(bytes, end_at, width, invalid)?)
            .ok_or_else(|| invalid(end_at, "hashtable bucket end overflowed"))?;
        if start < entry_floor || end < start || end > bytes.len() {
            return Err(invalid(start_at, "hashtable bucket range is invalid"));
        }
        let mut cursor: usize = start;
        while cursor < end {
            cursor = cursor
                .checked_add(1)
                .ok_or_else(|| invalid(cursor, "hashtable hash cursor overflowed"))?;
            let relative_at: usize = cursor;
            let (delta, width): (i32, usize) = decode_signed(bytes, relative_at, invalid)?;
            cursor = cursor
                .checked_add(width)
                .ok_or_else(|| invalid(relative_at, "hashtable entry cursor overflowed"))?;
            if cursor > end {
                return Err(invalid(
                    relative_at,
                    "hashtable bucket entry exceeds its range",
                ));
            }
            let target: usize = if delta >= 0 {
                relative_at.checked_add(delta.unsigned_abs() as usize)
            } else {
                relative_at.checked_sub(delta.unsigned_abs() as usize)
            }
            .ok_or_else(|| invalid(relative_at, "hashtable entry target overflowed"))?;
            if target < entry_floor || target >= bytes.len() {
                return Err(invalid(
                    relative_at,
                    "hashtable entry target is outside the blob",
                ));
            }
            if offsets.len() >= max_entries {
                return Err(invalid(
                    relative_at,
                    "hashtable entry count exceeds parser limit",
                ));
            }
            offsets.push(target);
        }
    }
    Ok(offsets)
}
