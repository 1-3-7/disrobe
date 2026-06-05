//! Per-version source-line resolution decoding `lnotab`, the 3.10 `linetable`, and the PEP 626 location table.

#![allow(clippy::redundant_pub_crate)]

use disrobe_py_marshal::{CodeObject, PyVersion};

const LNOTAB_LINE_WRAP: i32 = 0x80;
const LNOTAB_SIGNED_FLOOR: i32 = 0x100;
const LOCATION_ENTRY_START_BIT: u8 = 0x80;
const LOCATION_CODE_MASK: u8 = 0x78;
const LOCATION_CODE_SHIFT: u32 = 3;
const LOCATION_LENGTH_MASK: u8 = 0x07;
const LOCATION_SECOND_BYTE_BIT: u8 = 0x40;
const LOCATION_SECOND_BYTE_MASK: u8 = 0x3F;
const VARINT_CHUNK_BITS: u32 = 6;
const LOCATION_SHORT_FORM_MAX: u8 = 9;
const LOCATION_ONE_LINE_0: u8 = 10;
const LOCATION_ONE_LINE_2: u8 = 12;
const LOCATION_NO_COLUMNS: u8 = 13;
const LOCATION_LONG_FORM: u8 = 14;
const LOCATION_NONE: u8 = 15;
const BYTECODE_UNIT_BYTES: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LineRegion {
    start: u32,
    end: u32,
    line: Option<u32>,
}

/// Resolves the source line for every byte offset of a code object, matching `CPython`'s `co_lines()` regions.
#[derive(Debug, Clone)]
pub(crate) struct LineMap {
    regions: Vec<LineRegion>,
}

impl LineMap {
    #[must_use]
    pub(crate) fn build(co: &CodeObject, version: PyVersion) -> Self {
        let firstlineno: i32 = co.firstlineno;
        let regions: Vec<LineRegion> = if version.major == 3 && version.minor >= 11 {
            decode_location_table(&co.linetable, firstlineno, co.code.len())
        } else if version.major == 3 && version.minor == 10 {
            decode_linetable_310(line_number_bytes(co), firstlineno)
        } else {
            decode_lnotab(line_number_bytes(co), firstlineno, version)
        };
        Self { regions }
    }

    #[must_use]
    pub(crate) fn line_at(&self, offset: u32) -> Option<u32> {
        self.regions
            .iter()
            .find(|region: &&LineRegion| offset >= region.start && offset < region.end)
            .and_then(|region: &LineRegion| region.line)
    }

    #[must_use]
    pub(crate) fn start_line(&self, offset: u32, previous_line: Option<u32>) -> Option<u32> {
        let current: Option<u32> = self.line_at(offset);
        if self.is_region_start(offset) && current != previous_line {
            current
        } else {
            None
        }
    }

    fn is_region_start(&self, offset: u32) -> bool {
        self.regions
            .iter()
            .any(|region: &LineRegion| region.start == offset)
    }
}

fn line_number_bytes(co: &CodeObject) -> &[u8] {
    if co.lnotab.is_empty() {
        &co.linetable
    } else {
        &co.lnotab
    }
}

fn push_region(regions: &mut Vec<LineRegion>, start: u32, end: u32, line: Option<u32>) {
    if end > start {
        regions.push(LineRegion { start, end, line });
    }
}

fn decode_lnotab(lnotab: &[u8], firstlineno: i32, version: PyVersion) -> Vec<LineRegion> {
    let starts: Vec<(u32, i32)> = lnotab_line_starts(lnotab, firstlineno, version);
    let mut regions: Vec<LineRegion> = Vec::with_capacity(starts.len());
    for window in starts.windows(2) {
        let (start, line): (u32, i32) = window[0];
        let (next_start, _): (u32, i32) = window[1];
        push_region(&mut regions, start, next_start, Some(line.max(0) as u32));
    }
    if let Some(&(start, line)) = starts.last() {
        push_region(&mut regions, start, u32::MAX, Some(line.max(0) as u32));
    }
    regions
}

fn lnotab_line_starts(lnotab: &[u8], firstlineno: i32, version: PyVersion) -> Vec<(u32, i32)> {
    let signed_line_delta: bool = version.major != 2;
    let mut starts: Vec<(u32, i32)> = Vec::with_capacity(lnotab.len() / 2 + 1);
    let mut addr: u32 = 0;
    let mut line: i32 = firstlineno;
    let mut last_line: Option<i32> = None;
    let mut chunks: core::slice::Chunks<'_, u8> = lnotab.chunks(2);
    while let Some(&[addr_incr, line_incr]) = chunks.next() {
        if addr_incr != 0 {
            if Some(line) != last_line {
                starts.push((addr, line));
                last_line = Some(line);
            }
            addr += u32::from(addr_incr);
        }
        line += decode_lnotab_line_delta(line_incr, signed_line_delta);
    }
    if Some(line) != last_line {
        starts.push((addr, line));
    }
    starts
}

#[inline]
fn decode_lnotab_line_delta(byte: u8, signed: bool) -> i32 {
    if signed && i32::from(byte) >= LNOTAB_LINE_WRAP {
        i32::from(byte) - LNOTAB_SIGNED_FLOOR
    } else {
        i32::from(byte)
    }
}

fn decode_linetable_310(linetable: &[u8], firstlineno: i32) -> Vec<LineRegion> {
    let mut regions: Vec<LineRegion> = Vec::with_capacity(linetable.len() / 2);
    let mut addr: u32 = 0;
    let mut line: i32 = firstlineno;
    let mut chunks: core::slice::Chunks<'_, u8> = linetable.chunks(2);
    while let Some(&[byte_incr, line_incr]) = chunks.next() {
        let signed: i32 = if i32::from(line_incr) >= LNOTAB_LINE_WRAP {
            i32::from(line_incr) - LNOTAB_SIGNED_FLOOR
        } else {
            i32::from(line_incr)
        };
        let end: u32 = addr + u32::from(byte_incr);
        if line_incr == 0x80 {
            push_region(&mut regions, addr, end, None);
        } else {
            line += signed;
            push_region(&mut regions, addr, end, Some(line.max(0) as u32));
        }
        addr = end;
    }
    regions
}

fn decode_location_table(table: &[u8], firstlineno: i32, code_len: usize) -> Vec<LineRegion> {
    let mut regions: Vec<LineRegion> = Vec::with_capacity(table.len() / 2);
    let mut cursor: usize = 0;
    let mut offset_units: u32 = 0;
    let mut line: i32 = firstlineno;
    let code_units: u32 = (code_len as u32) / BYTECODE_UNIT_BYTES;
    while cursor < table.len() {
        let first: u8 = table[cursor];
        if first & LOCATION_ENTRY_START_BIT == 0 {
            break;
        }
        cursor += 1;
        let code: u8 = (first & LOCATION_CODE_MASK) >> LOCATION_CODE_SHIFT;
        let length_units: u32 = u32::from(first & LOCATION_LENGTH_MASK) + 1;
        let start: u32 = offset_units * BYTECODE_UNIT_BYTES;
        let end: u32 = (offset_units + length_units) * BYTECODE_UNIT_BYTES;
        let region_line: Option<u32> = match code {
            LOCATION_NONE => None,
            LOCATION_LONG_FORM => {
                let (delta, next): (i32, usize) = read_signed_location_varint(table, cursor);
                cursor = next;
                cursor = skip_location_varint(table, cursor);
                cursor = skip_location_varint(table, cursor);
                cursor = skip_location_varint(table, cursor);
                line += delta;
                Some(line.max(0) as u32)
            }
            LOCATION_NO_COLUMNS => {
                let (delta, next): (i32, usize) = read_signed_location_varint(table, cursor);
                cursor = next;
                line += delta;
                Some(line.max(0) as u32)
            }
            LOCATION_ONE_LINE_0..=LOCATION_ONE_LINE_2 => {
                let delta: i32 = i32::from(code) - i32::from(LOCATION_ONE_LINE_0);
                line += delta;
                cursor = skip_location_varint(table, cursor);
                cursor = skip_location_varint(table, cursor);
                Some(line.max(0) as u32)
            }
            0..=LOCATION_SHORT_FORM_MAX => {
                cursor += 1;
                Some(line.max(0) as u32)
            }
            _ => Some(line.max(0) as u32),
        };
        push_region(&mut regions, start, end, region_line);
        offset_units += length_units;
    }
    if offset_units < code_units {
        push_region(
            &mut regions,
            offset_units * BYTECODE_UNIT_BYTES,
            code_len as u32,
            None,
        );
    }
    regions
}

fn read_unsigned_location_varint(table: &[u8], cursor: usize) -> (u32, usize) {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    let mut pos: usize = cursor;
    while let Some(&byte) = table.get(pos) {
        pos += 1;
        let chunk: u32 = u32::from(byte & LOCATION_SECOND_BYTE_MASK);
        if let Some(shifted) = chunk.checked_shl(shift) {
            result |= shifted;
        }
        shift += VARINT_CHUNK_BITS;
        if byte & LOCATION_SECOND_BYTE_BIT == 0 {
            break;
        }
    }
    (result, pos)
}

fn read_signed_location_varint(table: &[u8], cursor: usize) -> (i32, usize) {
    let (unsigned, pos): (u32, usize) = read_unsigned_location_varint(table, cursor);
    let signed: i32 = if unsigned & 1 == 1 {
        -((unsigned >> 1) as i32)
    } else {
        (unsigned >> 1) as i32
    };
    (signed, pos)
}

#[inline]
fn skip_location_varint(table: &[u8], cursor: usize) -> usize {
    read_unsigned_location_varint(table, cursor).1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn over_long_location_varint_does_not_overflow_shift() {
        let table: [u8; 8] = [
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_BIT | LOCATION_SECOND_BYTE_MASK,
            LOCATION_SECOND_BYTE_MASK,
        ];
        let (_, pos): (u32, usize) = read_unsigned_location_varint(&table, 0);
        assert_eq!(pos, table.len(), "all continuation bytes consumed");
    }

    #[test]
    fn short_location_varint_reads_value() {
        let table: [u8; 1] = [0x05];
        let (value, pos): (u32, usize) = read_unsigned_location_varint(&table, 0);
        assert_eq!(value, 5);
        assert_eq!(pos, 1);
    }
}
