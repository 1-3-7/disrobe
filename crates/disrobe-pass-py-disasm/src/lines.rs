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

#[derive(Debug, Clone)]
pub(crate) struct LineMap {
    regions: Vec<LineRegion>,
    skip_none: bool,
}

impl LineMap {
    #[must_use]
    pub(crate) fn build(co: &CodeObject, version: PyVersion) -> Self {
        let firstlineno: i32 = co.firstlineno;
        let (table, regions): (&'static str, Vec<LineRegion>) =
            if version.major == 3 && version.minor >= 11 {
                (
                    "co_linetable (3.11+ location-table)",
                    decode_location_table(&co.linetable, firstlineno, co.code.len()),
                )
            } else if version.major == 3 && version.minor == 10 {
                (
                    "co_linetable (3.10 byte/line)",
                    decode_linetable_310(line_number_bytes(co), firstlineno),
                )
            } else {
                (
                    "co_lnotab (<=3.9 addr/line)",
                    decode_lnotab(line_number_bytes(co), firstlineno, version),
                )
            };
        crate::debug::dbg_kv("line-table", || {
            format!(
                "{table} firstlineno={firstlineno} regions={}",
                regions.len()
            )
        });
        let skip_none: bool = version.major < 3 || (version.major == 3 && version.minor < 13);
        Self { regions, skip_none }
    }

    #[must_use]
    pub(crate) fn cursor(&self) -> LineCursor<'_> {
        LineCursor {
            regions: &self.regions,
            index: 0,
            last_line: LastLine::Unset,
            skip_none: self.skip_none,
        }
    }
}

#[derive(Debug)]
pub(crate) struct LineResolution {
    pub(crate) line: Option<u32>,
    pub(crate) start_line: Option<u32>,
    pub(crate) starts_line: bool,
}

#[derive(Debug)]
pub(crate) struct LineCursor<'a> {
    regions: &'a [LineRegion],
    index: usize,
    last_line: LastLine,
    skip_none: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LastLine {
    Unset,
    Seen(Option<u32>),
}

impl LineCursor<'_> {
    pub(crate) fn resolve(&mut self, offset: u32, _previous_line: Option<u32>) -> LineResolution {
        while self.index < self.regions.len() && self.regions[self.index].end <= offset {
            self.index += 1;
        }
        let region: Option<&LineRegion> = self
            .regions
            .get(self.index)
            .filter(|region: &&LineRegion| offset >= region.start && offset < region.end);
        let line: Option<u32> = region.and_then(|region: &LineRegion| region.line);
        let is_region_start: bool =
            region.is_some_and(|region: &LineRegion| region.start == offset);
        let starts_line: bool = if self.skip_none {
            is_region_start && line.is_some() && self.last_line != LastLine::Seen(line)
        } else {
            is_region_start && self.last_line != LastLine::Seen(line)
        };
        if is_region_start && (!self.skip_none || line.is_some()) {
            self.last_line = LastLine::Seen(line);
        }
        let start_line: Option<u32> = if starts_line { line } else { None };
        LineResolution {
            line,
            start_line,
            starts_line,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct LineMark {
    pub(crate) starts_line: bool,
    pub(crate) line: Option<u32>,
}

#[must_use]
pub(crate) fn line_marks(co: &CodeObject, version: PyVersion, offsets: &[u32]) -> Vec<LineMark> {
    let line_map: LineMap = LineMap::build(co, version);
    let mut cursor: LineCursor<'_> = line_map.cursor();
    let mut out: Vec<LineMark> = Vec::with_capacity(offsets.len());
    for &offset in offsets {
        let resolution: LineResolution = cursor.resolve(offset, None);
        out.push(LineMark {
            starts_line: resolution.starts_line,
            line: if resolution.starts_line {
                resolution.line
            } else {
                None
            },
        });
    }
    out
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
        let start: u32 = offset_units.saturating_mul(BYTECODE_UNIT_BYTES);
        let end: u32 = offset_units
            .saturating_add(length_units)
            .saturating_mul(BYTECODE_UNIT_BYTES);
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
        offset_units = offset_units.saturating_add(length_units);
    }
    if offset_units < code_units {
        push_region(
            &mut regions,
            offset_units.saturating_mul(BYTECODE_UNIT_BYTES),
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
