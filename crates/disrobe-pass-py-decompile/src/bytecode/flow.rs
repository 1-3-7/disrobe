use std::collections::BTreeMap;

use disrobe_py_marshal::PyVersion;

use crate::error::{DecompileError, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineEntry {
    pub start: usize,
    pub end: usize,
    pub line: u32,
}

#[derive(Debug, Default)]
pub struct JumpResolver {
    offsets_to_index: BTreeMap<usize, usize>,
}

impl JumpResolver {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            offsets_to_index: BTreeMap::new(),
        }
    }

    pub fn record(&mut self, offset: usize, index: usize) {
        let _: Option<usize> = self.offsets_to_index.insert(offset, index);
    }

    #[must_use]
    pub fn resolve(&self, offset: usize) -> Option<usize> {
        self.offsets_to_index.get(&offset).copied()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExceptionTableEntry {
    pub start: u32,
    pub length: u32,
    pub target: u32,
    pub depth: u8,
    pub lasti: bool,
}

impl ExceptionTableEntry {
    #[must_use]
    pub const fn end(self) -> u32 {
        self.start.saturating_add(self.length)
    }

    #[must_use]
    pub const fn contains(self, offset: u32) -> bool {
        offset >= self.start && offset < self.end()
    }
}

#[must_use]
pub fn followable_exception_entries(
    entries: &[ExceptionTableEntry],
    instruction_offsets: &[u32],
    code_len: u32,
) -> Vec<ExceptionTableEntry> {
    let decoded = |offset: u32| -> bool { instruction_offsets.binary_search(&offset).is_ok() };
    let mut accepted: Vec<ExceptionTableEntry> = Vec::with_capacity(entries.len());
    for &entry in entries {
        let Some(end): Option<u32> = entry.start.checked_add(entry.length) else {
            continue;
        };
        if entry.length == 0 || end > code_len || entry.target >= code_len {
            continue;
        }
        if !decoded(entry.start) || !decoded(entry.target) {
            continue;
        }
        let partially_overlaps: bool = accepted.iter().any(|prior: &ExceptionTableEntry| {
            let prior_end: u32 = prior.end();
            let intersects: bool = entry.start < prior_end && prior.start < end;
            let nested: bool = (entry.start >= prior.start && end <= prior_end)
                || (prior.start >= entry.start && prior_end <= end);
            intersects && !nested
        });
        if partially_overlaps {
            continue;
        }
        accepted.push(entry);
    }
    accepted
}

pub fn parse_exception_table(bytes: &[u8]) -> Result<Vec<ExceptionTableEntry>> {
    let mut entries: Vec<ExceptionTableEntry> = Vec::new();
    let mut cursor: ExcCursor<'_> = ExcCursor::new(bytes);
    while !cursor.is_empty() {
        let start_codeunits: u64 = cursor.read_varint()?;
        let length_codeunits: u64 = cursor.read_varint()?;
        let target_codeunits: u64 = cursor.read_varint()?;
        let depth_lasti: u64 = cursor.read_varint()?;

        let start_bytes: u32 = checked_codeunits_to_bytes(start_codeunits)?;
        let length_bytes: u32 = checked_codeunits_to_bytes(length_codeunits)?;
        let target_bytes: u32 = checked_codeunits_to_bytes(target_codeunits)?;
        let depth_u8: u8 = u8::try_from(depth_lasti >> 1).map_err(|_| {
            DecompileError::MalformedExceptionTable {
                reason: format!("depth {} out of range", depth_lasti >> 1),
            }
        })?;
        let lasti: bool = (depth_lasti & 1) != 0;

        entries.push(ExceptionTableEntry {
            start: start_bytes,
            length: length_bytes,
            target: target_bytes,
            depth: depth_u8,
            lasti,
        });
    }
    Ok(entries)
}

fn checked_codeunits_to_bytes(units: u64) -> Result<u32> {
    let bytes: u64 = units.saturating_mul(2);
    u32::try_from(bytes).map_err(|_| DecompileError::MalformedExceptionTable {
        reason: format!("offset/length {bytes} exceeds u32"),
    })
}

struct ExcCursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> ExcCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    const fn is_empty(&self) -> bool {
        self.pos >= self.bytes.len()
    }

    fn read_byte(&mut self) -> Result<u8> {
        let Some(&b): Option<&u8> = self.bytes.get(self.pos) else {
            return Err(DecompileError::MalformedExceptionTable {
                reason: format!("unexpected eof at offset {}", self.pos),
            });
        };
        self.pos += 1;
        Ok(b)
    }

    fn read_varint(&mut self) -> Result<u64> {
        let first: u8 = self.read_byte()?;
        let mut value: u64 = u64::from(first & 0x3F);
        let mut more: bool = (first & 0x40) != 0;
        let mut guard: u32 = 0;
        while more {
            if guard >= 10 {
                return Err(DecompileError::MalformedExceptionTable {
                    reason: "varint exceeds 60 bits".to_owned(),
                });
            }
            let next: u8 = self.read_byte()?;
            value = (value << 6) | u64::from(next & 0x3F);
            more = (next & 0x40) != 0;
            guard += 1;
        }
        Ok(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineTableEntry {
    pub start: u32,
    pub end: u32,
    pub line: Option<u32>,
}

pub fn parse_line_table(bytes: &[u8], version: PyVersion) -> Result<Vec<LineTableEntry>> {
    if version.major >= 3 && version.minor >= 11 {
        parse_pep626_linetable(bytes)
    } else if version.major == 3 && version.minor == 10 {
        parse_lnotab_pep626_legacy(bytes)
    } else {
        parse_lnotab_classic(bytes)
    }
}

#[must_use]
pub fn line_for_offset(table: &[LineTableEntry], offset: u32) -> Option<u32> {
    let idx: std::result::Result<usize, usize> =
        table.binary_search_by(|entry: &LineTableEntry| {
            if offset < entry.start {
                std::cmp::Ordering::Greater
            } else if offset >= entry.end {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Equal
            }
        });
    let pos: usize = idx.ok()?;
    table.get(pos).and_then(|entry: &LineTableEntry| entry.line)
}

fn parse_pep626_linetable(bytes: &[u8]) -> Result<Vec<LineTableEntry>> {
    let mut entries: Vec<LineTableEntry> = Vec::new();
    let mut pos: usize = 0;
    let mut bytecode_offset: u32 = 0;
    let mut current_line: i64 = 1;

    while pos < bytes.len() {
        let first: u8 = bytes[pos];
        pos += 1;
        if (first & 0x80) == 0 {
            return Err(DecompileError::MalformedLineTable {
                reason: format!("missing start bit at byte {}", pos - 1),
            });
        }
        let code: u8 = (first >> 3) & 0x0F;
        let length_codeunits: u32 = u32::from(first & 0x07) + 1;
        let chunk_bytes: u32 = length_codeunits * 2;

        let new_line: Option<i64> = match code {
            15 => None,
            13 => {
                let delta: i64 = read_signed_varint(bytes, &mut pos)?;
                current_line = current_line.saturating_add(delta);
                Some(current_line)
            }
            14 => {
                let delta: i64 = read_signed_varint(bytes, &mut pos)?;
                let _end_line_delta: u64 = read_unsigned_varint(bytes, &mut pos)?;
                let _column: u64 = read_unsigned_varint(bytes, &mut pos)?;
                let _end_column: u64 = read_unsigned_varint(bytes, &mut pos)?;
                current_line = current_line.saturating_add(delta);
                Some(current_line)
            }
            10..=12 => {
                let delta: i64 = i64::from(code) - 10;
                if pos + 1 >= bytes.len() {
                    return Err(DecompileError::MalformedLineTable {
                        reason: "short-form columns truncated".to_owned(),
                    });
                }
                pos += 2;
                current_line = current_line.saturating_add(delta);
                Some(current_line)
            }
            0..=9 => {
                if pos >= bytes.len() {
                    return Err(DecompileError::MalformedLineTable {
                        reason: "short-form second byte missing".to_owned(),
                    });
                }
                pos += 1;
                Some(current_line)
            }
            _ => {
                return Err(DecompileError::MalformedLineTable {
                    reason: format!("invalid linetable code {code}"),
                });
            }
        };

        let line_field: Option<u32> = new_line.and_then(|l: i64| u32::try_from(l).ok());
        let next_offset: u32 = bytecode_offset + chunk_bytes;
        entries.push(LineTableEntry {
            start: bytecode_offset,
            end: next_offset,
            line: line_field,
        });
        bytecode_offset = next_offset;
    }
    Ok(entries)
}

fn read_unsigned_varint(bytes: &[u8], pos: &mut usize) -> Result<u64> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= bytes.len() {
            return Err(DecompileError::MalformedLineTable {
                reason: "varint truncated".to_owned(),
            });
        }
        let byte: u8 = bytes[*pos];
        *pos += 1;
        value |= u64::from(byte & 0x3F) << shift;
        if (byte & 0x40) == 0 {
            break;
        }
        shift += 6;
        if shift >= 60 {
            return Err(DecompileError::MalformedLineTable {
                reason: "varint exceeds 60 bits".to_owned(),
            });
        }
    }
    Ok(value)
}

fn read_signed_varint(bytes: &[u8], pos: &mut usize) -> Result<i64> {
    let raw: u64 = read_unsigned_varint(bytes, pos)?;
    let magnitude: i64 = i64::try_from(raw >> 1).unwrap_or(i64::MAX);
    Ok(if raw & 1 == 0 { magnitude } else { -magnitude })
}

fn parse_lnotab_pep626_legacy(bytes: &[u8]) -> Result<Vec<LineTableEntry>> {
    let mut entries: Vec<LineTableEntry> = Vec::new();
    let mut bytecode_offset: u32 = 0;
    let mut current_line: i64 = 0;
    let mut idx: usize = 0;
    while idx + 1 < bytes.len() {
        let sdelta: u8 = bytes[idx];
        let line_delta_byte: i8 = bytes[idx + 1].cast_signed();
        idx += 2;
        let next_offset: u32 = bytecode_offset.saturating_add(u32::from(sdelta));
        let line_field: Option<u32> = if line_delta_byte == -128 {
            None
        } else {
            current_line = current_line.saturating_add(i64::from(line_delta_byte));
            u32::try_from(current_line).ok()
        };
        if next_offset > bytecode_offset {
            entries.push(LineTableEntry {
                start: bytecode_offset,
                end: next_offset,
                line: line_field,
            });
        }
        bytecode_offset = next_offset;
    }
    Ok(entries)
}

fn parse_lnotab_classic(bytes: &[u8]) -> Result<Vec<LineTableEntry>> {
    let mut entries: Vec<LineTableEntry> = Vec::new();
    let mut bytecode_offset: u32 = 0;
    let mut current_line: i64 = 0;
    let mut idx: usize = 0;
    while idx + 1 < bytes.len() {
        let offset_delta: u8 = bytes[idx];
        let line_delta: i8 = bytes[idx + 1].cast_signed();
        idx += 2;
        if offset_delta > 0 {
            let next_offset: u32 = bytecode_offset.saturating_add(u32::from(offset_delta));
            entries.push(LineTableEntry {
                start: bytecode_offset,
                end: next_offset,
                line: u32::try_from(current_line).ok(),
            });
            bytecode_offset = next_offset;
        }
        current_line = current_line.saturating_add(i64::from(line_delta));
    }
    Ok(entries)
}
