use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const MODULE_SIGNATURE: [u8; 4] = [0xE2, 0x9C, 0xA8, 0x0E];

const IDENTIFIER_DATA_BLOCK_ID: u64 = 12;
const IDENTIFIER_DATA_CODE: u64 = 1;
const CONTROL_BLOCK_ID: u64 = 9;
const METADATA_RECORD_CODE: u64 = 1;
const MODULE_NAME_RECORD_CODE: u64 = 2;
const TARGET_RECORD_CODE: u64 = 3;

const ABBREV_END_BLOCK: u64 = 0;
const ABBREV_ENTER_SUBBLOCK: u64 = 1;
const ABBREV_DEFINE_ABBREV: u64 = 2;
const ABBREV_UNABBREV_RECORD: u64 = 3;
const FIRST_APPLICATION_ABBREV: u64 = 4;

const BLOCKINFO_BLOCK_ID: u64 = 0;
const BLOCKINFO_CODE_SETBID: u64 = 1;

const MAX_DEPTH: usize = 64;
const MAX_ARRAY_LEN: u64 = 1 << 26;
const MAX_VBR_PIECES: u32 = 16;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwiftModuleDecls {
    pub signature_ok: bool,
    pub module_name: Option<String>,
    pub target_triple: Option<String>,
    pub compiler_version: Option<String>,
    pub identifiers: Vec<String>,
}

impl SwiftModuleDecls {
    #[must_use]
    pub fn type_like_identifiers(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .map(String::as_str)
            .filter(|s: &&str| {
                let bytes: &[u8] = s.as_bytes();
                matches!(bytes.first(), Some(b) if b.is_ascii_uppercase())
                    && s.chars()
                        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
            .collect()
    }

    #[must_use]
    pub fn member_like_identifiers(&self) -> Vec<&str> {
        self.identifiers
            .iter()
            .map(String::as_str)
            .filter(|s: &&str| {
                let bytes: &[u8] = s.as_bytes();
                matches!(bytes.first(), Some(b) if b.is_ascii_lowercase())
                    && s.chars()
                        .all(|c: char| c.is_ascii_alphanumeric() || c == '_')
            })
            .collect()
    }

    #[must_use]
    pub fn contains(&self, identifier: &str) -> bool {
        self.identifiers.iter().any(|s: &String| s == identifier)
    }
}

#[must_use]
pub fn is_swift_module(bytes: &[u8]) -> bool {
    bytes.starts_with(&MODULE_SIGNATURE)
}

pub fn read(bytes: &[u8]) -> Result<SwiftModuleDecls> {
    crate::debug::dbg_section("swiftmodule read");
    if !is_swift_module(bytes) {
        return Err(Error::NotSwiftModule);
    }
    let mut walker: BitstreamWalker<'_> = BitstreamWalker::new(&bytes[MODULE_SIGNATURE.len()..]);
    let mut sink: DeclSink = DeclSink::default();
    walker.walk_top_level(&mut sink)?;
    let identifiers: Vec<String> = split_identifier_blob(&sink.identifier_blob);
    crate::debug::dbg_kv("decls", || {
        format!(
            "module={:?} target={:?} identifiers={}",
            sink.module_name,
            sink.target_triple,
            identifiers.len()
        )
    });
    Ok(SwiftModuleDecls {
        signature_ok: true,
        module_name: sink.module_name,
        target_triple: sink.target_triple,
        compiler_version: sink.compiler_version,
        identifiers,
    })
}

fn split_identifier_blob(blob: &[u8]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for piece in blob.split(|b: &u8| *b == 0) {
        if piece.is_empty() {
            continue;
        }
        if let Ok(text) = std::str::from_utf8(piece) {
            out.push(text.to_owned());
        }
    }
    out
}

#[derive(Default)]
struct DeclSink {
    identifier_blob: Vec<u8>,
    module_name: Option<String>,
    target_triple: Option<String>,
    compiler_version: Option<String>,
}

impl DeclSink {
    fn on_record(&mut self, block_id: u64, code: u64, blob: Option<&[u8]>) {
        match (block_id, code) {
            (IDENTIFIER_DATA_BLOCK_ID, IDENTIFIER_DATA_CODE) => {
                if let Some(data) = blob
                    && self.identifier_blob.is_empty()
                {
                    self.identifier_blob = data.to_vec();
                }
            }
            (CONTROL_BLOCK_ID, MODULE_NAME_RECORD_CODE) if self.module_name.is_none() => {
                self.module_name = blob.and_then(decode_blob_string);
            }
            (CONTROL_BLOCK_ID, TARGET_RECORD_CODE) if self.target_triple.is_none() => {
                self.target_triple = blob.and_then(decode_blob_string);
            }
            (CONTROL_BLOCK_ID, METADATA_RECORD_CODE) if self.compiler_version.is_none() => {
                self.compiler_version = blob.and_then(decode_blob_string);
            }
            _ => {}
        }
    }
}

fn decode_blob_string(blob: &[u8]) -> Option<String> {
    let trimmed: &[u8] = blob.strip_suffix(&[0]).unwrap_or(blob);
    std::str::from_utf8(trimmed)
        .ok()
        .map(str::trim)
        .filter(|s: &&str| !s.is_empty())
        .map(str::to_owned)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AbbrevEncoding {
    Fixed,
    Vbr,
    Array,
    Char6,
    Blob,
}

impl AbbrevEncoding {
    fn from_code(code: u64) -> Result<Self> {
        match code {
            1 => Ok(Self::Fixed),
            2 => Ok(Self::Vbr),
            3 => Ok(Self::Array),
            4 => Ok(Self::Char6),
            5 => Ok(Self::Blob),
            other => Err(Error::BadBitstream(format!(
                "unknown abbrev encoding {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
struct AbbrevOp {
    is_literal: bool,
    literal: u64,
    encoding: Option<AbbrevEncoding>,
    extra: u64,
}

#[derive(Debug, Clone, Default)]
struct Abbrev {
    ops: Vec<AbbrevOp>,
}

struct BitstreamWalker<'a> {
    bits: BitReader<'a>,
    blockinfo: BTreeMap<u64, Vec<Abbrev>>,
}

impl<'a> BitstreamWalker<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self {
            bits: BitReader::new(buf),
            blockinfo: BTreeMap::new(),
        }
    }

    fn walk_top_level(&mut self, sink: &mut DeclSink) -> Result<()> {
        let top_width: u32 = 2;
        while self.bits.remaining_bits() >= u64::from(top_width) {
            let abbrev_id: u64 = self.bits.read(top_width)?;
            match abbrev_id {
                ABBREV_ENTER_SUBBLOCK => self.enter_subblock(sink, 0)?,
                ABBREV_END_BLOCK => {
                    self.bits.align32();
                }
                _ => break,
            }
        }
        Ok(())
    }

    fn enter_subblock(&mut self, sink: &mut DeclSink, depth: usize) -> Result<()> {
        if depth >= MAX_DEPTH {
            return Err(Error::BadBitstream("block nesting too deep".to_owned()));
        }
        let block_id: u64 = self.bits.read_vbr(8)?;
        let new_width: u64 = self.bits.read_vbr(4)?;
        if new_width == 0 || new_width > 32 {
            return Err(Error::BadBitstream(format!("bad abbrev width {new_width}")));
        }
        self.bits.align32();
        let _length_words: u64 = self.bits.read(32)?;
        if block_id == BLOCKINFO_BLOCK_ID {
            self.parse_blockinfo(u32::try_from(new_width).unwrap_or(32))?;
            return Ok(());
        }
        self.parse_block(
            block_id,
            u32::try_from(new_width).unwrap_or(32),
            sink,
            depth,
        )
    }

    fn parse_block(
        &mut self,
        block_id: u64,
        width: u32,
        sink: &mut DeclSink,
        depth: usize,
    ) -> Result<()> {
        let mut abbrevs: Vec<Abbrev> = self.blockinfo.get(&block_id).cloned().unwrap_or_default();
        loop {
            if self.bits.remaining_bits() < u64::from(width) {
                return Ok(());
            }
            let abbrev_id: u64 = self.bits.read(width)?;
            match abbrev_id {
                ABBREV_END_BLOCK => {
                    self.bits.align32();
                    return Ok(());
                }
                ABBREV_ENTER_SUBBLOCK => self.enter_subblock(sink, depth + 1)?,
                ABBREV_DEFINE_ABBREV => abbrevs.push(self.read_define_abbrev()?),
                ABBREV_UNABBREV_RECORD => {
                    self.skip_unabbrev_record()?;
                }
                application => {
                    let index: usize = usize::try_from(application - FIRST_APPLICATION_ABBREV)
                        .map_err(|_| Error::BadBitstream("abbrev id overflow".to_owned()))?;
                    let abbrev: Abbrev = abbrevs.get(index).cloned().ok_or_else(|| {
                        Error::BadBitstream(format!("abbrev {application} unknown"))
                    })?;
                    let (code, blob): (u64, Option<Vec<u8>>) = self.read_abbrev_record(&abbrev)?;
                    sink.on_record(block_id, code, blob.as_deref());
                }
            }
        }
    }

    fn parse_blockinfo(&mut self, width: u32) -> Result<()> {
        let mut current_bid: Option<u64> = None;
        loop {
            if self.bits.remaining_bits() < u64::from(width) {
                return Ok(());
            }
            let abbrev_id: u64 = self.bits.read(width)?;
            match abbrev_id {
                ABBREV_END_BLOCK => {
                    self.bits.align32();
                    return Ok(());
                }
                ABBREV_ENTER_SUBBLOCK => {
                    let mut throwaway: DeclSink = DeclSink::default();
                    self.enter_subblock(&mut throwaway, 1)?;
                }
                ABBREV_DEFINE_ABBREV => {
                    let abbrev: Abbrev = self.read_define_abbrev()?;
                    if let Some(bid) = current_bid {
                        self.blockinfo.entry(bid).or_default().push(abbrev);
                    }
                }
                ABBREV_UNABBREV_RECORD => {
                    let (code, ops): (u64, Vec<u64>) = self.read_unabbrev_record()?;
                    if code == BLOCKINFO_CODE_SETBID
                        && let Some(bid) = ops.first().copied()
                    {
                        current_bid = Some(bid);
                    }
                }
                _ => {
                    return Err(Error::BadBitstream(
                        "application abbrev inside BLOCKINFO".to_owned(),
                    ));
                }
            }
        }
    }

    fn read_define_abbrev(&mut self) -> Result<Abbrev> {
        let num_ops: u64 = self.bits.read_vbr(5)?;
        if num_ops > 1024 {
            return Err(Error::BadBitstream("abbrev op count too large".to_owned()));
        }
        let mut ops: Vec<AbbrevOp> = Vec::with_capacity(usize::try_from(num_ops).unwrap_or(0));
        for _ in 0..num_ops {
            let is_literal: bool = self.bits.read(1)? != 0;
            if is_literal {
                let literal: u64 = self.bits.read_vbr(8)?;
                ops.push(AbbrevOp {
                    is_literal: true,
                    literal,
                    encoding: None,
                    extra: 0,
                });
                continue;
            }
            let encoding: AbbrevEncoding = AbbrevEncoding::from_code(self.bits.read(3)?)?;
            let extra: u64 = match encoding {
                AbbrevEncoding::Fixed | AbbrevEncoding::Vbr => self.bits.read_vbr(5)?,
                _ => 0,
            };
            ops.push(AbbrevOp {
                is_literal: false,
                literal: 0,
                encoding: Some(encoding),
                extra,
            });
        }
        Ok(Abbrev { ops })
    }

    fn read_unabbrev_record(&mut self) -> Result<(u64, Vec<u64>)> {
        let code: u64 = self.bits.read_vbr(6)?;
        let num_ops: u64 = self.bits.read_vbr(6)?;
        if num_ops > MAX_ARRAY_LEN {
            return Err(Error::BadBitstream(
                "unabbrev op count too large".to_owned(),
            ));
        }
        let mut ops: Vec<u64> = Vec::with_capacity(usize::try_from(num_ops.min(1024)).unwrap_or(0));
        for _ in 0..num_ops {
            ops.push(self.bits.read_vbr(6)?);
        }
        Ok((code, ops))
    }

    fn skip_unabbrev_record(&mut self) -> Result<()> {
        self.read_unabbrev_record().map(|_| ())
    }

    fn read_abbrev_record(&mut self, abbrev: &Abbrev) -> Result<(u64, Option<Vec<u8>>)> {
        let mut code: Option<u64> = None;
        let mut blob: Option<Vec<u8>> = None;
        let mut index: usize = 0;
        while index < abbrev.ops.len() {
            let op: &AbbrevOp = &abbrev.ops[index];
            if op.is_literal {
                code.get_or_insert(op.literal);
                index += 1;
                continue;
            }
            match op.encoding {
                Some(AbbrevEncoding::Fixed) => {
                    let width: u32 = u32::try_from(op.extra)
                        .map_err(|_| Error::BadBitstream("fixed width overflow".to_owned()))?;
                    let value: u64 = self.bits.read(width)?;
                    code.get_or_insert(value);
                }
                Some(AbbrevEncoding::Vbr) => {
                    let width: u32 = u32::try_from(op.extra)
                        .map_err(|_| Error::BadBitstream("vbr width overflow".to_owned()))?;
                    let value: u64 = self.bits.read_vbr(width)?;
                    code.get_or_insert(value);
                }
                Some(AbbrevEncoding::Char6) => {
                    let value: u64 = self.bits.read(6)?;
                    code.get_or_insert(value);
                }
                Some(AbbrevEncoding::Array) => {
                    let count: u64 = self.bits.read_vbr(6)?;
                    if count > MAX_ARRAY_LEN {
                        return Err(Error::BadBitstream("array length too large".to_owned()));
                    }
                    let element: &AbbrevOp = abbrev.ops.get(index + 1).ok_or_else(|| {
                        Error::BadBitstream("array missing element op".to_owned())
                    })?;
                    for _ in 0..count {
                        self.read_scalar_element(element)?;
                    }
                    index += 2;
                    continue;
                }
                Some(AbbrevEncoding::Blob) => {
                    let count: u64 = self.bits.read_vbr(6)?;
                    if count > MAX_ARRAY_LEN {
                        return Err(Error::BadBitstream("blob length too large".to_owned()));
                    }
                    blob = Some(self.bits.read_blob(count)?);
                }
                None => {
                    return Err(Error::BadBitstream(
                        "non-literal op without encoding".to_owned(),
                    ));
                }
            }
            index += 1;
        }
        Ok((code.unwrap_or(0), blob))
    }

    fn read_scalar_element(&mut self, element: &AbbrevOp) -> Result<()> {
        match element.encoding {
            Some(AbbrevEncoding::Fixed) => {
                let width: u32 = u32::try_from(element.extra)
                    .map_err(|_| Error::BadBitstream("fixed width overflow".to_owned()))?;
                self.bits.read(width)?;
            }
            Some(AbbrevEncoding::Vbr) => {
                let width: u32 = u32::try_from(element.extra)
                    .map_err(|_| Error::BadBitstream("vbr width overflow".to_owned()))?;
                self.bits.read_vbr(width)?;
            }
            Some(AbbrevEncoding::Char6) => {
                self.bits.read(6)?;
            }
            _ => {
                return Err(Error::BadBitstream(
                    "invalid array element encoding".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

struct BitReader<'a> {
    buf: &'a [u8],
    bit_pos: u64,
}

impl<'a> BitReader<'a> {
    const fn new(buf: &'a [u8]) -> Self {
        Self { buf, bit_pos: 0 }
    }

    const fn total_bits(&self) -> u64 {
        (self.buf.len() as u64) * 8
    }

    const fn remaining_bits(&self) -> u64 {
        self.total_bits().saturating_sub(self.bit_pos)
    }

    fn read(&mut self, width: u32) -> Result<u64> {
        if width == 0 {
            return Ok(0);
        }
        if width > 32 {
            return Err(Error::BadBitstream(format!("fixed read width {width}")));
        }
        if self.bit_pos + u64::from(width) > self.total_bits() {
            return Err(Error::BadBitstream("read past end of bitstream".to_owned()));
        }
        let mut value: u64 = 0;
        for i in 0..width {
            let pos: u64 = self.bit_pos + u64::from(i);
            let byte: u8 = self.buf[usize::try_from(pos >> 3).unwrap_or(usize::MAX)];
            let bit: u64 = u64::from((byte >> (pos & 7)) & 1);
            value |= bit << i;
        }
        self.bit_pos += u64::from(width);
        Ok(value)
    }

    fn read_vbr(&mut self, width: u32) -> Result<u64> {
        if !(2..=32).contains(&width) {
            return Err(Error::BadBitstream(format!("vbr width {width}")));
        }
        let high_bit: u64 = 1 << (width - 1);
        let mask: u64 = high_bit - 1;
        let mut piece: u64 = self.read(width)?;
        if piece & high_bit == 0 {
            return Ok(piece);
        }
        let mut result: u64 = piece & mask;
        let mut shift: u32 = width - 1;
        let mut pieces: u32 = 1;
        loop {
            piece = self.read(width)?;
            let chunk: u64 = piece & mask;
            result |= chunk
                .checked_shl(shift)
                .ok_or_else(|| Error::BadBitstream("vbr shift overflow".to_owned()))?;
            if piece & high_bit == 0 {
                return Ok(result);
            }
            shift += width - 1;
            pieces += 1;
            if pieces > MAX_VBR_PIECES {
                return Err(Error::BadBitstream("vbr too many pieces".to_owned()));
            }
        }
    }

    const fn align32(&mut self) {
        self.bit_pos = (self.bit_pos + 31) & !31;
    }

    fn read_blob(&mut self, byte_count: u64) -> Result<Vec<u8>> {
        self.align32();
        let start: u64 = self.bit_pos >> 3;
        let count: usize = usize::try_from(byte_count)
            .map_err(|_| Error::BadBitstream("blob length overflow".to_owned()))?;
        let start_usize: usize = usize::try_from(start)
            .map_err(|_| Error::BadBitstream("blob offset overflow".to_owned()))?;
        let end: usize = start_usize
            .checked_add(count)
            .ok_or_else(|| Error::BadBitstream("blob range overflow".to_owned()))?;
        if end > self.buf.len() {
            return Err(Error::BadBitstream("blob past end of bitstream".to_owned()));
        }
        let data: Vec<u8> = self.buf[start_usize..end].to_vec();
        self.bit_pos = (end as u64) * 8;
        self.align32();
        Ok(data)
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn push_bits(out: &mut Vec<u8>, bit_pos: &mut usize, value: u64, width: u32) {
        for offset in 0..width {
            let bit: u8 = u8::try_from((value >> offset) & 1).expect("bit fits in u8");
            let byte_index: usize = *bit_pos / 8;
            if byte_index == out.len() {
                out.push(0);
            }
            out[byte_index] |= bit << (*bit_pos % 8);
            *bit_pos += 1;
        }
    }

    fn push_vbr(out: &mut Vec<u8>, bit_pos: &mut usize, width: u32, value: u64) {
        let payload_bits: u32 = width - 1;
        let continuation: u64 = 1u64 << payload_bits;
        let mask: u64 = continuation - 1;
        let mut remaining: u64 = value;
        loop {
            let chunk: u64 = remaining & mask;
            remaining >>= payload_bits;
            let piece: u64 = if remaining == 0 {
                chunk
            } else {
                chunk | continuation
            };
            push_bits(out, bit_pos, piece, width);
            if remaining == 0 {
                break;
            }
        }
    }

    #[test]
    fn unabbrev_record_op_count_above_cap_is_rejected() {
        let mut bytes: Vec<u8> = Vec::new();
        let mut bit_pos: usize = 0;
        push_vbr(&mut bytes, &mut bit_pos, 6, 1);
        push_vbr(&mut bytes, &mut bit_pos, 6, MAX_ARRAY_LEN + 1);

        let mut walker: BitstreamWalker<'_> = BitstreamWalker::new(&bytes);
        let err: Error = walker
            .read_unabbrev_record()
            .expect_err("oversized unabbrev record must reject");
        assert!(
            matches!(err, Error::BadBitstream(ref message) if message == "unabbrev op count too large"),
            "got {err}"
        );
    }
}
