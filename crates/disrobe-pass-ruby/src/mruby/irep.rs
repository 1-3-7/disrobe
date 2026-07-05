use serde::{Deserialize, Serialize};

use crate::error::{Result, RubyError};

pub(crate) const IREP_MAX_DEPTH: u32 = 256;
pub(crate) const IREP_MAX_RECORDS: u32 = 1_048_576;
const IREP_SECTION_SUBHEADER: usize = 4;
const CATCH_HANDLER_SIZE: usize = 13;
const POOL_PREALLOC_CAP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PoolKind {
    Int32,
    Int64,
    Float,
    String,
    BigInt,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PoolEntry {
    pub kind: PoolKind,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrepRecord {
    pub depth: u32,
    pub index: u32,
    pub nlocals: u16,
    pub nregs: u16,
    pub child_count: u16,
    pub catch_count: u16,
    pub insn_len: u32,
    pub iseq: Vec<u8>,
    pub pool: Vec<PoolEntry>,
    pub symbols: Vec<String>,
    pub child_indices: Vec<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IrepTree {
    pub records: Vec<IrepRecord>,
    pub total_insn_bytes: u32,
    pub total_symbols: u32,
    pub total_pool_entries: u32,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RiteVersion {
    pub catch_field_present: bool,
}

#[inline]
pub(crate) const fn version_layout(format_version: [u8; 4]) -> RiteVersion {
    match &format_version {
        b"0001" | b"0002" | b"0003" | b"0004" | b"0005" | b"0006" => RiteVersion {
            catch_field_present: false,
        },
        _ => RiteVersion {
            catch_field_present: true,
        },
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let b: u8 = *self
            .bytes
            .get(self.pos)
            .ok_or(RubyError::MrubyIrepTruncated { at: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos.saturating_add(2))
            .ok_or(RubyError::MrubyIrepTruncated { at: self.pos })?;
        let arr: [u8; 2] = slice
            .try_into()
            .map_err(|_| RubyError::MrubyIrepTruncated { at: self.pos })?;
        self.pos += 2;
        Ok(u16::from_be_bytes(arr))
    }

    fn u32(&mut self) -> Result<u32> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos.saturating_add(4))
            .ok_or(RubyError::MrubyIrepTruncated { at: self.pos })?;
        let arr: [u8; 4] = slice
            .try_into()
            .map_err(|_| RubyError::MrubyIrepTruncated { at: self.pos })?;
        self.pos += 4;
        Ok(u32::from_be_bytes(arr))
    }

    fn f64_be(&mut self) -> Result<f64> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos.saturating_add(8))
            .ok_or(RubyError::MrubyIrepTruncated { at: self.pos })?;
        let arr: [u8; 8] = slice
            .try_into()
            .map_err(|_| RubyError::MrubyIrepTruncated { at: self.pos })?;
        self.pos += 8;
        Ok(f64::from_be_bytes(arr))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let slice: &[u8] = self
            .bytes
            .get(self.pos..self.pos.saturating_add(n))
            .ok_or(RubyError::MrubyIrepTruncated { at: self.pos })?;
        self.pos += n;
        Ok(slice)
    }
}

fn read_pool_entry(cur: &mut Cursor<'_>) -> Result<PoolEntry> {
    let tag: u8 = cur.u8()?;
    match tag {
        0x00 | 0x02 => {
            let len: u16 = cur.u16()?;
            let bytes: &[u8] = cur.take(usize::from(len).saturating_add(1))?;
            let text: &[u8] = &bytes[..usize::from(len)];
            Ok(PoolEntry {
                kind: PoolKind::String,
                value: Some(String::from_utf8_lossy(text).into_owned()),
            })
        }
        0x01 => {
            let v: i32 = cur.u32()? as i32;
            Ok(PoolEntry {
                kind: PoolKind::Int32,
                value: Some(v.to_string()),
            })
        }
        0x03 => {
            let hi: u64 = u64::from(cur.u32()?);
            let lo: u64 = u64::from(cur.u32()?);
            let v: i64 = ((hi << 32) | lo) as i64;
            Ok(PoolEntry {
                kind: PoolKind::Int64,
                value: Some(v.to_string()),
            })
        }
        0x05 => {
            let v: f64 = cur.f64_be()?;
            Ok(PoolEntry {
                kind: PoolKind::Float,
                value: Some(format_float(v)),
            })
        }
        0x07 => {
            let len: u8 = cur.u8()?;
            let _data: &[u8] = cur.take(usize::from(len).saturating_add(2))?;
            Ok(PoolEntry {
                kind: PoolKind::BigInt,
                value: None,
            })
        }
        _ => Err(RubyError::MrubyIrepTruncated { at: cur.pos }),
    }
}

fn format_float(v: f64) -> String {
    if v.fract() == 0.0 && v.is_finite() {
        format!("{v:.1}")
    } else {
        v.to_string()
    }
}

fn read_symbol(cur: &mut Cursor<'_>) -> Result<Option<String>> {
    let len: u16 = cur.u16()?;
    if len == u16::MAX {
        return Ok(None);
    }
    let bytes: &[u8] = cur.take(usize::from(len).saturating_add(1))?;
    let name: &[u8] = &bytes[..usize::from(len)];
    Ok(Some(String::from_utf8_lossy(name).into_owned()))
}

fn read_record(
    cur: &mut Cursor<'_>,
    ver: RiteVersion,
    depth: u32,
    out: &mut Vec<IrepRecord>,
) -> Result<u32> {
    if depth > IREP_MAX_DEPTH {
        return Err(RubyError::MrubyIrepDepthExceeded);
    }
    if out.len() as u32 >= IREP_MAX_RECORDS {
        return Err(RubyError::MrubyIrepTooManyRecords);
    }
    let _record_size: u32 = cur.u32()?;
    let nlocals: u16 = cur.u16()?;
    let nregs: u16 = cur.u16()?;
    let child_count: u16 = cur.u16()?;
    let catch_count: u16 = if ver.catch_field_present {
        cur.u16()?
    } else {
        0
    };
    let insn_len: u32 = cur.u32()?;
    let insn_len_usize: usize =
        usize::try_from(insn_len).map_err(|_| RubyError::MrubyIrepTruncated { at: cur.pos })?;
    let catch_bytes: usize = CATCH_HANDLER_SIZE
        .checked_mul(usize::from(catch_count))
        .ok_or(RubyError::MrubyIrepTruncated { at: cur.pos })?;
    let iseq_bytes: usize = insn_len_usize
        .checked_add(catch_bytes)
        .ok_or(RubyError::MrubyIrepTruncated { at: cur.pos })?;
    let iseq_full: &[u8] = cur.take(iseq_bytes)?;
    let iseq: Vec<u8> = iseq_full[..insn_len_usize].to_vec();

    let pool_len: u32 = u32::from(cur.u16()?);
    let mut pool: Vec<PoolEntry> = Vec::with_capacity((pool_len as usize).min(POOL_PREALLOC_CAP));
    for _ in 0..pool_len {
        pool.push(read_pool_entry(cur)?);
    }

    let sym_len: u32 = u32::from(cur.u16()?);
    let mut symbols: Vec<String> = Vec::with_capacity((sym_len as usize).min(POOL_PREALLOC_CAP));
    for _ in 0..sym_len {
        match read_symbol(cur)? {
            Some(name) => symbols.push(name),
            None => symbols.push(String::new()),
        }
    }

    let this_index: u32 = u32::try_from(out.len()).unwrap_or(u32::MAX);
    out.push(IrepRecord {
        depth,
        index: this_index,
        nlocals,
        nregs,
        child_count,
        catch_count,
        insn_len,
        iseq,
        pool,
        symbols,
        child_indices: Vec::with_capacity(usize::from(child_count)),
    });

    let mut children: Vec<u32> = Vec::with_capacity(usize::from(child_count));
    for _ in 0..child_count {
        let child_idx: u32 = read_record(cur, ver, depth.saturating_add(1), out)?;
        children.push(child_idx);
    }
    if let Some(rec) = out.get_mut(this_index as usize) {
        rec.child_indices = children;
    }
    Ok(this_index)
}

pub(crate) fn parse_irep(section_body: &[u8], format_version: [u8; 4]) -> Result<IrepTree> {
    let ver: RiteVersion = version_layout(format_version);
    let mut cur: Cursor<'_> = Cursor::new(section_body);

    if section_body.len() > IREP_SECTION_SUBHEADER {
        cur.pos = IREP_SECTION_SUBHEADER;
    }

    let mut records: Vec<IrepRecord> = Vec::new();
    read_record(&mut cur, ver, 0, &mut records)?;

    let total_insn_bytes: u32 = sum_insn_bytes(&records);
    let total_symbols: u32 =
        saturating_len_sum(records.iter().map(|r: &IrepRecord| r.symbols.len()));
    let total_pool_entries: u32 =
        saturating_len_sum(records.iter().map(|r: &IrepRecord| r.pool.len()));

    Ok(IrepTree {
        records,
        total_insn_bytes,
        total_symbols,
        total_pool_entries,
    })
}

fn sum_insn_bytes(records: &[IrepRecord]) -> u32 {
    records.iter().fold(0u32, |acc: u32, record: &IrepRecord| {
        acc.saturating_add(record.insn_len)
    })
}

fn saturating_len_sum<I>(lengths: I) -> u32
where
    I: Iterator<Item = usize>,
{
    let total: usize = lengths.fold(0usize, |acc: usize, len: usize| acc.saturating_add(len));
    u32::try_from(total).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn build_irep_body() -> Vec<u8> {
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&2u16.to_be_bytes());
        rec.extend_from_slice(&3u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&4u32.to_be_bytes());
        rec.extend_from_slice(&[0x01, 0x02, 0x03, 0x25]);
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.push(0x00);
        rec.extend_from_slice(&5u16.to_be_bytes());
        rec.extend_from_slice(b"hello\x00");
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&4u16.to_be_bytes());
        rec.extend_from_slice(b"puts\x00");

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&rec);
        body
    }

    #[test]
    fn parses_single_irep_with_pool_and_syms() {
        let body: Vec<u8> = build_irep_body();
        let tree: IrepTree = parse_irep(&body, *b"0300").expect("parse");
        assert_eq!(tree.records.len(), 1);
        let rec: &IrepRecord = &tree.records[0];
        assert_eq!(rec.nlocals, 2);
        assert_eq!(rec.nregs, 3);
        assert_eq!(rec.insn_len, 4);
        assert_eq!(rec.iseq, vec![0x01, 0x02, 0x03, 0x25]);
        assert_eq!(rec.pool.len(), 1);
        assert_eq!(rec.pool[0].value.as_deref(), Some("hello"));
        assert_eq!(rec.symbols, vec!["puts".to_owned()]);
        assert_eq!(tree.total_symbols, 1);
    }

    #[test]
    fn pool_int32_is_decoded_as_signed_decimal() {
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.push(0x01);
        rec.extend_from_slice(&(-42i32 as u32).to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&rec);
        let tree: IrepTree = parse_irep(&body, *b"0300").expect("parse");
        assert_eq!(tree.records[0].pool[0].kind, PoolKind::Int32);
        assert_eq!(tree.records[0].pool[0].value.as_deref(), Some("-42"));
    }

    #[test]
    fn catch_handler_bytes_are_skipped_before_pool() {
        let mut rec: Vec<u8> = Vec::new();
        rec.extend_from_slice(&0u32.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&0u16.to_be_bytes());
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.extend_from_slice(&2u32.to_be_bytes());
        rec.extend_from_slice(&[0x3b, 0x25]);
        rec.extend_from_slice(&[0u8; CATCH_HANDLER_SIZE]);
        rec.extend_from_slice(&1u16.to_be_bytes());
        rec.push(0x00);
        rec.extend_from_slice(&3u16.to_be_bytes());
        rec.extend_from_slice(b"abc\x00");
        rec.extend_from_slice(&0u16.to_be_bytes());
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&rec);
        let tree: IrepTree = parse_irep(&body, *b"0300").expect("parse");
        assert_eq!(tree.records[0].catch_count, 1);
        assert_eq!(tree.records[0].iseq, vec![0x3b, 0x25]);
        assert_eq!(tree.records[0].pool[0].value.as_deref(), Some("abc"));
    }

    #[test]
    fn nested_children_are_indexed() {
        let mut child: Vec<u8> = Vec::new();
        child.extend_from_slice(&0u32.to_be_bytes());
        child.extend_from_slice(&0u16.to_be_bytes());
        child.extend_from_slice(&1u16.to_be_bytes());
        child.extend_from_slice(&0u16.to_be_bytes());
        child.extend_from_slice(&0u16.to_be_bytes());
        child.extend_from_slice(&1u32.to_be_bytes());
        child.push(0x25);
        child.extend_from_slice(&0u16.to_be_bytes());
        child.extend_from_slice(&0u16.to_be_bytes());

        let mut parent: Vec<u8> = Vec::new();
        parent.extend_from_slice(&0u32.to_be_bytes());
        parent.extend_from_slice(&0u16.to_be_bytes());
        parent.extend_from_slice(&1u16.to_be_bytes());
        parent.extend_from_slice(&1u16.to_be_bytes());
        parent.extend_from_slice(&0u16.to_be_bytes());
        parent.extend_from_slice(&1u32.to_be_bytes());
        parent.push(0x25);
        parent.extend_from_slice(&0u16.to_be_bytes());
        parent.extend_from_slice(&0u16.to_be_bytes());
        parent.extend_from_slice(&child);

        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&parent);
        let tree: IrepTree = parse_irep(&body, *b"0300").expect("parse");
        assert_eq!(tree.records.len(), 2);
        assert_eq!(tree.records[0].child_indices, vec![1u32]);
        assert_eq!(tree.records[1].depth, 1);
    }

    fn empty_record(insn_len: u32) -> IrepRecord {
        IrepRecord {
            depth: 0,
            index: 0,
            nlocals: 0,
            nregs: 0,
            child_count: 0,
            catch_count: 0,
            insn_len,
            iseq: Vec::new(),
            pool: Vec::new(),
            symbols: Vec::new(),
            child_indices: Vec::new(),
        }
    }

    #[test]
    fn summary_counts_saturate() {
        let records: Vec<IrepRecord> = vec![empty_record(u32::MAX), empty_record(1)];
        assert_eq!(sum_insn_bytes(&records), u32::MAX);

        let too_many: usize = usize::try_from(u64::from(u32::MAX) + 1).unwrap_or(usize::MAX);
        assert_eq!(saturating_len_sum([too_many].into_iter()), u32::MAX);
    }

    #[test]
    fn truncated_record_errors_cleanly() {
        let body: Vec<u8> = vec![0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let err: RubyError = parse_irep(&body, *b"0300").expect_err("truncated");
        assert!(matches!(err, RubyError::MrubyIrepTruncated { .. }));
    }

    #[test]
    fn deep_recursion_is_bounded() {
        let mut body: Vec<u8> = Vec::new();
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u32.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        let err: RubyError = parse_irep(&body, *b"0300").expect_err("must bound");
        assert!(matches!(
            err,
            RubyError::MrubyIrepTruncated { .. } | RubyError::MrubyIrepDepthExceeded
        ));
    }
}
