use serde::Serialize;

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 256usize;

const NILVALUE_SXP: u32 = 254u32;
const REF_SXP: u32 = 255u32;
const NILSXP: u32 = 0u32;
const SYMSXP: u32 = 1u32;
const LISTSXP: u32 = 2u32;
const CLOSXP: u32 = 3u32;
const ENVSXP: u32 = 4u32;
const LANGSXP: u32 = 6u32;
const SPECIALSXP: u32 = 7u32;
const BUILTINSXP: u32 = 8u32;
const CHARSXP: u32 = 9u32;
const LGLSXP: u32 = 10u32;
const INTSXP: u32 = 13u32;
const REALSXP: u32 = 14u32;
const CPLXSXP: u32 = 15u32;
const STRSXP: u32 = 16u32;
const VECSXP: u32 = 19u32;
const RAWSXP: u32 = 24u32;
const S4SXP: u32 = 25u32;

const HAS_ATTR_BIT: u32 = 1u32 << 9;
const HAS_TAG_BIT: u32 = 1u32 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RdsEncoding {
    Xdr,
    Binary,
    Ascii,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsHeader {
    pub encoding: RdsEncoding,
    pub version: u32,
    pub writer_version: String,
    pub min_reader_version: String,
    pub native_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsObject {
    pub header: RdsHeader,
    pub root_type: String,
    pub root_length: Option<usize>,
    pub names: Vec<String>,
    pub class: Vec<String>,
    pub symbols: Vec<String>,
    pub string_values: Vec<String>,
    pub node_count: usize,
}

#[must_use]
pub fn is_rds(bytes: &[u8]) -> bool {
    detect_encoding(bytes).is_some()
}

fn detect_encoding(bytes: &[u8]) -> Option<RdsEncoding> {
    if bytes.len() < 2 {
        return None;
    }
    match (bytes[0], bytes[1]) {
        (b'X', b'\n') => Some(RdsEncoding::Xdr),
        (b'B', b'\n') => Some(RdsEncoding::Binary),
        (b'A', b'\n') => Some(RdsEncoding::Ascii),
        _ => None,
    }
}

struct XdrReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> XdrReader<'a> {
    const fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.pos + n > self.bytes.len() {
            return Err(Error::RdsTruncated {
                offset: self.pos,
                needed: n,
                had: self.bytes.len().saturating_sub(self.pos),
            });
        }
        Ok(())
    }

    fn i32(&mut self) -> Result<i32> {
        self.need(4)?;
        let v: i32 = i32::from_be_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(self.i32()? as u32)
    }

    fn f64(&mut self) -> Result<f64> {
        self.need(8)?;
        let mut buf: [u8; 8] = [0u8; 8];
        buf.copy_from_slice(&self.bytes[self.pos..self.pos + 8]);
        self.pos += 8;
        Ok(f64::from_be_bytes(buf))
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.need(n)?;
        self.pos += n;
        Ok(())
    }

    fn string(&mut self, len: usize) -> Result<String> {
        self.need(len)?;
        let s: String = String::from_utf8_lossy(&self.bytes[self.pos..self.pos + len]).into_owned();
        self.pos += len;
        Ok(s)
    }
}

struct Walk {
    names: Vec<String>,
    class: Vec<String>,
    symbols: Vec<String>,
    string_values: Vec<String>,
    node_count: usize,
}

pub fn read_rds(bytes: &[u8]) -> Result<RdsObject> {
    let encoding: RdsEncoding = detect_encoding(bytes).ok_or_else(|| {
        Error::NotRds([
            *bytes.first().unwrap_or(&0u8),
            *bytes.get(1).unwrap_or(&0u8),
        ])
    })?;
    if encoding != RdsEncoding::Xdr {
        return Err(Error::RdsFormat(bytes[0]));
    }
    let mut r: XdrReader<'_> = XdrReader::new(bytes, 2);
    let version: u32 = r.u32()?;
    let writer_version: String = decode_version(r.u32()?);
    let min_reader_version: String = decode_version(r.u32()?);
    let native_encoding: Option<String> = if version >= 3 {
        let enc_len: i32 = r.i32()?;
        if enc_len >= 0 {
            Some(r.string(enc_len as usize)?)
        } else {
            None
        }
    } else {
        None
    };

    let header: RdsHeader = RdsHeader {
        encoding,
        version,
        writer_version,
        min_reader_version,
        native_encoding,
    };

    let mut walk: Walk = Walk {
        names: Vec::new(),
        class: Vec::new(),
        symbols: Vec::new(),
        string_values: Vec::new(),
        node_count: 0usize,
    };
    let (root_type, root_length): (String, Option<usize>) = walk_item(&mut r, &mut walk, 0)?;

    dedup_sorted(&mut walk.symbols);
    dedup_sorted(&mut walk.string_values);

    Ok(RdsObject {
        header,
        root_type,
        root_length,
        names: walk.names,
        class: walk.class,
        symbols: walk.symbols,
        string_values: walk.string_values,
        node_count: walk.node_count,
    })
}

fn walk_item(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<(String, Option<usize>)> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    w.node_count += 1;
    let flags: u32 = r.u32()?;
    let sxp: u32 = flags & 0xFFu32;
    let has_attr: bool = (flags & HAS_ATTR_BIT) != 0;
    let has_tag: bool = (flags & HAS_TAG_BIT) != 0;

    let label: String = sxp_label(sxp);

    let length: Option<usize> = match sxp {
        NILVALUE_SXP | NILSXP => None,
        REF_SXP => None,
        SYMSXP => {
            let (_t, _l): (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            None
        }
        LISTSXP | LANGSXP | CLOSXP => {
            if has_attr {
                walk_attributes(r, w, depth + 1)?;
            }
            if has_tag {
                let _tag: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
            let _car: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let _cdr: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            return Ok((label, None));
        }
        CHARSXP => {
            let len: i32 = r.i32()?;
            if len >= 0 {
                let s: String = r.string(len as usize)?;
                w.string_values.push(s);
                Some(len as usize)
            } else {
                None
            }
        }
        LGLSXP | INTSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            r.skip(count.saturating_mul(4))?;
            Some(count)
        }
        REALSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            for _ in 0..count {
                let _v: f64 = r.f64()?;
            }
            Some(count)
        }
        CPLXSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            r.skip(count.saturating_mul(16))?;
            Some(count)
        }
        RAWSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            r.skip(count)?;
            Some(count)
        }
        STRSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            for _ in 0..count {
                let _e: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
            Some(count)
        }
        VECSXP | S4SXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            for _ in 0..count {
                let _e: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
            Some(count)
        }
        ENVSXP => {
            let _locked: i32 = r.i32()?;
            let _enclos: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let _frame: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let _hashtab: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let _attr: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            return Ok((label, None));
        }
        SPECIALSXP | BUILTINSXP => {
            let len: i32 = r.i32()?;
            if len >= 0 {
                let _name: String = r.string(len as usize)?;
            }
            None
        }
        other => return Err(Error::RdsUnsupportedType(other)),
    };

    if sxp == SYMSXP
        && let Some(name) = w.string_values.last().cloned()
    {
        w.symbols.push(name);
    }

    if has_attr && !matches!(sxp, LISTSXP | LANGSXP | CLOSXP) {
        walk_attributes(r, w, depth + 1)?;
    }

    Ok((label, length))
}

fn walk_attributes(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<()> {
    let mut next: u32 = r.u32()?;
    loop {
        let sxp: u32 = next & 0xFFu32;
        if sxp == NILVALUE_SXP || sxp == NILSXP {
            break;
        }
        let has_tag: bool = (next & HAS_TAG_BIT) != 0;
        let tag_name: Option<String> = if has_tag {
            let before: usize = w.symbols.len();
            let _tag: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            w.symbols.get(before).cloned()
        } else {
            None
        };
        let before_strings: usize = w.string_values.len();
        let _value: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
        if let Some(tag) = tag_name.as_deref() {
            let collected: Vec<String> = w.string_values[before_strings..].to_vec();
            match tag {
                "names" => w.names.extend(collected),
                "class" => w.class.extend(collected),
                _ => {}
            }
        }
        next = r.u32()?;
    }
    Ok(())
}

fn sxp_label(sxp: u32) -> String {
    match sxp {
        NILVALUE_SXP | NILSXP => "NULL",
        SYMSXP => "symbol",
        LISTSXP => "pairlist",
        CLOSXP => "closure",
        ENVSXP => "environment",
        LANGSXP => "language",
        SPECIALSXP => "special",
        BUILTINSXP => "builtin",
        CHARSXP => "char",
        LGLSXP => "logical",
        INTSXP => "integer",
        REALSXP => "double",
        CPLXSXP => "complex",
        STRSXP => "character",
        VECSXP => "list",
        RAWSXP => "raw",
        S4SXP => "S4",
        _ => "unknown",
    }
    .to_owned()
}

fn decode_version(v: u32) -> String {
    let major: u32 = (v / 65536) % 256;
    let minor: u32 = (v / 256) % 256;
    let patch: u32 = v % 256;
    format!("{major}.{minor}.{patch}")
}

fn dedup_sorted(items: &mut Vec<String>) {
    items.sort_unstable();
    items.dedup();
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn xdr_string_vector(names: &[&str], values: &[&str]) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"X\n");
        out.extend_from_slice(&3i32.to_be_bytes());
        out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
        out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
        out.extend_from_slice(&5i32.to_be_bytes());
        out.extend_from_slice(b"UTF-8");
        let has_attr: u32 = if names.is_empty() { 0 } else { HAS_ATTR_BIT };
        out.extend_from_slice(&(STRSXP | has_attr).to_be_bytes());
        out.extend_from_slice(&(values.len() as i32).to_be_bytes());
        for v in values {
            out.extend_from_slice(&CHARSXP.to_be_bytes());
            out.extend_from_slice(&(v.len() as i32).to_be_bytes());
            out.extend_from_slice(v.as_bytes());
        }
        if !names.is_empty() {
            out.extend_from_slice(&(LISTSXP | HAS_TAG_BIT).to_be_bytes());
            out.extend_from_slice(&(SYMSXP).to_be_bytes());
            out.extend_from_slice(&CHARSXP.to_be_bytes());
            out.extend_from_slice(&5i32.to_be_bytes());
            out.extend_from_slice(b"names");
            out.extend_from_slice(&STRSXP.to_be_bytes());
            out.extend_from_slice(&(names.len() as i32).to_be_bytes());
            for n in names {
                out.extend_from_slice(&CHARSXP.to_be_bytes());
                out.extend_from_slice(&(n.len() as i32).to_be_bytes());
                out.extend_from_slice(n.as_bytes());
            }
            out.extend_from_slice(&NILVALUE_SXP.to_be_bytes());
        }
        out
    }

    #[test]
    fn detects_xdr_rds() {
        let bytes: Vec<u8> = xdr_string_vector(&[], &["a"]);
        assert!(is_rds(&bytes));
    }

    #[test]
    fn rejects_non_rds() {
        assert!(!is_rds(b"PK\x03\x04not an rds"));
    }

    #[test]
    fn parses_header_version() {
        let bytes: Vec<u8> = xdr_string_vector(&[], &["x"]);
        let obj: RdsObject = read_rds(&bytes).expect("parse");
        assert_eq!(obj.header.version, 3);
        assert_eq!(obj.header.encoding, RdsEncoding::Xdr);
        assert_eq!(obj.header.native_encoding.as_deref(), Some("UTF-8"));
    }

    #[test]
    fn recovers_string_values_and_root() {
        let bytes: Vec<u8> = xdr_string_vector(&[], &["hello", "world"]);
        let obj: RdsObject = read_rds(&bytes).expect("parse");
        assert_eq!(obj.root_type, "character");
        assert_eq!(obj.root_length, Some(2));
        assert!(obj.string_values.contains(&"hello".to_owned()));
        assert!(obj.string_values.contains(&"world".to_owned()));
    }

    #[test]
    fn recovers_names_attribute() {
        let bytes: Vec<u8> = xdr_string_vector(&["alpha", "beta"], &["1", "2"]);
        let obj: RdsObject = read_rds(&bytes).expect("parse");
        assert!(obj.names.contains(&"alpha".to_owned()));
        assert!(obj.names.contains(&"beta".to_owned()));
    }
}
