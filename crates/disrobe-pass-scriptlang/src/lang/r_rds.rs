use serde::Serialize;

use disrobe_bytes::{ByteReadError, ByteReader};

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 256usize;
const MAX_NODES: usize = 65_536usize;
const MAX_STRING_BYTES: usize = 64 * 1024;
const MAX_RVALUE_VECTOR_ENTRIES: usize = 4096usize;
const RAW_VECTOR_CAP: usize = 4096usize;
const COMPLEX_VECTOR_CAP: usize = 1024usize;

const REF_SXP: u32 = 255u32;
const NILVALUE_SXP: u32 = 254u32;
const GLOBALENV_SXP: u32 = 253u32;
const UNBOUNDVALUE_SXP: u32 = 252u32;
const MISSINGARG_SXP: u32 = 251u32;
const BASENAMESPACE_SXP: u32 = 250u32;
const NAMESPACESXP: u32 = 249u32;
const PACKAGESXP: u32 = 248u32;
const PERSISTSXP: u32 = 247u32;
const CLASSREFSXP: u32 = 246u32;
const GENERICREFSXP: u32 = 245u32;
const BCREPDEF: u32 = 244u32;
const BCREPREF: u32 = 243u32;
const EMPTYENV_SXP: u32 = 242u32;
const BASEENV_SXP: u32 = 241u32;
const ATTRLANGSXP: u32 = 240u32;
const ATTRLISTSXP: u32 = 239u32;
const ALTREP_SXP: u32 = 238u32;
const NILSXP: u32 = 0u32;
const SYMSXP: u32 = 1u32;
const LISTSXP: u32 = 2u32;
const CLOSXP: u32 = 3u32;
const ENVSXP: u32 = 4u32;
const PROMSXP: u32 = 5u32;
const LANGSXP: u32 = 6u32;
const SPECIALSXP: u32 = 7u32;
const BUILTINSXP: u32 = 8u32;
const CHARSXP: u32 = 9u32;
const LGLSXP: u32 = 10u32;
const INTSXP: u32 = 13u32;
const REALSXP: u32 = 14u32;
const CPLXSXP: u32 = 15u32;
const STRSXP: u32 = 16u32;
const DOTSXP: u32 = 17u32;
const ANYSXP: u32 = 18u32;
const VECSXP: u32 = 19u32;
const EXPRSXP: u32 = 20u32;
const BCODESXP: u32 = 21u32;
const EXTPTRSXP: u32 = 22u32;
const WEAKREFSXP: u32 = 23u32;
const RAWSXP: u32 = 24u32;
const S4SXP: u32 = 25u32;

const HAS_ATTR_BIT: u32 = 1u32 << 9;
const HAS_TAG_BIT: u32 = 1u32 << 10;

const R_NA_REAL_BITS: u64 = 0x7FF0_0000_0000_07A2u64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RdsEncoding {
    Xdr,
    Binary,
    Ascii,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RdsContainer {
    Rds,
    Rda,
}

const RDA_MAGICS: [&[u8; 5]; 6] = [
    b"RDX2\n", b"RDX3\n", b"RDA2\n", b"RDA3\n", b"RDB2\n", b"RDB3\n",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsHeader {
    pub container: RdsContainer,
    pub container_magic: Option<String>,
    pub encoding: RdsEncoding,
    pub version: u32,
    pub writer_version: String,
    pub min_reader_version: String,
    pub native_encoding: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsFormal {
    pub name: String,
    pub default: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsEnvironment {
    pub is_reference: bool,
    pub frame_bindings: Vec<String>,
    pub enclosing: Option<Box<Self>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsClosure {
    pub formals: Vec<RdsFormal>,
    pub body: String,
    pub environment: RdsEnvironment,
    pub rendered: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsComplex {
    pub re: String,
    pub im: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsRawVector {
    pub length: usize,
    pub bytes: Vec<u8>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsComplexVector {
    pub length: usize,
    pub values: Vec<RdsComplex>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsS4Object {
    pub class: Option<String>,
    pub package: Option<String>,
    pub slots: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsEnvironmentInfo {
    pub bindings: Vec<String>,
    pub enclosing: String,
    pub is_hashed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsAltrep {
    pub class: Option<String>,
    pub package: Option<String>,
    pub serialized_type: Option<i64>,
    pub represented_type: Option<String>,
    pub represented_length: Option<usize>,
    pub materialized: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsExternalPointer {
    pub tag: Option<String>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RdsWeakReference {
    pub note: String,
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
    pub closures: Vec<RdsClosure>,
    pub raw_vectors: Vec<RdsRawVector>,
    pub complex_vectors: Vec<RdsComplexVector>,
    pub s4_objects: Vec<RdsS4Object>,
    pub environments: Vec<RdsEnvironmentInfo>,
    pub altrep_objects: Vec<RdsAltrep>,
    pub external_pointers: Vec<RdsExternalPointer>,
    pub weak_references: Vec<RdsWeakReference>,
    pub bytecode_expressions: Vec<String>,
    pub node_count: usize,
}

#[must_use]
pub fn is_rds(bytes: &[u8]) -> bool {
    detect_stream(bytes).is_some()
}

fn detect_container(bytes: &[u8]) -> Option<(RdsContainer, &'static str, usize)> {
    let head: &[u8] = bytes.get(..5)?;
    for magic in RDA_MAGICS {
        if head == magic.as_slice() {
            let label: &'static str = match core::str::from_utf8(&magic[..4]) {
                Ok(text) => match text {
                    "RDX2" => "RDX2",
                    "RDX3" => "RDX3",
                    "RDA2" => "RDA2",
                    "RDA3" => "RDA3",
                    "RDB2" => "RDB2",
                    _ => "RDB3",
                },
                Err(_) => return None,
            };
            return Some((RdsContainer::Rda, label, 5usize));
        }
    }
    None
}

fn detect_stream(bytes: &[u8]) -> Option<(RdsEncoding, usize)> {
    let frame: usize = detect_container(bytes).map_or(0usize, |(_, _, len)| len);
    let rest: &[u8] = bytes.get(frame..)?;
    let (&first, &second): (&u8, &u8) = (rest.first()?, rest.get(1)?);
    let encoding: RdsEncoding = match first {
        b'X' => RdsEncoding::Xdr,
        b'B' => RdsEncoding::Binary,
        b'A' => RdsEncoding::Ascii,
        _ => return None,
    };
    match (encoding, second) {
        (_, b'\n') => Some((encoding, frame + 2usize)),
        (RdsEncoding::Ascii, b'\r') if rest.get(2) == Some(&b'\n') => {
            Some((encoding, frame + 3usize))
        }
        _ => None,
    }
}

struct StreamReader<'a> {
    reader: ByteReader<'a>,
    encoding: RdsEncoding,
}

impl<'a> StreamReader<'a> {
    fn new(bytes: &'a [u8], pos: usize, encoding: RdsEncoding) -> Result<Self> {
        let mut reader: ByteReader<'a> = ByteReader::new(bytes);
        reader.seek(pos).map_err(Self::truncated)?;
        Ok(Self { reader, encoding })
    }

    fn truncated(error: ByteReadError) -> Error {
        Error::RdsTruncated {
            offset: error.offset,
            needed: error.needed,
            had: error.available,
        }
    }

    fn exhausted(&self, needed: usize) -> Error {
        Error::RdsTruncated {
            offset: self.reader.position(),
            needed,
            had: self.reader.remaining(),
        }
    }

    #[inline]
    fn remaining(&self) -> usize {
        self.reader.remaining()
    }

    #[inline]
    fn bounded_capacity(&self, count: usize, elem_bytes: usize) -> usize {
        disrobe_bytes::bounded_element_capacity(count as u64, elem_bytes, self.remaining())
    }

    fn ascii_token(&mut self) -> Result<&'a [u8]> {
        while let Ok(byte) = self.reader.peek_u8() {
            if byte.is_ascii_whitespace() {
                self.reader.skip(1usize).map_err(Self::truncated)?;
            } else {
                break;
            }
        }
        let start: usize = self.reader.position();
        while let Ok(byte) = self.reader.peek_u8() {
            if byte.is_ascii_whitespace() {
                break;
            }
            self.reader.skip(1usize).map_err(Self::truncated)?;
        }
        let end: usize = self.reader.position();
        if end == start {
            return Err(self.exhausted(1usize));
        }
        self.reader
            .as_slice()
            .get(start..end)
            .ok_or_else(|| self.exhausted(end - start))
    }

    fn ascii_word(&mut self) -> Result<String> {
        let token: &[u8] = self.ascii_token()?;
        Ok(String::from_utf8_lossy(token).into_owned())
    }

    fn i32(&mut self) -> Result<i32> {
        match self.encoding {
            RdsEncoding::Xdr => self.reader.read_i32_be().map_err(Self::truncated),
            RdsEncoding::Binary => self.reader.read_i32_le().map_err(Self::truncated),
            RdsEncoding::Ascii => {
                let word: String = self.ascii_word()?;
                if word == "NA" {
                    return Ok(i32::MIN);
                }
                word.parse::<i32>()
                    .map_err(|_| Error::RdsAsciiToken { token: word })
            }
        }
    }

    fn u32(&mut self) -> Result<u32> {
        match self.encoding {
            RdsEncoding::Xdr => self.reader.read_u32_be().map_err(Self::truncated),
            RdsEncoding::Binary => self.reader.read_u32_le().map_err(Self::truncated),
            RdsEncoding::Ascii => self.i32().map(|value: i32| value as u32),
        }
    }

    fn f64(&mut self) -> Result<f64> {
        match self.encoding {
            RdsEncoding::Xdr => {
                let bits: u64 = self.reader.read_u64_be().map_err(Self::truncated)?;
                Ok(f64::from_bits(bits))
            }
            RdsEncoding::Binary => {
                let bits: u64 = self.reader.read_u64_le().map_err(Self::truncated)?;
                Ok(f64::from_bits(bits))
            }
            RdsEncoding::Ascii => {
                let word: String = self.ascii_word()?;
                match word.as_str() {
                    "NA" => Ok(f64::from_bits(R_NA_REAL_BITS)),
                    "NaN" => Ok(f64::NAN),
                    "Inf" => Ok(f64::INFINITY),
                    "-Inf" => Ok(f64::NEG_INFINITY),
                    other => other.parse::<f64>().map_err(|_| Error::RdsAsciiToken {
                        token: word.clone(),
                    }),
                }
            }
        }
    }

    fn skip_ints(&mut self, count: usize) -> Result<()> {
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => self
                .reader
                .skip(count.saturating_mul(4usize))
                .map_err(Self::truncated),
            RdsEncoding::Ascii => {
                for _ in 0..count {
                    let _value: i32 = self.i32()?;
                }
                Ok(())
            }
        }
    }

    fn skip_reals(&mut self, count: usize) -> Result<()> {
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => self
                .reader
                .skip(count.saturating_mul(8usize))
                .map_err(Self::truncated),
            RdsEncoding::Ascii => {
                for _ in 0..count {
                    let _value: f64 = self.f64()?;
                }
                Ok(())
            }
        }
    }

    fn skip_raw(&mut self, count: usize) -> Result<()> {
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => {
                self.reader.skip(count).map_err(Self::truncated)
            }
            RdsEncoding::Ascii => {
                for _ in 0..count {
                    let _byte: u8 = self.raw_byte()?;
                }
                Ok(())
            }
        }
    }

    fn raw_byte(&mut self) -> Result<u8> {
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => {
                self.reader.read_u8().map_err(Self::truncated)
            }
            RdsEncoding::Ascii => {
                let word: String = self.ascii_word()?;
                u8::from_str_radix(&word, 16).map_err(|_| Error::RdsAsciiToken {
                    token: word.clone(),
                })
            }
        }
    }

    fn raw_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => {
                Ok(self.reader.read_bytes(n).map_err(Self::truncated)?.to_vec())
            }
            RdsEncoding::Ascii => {
                let mut out: Vec<u8> = Vec::with_capacity(self.bounded_capacity(n, 2usize));
                for _ in 0..n {
                    out.push(self.raw_byte()?);
                }
                Ok(out)
            }
        }
    }

    fn string(&mut self, len: usize) -> Result<String> {
        if len > MAX_STRING_BYTES {
            return Err(Error::RdsValueTooLarge {
                kind: "string",
                len,
                max: MAX_STRING_BYTES,
            });
        }
        match self.encoding {
            RdsEncoding::Xdr | RdsEncoding::Binary => {
                let raw: &[u8] = self.reader.read_bytes(len).map_err(Self::truncated)?;
                Ok(String::from_utf8_lossy(raw).into_owned())
            }
            RdsEncoding::Ascii => self.ascii_string(len),
        }
    }

    fn ascii_string(&mut self, len: usize) -> Result<String> {
        if len == 0usize {
            return Ok(String::new());
        }
        while let Ok(byte) = self.reader.peek_u8() {
            if byte.is_ascii_whitespace() {
                self.reader.skip(1usize).map_err(Self::truncated)?;
            } else {
                break;
            }
        }
        let mut out: Vec<u8> = Vec::with_capacity(self.bounded_capacity(len, 1usize));
        for _ in 0..len {
            let byte: u8 = self.reader.read_u8().map_err(Self::truncated)?;
            if byte != b'\\' {
                out.push(byte);
                continue;
            }
            let escape: u8 = self.reader.read_u8().map_err(Self::truncated)?;
            match escape {
                b'n' => out.push(b'\n'),
                b't' => out.push(b'\t'),
                b'v' => out.push(0x0bu8),
                b'b' => out.push(0x08u8),
                b'r' => out.push(b'\r'),
                b'f' => out.push(0x0cu8),
                b'a' => out.push(0x07u8),
                b'0'..=b'7' => {
                    let mut value: u32 = u32::from(escape - b'0');
                    for _ in 0..2 {
                        let Ok(digit) = self.reader.peek_u8() else {
                            break;
                        };
                        if !(b'0'..=b'7').contains(&digit) {
                            break;
                        }
                        self.reader.skip(1usize).map_err(Self::truncated)?;
                        value = value.saturating_mul(8u32) + u32::from(digit - b'0');
                    }
                    out.push(u8::try_from(value & 0xFFu32).unwrap_or(0u8));
                }
                other => out.push(other),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

struct Walk {
    names: Vec<String>,
    class: Vec<String>,
    symbols: Vec<String>,
    string_values: Vec<String>,
    closures: Vec<RdsClosure>,
    raw_vectors: Vec<RdsRawVector>,
    complex_vectors: Vec<RdsComplexVector>,
    s4_objects: Vec<RdsS4Object>,
    environments: Vec<RdsEnvironmentInfo>,
    altrep_objects: Vec<RdsAltrep>,
    external_pointers: Vec<RdsExternalPointer>,
    weak_references: Vec<RdsWeakReference>,
    bytecode_expressions: Vec<String>,
    ref_table: Vec<String>,
    bc_reps: usize,
    node_count: usize,
}

impl Walk {
    fn empty() -> Self {
        Self {
            names: Vec::new(),
            class: Vec::new(),
            symbols: Vec::new(),
            string_values: Vec::new(),
            closures: Vec::new(),
            raw_vectors: Vec::new(),
            complex_vectors: Vec::new(),
            s4_objects: Vec::new(),
            environments: Vec::new(),
            altrep_objects: Vec::new(),
            external_pointers: Vec::new(),
            weak_references: Vec::new(),
            bytecode_expressions: Vec::new(),
            ref_table: Vec::new(),
            bc_reps: 0usize,
            node_count: 0usize,
        }
    }
}

fn count_node(w: &mut Walk) -> Result<()> {
    let node_count: usize = w
        .node_count
        .checked_add(1usize)
        .ok_or(Error::RdsNodeLimitExceeded(MAX_NODES))?;
    if node_count > MAX_NODES {
        return Err(Error::RdsNodeLimitExceeded(MAX_NODES));
    }
    w.node_count = node_count;
    Ok(())
}

fn require_rvalue_vector_length(kind: &'static str, count: usize) -> Result<()> {
    if count > MAX_RVALUE_VECTOR_ENTRIES {
        return Err(Error::RdsValueTooLarge {
            kind,
            len: count,
            max: MAX_RVALUE_VECTOR_ENTRIES,
        });
    }
    Ok(())
}

pub fn read_rds(bytes: &[u8]) -> Result<RdsObject> {
    let (encoding, payload_offset): (RdsEncoding, usize) =
        detect_stream(bytes).ok_or_else(|| {
            Error::NotRds([
                bytes.first().copied().map_or(0u8, |value: u8| value),
                bytes.get(1).copied().map_or(0u8, |value: u8| value),
            ])
        })?;
    let (container, container_magic): (RdsContainer, Option<String>) = detect_container(bytes)
        .map_or((RdsContainer::Rds, None), |(kind, magic, _)| {
            (kind, Some(magic.to_owned()))
        });
    let mut r: StreamReader<'_> = StreamReader::new(bytes, payload_offset, encoding)?;
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
        container,
        container_magic,
        encoding,
        version,
        writer_version,
        min_reader_version,
        native_encoding,
    };

    let mut walk: Walk = Walk::empty();
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
        closures: walk.closures,
        raw_vectors: walk.raw_vectors,
        complex_vectors: walk.complex_vectors,
        s4_objects: walk.s4_objects,
        environments: walk.environments,
        altrep_objects: walk.altrep_objects,
        external_pointers: walk.external_pointers,
        weak_references: walk.weak_references,
        bytecode_expressions: walk.bytecode_expressions,
        node_count: walk.node_count,
    })
}

fn walk_item(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    depth: usize,
) -> Result<(String, Option<usize>)> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let flags: u32 = r.u32()?;
    walk_item_body(r, w, flags, depth)
}

fn walk_item_body(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    flags: u32,
    depth: usize,
) -> Result<(String, Option<usize>)> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    count_node(w)?;
    let sxp: u32 = flags & 0xFFu32;
    let has_attr: bool = (flags & HAS_ATTR_BIT) != 0;
    let has_tag: bool = (flags & HAS_TAG_BIT) != 0;

    let label: String = sxp_label(sxp);

    let length: Option<usize> = match sxp {
        NILVALUE_SXP | NILSXP | UNBOUNDVALUE_SXP | MISSINGARG_SXP | GLOBALENV_SXP
        | EMPTYENV_SXP | BASEENV_SXP | BASENAMESPACE_SXP => None,
        REF_SXP => {
            let index: usize = ref_index(flags, r)?;
            if let Some(name) = w.ref_table.get(index).cloned()
                && !name.is_empty()
            {
                w.symbols.push(name);
            }
            return Ok((label, None));
        }
        CLASSREFSXP | GENERICREFSXP => {
            let _ref: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            return Ok((label, None));
        }
        PERSISTSXP | NAMESPACESXP | PACKAGESXP => {
            read_in_stringvec(r, w)?;
            w.ref_table.push(String::new());
            return Ok((label, None));
        }
        ALTREP_SXP => {
            let altrep: RdsAltrep = read_altrep(r, w, depth + 1)?;
            let represented: (String, Option<usize>) = (
                altrep
                    .represented_type
                    .clone()
                    .unwrap_or_else(|| label.clone()),
                altrep.represented_length,
            );
            w.altrep_objects.push(altrep);
            return Ok(represented);
        }
        SYMSXP => {
            let (_t, _l): (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            None
        }
        CLOSXP => {
            let closure: RdsClosure = recurse_closure(r, w, has_attr, has_tag, depth + 1)?;
            w.closures.push(closure);
            return Ok((label, None));
        }
        LISTSXP | LANGSXP | PROMSXP | DOTSXP => {
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
        EXTPTRSXP => {
            w.ref_table.push(String::new());
            let _prot: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let tag: Option<String> = capture_symbol_or_string(r, w, depth + 1)?;
            if has_attr {
                walk_attributes(r, w, depth + 1)?;
            }
            w.external_pointers.push(RdsExternalPointer {
                tag,
                note: "external pointer address is a runtime value and is not present in the serialized stream".to_owned(),
            });
            return Ok((label, None));
        }
        WEAKREFSXP => {
            w.ref_table.push(String::new());
            w.weak_references.push(RdsWeakReference {
                note: "R serializes a weak reference as a type-only placeholder; its key, value, and finalizer are recreated at load time and are not present in the stream".to_owned(),
            });
            return Ok((label, None));
        }
        BCODESXP => {
            let _expression: Option<RValue> = read_bytecode(r, w, depth + 1)?;
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
            r.skip_ints(count)?;
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
            let keep: usize = count.min(COMPLEX_VECTOR_CAP);
            let mut values: Vec<RdsComplex> = Vec::with_capacity(r.bounded_capacity(keep, 16));
            for i in 0..count {
                let re: f64 = r.f64()?;
                let im: f64 = r.f64()?;
                if i < keep {
                    values.push(RdsComplex {
                        re: render_real(re),
                        im: render_real(im),
                    });
                }
            }
            w.complex_vectors.push(RdsComplexVector {
                length: count,
                values,
            });
            Some(count)
        }
        RAWSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            let keep: usize = count.min(RAW_VECTOR_CAP);
            let bytes: Vec<u8> = r.raw_bytes(keep)?;
            r.skip_raw(count - keep)?;
            w.raw_vectors.push(RdsRawVector {
                length: count,
                bytes,
                truncated: count > keep,
            });
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
        VECSXP | EXPRSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            for _ in 0..count {
                let _e: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
            Some(count)
        }
        S4SXP => {
            let slot: usize = reserve_s4(w);
            let recovered: RdsS4Object = if has_attr {
                read_s4_slots(r, w, depth + 1)?
            } else {
                RdsS4Object {
                    class: None,
                    package: None,
                    slots: Vec::new(),
                }
            };
            if let Some(entry) = w.s4_objects.get_mut(slot) {
                *entry = recovered;
            }
            return Ok((label, None));
        }
        ENVSXP => {
            w.ref_table.push(String::new());
            let slot: usize = reserve_environment(w);
            let _locked: i32 = r.i32()?;
            let enclos: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let frame_bindings: Vec<String> = collect_env_frame(r, w, depth + 1)?;
            let hashed: bool = frame_bindings.is_empty();
            let hashtab_bindings: Vec<String> = collect_env_hashtab(r, w, depth + 1)?;
            let _attr: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let mut bindings: Vec<String> = frame_bindings;
            bindings.extend(hashtab_bindings);
            bindings.sort_unstable();
            bindings.dedup();
            if let Some(entry) = w.environments.get_mut(slot) {
                *entry = RdsEnvironmentInfo {
                    bindings,
                    enclosing: enclos.0,
                    is_hashed: hashed,
                };
            }
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
        w.symbols.push(name.clone());
        w.ref_table.push(name);
    }

    if has_attr && !matches!(sxp, LISTSXP | LANGSXP | PROMSXP | DOTSXP) {
        walk_attributes(r, w, depth + 1)?;
    }

    Ok((label, length))
}

fn reserve_s4(w: &mut Walk) -> usize {
    let slot: usize = w.s4_objects.len();
    w.s4_objects.push(RdsS4Object {
        class: None,
        package: None,
        slots: Vec::new(),
    });
    slot
}

fn reserve_environment(w: &mut Walk) -> usize {
    let slot: usize = w.environments.len();
    w.environments.push(RdsEnvironmentInfo {
        bindings: Vec::new(),
        enclosing: String::new(),
        is_hashed: false,
    });
    slot
}

fn read_altrep(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<RdsAltrep> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let info: RValue = read_rvalue(r, w, depth + 1)?;
    let (class, package, serialized_type): (Option<String>, Option<String>, Option<i64>) =
        altrep_info(&info);
    let state: RValue = read_rvalue(r, w, depth + 1)?;
    let _attr: RValue = read_rvalue(r, w, depth + 1)?;
    let materialized: Option<String> = class
        .as_deref()
        .and_then(|c: &str| materialize_altrep(c, &state));
    let represented_type: Option<String> = serialized_type
        .and_then(|value: i64| u32::try_from(value).ok())
        .map(sxp_label);
    let represented_length: Option<usize> = altrep_length(&state);
    let note: Option<String> = if materialized.is_none() {
        Some(format!(
            "altrep class '{}' is reconstructed lazily by R from this state; static materialization not modeled",
            class.as_deref().map_or("<unknown>", |value: &str| value)
        ))
    } else {
        None
    };
    Ok(RdsAltrep {
        class,
        package,
        serialized_type,
        represented_type,
        represented_length,
        materialized,
        note,
    })
}

fn altrep_length(state: &RValue) -> Option<usize> {
    match state {
        RValue::RealVec(values) if values.len() == 3 => {
            let count: f64 = *values.first()?;
            if count.is_finite() && count >= 0.0 {
                usize::try_from(count as u64).ok()
            } else {
                None
            }
        }
        RValue::StringVec(values) => Some(values.len()),
        _ => None,
    }
}

fn altrep_info(info: &RValue) -> (Option<String>, Option<String>, Option<i64>) {
    let RValue::Pairlist(pairs) = info else {
        return (None, None, None);
    };
    let class: Option<String> = pairs.first().and_then(pair_symbol);
    let package: Option<String> = pairs.get(1).and_then(pair_symbol);
    let serialized_type: Option<i64> =
        pairs
            .get(2)
            .and_then(|(_, v): &(Option<String>, RValue)| match v {
                RValue::IntVec(items) => items.first().copied(),
                _ => None,
            });
    (class, package, serialized_type)
}

fn pair_symbol(pair: &(Option<String>, RValue)) -> Option<String> {
    match &pair.1 {
        RValue::Symbol(s) if !s.is_empty() => Some(s.clone()),
        RValue::StringVec(v) => v.first().filter(|s: &&String| !s.is_empty()).cloned(),
        _ => None,
    }
}

fn materialize_altrep(class: &str, state: &RValue) -> Option<String> {
    let reals: &[f64] = match state {
        RValue::RealVec(v) if v.len() == 3 => v.as_slice(),
        _ => return None,
    };
    let n: f64 = reals[0];
    let start: f64 = reals[1];
    let step: f64 = reals[2];
    match class {
        "compact_intseq" | "compact_realseq" => {
            let count: i64 = n as i64;
            if count <= 0 {
                return Some("integer(0)".to_owned());
            }
            let last: f64 = step.mul_add(n - 1.0, start);
            if (step - 1.0).abs() < f64::EPSILON {
                Some(format!("{}:{}", render_real(start), render_real(last)))
            } else {
                Some(format!(
                    "seq({}, {}, by = {}) [n={count}]",
                    render_real(start),
                    render_real(last),
                    render_real(step)
                ))
            }
        }
        _ => None,
    }
}

fn capture_symbol_or_string(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    depth: usize,
) -> Result<Option<String>> {
    let before: usize = w.symbols.len();
    let before_strings: usize = w.string_values.len();
    let _tag: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
    let from_symbol: Option<String> = w.symbols.get(before).cloned();
    let from_string: Option<String> = w.string_values.get(before_strings).cloned();
    Ok(from_symbol
        .or(from_string)
        .filter(|s: &String| !s.is_empty()))
}

fn read_s4_slots(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<RdsS4Object> {
    let mut slots: Vec<String> = Vec::new();
    let mut class: Option<String> = None;
    let mut package: Option<String> = None;
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
        match tag_name.as_deref() {
            Some("class") => {
                class = w.string_values.get(before_strings).cloned();
                if class.is_none() {
                    class.clone_from(&w.class.last().cloned());
                }
                if let Some(name) = class.clone() {
                    w.class.push(name);
                }
                package = w
                    .symbols
                    .last()
                    .filter(|s: &&String| *s == ".GlobalEnv")
                    .cloned();
            }
            Some(other) => slots.push(other.to_owned()),
            None => {}
        }
        next = r.u32()?;
    }
    Ok(RdsS4Object {
        class,
        package,
        slots,
    })
}

fn collect_env_frame(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<Vec<String>> {
    let flags: u32 = r.u32()?;
    let sxp: u32 = flags & 0xFFu32;
    if sxp == NILVALUE_SXP || sxp == NILSXP {
        return Ok(Vec::new());
    }
    let value: RValue = read_rvalue_with_flags(r, w, flags, depth + 1)?;
    Ok(pairlist_tags(&value))
}

fn collect_env_hashtab(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    depth: usize,
) -> Result<Vec<String>> {
    let flags: u32 = r.u32()?;
    let sxp: u32 = flags & 0xFFu32;
    if sxp == NILVALUE_SXP || sxp == NILSXP {
        return Ok(Vec::new());
    }
    if sxp != VECSXP {
        let _value: RValue = read_rvalue_with_flags(r, w, flags, depth + 1)?;
        return Ok(Vec::new());
    }
    let n: i32 = r.i32()?;
    let count: usize = n.max(0) as usize;
    let mut names: Vec<String> = Vec::new();
    for _ in 0..count {
        let bucket: RValue = read_rvalue(r, w, depth + 1)?;
        names.extend(pairlist_tags(&bucket));
    }
    let has_attr: bool = (flags & HAS_ATTR_BIT) != 0;
    if has_attr {
        walk_attributes(r, w, depth + 1)?;
    }
    Ok(names)
}

fn pairlist_tags(value: &RValue) -> Vec<String> {
    match value {
        RValue::Pairlist(pairs) => pairs
            .iter()
            .filter_map(|(tag, _): &(Option<String>, RValue)| {
                tag.as_ref().filter(|s: &&String| !s.is_empty()).cloned()
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn read_bytecode(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<Option<RValue>> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let declared_reps: i32 = r.i32()?;
    let table_len: usize = declared_reps.max(0) as usize;
    w.bc_reps = table_len;
    let mut table: Vec<RValue> = vec![RValue::Null; r.bounded_capacity(table_len, 4usize)];
    let expression: Option<RValue> = read_bytecode_body(r, w, &mut table, depth + 1)?;
    if let Some(ref value) = expression {
        w.bytecode_expressions.push(render_rvalue(value));
    }
    Ok(expression)
}

fn read_bytecode_body(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    table: &mut Vec<RValue>,
    depth: usize,
) -> Result<Option<RValue>> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let _code: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
    let declared: i32 = r.i32()?;
    let count: usize = declared.max(0) as usize;
    let mut expression: Option<RValue> = None;
    for index in 0..count {
        let type_tag: u32 = r.u32()?;
        let wanted: bool = index == 0usize;
        let value: Option<RValue> = match type_tag {
            BCODESXP => read_bytecode_body(r, w, table, depth + 1)?,
            LANGSXP | LISTSXP | BCREPDEF | BCREPREF | ATTRLANGSXP | ATTRLISTSXP => {
                Some(read_bclang(r, w, table, type_tag, depth + 1)?)
            }
            _ if wanted => Some(read_rvalue(r, w, depth + 1)?),
            _ => {
                let _constant: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
                None
            }
        };
        if wanted {
            expression = value;
        }
    }
    Ok(expression)
}

fn read_bclang(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    table: &mut Vec<RValue>,
    type_hint: u32,
    depth: usize,
) -> Result<RValue> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    if type_hint == BCREPREF {
        let index: i32 = r.i32()?;
        let resolved: RValue = usize::try_from(index)
            .ok()
            .and_then(|slot: usize| table.get(slot).cloned())
            .unwrap_or(RValue::Other);
        return Ok(resolved);
    }
    let mut effective: u32 = type_hint;
    let mut slot: Option<usize> = None;
    if effective == BCREPDEF {
        let declared: i32 = r.i32()?;
        slot = usize::try_from(declared).ok();
        effective = r.u32()?;
    }
    let mut has_attr: bool = false;
    if effective == ATTRLANGSXP {
        effective = LANGSXP;
        has_attr = true;
    } else if effective == ATTRLISTSXP {
        effective = LISTSXP;
        has_attr = true;
    }
    if !matches!(effective, LANGSXP | LISTSXP) {
        return read_rvalue(r, w, depth + 1);
    }
    if has_attr {
        let _attributes: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
    }
    let tag: Option<String> = match read_rvalue(r, w, depth + 1)? {
        RValue::Symbol(name) if !name.is_empty() => Some(name),
        _ => None,
    };
    let car_hint: u32 = r.u32()?;
    let car: RValue = read_bclang(r, w, table, car_hint, depth + 1)?;
    let cdr_hint: u32 = r.u32()?;
    let cdr: RValue = read_bclang(r, w, table, cdr_hint, depth + 1)?;
    let value: RValue = if effective == LANGSXP {
        let mut items: Vec<RValue> = vec![car];
        flatten_pairlist(cdr, &mut items);
        RValue::Lang(items)
    } else {
        let mut pairs: Vec<(Option<String>, RValue)> = vec![(tag, car)];
        flatten_named_pairlist(cdr, &mut pairs);
        RValue::Pairlist(pairs)
    };
    if let Some(index) = slot
        && let Some(entry) = table.get_mut(index)
    {
        entry.clone_from(&value);
    }
    Ok(value)
}

fn walk_attributes(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<()> {
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

fn recurse_closure(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    has_attr: bool,
    has_tag: bool,
    depth: usize,
) -> Result<RdsClosure> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    if has_attr {
        walk_attributes(r, w, depth + 1)?;
    }
    let environment: RdsEnvironment = if has_tag {
        match read_rvalue(r, w, depth + 1)? {
            RValue::Environment(env) => env,
            _ => RdsEnvironment {
                is_reference: false,
                frame_bindings: Vec::new(),
                enclosing: None,
            },
        }
    } else {
        RdsEnvironment {
            is_reference: false,
            frame_bindings: Vec::new(),
            enclosing: None,
        }
    };
    let formals_value: RValue = read_rvalue(r, w, depth + 1)?;
    let body_value: RValue = read_rvalue(r, w, depth + 1)?;
    let formals: Vec<RdsFormal> = read_formals(&formals_value);
    let body: String = render_rvalue(&body_value);
    let rendered: String = render_closure(&formals, &body);
    Ok(RdsClosure {
        formals,
        body,
        environment,
        rendered,
    })
}

#[derive(Debug, Clone)]
enum RValue {
    Null,
    Symbol(String),
    Pairlist(Vec<(Option<String>, Self)>),
    Lang(Vec<Self>),
    StringVec(Vec<String>),
    RealVec(Vec<f64>),
    IntVec(Vec<i64>),
    Environment(RdsEnvironment),
    Other,
}

fn read_rvalue(r: &mut StreamReader<'_>, w: &mut Walk, depth: usize) -> Result<RValue> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let flags: u32 = r.u32()?;
    read_rvalue_with_flags(r, w, flags, depth)
}

fn read_rvalue_with_flags(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    flags: u32,
    depth: usize,
) -> Result<RValue> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    count_node(w)?;
    let sxp: u32 = flags & 0xFFu32;
    let has_attr: bool = (flags & HAS_ATTR_BIT) != 0;
    let has_tag: bool = (flags & HAS_TAG_BIT) != 0;

    match sxp {
        NILVALUE_SXP | NILSXP | UNBOUNDVALUE_SXP => Ok(RValue::Null),
        MISSINGARG_SXP => Ok(RValue::Symbol(String::new())),
        GLOBALENV_SXP | EMPTYENV_SXP | BASEENV_SXP | BASENAMESPACE_SXP => {
            Ok(RValue::Environment(RdsEnvironment {
                is_reference: true,
                frame_bindings: Vec::new(),
                enclosing: None,
            }))
        }
        REF_SXP => {
            let index: usize = ref_index(flags, r)?;
            Ok(RValue::Symbol(
                w.ref_table
                    .get(index)
                    .map_or_else(String::new, |value: &String| value.clone()),
            ))
        }
        SYMSXP => {
            let printname: RValue = read_rvalue(r, w, depth + 1)?;
            let name: String = match printname {
                RValue::StringVec(ref v) => v
                    .first()
                    .map_or_else(String::new, |value: &String| value.clone()),
                RValue::Symbol(ref s) => s.clone(),
                _ => String::new(),
            };
            if !name.is_empty() {
                w.symbols.push(name.clone());
                w.ref_table.push(name.clone());
            }
            Ok(RValue::Symbol(name))
        }
        CHARSXP => {
            let len: i32 = r.i32()?;
            if len >= 0 {
                let s: String = r.string(len as usize)?;
                w.string_values.push(s.clone());
                Ok(RValue::StringVec(vec![s]))
            } else {
                Ok(RValue::StringVec(vec![String::new()]))
            }
        }
        LISTSXP | LANGSXP => {
            if has_attr {
                walk_attributes(r, w, depth + 1)?;
            }
            let tag: Option<String> = if has_tag {
                match read_rvalue(r, w, depth + 1)? {
                    RValue::Symbol(s) => Some(s),
                    _ => None,
                }
            } else {
                None
            };
            let car: RValue = read_rvalue(r, w, depth + 1)?;
            let cdr: RValue = read_rvalue(r, w, depth + 1)?;
            if sxp == LANGSXP {
                let mut items: Vec<RValue> = vec![car];
                flatten_pairlist(cdr, &mut items);
                Ok(RValue::Lang(items))
            } else {
                let mut pairs: Vec<(Option<String>, RValue)> = vec![(tag, car)];
                flatten_named_pairlist(cdr, &mut pairs);
                Ok(RValue::Pairlist(pairs))
            }
        }
        STRSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            require_rvalue_vector_length("string vector", count)?;
            let mut out: Vec<String> = Vec::with_capacity(r.bounded_capacity(count, 8));
            for _ in 0..count {
                if let RValue::StringVec(mut v) = read_rvalue(r, w, depth + 1)? {
                    out.append(&mut v);
                }
            }
            Ok(RValue::StringVec(out))
        }
        REALSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            require_rvalue_vector_length("real vector", count)?;
            let mut out: Vec<f64> = Vec::with_capacity(r.bounded_capacity(count, 8));
            for _ in 0..count {
                out.push(r.f64()?);
            }
            Ok(RValue::RealVec(out))
        }
        LGLSXP | INTSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            require_rvalue_vector_length("integer vector", count)?;
            let mut out: Vec<i64> = Vec::with_capacity(r.bounded_capacity(count, 4));
            for _ in 0..count {
                out.push(i64::from(r.i32()?));
            }
            Ok(RValue::IntVec(out))
        }
        ENVSXP => {
            w.ref_table.push(String::new());
            let env: RdsEnvironment = read_environment(r, w, depth + 1)?;
            Ok(RValue::Environment(env))
        }
        PROMSXP | DOTSXP => {
            if has_attr {
                walk_attributes(r, w, depth + 1)?;
            }
            if has_tag {
                let _tag: RValue = read_rvalue(r, w, depth + 1)?;
            }
            let _car: RValue = read_rvalue(r, w, depth + 1)?;
            let _cdr: RValue = read_rvalue(r, w, depth + 1)?;
            Ok(RValue::Other)
        }
        VECSXP | EXPRSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
            for _ in 0..count {
                let _e: RValue = read_rvalue(r, w, depth + 1)?;
            }
            if has_attr {
                walk_attributes(r, w, depth + 1)?;
            }
            Ok(RValue::Other)
        }
        BCODESXP => Ok(read_bytecode(r, w, depth + 1)?.unwrap_or(RValue::Other)),
        _ => {
            let mut tmp: Walk = Walk {
                ref_table: std::mem::take(&mut w.ref_table),
                bc_reps: w.bc_reps,
                node_count: w.node_count,
                ..Walk::empty()
            };
            rewind_and_walk(r, &mut tmp, flags, sxp, has_attr, has_tag, depth)?;
            w.ref_table = tmp.ref_table;
            w.bc_reps = tmp.bc_reps;
            w.node_count = tmp.node_count;
            w.symbols.append(&mut tmp.symbols);
            w.string_values.append(&mut tmp.string_values);
            w.closures.append(&mut tmp.closures);
            Ok(RValue::Other)
        }
    }
}

fn rewind_and_walk(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    _flags: u32,
    sxp: u32,
    has_attr: bool,
    _has_tag: bool,
    depth: usize,
) -> Result<()> {
    match sxp {
        CPLXSXP => {
            let n: i32 = r.i32()?;
            let complex_count: usize = n.max(0) as usize;
            r.skip_reals(complex_count.saturating_mul(2usize))?;
        }
        RAWSXP => {
            let n: i32 = r.i32()?;
            r.skip_raw(n.max(0) as usize)?;
        }
        VECSXP => {
            let n: i32 = r.i32()?;
            for _ in 0..n.max(0) {
                let _e: RValue = read_rvalue(r, w, depth + 1)?;
            }
        }
        S4SXP => {}
        EXTPTRSXP => {
            w.ref_table.push(String::new());
            let _prot: RValue = read_rvalue(r, w, depth + 1)?;
            let _tag: RValue = read_rvalue(r, w, depth + 1)?;
        }
        WEAKREFSXP => {
            w.ref_table.push(String::new());
        }
        ALTREP_SXP => {
            let _info: RValue = read_rvalue(r, w, depth + 1)?;
            let _state: RValue = read_rvalue(r, w, depth + 1)?;
            let _attr: RValue = read_rvalue(r, w, depth + 1)?;
            return Ok(());
        }
        NAMESPACESXP | PACKAGESXP | PERSISTSXP => {
            let _names: Vec<String> = read_in_stringvec(r, w)?;
            w.ref_table.push(String::new());
            return Ok(());
        }
        SPECIALSXP | BUILTINSXP => {
            let len: i32 = r.i32()?;
            if len >= 0 {
                let _name: String = r.string(len as usize)?;
            }
        }
        _ => return Err(Error::RdsUnsupportedType(sxp)),
    }
    if has_attr {
        walk_attributes(r, w, depth + 1)?;
    }
    Ok(())
}

fn read_environment(
    r: &mut StreamReader<'_>,
    w: &mut Walk,
    depth: usize,
) -> Result<RdsEnvironment> {
    let _locked: i32 = r.i32()?;
    let enclos: RValue = read_rvalue(r, w, depth + 1)?;
    let frame: RValue = read_rvalue(r, w, depth + 1)?;
    let _hashtab: RValue = read_rvalue(r, w, depth + 1)?;
    let _attr: RValue = read_rvalue(r, w, depth + 1)?;
    let frame_bindings: Vec<String> = match frame {
        RValue::Pairlist(pairs) => pairs
            .into_iter()
            .filter_map(|(tag, _): (Option<String>, RValue)| tag)
            .collect(),
        _ => Vec::new(),
    };
    let enclosing: Option<Box<RdsEnvironment>> = match enclos {
        RValue::Environment(env) => Some(Box::new(env)),
        _ => None,
    };
    Ok(RdsEnvironment {
        is_reference: false,
        frame_bindings,
        enclosing,
    })
}

fn ref_index(flags: u32, r: &mut StreamReader<'_>) -> Result<usize> {
    let packed: u32 = flags >> 8;
    let index: u32 = if packed == 0 { r.u32()? } else { packed };
    Ok((index as usize).saturating_sub(1))
}

fn read_in_stringvec(r: &mut StreamReader<'_>, w: &mut Walk) -> Result<Vec<String>> {
    let _leading: i32 = r.i32()?;
    let n: i32 = r.i32()?;
    let count: usize = n.max(0) as usize;
    require_rvalue_vector_length("string vector", count)?;
    let mut out: Vec<String> = Vec::with_capacity(r.bounded_capacity(count, 8));
    for _ in 0..count {
        let flags: u32 = r.u32()?;
        if flags & 0xFFu32 == CHARSXP {
            let len: i32 = r.i32()?;
            if len >= 0 {
                let s: String = r.string(len as usize)?;
                w.string_values.push(s.clone());
                out.push(s);
            }
        }
    }
    Ok(out)
}

fn flatten_pairlist(cdr: RValue, items: &mut Vec<RValue>) {
    match cdr {
        RValue::Pairlist(pairs) => {
            for (_tag, value) in pairs {
                items.push(value);
            }
        }
        RValue::Lang(more) => items.extend(more),
        RValue::Null => {}
        other => items.push(other),
    }
}

fn flatten_named_pairlist(cdr: RValue, pairs: &mut Vec<(Option<String>, RValue)>) {
    match cdr {
        RValue::Pairlist(more) => pairs.extend(more),
        RValue::Null => {}
        other => pairs.push((None, other)),
    }
}

fn read_formals(value: &RValue) -> Vec<RdsFormal> {
    match value {
        RValue::Pairlist(pairs) => pairs
            .iter()
            .filter_map(|(tag, default): &(Option<String>, RValue)| {
                tag.as_ref().map(|name: &String| RdsFormal {
                    name: name.clone(),
                    default: formal_default(default),
                })
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn formal_default(value: &RValue) -> Option<String> {
    match value {
        RValue::Symbol(s) if s.is_empty() => None,
        RValue::Null => None,
        other => Some(render_rvalue(other)),
    }
}

fn render_closure(formals: &[RdsFormal], body: &str) -> String {
    let params: String = formals
        .iter()
        .map(|f: &RdsFormal| match &f.default {
            Some(def) => format!("{} = {def}", f.name),
            None => f.name.clone(),
        })
        .collect::<Vec<String>>()
        .join(", ");
    format!("function({params}) {body}")
}

fn render_rvalue(value: &RValue) -> String {
    match value {
        RValue::Null => "NULL".to_owned(),
        RValue::Symbol(s) => s.clone(),
        RValue::StringVec(v) if v.len() == 1 => format!("\"{}\"", v[0]),
        RValue::StringVec(v) => format!(
            "c({})",
            v.iter()
                .map(|s: &String| format!("\"{s}\""))
                .collect::<Vec<String>>()
                .join(", ")
        ),
        RValue::RealVec(v) if v.len() == 1 => render_real(v[0]),
        RValue::RealVec(v) => format!(
            "c({})",
            v.iter()
                .map(|x: &f64| render_real(*x))
                .collect::<Vec<String>>()
                .join(", ")
        ),
        RValue::IntVec(v) if v.len() == 1 => render_int(v[0]),
        RValue::IntVec(v) => format!(
            "c({})",
            v.iter()
                .map(|x: &i64| render_int(*x))
                .collect::<Vec<String>>()
                .join(", ")
        ),
        RValue::Lang(items) => render_call(items),
        RValue::Pairlist(_) | RValue::Environment(_) | RValue::Other => "...".to_owned(),
    }
}

fn render_call(items: &[RValue]) -> String {
    let Some((head, args)): Option<(&RValue, &[RValue])> = items.split_first() else {
        return "()".to_owned();
    };
    let head_name: String = render_rvalue(head);
    if let Some(rendered) = render_control_flow(&head_name, args) {
        return rendered;
    }
    if let Some(rendered) = render_indexing(&head_name, args) {
        return rendered;
    }
    if args.len() == 2
        && let Some(symbol) = binary_operator(&head_name)
    {
        let spacing: &str = if tight_operator(&head_name) { "" } else { " " };
        return format!(
            "{}{spacing}{symbol}{spacing}{}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1])
        );
    }
    if args.len() == 1
        && let Some(symbol) = unary_operator(&head_name)
    {
        return format!("{symbol}{}", render_rvalue(&args[0]));
    }
    if head_name == "{" {
        let body: String = args
            .iter()
            .map(render_rvalue)
            .collect::<Vec<String>>()
            .join("; ");
        return format!("{{ {body} }}");
    }
    if head_name == "(" && args.len() == 1 {
        return format!("({})", render_rvalue(&args[0]));
    }
    let rendered_args: String = args
        .iter()
        .map(render_rvalue)
        .collect::<Vec<String>>()
        .join(", ");
    format!("{head_name}({rendered_args})")
}

fn render_control_flow(head: &str, args: &[RValue]) -> Option<String> {
    match (head, args.len()) {
        ("if", 2) => Some(format!(
            "if ({}) {}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1])
        )),
        ("if", 3) => Some(format!(
            "if ({}) {} else {}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1]),
            render_rvalue(&args[2])
        )),
        ("for", 3) => Some(format!(
            "for ({} in {}) {}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1]),
            render_rvalue(&args[2])
        )),
        ("while", 2) => Some(format!(
            "while ({}) {}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1])
        )),
        ("repeat", 1) => Some(format!("repeat {}", render_rvalue(&args[0]))),
        ("break" | "next", 0) => Some(head.to_owned()),
        ("function", 2 | 3) => Some(format!(
            "function({}) {}",
            render_formal_pairlist(&args[0]),
            render_rvalue(&args[1])
        )),
        _ => None,
    }
}

fn render_formal_pairlist(value: &RValue) -> String {
    let RValue::Pairlist(pairs) = value else {
        return String::new();
    };
    pairs
        .iter()
        .map(|(tag, default): &(Option<String>, RValue)| {
            let name: &str = tag.as_deref().unwrap_or_default();
            match formal_default(default) {
                Some(rendered) => format!("{name} = {rendered}"),
                None => name.to_owned(),
            }
        })
        .collect::<Vec<String>>()
        .join(", ")
}

fn render_indexing(head: &str, args: &[RValue]) -> Option<String> {
    let (target, rest): (&RValue, &[RValue]) = args.split_first()?;
    let subscripts: String = rest
        .iter()
        .map(render_rvalue)
        .collect::<Vec<String>>()
        .join(", ");
    match head {
        "[" => Some(format!("{}[{subscripts}]", render_rvalue(target))),
        "[[" => Some(format!("{}[[{subscripts}]]", render_rvalue(target))),
        "$" | "@" => Some(format!("{}{head}{subscripts}", render_rvalue(target))),
        _ => None,
    }
}

const fn tight_operator(name: &str) -> bool {
    matches!(name.as_bytes(), b":" | b"^")
}

fn unary_operator(name: &str) -> Option<&'static str> {
    match name {
        "-" => Some("-"),
        "+" => Some("+"),
        "!" => Some("!"),
        "~" => Some("~"),
        _ => None,
    }
}

fn binary_operator(name: &str) -> Option<&'static str> {
    match name {
        "+" => Some("+"),
        "-" => Some("-"),
        "*" => Some("*"),
        "/" => Some("/"),
        "^" => Some("^"),
        ":" => Some(":"),
        "%%" => Some("%%"),
        "%/%" => Some("%/%"),
        "%in%" => Some("%in%"),
        "%o%" => Some("%o%"),
        "%*%" => Some("%*%"),
        "==" => Some("=="),
        "!=" => Some("!="),
        "<" => Some("<"),
        ">" => Some(">"),
        "<=" => Some("<="),
        ">=" => Some(">="),
        "&" => Some("&"),
        "|" => Some("|"),
        "&&" => Some("&&"),
        "||" => Some("||"),
        "<-" => Some("<-"),
        "<<-" => Some("<<-"),
        "=" => Some("="),
        "~" => Some("~"),
        _ => None,
    }
}

fn render_real(x: f64) -> String {
    if x.to_bits() == R_NA_REAL_BITS {
        return "NA".to_owned();
    }
    if x.is_nan() {
        return "NaN".to_owned();
    }
    if x.is_infinite() {
        return if x.is_sign_negative() {
            "-Inf".to_owned()
        } else {
            "Inf".to_owned()
        };
    }
    if x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{x:.0}")
    } else {
        format!("{x}")
    }
}

fn render_int(x: i64) -> String {
    if x == i64::from(i32::MIN) {
        "NA".to_owned()
    } else {
        format!("{x}L")
    }
}

fn sxp_label(sxp: u32) -> String {
    match sxp {
        NILVALUE_SXP | NILSXP => "NULL",
        SYMSXP => "symbol",
        LISTSXP => "pairlist",
        CLOSXP => "closure",
        ENVSXP => "environment",
        PROMSXP => "promise",
        LANGSXP => "language",
        SPECIALSXP => "special",
        BUILTINSXP => "builtin",
        CHARSXP => "char",
        LGLSXP => "logical",
        INTSXP => "integer",
        REALSXP => "double",
        CPLXSXP => "complex",
        STRSXP => "character",
        DOTSXP => "...",
        ANYSXP => "any",
        VECSXP => "list",
        EXPRSXP => "expression",
        BCODESXP => "bytecode",
        EXTPTRSXP => "externalptr",
        WEAKREFSXP => "weakref",
        RAWSXP => "raw",
        S4SXP => "S4",
        GLOBALENV_SXP | EMPTYENV_SXP | BASEENV_SXP => "environment",
        BASENAMESPACE_SXP | NAMESPACESXP => "namespace",
        PACKAGESXP => "package",
        UNBOUNDVALUE_SXP => "unbound",
        MISSINGARG_SXP => "missing",
        REF_SXP => "ref",
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
    fn rejects_string_payload_above_materialization_cap() {
        let payload: Vec<u8> = vec![b'a'; 65_537usize];
        let mut bytes: Vec<u8> = xdr_header();
        bytes.extend_from_slice(&CHARSXP.to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as i32).to_be_bytes());
        bytes.extend_from_slice(&payload);

        let result: Result<RdsObject> = read_rds(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_rvalue_vector_above_materialization_cap() {
        let count: usize = 4_097usize;
        let mut bytes: Vec<u8> = Vec::with_capacity(8usize.saturating_add(count * 8usize));
        bytes.extend_from_slice(&REALSXP.to_be_bytes());
        bytes.extend_from_slice(&(count as i32).to_be_bytes());
        for _ in 0..count {
            bytes.extend_from_slice(&0f64.to_bits().to_be_bytes());
        }
        let mut reader: StreamReader<'_> =
            StreamReader::new(&bytes, 0usize, RdsEncoding::Xdr).expect("reader");
        let mut walk: Walk = Walk::empty();

        let result: Result<RValue> = read_rvalue(&mut reader, &mut walk, 0usize);
        assert!(result.is_err());
    }

    #[test]
    fn rejects_node_count_above_cap() {
        const NODE_CAP: usize = 65_536;
        let payload_bytes: usize = NODE_CAP.saturating_mul(4usize);
        let mut bytes: Vec<u8> = Vec::with_capacity(22usize.saturating_add(payload_bytes));
        bytes.extend_from_slice(b"X\n");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&VECSXP.to_be_bytes());
        let declared_nodes: i32 = i32::try_from(NODE_CAP).expect("cap fits i32");
        bytes.extend_from_slice(&declared_nodes.to_be_bytes());
        let nodes: Vec<u8> = NILSXP.to_be_bytes().repeat(NODE_CAP);
        bytes.extend_from_slice(&nodes);

        let result: Result<RdsObject> = read_rds(&bytes);
        assert!(matches!(result, Err(Error::RdsNodeLimitExceeded(limit)) if limit == NODE_CAP));
    }

    #[test]
    fn accepts_node_count_at_cap() {
        let child_count: usize = MAX_NODES.saturating_sub(1usize);
        let payload_bytes: usize = child_count.saturating_mul(4usize);
        let mut bytes: Vec<u8> = Vec::with_capacity(22usize.saturating_add(payload_bytes));
        bytes.extend_from_slice(b"X\n");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&VECSXP.to_be_bytes());
        let declared_nodes: i32 = i32::try_from(child_count).expect("cap fits i32");
        bytes.extend_from_slice(&declared_nodes.to_be_bytes());
        let nodes: Vec<u8> = NILSXP.to_be_bytes().repeat(child_count);
        bytes.extend_from_slice(&nodes);

        let result: Result<RdsObject> = read_rds(&bytes);
        assert!(matches!(result, Ok(RdsObject { node_count, .. }) if node_count == MAX_NODES));
    }

    #[test]
    fn xdr_truncation_reports_cursor_offset_and_width() {
        assert!(matches!(
            read_rds(b"X\n"),
            Err(Error::RdsTruncated {
                offset: 2,
                needed: 4,
                had: 0,
            })
        ));
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

    fn xdr_header() -> Vec<u8> {
        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"X\n");
        out.extend_from_slice(&3i32.to_be_bytes());
        out.extend_from_slice(&0x04_05_00i32.to_be_bytes());
        out.extend_from_slice(&0x03_05_00i32.to_be_bytes());
        out.extend_from_slice(&5i32.to_be_bytes());
        out.extend_from_slice(b"UTF-8");
        out
    }

    #[test]
    fn bounded_capacity_caps_untrusted_length_to_buffer() {
        let buffer: [u8; 16] = [0u8; 16];
        let reader: StreamReader<'_> = StreamReader::new(&buffer, 0, RdsEncoding::Xdr).unwrap();
        let bounded_f64: usize = reader.bounded_capacity(i32::MAX as usize, 8);
        let bounded_i32: usize = reader.bounded_capacity(i32::MAX as usize, 4);
        let bounded_str: usize = reader.bounded_capacity(i32::MAX as usize, 8);
        assert!(bounded_f64 <= 16 / 8 + 1);
        assert!(bounded_i32 <= 16 / 4 + 1);
        assert!(bounded_str <= 16 / 8 + 1);
        assert!(bounded_f64 < i32::MAX as usize);
    }

    #[test]
    fn bounded_capacity_preserves_legitimate_length() {
        let buffer: [u8; 4096] = [0u8; 4096];
        let reader: StreamReader<'_> = StreamReader::new(&buffer, 0, RdsEncoding::Xdr).unwrap();
        assert_eq!(reader.bounded_capacity(3, 8), 3);
        assert_eq!(reader.bounded_capacity(0, 8), 0);
    }

    #[test]
    fn skip_rejects_overflowing_count() {
        let buffer: [u8; 0] = [];
        let mut reader: StreamReader<'_> = StreamReader::new(&buffer, 0, RdsEncoding::Xdr).unwrap();
        assert!(reader.skip_raw(usize::MAX).is_err());
    }

    fn closure_with_oversized_vector(sxp: u32) -> Vec<u8> {
        let mut bytes: Vec<u8> = xdr_header();
        bytes.extend_from_slice(&CLOSXP.to_be_bytes());
        bytes.extend_from_slice(&sxp.to_be_bytes());
        bytes.extend_from_slice(&i32::MAX.to_be_bytes());
        bytes
    }

    #[test]
    fn rejects_oversized_real_vector_without_oom() {
        assert!(read_rds(&closure_with_oversized_vector(REALSXP)).is_err());
    }

    #[test]
    fn rejects_oversized_int_vector_without_oom() {
        assert!(read_rds(&closure_with_oversized_vector(INTSXP)).is_err());
    }

    #[test]
    fn rejects_oversized_string_vector_without_oom() {
        assert!(read_rds(&closure_with_oversized_vector(STRSXP)).is_err());
    }
}
