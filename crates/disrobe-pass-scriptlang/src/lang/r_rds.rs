use serde::Serialize;

use disrobe_bytes::{ByteReadError, ByteReader};

use crate::error::{Error, Result};

const MAX_DEPTH: usize = 256usize;
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
    reader: ByteReader<'a>,
}

impl<'a> XdrReader<'a> {
    fn new(bytes: &'a [u8], pos: usize) -> Result<Self> {
        let mut reader: ByteReader<'a> = ByteReader::new(bytes);
        reader.seek(pos).map_err(Self::truncated)?;
        Ok(Self { reader })
    }

    fn truncated(error: ByteReadError) -> Error {
        Error::RdsTruncated {
            offset: error.offset,
            needed: error.needed,
            had: error.available,
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

    fn i32(&mut self) -> Result<i32> {
        self.reader.read_i32_be().map_err(Self::truncated)
    }

    fn u32(&mut self) -> Result<u32> {
        self.reader.read_u32_be().map_err(Self::truncated)
    }

    fn f64(&mut self) -> Result<f64> {
        let bits: u64 = self.reader.read_u64_be().map_err(Self::truncated)?;
        Ok(f64::from_bits(bits))
    }

    fn skip(&mut self, n: usize) -> Result<()> {
        self.reader.skip(n).map_err(Self::truncated)
    }

    fn raw_bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let out: Vec<u8> = self.reader.read_bytes(n).map_err(Self::truncated)?.to_vec();
        Ok(out)
    }

    fn string(&mut self, len: usize) -> Result<String> {
        let raw: &[u8] = self.reader.read_bytes(len).map_err(Self::truncated)?;
        let s: String = String::from_utf8_lossy(raw).into_owned();
        Ok(s)
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
            ref_table: Vec::new(),
            bc_reps: 0usize,
            node_count: 0usize,
        }
    }
}

pub fn read_rds(bytes: &[u8]) -> Result<RdsObject> {
    let encoding: RdsEncoding = detect_encoding(bytes).ok_or_else(|| {
        Error::NotRds([
            bytes.first().copied().map_or(0u8, |value: u8| value),
            bytes.get(1).copied().map_or(0u8, |value: u8| value),
        ])
    })?;
    if encoding != RdsEncoding::Xdr {
        return Err(Error::RdsFormat(bytes[0]));
    }
    let mut r: XdrReader<'_> = XdrReader::new(bytes, 2)?;
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
        node_count: walk.node_count,
    })
}

fn walk_item(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<(String, Option<usize>)> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let flags: u32 = r.u32()?;
    walk_item_body(r, w, flags, depth)
}

fn walk_item_body(
    r: &mut XdrReader<'_>,
    w: &mut Walk,
    flags: u32,
    depth: usize,
) -> Result<(String, Option<usize>)> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    w.node_count += 1;
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
            w.altrep_objects.push(altrep);
            return Ok((label, None));
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
            walk_bytecode(r, w, depth + 1)?;
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
            r.skip(count - keep)?;
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
            if has_attr {
                let s4: RdsS4Object = read_s4_slots(r, w, depth + 1)?;
                w.s4_objects.push(s4);
            } else {
                w.s4_objects.push(RdsS4Object {
                    class: None,
                    package: None,
                    slots: Vec::new(),
                });
            }
            return Ok((label, None));
        }
        ENVSXP => {
            w.ref_table.push(String::new());
            let _locked: i32 = r.i32()?;
            let enclos: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let frame_before: usize = w.symbols.len();
            let frame_bindings: Vec<String> = collect_env_frame(r, w, depth + 1)?;
            let hashed: bool = frame_bindings.is_empty();
            let hashtab_bindings: Vec<String> = collect_env_hashtab(r, w, depth + 1)?;
            let _attr: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let _ = frame_before;
            let mut bindings: Vec<String> = frame_bindings;
            bindings.extend(hashtab_bindings);
            bindings.sort_unstable();
            bindings.dedup();
            w.environments.push(RdsEnvironmentInfo {
                bindings,
                enclosing: enclos.0,
                is_hashed: hashed,
            });
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

fn read_altrep(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<RdsAltrep> {
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
        materialized,
        note,
    })
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
    r: &mut XdrReader<'_>,
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

fn read_s4_slots(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<RdsS4Object> {
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

fn collect_env_frame(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<Vec<String>> {
    let flags: u32 = r.u32()?;
    let sxp: u32 = flags & 0xFFu32;
    if sxp == NILVALUE_SXP || sxp == NILSXP {
        return Ok(Vec::new());
    }
    let value: RValue = read_rvalue_with_flags(r, w, flags, depth + 1)?;
    Ok(pairlist_tags(&value))
}

fn collect_env_hashtab(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<Vec<String>> {
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

fn walk_bytecode(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let reps: i32 = r.i32()?;
    w.bc_reps = reps.max(0) as usize;
    walk_bytecode_body(r, w, depth + 1)
}

fn walk_bytecode_body(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let _code: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
    let n: i32 = r.i32()?;
    let count: usize = n.max(0) as usize;
    for _ in 0..count {
        let type_hint: u32 = r.u32()?;
        match type_hint {
            BCODESXP => walk_bytecode_body(r, w, depth + 1)?,
            LANGSXP | LISTSXP | BCREPDEF | BCREPREF | ATTRLANGSXP | ATTRLISTSXP => {
                walk_bclang(r, w, type_hint, depth + 1)?;
            }
            _ => {
                let _const: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
        }
    }
    Ok(())
}

fn walk_bclang(r: &mut XdrReader<'_>, w: &mut Walk, type_hint: u32, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    if type_hint == BCREPREF {
        let _index: i32 = r.i32()?;
        return Ok(());
    }
    let mut effective: u32 = type_hint;
    if effective == BCREPDEF {
        let _pos: i32 = r.i32()?;
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
    match effective {
        LANGSXP | LISTSXP => {
            if has_attr {
                let _attr: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            }
            let _tag: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            let car_hint: u32 = r.u32()?;
            walk_bclang_child(r, w, car_hint, depth + 1)?;
            let cdr_hint: u32 = r.u32()?;
            walk_bclang_child(r, w, cdr_hint, depth + 1)?;
            Ok(())
        }
        _ => {
            let _walked: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            Ok(())
        }
    }
}

fn walk_bclang_child(
    r: &mut XdrReader<'_>,
    w: &mut Walk,
    type_hint: u32,
    depth: usize,
) -> Result<()> {
    match type_hint {
        BCREPREF | BCREPDEF | LANGSXP | LISTSXP | ATTRLANGSXP | ATTRLISTSXP => {
            walk_bclang(r, w, type_hint, depth + 1)
        }
        _ => {
            let _walked: (String, Option<usize>) = walk_item(r, w, depth + 1)?;
            Ok(())
        }
    }
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

fn recurse_closure(
    r: &mut XdrReader<'_>,
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

fn read_rvalue(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<RValue> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    let flags: u32 = r.u32()?;
    read_rvalue_with_flags(r, w, flags, depth)
}

fn read_rvalue_with_flags(
    r: &mut XdrReader<'_>,
    w: &mut Walk,
    flags: u32,
    depth: usize,
) -> Result<RValue> {
    if depth > MAX_DEPTH {
        return Err(Error::RdsDepthExceeded(MAX_DEPTH));
    }
    w.node_count += 1;
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
            let mut out: Vec<f64> = Vec::with_capacity(r.bounded_capacity(count, 8));
            for _ in 0..count {
                out.push(r.f64()?);
            }
            Ok(RValue::RealVec(out))
        }
        LGLSXP | INTSXP => {
            let n: i32 = r.i32()?;
            let count: usize = n.max(0) as usize;
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
        BCODESXP => {
            walk_bytecode(r, w, depth + 1)?;
            Ok(RValue::Other)
        }
        _ => {
            let mut tmp: Walk = Walk {
                ref_table: std::mem::take(&mut w.ref_table),
                bc_reps: w.bc_reps,
                ..Walk::empty()
            };
            rewind_and_walk(r, &mut tmp, flags, sxp, has_attr, has_tag, depth)?;
            w.ref_table = tmp.ref_table;
            w.bc_reps = tmp.bc_reps;
            w.symbols.append(&mut tmp.symbols);
            w.string_values.append(&mut tmp.string_values);
            w.closures.append(&mut tmp.closures);
            Ok(RValue::Other)
        }
    }
}

fn rewind_and_walk(
    r: &mut XdrReader<'_>,
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
            r.skip((n.max(0) as usize).saturating_mul(16))?;
        }
        RAWSXP => {
            let n: i32 = r.i32()?;
            r.skip(n.max(0) as usize)?;
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

fn read_environment(r: &mut XdrReader<'_>, w: &mut Walk, depth: usize) -> Result<RdsEnvironment> {
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

fn ref_index(flags: u32, r: &mut XdrReader<'_>) -> Result<usize> {
    let packed: u32 = flags >> 8;
    let index: u32 = if packed == 0 { r.u32()? } else { packed };
    Ok((index as usize).saturating_sub(1))
}

fn read_in_stringvec(r: &mut XdrReader<'_>, w: &mut Walk) -> Result<Vec<String>> {
    let _leading: i32 = r.i32()?;
    let n: i32 = r.i32()?;
    let count: usize = n.max(0) as usize;
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
        RValue::IntVec(v) if v.len() == 1 => format!("{}L", v[0]),
        RValue::IntVec(v) => format!(
            "c({})",
            v.iter()
                .map(|x: &i64| format!("{x}L"))
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
    if let Some(symbol) = binary_operator(&head_name)
        && args.len() == 2
    {
        return format!(
            "{} {symbol} {}",
            render_rvalue(&args[0]),
            render_rvalue(&args[1])
        );
    }
    if head_name == "{" {
        let body: String = args
            .iter()
            .map(render_rvalue)
            .collect::<Vec<String>>()
            .join("; ");
        return format!("{{ {body} }}");
    }
    let rendered_args: String = args
        .iter()
        .map(render_rvalue)
        .collect::<Vec<String>>()
        .join(", ");
    format!("{head_name}({rendered_args})")
}

fn binary_operator(name: &str) -> Option<&'static str> {
    match name {
        "+" => Some("+"),
        "-" => Some("-"),
        "*" => Some("*"),
        "/" => Some("/"),
        "^" => Some("^"),
        "%%" => Some("%%"),
        "==" => Some("=="),
        "!=" => Some("!="),
        "<" => Some("<"),
        ">" => Some(">"),
        "<=" => Some("<="),
        ">=" => Some(">="),
        "&&" => Some("&&"),
        "||" => Some("||"),
        "<-" => Some("<-"),
        _ => None,
    }
}

fn render_real(x: f64) -> String {
    if x.fract() == 0.0 && x.abs() < 1e15 {
        format!("{x:.0}")
    } else {
        format!("{x}")
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
        DOTSXP => "dots",
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
        let reader: XdrReader<'_> = XdrReader::new(&buffer, 0).unwrap();
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
        let reader: XdrReader<'_> = XdrReader::new(&buffer, 0).unwrap();
        assert_eq!(reader.bounded_capacity(3, 8), 3);
        assert_eq!(reader.bounded_capacity(0, 8), 0);
    }

    #[test]
    fn skip_rejects_overflowing_count() {
        let buffer: [u8; 0] = [];
        let mut reader: XdrReader<'_> = XdrReader::new(&buffer, 0).unwrap();
        assert!(reader.skip(usize::MAX).is_err());
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
