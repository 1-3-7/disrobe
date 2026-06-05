use indexmap::IndexMap;

use crate::error::{Error, Result};
use crate::object::{BigInt, CodeEra, CodeObject, Object};
use crate::reftable::{RefEntry, RefKind, RefTableDump};
use crate::version::PyVersion;

const FLAG_REF: u8 = 0x80;
const TAG_MASK: u8 = 0x7F;
const MAX_DEPTH: usize = 256;
const MAX_LONG_DIGITS: u32 = 1 << 24;
const MAX_LEN: u32 = 1 << 28;
const MAX_REFS: usize = 1 << 20;
const MAX_DICT_ENTRIES: usize = 1 << 20;
const CO_PYARMOR_OBFUSCATED: i32 = 0x2000_0000;

pub fn load(data: &[u8], version: PyVersion) -> Result<Object> {
    let mut r: Reader<'_> = Reader::new(data, version, false);
    r.read_object(0)
}

pub fn load_with_reftable(data: &[u8], version: PyVersion) -> Result<(Object, RefTableDump)> {
    let mut r: Reader<'_> = Reader::new(data, version, true);
    let obj: Object = r.read_object(0)?;
    let mut dump: RefTableDump = r.dump.take().unwrap_or_else(RefTableDump::empty);
    dump.finalize(r.pos);
    Ok((obj, dump))
}

#[derive(Debug)]
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    refs: Vec<Object>,
    interned_strings: Vec<String>,
    version: PyVersion,
    dump: Option<RefTableDump>,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8], version: PyVersion, trace: bool) -> Self {
        Self {
            buf,
            pos: 0,
            refs: Vec::new(),
            interned_strings: Vec::new(),
            version,
            dump: if trace {
                Some(RefTableDump::empty())
            } else {
                None
            },
        }
    }

    fn read_byte(&mut self) -> Result<u8> {
        let b: u8 = *self
            .buf
            .get(self.pos)
            .ok_or(Error::Eof { offset: self.pos })?;
        self.pos += 1;
        Ok(b)
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        let end: usize = self
            .pos
            .checked_add(n)
            .ok_or(Error::Eof { offset: self.pos })?;
        if end > self.buf.len() {
            return Err(Error::Eof { offset: self.pos });
        }
        let slice: &'a [u8] = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn read_i16(&mut self) -> Result<i32> {
        let b: &'a [u8] = self.read_bytes(2)?;
        Ok(i32::from(i16::from_le_bytes([b[0], b[1]])))
    }

    fn read_i32(&mut self) -> Result<i32> {
        let b: &'a [u8] = self.read_bytes(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let b: &'a [u8] = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn read_i64(&mut self) -> Result<i64> {
        let b: &'a [u8] = self.read_bytes(8)?;
        Ok(i64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn read_f64(&mut self) -> Result<f64> {
        let b: &'a [u8] = self.read_bytes(8)?;
        Ok(f64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    fn alloc_ref(&mut self) -> Result<u32> {
        let len: usize = self.refs.len();
        if len >= MAX_REFS {
            let truncated: u32 = u32::try_from(len).unwrap_or(u32::MAX);
            return Err(Error::LengthOverflow(truncated));
        }
        let idx: u32 = u32::try_from(len).unwrap_or(u32::MAX);
        self.refs.push(Object::Null);
        Ok(idx)
    }

    fn set_ref(&mut self, idx: u32, obj: Object) {
        if let Some(slot) = self.refs.get_mut(idx as usize) {
            *slot = obj;
        }
    }

    fn read_object(&mut self, depth: usize) -> Result<Object> {
        if depth >= MAX_DEPTH {
            return Err(Error::DepthLimit(MAX_DEPTH));
        }
        let start: usize = self.pos;
        let head: u8 = self.read_byte()?;
        let tag: u8 = head & TAG_MASK;
        let has_ref: bool = head & FLAG_REF != 0;
        let ref_idx: Option<u32> = if has_ref {
            Some(self.alloc_ref()?)
        } else {
            None
        };
        let entry_slot: Option<usize> = self.open_trace(ref_idx, start, depth, tag);
        let mut ref_preview_override: Option<u32> = None;
        let obj: Object = self.decode_tag(tag, depth, &mut ref_preview_override)?;
        if let Some(idx) = ref_idx {
            self.set_ref(idx, obj.clone());
        }
        self.close_trace(entry_slot, start, &obj, ref_preview_override);
        Ok(obj)
    }

    fn open_trace(
        &mut self,
        ref_idx: Option<u32>,
        start: usize,
        depth: usize,
        tag: u8,
    ) -> Option<usize> {
        let dump: &mut RefTableDump = self.dump.as_mut()?;
        dump.entries.push(RefEntry {
            index: ref_idx.unwrap_or(u32::MAX),
            byte_offset: start,
            byte_length: 0,
            depth: u16::try_from(depth).unwrap_or(u16::MAX),
            tag,
            kind: RefKind::from_tag(tag),
            preview: String::new(),
        });
        Some(dump.entries.len() - 1)
    }

    fn close_trace(
        &mut self,
        entry_slot: Option<usize>,
        start: usize,
        obj: &Object,
        ref_override: Option<u32>,
    ) {
        let Some(slot): Option<usize> = entry_slot else {
            return;
        };
        let pos: usize = self.pos;
        let Some(dump): Option<&mut RefTableDump> = self.dump.as_mut() else {
            return;
        };
        let Some(entry): Option<&mut RefEntry> = dump.entries.get_mut(slot) else {
            return;
        };
        entry.byte_length = pos.saturating_sub(start);
        entry.preview = if let Some(idx) = ref_override {
            entry.kind = RefKind::Ref;
            idx.to_string()
        } else {
            object_preview(obj)
        };
    }

    fn decode_tag(
        &mut self,
        tag: u8,
        depth: usize,
        ref_override: &mut Option<u32>,
    ) -> Result<Object> {
        match tag {
            b'0' => Ok(Object::Null),
            b'N' => Ok(Object::None),
            b'S' => Ok(Object::StopIteration),
            b'.' => Ok(Object::Ellipsis),
            b'F' => Ok(Object::False),
            b'T' => Ok(Object::True),
            b'i' => Ok(Object::Int(self.read_i32()?)),
            b'I' => Ok(Object::Int64(self.read_i64()?)),
            b'g' => Ok(Object::Float(self.read_f64()?)),
            b'f' => self.decode_ascii_float(),
            b'x' => self.decode_ascii_complex(),
            b'y' => Ok(Object::Complex {
                real: self.read_f64()?,
                imag: self.read_f64()?,
            }),
            b'l' => self.read_long(),
            b's' if self.version.major < 3 => self.decode_legacy_string_obj(),
            b's' => self.decode_bytes_obj(),
            b'u' | b't' | b'a' | b'A' => self.decode_string_obj(tag),
            b'z' | b'Z' => self.decode_short_ascii(tag),
            b'(' | b'[' | b'<' | b'>' => self.decode_collection(tag, depth),
            b')' => {
                let len: usize = self.read_byte()? as usize;
                Ok(Object::Tuple(self.read_n_objects(len, depth + 1)?))
            }
            b'{' => Ok(Object::Dict(self.read_dict(depth + 1)?)),
            b'}' => Ok(Object::FrozenDict(self.read_dict(depth + 1)?)),
            b':' => {
                let lower: Object = self.read_object(depth + 1)?;
                let upper: Object = self.read_object(depth + 1)?;
                let stride: Object = self.read_object(depth + 1)?;
                Ok(Object::Tuple(vec![lower, upper, stride]))
            }
            b'c' | b'C' => Ok(Object::Code(Box::new(self.read_code_object(depth + 1)?))),
            b'r' => self.decode_back_ref(ref_override),
            b'R' => self.decode_string_ref(ref_override),
            _ => Err(Error::UnknownTag {
                tag,
                offset: self.pos - 1,
            }),
        }
    }

    fn decode_string_ref(&mut self, ref_override: &mut Option<u32>) -> Result<Object> {
        let idx: u32 = self.read_u32()?;
        let resolved: String =
            self.interned_strings
                .get(idx as usize)
                .cloned()
                .ok_or(Error::RefOutOfBounds {
                    index: idx,
                    len: self.interned_strings.len(),
                })?;
        *ref_override = Some(idx);
        Ok(Object::String {
            value: resolved,
            interned: true,
        })
    }

    fn decode_ascii_float(&mut self) -> Result<Object> {
        let len: usize = self.read_byte()? as usize;
        let offset: usize = self.pos;
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let s: &str = core::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 {
            offset: self.pos - len,
            source,
        })?;
        let value: f64 = s.parse::<f64>().map_err(|_| Error::InvalidAsciiFloat {
            literal: s.to_owned(),
            offset,
        })?;
        Ok(Object::Float(value))
    }

    fn decode_ascii_complex(&mut self) -> Result<Object> {
        let len: usize = self.read_byte()? as usize;
        let offset: usize = self.pos;
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let s: &str = core::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 {
            offset: self.pos - len,
            source,
        })?;
        let mut parts: core::str::SplitWhitespace<'_> = s.split_whitespace();
        let parse_part = |part: Option<&str>| -> Result<f64> {
            let raw: &str = part.ok_or_else(|| Error::InvalidAsciiFloat {
                literal: s.to_owned(),
                offset,
            })?;
            raw.parse::<f64>().map_err(|_| Error::InvalidAsciiFloat {
                literal: s.to_owned(),
                offset,
            })
        };
        let real: f64 = parse_part(parts.next())?;
        let imag: f64 = parse_part(parts.next())?;
        Ok(Object::Complex { real, imag })
    }

    fn decode_bytes_obj(&mut self) -> Result<Object> {
        let len: u32 = self.read_u32()?;
        if len > MAX_LEN {
            return Err(Error::LengthOverflow(len));
        }
        Ok(Object::Bytes(self.read_bytes(len as usize)?.to_vec()))
    }

    fn decode_legacy_string_obj(&mut self) -> Result<Object> {
        let len: u32 = self.read_u32()?;
        if len > MAX_LEN {
            return Err(Error::LengthOverflow(len));
        }
        let bytes: &'a [u8] = self.read_bytes(len as usize)?;
        let value: String = core::str::from_utf8(bytes).map_or_else(
            |_| bytes.iter().map(|&b| b as char).collect(),
            ToOwned::to_owned,
        );
        Ok(Object::String {
            value,
            interned: false,
        })
    }

    fn decode_string_obj(&mut self, tag: u8) -> Result<Object> {
        let len: u32 = self.read_u32()?;
        if len > MAX_LEN {
            return Err(Error::LengthOverflow(len));
        }
        let bytes: &'a [u8] = self.read_bytes(len as usize)?;
        let value: String = core::str::from_utf8(bytes)
            .map_err(|source| Error::InvalidUtf8 {
                offset: self.pos - len as usize,
                source,
            })?
            .to_owned();
        let interned: bool = matches!(tag, b't' | b'A');
        if interned {
            self.interned_strings.push(value.clone());
        }
        if tag == b'u' && self.version.major < 3 {
            return Ok(Object::Unicode { value, interned });
        }
        Ok(Object::String { value, interned })
    }

    fn decode_short_ascii(&mut self, tag: u8) -> Result<Object> {
        let len: usize = self.read_byte()? as usize;
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let value: String = core::str::from_utf8(bytes)
            .map_err(|source| Error::InvalidUtf8 {
                offset: self.pos - len,
                source,
            })?
            .to_owned();
        let interned: bool = tag == b'Z';
        if interned {
            self.interned_strings.push(value.clone());
        }
        Ok(Object::ShortAscii { value, interned })
    }

    fn decode_collection(&mut self, tag: u8, depth: usize) -> Result<Object> {
        let len: u32 = self.read_u32()?;
        if len > MAX_LEN {
            return Err(Error::LengthOverflow(len));
        }
        let items: Vec<Object> = self.read_n_objects(len as usize, depth + 1)?;
        Ok(match tag {
            b'(' => Object::Tuple(items),
            b'[' => Object::List(items),
            b'<' => Object::Set(items),
            b'>' => Object::FrozenSet(items),
            _ => Object::Null,
        })
    }

    fn decode_back_ref(&mut self, ref_override: &mut Option<u32>) -> Result<Object> {
        let idx: u32 = self.read_u32()?;
        let resolved: Object =
            self.refs
                .get(idx as usize)
                .cloned()
                .ok_or(Error::RefOutOfBounds {
                    index: idx,
                    len: self.refs.len(),
                })?;
        *ref_override = Some(idx);
        Ok(resolved)
    }

    fn read_n_objects(&mut self, n: usize, depth: usize) -> Result<Vec<Object>> {
        let mut v: Vec<Object> = Vec::with_capacity(n.min(self.remaining()));
        for _ in 0..n {
            v.push(self.read_object(depth)?);
        }
        Ok(v)
    }

    fn read_dict(&mut self, depth: usize) -> Result<IndexMap<Object, Object>> {
        let mut map: IndexMap<Object, Object> = IndexMap::new();
        loop {
            if map.len() >= MAX_DICT_ENTRIES {
                let truncated: u32 = u32::try_from(map.len()).unwrap_or(u32::MAX);
                return Err(Error::LengthOverflow(truncated));
            }
            let key: Object = self.read_object(depth)?;
            if matches!(key, Object::Null) {
                break;
            }
            let val: Object = self.read_object(depth)?;
            map.insert(key, val);
        }
        Ok(map)
    }

    fn read_long(&mut self) -> Result<Object> {
        let n_signed: i32 = self.read_i32()?;
        let sign: i8 = match n_signed.cmp(&0) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Equal => 0,
            core::cmp::Ordering::Greater => 1,
        };
        let digit_count: u32 = n_signed.unsigned_abs();
        if digit_count > MAX_LONG_DIGITS {
            return Err(Error::LongDigitOverflow(digit_count));
        }
        let capacity: usize = (digit_count as usize).min(self.remaining() / 2);
        let mut digits: Vec<u16> = Vec::with_capacity(capacity);
        for _ in 0..digit_count {
            let b: &'a [u8] = self.read_bytes(2)?;
            digits.push(u16::from_le_bytes([b[0], b[1]]));
        }
        Ok(Object::Long(BigInt { sign, digits }))
    }

    fn read_code_object(&mut self, depth: usize) -> Result<CodeObject> {
        let era: CodeEra = crate::object::code_era_for(self.version);
        let mut co: CodeObject = CodeObject::new(era);

        match era {
            CodeEra::Py10to12 => {
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
            }
            CodeEra::Py13to14 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
            }
            CodeEra::Py15to20 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.stacksize = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i16()?;
                co.lnotab = self.read_bytes_obj(depth)?;
            }
            CodeEra::Py21to22 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.stacksize = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.freevars = self.read_tuple(depth)?;
                co.cellvars = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i16()?;
                co.lnotab = self.read_bytes_obj(depth)?;
            }
            CodeEra::Py27 => {
                co.argcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.freevars = self.read_tuple(depth)?;
                co.cellvars = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj(depth)?;
            }
            CodeEra::Py30to37 => {
                co.argcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.freevars = self.read_tuple(depth)?;
                co.cellvars = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj(depth)?;
                co.pyarmor_trailer = self.consume_pyarmor_trailer_if_present(co.flags)?;
            }
            CodeEra::Py38to310 => {
                co.argcount = self.read_i32()?;
                co.posonlyargcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.varnames = self.read_tuple(depth)?;
                co.freevars = self.read_tuple(depth)?;
                co.cellvars = self.read_tuple(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj(depth)?;
                co.pyarmor_trailer = self.consume_pyarmor_trailer_if_present(co.flags)?;
            }
            CodeEra::Py311Plus => {
                co.argcount = self.read_i32()?;
                co.posonlyargcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj(depth)?;
                co.consts = self.read_tuple(depth)?;
                co.names = self.read_tuple(depth)?;
                co.localsplusnames = self.read_tuple(depth)?;
                co.localspluskinds = self.read_bytes_obj(depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.qualname = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.linetable = self.read_bytes_obj(depth)?;
                co.exceptiontable = self.read_bytes_obj(depth)?;
                co.pyarmor_trailer = self.consume_pyarmor_trailer_if_present(co.flags)?;
            }
        }
        Ok(co)
    }

    fn consume_pyarmor_trailer_if_present(&mut self, flags: i32) -> Result<Vec<u8>> {
        if flags & CO_PYARMOR_OBFUSCATED == 0 {
            return Ok(Vec::new());
        }
        let extra_len: usize = self.read_byte()? as usize;
        if extra_len == 0 {
            return Ok(Vec::new());
        }
        let end: usize = self
            .pos
            .checked_add(extra_len)
            .ok_or(Error::Eof { offset: self.pos })?;
        if end > self.buf.len() {
            return Err(Error::Eof { offset: self.pos });
        }
        let bytes: Vec<u8> = self.buf[self.pos..end].to_vec();
        self.pos = end;
        Ok(bytes)
    }

    fn read_bytes_obj(&mut self, depth: usize) -> Result<Vec<u8>> {
        match self.read_object(depth)? {
            Object::Bytes(b) => Ok(b),
            Object::String { value, .. } | Object::ShortAscii { value, .. } => {
                Ok(text_to_raw_bytes(&value))
            }
            Object::Ref(idx) => {
                let target: Object =
                    self.refs
                        .get(idx as usize)
                        .cloned()
                        .ok_or(Error::RefOutOfBounds {
                            index: idx,
                            len: self.refs.len(),
                        })?;
                match target {
                    Object::Bytes(b) => Ok(b),
                    Object::String { value, .. } | Object::ShortAscii { value, .. } => {
                        Ok(text_to_raw_bytes(&value))
                    }
                    _ => Ok(Vec::new()),
                }
            }
            _ => Ok(Vec::new()),
        }
    }

    fn read_tuple(&mut self, depth: usize) -> Result<Vec<Object>> {
        match self.read_object(depth)? {
            Object::Tuple(t) | Object::List(t) => Ok(t),
            Object::Ref(idx) => match self.refs.get(idx as usize).cloned() {
                Some(Object::Tuple(t) | Object::List(t)) => Ok(t),
                _ => Ok(Vec::new()),
            },
            _ => Ok(Vec::new()),
        }
    }
}

fn text_to_raw_bytes(value: &str) -> Vec<u8> {
    if value.chars().all(|c| (c as u32) <= 0xFF) {
        value.chars().map(|c| c as u8).collect()
    } else {
        value.as_bytes().to_vec()
    }
}

fn object_preview(obj: &Object) -> String {
    match obj {
        Object::Int(n) => n.to_string(),
        Object::Int64(n) => n.to_string(),
        Object::Float(f) => format!("{f}"),
        Object::Complex { real, imag } => format!("{real}+{imag}i"),
        Object::Long(big) => format!("sign={} digits={}", big.sign, big.digits.len()),
        Object::Bytes(b) => format!("len={}", b.len()),
        Object::String { value, .. }
        | Object::Unicode { value, .. }
        | Object::ShortAscii { value, .. } => preview_str(value),
        Object::Tuple(t) | Object::List(t) | Object::Set(t) | Object::FrozenSet(t) => {
            format!("len={}", t.len())
        }
        Object::Dict(d) | Object::FrozenDict(d) => format!("len={}", d.len()),
        Object::Code(co) => code_preview(co),
        Object::Ref(idx) => idx.to_string(),
        Object::None
        | Object::True
        | Object::False
        | Object::Ellipsis
        | Object::StopIteration
        | Object::Null => String::new(),
    }
}

fn preview_str(s: &str) -> String {
    const LIMIT: usize = 32;
    if s.len() <= LIMIT {
        s.to_owned()
    } else {
        let take: usize = s.char_indices().nth(LIMIT).map_or(s.len(), |(i, _)| i);
        format!("{}...", &s[..take])
    }
}

fn code_preview(co: &CodeObject) -> String {
    let name: String = match &co.name {
        Object::ShortAscii { value, .. } | Object::String { value, .. } => value.clone(),
        _ => String::from("<anon>"),
    };
    format!(
        "name={name} consts={} names={} code={}b",
        co.consts.len(),
        co.names.len(),
        co.code.len()
    )
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_none() {
        let obj: Object = load(b"N", PyVersion::PY312).unwrap();
        assert_eq!(obj, Object::None);
    }

    #[test]
    fn round_trip_true_false() {
        assert_eq!(load(b"T", PyVersion::PY312).unwrap(), Object::True);
        assert_eq!(load(b"F", PyVersion::PY312).unwrap(), Object::False);
    }

    #[test]
    fn read_int() {
        let data: Vec<u8> = b"i".iter().copied().chain(42i32.to_le_bytes()).collect();
        let obj: Object = load(&data, PyVersion::PY312).unwrap();
        assert_eq!(obj, Object::Int(42));
    }

    fn string_tag_payload(text: &[u8]) -> Vec<u8> {
        let mut data: Vec<u8> = vec![b's'];
        data.extend((text.len() as u32).to_le_bytes());
        data.extend_from_slice(text);
        data
    }

    #[test]
    fn legacy_string_tag_is_text_pre_three() {
        let data: Vec<u8> = string_tag_payload(b"sys");
        for version in [
            PyVersion::PY11,
            PyVersion::PY15,
            PyVersion::PY22,
            PyVersion::PY27,
        ] {
            let obj: Object = load(&data, version).unwrap();
            assert!(
                matches!(&obj, Object::String { value, interned: false } if value == "sys"),
                "py{}.{} 's' must decode as text string, got {obj:?}",
                version.major,
                version.minor
            );
        }
    }

    #[test]
    fn string_tag_is_bytes_in_three() {
        let data: Vec<u8> = string_tag_payload(b"abc");
        for version in [PyVersion::PY30, PyVersion::PY38, PyVersion::PY312] {
            let obj: Object = load(&data, version).unwrap();
            assert!(
                matches!(&obj, Object::Bytes(b) if b == b"abc"),
                "py{}.{} 's' must decode as bytes, got {obj:?}",
                version.major,
                version.minor
            );
        }
    }

    #[test]
    fn legacy_string_tag_preserves_high_bytes() {
        let data: Vec<u8> = string_tag_payload(&[0x80, 0x81, b'A']);
        let obj: Object = load(&data, PyVersion::PY22).unwrap();
        let Object::String { value, .. } = obj else {
            panic!("expected legacy string");
        };
        let recovered: Vec<u8> = text_to_raw_bytes(&value);
        assert_eq!(recovered, vec![0x80, 0x81, b'A'], "high bytes round-trip");
    }

    #[test]
    fn read_short_ascii() {
        let mut data: Vec<u8> = vec![b'z', 5];
        data.extend(b"hello");
        let obj: Object = load(&data, PyVersion::PY312).unwrap();
        assert!(matches!(
            obj,
            Object::ShortAscii { ref value, .. } if value == "hello"
        ));
    }

    #[test]
    fn unknown_tag_errors() {
        let data: Vec<u8> = vec![0x05];
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        assert!(matches!(err, Error::UnknownTag { tag: 0x05, .. }));
    }

    #[test]
    fn ascii_float_parses_valid_literal() {
        let mut data: Vec<u8> = vec![b'f', 3];
        data.extend(b"2.5");
        let obj: Object = load(&data, PyVersion::PY27).unwrap();
        assert!(matches!(obj, Object::Float(v) if (v - 2.5).abs() < 1e-9));
    }

    #[test]
    fn ascii_float_rejects_malformed_literal() {
        let mut data: Vec<u8> = vec![b'f', 3];
        data.extend(b"x.y");
        let err: Error = load(&data, PyVersion::PY27).unwrap_err();
        assert!(matches!(err, Error::InvalidAsciiFloat { .. }));
    }

    #[test]
    fn ascii_complex_rejects_malformed_literal() {
        let mut data: Vec<u8> = vec![b'x', 3];
        data.extend(b"q z");
        let err: Error = load(&data, PyVersion::PY27).unwrap_err();
        assert!(matches!(err, Error::InvalidAsciiFloat { .. }));
    }

    #[test]
    fn stringref_resolves_to_prior_interned_string() {
        let mut data: Vec<u8> = vec![b'('];
        data.extend(2u32.to_le_bytes());
        data.push(b't');
        data.extend(5u32.to_le_bytes());
        data.extend(b"hello");
        data.push(b'R');
        data.extend(0u32.to_le_bytes());
        let obj: Object = load(&data, PyVersion::PY27).unwrap();
        let items: Vec<Object> = match obj {
            Object::Tuple(items) => items,
            other => unreachable!("expected tuple, got {other:?}"),
        };
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], Object::String { value, interned: true } if value == "hello"));
        assert!(matches!(&items[1], Object::String { value, interned: true } if value == "hello"));
    }

    #[test]
    fn stringref_out_of_bounds_errors() {
        let data: Vec<u8> = {
            let mut v: Vec<u8> = vec![b'R'];
            v.extend(0u32.to_le_bytes());
            v
        };
        let err: Error = load(&data, PyVersion::PY27).unwrap_err();
        assert!(matches!(err, Error::RefOutOfBounds { .. }));
    }

    fn short(value: &str) -> Object {
        Object::ShortAscii {
            value: value.to_owned(),
            interned: false,
        }
    }

    fn synth_code(era: CodeEra) -> CodeObject {
        let mut co: CodeObject = CodeObject::new(era);
        co.argcount = 2;
        co.nlocals = 3;
        co.stacksize = 5;
        co.flags = 0x43;
        co.code = vec![0x64, 0x00, 0x53];
        co.consts = vec![Object::None, Object::Int(7)];
        co.names = vec![short("a"), short("b")];
        co.varnames = vec![short("x"), short("y"), short("z")];
        co.freevars = vec![short("fv")];
        co.cellvars = vec![short("cv")];
        co.filename = short("<synth>");
        co.name = short("<module>");
        co.firstlineno = 11;
        co.lnotab = vec![0x00, 0x01];
        co
    }

    fn marshal_round_trip(version: PyVersion) -> CodeObject {
        let era: CodeEra = crate::object::code_era_for(version);
        let original: CodeObject = synth_code(era);
        let bytes: Vec<u8> =
            crate::writer::dump(&Object::Code(Box::new(original)), version).unwrap();
        match load(&bytes, version).unwrap() {
            Object::Code(boxed) => *boxed,
            other => unreachable!("expected code object, got {other:?}"),
        }
    }

    #[test]
    fn code_era_py10to12_round_trips_minimal_fields() {
        let co: CodeObject = marshal_round_trip(PyVersion::PY11);
        assert_eq!(co.era, CodeEra::Py10to12);
        assert_eq!(co.code, vec![0x64, 0x00, 0x53]);
        assert_eq!(co.consts.len(), 2);
        assert_eq!(co.names.len(), 2);
        assert_eq!(co.name, short("<module>"));
        assert_eq!(co.argcount, 0, "no argcount field pre-1.3");
        assert!(co.varnames.is_empty(), "no varnames field pre-1.3");
    }

    #[test]
    fn code_era_py13to14_round_trips_16bit_fields() {
        let co: CodeObject = marshal_round_trip(PyVersion::PY14);
        assert_eq!(co.era, CodeEra::Py13to14);
        assert_eq!(co.argcount, 2);
        assert_eq!(co.nlocals, 3);
        assert_eq!(co.flags, 0x43);
        assert_eq!(co.varnames.len(), 3);
        assert_eq!(co.stacksize, 0, "no stacksize field pre-1.5");
        assert_eq!(co.firstlineno, 0, "no firstline field pre-1.5");
    }

    #[test]
    fn code_era_py15to20_round_trips_with_stack_and_lines() {
        for version in [PyVersion::PY15, PyVersion::PY16, PyVersion::PY20] {
            let co: CodeObject = marshal_round_trip(version);
            assert_eq!(co.era, CodeEra::Py15to20, "era for {version:?}");
            assert_eq!(co.argcount, 2);
            assert_eq!(co.stacksize, 5);
            assert_eq!(co.firstlineno, 11);
            assert_eq!(co.lnotab, vec![0x00, 0x01]);
            assert!(co.freevars.is_empty(), "no freevars pre-2.1");
        }
    }

    #[test]
    fn code_era_py21to22_round_trips_free_and_cell() {
        for version in [PyVersion::PY21, PyVersion::PY22] {
            let co: CodeObject = marshal_round_trip(version);
            assert_eq!(co.era, CodeEra::Py21to22, "era for {version:?}");
            assert_eq!(co.argcount, 2);
            assert_eq!(co.stacksize, 5);
            assert_eq!(co.freevars, vec![short("fv")]);
            assert_eq!(co.cellvars, vec![short("cv")]);
            assert_eq!(co.firstlineno, 11);
        }
    }

    #[test]
    fn code_era_py23_to_27_uses_32bit_layout() {
        for version in [PyVersion::PY23, PyVersion::PY25, PyVersion::PY27] {
            let co: CodeObject = marshal_round_trip(version);
            assert_eq!(co.era, CodeEra::Py27, "era for {version:?}");
            assert_eq!(co.argcount, 2);
            assert_eq!(co.freevars, vec![short("fv")]);
        }
    }
}
