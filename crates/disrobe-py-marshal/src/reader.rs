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
        let dump = self.dump.as_mut()?;
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
            b'c' => Ok(Object::Code(Box::new(self.read_code_object(depth + 1)?))),
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
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let s: &str = core::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 {
            offset: self.pos - len,
            source,
        })?;
        Ok(Object::Float(s.parse::<f64>().unwrap_or(0.0)))
    }

    fn decode_ascii_complex(&mut self) -> Result<Object> {
        let len: usize = self.read_byte()? as usize;
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let s: &str = core::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 {
            offset: self.pos - len,
            source,
        })?;
        let mut parts: core::str::SplitWhitespace<'_> = s.split_whitespace();
        let real: f64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0.0);
        let imag: f64 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0.0);
        Ok(Object::Complex { real, imag })
    }

    fn decode_bytes_obj(&mut self) -> Result<Object> {
        let len: u32 = self.read_u32()?;
        if len > MAX_LEN {
            return Err(Error::LengthOverflow(len));
        }
        Ok(Object::Bytes(self.read_bytes(len as usize)?.to_vec()))
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
        let mut v: Vec<Object> = Vec::with_capacity(n);
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
        let mut digits: Vec<u16> = Vec::with_capacity(digit_count as usize);
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
                Ok(value.into_bytes())
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
                        Ok(value.into_bytes())
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

fn object_preview(obj: &Object) -> String {
    match obj {
        Object::Int(n) => n.to_string(),
        Object::Int64(n) => n.to_string(),
        Object::Float(f) => format!("{f}"),
        Object::Complex { real, imag } => format!("{real}+{imag}i"),
        Object::Long(big) => format!("sign={} digits={}", big.sign, big.digits.len()),
        Object::Bytes(b) => format!("len={}", b.len()),
        Object::String { value, .. } | Object::ShortAscii { value, .. } => preview_str(value),
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
#[allow(clippy::expect_used, clippy::unwrap_used)]
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
}
