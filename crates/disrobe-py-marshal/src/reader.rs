use disrobe_bytes::{ByteReadError, ByteReader};
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
#[cfg(not(test))]
const MAX_INTERNED_STRINGS: usize = 1 << 20;
#[cfg(test)]
const MAX_INTERNED_STRINGS: usize = 1 << 13;
#[cfg(not(test))]
const MAX_TRACE_ENTRIES: usize = 1 << 20;
#[cfg(test)]
const MAX_TRACE_ENTRIES: usize = 1 << 12;
const MAX_DICT_ENTRIES: usize = 1 << 20;
const MAX_COLLECTION_ITEMS: usize = 1 << 20;
const MAX_OBJECT_PREALLOC: usize = 1024;
const NODE_BUDGET: u64 = 8_000_000;
#[cfg(not(test))]
const BYTE_BUDGET: u64 = 512 * 1024 * 1024;
#[cfg(test)]
const BYTE_BUDGET: u64 = 1024 * 1024;
const CO_PYARMOR_OBFUSCATED: i32 = 0x2000_0000;

fn u32_saturating_from_usize(value: usize) -> u32 {
    u32::try_from(value).map_or(u32::MAX, |converted: u32| converted)
}

fn u16_saturating_from_usize(value: usize) -> u16 {
    u16::try_from(value).map_or(u16::MAX, |converted: u16| converted)
}

fn object_node_count_capped(obj: &Object, cap: u64) -> u64 {
    fn walk(obj: &Object, cap: u64, acc: &mut u64) {
        if *acc >= cap {
            return;
        }
        *acc += 1;
        match obj {
            Object::Tuple(items)
            | Object::List(items)
            | Object::Set(items)
            | Object::FrozenSet(items) => {
                for item in items {
                    if *acc >= cap {
                        return;
                    }
                    walk(item, cap, acc);
                }
            }
            Object::Dict(map) | Object::FrozenDict(map) => {
                for (k, v) in map {
                    if *acc >= cap {
                        return;
                    }
                    walk(k, cap, acc);
                    walk(v, cap, acc);
                }
            }
            Object::Slice { lower, upper, step } => {
                walk(lower, cap, acc);
                walk(upper, cap, acc);
                walk(step, cap, acc);
            }
            Object::Code(co) => {
                for item in co
                    .consts
                    .iter()
                    .chain(&co.names)
                    .chain(&co.varnames)
                    .chain(&co.freevars)
                    .chain(&co.cellvars)
                    .chain(&co.localsplusnames)
                {
                    if *acc >= cap {
                        return;
                    }
                    walk(item, cap, acc);
                }
                walk(&co.filename, cap, acc);
                walk(&co.name, cap, acc);
                walk(&co.qualname, cap, acc);
            }
            Object::None
            | Object::StopIteration
            | Object::Ellipsis
            | Object::False
            | Object::True
            | Object::Int(_)
            | Object::Int64(_)
            | Object::Long(_)
            | Object::Float(_)
            | Object::Complex { .. }
            | Object::Bytes(_)
            | Object::String { .. }
            | Object::Unicode { .. }
            | Object::ShortAscii { .. }
            | Object::Ref(_)
            | Object::Null => {}
        }
    }
    let mut acc: u64 = 0;
    walk(obj, cap, &mut acc);
    acc
}

fn add_capped(acc: &mut u64, amount: usize, cap: u64) {
    let amount_u64: u64 = u64::try_from(amount).map_or(u64::MAX, |value: u64| value);
    let remaining: u64 = cap.saturating_sub(*acc);
    *acc = acc.saturating_add(amount_u64.min(remaining));
}

fn object_byte_count_capped(obj: &Object, cap: u64) -> u64 {
    fn walk(obj: &Object, cap: u64, acc: &mut u64) {
        if *acc >= cap {
            return;
        }
        match obj {
            Object::Long(big) => add_capped(acc, big.digits.len().saturating_mul(2), cap),
            Object::Bytes(bytes) => add_capped(acc, bytes.len(), cap),
            Object::String { value, .. }
            | Object::Unicode { value, .. }
            | Object::ShortAscii { value, .. } => add_capped(acc, value.len(), cap),
            Object::Tuple(items)
            | Object::List(items)
            | Object::Set(items)
            | Object::FrozenSet(items) => {
                for item in items {
                    walk(item, cap, acc);
                    if *acc >= cap {
                        return;
                    }
                }
            }
            Object::Dict(map) | Object::FrozenDict(map) => {
                for (key, value) in map {
                    walk(key, cap, acc);
                    walk(value, cap, acc);
                    if *acc >= cap {
                        return;
                    }
                }
            }
            Object::Code(co) => {
                add_capped(acc, co.code.len(), cap);
                add_capped(acc, co.lnotab.len(), cap);
                add_capped(acc, co.linetable.len(), cap);
                add_capped(acc, co.exceptiontable.len(), cap);
                add_capped(acc, co.pyarmor_trailer.len(), cap);
                for item in co
                    .consts
                    .iter()
                    .chain(&co.names)
                    .chain(&co.varnames)
                    .chain(&co.freevars)
                    .chain(&co.cellvars)
                    .chain(&co.localsplusnames)
                {
                    walk(item, cap, acc);
                    if *acc >= cap {
                        return;
                    }
                }
                walk(&co.filename, cap, acc);
                walk(&co.name, cap, acc);
                walk(&co.qualname, cap, acc);
            }
            Object::Slice { lower, upper, step } => {
                walk(lower, cap, acc);
                walk(upper, cap, acc);
                walk(step, cap, acc);
            }
            Object::None
            | Object::StopIteration
            | Object::Ellipsis
            | Object::False
            | Object::True
            | Object::Int(_)
            | Object::Int64(_)
            | Object::Float(_)
            | Object::Complex { .. }
            | Object::Ref(_)
            | Object::Null => {}
        }
    }
    let mut acc: u64 = 0;
    walk(obj, cap, &mut acc);
    acc
}

fn charged_totals_after_clone(
    obj: &Object,
    already_nodes: u64,
    already_bytes: u64,
) -> Result<(u64, u64)> {
    let remaining_bytes: u64 = BYTE_BUDGET.saturating_sub(already_bytes);
    let bytes: u64 = object_byte_count_capped(obj, remaining_bytes.saturating_add(1));
    if bytes > remaining_bytes {
        return Err(Error::ByteBudget { limit: BYTE_BUDGET });
    }
    Ok((
        charged_node_total_after_clone(obj, already_nodes)?,
        already_bytes.saturating_add(bytes),
    ))
}

fn charged_node_total_after_clone(obj: &Object, already: u64) -> Result<u64> {
    let remaining: u64 = NODE_BUDGET.saturating_sub(already);
    let nodes: u64 = object_node_count_capped(obj, remaining.saturating_add(1));
    if nodes > remaining {
        return Err(Error::NodeBudget { limit: NODE_BUDGET });
    }
    Ok(already.saturating_add(nodes))
}

pub fn load(data: &[u8], version: PyVersion) -> Result<Object> {
    let mut r: Reader<'_> = Reader::new(data, version, false);
    r.read_object(0)
}

pub fn load_with_reftable(data: &[u8], version: PyVersion) -> Result<(Object, RefTableDump)> {
    let mut r: Reader<'_> = Reader::new(data, version, true);
    let obj: Object = r.read_object(0)?;
    let mut dump: RefTableDump = r.dump.take().unwrap_or_else(RefTableDump::empty);
    dump.finalize(r.cursor.position());
    Ok((obj, dump))
}

#[derive(Debug)]
enum RefSlot {
    Pending { definition_offset: usize },
    Ready(Object),
}

const fn byte_read_error_to_eof(error: ByteReadError) -> Error {
    Error::Eof {
        offset: error.offset,
    }
}

#[derive(Debug)]
struct Reader<'a> {
    cursor: ByteReader<'a>,
    refs: Vec<RefSlot>,
    interned_strings: Vec<String>,
    version: PyVersion,
    dump: Option<RefTableDump>,
    materialized_nodes: u64,
    materialized_bytes: u64,
}

impl<'a> Reader<'a> {
    const fn new(buf: &'a [u8], version: PyVersion, trace: bool) -> Self {
        Self {
            cursor: ByteReader::new(buf),
            refs: Vec::new(),
            interned_strings: Vec::new(),
            version,
            dump: if trace {
                Some(RefTableDump::empty())
            } else {
                None
            },
            materialized_nodes: 0,
            materialized_bytes: 0,
        }
    }

    fn clone_obj_charged(&mut self, obj: &Object) -> Result<Object> {
        let (total_nodes, total_bytes): (u64, u64) =
            charged_totals_after_clone(obj, self.materialized_nodes, self.materialized_bytes)?;
        let cloned: Object = obj.clone();
        self.materialized_nodes = total_nodes;
        self.materialized_bytes = total_bytes;
        Ok(cloned)
    }

    fn read_byte(&mut self) -> Result<u8> {
        self.cursor.read_u8().map_err(byte_read_error_to_eof)
    }

    #[inline]
    const fn remaining(&self) -> usize {
        self.cursor.remaining()
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.cursor.read_bytes(n).map_err(byte_read_error_to_eof)
    }

    fn read_i16(&mut self) -> Result<i32> {
        self.cursor
            .read_i16_le()
            .map(i32::from)
            .map_err(byte_read_error_to_eof)
    }

    fn read_i32(&mut self) -> Result<i32> {
        self.cursor.read_i32_le().map_err(byte_read_error_to_eof)
    }

    fn read_u32(&mut self) -> Result<u32> {
        self.cursor.read_u32_le().map_err(byte_read_error_to_eof)
    }

    fn read_i64(&mut self) -> Result<i64> {
        self.cursor.read_i64_le().map_err(byte_read_error_to_eof)
    }

    fn read_f64(&mut self) -> Result<f64> {
        self.cursor
            .read_u64_le()
            .map(f64::from_bits)
            .map_err(byte_read_error_to_eof)
    }

    fn alloc_ref(&mut self, definition_offset: usize) -> Result<u32> {
        let len: usize = self.refs.len();
        if len >= MAX_REFS {
            let truncated: u32 = u32_saturating_from_usize(len);
            return Err(Error::LengthOverflow(truncated));
        }
        let idx: u32 = u32_saturating_from_usize(len);
        self.refs.push(RefSlot::Pending { definition_offset });
        Ok(idx)
    }

    fn set_ref(&mut self, idx: u32, obj: Object) {
        if let Some(slot) = self.refs.get_mut(idx as usize) {
            *slot = RefSlot::Ready(obj);
        }
    }

    fn ready_ref(&self, idx: u32, reference_offset: usize) -> Result<&Object> {
        let len: usize = self.refs.len();
        match self
            .refs
            .get(idx as usize)
            .ok_or(Error::RefOutOfBounds { index: idx, len })?
        {
            RefSlot::Pending { definition_offset } => Err(Error::RecursiveReference {
                index: idx,
                reference_offset,
                definition_offset: *definition_offset,
            }),
            RefSlot::Ready(obj) => Ok(obj),
        }
    }

    fn read_object(&mut self, depth: usize) -> Result<Object> {
        if depth >= MAX_DEPTH {
            return Err(Error::DepthLimit(MAX_DEPTH));
        }
        let start: usize = self.cursor.position();
        let head: u8 = self.read_byte()?;
        let tag: u8 = head & TAG_MASK;
        let has_ref: bool = head & FLAG_REF != 0;
        let ref_idx: Option<u32> = if has_ref {
            Some(self.alloc_ref(start)?)
        } else {
            None
        };
        let entry_slot: Option<usize> = self.open_trace(ref_idx, start, depth, tag);
        let mut ref_preview_override: Option<u32> = None;
        let obj: Object = self.decode_tag(tag, depth, &mut ref_preview_override)?;
        if let Some(idx) = ref_idx {
            let stored: Object = self.clone_obj_charged(&obj)?;
            self.set_ref(idx, stored);
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
        if dump.entries.len() >= MAX_TRACE_ENTRIES {
            dump.entries_omitted = dump.entries_omitted.saturating_add(1);
            return None;
        }
        dump.entries.push(RefEntry {
            index: ref_idx.map_or(u32::MAX, |index: u32| index),
            byte_offset: start,
            byte_length: 0,
            depth: u16_saturating_from_usize(depth),
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
        let pos: usize = self.cursor.position();
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
                Ok(Object::Slice {
                    lower: Box::new(lower),
                    upper: Box::new(upper),
                    step: Box::new(stride),
                })
            }
            b'c' | b'C' => Ok(Object::Code(Box::new(self.read_code_object(depth + 1)?))),
            b'r' => self.decode_back_ref(ref_override),
            b'R' => self.decode_string_ref(ref_override),
            _ => Err(Error::UnknownTag {
                tag,
                offset: self.cursor.position() - 1,
            }),
        }
    }

    fn decode_string_ref(&mut self, ref_override: &mut Option<u32>) -> Result<Object> {
        let idx: u32 = self.read_u32()?;
        let Some(value): Option<&String> = self.interned_strings.get(idx as usize) else {
            return Err(Error::RefOutOfBounds {
                index: idx,
                len: self.interned_strings.len(),
            });
        };
        let value_len: u64 = u64::try_from(value.len()).map_or(u64::MAX, |len: u64| len);
        let remaining_bytes: u64 = BYTE_BUDGET.saturating_sub(self.materialized_bytes);
        if value_len > remaining_bytes {
            return Err(Error::ByteBudget { limit: BYTE_BUDGET });
        }
        let remaining_nodes: u64 = NODE_BUDGET.saturating_sub(self.materialized_nodes);
        if remaining_nodes == 0 {
            return Err(Error::NodeBudget { limit: NODE_BUDGET });
        }
        let resolved: String = value.clone();
        self.materialized_bytes = self.materialized_bytes.saturating_add(value_len);
        self.materialized_nodes = self.materialized_nodes.saturating_add(1);
        *ref_override = Some(idx);
        Ok(Object::String {
            value: resolved,
            interned: true,
        })
    }

    fn decode_ascii_float(&mut self) -> Result<Object> {
        Ok(Object::Float(self.read_ascii_float()?))
    }

    fn read_ascii_float(&mut self) -> Result<f64> {
        let len: usize = self.read_byte()? as usize;
        let offset: usize = self.cursor.position();
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let s: &str =
            core::str::from_utf8(bytes).map_err(|source| Error::InvalidUtf8 { offset, source })?;
        s.parse::<f64>().map_err(|_| Error::InvalidAsciiFloat {
            literal: s.to_owned(),
            offset,
        })
    }

    fn decode_ascii_complex(&mut self) -> Result<Object> {
        let real: f64 = self.read_ascii_float()?;
        let imag: f64 = self.read_ascii_float()?;
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
        let value: String = String::from_utf8_lossy(bytes).into_owned();
        let interned: bool = matches!(tag, b't' | b'A');
        if interned {
            self.push_interned_string(value.clone())?;
        }
        let is_unicode: bool = tag == b'u' || (tag == b't' && self.version.major >= 3);
        if is_unicode {
            return Ok(Object::Unicode { value, interned });
        }
        Ok(Object::String { value, interned })
    }

    fn decode_short_ascii(&mut self, tag: u8) -> Result<Object> {
        let len: usize = self.read_byte()? as usize;
        let bytes: &'a [u8] = self.read_bytes(len)?;
        let value: String = String::from_utf8_lossy(bytes).into_owned();
        let interned: bool = tag == b'Z';
        if interned {
            self.push_interned_string(value.clone())?;
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
        let reference_offset: usize = self.cursor.position().saturating_sub(1);
        let idx: u32 = self.read_u32()?;
        let already_nodes: u64 = self.materialized_nodes;
        let already_bytes: u64 = self.materialized_bytes;
        let entry: &Object = self.ready_ref(idx, reference_offset)?;
        let (total_nodes, total_bytes): (u64, u64) =
            charged_totals_after_clone(entry, already_nodes, already_bytes)?;
        let resolved: Object = entry.clone();
        self.materialized_nodes = total_nodes;
        self.materialized_bytes = total_bytes;
        *ref_override = Some(idx);
        Ok(resolved)
    }

    fn read_n_objects(&mut self, n: usize, depth: usize) -> Result<Vec<Object>> {
        if n > MAX_COLLECTION_ITEMS {
            let truncated: u32 = u32_saturating_from_usize(n);
            return Err(Error::LengthOverflow(truncated));
        }
        let mut v: Vec<Object> = Vec::with_capacity(object_prealloc_capacity(n, self.remaining()));
        for _ in 0..n {
            v.push(self.read_object(depth)?);
        }
        Ok(v)
    }

    fn push_interned_string(&mut self, value: String) -> Result<()> {
        if self.interned_strings.len() >= MAX_INTERNED_STRINGS {
            return Err(Error::LengthOverflow(u32_saturating_from_usize(
                MAX_INTERNED_STRINGS,
            )));
        }
        self.interned_strings.push(value);
        Ok(())
    }

    fn read_dict(&mut self, depth: usize) -> Result<IndexMap<Object, Object>> {
        let mut map: IndexMap<Object, Object> = IndexMap::new();
        let mut entry_count: usize = 0;
        loop {
            if entry_count >= MAX_DICT_ENTRIES {
                let truncated: u32 = u32_saturating_from_usize(entry_count);
                return Err(Error::LengthOverflow(truncated));
            }
            let key: Object = self.read_object(depth)?;
            if matches!(key, Object::Null) {
                break;
            }
            let val: Object = self.read_object(depth)?;
            map.insert(key, val);
            entry_count = entry_count.saturating_add(1);
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
            let digit: u16 = self.cursor.read_u16_le().map_err(byte_read_error_to_eof)?;
            digits.push(digit);
        }
        Ok(Object::Long(BigInt { sign, digits }))
    }

    fn read_code_object(&mut self, depth: usize) -> Result<CodeObject> {
        let era: CodeEra = crate::object::code_era_for(self.version);
        let mut co: CodeObject = CodeObject::new(era);

        match era {
            CodeEra::Py10to12 => {
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
            }
            CodeEra::Py13to14 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
            }
            CodeEra::Py15to20 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.stacksize = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i16()?;
                co.lnotab = self.read_bytes_obj("lnotab", depth)?;
            }
            CodeEra::Py21to22 => {
                co.argcount = self.read_i16()?;
                co.nlocals = self.read_i16()?;
                co.stacksize = self.read_i16()?;
                co.flags = self.read_i16()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.freevars = self.read_tuple("freevars", depth)?;
                co.cellvars = self.read_tuple("cellvars", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i16()?;
                co.lnotab = self.read_bytes_obj("lnotab", depth)?;
            }
            CodeEra::Py27 => {
                co.argcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.freevars = self.read_tuple("freevars", depth)?;
                co.cellvars = self.read_tuple("cellvars", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj("lnotab", depth)?;
            }
            CodeEra::Py30to37 => {
                co.argcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.freevars = self.read_tuple("freevars", depth)?;
                co.cellvars = self.read_tuple("cellvars", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj("lnotab", depth)?;
                co.pyarmor_trailer = self.consume_pyarmor_trailer_if_present(co.flags)?;
            }
            CodeEra::Py38to310 => {
                co.argcount = self.read_i32()?;
                co.posonlyargcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.nlocals = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.varnames = self.read_tuple("varnames", depth)?;
                co.freevars = self.read_tuple("freevars", depth)?;
                co.cellvars = self.read_tuple("cellvars", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.lnotab = self.read_bytes_obj("lnotab", depth)?;
                co.pyarmor_trailer = self.consume_pyarmor_trailer_if_present(co.flags)?;
            }
            CodeEra::Py311Plus => {
                co.argcount = self.read_i32()?;
                co.posonlyargcount = self.read_i32()?;
                co.kwonlyargcount = self.read_i32()?;
                co.stacksize = self.read_i32()?;
                co.flags = self.read_i32()?;
                co.code = self.read_bytes_obj("code", depth)?;
                co.consts = self.read_tuple("consts", depth)?;
                co.names = self.read_tuple("names", depth)?;
                co.localsplusnames = self.read_tuple("localsplusnames", depth)?;
                co.localspluskinds = self.read_bytes_obj("localspluskinds", depth)?;
                co.filename = self.read_object(depth)?;
                co.name = self.read_object(depth)?;
                co.qualname = self.read_object(depth)?;
                co.firstlineno = self.read_i32()?;
                co.linetable = self.read_bytes_obj("linetable", depth)?;
                co.exceptiontable = self.read_bytes_obj("exceptiontable", depth)?;
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
        let bytes: Vec<u8> = self.read_bytes(extra_len)?.to_vec();
        Ok(bytes)
    }

    fn read_bytes_obj(&mut self, field: &'static str, depth: usize) -> Result<Vec<u8>> {
        match self.read_object(depth)? {
            Object::Bytes(b) => Ok(b),
            Object::String { value, .. } | Object::ShortAscii { value, .. } => {
                Ok(text_to_raw_bytes(&value))
            }
            other => Err(self.code_field_type_err(field, "bytes", &other)),
        }
    }

    fn read_tuple(&mut self, field: &'static str, depth: usize) -> Result<Vec<Object>> {
        match self.read_object(depth)? {
            Object::Tuple(t) | Object::List(t) => Ok(t),
            other => Err(self.code_field_type_err(field, "tuple", &other)),
        }
    }

    const fn code_field_type_err(
        &self,
        field: &'static str,
        expected: &'static str,
        got: &Object,
    ) -> Error {
        Error::CodeFieldType {
            era: crate::object::code_era_for(self.version),
            field,
            expected,
            got: object_kind_name(got),
        }
    }
}

const fn object_kind_name(obj: &Object) -> &'static str {
    match obj {
        Object::None => "none",
        Object::StopIteration => "stop-iteration",
        Object::Ellipsis => "ellipsis",
        Object::False => "false",
        Object::True => "true",
        Object::Int(_) => "int",
        Object::Int64(_) => "int64",
        Object::Long(_) => "long",
        Object::Float(_) => "float",
        Object::Complex { .. } => "complex",
        Object::Bytes(_) => "bytes",
        Object::String { .. } => "string",
        Object::Unicode { .. } => "unicode",
        Object::ShortAscii { .. } => "short-ascii",
        Object::Tuple(_) => "tuple",
        Object::List(_) => "list",
        Object::Dict(_) => "dict",
        Object::Set(_) => "set",
        Object::FrozenSet(_) => "frozenset",
        Object::FrozenDict(_) => "frozendict",
        Object::Code(_) => "code",
        Object::Slice { .. } => "slice",
        Object::Ref(_) => "ref",
        Object::Null => "null",
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
        Object::Slice { .. } => "slice".to_owned(),
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
    let name: &str = match &co.name {
        Object::ShortAscii { value, .. } | Object::String { value, .. } => value,
        _ => "<anon>",
    };
    format!(
        "name={} consts={} names={} code={}b",
        preview_str(name),
        co.consts.len(),
        co.names.len(),
        co.code.len()
    )
}

const fn object_prealloc_capacity(n: usize, remaining_bytes: usize) -> usize {
    let by_declared: usize = if n < remaining_bytes {
        n
    } else {
        remaining_bytes
    };
    if by_declared < MAX_OBJECT_PREALLOC {
        by_declared
    } else {
        MAX_OBJECT_PREALLOC
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn object_prealloc_capacity_is_small_for_huge_inputs() {
        assert_eq!(
            object_prealloc_capacity(usize::MAX, usize::MAX),
            MAX_OBJECT_PREALLOC
        );
        assert_eq!(object_prealloc_capacity(12, usize::MAX), 12);
        assert_eq!(object_prealloc_capacity(usize::MAX, 7), 7);
    }

    #[test]
    fn non_utf8_unicode_string_does_not_drop_the_whole_marshal_tree() {
        let mut data: Vec<u8> = vec![b'('];
        data.extend(3u32.to_le_bytes());

        data.push(b'i');
        data.extend(1i32.to_le_bytes());

        let bad: [u8; 3] = [0x61, 0xff, 0x62];
        data.push(b'u');
        data.extend((bad.len() as u32).to_le_bytes());
        data.extend_from_slice(&bad);

        data.push(b'i');
        data.extend(2i32.to_le_bytes());

        let obj: Object =
            load(&data, PyVersion::PY312).expect("one bad byte must not abort the tree");
        let Object::Tuple(items) = obj else {
            panic!("expected a tuple");
        };
        assert_eq!(items.len(), 3);
        assert_eq!(items[0], Object::Int(1));
        assert_eq!(items[2], Object::Int(2));
        let Object::Unicode { value, .. } = &items[1] else {
            panic!("expected a unicode string in the middle slot");
        };
        assert!(value.contains('\u{fffd}'));
        assert!(value.starts_with('a'));
        assert!(value.ends_with('b'));
    }

    #[test]
    fn oversized_collection_rejects_before_reading_item_bodies() {
        let mut data: Vec<u8> = vec![b'('];
        data.extend((MAX_COLLECTION_ITEMS as u32 + 1).to_le_bytes());
        data.push(b'N');
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        assert!(matches!(err, Error::LengthOverflow(_)));
    }

    #[test]
    fn interned_string_table_rejects_more_than_the_reference_limit() {
        let count: usize = MAX_INTERNED_STRINGS.saturating_add(1);
        let mut data: Vec<u8> = Vec::with_capacity(count.saturating_add(5));
        data.push(b'(');
        data.extend((count as u32).to_le_bytes());
        for _ in 0..count {
            data.push(b't');
            data.extend(0u32.to_le_bytes());
        }

        let err: Error = load(&data, PyVersion::PY312).unwrap_err();

        assert!(
            matches!(err, Error::LengthOverflow(limit) if limit == MAX_INTERNED_STRINGS as u32)
        );
    }

    #[test]
    fn ref_table_trace_truncates_instead_of_failing_a_parse() {
        let mut data: Vec<u8> = Vec::with_capacity(MAX_TRACE_ENTRIES.saturating_add(5));
        data.push(b'(');
        data.extend(u32_saturating_from_usize(MAX_TRACE_ENTRIES).to_le_bytes());
        data.extend(core::iter::repeat_n(b'N', MAX_TRACE_ENTRIES));

        let (object, dump): (Object, RefTableDump) =
            load_with_reftable(&data, PyVersion::PY312).expect("the trace bound is diagnostic");

        assert!(matches!(object, Object::Tuple(_)));
        assert_eq!(dump.entries.len(), MAX_TRACE_ENTRIES);
        assert_eq!(dump.entries_omitted, 1);
        assert_eq!(dump.total_bytes, data.len());
    }

    #[test]
    fn dict_rejects_repeated_keys_after_the_entry_limit() {
        let mut data: Vec<u8> = Vec::with_capacity(MAX_DICT_ENTRIES.saturating_mul(4));
        data.push(b'{');
        for _ in 0..MAX_DICT_ENTRIES {
            data.extend([b'z', 1, b'k', b'N']);
        }
        data.extend([b'z', 1, b'k', b'N', b'0']);

        let err: Error = load(&data, PyVersion::PY312).unwrap_err();

        assert!(matches!(err, Error::LengthOverflow(limit) if limit == MAX_DICT_ENTRIES as u32));
    }

    #[test]
    fn code_preview_truncates_the_code_name() {
        let mut code: CodeObject = CodeObject::new(CodeEra::Py311Plus);
        code.name = Object::ShortAscii {
            value: "a".repeat(64),
            interned: false,
        };

        let preview: String = code_preview(&code);

        assert!(preview.starts_with("name=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa..."));
    }

    #[test]
    fn recursive_back_ref_is_rejected_without_null_substitution() {
        const DATA: &[u8] = b"\xdb\x01\x00\x00\x00r\x00\x00\x00\x00";
        let err: Error = load(DATA, PyVersion::PY314)
            .expect_err("cyclic reference must not become an Object::Null value");
        assert_eq!(
            err.to_string(),
            "DR-MARSHAL-0020: recursive marshal reference 0 at offset 5 targets unfinished object at offset 0; cyclic object graphs are unsupported"
        );
        assert!(matches!(
            err,
            Error::RecursiveReference {
                index: 0,
                reference_offset: 5,
                definition_offset: 0,
            }
        ));
    }

    #[test]
    fn chained_back_ref_clone_bomb_returns_err_fast() {
        const LAYERS: u32 = 40;
        let mut data: Vec<u8> = vec![FLAG_REF | b'['];
        data.extend(LAYERS.to_le_bytes());
        data.push(FLAG_REF | b'N');
        for layer in 1..LAYERS {
            data.push(FLAG_REF | b')');
            data.push(0x02);
            data.push(b'r');
            data.extend(layer.to_le_bytes());
            data.push(b'r');
            data.extend(layer.to_le_bytes());
        }
        let start: std::time::Instant = std::time::Instant::now();
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            matches!(err, Error::NodeBudget { .. }),
            "chained back-ref bomb must hit the node budget, got {err:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "back-ref bomb must bail fast, took {elapsed:?}"
        );
    }

    #[test]
    fn back_ref_byte_clone_bomb_returns_err_fast() {
        const PAYLOAD_LEN: usize = 256 * 1024;
        const REFS: u32 = 8;
        let mut data: Vec<u8> = vec![b'['];
        data.extend(REFS.to_le_bytes());
        data.push(FLAG_REF | b's');
        data.extend((PAYLOAD_LEN as u32).to_le_bytes());
        data.extend(core::iter::repeat_n(0x41, PAYLOAD_LEN));
        for _ in 1..REFS {
            data.push(b'r');
            data.extend(0u32.to_le_bytes());
        }
        let start: std::time::Instant = std::time::Instant::now();
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            matches!(err, Error::ByteBudget { .. }),
            "back-ref byte bomb must hit the byte budget, got {err:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "back-ref byte bomb must bail fast, took {elapsed:?}"
        );
    }

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
    fn binary_float_is_little_endian() {
        let data: &[u8] = &[b'g', 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0x3f];
        let obj: Object = load(data, PyVersion::PY312).unwrap();
        let Object::Float(value) = obj else {
            panic!("expected binary float");
        };
        assert_eq!(value.to_bits(), 0x3ff0_0000_0000_0001);
    }

    #[test]
    fn truncated_binary_float_preserves_payload_eof_offset() {
        let data: &[u8] = &[b'g', 0x00, 0x00, 0x00, 0x00];
        let err: Error = load(data, PyVersion::PY312).unwrap_err();
        assert!(matches!(err, Error::Eof { offset: 1 }));
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
    fn ascii_complex_reads_separate_length_prefixed_parts() {
        const DATA: &[u8] = b"x\x031.5\x05-2.25";
        let versions: [PyVersion; 4] = [
            PyVersion::PY15,
            PyVersion::PY27,
            PyVersion::PY312,
            PyVersion::PY315,
        ];
        for version in versions {
            let obj: Object = load(DATA, version).expect("CPython format-0 complex must decode");
            assert_eq!(
                obj,
                Object::Complex {
                    real: 1.5,
                    imag: -2.25,
                }
            );
        }
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

    #[test]
    fn stringref_byte_clone_bomb_returns_err_fast() {
        const PAYLOAD_LEN: usize = 256 * 1024;
        const REFS: u32 = 8;
        let mut data: Vec<u8> = vec![b'['];
        data.extend((REFS + 1).to_le_bytes());
        data.push(b't');
        data.extend((PAYLOAD_LEN as u32).to_le_bytes());
        data.extend(core::iter::repeat_n(0x41, PAYLOAD_LEN));
        for _ in 0..REFS {
            data.push(b'R');
            data.extend(0u32.to_le_bytes());
        }
        let start: std::time::Instant = std::time::Instant::now();
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        let elapsed: std::time::Duration = start.elapsed();
        assert!(
            matches!(err, Error::ByteBudget { .. }),
            "string-ref byte bomb must hit the byte budget, got {err:?}"
        );
        assert!(
            elapsed < std::time::Duration::from_secs(2),
            "string-ref byte bomb must bail fast, took {elapsed:?}"
        );
    }

    #[test]
    fn stringref_small_string_resolves_under_budget() {
        const REFS: u32 = 16;
        let mut data: Vec<u8> = vec![b'['];
        data.extend((REFS + 1).to_le_bytes());
        data.push(b't');
        data.extend(2u32.to_le_bytes());
        data.extend(b"hi");
        for _ in 0..REFS {
            data.push(b'R');
            data.extend(0u32.to_le_bytes());
        }
        let obj: Object = load(&data, PyVersion::PY312).unwrap();
        let Object::List(items) = obj else {
            panic!("expected a list");
        };
        assert_eq!(items.len(), (REFS + 1) as usize);
        for item in &items[1..] {
            assert!(
                matches!(item, Object::String { value, interned: true } if value == "hi"),
                "each string-ref must still resolve, got {item:?}"
            );
        }
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

    fn py311_code_prefix() -> Vec<u8> {
        let mut data: Vec<u8> = vec![b'c'];
        for _ in 0..5 {
            data.extend(0i32.to_le_bytes());
        }
        data
    }

    #[test]
    fn code_field_type_mismatch_on_code_is_structured_error() {
        let mut data: Vec<u8> = py311_code_prefix();
        data.push(b'N');
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        assert!(
            matches!(
                err,
                Error::CodeFieldType {
                    era: CodeEra::Py311Plus,
                    field: "code",
                    expected: "bytes",
                    got: "none",
                }
            ),
            "expected structured CodeFieldType error, got {err:?}"
        );
    }

    #[test]
    fn code_field_type_mismatch_on_consts_is_structured_error() {
        let mut data: Vec<u8> = py311_code_prefix();
        data.push(b's');
        data.extend(0u32.to_le_bytes());
        data.push(b'N');
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        assert!(
            matches!(
                err,
                Error::CodeFieldType {
                    field: "consts",
                    expected: "tuple",
                    got: "none",
                    ..
                }
            ),
            "expected structured CodeFieldType error for consts, got {err:?}"
        );
    }

    #[test]
    fn code_field_type_mismatch_via_ref_is_structured_error() {
        let mut data: Vec<u8> = py311_code_prefix();
        data.push(FLAG_REF | b'N');
        data.push(b'r');
        data.extend(0u32.to_le_bytes());
        let err: Error = load(&data, PyVersion::PY312).unwrap_err();
        assert!(
            matches!(
                err,
                Error::CodeFieldType {
                    field: "code",
                    expected: "bytes",
                    got: "none",
                    ..
                }
            ),
            "expected structured CodeFieldType error through a ref, got {err:?}"
        );
    }

    #[test]
    fn unicode_round_trips_under_py3() {
        let original: Object = Object::Unicode {
            value: "héllo".to_owned(),
            interned: false,
        };
        let bytes: Vec<u8> = crate::writer::dump(&original, PyVersion::PY312).unwrap();
        assert_eq!(bytes[0], b'u');
        let back: Object = load(&bytes, PyVersion::PY312).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn unicode_round_trips_under_py2() {
        let original: Object = Object::Unicode {
            value: "café".to_owned(),
            interned: false,
        };
        let bytes: Vec<u8> = crate::writer::dump(&original, PyVersion::PY27).unwrap();
        let back: Object = load(&bytes, PyVersion::PY27).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn interned_non_ascii_decodes_as_utf8_unicode_under_py3() {
        const DATA: &[u8] = b"\xf4\x02\x00\x00\x00\xc3\xa9";
        let obj: Object = load(DATA, PyVersion::PY314).unwrap();
        let Object::Unicode { value, interned } = &obj else {
            panic!("py3 TYPE_INTERNED must decode as Unicode, got {obj:?}");
        };
        assert_eq!(value, "\u{e9}");
        assert!(*interned);
        let out: Vec<u8> = crate::writer::dump(&obj, PyVersion::PY314).unwrap();
        assert_eq!(
            out[0], b'u',
            "interned unicode must re-emit under a utf8 tag, never an ascii tag"
        );
        assert!(out.ends_with(&[0xc3, 0xa9]));
        let back: Object = load(&out, PyVersion::PY314).unwrap();
        let Object::Unicode { value: rv, .. } = &back else {
            panic!("re-dump must stay unicode, got {back:?}");
        };
        assert_eq!(rv, "\u{e9}");
    }

    #[test]
    fn interned_tag_stays_bytes_string_under_py2() {
        const DATA: &[u8] = b"t\x03\x00\x00\x00abc";
        let obj: Object = load(DATA, PyVersion::PY27).unwrap();
        assert!(
            matches!(&obj, Object::String { value, interned: true } if value == "abc"),
            "py2 TYPE_INTERNED must stay a byte string, got {obj:?}"
        );
    }

    #[test]
    fn frozen_dict_tag_decodes_to_frozen_dict_variant() {
        let mut data: Vec<u8> = vec![b'}'];
        data.push(b'z');
        data.push(1);
        data.extend(b"k");
        data.push(b'i');
        data.extend(1i32.to_le_bytes());
        data.push(b'0');
        let obj: Object = load(&data, PyVersion::PY312).unwrap();
        let Object::FrozenDict(map) = obj else {
            panic!("expected a frozen dict for the '}}' tag");
        };
        assert_eq!(map.len(), 1);
        assert_eq!(map.get(&short("k")), Some(&Object::Int(1)));
    }

    #[test]
    fn frozen_dict_round_trips_through_dump_and_load() {
        let mut map: IndexMap<Object, Object> = IndexMap::new();
        map.insert(short("a"), Object::Int(1));
        map.insert(short("b"), Object::Int(2));
        let original: Object = Object::FrozenDict(map);
        let bytes: Vec<u8> = crate::writer::dump(&original, PyVersion::PY312).unwrap();
        assert_eq!(bytes[0], b'}');
        let back: Object = load(&bytes, PyVersion::PY312).unwrap();
        assert_eq!(back, original);
    }

    #[test]
    fn frozen_dict_is_distinct_from_plain_dict() {
        let mut plain: IndexMap<Object, Object> = IndexMap::new();
        plain.insert(short("k"), Object::Int(1));
        let dict: Object = Object::Dict(plain.clone());
        let frozen: Object = Object::FrozenDict(plain);
        assert_ne!(dict, frozen);
    }

    #[test]
    fn back_ref_code_fields_resolve_through_concrete_arms() {
        let mut data: Vec<u8> = vec![b'c'];
        for _ in 0..5 {
            data.extend(0i32.to_le_bytes());
        }
        data.push(FLAG_REF | b's');
        data.extend(2u32.to_le_bytes());
        data.extend_from_slice(&[0x64, 0x00]);
        data.push(FLAG_REF | b'(');
        data.extend(1u32.to_le_bytes());
        data.push(b'N');
        data.push(b'r');
        data.extend(1u32.to_le_bytes());
        data.push(b'(');
        data.extend(0u32.to_le_bytes());
        data.push(b'r');
        data.extend(0u32.to_le_bytes());
        data.extend_from_slice(&[b'z', 1, b'f']);
        data.extend_from_slice(&[b'z', 1, b'n']);
        data.extend_from_slice(&[b'z', 1, b'q']);
        data.extend(0i32.to_le_bytes());
        data.push(b's');
        data.extend(0u32.to_le_bytes());
        data.push(b's');
        data.extend(0u32.to_le_bytes());

        let obj: Object = load(&data, PyVersion::PY312)
            .expect("a code object whose fields are resolved back-refs must decode");
        let Object::Code(co) = obj else {
            panic!("expected a code object");
        };
        assert_eq!(co.code, vec![0x64, 0x00]);
        assert_eq!(co.consts, vec![Object::None]);
        assert_eq!(
            co.names,
            vec![Object::None],
            "names resolved via a back-ref to consts must decode through the tuple arm"
        );
        assert_eq!(
            co.localspluskinds,
            vec![0x64, 0x00],
            "localspluskinds resolved via a back-ref to code must decode through the bytes arm"
        );
    }
}
