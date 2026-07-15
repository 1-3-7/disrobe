use std::collections::{BTreeMap, BTreeSet};

use disrobe_pass_pickle::{Disassembly, PickleValue, Session, disassemble};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub(crate) const MAX_CONST_FILE_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_BUILD_CONST_BYTES: u64 = 1024 * 1024 * 1024;
pub(crate) const MAX_BUILD_CONST_FILES: usize = 4_096;
const MAX_CONSTANT_LABEL_BYTES: usize = 4_096;

#[derive(Debug, Default)]
pub(crate) struct ConstantInputBudget {
    count: usize,
    total: u64,
}

impl ConstantInputBudget {
    pub(crate) fn add(&mut self, bytes: usize) -> Result<()> {
        self.count = self
            .count
            .checked_add(1usize)
            .ok_or(Error::TooManyConstantInputs {
                count: usize::MAX,
                max_count: MAX_BUILD_CONST_FILES,
            })?;
        validate_constant_input_count(self.count)?;
        validate_const_file_size(bytes)?;
        let bytes_len: u64 = u64::try_from(bytes).map_or(u64::MAX, |value: u64| value);
        let Some(next_total): Option<u64> = self.total.checked_add(bytes_len) else {
            return Err(Error::InputTooLarge {
                resource: "constant input set",
                bytes: u64::MAX,
                max_bytes: MAX_BUILD_CONST_BYTES,
            });
        };
        self.total = next_total;
        validate_constant_input_total(self.total)
    }
}

pub(crate) fn builtin_type_name<'a>(module: &str, name: &'a str) -> Option<&'a str> {
    const BUILTIN_TYPES: [&str; 19] = [
        "NoneType",
        "NotImplementedType",
        "EllipsisType",
        "bool",
        "bytes",
        "bytearray",
        "complex",
        "dict",
        "float",
        "frozenset",
        "int",
        "list",
        "memoryview",
        "object",
        "range",
        "set",
        "slice",
        "str",
        "tuple",
    ];
    (module == "builtins" && BUILTIN_TYPES.contains(&name)).then_some(name)
}

fn md5_hex_nuitka_string_repr(s: &str) -> String {
    let repr: String = nuitka_string_repr(s);
    format!("{:x}", md5::compute(repr.as_bytes()))
}

pub(crate) fn nuitka_string_repr(value: &str) -> String {
    let quote: char = literal_quote(value.contains('\''), value.contains('"'));
    let mut rendered: String = String::with_capacity(value.len().saturating_add(2));
    rendered.push(quote);
    for character in value.chars() {
        match character {
            '\\' => rendered.push_str("\\\\"),
            '\n' => rendered.push_str("\\n"),
            '\r' => rendered.push_str("\\r"),
            '\t' => rendered.push_str("\\t"),
            character if character == quote => {
                rendered.push('\\');
                rendered.push(character);
            }
            character if python_repr_needs_escape(character) => {
                append_python_codepoint_escape(&mut rendered, u32::from(character));
            }
            character => rendered.push(character),
        }
    }
    rendered.push(quote);
    rendered
}

pub(crate) fn nuitka_bytes_repr(bytes: &[u8]) -> String {
    let quote: char = literal_quote(bytes.contains(&b'\''), bytes.contains(&b'"'));
    let mut rendered: String = String::with_capacity(bytes.len().saturating_add(3));
    rendered.push('b');
    rendered.push(quote);
    for byte in bytes {
        match *byte {
            b'\\' => rendered.push_str("\\\\"),
            b'\n' => rendered.push_str("\\n"),
            b'\r' => rendered.push_str("\\r"),
            b'\t' => rendered.push_str("\\t"),
            byte if char::from(byte) == quote => {
                rendered.push('\\');
                rendered.push(char::from(byte));
            }
            0x20..=0x7e => rendered.push(char::from(*byte)),
            byte => append_python_codepoint_escape(&mut rendered, u32::from(byte)),
        }
    }
    rendered.push(quote);
    rendered
}

const fn literal_quote(has_single_quote: bool, has_double_quote: bool) -> char {
    if has_single_quote && !has_double_quote {
        '"'
    } else {
        '\''
    }
}

fn python_repr_needs_escape(character: char) -> bool {
    let codepoint: u32 = u32::from(character);
    character.is_control()
        || (character.is_whitespace() && character != ' ')
        || matches!(
            codepoint,
            0x00ad
                | 0x0600..=0x0605
                | 0x061c
                | 0x06dd
                | 0x070f
                | 0x0890..=0x0891
                | 0x08e2
                | 0x180e
                | 0x200b..=0x200f
                | 0x202a..=0x202e
                | 0x2060..=0x2064
                | 0x2066..=0x206f
                | 0xfeff
                | 0xfff9..=0xfffb
                | 0x110bd
                | 0x110cd
                | 0x13430..=0x1343f
                | 0x1bca0..=0x1bca3
                | 0x1d173..=0x1d17a
                | 0xe0001
                | 0xe0020..=0xe007f
                | 0xfdd0..=0xfdef
        )
        || codepoint & 0xffff == 0xfffe
        || codepoint & 0xffff == 0xffff
        || matches!(
            codepoint,
            0xE000..=0xF8FF | 0xF_0000..=0xF_FFFD | 0x10_0000..=0x10_FFFD
        )
}

fn append_python_codepoint_escape(rendered: &mut String, codepoint: u32) {
    let (marker, width): (char, u32) = if codepoint <= 0xff {
        ('x', 2u32)
    } else if codepoint <= 0xffff {
        ('u', 4u32)
    } else {
        ('U', 8u32)
    };
    rendered.push('\\');
    rendered.push(marker);
    for offset in (0u32..width).rev() {
        let digit: u32 = (codepoint >> (offset * 4u32)) & 0x0f;
        let hex: Option<char> = char::from_digit(digit, 16u32);
        if let Some(hex) = hex {
            rendered.push(hex);
        }
    }
}

fn md5_hex_nuitka_bytes_repr(bytes: &[u8]) -> String {
    let repr: String = nuitka_bytes_repr(bytes);
    format!("{:x}", md5::compute(repr.as_bytes()))
}

const MAX_STREAMS_PER_FILE: usize = 1_000_000;
const FLATTEN_DEPTH: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantProvenance {
    pub source_file: String,
    pub blob_name: String,
    pub stream_index: usize,
    pub byte_offset: usize,
    pub byte_len: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantEntry {
    pub provenance: ConstantProvenance,
    pub value: PickleValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DictLocation {
    pub entry_index: usize,
    pub path: Vec<DictPathStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DictPathStep {
    Tuple(usize),
    List(usize),
    Set(usize),
    FrozenSet(usize),
    DictKey(usize),
    DictValue(usize),
    PersId,
    ReduceCallable,
    ReduceArgs,
    ObjectClass,
    ObjectArgs,
    ObjectKwargs,
    ObjectState,
    ObjectListItem(usize),
    ObjectDictKey(usize),
    ObjectDictValue(usize),
}

struct PendingDictDigest {
    digest: String,
    path: Vec<DictPathStep>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstantsPool {
    pub entries: Vec<ConstantEntry>,
    pub strings: BTreeSet<String>,
    pub ints: BTreeSet<i64>,
    pub floats: Vec<f64>,
    #[serde(default)]
    pub bytes: BTreeSet<Vec<u8>>,
    pub tuples: Vec<Vec<PickleValue>>,
    pub globals: BTreeSet<(String, String)>,
    pub digest_to_string: BTreeMap<String, String>,
    #[serde(default)]
    pub ambiguous_string_digests: BTreeSet<String>,
    #[serde(default)]
    pub digest_to_bytes: BTreeMap<String, Vec<u8>>,
    #[serde(default)]
    pub ambiguous_bytes_digests: BTreeSet<String>,
    #[serde(default)]
    pub(crate) digest_to_dict: BTreeMap<String, DictLocation>,
    #[serde(default)]
    pub ambiguous_dict_digests: BTreeSet<String>,
    pub bytes_consumed: usize,
    pub stream_count: usize,
}

impl ConstantsPool {
    #[must_use]
    pub fn dict_pairs_for_digest(&self, digest: &str) -> Option<&[(PickleValue, PickleValue)]> {
        let location: &DictLocation = self.digest_to_dict.get(digest)?;
        let entry: &ConstantEntry = self.entries.get(location.entry_index)?;
        let value: &PickleValue = dict_value_at_path(&entry.value, &location.path)?;
        match value {
            PickleValue::Dict(pairs) => Some(pairs),
            _ => None,
        }
    }
}

fn dict_value_at_path<'a>(
    mut value: &'a PickleValue,
    path: &[DictPathStep],
) -> Option<&'a PickleValue> {
    for step in path {
        value = match (step, value) {
            (DictPathStep::Tuple(index), PickleValue::Tuple(values))
            | (DictPathStep::List(index), PickleValue::List(values))
            | (DictPathStep::Set(index), PickleValue::Set(values))
            | (DictPathStep::FrozenSet(index), PickleValue::FrozenSet(values)) => {
                values.get(*index)?
            }
            (DictPathStep::DictKey(index), PickleValue::Dict(pairs)) => &pairs.get(*index)?.0,
            (DictPathStep::DictValue(index), PickleValue::Dict(pairs)) => &pairs.get(*index)?.1,
            (DictPathStep::PersId, PickleValue::PersId { id }) => id,
            (DictPathStep::ReduceCallable, PickleValue::Reduce { callable, .. }) => callable,
            (DictPathStep::ReduceArgs, PickleValue::Reduce { args, .. })
            | (DictPathStep::ObjectArgs, PickleValue::Object { args, .. }) => args,
            (DictPathStep::ObjectClass, PickleValue::Object { cls, .. }) => cls,
            (DictPathStep::ObjectKwargs, PickleValue::Object { kwargs, .. }) => {
                kwargs.as_deref()?
            }
            (DictPathStep::ObjectState, PickleValue::Object { state, .. }) => state.as_deref()?,
            (DictPathStep::ObjectListItem(index), PickleValue::Object { listitems, .. }) => {
                listitems.get(*index)?
            }
            (DictPathStep::ObjectDictKey(index), PickleValue::Object { dictitems, .. }) => {
                &dictitems.get(*index)?.0
            }
            (DictPathStep::ObjectDictValue(index), PickleValue::Object { dictitems, .. }) => {
                &dictitems.get(*index)?.1
            }
            _ => return None,
        };
    }
    Some(value)
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConstantsTable {
    pub pools: BTreeMap<String, ConstantsPool>,
    pub all_strings: BTreeSet<String>,
    pub all_ints: BTreeSet<i64>,
}

pub fn decode_const_file(
    bytes: &[u8],
    source_file: &str,
    blob_name: &str,
) -> Result<ConstantsPool> {
    validate_const_file_size(bytes.len())?;
    validate_constant_label_size("constant source file", source_file)?;
    validate_constant_label_size("constant blob name", blob_name)?;
    let mut session: Session = Session::new();
    let mut pool: ConstantsPool = ConstantsPool::default();
    let mut cursor: usize = 0usize;

    while cursor < bytes.len() {
        let rest: &[u8] = &bytes[cursor..];
        let dis: Disassembly = disassemble(rest)
            .map_err(|e: disrobe_pass_pickle::Error| Error::ConstPickle(e.to_string()))?;
        let stop_off: usize = dis
            .stop_offset
            .ok_or(Error::ConstStreamNoStop { offset: cursor })?;
        let consumed: usize = stop_off + 1;
        let value: PickleValue = session
            .run(&dis)
            .map_err(|e: disrobe_pass_pickle::Error| Error::ConstPickle(e.to_string()))?;

        let provenance: ConstantProvenance = ConstantProvenance {
            source_file: source_file.to_owned(),
            blob_name: blob_name.to_owned(),
            stream_index: pool.entries.len(),
            byte_offset: cursor,
            byte_len: consumed,
        };

        let entry_index: usize = pool.entries.len();
        let mut pending_dicts: Vec<PendingDictDigest> = Vec::new();
        let mut path: Vec<DictPathStep> = Vec::new();
        flatten_into(&value, &mut pool, 0, &mut pending_dicts, &mut path)?;
        pool.entries.push(ConstantEntry { provenance, value });
        index_pending_dicts(&mut pool, entry_index, pending_dicts);

        cursor += consumed;

        if pool.entries.len() > MAX_STREAMS_PER_FILE {
            return Err(Error::ConstTooManyStreams);
        }
    }

    pool.bytes_consumed = cursor;
    pool.stream_count = pool.entries.len();

    if pool.bytes_consumed != bytes.len() {
        return Err(Error::ConstTrailingBytes {
            consumed: cursor,
            total: bytes.len(),
        });
    }

    Ok(pool)
}

pub fn decode_build_constants(files: &[(String, Vec<u8>, String)]) -> Result<ConstantsTable> {
    validate_constant_input_lengths(files.iter().map(|(_, bytes, _)| bytes.len()))?;
    let mut table: ConstantsTable = ConstantsTable::default();

    for (source_file, bytes, blob_name) in files {
        let pool: ConstantsPool = decode_const_file(bytes, source_file, blob_name)?;
        for s in &pool.strings {
            table.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            table.all_ints.insert(*i);
        }
        table.pools.insert(source_file.clone(), pool);
    }

    Ok(table)
}

pub(crate) fn validate_const_file_size(bytes: usize) -> Result<()> {
    let bytes: u64 = u64::try_from(bytes).map_or(u64::MAX, |value: u64| value);
    if bytes > MAX_CONST_FILE_BYTES {
        return Err(Error::InputTooLarge {
            resource: "constant file",
            bytes,
            max_bytes: MAX_CONST_FILE_BYTES,
        });
    }
    Ok(())
}

fn validate_constant_label_size(resource: &'static str, label: &str) -> Result<()> {
    let bytes: u64 = u64::try_from(label.len()).map_or(u64::MAX, |value: u64| value);
    let max_bytes: u64 = MAX_CONSTANT_LABEL_BYTES as u64;
    if bytes > max_bytes {
        return Err(Error::InputTooLarge {
            resource,
            bytes,
            max_bytes,
        });
    }
    Ok(())
}

pub(crate) fn validate_constant_input_lengths<I>(lengths: I) -> Result<()>
where
    I: IntoIterator<Item = usize>,
{
    let mut budget: ConstantInputBudget = ConstantInputBudget::default();
    for bytes in lengths {
        budget.add(bytes)?;
    }
    Ok(())
}

const fn validate_constant_input_count(count: usize) -> Result<()> {
    if count > MAX_BUILD_CONST_FILES {
        return Err(Error::TooManyConstantInputs {
            count,
            max_count: MAX_BUILD_CONST_FILES,
        });
    }
    Ok(())
}

const fn validate_constant_input_total(bytes: u64) -> Result<()> {
    if bytes > MAX_BUILD_CONST_BYTES {
        return Err(Error::InputTooLarge {
            resource: "constant input set",
            bytes,
            max_bytes: MAX_BUILD_CONST_BYTES,
        });
    }
    Ok(())
}

fn index_pending_dicts(
    pool: &mut ConstantsPool,
    entry_index: usize,
    pending_dicts: Vec<PendingDictDigest>,
) {
    for pending in pending_dicts {
        let location: DictLocation = DictLocation {
            entry_index,
            path: pending.path,
        };
        let existing: Option<DictLocation> = pool.digest_to_dict.get(&pending.digest).cloned();
        let Some(existing): Option<DictLocation> = existing else {
            pool.digest_to_dict.insert(pending.digest, location);
            continue;
        };
        if dict_pairs_at(pool, &existing) != dict_pairs_at(pool, &location) {
            pool.ambiguous_dict_digests.insert(pending.digest);
        }
    }
}

fn dict_pairs_at<'a>(
    pool: &'a ConstantsPool,
    location: &DictLocation,
) -> Option<&'a [(PickleValue, PickleValue)]> {
    let entry: &ConstantEntry = pool.entries.get(location.entry_index)?;
    let value: &PickleValue = dict_value_at_path(&entry.value, &location.path)?;
    match value {
        PickleValue::Dict(pairs) => Some(pairs),
        _ => None,
    }
}

fn flatten_into(
    value: &PickleValue,
    pool: &mut ConstantsPool,
    depth: usize,
    pending_dicts: &mut Vec<PendingDictDigest>,
    path: &mut Vec<DictPathStep>,
) -> Result<()> {
    if depth > FLATTEN_DEPTH {
        return Err(Error::ConstFlattenDepth);
    }
    let next: usize = depth + 1;
    match value {
        PickleValue::Str(s) | PickleValue::BigInt(s) => {
            let digest: String = md5_hex_nuitka_string_repr(s);
            index_string_digest(pool, digest, s);
            pool.strings.insert(s.clone());
        }
        PickleValue::Bytes(bytes) => {
            let digest: String = md5_hex_nuitka_bytes_repr(bytes);
            pool.bytes.insert(bytes.clone());
            index_bytes_digest(pool, digest, bytes);
        }
        PickleValue::Int(i) => {
            pool.ints.insert(*i);
        }
        PickleValue::Float(f) => {
            let bits: u64 = f.to_bits();
            if !pool
                .floats
                .iter()
                .any(|existing: &f64| existing.to_bits() == bits)
            {
                pool.floats.push(*f);
            }
        }
        PickleValue::Tuple(items) => {
            pool.tuples.push(items.clone());
            for (index, item) in items.iter().enumerate() {
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::Tuple(index),
                )?;
            }
        }
        PickleValue::List(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::List(index),
                )?;
            }
        }
        PickleValue::Set(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::Set(index),
                )?;
            }
        }
        PickleValue::FrozenSet(items) => {
            for (index, item) in items.iter().enumerate() {
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::FrozenSet(index),
                )?;
            }
        }
        PickleValue::Dict(pairs) => {
            if let Some(digest) = md5_hex_nuitka_value_repr(value, depth) {
                pending_dicts.push(PendingDictDigest {
                    digest,
                    path: path.clone(),
                });
            }
            for (index, (key, item)) in pairs.iter().enumerate() {
                flatten_child(
                    key,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::DictKey(index),
                )?;
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::DictValue(index),
                )?;
            }
        }
        PickleValue::Global { module, name } => {
            pool.globals.insert((module.clone(), name.clone()));
            pool.strings.insert(module.clone());
            pool.strings.insert(name.clone());
        }
        PickleValue::PersId { id } => {
            flatten_child(id, pool, next, pending_dicts, path, DictPathStep::PersId)?;
        }
        PickleValue::Reduce { callable, args } => {
            flatten_child(
                callable,
                pool,
                next,
                pending_dicts,
                path,
                DictPathStep::ReduceCallable,
            )?;
            flatten_child(
                args,
                pool,
                next,
                pending_dicts,
                path,
                DictPathStep::ReduceArgs,
            )?;
        }
        PickleValue::Object {
            cls,
            args,
            kwargs,
            state,
            listitems,
            dictitems,
            ..
        } => {
            flatten_child(
                cls,
                pool,
                next,
                pending_dicts,
                path,
                DictPathStep::ObjectClass,
            )?;
            flatten_child(
                args,
                pool,
                next,
                pending_dicts,
                path,
                DictPathStep::ObjectArgs,
            )?;
            if let Some(kwargs_value) = kwargs {
                flatten_child(
                    kwargs_value,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::ObjectKwargs,
                )?;
            }
            if let Some(state_value) = state {
                flatten_child(
                    state_value,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::ObjectState,
                )?;
            }
            for (index, item) in listitems.iter().enumerate() {
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::ObjectListItem(index),
                )?;
            }
            for (index, (key, item)) in dictitems.iter().enumerate() {
                flatten_child(
                    key,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::ObjectDictKey(index),
                )?;
                flatten_child(
                    item,
                    pool,
                    next,
                    pending_dicts,
                    path,
                    DictPathStep::ObjectDictValue(index),
                )?;
            }
        }
        PickleValue::None
        | PickleValue::Bool(_)
        | PickleValue::Ext { .. }
        | PickleValue::MemoRef { .. }
        | PickleValue::OutOfBandBuffer { .. } => {}
    }
    Ok(())
}

fn index_string_digest(pool: &mut ConstantsPool, digest: String, value: &str) {
    match pool.digest_to_string.get(&digest) {
        Some(existing) if existing != value => {
            pool.ambiguous_string_digests.insert(digest);
        }
        Some(_) => {}
        None => {
            pool.digest_to_string.insert(digest, value.to_owned());
        }
    }
}

fn index_bytes_digest(pool: &mut ConstantsPool, digest: String, value: &[u8]) {
    match pool.digest_to_bytes.get(&digest) {
        Some(existing) if existing.as_slice() != value => {
            pool.ambiguous_bytes_digests.insert(digest);
        }
        Some(_) => {}
        None => {
            pool.digest_to_bytes.insert(digest, value.to_vec());
        }
    }
}

fn flatten_child(
    value: &PickleValue,
    pool: &mut ConstantsPool,
    depth: usize,
    pending_dicts: &mut Vec<PendingDictDigest>,
    path: &mut Vec<DictPathStep>,
    step: DictPathStep,
) -> Result<()> {
    path.push(step);
    let result: Result<()> = flatten_into(value, pool, depth, pending_dicts, path);
    let _: Option<DictPathStep> = path.pop();
    result
}

fn md5_hex_nuitka_value_repr(value: &PickleValue, depth: usize) -> Option<String> {
    let repr: String = nuitka_value_repr(value, depth)?;
    Some(format!("{:x}", md5::compute(repr.as_bytes())))
}

pub(crate) fn nuitka_value_repr(value: &PickleValue, depth: usize) -> Option<String> {
    if depth > FLATTEN_DEPTH {
        return None;
    }
    let next: usize = depth.checked_add(1)?;
    match value {
        PickleValue::None => Some("None".to_owned()),
        PickleValue::Bool(true) => Some("True".to_owned()),
        PickleValue::Bool(false) => Some("False".to_owned()),
        PickleValue::Int(value) => Some(value.to_string()),
        PickleValue::BigInt(value) if is_decimal_integer(value) => Some(value.clone()),
        PickleValue::Float(value) => Some(nuitka_float_repr(*value)),
        PickleValue::Str(value) => Some(nuitka_string_repr(value)),
        PickleValue::Bytes(value) => Some(nuitka_bytes_repr(value)),
        PickleValue::Global { module, name } => {
            builtin_type_name(module, name).map(|name: &str| format!("<class '{name}'>"))
        }
        PickleValue::Tuple(values) => nuitka_sequence_repr(values, '(', ')', true, next),
        PickleValue::List(values) => nuitka_sequence_repr(values, '[', ']', false, next),
        PickleValue::Set(values) => nuitka_set_repr(values, next),
        PickleValue::FrozenSet(values) => nuitka_frozenset_repr(values, next),
        PickleValue::Dict(pairs) => nuitka_dict_repr(pairs, next),
        _ => None,
    }
}

fn is_decimal_integer(value: &str) -> bool {
    let digits: &str = value.strip_prefix('-').map_or(value, |digits: &str| digits);
    !digits.is_empty() && digits.bytes().all(|byte: u8| byte.is_ascii_digit())
}

fn nuitka_float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value == f64::INFINITY {
        return "inf".to_owned();
    }
    if value == f64::NEG_INFINITY {
        return "-inf".to_owned();
    }
    let rendered: String = format!("{value:?}");
    normalize_python_float_exponent(&rendered)
}

fn normalize_python_float_exponent(rendered: &str) -> String {
    let Some(exponent_start): Option<usize> = rendered.find(['e', 'E']) else {
        return rendered.to_owned();
    };
    let mantissa: &str = &rendered[..exponent_start];
    let exponent: &str = &rendered[exponent_start + 1..];
    let mut characters: std::str::Chars<'_> = exponent.chars();
    let (sign, digits): (&str, &str) = match characters.next() {
        Some('+') => ("+", characters.as_str()),
        Some('-') => ("-", characters.as_str()),
        _ => ("+", exponent),
    };
    if digits.is_empty() || !digits.bytes().all(|byte: u8| byte.is_ascii_digit()) {
        return rendered.to_owned();
    }
    let padding: &str = if digits.len() == 1 { "0" } else { "" };
    format!("{mantissa}e{sign}{padding}{digits}")
}

fn nuitka_set_repr(values: &[PickleValue], depth: usize) -> Option<String> {
    if values.is_empty() {
        return Some("set()".to_owned());
    }
    nuitka_sequence_repr(values, '{', '}', false, depth)
}

fn nuitka_frozenset_repr(values: &[PickleValue], depth: usize) -> Option<String> {
    if values.is_empty() {
        return Some("frozenset()".to_owned());
    }
    let set: String = nuitka_set_repr(values, depth)?;
    Some(format!("frozenset({set})"))
}

fn nuitka_sequence_repr(
    values: &[PickleValue],
    open: char,
    close: char,
    singleton_comma: bool,
    depth: usize,
) -> Option<String> {
    let values: Vec<String> = values
        .iter()
        .map(|value: &PickleValue| nuitka_value_repr(value, depth))
        .collect::<Option<_>>()?;
    let mut rendered: String = values.join(", ");
    if singleton_comma && values.len() == 1 {
        rendered.push(',');
    }
    Some(format!("{open}{rendered}{close}"))
}

fn nuitka_dict_repr(pairs: &[(PickleValue, PickleValue)], depth: usize) -> Option<String> {
    let pairs: Option<Vec<String>> = pairs
        .iter()
        .map(|(key, value): &(PickleValue, PickleValue)| {
            Some(format!(
                "{}: {}",
                nuitka_value_repr(key, depth)?,
                nuitka_value_repr(value, depth)?
            ))
        })
        .collect();
    Some(format!("{{{}}}", pairs?.join(", ")))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MODULE_CONST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/module.hello.const");

    fn flatten_test_value(value: PickleValue, pool: &mut ConstantsPool) {
        let entry_index: usize = pool.entries.len();
        let mut pending_dicts: Vec<PendingDictDigest> = Vec::new();
        let mut path: Vec<DictPathStep> = Vec::new();
        flatten_into(&value, pool, 0, &mut pending_dicts, &mut path).expect("flatten");
        pool.entries.push(ConstantEntry {
            provenance: ConstantProvenance {
                source_file: "test".to_owned(),
                blob_name: "test".to_owned(),
                stream_index: entry_index,
                byte_offset: 0usize,
                byte_len: 0usize,
            },
            value,
        });
        index_pending_dicts(pool, entry_index, pending_dicts);
    }

    #[test]
    fn conflicting_string_and_bytes_digest_values_are_ambiguous() {
        let mut pool: ConstantsPool = ConstantsPool::default();
        index_string_digest(&mut pool, "collision".to_owned(), "first");
        index_string_digest(&mut pool, "collision".to_owned(), "second");
        index_bytes_digest(&mut pool, "collision".to_owned(), b"first");
        index_bytes_digest(&mut pool, "collision".to_owned(), b"second");
        assert_eq!(
            pool.digest_to_string.get("collision").map(String::as_str),
            Some("first")
        );
        assert_eq!(
            pool.digest_to_bytes.get("collision").map(Vec::as_slice),
            Some(b"first".as_slice())
        );
        assert!(pool.ambiguous_string_digests.contains("collision"));
        assert!(pool.ambiguous_bytes_digests.contains("collision"));
    }

    #[test]
    fn single_stream_int_consumes_all_bytes() {
        let bytes: &[u8] = b"\x80\x05K\x07.";
        let pool: ConstantsPool = decode_const_file(bytes, "x.const", "x").expect("decode");
        assert_eq!(pool.stream_count, 1);
        assert_eq!(pool.bytes_consumed, bytes.len());
        assert!(pool.ints.contains(&7));
    }

    #[test]
    fn concatenated_streams_with_shared_memo() {
        let module: ConstantsPool =
            decode_const_file(MODULE_CONST, "module.hello.const", "hello").expect("decode");
        assert_eq!(module.bytes_consumed, MODULE_CONST.len());
        assert!(module.strings.contains("greet"));
        assert!(module.strings.contains("fib"));
        assert!(module.strings.contains("disrobe"));
        assert!(
            module
                .globals
                .contains(&("builtins".to_owned(), "str".to_owned()))
        );
    }

    #[test]
    fn stream_lacking_stop_surfaces_pickle_error() {
        let bytes: &[u8] = b"\x80\x05K\x07";
        let r: Result<ConstantsPool> = decode_const_file(bytes, "x.const", "x");
        assert!(matches!(r, Err(Error::ConstPickle(_))));
    }

    #[test]
    fn float_dedup_by_bit_pattern() {
        let bytes: &[u8] = b"\x80\x05\x95\x00\x00\x00\x00\x00\x00\x00\x00G?\xf0\x00\x00\x00\x00\x00\x00.\x80\x05G?\xf0\x00\x00\x00\x00\x00\x00.";
        let pool: ConstantsPool = decode_const_file(bytes, "x.const", "x").expect("decode");
        assert_eq!(pool.floats.len(), 1);
        assert!((pool.floats[0] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn build_constants_unions_strings_and_ints() {
        let files: Vec<(String, Vec<u8>, String)> = vec![
            (
                "a.const".to_owned(),
                b"\x80\x05\x8c\x03foo\x94.".to_vec(),
                "a".to_owned(),
            ),
            (
                "b.const".to_owned(),
                b"\x80\x05K\x2a.".to_vec(),
                "b".to_owned(),
            ),
        ];
        let table: ConstantsTable = decode_build_constants(&files).expect("decode build");
        assert_eq!(table.pools.len(), 2);
        assert!(table.all_strings.contains("foo"));
        assert!(table.all_ints.contains(&42));
    }

    #[test]
    fn constant_input_caps_reject_before_decode() {
        assert!(matches!(
            validate_const_file_size(usize::try_from(MAX_CONST_FILE_BYTES + 1u64).unwrap()),
            Err(Error::InputTooLarge { resource, bytes, max_bytes })
                if resource == "constant file"
                    && bytes == MAX_CONST_FILE_BYTES + 1u64
                    && max_bytes == MAX_CONST_FILE_BYTES
        ));
        assert!(matches!(
            validate_constant_input_count(MAX_BUILD_CONST_FILES + 1usize),
            Err(Error::TooManyConstantInputs { count, max_count })
                if count == MAX_BUILD_CONST_FILES + 1usize
                    && max_count == MAX_BUILD_CONST_FILES
        ));
        assert!(matches!(
            validate_constant_input_total(MAX_BUILD_CONST_BYTES + 1u64),
            Err(Error::InputTooLarge { resource, bytes, max_bytes })
                if resource == "constant input set"
                    && bytes == MAX_BUILD_CONST_BYTES + 1u64
                    && max_bytes == MAX_BUILD_CONST_BYTES
        ));
    }

    #[test]
    fn prior_pool_json_without_bytes_fields_deserializes() {
        let prior: &str = r#"{
            "entries": [],
            "strings": [],
            "ints": [],
            "floats": [],
            "tuples": [],
            "globals": [],
            "digest_to_string": {},
            "bytes_consumed": 0,
            "stream_count": 0
        }"#;
        let pool: ConstantsPool = serde_json::from_str(prior).expect("deserialize");
        assert!(pool.bytes.is_empty());
        assert!(pool.digest_to_bytes.is_empty());
        assert!(pool.ambiguous_string_digests.is_empty());
        assert!(pool.ambiguous_bytes_digests.is_empty());
        assert!(pool.digest_to_dict.is_empty());
        assert!(pool.ambiguous_dict_digests.is_empty());
    }

    #[test]
    fn strings_use_nuitka_repr_digest_keys() {
        let value: &str = "quote' slash\\ newline\n";
        let mut pool: ConstantsPool = ConstantsPool::default();
        flatten_test_value(PickleValue::Str(value.to_owned()), &mut pool);
        assert_eq!(
            pool.digest_to_string
                .get("b29780b2f746c359f51f8b02f50dc142"),
            Some(&value.to_owned())
        );
    }

    #[test]
    fn literal_repr_matches_cpython_control_escapes() {
        assert_eq!(nuitka_string_repr("\u{007f}\u{200b}😀"), "'\\x7f\\u200b😀'");
        assert_eq!(
            nuitka_string_repr("\u{00a0}\u{200e}\u{feff}"),
            "'\\xa0\\u200e\\ufeff'"
        );
        assert_eq!(
            nuitka_bytes_repr(&[0x7f, 0xa0, b'\'', b'"']),
            "b'\\x7f\\xa0\\\'\"'"
        );
    }

    #[test]
    fn structured_values_use_cpython_repr_forms() {
        assert_eq!(nuitka_float_repr(1.5), "1.5");
        assert_eq!(nuitka_float_repr(1.0e20), "1e+20");
        assert_eq!(nuitka_float_repr(1.0e-7), "1e-07");
        assert_eq!(nuitka_float_repr(f64::INFINITY), "inf");
        assert_eq!(nuitka_float_repr(f64::NAN), "nan");
        let value: PickleValue = PickleValue::Dict(vec![
            (
                PickleValue::Str("ratio".to_owned()),
                PickleValue::Float(1.5),
            ),
            (
                PickleValue::Str("labels".to_owned()),
                PickleValue::FrozenSet(vec![PickleValue::Int(1), PickleValue::Int(2)]),
            ),
            (
                PickleValue::Str("options".to_owned()),
                PickleValue::Set(vec![PickleValue::Int(3), PickleValue::Int(4)]),
            ),
        ]);
        assert_eq!(
            nuitka_value_repr(&value, 0usize).as_deref(),
            Some("{'ratio': 1.5, 'labels': frozenset({1, 2}), 'options': {3, 4}}")
        );
    }

    #[test]
    fn float_reemit_keeps_decimal_sign_and_boundary_form() {
        assert_eq!(nuitka_float_repr(2.0), "2.0");
        assert_eq!(nuitka_float_repr(100.0), "100.0");
        assert_eq!(nuitka_float_repr(1e15), "1000000000000000.0");
        assert_eq!(nuitka_float_repr(1e16), "1e+16");
        assert_eq!(nuitka_float_repr(1e-4), "0.0001");
        assert_eq!(nuitka_float_repr(1e-5), "1e-05");
        assert_eq!(
            nuitka_float_repr(1_234_567_890_123_456.0),
            "1234567890123456.0"
        );
        assert_eq!(nuitka_float_repr(-0.0), "-0.0");
        assert_eq!(
            nuitka_value_repr(&PickleValue::Float(-0.0), 0usize).as_deref(),
            Some("-0.0")
        );
    }

    #[test]
    fn high_byte_reemit_matches_cpython_escapes() {
        assert_eq!(
            nuitka_bytes_repr(&[0x80, 0xff, 0x00, 0x7f]),
            "b'\\x80\\xff\\x00\\x7f'"
        );
        assert_eq!(nuitka_bytes_repr(&[0xe4, 0xb8, 0xad]), "b'\\xe4\\xb8\\xad'");
        assert_eq!(nuitka_bytes_repr(b"'"), "b\"'\"");
        assert_eq!(nuitka_bytes_repr(b"\""), "b'\"'");
        assert_eq!(nuitka_bytes_repr(b"'\""), "b'\\'\"'");
        assert_eq!(nuitka_string_repr("\u{e9}"), "'\u{e9}'");
        assert_eq!(nuitka_string_repr("\u{4e2d}"), "'\u{4e2d}'");
        assert_eq!(nuitka_string_repr("\u{1f600}"), "'\u{1f600}'");
        assert_eq!(nuitka_string_repr("\u{7f}"), "'\\x7f'");
        assert_eq!(nuitka_string_repr("\u{a0}"), "'\\xa0'");
        assert_eq!(nuitka_string_repr("{x}=%s"), "'{x}=%s'");
        assert_eq!(nuitka_string_repr("quote'here"), "\"quote'here\"");
        assert_eq!(nuitka_string_repr("dq\"here"), "'dq\"here'");
        assert_eq!(nuitka_string_repr("both'\"x"), "'both\\'\"x'");
    }

    #[test]
    fn dictionaries_use_nuitka_repr_digest_keys() {
        let value: PickleValue = PickleValue::Dict(vec![
            (
                PickleValue::Str("enabled".to_owned()),
                PickleValue::Bool(true),
            ),
            (PickleValue::Str("limit".to_owned()), PickleValue::Int(7)),
        ]);
        let mut pool: ConstantsPool = ConstantsPool::default();
        flatten_test_value(value.clone(), &mut pool);
        let digest: String = format!("{:x}", md5::compute(b"{'enabled': True, 'limit': 7}"));
        let expected: Option<&[(PickleValue, PickleValue)]> = match &value {
            PickleValue::Dict(pairs) => Some(pairs),
            _ => None,
        };
        assert_eq!(pool.dict_pairs_for_digest(&digest), expected);
    }

    #[test]
    fn deeply_nested_dictionary_repr_respects_flatten_depth() {
        let mut value: PickleValue = PickleValue::Int(1);
        for _ in 0..=FLATTEN_DEPTH {
            value = PickleValue::Dict(vec![(PickleValue::Str("k".to_owned()), value)]);
        }
        assert!(nuitka_value_repr(&value, 0usize).is_none());
        let mut pool: ConstantsPool = ConstantsPool::default();
        let mut pending_dicts: Vec<PendingDictDigest> = Vec::new();
        let mut path: Vec<DictPathStep> = Vec::new();
        assert!(matches!(
            flatten_into(&value, &mut pool, 0usize, &mut pending_dicts, &mut path),
            Err(Error::ConstFlattenDepth)
        ));
    }
}
