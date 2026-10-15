use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::error::{Error, Result};

const MAGIC: &[u8; 10] = b"NIBArchive";
const HEADER_LEN: usize = 50;
const TABLE_ENTRY_MIN: usize = 1;
const VARINT_MAX_BYTES: usize = 10;
const CLASS_EXTRAS_MAX: usize = 1024;
const STRING_CLASSES: [&str; 3] = ["NSString", "NSMutableString", "NSLocalizableString"];

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum NibValue {
    Int8 {
        value: i8,
    },
    Int16 {
        value: i16,
    },
    Int32 {
        value: i32,
    },
    Int64 {
        value: i64,
    },
    Bool {
        value: bool,
    },
    Float {
        value: f32,
    },
    Double {
        value: f64,
    },
    Data {
        hex: String,
        numbers: Option<Vec<f64>>,
    },
    Nil,
    Object {
        index: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NibEntry {
    pub key: String,
    pub value: NibValue,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NibObject {
    pub index: usize,
    pub class: String,
    pub entries: Vec<NibEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct NibClass {
    pub name: String,
    pub extras: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct NibConnection {
    pub kind: String,
    pub label: Option<String>,
    pub source: Option<u32>,
    pub source_class: Option<String>,
    pub destination: Option<u32>,
    pub destination_class: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct NibArchive {
    pub format_version: u32,
    pub coder_version: u32,
    pub classes: Vec<NibClass>,
    pub objects: Vec<NibObject>,
    pub connections: Vec<NibConnection>,
    pub custom_classes: Vec<String>,
    pub strings: Vec<String>,
    pub trailing_bytes: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
    end: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8], start: usize, end: usize) -> Self {
        Self {
            bytes,
            at: start,
            end,
        }
    }

    fn take(&mut self, len: usize, what: &str) -> Result<&'a [u8]> {
        let stop: usize = self
            .at
            .checked_add(len)
            .filter(|stop: &usize| *stop <= self.end)
            .ok_or_else(|| {
                malformed(format!("{what} at offset {} runs past its table", self.at))
            })?;
        let slice: &'a [u8] = &self.bytes[self.at..stop];
        self.at = stop;
        Ok(slice)
    }

    fn byte(&mut self, what: &str) -> Result<u8> {
        Ok(self.take(1, what)?[0])
    }

    fn varint(&mut self, what: &str) -> Result<u64> {
        let mut value: u64 = 0;
        for index in 0..VARINT_MAX_BYTES {
            let byte: u8 = self.byte(what)?;
            let shift: u32 = u32::try_from(index * 7).unwrap_or(u32::MAX);
            let part: u64 = u64::from(byte & 0x7f)
                .checked_shl(shift)
                .filter(|part: &u64| part >> shift == u64::from(byte & 0x7f))
                .ok_or_else(|| malformed(format!("{what} varint overflows 64 bits")))?;
            value |= part;
            if byte & 0x80 != 0 {
                return Ok(value);
            }
        }
        Err(malformed(format!(
            "{what} varint is longer than {VARINT_MAX_BYTES} bytes"
        )))
    }

    fn index(&mut self, what: &str) -> Result<usize> {
        usize::try_from(self.varint(what)?)
            .map_err(|_| malformed(format!("{what} is not addressable")))
    }

    fn array<const N: usize>(&mut self, what: &str) -> Result<[u8; N]> {
        let slice: &[u8] = self.take(N, what)?;
        let mut out: [u8; N] = [0; N];
        out.copy_from_slice(slice);
        Ok(out)
    }
}

const fn malformed(message: String) -> Error {
    Error::NibArchive(message)
}

#[must_use]
pub fn is_nib_archive(bytes: &[u8]) -> bool {
    bytes.starts_with(MAGIC)
}

struct Header {
    format_version: u32,
    coder_version: u32,
    tables: [(usize, usize); 4],
}

fn header(bytes: &[u8]) -> Result<Header> {
    if !is_nib_archive(bytes) {
        return Err(malformed(
            "the file does not start with NIBArchive".to_owned(),
        ));
    }
    let fields: &[u8] = bytes.get(MAGIC.len()..HEADER_LEN).ok_or_else(|| {
        malformed(format!(
            "header needs {HEADER_LEN} bytes, file has {}",
            bytes.len()
        ))
    })?;
    let words: Vec<u32> = fields
        .chunks_exact(4)
        .map(|chunk: &[u8]| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect();
    let table = |pair: usize| -> Result<(usize, usize)> {
        let count: usize = usize::try_from(words[2 + pair * 2])
            .map_err(|_| malformed("table count is not addressable".to_owned()))?;
        let offset: usize = usize::try_from(words[3 + pair * 2])
            .map_err(|_| malformed("table offset is not addressable".to_owned()))?;
        Ok((count, offset))
    };
    Ok(Header {
        format_version: words[0],
        coder_version: words[1],
        tables: [table(0)?, table(1)?, table(2)?, table(3)?],
    })
}

pub fn decode_nib_archive(bytes: &[u8]) -> Result<NibArchive> {
    let header: Header = header(bytes)?;
    let [objects_at, keys_at, values_at, classes_at]: [(usize, usize); 4] = header.tables;
    let names: [&str; 4] = ["object", "key", "value", "class name"];
    for ((count, offset), name) in header.tables.iter().zip(names) {
        if *offset < HEADER_LEN || *offset > bytes.len() {
            return Err(malformed(format!(
                "{name} table offset {offset} lies outside the file"
            )));
        }
        let room: usize = bytes.len() - offset;
        if count.saturating_mul(TABLE_ENTRY_MIN) > room {
            return Err(malformed(format!(
                "{name} table declares {count} entries but only {room} bytes follow it"
            )));
        }
    }
    let mut order: Vec<(usize, usize)> = header
        .tables
        .iter()
        .enumerate()
        .map(|(slot, (_, offset))| (*offset, slot))
        .collect();
    order.sort_unstable();
    let mut ends: [usize; 4] = [bytes.len(); 4];
    for pair in order.windows(2) {
        ends[pair[0].1] = pair[1].0;
    }
    let (raw_objects, objects_end): (Vec<(usize, usize, usize)>, usize) =
        read_objects(bytes, objects_at, ends[0])?;
    let (keys, keys_end): (Vec<String>, usize) = read_keys(bytes, keys_at, ends[1])?;
    let (values, values_end): (Vec<(usize, NibValue)>, usize) =
        read_values(bytes, values_at, ends[2])?;
    let (classes, classes_end): (Vec<NibClass>, usize) = read_classes(bytes, classes_at, ends[3])?;
    let last_slot: usize = order.last().map_or(3, |(_, slot): &(usize, usize)| *slot);
    let consumed: usize = [objects_end, keys_end, values_end, classes_end][last_slot];
    let mut objects: Vec<NibObject> = Vec::with_capacity(raw_objects.len());
    for (index, (class_index, first, count)) in raw_objects.into_iter().enumerate() {
        let class: &NibClass = classes.get(class_index).ok_or_else(|| {
            malformed(format!(
                "object {index} names class {class_index} of {}",
                classes.len()
            ))
        })?;
        let stop: usize = first
            .checked_add(count)
            .filter(|stop: &usize| *stop <= values.len())
            .ok_or_else(|| {
                malformed(format!(
                    "object {index} takes values {first}..{first}+{count} of {}",
                    values.len()
                ))
            })?;
        let mut entries: Vec<NibEntry> = Vec::with_capacity(count);
        for (key_index, value) in &values[first..stop] {
            let key: &String = keys.get(*key_index).ok_or_else(|| {
                malformed(format!("a value names key {key_index} of {}", keys.len()))
            })?;
            if let NibValue::Object { index: target } = value
                && usize::try_from(*target)
                    .map_or(true, |target: usize| target >= header.tables[0].0)
            {
                return Err(malformed(format!(
                    "object {index} refers to object {target} of {}",
                    header.tables[0].0
                )));
            }
            entries.push(NibEntry {
                key: key.clone(),
                value: value.clone(),
            });
        }
        objects.push(NibObject {
            index,
            class: class.name.clone(),
            entries,
        });
    }
    let strings: BTreeMap<usize, String> = string_objects(&objects);
    Ok(NibArchive {
        format_version: header.format_version,
        coder_version: header.coder_version,
        connections: connections(&objects, &strings),
        custom_classes: custom_classes(&objects, &strings),
        strings: strings
            .values()
            .cloned()
            .collect::<BTreeSet<String>>()
            .into_iter()
            .collect(),
        trailing_bytes: bytes.len().saturating_sub(consumed),
        classes,
        objects,
    })
}

type Objects = (Vec<(usize, usize, usize)>, usize);

fn read_objects(bytes: &[u8], (count, offset): (usize, usize), end: usize) -> Result<Objects> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, offset, end);
    let mut objects: Vec<(usize, usize, usize)> = Vec::with_capacity(count);
    for _ in 0..count {
        let class: usize = cursor.index("object class index")?;
        let first: usize = cursor.index("object value index")?;
        let values: usize = cursor.index("object value count")?;
        objects.push((class, first, values));
    }
    Ok((objects, cursor.at))
}

fn read_keys(
    bytes: &[u8],
    (count, offset): (usize, usize),
    end: usize,
) -> Result<(Vec<String>, usize)> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, offset, end);
    let mut keys: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        let len: usize = cursor.index("key length")?;
        let name: &[u8] = cursor.take(len, "key name")?;
        keys.push(String::from_utf8_lossy(name).into_owned());
    }
    Ok((keys, cursor.at))
}

type Values = (Vec<(usize, NibValue)>, usize);

fn read_values(bytes: &[u8], (count, offset): (usize, usize), end: usize) -> Result<Values> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, offset, end);
    let mut values: Vec<(usize, NibValue)> = Vec::with_capacity(count);
    for _ in 0..count {
        let key: usize = cursor.index("value key index")?;
        let kind: u8 = cursor.byte("value type")?;
        let value: NibValue = match kind {
            0 => NibValue::Int8 {
                value: i8::from_le_bytes(cursor.array::<1>("int8 value")?),
            },
            1 => NibValue::Int16 {
                value: i16::from_le_bytes(cursor.array::<2>("int16 value")?),
            },
            2 => NibValue::Int32 {
                value: i32::from_le_bytes(cursor.array::<4>("int32 value")?),
            },
            3 => NibValue::Int64 {
                value: i64::from_le_bytes(cursor.array::<8>("int64 value")?),
            },
            4 => NibValue::Bool { value: true },
            5 => NibValue::Bool { value: false },
            6 => NibValue::Float {
                value: f32::from_le_bytes(cursor.array::<4>("float value")?),
            },
            7 => NibValue::Double {
                value: f64::from_le_bytes(cursor.array::<8>("double value")?),
            },
            8 => {
                let len: usize = cursor.index("data length")?;
                let data: &[u8] = cursor.take(len, "data bytes")?;
                NibValue::Data {
                    hex: hex(data),
                    numbers: packed_numbers(data),
                }
            }
            9 => NibValue::Nil,
            10 => NibValue::Object {
                index: u32::from_le_bytes(cursor.array::<4>("object reference")?),
            },
            other => {
                return Err(malformed(format!(
                    "value type {other} at offset {} is not a NIB value type",
                    cursor.at - 1
                )));
            }
        };
        values.push((key, value));
    }
    Ok((values, cursor.at))
}

fn read_classes(
    bytes: &[u8],
    (count, offset): (usize, usize),
    end: usize,
) -> Result<(Vec<NibClass>, usize)> {
    let mut cursor: Cursor<'_> = Cursor::new(bytes, offset, end);
    let mut classes: Vec<NibClass> = Vec::with_capacity(count);
    for _ in 0..count {
        let len: usize = cursor.index("class name length")?;
        let extra_count: usize = cursor.index("class extra count")?;
        if extra_count > CLASS_EXTRAS_MAX {
            return Err(malformed(format!(
                "class declares {extra_count} extra values, over the {CLASS_EXTRAS_MAX} cap"
            )));
        }
        let mut extras: Vec<i32> = Vec::with_capacity(extra_count);
        for _ in 0..extra_count {
            extras.push(i32::from_le_bytes(cursor.array::<4>("class extra value")?));
        }
        let name: &[u8] = cursor.take(len, "class name")?;
        let trimmed: &[u8] = name.strip_suffix(&[0]).unwrap_or(name);
        classes.push(NibClass {
            name: String::from_utf8_lossy(trimmed).into_owned(),
            extras,
        });
    }
    Ok((classes, cursor.at))
}

fn packed_numbers(data: &[u8]) -> Option<Vec<f64>> {
    let (&tag, rest): (&u8, &[u8]) = data.split_first()?;
    if rest.is_empty() {
        return None;
    }
    match tag {
        7 if rest.len() % 8 == 0 => Some(
            rest.chunks_exact(8)
                .map(|chunk: &[u8]| {
                    f64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ])
                })
                .collect(),
        ),
        6 if rest.len() % 4 == 0 => Some(
            rest.chunks_exact(4)
                .map(|chunk: &[u8]| {
                    f64::from(f32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
                })
                .collect(),
        ),
        _ => None,
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut text: String = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(DIGITS[usize::from(byte >> 4)]));
        text.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    text
}

fn unhex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .chunks_exact(2)
        .filter_map(|pair: &[u8]| {
            let high: u8 = char::from(pair[0])
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())?;
            let low: u8 = char::from(pair[1])
                .to_digit(16)
                .and_then(|d| u8::try_from(d).ok())?;
            Some(high << 4 | low)
        })
        .collect()
}

fn string_objects(objects: &[NibObject]) -> BTreeMap<usize, String> {
    let mut strings: BTreeMap<usize, String> = BTreeMap::new();
    for object in objects {
        if !STRING_CLASSES.contains(&object.class.as_str()) {
            continue;
        }
        let bytes: Option<Vec<u8>> =
            object
                .entries
                .iter()
                .find_map(|entry: &NibEntry| match &entry.value {
                    NibValue::Data { hex, .. } if entry.key == "NS.bytes" => Some(unhex(hex)),
                    _ => None,
                });
        if let Some(bytes) = bytes
            && let Ok(text) = String::from_utf8(bytes)
        {
            strings.insert(object.index, text);
        }
    }
    strings
}

fn reference(object: &NibObject, key: &str) -> Option<u32> {
    object
        .entries
        .iter()
        .find_map(|entry: &NibEntry| match entry.value {
            NibValue::Object { index } if entry.key == key => Some(index),
            _ => None,
        })
}

fn class_of(
    objects: &[NibObject],
    strings: &BTreeMap<usize, String>,
    index: Option<u32>,
) -> Option<String> {
    let object: &NibObject = objects.get(usize::try_from(index?).ok()?)?;
    if object.class == "UIClassSwapper"
        && let Some(name) = reference(object, "UIClassName")
            .and_then(|target: u32| usize::try_from(target).ok())
            .and_then(|target: usize| strings.get(&target))
    {
        return Some(name.clone());
    }
    Some(object.class.clone())
}

fn connections(objects: &[NibObject], strings: &BTreeMap<usize, String>) -> Vec<NibConnection> {
    let mut found: Vec<NibConnection> = Vec::new();
    for object in objects {
        let kind: &str = match object.class.as_str() {
            "UIRuntimeOutletConnection" | "NSNibOutletConnector" => "outlet",
            "UIRuntimeOutletCollectionConnection" => "outlet-collection",
            "UIRuntimeEventConnection" | "NSNibControlConnector" => "action",
            _ => continue,
        };
        let label: Option<String> = ["UILabel", "NSLabel"]
            .into_iter()
            .find_map(|key: &str| reference(object, key))
            .and_then(|index: u32| usize::try_from(index).ok())
            .and_then(|index: usize| strings.get(&index).cloned());
        let source: Option<u32> = ["UISource", "NSSource"]
            .into_iter()
            .find_map(|key: &str| reference(object, key));
        let destination: Option<u32> = ["UIDestination", "NSDestination"]
            .into_iter()
            .find_map(|key: &str| reference(object, key));
        found.push(NibConnection {
            kind: kind.to_owned(),
            label,
            source,
            source_class: class_of(objects, strings, source),
            destination,
            destination_class: class_of(objects, strings, destination),
        });
    }
    found.sort();
    found
}

fn custom_classes(objects: &[NibObject], strings: &BTreeMap<usize, String>) -> Vec<String> {
    let mut names: BTreeSet<String> = BTreeSet::new();
    for object in objects {
        if object.class != "UIClassSwapper" {
            continue;
        }
        if let Some(name) = reference(object, "UIClassName")
            .and_then(|index: u32| usize::try_from(index).ok())
            .and_then(|index: usize| strings.get(&index))
        {
            names.insert(name.clone());
        }
    }
    names.into_iter().collect()
}
