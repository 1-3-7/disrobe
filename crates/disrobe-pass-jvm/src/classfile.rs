use std::collections::BTreeMap;

use disrobe_bytes::ByteReader;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const CLASS_MAGIC: u32 = 0xCAFE_BABE;
pub const MIN_MAJOR: u16 = 45;
pub const MAX_MAJOR: u16 = 69;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JavaVersion {
    Jdk1_0_2,
    Jdk1_1,
    Jdk1_2,
    Jdk1_3,
    Jdk1_4,
    Jse5,
    Jse6,
    Jse7,
    Jse8,
    Jse9,
    Jse10,
    Jse11,
    Jse12,
    Jse13,
    Jse14,
    Jse15,
    Jse16,
    Jse17,
    Jse18,
    Jse19,
    Jse20,
    Jse21,
    Jse22,
    Jse23,
    Jse24,
    Jse25,
}

impl JavaVersion {
    #[inline]
    #[must_use]
    pub const fn from_major(major: u16) -> Option<Self> {
        match major {
            45 => Some(Self::Jdk1_0_2),
            46 => Some(Self::Jdk1_2),
            47 => Some(Self::Jdk1_3),
            48 => Some(Self::Jdk1_4),
            49 => Some(Self::Jse5),
            50 => Some(Self::Jse6),
            51 => Some(Self::Jse7),
            52 => Some(Self::Jse8),
            53 => Some(Self::Jse9),
            54 => Some(Self::Jse10),
            55 => Some(Self::Jse11),
            56 => Some(Self::Jse12),
            57 => Some(Self::Jse13),
            58 => Some(Self::Jse14),
            59 => Some(Self::Jse15),
            60 => Some(Self::Jse16),
            61 => Some(Self::Jse17),
            62 => Some(Self::Jse18),
            63 => Some(Self::Jse19),
            64 => Some(Self::Jse20),
            65 => Some(Self::Jse21),
            66 => Some(Self::Jse22),
            67 => Some(Self::Jse23),
            68 => Some(Self::Jse24),
            69 => Some(Self::Jse25),
            _ => None,
        }
    }

    #[inline]
    #[must_use]
    pub const fn marketing_name(self) -> &'static str {
        match self {
            Self::Jdk1_0_2 => "JDK 1.0.2 / 1.1",
            Self::Jdk1_1 => "JDK 1.1",
            Self::Jdk1_2 => "JDK 1.2",
            Self::Jdk1_3 => "JDK 1.3",
            Self::Jdk1_4 => "JDK 1.4",
            Self::Jse5 => "Java SE 5",
            Self::Jse6 => "Java SE 6",
            Self::Jse7 => "Java SE 7",
            Self::Jse8 => "Java SE 8",
            Self::Jse9 => "Java SE 9",
            Self::Jse10 => "Java SE 10",
            Self::Jse11 => "Java SE 11 (LTS)",
            Self::Jse12 => "Java SE 12",
            Self::Jse13 => "Java SE 13",
            Self::Jse14 => "Java SE 14",
            Self::Jse15 => "Java SE 15",
            Self::Jse16 => "Java SE 16",
            Self::Jse17 => "Java SE 17 (LTS)",
            Self::Jse18 => "Java SE 18",
            Self::Jse19 => "Java SE 19",
            Self::Jse20 => "Java SE 20",
            Self::Jse21 => "Java SE 21 (LTS)",
            Self::Jse22 => "Java SE 22",
            Self::Jse23 => "Java SE 23",
            Self::Jse24 => "Java SE 24",
            Self::Jse25 => "Java SE 25 (LTS)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConstantPoolEntry {
    Utf8(String),
    Integer(i32),
    Float(u32),
    Long(i64),
    Double(u64),
    Class {
        name_index: u16,
    },
    String {
        utf8_index: u16,
    },
    Fieldref {
        class_index: u16,
        name_and_type_index: u16,
    },
    Methodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    InterfaceMethodref {
        class_index: u16,
        name_and_type_index: u16,
    },
    NameAndType {
        name_index: u16,
        descriptor_index: u16,
    },
    MethodHandle {
        reference_kind: u8,
        reference_index: u16,
    },
    MethodType {
        descriptor_index: u16,
    },
    Dynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    InvokeDynamic {
        bootstrap_method_attr_index: u16,
        name_and_type_index: u16,
    },
    Module {
        name_index: u16,
    },
    Package {
        name_index: u16,
    },
    Placeholder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attribute {
    pub name_index: u16,
    pub info: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodInfo {
    pub access_flags: u16,
    pub name_index: u16,
    pub descriptor_index: u16,
    pub attributes: Vec<Attribute>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassFile {
    pub minor_version: u16,
    pub major_version: u16,
    pub constant_pool: Vec<ConstantPoolEntry>,
    pub access_flags: u16,
    pub this_class: u16,
    pub super_class: u16,
    pub interfaces: Vec<u16>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
    pub attributes: Vec<Attribute>,
}

impl ClassFile {
    #[inline]
    #[must_use]
    pub const fn version(&self) -> Option<JavaVersion> {
        JavaVersion::from_major(self.major_version)
    }

    pub fn utf8_at(&self, index: u16) -> Result<&str> {
        let idx: usize = usize::from(index);
        if idx == 0 || idx >= self.constant_pool.len() {
            return Err(Error::BadConstantIndex {
                idx,
                size: self.constant_pool.len(),
            });
        }
        match &self.constant_pool[idx] {
            ConstantPoolEntry::Utf8(s) => Ok(s.as_str()),
            _ => Err(Error::BadConstantIndex {
                idx,
                size: self.constant_pool.len(),
            }),
        }
    }

    pub fn class_name(&self, index: u16) -> Result<&str> {
        let idx: usize = usize::from(index);
        if idx == 0 || idx >= self.constant_pool.len() {
            return Err(Error::BadConstantIndex {
                idx,
                size: self.constant_pool.len(),
            });
        }
        let name_index: u16 = match self.constant_pool[idx] {
            ConstantPoolEntry::Class { name_index } => name_index,
            _ => {
                return Err(Error::BadConstantIndex {
                    idx,
                    size: self.constant_pool.len(),
                });
            }
        };
        self.utf8_at(name_index)
    }

    pub fn this_class_name(&self) -> Result<&str> {
        self.class_name(self.this_class)
    }

    #[must_use]
    pub fn collect_strings(&self) -> BTreeMap<u16, String> {
        let mut out: BTreeMap<u16, String> = BTreeMap::new();
        for (i, entry) in self.constant_pool.iter().enumerate() {
            if let ConstantPoolEntry::Utf8(s) = entry
                && let Ok(idx16) = u16::try_from(i)
            {
                out.insert(idx16, s.clone());
            }
        }
        out
    }
}

#[inline]
fn bounded_capacity(count: u16, remaining: usize) -> usize {
    usize::from(count).min(remaining)
}

pub fn parse(bytes: &[u8]) -> Result<ClassFile> {
    let mut r: ByteReader<'_> = ByteReader::new(bytes);
    let magic: u32 = r.read_u32_be()?;
    if magic != CLASS_MAGIC && !disrobe_binfmt::structural::validate_java_class(bytes) {
        return Err(Error::BadMagic(magic));
    }
    let minor_version: u16 = r.read_u16_be()?;
    let major_version: u16 = r.read_u16_be()?;
    if !(MIN_MAJOR..=MAX_MAJOR).contains(&major_version) {
        return Err(Error::UnsupportedClassVersion {
            major: major_version,
        });
    }
    let cp_count: u16 = r.read_u16_be()?;
    let mut cp: Vec<ConstantPoolEntry> =
        Vec::with_capacity(bounded_capacity(cp_count, r.remaining()));
    cp.push(ConstantPoolEntry::Placeholder);
    let mut i: usize = 1;
    while i < usize::from(cp_count) {
        let tag: u8 = r.read_u8()?;
        let entry: ConstantPoolEntry = match tag {
            1 => {
                let len: u16 = r.read_u16_be()?;
                let raw: &[u8] = r.read_bytes(usize::from(len))?;
                ConstantPoolEntry::Utf8(decode_modified_utf8(raw)?)
            }
            3 => ConstantPoolEntry::Integer(r.read_u32_be()? as i32),
            4 => ConstantPoolEntry::Float(r.read_u32_be()?),
            5 => ConstantPoolEntry::Long(r.read_u64_be()? as i64),
            6 => ConstantPoolEntry::Double(r.read_u64_be()?),
            7 => ConstantPoolEntry::Class {
                name_index: r.read_u16_be()?,
            },
            8 => ConstantPoolEntry::String {
                utf8_index: r.read_u16_be()?,
            },
            9 => ConstantPoolEntry::Fieldref {
                class_index: r.read_u16_be()?,
                name_and_type_index: r.read_u16_be()?,
            },
            10 => ConstantPoolEntry::Methodref {
                class_index: r.read_u16_be()?,
                name_and_type_index: r.read_u16_be()?,
            },
            11 => ConstantPoolEntry::InterfaceMethodref {
                class_index: r.read_u16_be()?,
                name_and_type_index: r.read_u16_be()?,
            },
            12 => ConstantPoolEntry::NameAndType {
                name_index: r.read_u16_be()?,
                descriptor_index: r.read_u16_be()?,
            },
            15 => ConstantPoolEntry::MethodHandle {
                reference_kind: r.read_u8()?,
                reference_index: r.read_u16_be()?,
            },
            16 => ConstantPoolEntry::MethodType {
                descriptor_index: r.read_u16_be()?,
            },
            17 => ConstantPoolEntry::Dynamic {
                bootstrap_method_attr_index: r.read_u16_be()?,
                name_and_type_index: r.read_u16_be()?,
            },
            18 => ConstantPoolEntry::InvokeDynamic {
                bootstrap_method_attr_index: r.read_u16_be()?,
                name_and_type_index: r.read_u16_be()?,
            },
            19 => ConstantPoolEntry::Module {
                name_index: r.read_u16_be()?,
            },
            20 => ConstantPoolEntry::Package {
                name_index: r.read_u16_be()?,
            },
            other => return Err(Error::UnknownConstantTag(other, i)),
        };
        let is_long_or_double: bool = matches!(
            entry,
            ConstantPoolEntry::Long(_) | ConstantPoolEntry::Double(_)
        );
        cp.push(entry);
        if is_long_or_double {
            cp.push(ConstantPoolEntry::Placeholder);
            i += 2;
        } else {
            i += 1;
        }
    }
    let access_flags: u16 = r.read_u16_be()?;
    let this_class: u16 = r.read_u16_be()?;
    let super_class: u16 = r.read_u16_be()?;
    let interfaces_count: u16 = r.read_u16_be()?;
    let mut interfaces: Vec<u16> =
        Vec::with_capacity(bounded_capacity(interfaces_count, r.remaining()));
    for _ in 0..interfaces_count {
        interfaces.push(r.read_u16_be()?);
    }
    let fields_count: u16 = r.read_u16_be()?;
    let mut fields: Vec<FieldInfo> =
        Vec::with_capacity(bounded_capacity(fields_count, r.remaining()));
    for _ in 0..fields_count {
        fields.push(parse_field(&mut r)?);
    }
    let methods_count: u16 = r.read_u16_be()?;
    let mut methods: Vec<MethodInfo> =
        Vec::with_capacity(bounded_capacity(methods_count, r.remaining()));
    for _ in 0..methods_count {
        methods.push(parse_method(&mut r)?);
    }
    let attrs_count: u16 = r.read_u16_be()?;
    let mut attributes: Vec<Attribute> =
        Vec::with_capacity(bounded_capacity(attrs_count, r.remaining()));
    for _ in 0..attrs_count {
        attributes.push(parse_attribute(&mut r)?);
    }
    Ok(ClassFile {
        minor_version,
        major_version,
        constant_pool: cp,
        access_flags,
        this_class,
        super_class,
        interfaces,
        fields,
        methods,
        attributes,
    })
}

fn parse_field(r: &mut ByteReader<'_>) -> Result<FieldInfo> {
    let access_flags: u16 = r.read_u16_be()?;
    let name_index: u16 = r.read_u16_be()?;
    let descriptor_index: u16 = r.read_u16_be()?;
    let attrs_count: u16 = r.read_u16_be()?;
    let mut attributes: Vec<Attribute> =
        Vec::with_capacity(bounded_capacity(attrs_count, r.remaining()));
    for _ in 0..attrs_count {
        attributes.push(parse_attribute(r)?);
    }
    Ok(FieldInfo {
        access_flags,
        name_index,
        descriptor_index,
        attributes,
    })
}

fn parse_method(r: &mut ByteReader<'_>) -> Result<MethodInfo> {
    let access_flags: u16 = r.read_u16_be()?;
    let name_index: u16 = r.read_u16_be()?;
    let descriptor_index: u16 = r.read_u16_be()?;
    let attrs_count: u16 = r.read_u16_be()?;
    let mut attributes: Vec<Attribute> =
        Vec::with_capacity(bounded_capacity(attrs_count, r.remaining()));
    for _ in 0..attrs_count {
        attributes.push(parse_attribute(r)?);
    }
    Ok(MethodInfo {
        access_flags,
        name_index,
        descriptor_index,
        attributes,
    })
}

fn parse_attribute(r: &mut ByteReader<'_>) -> Result<Attribute> {
    let name_index: u16 = r.read_u16_be()?;
    let length: u32 = r.read_u32_be()?;
    let length_usize: usize = usize::try_from(length).map_err(|_| Error::Truncated {
        offset: r.position(),
        needed: usize::MAX,
        had: r.remaining(),
    })?;
    let info: Vec<u8> = r.read_bytes(length_usize)?.to_vec();
    Ok(Attribute { name_index, info })
}

const SURROGATE_TOLERANCE_MARKER: char = '\u{FFFD}';

fn decode_surrogate_pair(raw: &[u8], i: usize, high: u32) -> Option<char> {
    if i + 5 >= raw.len() {
        return None;
    }
    let c4: u8 = raw[i + 3];
    let c5: u8 = raw[i + 4];
    let c6: u8 = raw[i + 5];
    if c4 != 0xED || (c5 & 0xC0) != 0x80 || (c6 & 0xC0) != 0x80 {
        return None;
    }
    let low: u32 =
        (u32::from(c4 & 0x0F) << 12) | (u32::from(c5 & 0x3F) << 6) | u32::from(c6 & 0x3F);
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    let combined: u32 = 0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00);
    char::from_u32(combined)
}

fn decode_modified_utf8(raw: &[u8]) -> Result<String> {
    let mut out: String = String::with_capacity(raw.len());
    let mut i: usize = 0;
    while i < raw.len() {
        let b1: u8 = raw[i];
        if b1 == 0 {
            return Err(Error::BadModifiedUtf8);
        }
        if b1 < 0x80 {
            out.push(b1 as char);
            i += 1;
        } else if (b1 & 0xE0) == 0xC0 {
            if i + 1 >= raw.len() {
                return Err(Error::BadModifiedUtf8);
            }
            let b2: u8 = raw[i + 1];
            if (b2 & 0xC0) != 0x80 {
                return Err(Error::BadModifiedUtf8);
            }
            let cp: u32 = (u32::from(b1 & 0x1F) << 6) | u32::from(b2 & 0x3F);
            let Some(ch): Option<char> = char::from_u32(cp) else {
                return Err(Error::BadModifiedUtf8);
            };
            out.push(ch);
            i += 2;
        } else if (b1 & 0xF0) == 0xE0 {
            if i + 2 >= raw.len() {
                return Err(Error::BadModifiedUtf8);
            }
            let b2: u8 = raw[i + 1];
            let b3: u8 = raw[i + 2];
            if (b2 & 0xC0) != 0x80 || (b3 & 0xC0) != 0x80 {
                return Err(Error::BadModifiedUtf8);
            }
            let cp: u32 =
                (u32::from(b1 & 0x0F) << 12) | (u32::from(b2 & 0x3F) << 6) | u32::from(b3 & 0x3F);
            if (0xD800..=0xDBFF).contains(&cp) {
                if let Some(pair) = decode_surrogate_pair(raw, i, cp) {
                    out.push(pair);
                    i += 6;
                } else {
                    out.push(SURROGATE_TOLERANCE_MARKER);
                    i += 3;
                }
            } else if (0xDC00..=0xDFFF).contains(&cp) {
                out.push(SURROGATE_TOLERANCE_MARKER);
                i += 3;
            } else {
                let Some(ch): Option<char> = char::from_u32(cp) else {
                    return Err(Error::BadModifiedUtf8);
                };
                out.push(ch);
                i += 3;
            }
        } else {
            return Err(Error::BadModifiedUtf8);
        }
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_magic() {
        let bytes: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x34];
        let err: Error = parse(&bytes).expect_err("magic should fail");
        assert!(matches!(err, Error::BadMagic(_)));
    }

    #[test]
    fn reader_uses_big_endian_byte_reader_and_preserves_eof_error() {
        let mut reader: ByteReader<'_> = ByteReader::new(&[0x12, 0x34, 0x56]);
        assert_eq!(reader.read_u16_be().expect("u16 read"), 0x1234);

        let error: Error = reader
            .read_u16_be()
            .map_err(Error::from)
            .expect_err("truncated u16 read");
        assert!(matches!(
            error,
            Error::Truncated {
                offset: 2,
                needed: 2,
                had: 1,
            }
        ));
    }

    #[test]
    fn java_version_round_trip() {
        for major in MIN_MAJOR..=MAX_MAJOR {
            assert!(JavaVersion::from_major(major).is_some());
        }
        assert_eq!(JavaVersion::from_major(44), None);
        assert_eq!(JavaVersion::from_major(70), None);
    }

    #[test]
    fn modified_utf8_decodes_ascii() {
        let s: String = decode_modified_utf8(b"hello").expect("ascii");
        assert_eq!(s, "hello");
    }

    #[test]
    fn modified_utf8_rejects_null() {
        let err: Error =
            decode_modified_utf8(&[0u8]).expect_err("null byte not allowed in modified utf-8");
        assert!(matches!(err, Error::BadModifiedUtf8));
    }

    #[test]
    fn modified_utf8_decodes_supplementary_pair() {
        let bytes: [u8; 6] = [0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80];
        let s: String = decode_modified_utf8(&bytes).expect("supplementary");
        assert_eq!(s, "\u{1F600}");
    }

    #[test]
    fn modified_utf8_decodes_two_byte_supplementary_null() {
        let bytes: [u8; 2] = [0xC0, 0x80];
        let s: String = decode_modified_utf8(&bytes).expect("embedded null");
        assert_eq!(s, "\u{0}");
    }

    #[test]
    fn modified_utf8_tolerates_lone_high_surrogate() {
        let bytes: [u8; 3] = [0xED, 0xA0, 0xBD];
        let s: String = decode_modified_utf8(&bytes)
            .expect("a lone high surrogate is decoded to the replacement marker, not rejected");
        assert_eq!(s, "\u{FFFD}");
    }

    #[test]
    fn modified_utf8_tolerates_lone_low_surrogate() {
        let bytes: [u8; 3] = [0xED, 0xB9, 0xB7];
        let s: String = decode_modified_utf8(&bytes)
            .expect("a lone low surrogate is decoded to the replacement marker, not rejected");
        assert_eq!(s, "\u{FFFD}");
    }

    #[test]
    fn modified_utf8_tolerant_class_bodies_still_decode_around_surrogates() {
        let bytes: [u8; 8] = [b'a', 0xED, 0xA2, 0x85, 0xEB, 0xAA, 0xB4, b'z'];
        let s: String = decode_modified_utf8(&bytes)
            .expect("an unpaired surrogate mid-string does not abort the whole constant");
        assert_eq!(s, "a\u{FFFD}\u{BAB4}z");
    }

    fn minimal_class() -> Vec<u8> {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&52u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v
    }

    #[test]
    fn well_formed_minimal_class_still_parses_identically() {
        let bytes: Vec<u8> = minimal_class();
        let a: ClassFile = parse(&bytes).expect("minimal class parses");
        let b: ClassFile = parse(&bytes).expect("re-parse");
        assert_eq!(a, b);
        assert_eq!(a.major_version, 52);
        assert_eq!(a.constant_pool.len(), 1);
        assert!(a.fields.is_empty() && a.methods.is_empty() && a.attributes.is_empty());
    }

    #[test]
    fn bounded_capacity_caps_to_remaining_input() {
        assert_eq!(bounded_capacity(65535, 40), 40);
        assert_eq!(bounded_capacity(65535, 0), 0);
        assert_eq!(bounded_capacity(10, 40), 10);
        assert_eq!(bounded_capacity(0, 40), 0);
        assert_eq!(bounded_capacity(40, 40), 40);
    }

    #[test]
    fn declared_count_does_not_drive_preallocation() {
        let entry_size: usize = std::mem::size_of::<ConstantPoolEntry>();
        let untethered_bytes: usize = 65535 * entry_size;
        let capped_bytes: usize = bounded_capacity(65535, 40) * entry_size;
        assert!(capped_bytes * 100 < untethered_bytes);
        assert_eq!(capped_bytes, 40 * entry_size);
    }

    fn malformed_battery() -> Vec<Vec<u8>> {
        let mut cases: Vec<Vec<u8>> = vec![
            Vec::new(),
            vec![0xCA, 0xFE, 0xBA],
            vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00],
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x34],
        ];
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&52u16.to_be_bytes());
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&52u16.to_be_bytes());
            v.extend_from_slice(&2u16.to_be_bytes());
            v.push(1);
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&52u16.to_be_bytes());
            v.extend_from_slice(&2u16.to_be_bytes());
            v.push(200);
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = minimal_class();
            let len: usize = v.len();
            v.truncate(len - 8);
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = minimal_class();
            let len: usize = v.len();
            v.truncate(len - 6);
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = minimal_class();
            let len: usize = v.len();
            v.truncate(len - 4);
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = minimal_class();
            let len: usize = v.len();
            v.truncate(len - 2);
            v.extend_from_slice(&0xFFFFu16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&52u16.to_be_bytes());
            v.extend_from_slice(&2u16.to_be_bytes());
            v.push(5);
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&99u16.to_be_bytes());
            cases.push(v);
        }
        {
            let mut v: Vec<u8> = Vec::new();
            v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&52u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&0u16.to_be_bytes());
            v.extend_from_slice(&0xFFFF_FFFFu32.to_be_bytes());
            cases.push(v);
        }
        cases
    }

    #[test]
    fn malformed_inputs_error_without_panic() {
        for (n, case) in malformed_battery().into_iter().enumerate() {
            let outcome: std::thread::Result<Result<ClassFile>> =
                std::panic::catch_unwind(move || parse(&case));
            assert!(outcome.is_ok(), "case {n} panicked in the parser");
            let parsed: Result<ClassFile> = outcome.unwrap();
            assert!(parsed.is_err(), "case {n} should error");
        }
    }

    #[test]
    fn random_bytes_smoke_never_panics() {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        for iteration in 0..4096u32 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let len: usize = (state as usize) % 512;
            let mut buf: Vec<u8> = Vec::with_capacity(len);
            let mut s: u64 = state ^ u64::from(iteration);
            for _ in 0..len {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                buf.push((s & 0xFF) as u8);
            }
            let outcome: std::thread::Result<Result<ClassFile>> =
                std::panic::catch_unwind(move || parse(&buf));
            assert!(
                outcome.is_ok(),
                "random input at iteration {iteration} panicked"
            );
        }
    }

    #[test]
    fn declared_count_far_beyond_input_errors_fast() {
        let mut v: Vec<u8> = Vec::new();
        v.extend_from_slice(&CLASS_MAGIC.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&52u16.to_be_bytes());
        v.extend_from_slice(&0xFFFFu16.to_be_bytes());
        let err: Error = parse(&v).expect_err("huge constant pool over a tiny buffer must error");
        assert!(matches!(err, Error::Truncated { .. }));
    }
}
