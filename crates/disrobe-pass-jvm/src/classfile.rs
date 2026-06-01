use std::collections::BTreeMap;

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

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[inline]
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    #[inline]
    const fn need(&self, n: usize) -> Result<()> {
        if self.pos.saturating_add(n) > self.bytes.len() {
            return Err(Error::Truncated {
                offset: self.pos,
                needed: n,
                had: self.bytes.len().saturating_sub(self.pos),
            });
        }
        Ok(())
    }

    #[inline]
    fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v: u8 = self.bytes[self.pos];
        self.pos += 1;
        Ok(v)
    }

    #[inline]
    fn u16(&mut self) -> Result<u16> {
        self.need(2)?;
        let v: u16 = u16::from_be_bytes([self.bytes[self.pos], self.bytes[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    #[inline]
    fn u32(&mut self) -> Result<u32> {
        self.need(4)?;
        let v: u32 = u32::from_be_bytes([
            self.bytes[self.pos],
            self.bytes[self.pos + 1],
            self.bytes[self.pos + 2],
            self.bytes[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    #[inline]
    fn u64(&mut self) -> Result<u64> {
        let hi: u32 = self.u32()?;
        let lo: u32 = self.u32()?;
        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    #[inline]
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let out: &'a [u8] = &self.bytes[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }
}

pub fn parse(bytes: &[u8]) -> Result<ClassFile> {
    let mut r: Reader<'_> = Reader::new(bytes);
    let magic: u32 = r.u32()?;
    if magic != CLASS_MAGIC {
        return Err(Error::BadMagic(magic));
    }
    let minor_version: u16 = r.u16()?;
    let major_version: u16 = r.u16()?;
    if !(MIN_MAJOR..=MAX_MAJOR).contains(&major_version) {
        return Err(Error::UnsupportedClassVersion {
            major: major_version,
        });
    }
    let cp_count: u16 = r.u16()?;
    let mut cp: Vec<ConstantPoolEntry> = Vec::with_capacity(usize::from(cp_count));
    cp.push(ConstantPoolEntry::Placeholder);
    let mut i: usize = 1;
    while i < usize::from(cp_count) {
        let tag: u8 = r.u8()?;
        let entry: ConstantPoolEntry = match tag {
            1 => {
                let len: u16 = r.u16()?;
                let raw: &[u8] = r.take(usize::from(len))?;
                ConstantPoolEntry::Utf8(decode_modified_utf8(raw)?)
            }
            3 => ConstantPoolEntry::Integer(r.u32()? as i32),
            4 => ConstantPoolEntry::Float(r.u32()?),
            5 => ConstantPoolEntry::Long(r.u64()? as i64),
            6 => ConstantPoolEntry::Double(r.u64()?),
            7 => ConstantPoolEntry::Class {
                name_index: r.u16()?,
            },
            8 => ConstantPoolEntry::String {
                utf8_index: r.u16()?,
            },
            9 => ConstantPoolEntry::Fieldref {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            10 => ConstantPoolEntry::Methodref {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            11 => ConstantPoolEntry::InterfaceMethodref {
                class_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            12 => ConstantPoolEntry::NameAndType {
                name_index: r.u16()?,
                descriptor_index: r.u16()?,
            },
            15 => ConstantPoolEntry::MethodHandle {
                reference_kind: r.u8()?,
                reference_index: r.u16()?,
            },
            16 => ConstantPoolEntry::MethodType {
                descriptor_index: r.u16()?,
            },
            17 => ConstantPoolEntry::Dynamic {
                bootstrap_method_attr_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            18 => ConstantPoolEntry::InvokeDynamic {
                bootstrap_method_attr_index: r.u16()?,
                name_and_type_index: r.u16()?,
            },
            19 => ConstantPoolEntry::Module {
                name_index: r.u16()?,
            },
            20 => ConstantPoolEntry::Package {
                name_index: r.u16()?,
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
    let access_flags: u16 = r.u16()?;
    let this_class: u16 = r.u16()?;
    let super_class: u16 = r.u16()?;
    let interfaces_count: u16 = r.u16()?;
    let mut interfaces: Vec<u16> = Vec::with_capacity(usize::from(interfaces_count));
    for _ in 0..interfaces_count {
        interfaces.push(r.u16()?);
    }
    let fields_count: u16 = r.u16()?;
    let mut fields: Vec<FieldInfo> = Vec::with_capacity(usize::from(fields_count));
    for _ in 0..fields_count {
        fields.push(parse_field(&mut r)?);
    }
    let methods_count: u16 = r.u16()?;
    let mut methods: Vec<MethodInfo> = Vec::with_capacity(usize::from(methods_count));
    for _ in 0..methods_count {
        methods.push(parse_method(&mut r)?);
    }
    let attrs_count: u16 = r.u16()?;
    let mut attributes: Vec<Attribute> = Vec::with_capacity(usize::from(attrs_count));
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

fn parse_field(r: &mut Reader<'_>) -> Result<FieldInfo> {
    let access_flags: u16 = r.u16()?;
    let name_index: u16 = r.u16()?;
    let descriptor_index: u16 = r.u16()?;
    let attrs_count: u16 = r.u16()?;
    let mut attributes: Vec<Attribute> = Vec::with_capacity(usize::from(attrs_count));
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

fn parse_method(r: &mut Reader<'_>) -> Result<MethodInfo> {
    let access_flags: u16 = r.u16()?;
    let name_index: u16 = r.u16()?;
    let descriptor_index: u16 = r.u16()?;
    let attrs_count: u16 = r.u16()?;
    let mut attributes: Vec<Attribute> = Vec::with_capacity(usize::from(attrs_count));
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

fn parse_attribute(r: &mut Reader<'_>) -> Result<Attribute> {
    let name_index: u16 = r.u16()?;
    let length: u32 = r.u32()?;
    let info: Vec<u8> = r.take(length as usize)?.to_vec();
    Ok(Attribute { name_index, info })
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
                if i + 5 >= raw.len() {
                    return Err(Error::BadModifiedUtf8);
                }
                let c4: u8 = raw[i + 3];
                let c5: u8 = raw[i + 4];
                let c6: u8 = raw[i + 5];
                if c4 != 0xED || (c5 & 0xC0) != 0x80 || (c6 & 0xC0) != 0x80 {
                    return Err(Error::BadModifiedUtf8);
                }
                let low: u32 = (u32::from(c4 & 0x0F) << 12)
                    | (u32::from(c5 & 0x3F) << 6)
                    | u32::from(c6 & 0x3F);
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(Error::BadModifiedUtf8);
                }
                let combined: u32 = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                let Some(ch): Option<char> = char::from_u32(combined) else {
                    return Err(Error::BadModifiedUtf8);
                };
                out.push(ch);
                i += 6;
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
    fn modified_utf8_truncated_surrogate_errors() {
        let bytes: [u8; 3] = [0xED, 0xA0, 0xBD];
        let err: Error = decode_modified_utf8(&bytes).expect_err("lone high surrogate");
        assert!(matches!(err, Error::BadModifiedUtf8));
    }
}
