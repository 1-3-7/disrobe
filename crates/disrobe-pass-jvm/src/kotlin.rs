use serde::{Deserialize, Serialize};

use crate::classfile::{Attribute, ClassFile, ConstantPoolEntry};
use crate::error::{Error, Result};

const METADATA_ANNOTATION: &str = "Lkotlin/Metadata;";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum KotlinKind {
    Class,
    File,
    SyntheticClass,
    MultifileClassFacade,
    MultifileClassPart,
    Unknown,
}

impl KotlinKind {
    #[inline]
    #[must_use]
    pub const fn from_kind(k: i32) -> Self {
        match k {
            1 => Self::Class,
            2 => Self::File,
            3 => Self::SyntheticClass,
            4 => Self::MultifileClassFacade,
            5 => Self::MultifileClassPart,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KotlinMetadata {
    pub kind: KotlinKind,
    pub metadata_version: Vec<i32>,
    pub bytecode_version: Vec<i32>,
    pub package_name: Option<String>,
}

pub fn recover_metadata(cf: &ClassFile) -> Result<Option<KotlinMetadata>> {
    let runtime_visible_attr: Option<&Attribute> = cf.attributes.iter().find(|a| {
        cf.utf8_at(a.name_index)
            .map(|n| n == "RuntimeVisibleAnnotations")
            .unwrap_or(false)
    });
    let Some(attr): Option<&Attribute> = runtime_visible_attr else {
        return Ok(None);
    };
    if attr.info.len() < 2 {
        return Ok(None);
    }
    let num_annotations: u16 = u16::from_be_bytes([attr.info[0], attr.info[1]]);
    let mut cursor: usize = 2;
    for _ in 0..num_annotations {
        if cursor + 4 > attr.info.len() {
            return Ok(None);
        }
        let type_idx: u16 = u16::from_be_bytes([attr.info[cursor], attr.info[cursor + 1]]);
        let num_pairs: u16 = u16::from_be_bytes([attr.info[cursor + 2], attr.info[cursor + 3]]);
        cursor += 4;
        let type_name: &str = cf.utf8_at(type_idx)?;
        if type_name == METADATA_ANNOTATION {
            let meta: KotlinMetadata = parse_metadata_pairs(cf, &attr.info, cursor, num_pairs)?;
            return Ok(Some(meta));
        }
        cursor = skip_pairs(&attr.info, cursor, num_pairs)?;
    }
    Ok(None)
}

fn skip_pairs(buf: &[u8], start: usize, n: u16) -> Result<usize> {
    let mut cursor: usize = start;
    for _ in 0..n {
        if cursor + 2 > buf.len() {
            return Err(Error::BadKotlinMetadata("truncated element name index"));
        }
        cursor += 2;
        cursor = skip_element_value(buf, cursor)?;
    }
    Ok(cursor)
}

fn skip_element_value(buf: &[u8], start: usize) -> Result<usize> {
    if start >= buf.len() {
        return Err(Error::BadKotlinMetadata("truncated element value tag"));
    }
    let tag: u8 = buf[start];
    let mut cursor: usize = start + 1;
    match tag {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b's' | b'c' => {
            cursor += 2;
        }
        b'e' => {
            cursor += 4;
        }
        b'@' => {
            if cursor + 4 > buf.len() {
                return Err(Error::BadKotlinMetadata("truncated nested annotation"));
            }
            let np: u16 = u16::from_be_bytes([buf[cursor + 2], buf[cursor + 3]]);
            cursor += 4;
            cursor = skip_pairs(buf, cursor, np)?;
        }
        b'[' => {
            if cursor + 2 > buf.len() {
                return Err(Error::BadKotlinMetadata("truncated array length"));
            }
            let n: u16 = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
            cursor += 2;
            for _ in 0..n {
                cursor = skip_element_value(buf, cursor)?;
            }
        }
        _ => {
            return Err(Error::BadKotlinMetadata("unknown element value tag"));
        }
    }
    Ok(cursor)
}

fn parse_metadata_pairs(
    cf: &ClassFile,
    buf: &[u8],
    start: usize,
    num_pairs: u16,
) -> Result<KotlinMetadata> {
    let mut kind: KotlinKind = KotlinKind::Class;
    let mut metadata_version: Vec<i32> = Vec::new();
    let mut bytecode_version: Vec<i32> = Vec::new();
    let mut package_name: Option<String> = None;
    let mut cursor: usize = start;
    for _ in 0..num_pairs {
        if cursor + 2 > buf.len() {
            return Err(Error::BadKotlinMetadata("pair name truncated"));
        }
        let name_idx: u16 = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
        cursor += 2;
        let name: &str = cf.utf8_at(name_idx)?;
        let value_start: usize = cursor;
        cursor = skip_element_value(buf, cursor)?;
        match name {
            "k" => {
                let k_val: i32 = read_int_element(cf, &buf[value_start..])?;
                kind = KotlinKind::from_kind(k_val);
            }
            "mv" => {
                metadata_version = read_int_array_element(cf, &buf[value_start..])?;
            }
            "bv" => {
                bytecode_version = read_int_array_element(cf, &buf[value_start..])?;
            }
            "pn" => {
                package_name = Some(read_string_element(cf, &buf[value_start..])?);
            }
            _ => {}
        }
    }
    Ok(KotlinMetadata {
        kind,
        metadata_version,
        bytecode_version,
        package_name,
    })
}

fn read_int_element(cf: &ClassFile, buf: &[u8]) -> Result<i32> {
    if buf.len() < 3 || buf[0] != b'I' {
        return Err(Error::BadKotlinMetadata("expected int element"));
    }
    let idx: u16 = u16::from_be_bytes([buf[1], buf[2]]);
    match cf.constant_pool.get(usize::from(idx)) {
        Some(ConstantPoolEntry::Integer(v)) => Ok(*v),
        _ => Err(Error::BadKotlinMetadata("CP entry not Integer")),
    }
}

fn read_string_element(cf: &ClassFile, buf: &[u8]) -> Result<String> {
    if buf.len() < 3 || buf[0] != b's' {
        return Err(Error::BadKotlinMetadata("expected string element"));
    }
    let idx: u16 = u16::from_be_bytes([buf[1], buf[2]]);
    cf.utf8_at(idx).map(str::to_string)
}

fn read_int_array_element(cf: &ClassFile, buf: &[u8]) -> Result<Vec<i32>> {
    if buf.len() < 3 || buf[0] != b'[' {
        return Err(Error::BadKotlinMetadata("expected array element"));
    }
    let n: u16 = u16::from_be_bytes([buf[1], buf[2]]);
    let mut cursor: usize = 3;
    let mut out: Vec<i32> = Vec::with_capacity(usize::from(n));
    for _ in 0..n {
        if cursor + 3 > buf.len() || buf[cursor] != b'I' {
            return Err(Error::BadKotlinMetadata("array element not Integer"));
        }
        let idx: u16 = u16::from_be_bytes([buf[cursor + 1], buf[cursor + 2]]);
        match cf.constant_pool.get(usize::from(idx)) {
            Some(ConstantPoolEntry::Integer(v)) => out.push(*v),
            _ => return Err(Error::BadKotlinMetadata("CP entry not Integer")),
        }
        cursor += 3;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn kotlin_kind_round_trip() {
        for k in [1, 2, 3, 4, 5] {
            assert!(!matches!(KotlinKind::from_kind(k), KotlinKind::Unknown));
        }
        assert!(matches!(KotlinKind::from_kind(99), KotlinKind::Unknown));
    }

    #[test]
    fn recover_returns_none_when_no_annotations() {
        let cf: ClassFile = ClassFile {
            minor_version: 0,
            major_version: 52,
            constant_pool: vec![ConstantPoolEntry::Placeholder],
            access_flags: 0,
            this_class: 0,
            super_class: 0,
            interfaces: Vec::new(),
            fields: Vec::new(),
            methods: Vec::new(),
            attributes: Vec::new(),
        };
        let out: Option<KotlinMetadata> = recover_metadata(&cf).expect("ok");
        assert!(out.is_none());
    }
}
