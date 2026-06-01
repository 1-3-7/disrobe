use std::collections::BTreeMap;
use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const MAX_PREALLOC: u64 = 64 * 1024 * 1024;

#[inline]
fn entry_prealloc(uncompressed: u64, compressed: u64) -> usize {
    let bound: u64 = uncompressed
        .min(compressed.saturating_mul(2))
        .min(MAX_PREALLOC);
    usize::try_from(bound).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JarEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JarExtract {
    pub entries: Vec<JarEntry>,
    pub classes: BTreeMap<String, Vec<u8>>,
    pub manifest: Option<String>,
}

pub fn extract(bytes: &[u8]) -> Result<JarExtract> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
    let mut entries: Vec<JarEntry> = Vec::with_capacity(zip.len());
    let mut classes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifest: Option<String> = None;
    for i in 0..zip.len() {
        let mut file: zip::read::ZipFile<'_> =
            zip.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        let path: String = file.name().to_string();
        let mut buf: Vec<u8> =
            Vec::with_capacity(entry_prealloc(file.size(), file.compressed_size()));
        file.read_to_end(&mut buf)?;
        if path.ends_with(".class") {
            classes.insert(path.clone(), buf.clone());
        }
        if path == "META-INF/MANIFEST.MF" {
            manifest = Some(String::from_utf8_lossy(&buf).into_owned());
        }
        entries.push(JarEntry { path, bytes: buf });
    }
    Ok(JarExtract {
        entries,
        classes,
        manifest,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmodExtract {
    pub classes: BTreeMap<String, Vec<u8>>,
    pub native_libs: BTreeMap<String, Vec<u8>>,
    pub resources: BTreeMap<String, Vec<u8>>,
}

pub fn extract_jmod(bytes: &[u8]) -> Result<JmodExtract> {
    if bytes.len() < 4 {
        return Err(Error::BadJmodMagic([0u8; 4]));
    }
    let header: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if header[0] != b'J' || header[1] != b'M' {
        return Err(Error::BadJmodMagic(header));
    }
    let zip_bytes: &[u8] = &bytes[4..];
    let cursor: Cursor<&[u8]> = Cursor::new(zip_bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
    let mut classes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut native_libs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut resources: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for i in 0..zip.len() {
        let mut file: zip::read::ZipFile<'_> =
            zip.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        let path: String = file.name().to_string();
        let mut buf: Vec<u8> =
            Vec::with_capacity(entry_prealloc(file.size(), file.compressed_size()));
        file.read_to_end(&mut buf)?;
        if path.starts_with("classes/") {
            classes.insert(path, buf);
        } else if path.starts_with("native/")
            || path.starts_with("lib/")
            || path.starts_with("bin/")
        {
            native_libs.insert(path, buf);
        } else {
            resources.insert(path, buf);
        }
    }
    Ok(JmodExtract {
        classes,
        native_libs,
        resources,
    })
}

pub const JIMAGE_MAGIC: u32 = 0xCAFE_DADA;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JimageHeader {
    pub magic: u32,
    pub version_major: u16,
    pub version_minor: u16,
    pub flags: u32,
    pub resource_count: u32,
    pub table_length: u32,
    pub locations_size: u32,
    pub strings_size: u32,
}

pub fn parse_jimage_header(bytes: &[u8]) -> Result<JimageHeader> {
    if bytes.len() < 28 {
        return Err(Error::Truncated {
            offset: 0,
            needed: 28,
            had: bytes.len(),
        });
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let big_endian: bool = if magic == JIMAGE_MAGIC {
        false
    } else {
        let be: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        if be == JIMAGE_MAGIC {
            true
        } else {
            return Err(Error::BadJimageMagic(magic));
        }
    };
    let read16 = |o: usize| -> u16 {
        if big_endian {
            u16::from_be_bytes([bytes[o], bytes[o + 1]])
        } else {
            u16::from_le_bytes([bytes[o], bytes[o + 1]])
        }
    };
    let read32 = |o: usize| -> u32 {
        if big_endian {
            u32::from_be_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        } else {
            u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]])
        }
    };
    Ok(JimageHeader {
        magic: JIMAGE_MAGIC,
        version_major: read16(4),
        version_minor: read16(6),
        flags: read32(8),
        resource_count: read32(12),
        table_length: read32(16),
        locations_size: read32(20),
        strings_size: read32(24),
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApkExtract {
    pub jar: JarExtract,
    pub dex_files: BTreeMap<String, Vec<u8>>,
    pub manifest_bytes: Option<Vec<u8>>,
    pub resources_arsc: Option<Vec<u8>>,
    pub signatures: BTreeMap<String, Vec<u8>>,
}

pub fn extract_apk(bytes: &[u8]) -> Result<ApkExtract> {
    let jar: JarExtract = extract(bytes)?;
    let mut dex_files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut resources_arsc: Option<Vec<u8>> = None;
    let mut signatures: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &jar.entries {
        let p: &str = entry.path.as_str();
        if p.ends_with(".dex") {
            dex_files.insert(entry.path.clone(), entry.bytes.clone());
        } else if p == "AndroidManifest.xml" {
            manifest_bytes = Some(entry.bytes.clone());
        } else if p == "resources.arsc" {
            resources_arsc = Some(entry.bytes.clone());
        } else if p.starts_with("META-INF/")
            && (p.ends_with(".RSA")
                || p.ends_with(".DSA")
                || p.ends_with(".EC")
                || p.ends_with(".SF"))
        {
            signatures.insert(entry.path.clone(), entry.bytes.clone());
        }
    }
    Ok(ApkExtract {
        jar,
        dex_files,
        manifest_bytes,
        resources_arsc,
        signatures,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn jmod_magic_rejected_on_short() {
        let err: Error = extract_jmod(&[0u8, 1u8]).expect_err("too short");
        assert!(matches!(err, Error::BadJmodMagic(_)));
    }

    #[test]
    fn jimage_header_rejects_bad_magic() {
        let bytes: [u8; 32] = [0u8; 32];
        let err: Error = parse_jimage_header(&bytes).expect_err("bad magic");
        assert!(matches!(err, Error::BadJimageMagic(_)));
    }

    #[test]
    fn jimage_header_parses_little_endian() {
        let mut bytes: Vec<u8> = Vec::with_capacity(32);
        bytes.extend_from_slice(&JIMAGE_MAGIC.to_le_bytes());
        bytes.extend_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&[0u8; 20]);
        let hdr: JimageHeader = parse_jimage_header(&bytes).expect("le magic");
        assert_eq!(hdr.version_major, 1);
    }
}
