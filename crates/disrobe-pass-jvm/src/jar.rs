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

pub const JMOD_MAGIC: [u8; 4] = [0x4A, 0x4D, 0x01, 0x00];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JmodExtract {
    pub classes: BTreeMap<String, Vec<u8>>,
    pub native_libs: BTreeMap<String, Vec<u8>>,
    pub config: BTreeMap<String, Vec<u8>>,
    pub bin: BTreeMap<String, Vec<u8>>,
    pub legal: BTreeMap<String, Vec<u8>>,
    pub headers: BTreeMap<String, Vec<u8>>,
    pub man: BTreeMap<String, Vec<u8>>,
    pub resources: BTreeMap<String, Vec<u8>>,
}

pub fn extract_jmod(bytes: &[u8]) -> Result<JmodExtract> {
    if bytes.len() < 4 {
        return Err(Error::BadJmodMagic([0u8; 4]));
    }
    let header: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    if header != JMOD_MAGIC {
        return Err(Error::BadJmodMagic(header));
    }
    let zip_bytes: &[u8] = &bytes[4..];
    let cursor: Cursor<&[u8]> = Cursor::new(zip_bytes);
    let mut zip: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
    let mut classes: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut native_libs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut config: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut bin: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut legal: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut headers: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut man: BTreeMap<String, Vec<u8>> = BTreeMap::new();
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
        } else if path.starts_with("lib/") || path.starts_with("native/") {
            native_libs.insert(path, buf);
        } else if path.starts_with("conf/") {
            config.insert(path, buf);
        } else if path.starts_with("bin/") {
            bin.insert(path, buf);
        } else if path.starts_with("legal/") {
            legal.insert(path, buf);
        } else if path.starts_with("include/") {
            headers.insert(path, buf);
        } else if path.starts_with("man/") {
            man.insert(path, buf);
        } else {
            resources.insert(path, buf);
        }
    }
    Ok(JmodExtract {
        classes,
        native_libs,
        config,
        bin,
        legal,
        headers,
        man,
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
pub struct JimageResource {
    pub module: String,
    pub parent: String,
    pub base: String,
    pub extension: String,
    pub full_name: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jimage {
    pub header: JimageHeader,
    pub endian_big: bool,
    pub resources: Vec<JimageResource>,
}

const JIMAGE_HEADER_SIZE: usize = 28;

const ATTRIBUTE_END: u8 = 0;
const ATTRIBUTE_MODULE: u8 = 1;
const ATTRIBUTE_PARENT: u8 = 2;
const ATTRIBUTE_BASE: u8 = 3;
const ATTRIBUTE_EXTENSION: u8 = 4;
const ATTRIBUTE_OFFSET: u8 = 5;
const ATTRIBUTE_COMPRESSED: u8 = 6;
const ATTRIBUTE_UNCOMPRESSED: u8 = 7;

#[inline]
fn read_be_uint(slice: &[u8], len: usize) -> u64 {
    let mut v: u64 = 0;
    for &b in &slice[..len] {
        v = (v << 8) | u64::from(b);
    }
    v
}

fn read_string(strings: &[u8], off: usize) -> Result<String> {
    if off >= strings.len() {
        return Err(Error::JimageOutOfRange {
            offset: off,
            size: strings.len(),
        });
    }
    let tail: &[u8] = &strings[off..];
    let end: usize = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

pub fn parse_jimage(bytes: &[u8]) -> Result<Jimage> {
    let header: JimageHeader = parse_jimage_header(bytes)?;
    let first4: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let endian_big: bool = u32::from_le_bytes(first4) != JIMAGE_MAGIC;

    let size: usize = bytes.len();
    let table_len: usize = header.table_length as usize;

    let redirect_end: usize = JIMAGE_HEADER_SIZE
        .checked_add(table_len.checked_mul(4).ok_or(Error::JimageOutOfRange {
            offset: usize::MAX,
            size,
        })?)
        .ok_or(Error::JimageOutOfRange {
            offset: usize::MAX,
            size,
        })?;
    if redirect_end > size {
        return Err(Error::JimageOutOfRange {
            offset: redirect_end,
            size,
        });
    }

    let offsets_end: usize = redirect_end
        .checked_add(table_len.checked_mul(4).ok_or(Error::JimageOutOfRange {
            offset: usize::MAX,
            size,
        })?)
        .ok_or(Error::JimageOutOfRange {
            offset: usize::MAX,
            size,
        })?;
    if offsets_end > size {
        return Err(Error::JimageOutOfRange {
            offset: offsets_end,
            size,
        });
    }

    let locations_size: usize = header.locations_size as usize;
    let locations_end: usize =
        offsets_end
            .checked_add(locations_size)
            .ok_or(Error::JimageOutOfRange {
                offset: usize::MAX,
                size,
            })?;
    if locations_end > size {
        return Err(Error::JimageOutOfRange {
            offset: locations_end,
            size,
        });
    }

    let strings_size: usize = header.strings_size as usize;
    let strings_end: usize =
        locations_end
            .checked_add(strings_size)
            .ok_or(Error::JimageOutOfRange {
                offset: usize::MAX,
                size,
            })?;
    if strings_end > size {
        return Err(Error::JimageOutOfRange {
            offset: strings_end,
            size,
        });
    }

    let offsets_region: &[u8] = &bytes[redirect_end..offsets_end];
    let locations_region: &[u8] = &bytes[offsets_end..locations_end];
    let strings_region: &[u8] = &bytes[locations_end..strings_end];

    let mut resources: Vec<JimageResource> = Vec::new();
    for i in 0..table_len {
        let base: usize = i * 4;
        let loc_off: usize = if endian_big {
            u32::from_be_bytes([
                offsets_region[base],
                offsets_region[base + 1],
                offsets_region[base + 2],
                offsets_region[base + 3],
            ]) as usize
        } else {
            u32::from_le_bytes([
                offsets_region[base],
                offsets_region[base + 1],
                offsets_region[base + 2],
                offsets_region[base + 3],
            ]) as usize
        };
        if loc_off == 0 {
            continue;
        }
        let resource: JimageResource = decode_location(locations_region, loc_off, strings_region)?;
        resources.push(resource);
    }

    Ok(Jimage {
        header,
        endian_big,
        resources,
    })
}

fn decode_location(locations: &[u8], start: usize, strings: &[u8]) -> Result<JimageResource> {
    if start >= locations.len() {
        return Err(Error::JimageOutOfRange {
            offset: start,
            size: locations.len(),
        });
    }
    let mut module_off: u64 = 0;
    let mut parent_off: u64 = 0;
    let mut base_off: u64 = 0;
    let mut extension_off: u64 = 0;
    let mut uncompressed_size: u64 = 0;
    let mut compressed_size: u64 = 0;

    let mut cursor: usize = start;
    loop {
        if cursor >= locations.len() {
            return Err(Error::JimageOutOfRange {
                offset: cursor,
                size: locations.len(),
            });
        }
        let data: u8 = locations[cursor];
        cursor += 1;
        let kind: u8 = data >> 3;
        if kind == ATTRIBUTE_END {
            break;
        }
        let length: usize = ((data & 0x07) as usize) + 1;
        let value_end: usize = cursor.checked_add(length).ok_or(Error::JimageOutOfRange {
            offset: usize::MAX,
            size: locations.len(),
        })?;
        if value_end > locations.len() {
            return Err(Error::JimageOutOfRange {
                offset: value_end,
                size: locations.len(),
            });
        }
        let value: u64 = read_be_uint(&locations[cursor..value_end], length);
        cursor = value_end;
        match kind {
            ATTRIBUTE_MODULE => module_off = value,
            ATTRIBUTE_PARENT => parent_off = value,
            ATTRIBUTE_BASE => base_off = value,
            ATTRIBUTE_EXTENSION => extension_off = value,
            ATTRIBUTE_OFFSET => {}
            ATTRIBUTE_COMPRESSED => compressed_size = value,
            ATTRIBUTE_UNCOMPRESSED => uncompressed_size = value,
            _ => {}
        }
    }

    let module: String = read_string(strings, module_off as usize)?;
    let parent: String = read_string(strings, parent_off as usize)?;
    let base: String = read_string(strings, base_off as usize)?;
    let extension: String = read_string(strings, extension_off as usize)?;

    let mut full_name: String = String::new();
    full_name.push('/');
    full_name.push_str(&module);
    full_name.push('/');
    if !parent.is_empty() {
        full_name.push_str(&parent);
        full_name.push('/');
    }
    full_name.push_str(&base);
    if !extension.is_empty() {
        full_name.push('.');
        full_name.push_str(&extension);
    }

    Ok(JimageResource {
        module,
        parent,
        base,
        extension,
        full_name,
        uncompressed_size,
        compressed_size,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AabModule {
    pub name: String,
    pub manifest: Option<Vec<u8>>,
    pub dex_files: BTreeMap<String, Vec<u8>>,
    pub resources_pb: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AabExtract {
    pub jar: JarExtract,
    pub bundle_config: Vec<u8>,
    pub modules: BTreeMap<String, AabModule>,
    pub signatures: BTreeMap<String, Vec<u8>>,
}

pub fn extract_aab(bytes: &[u8]) -> Result<AabExtract> {
    let jar: JarExtract = extract(bytes)?;
    let mut bundle_config: Option<Vec<u8>> = None;
    let mut modules: BTreeMap<String, AabModule> = BTreeMap::new();
    let mut signatures: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for entry in &jar.entries {
        let p: &str = entry.path.as_str();
        if p == "BundleConfig.pb" {
            bundle_config = Some(entry.bytes.clone());
            continue;
        }
        if p.starts_with("META-INF/") {
            if p.ends_with(".RSA")
                || p.ends_with(".DSA")
                || p.ends_with(".EC")
                || p.ends_with(".SF")
            {
                signatures.insert(entry.path.clone(), entry.bytes.clone());
            }
            continue;
        }
        let Some((module_name, rest)): Option<(&str, &str)> = p.split_once('/') else {
            continue;
        };
        if module_name.is_empty() || rest.is_empty() {
            continue;
        }
        let module: &mut AabModule =
            modules
                .entry(module_name.to_owned())
                .or_insert_with(|| AabModule {
                    name: module_name.to_owned(),
                    manifest: None,
                    dex_files: BTreeMap::new(),
                    resources_pb: None,
                });
        if rest == "manifest/AndroidManifest.xml" {
            module.manifest = Some(entry.bytes.clone());
        } else if rest == "resources.pb" {
            module.resources_pb = Some(entry.bytes.clone());
        } else if rest.starts_with("dex/") && rest.ends_with(".dex") {
            module
                .dex_files
                .insert(rest.to_owned(), entry.bytes.clone());
        }
    }
    let Some(bundle_config): Option<Vec<u8>> = bundle_config else {
        return Err(Error::NotAab);
    };
    Ok(AabExtract {
        jar,
        bundle_config,
        modules,
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

    fn build_aab(with_bundle_config: bool) -> Vec<u8> {
        use std::io::Write as _;
        let cursor: Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(512));
        let mut zip: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(cursor);
        let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        if with_bundle_config {
            zip.start_file("BundleConfig.pb", opts).unwrap();
            zip.write_all(b"\x08\x01").unwrap();
        }
        zip.start_file("base/manifest/AndroidManifest.xml", opts)
            .unwrap();
        zip.write_all(b"\x0a\x07android").unwrap();
        zip.start_file("base/dex/classes.dex", opts).unwrap();
        zip.write_all(b"dex\n035\0padpadpadpad").unwrap();
        zip.start_file("base/resources.pb", opts).unwrap();
        zip.write_all(b"\x12\x00").unwrap();
        zip.start_file("feature_x/manifest/AndroidManifest.xml", opts)
            .unwrap();
        zip.write_all(b"\x0a\x09feature_x").unwrap();
        zip.start_file("META-INF/CERT.RSA", opts).unwrap();
        zip.write_all(b"sig").unwrap();
        zip.finish().unwrap().into_inner()
    }

    #[test]
    fn aab_enumerates_modules_and_locates_base() {
        let bytes: Vec<u8> = build_aab(true);
        let aab: AabExtract = extract_aab(&bytes).expect("valid aab");
        assert!(!aab.bundle_config.is_empty());
        assert!(aab.modules.len() >= 2);
        let base: &AabModule = aab.modules.get("base").expect("base module present");
        assert!(base.manifest.is_some());
        assert_eq!(base.dex_files.len(), 1);
        assert!(base.dex_files.contains_key("dex/classes.dex"));
        assert!(base.resources_pb.is_some());
        assert!(aab.modules.contains_key("feature_x"));
        assert_eq!(aab.signatures.len(), 1);
    }

    #[test]
    fn aab_without_bundle_config_is_rejected() {
        let bytes: Vec<u8> = build_aab(false);
        let err: Error = extract_aab(&bytes).expect_err("missing BundleConfig.pb");
        assert!(matches!(err, Error::NotAab));
    }

    #[test]
    fn aab_rejects_non_zip_bytes() {
        let err: Error = extract_aab(&[0xFFu8, 0x00, 0x13, 0x37]).expect_err("not a zip");
        assert!(matches!(err, Error::Zip(_)));
    }
}
