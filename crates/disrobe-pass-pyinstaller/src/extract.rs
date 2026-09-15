use core::ops::Range;
use std::io::Read;
use std::path::Path;

use disrobe_py_marshal::{PyVersion, magic_for, pyversion_from_magic};
use flate2::read::ZlibDecoder;

use crate::base_library::{ZipMember, read_base_library_pyc_members};
use crate::cookie::{Cookie, find_cookie};
use crate::crypto::{AesMode, decrypt, recover_key_from_module};
use crate::debug::{dbg_enabled, dbg_hex, dbg_kv_guarded, dbg_line, dbg_section};
use crate::error::{Error, Result};
use crate::pyc_zipper::{UnzippedPyc, ZipperCompression, unzip_pyc};
use crate::pyz::{PyzEntry, PyzTocKind};
use crate::toc::{
    DependencyReference, EntryType, TocEntry, TocNameStatus, overlay_position, walk_toc,
};

#[derive(Debug, Clone)]
pub struct ExtractedEntry {
    pub toc: TocEntry,
    pub data: Vec<u8>,
    pub written_path: Option<String>,
    pub decrypted: bool,
    pub pyc_unzipped: bool,
    pub pyc_compression: Option<ZipperCompression>,
}

#[derive(Debug)]
pub struct ExtractOutput {
    pub cookie: Cookie,
    pub entries: Vec<ExtractedEntry>,
    pub encryption_key: Option<[u8; 16]>,
    pub bare_pyc_paths: Vec<String>,
    pub pyz_module_count: usize,
    pub pyc_unzipped_count: usize,
    pub base_library_module_count: usize,
    pub runtime_options: Vec<String>,
    pub dependencies: Vec<DependencyReference>,
}

pub fn extract_from_path(path: &Path) -> Result<ExtractOutput> {
    let bytes: Vec<u8> = read_file_bounded(path, MAX_INPUT_FILE_BYTES)?;
    extract_archive(&bytes)
}

fn read_file_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file: std::fs::File = std::fs::File::open(path)?;
    let len: u64 = file.metadata()?.len();
    if len > limit {
        return Err(Error::InputFileTooLarge { len, limit });
    }
    let capacity: usize =
        usize::try_from(len).map_err(|_| Error::InputFileTooLarge { len, limit })?;
    let mut limited: std::io::Take<std::fs::File> = file.take(limit.saturating_add(1u64));
    let mut bytes: Vec<u8> = Vec::with_capacity(capacity);
    let _: usize = limited.read_to_end(&mut bytes)?;
    let observed: u64 = u64::try_from(bytes.len()).map_err(|_| Error::InputFileTooLarge {
        len: u64::MAX,
        limit,
    })?;
    if observed > limit {
        return Err(Error::InputFileTooLarge {
            len: observed,
            limit,
        });
    }
    Ok(bytes)
}

pub fn extract_archive(image: &[u8]) -> Result<ExtractOutput> {
    extract_archive_with_budget(image, MAX_AGGREGATE_INFLATE)
}

pub(crate) fn extract_archive_with_budget(
    image: &[u8],
    aggregate_inflate_budget: u64,
) -> Result<ExtractOutput> {
    let cookie: Cookie = find_cookie(image)?;
    let toc: Vec<TocEntry> = walk_toc(image, &cookie)?;
    let overlay_pos: usize = overlay_position(image.len(), &cookie)?;

    dbg_section("extract.archive");
    let py_version: PyVersion = PyVersion::new(cookie.python_major, cookie.python_minor);
    let key: Option<[u8; 16]> = locate_encryption_key(image, &toc, overlay_pos, py_version);
    let mut entries: Vec<ExtractedEntry> = Vec::with_capacity(toc.len());
    let mut bare_pyc_paths: Vec<String> = Vec::new();

    let mut pyz_module_count: usize = 0usize;
    let mut pyc_unzipped_count: usize = 0usize;
    let mut base_library_module_count: usize = 0usize;
    let mut inflate_budget: u64 = aggregate_inflate_budget;
    let mut runtime_options: Vec<String> = Vec::new();
    let mut dependencies: Vec<DependencyReference> = Vec::new();

    for entry in toc {
        match entry.entry_type {
            EntryType::RuntimeOption => {
                runtime_options.push(entry.raw_name);
                continue;
            }
            EntryType::Dependency => {
                dependencies.push(DependencyReference {
                    entry_name: entry.name,
                    referenced_executable: entry.dependency_source,
                });
                continue;
            }
            _ => {}
        }
        let range: Range<usize> = entry_range(image.len(), overlay_pos, &entry)?;
        let raw: &[u8] = &image[range];
        let (decrypted_view, decrypted): (DecryptedBuf<'_>, bool) = decrypt_view(raw, key.as_ref());

        let inflated: Vec<u8> = if entry.compressed_flag == 1 {
            inflate(decrypted_view.as_slice(), &mut inflate_budget).map_err(|e| Error::Inflate {
                name: entry.name.clone(),
                source: e,
            })?
        } else {
            decrypted_view.into_owned()
        };

        let is_pyz: bool = entry.entry_type.is_pyz();
        let is_carrier: bool = entry.entry_type.is_pyc_carrier();

        if dbg_enabled() {
            let name: String = entry.name.clone();
            let label: &'static str = entry.entry_type.label();
            let inflated_len: usize = inflated.len();
            dbg_line(|| {
                format!(
                    "extract '{name}' type={label} inflated={inflated_len} decrypted={decrypted} carrier={is_carrier} pyz={is_pyz}"
                )
            });
        }

        let reconstructed: Vec<u8> = if is_carrier {
            prepend_pyc_header(&inflated, py_version)?
        } else {
            inflated.clone()
        };

        let mut pyc_unzipped: bool = false;
        let mut pyc_compression: Option<ZipperCompression> = None;
        let final_bytes: Vec<u8> = if is_carrier {
            match unzip_pyc(&reconstructed) {
                Some(unzipped) => {
                    let UnzippedPyc {
                        pyc_bytes,
                        compression,
                        ..
                    } = unzipped;
                    pyc_unzipped = true;
                    pyc_compression = Some(compression);
                    pyc_unzipped_count += 1;
                    let label: &'static str = compression.label();
                    let name: String = entry.name.clone();
                    dbg_line(|| format!("unzipped pyc-zipper layer for '{name}' ({label})"));
                    pyc_bytes
                }
                None => reconstructed,
            }
        } else {
            reconstructed
        };

        if is_carrier && dbg_enabled() {
            dbg_hex("pyc-head", &final_bytes, 16);
        }

        if is_carrier {
            bare_pyc_paths.push(format!("{}.pyc", entry.name));
        }

        if is_pyz {
            let mut unpacked: Vec<ExtractedEntry> =
                unpack_pyz_entry(&entry.name, &inflated, &mut inflate_budget, key.as_ref());
            pyz_module_count += unpacked.len();
            for module in &unpacked {
                bare_pyc_paths.push(module.toc.name.clone());
                if module.pyc_unzipped {
                    pyc_unzipped_count += 1;
                }
            }
            entries.append(&mut unpacked);
        }

        if is_base_library_zip(&entry.name) {
            let mut members: Vec<ExtractedEntry> =
                unpack_base_library(&entry.name, &inflated, &mut inflate_budget);
            base_library_module_count += members.len();
            for module in &members {
                bare_pyc_paths.push(module.toc.name.clone());
                if module.pyc_unzipped {
                    pyc_unzipped_count += 1;
                }
            }
            entries.append(&mut members);
        }

        entries.push(ExtractedEntry {
            toc: entry,
            data: final_bytes,
            written_path: None,
            decrypted,
            pyc_unzipped,
            pyc_compression,
        });
    }

    Ok(ExtractOutput {
        cookie,
        entries,
        encryption_key: key,
        bare_pyc_paths,
        pyz_module_count,
        pyc_unzipped_count,
        base_library_module_count,
        runtime_options,
        dependencies,
    })
}

fn unpack_pyz_entry(
    pyz_name: &str,
    pyz_blob: &[u8],
    inflate_budget: &mut u64,
    key: Option<&[u8; 16]>,
) -> Vec<ExtractedEntry> {
    let Ok((pyz_version, pyz_entries)): Result<(PyVersion, Vec<PyzEntry>)> =
        crate::pyz::extract_pyz_bounded(pyz_blob, inflate_budget, key)
    else {
        return Vec::new();
    };
    let root: String = format!("{pyz_name}_extracted");
    let mut out: Vec<ExtractedEntry> = Vec::with_capacity(pyz_entries.len());
    for module in pyz_entries {
        let is_package: bool = matches!(module.kind, PyzTocKind::Package);
        let entry_type: EntryType = if is_package {
            EntryType::PyzPackage
        } else if matches!(module.kind, PyzTocKind::Module) {
            EntryType::PyzModule
        } else {
            continue;
        };
        let Some(rel_path): Option<String> = pyz_module_relpath(&root, &module.name, is_package)
        else {
            continue;
        };
        let Ok(reconstructed): Result<Vec<u8>> = prepend_pyc_header(&module.bytes, pyz_version)
        else {
            continue;
        };
        let (pyc, pyc_unzipped, pyc_compression): (Vec<u8>, bool, Option<ZipperCompression>) =
            match unzip_pyc(&reconstructed) {
                Some(unzipped) => (unzipped.pyc_bytes, true, Some(unzipped.compression)),
                None => (reconstructed, false, None),
            };
        let uncompressed_size: u32 = saturating_u32_from_usize(pyc.len());
        out.push(ExtractedEntry {
            toc: TocEntry {
                entry_size: 0,
                entry_position: 0,
                compressed_size: nonnegative_i32_to_u32(module.length.max(0)),
                uncompressed_size,
                compressed_flag: 1,
                entry_type,
                raw_name: module.name,
                name: rel_path,
                name_status: TocNameStatus::Preserved,
                dependency_source: None,
            },
            data: pyc,
            written_path: None,
            decrypted: false,
            pyc_unzipped,
            pyc_compression,
        });
    }
    out
}

fn pyz_module_relpath(root: &str, dotted: &str, is_package: bool) -> Option<String> {
    let mut path: String = String::with_capacity(pyz_relpath_capacity(root.len(), dotted.len()));
    path.push_str(root);
    for part in dotted.split('.') {
        if part.is_empty() || part == ".." || part.contains(['/', '\\', ':']) {
            return None;
        }
        path.push('/');
        path.push_str(part);
    }
    if is_package {
        path.push_str("/__init__.pyc");
    } else {
        path.push_str(".pyc");
    }
    Some(path)
}

fn is_base_library_zip(name: &str) -> bool {
    name.rsplit('/')
        .next()
        .unwrap_or(name)
        .eq_ignore_ascii_case("base_library.zip")
}

fn unpack_base_library(
    zip_name: &str,
    zip_bytes: &[u8],
    inflate_budget: &mut u64,
) -> Vec<ExtractedEntry> {
    let members: Vec<ZipMember> = read_base_library_pyc_members(zip_bytes, inflate_budget);
    let root: String = format!("{zip_name}_extracted");
    let mut out: Vec<ExtractedEntry> = Vec::with_capacity(members.len());
    for member in members {
        let Some((pyc_version, body)): Option<(PyVersion, &[u8])> =
            strip_pyc_header_to_body(&member.data)
        else {
            dbg_line(|| {
                let name: &str = &member.name;
                format!("base_library member '{name}' is not a recognizable .pyc; skipping")
            });
            continue;
        };
        let Some(rel_path): Option<String> = base_library_relpath(&root, &member.name) else {
            continue;
        };
        let Ok(reconstructed): Result<Vec<u8>> = prepend_pyc_header(body, pyc_version) else {
            continue;
        };
        let (pyc, pyc_unzipped, pyc_compression): (Vec<u8>, bool, Option<ZipperCompression>) =
            match unzip_pyc(&reconstructed) {
                Some(unzipped) => (unzipped.pyc_bytes, true, Some(unzipped.compression)),
                None => (reconstructed, false, None),
            };
        let is_package: bool = member
            .name
            .rsplit('/')
            .next()
            .is_some_and(|leaf: &str| leaf.eq_ignore_ascii_case("__init__.pyc"));
        let entry_type: EntryType = if is_package {
            EntryType::BaseLibraryPackage
        } else {
            EntryType::BaseLibraryModule
        };
        out.push(ExtractedEntry {
            toc: TocEntry {
                entry_size: 0,
                entry_position: 0,
                compressed_size: saturating_u32_from_usize(member.compressed_len),
                uncompressed_size: saturating_u32_from_usize(pyc.len()),
                compressed_flag: u8::from(!member.stored),
                entry_type,
                raw_name: member.name,
                name: rel_path,
                name_status: TocNameStatus::Preserved,
                dependency_source: None,
            },
            data: pyc,
            written_path: None,
            decrypted: false,
            pyc_unzipped,
            pyc_compression,
        });
    }
    out
}

fn strip_pyc_header_to_body(pyc: &[u8]) -> Option<(PyVersion, &[u8])> {
    let magic_bytes: &[u8] = pyc.get(0..4)?;
    let magic: u32 = u32::from_le_bytes([
        magic_bytes[0],
        magic_bytes[1],
        magic_bytes[2],
        magic_bytes[3],
    ]);
    let version: PyVersion = pyversion_from_magic(magic)?;
    let body: &[u8] = pyc.get(version.pyc_header_len()..)?;
    if body.is_empty() {
        return None;
    }
    Some((version, body))
}

fn base_library_relpath(root: &str, zip_path: &str) -> Option<String> {
    let mut path: String = String::with_capacity(root.len().saturating_add(zip_path.len() + 1));
    path.push_str(root);
    for part in zip_path.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\\', ':']) {
            return None;
        }
        path.push('/');
        path.push_str(part);
    }
    Some(path)
}

const fn saturating_u32_from_usize(value: usize) -> u32 {
    if value > u32::MAX as usize {
        u32::MAX
    } else {
        value as u32
    }
}

const fn nonnegative_i32_to_u32(value: i32) -> u32 {
    if value <= 0 { 0u32 } else { value as u32 }
}

const fn pyz_relpath_capacity(root_len: usize, dotted_len: usize) -> usize {
    root_len.saturating_add(dotted_len).saturating_add(12usize)
}

enum DecryptedBuf<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl DecryptedBuf<'_> {
    const fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(b) => b,
            Self::Owned(v) => v.as_slice(),
        }
    }

    fn into_owned(self) -> Vec<u8> {
        match self {
            Self::Borrowed(b) => b.to_vec(),
            Self::Owned(v) => v,
        }
    }
}

fn decrypt_view<'a>(raw: &'a [u8], key: Option<&[u8; 16]>) -> (DecryptedBuf<'a>, bool) {
    let Some(k) = key else {
        return (DecryptedBuf::Borrowed(raw), false);
    };
    for mode in [AesMode::Ctr, AesMode::Cfb8] {
        if let Some(plain) = decrypt(raw, k, mode)
            && looks_like_zlib(&plain)
        {
            return (DecryptedBuf::Owned(plain), true);
        }
    }
    (DecryptedBuf::Borrowed(raw), false)
}

fn looks_like_zlib(buf: &[u8]) -> bool {
    buf.len() >= 2 && buf[0] == 0x78 && matches!(buf[1], 0x01 | 0x5e | 0x9c | 0xda)
}

fn locate_encryption_key(
    image: &[u8],
    toc: &[TocEntry],
    overlay_pos: usize,
    py_version: PyVersion,
) -> Option<[u8; 16]> {
    let Some(key_entry): Option<&TocEntry> = toc.iter().find(|e| {
        e.name == "pyimod00_crypto_key"
            && matches!(e.entry_type, EntryType::Module | EntryType::Package)
    }) else {
        dbg_line(|| "no pyimod00_crypto_key module: archive is unencrypted".to_owned());
        return None;
    };
    dbg_line(|| "pyimod00_crypto_key present: recovering AES key from its code object".to_owned());
    let Ok(range): Result<Range<usize>> = entry_range(image.len(), overlay_pos, key_entry) else {
        dbg_line(|| "crypto-key entry data exceeds file size".to_owned());
        return None;
    };
    let raw: &[u8] = &image[range];
    let inflated: Vec<u8> = if key_entry.compressed_flag == 1 {
        let mut key_budget: u64 = MAX_KEY_MODULE_INFLATE;
        inflate(raw, &mut key_budget).ok()?
    } else {
        raw.to_vec()
    };
    let body: &[u8] = strip_optional_pyc_header(&inflated, py_version);
    let key: Option<[u8; 16]> = recover_key_from_module(body, py_version)
        .or_else(|| recover_key_from_module(&inflated, py_version));
    if let Some(bytes) = key {
        dbg_kv_guarded("crypto_key", || {
            String::from_utf8_lossy(&bytes).into_owned()
        });
    } else {
        dbg_line(|| "crypto-key module found but 16-byte key not recoverable".to_owned());
    }
    key
}

fn entry_range(image_len: usize, overlay_pos: usize, entry: &TocEntry) -> Result<Range<usize>> {
    let entry_position: usize = usize::try_from(entry.entry_position).map_err(|_| {
        Error::TocWalk(
            overlay_pos,
            format!(
                "entry '{}' position {} does not fit usize",
                entry.name, entry.entry_position
            ),
        )
    })?;
    let compressed_size: usize = usize::try_from(entry.compressed_size).map_err(|_| {
        Error::TocWalk(
            overlay_pos,
            format!(
                "entry '{}' compressed size {} does not fit usize",
                entry.name, entry.compressed_size
            ),
        )
    })?;
    let start: usize = overlay_pos.checked_add(entry_position).ok_or_else(|| {
        Error::TocWalk(
            overlay_pos,
            format!(
                "entry '{}' position {} overflows usize",
                entry.name, entry.entry_position
            ),
        )
    })?;
    let end: usize = start.checked_add(compressed_size).ok_or_else(|| {
        Error::TocWalk(
            start,
            format!(
                "entry '{}' compressed size {} overflows usize",
                entry.name, entry.compressed_size
            ),
        )
    })?;
    if end > image_len {
        return Err(Error::TocWalk(
            start,
            format!("entry '{}' data exceeds file size", entry.name),
        ));
    }
    Ok(start..end)
}

fn strip_optional_pyc_header(body: &[u8], py_version: PyVersion) -> &[u8] {
    if body.len() >= 4 && magic_for(py_version).is_some_and(|m| body[..4] == m.to_le_bytes()) {
        let header_len: usize = py_version.pyc_header_len();
        return body
            .get(header_len..)
            .map_or(body, |stripped: &[u8]| stripped);
    }
    body
}

const MAX_INFLATE_RATIO: u64 = 1024;
const MAX_INFLATE_ABS: u64 = 4 * 1024 * 1024 * 1024;
const MAX_AGGREGATE_INFLATE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_KEY_MODULE_INFLATE: u64 = 1024 * 1024;
const MAX_INPUT_FILE_BYTES: u64 = 1024 * 1024 * 1024;

fn inflate(input: &[u8], aggregate_budget: &mut u64) -> std::io::Result<Vec<u8>> {
    let cap: u64 = (input.len() as u64)
        .saturating_mul(MAX_INFLATE_RATIO)
        .min(MAX_INFLATE_ABS)
        .min(*aggregate_budget);
    let budget: u64 = cap.saturating_add(1);
    let decoder: ZlibDecoder<&[u8]> = ZlibDecoder::new(input);
    let mut limited: std::io::Take<ZlibDecoder<&[u8]>> = decoder.take(budget);
    let mut out: Vec<u8> = Vec::new();
    limited.read_to_end(&mut out)?;
    if out.len() as u64 > cap {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("decompressed entry exceeds bomb cap of {cap} bytes"),
        ));
    }
    *aggregate_budget = aggregate_budget.saturating_sub(out.len() as u64);
    Ok(out)
}

fn prepend_pyc_header(body: &[u8], py_version: PyVersion) -> Result<Vec<u8>> {
    let magic: u32 = magic_for(py_version).ok_or(Error::UnknownPycVersion {
        major: py_version.major,
        minor: py_version.minor,
    })?;
    let trailing_u32_count: usize = if py_version.has_pep552_header() {
        3
    } else if py_version.has_source_size() {
        2
    } else {
        1
    };
    let mut header: Vec<u8> =
        Vec::with_capacity(pyc_header_capacity(trailing_u32_count, body.len()));
    header.extend_from_slice(&magic.to_le_bytes());
    for _ in 0..trailing_u32_count {
        header.extend_from_slice(&0u32.to_le_bytes());
    }
    header.extend_from_slice(body);
    Ok(header)
}

const fn pyc_header_capacity(trailing_u32_count: usize, body_len: usize) -> usize {
    4usize
        .saturating_add(trailing_u32_count.saturating_mul(4usize))
        .saturating_add(body_len)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use disrobe_core::scratch::ScratchFile;

    #[test]
    fn missing_cookie_fails() {
        let data: Vec<u8> = vec![0u8; 4096];
        let err: Option<Error> = extract_archive(&data).err();
        assert!(matches!(err, Some(Error::CookieNotFound)));
    }

    #[test]
    fn path_reader_rejects_file_past_cap() {
        let (scratch, handle): (ScratchFile, std::fs::File) =
            ScratchFile::create("disrobe-pyinstaller-read-cap", "bin")
                .expect("create scratch file");
        drop(handle);
        let path: std::path::PathBuf = scratch.path().to_path_buf();
        std::fs::write(&path, [0u8; 8]).expect("write temp input");
        let err: Error = read_file_bounded(&path, 4u64).expect_err("over-cap file rejected");
        assert!(matches!(err, Error::InputFileTooLarge { len: 8, limit: 4 }));
    }

    #[test]
    fn pyc_header_py312_layout() {
        let body: Vec<u8> = vec![0x00, 0x01, 0x02, 0x03];
        let header: Vec<u8> =
            prepend_pyc_header(&body, PyVersion::PY312).expect("3.12 has a magic");
        assert_eq!(header.len(), 16 + body.len());
        assert_eq!(&header[2..4], b"\r\n");
        assert_eq!(&header[12..16], &[0x00; 4]);
        assert_eq!(&header[16..], body.as_slice());
    }

    #[test]
    fn pyc_header_py34_short_layout() {
        let body: Vec<u8> = vec![0xAA; 8];
        let header: Vec<u8> = prepend_pyc_header(&body, PyVersion::PY34).expect("3.4 has a magic");
        assert_eq!(header.len(), 12 + body.len());
        assert_eq!(&header[12..], body.as_slice());
    }

    #[test]
    fn pyc_header_py27_legacy_layout() {
        let body: Vec<u8> = vec![0xCC; 8];
        let header: Vec<u8> = prepend_pyc_header(&body, PyVersion::PY27).expect("2.7 has a magic");
        assert_eq!(header.len(), 8 + body.len());
        assert_eq!(&header[8..], body.as_slice());
    }

    #[test]
    fn pyc_header_stamps_correct_magic_for_non_312_version() {
        let body: Vec<u8> = vec![0x11, 0x22, 0x33, 0x44];
        for version in [PyVersion::PY311, PyVersion::PY313, PyVersion::PY314] {
            let header: Vec<u8> =
                prepend_pyc_header(&body, version).expect("mapped version has a magic");
            let stamped: u32 = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
            let expected: u32 = magic_for(version).expect("oracle magic for mapped version");
            assert_eq!(
                stamped, expected,
                "{}.{} pyc must carry its own magic, never the 3.12 fallback",
                version.major, version.minor
            );
            assert_ne!(
                stamped,
                magic_for(PyVersion::PY312).expect("3.12 magic"),
                "{}.{} must not be stamped with the 3.12 magic",
                version.major,
                version.minor
            );
        }
    }

    #[test]
    fn integer_capacity_helpers_saturate() {
        assert_eq!(saturating_u32_from_usize(7usize), 7u32);
        assert_eq!(saturating_u32_from_usize(usize::MAX), u32::MAX);
        assert_eq!(nonnegative_i32_to_u32(-1i32), 0u32);
        assert_eq!(nonnegative_i32_to_u32(9i32), 9u32);
    }

    #[test]
    fn pyc_header_refuses_unknown_version_instead_of_silent_312() {
        let body: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let unknown: PyVersion = PyVersion::new(3, 20);
        assert!(
            magic_for(unknown).is_none(),
            "test premise: this version must be absent from the magic table",
        );
        let err: Error = prepend_pyc_header(&body, unknown)
            .expect_err("an unmapped version must error, never stamp the 3.12 magic");
        assert!(
            matches!(
                err,
                Error::UnknownPycVersion {
                    major: 3,
                    minor: 20
                }
            ),
            "unmapped version must surface UnknownPycVersion, got {err:?}",
        );
    }

    #[test]
    fn pyz_relpath_capacity_saturates() {
        assert_eq!(pyz_relpath_capacity(4usize, 8usize), 24usize);
        assert_eq!(pyz_relpath_capacity(usize::MAX, 1usize), usize::MAX);
    }

    #[test]
    fn pyc_header_capacity_saturates() {
        assert_eq!(pyc_header_capacity(3usize, 4usize), 20usize);
        assert_eq!(pyc_header_capacity(usize::MAX, 1usize), usize::MAX);
        assert_eq!(pyc_header_capacity(1usize, usize::MAX), usize::MAX);
    }

    #[test]
    fn inflate_roundtrips_small_payload() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let payload: &[u8] = b"pyinstaller entry payload bytes";
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let mut budget: u64 = MAX_AGGREGATE_INFLATE;
        let out: Vec<u8> = inflate(&compressed, &mut budget).unwrap();
        assert_eq!(out, payload);
        assert_eq!(budget, MAX_AGGREGATE_INFLATE - payload.len() as u64);
    }

    #[test]
    fn inflate_rejects_decompression_bomb() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let zeros: Vec<u8> = vec![0u8; 64 * 1024 * 1024];
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&zeros).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        assert!(
            (compressed.len() as u64) * MAX_INFLATE_RATIO < zeros.len() as u64,
            "test bomb must exceed the ratio cap to be meaningful"
        );
        let mut budget: u64 = MAX_AGGREGATE_INFLATE;
        let err: std::io::Error = inflate(&compressed, &mut budget).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn inflate_honors_exhausted_aggregate_budget() {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let payload: Vec<u8> = vec![0u8; 1024];
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::best());
        enc.write_all(&payload).unwrap();
        let compressed: Vec<u8> = enc.finish().unwrap();
        let mut budget: u64 = 16;
        let err: std::io::Error = inflate(&compressed, &mut budget).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(budget, 16, "a rejected inflate must not consume the budget");
    }

    fn zlib_compress(input: &[u8]) -> Vec<u8> {
        use flate2::Compression;
        use flate2::write::ZlibEncoder;
        use std::io::Write;
        let mut enc: ZlibEncoder<Vec<u8>> = ZlibEncoder::new(Vec::new(), Compression::new(9));
        enc.write_all(input).expect("zlib write");
        enc.finish().expect("zlib finish")
    }

    fn assemble_v21_carchive(
        entries: &[(u8, &str, Vec<u8>)],
        pyver: u32,
        trailing: &[u8],
    ) -> Vec<u8> {
        const COOKIE_LEN_V21: usize = 88;
        let mut data_region: Vec<u8> = Vec::new();
        let mut toc_region: Vec<u8> = Vec::new();
        for (type_byte, name, payload) in entries {
            let compressed: Vec<u8> = zlib_compress(payload);
            let position: u32 = u32::try_from(data_region.len()).expect("pos fits");
            let clen: u32 = u32::try_from(compressed.len()).expect("clen fits");
            let ulen: u32 = u32::try_from(payload.len()).expect("ulen fits");
            data_region.extend_from_slice(&compressed);
            let name_bytes: &[u8] = name.as_bytes();
            let entry_size: u32 = 18 + u32::try_from(name_bytes.len()).expect("name fits");
            toc_region.extend_from_slice(&entry_size.to_be_bytes());
            toc_region.extend_from_slice(&position.to_be_bytes());
            toc_region.extend_from_slice(&clen.to_be_bytes());
            toc_region.extend_from_slice(&ulen.to_be_bytes());
            toc_region.push(1u8);
            toc_region.push(*type_byte);
            toc_region.extend_from_slice(name_bytes);
        }
        let toc_offset: u32 = u32::try_from(data_region.len()).expect("toc_offset fits");
        let toc_length: u32 = u32::try_from(toc_region.len()).expect("toc_length fits");
        let package_len: u32 =
            toc_offset + toc_length + u32::try_from(COOKIE_LEN_V21).expect("cookie fits");
        let mut archive: Vec<u8> = Vec::new();
        archive.extend_from_slice(&data_region);
        archive.extend_from_slice(&toc_region);
        archive.extend_from_slice(crate::MEI_MAGIC);
        archive.extend_from_slice(&package_len.to_be_bytes());
        archive.extend_from_slice(&toc_offset.to_be_bytes());
        archive.extend_from_slice(&toc_length.to_be_bytes());
        archive.extend_from_slice(&pyver.to_be_bytes());
        let mut libname: Vec<u8> = b"python312.dll".to_vec();
        libname.resize(64, 0u8);
        archive.extend_from_slice(&libname);
        archive.extend_from_slice(trailing);
        archive
    }

    #[test]
    fn extracts_through_trailing_authenticode_style_signature() {
        let entries: [(u8, &str, Vec<u8>); 2] = [
            (b'b', "_socket.pyd", b"native-extension-bytes".to_vec()),
            (b'x', "data.bin", b"resource-bytes".to_vec()),
        ];
        let signature: Vec<u8> = vec![0x99u8; 4096];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 312, &signature);
        let out: ExtractOutput =
            extract_archive(&archive).expect("trailing-signed archive extracts");
        assert_eq!(
            out.entries.len(),
            2,
            "both entries recovered past the trailing blob"
        );
        let socket: &ExtractedEntry = out
            .entries
            .iter()
            .find(|e| e.toc.name == "_socket.pyd")
            .expect("native entry recovered");
        assert_eq!(
            socket.data, b"native-extension-bytes",
            "payload bytes intact"
        );
    }

    #[test]
    fn aggregate_inflate_budget_bounds_total_output_across_entries() {
        let payload: Vec<u8> = vec![0u8; 4096];
        let entries: [(u8, &str, Vec<u8>); 4] = [
            (b'x', "a.bin", payload.clone()),
            (b'x', "b.bin", payload.clone()),
            (b'x', "c.bin", payload.clone()),
            (b'x', "d.bin", payload),
        ];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 312, &[]);

        let full: ExtractOutput = extract_archive(&archive)
            .expect("valid multi-entry archive extracts under default budget");
        assert_eq!(
            full.entries.len(),
            4,
            "all four entries recover with the default budget"
        );
        assert!(
            full.entries.iter().all(|e| e.data.len() == 4096),
            "each recovered entry carries its full uncompressed body"
        );

        let starved: Result<ExtractOutput> = extract_archive_with_budget(&archive, 4096 + 2048);
        let err: Error =
            starved.expect_err("a budget below the aggregate output must reject, not OOM");
        assert!(
            matches!(err, Error::Inflate { .. }),
            "aggregate-budget exhaustion surfaces a structured Inflate error, got {err:?}"
        );
    }

    #[test]
    fn picks_last_cookie_when_magic_appears_in_data() {
        let mut decoy_payload: Vec<u8> = Vec::new();
        decoy_payload.extend_from_slice(crate::MEI_MAGIC);
        decoy_payload.extend_from_slice(&[0u8; 80]);
        let entries: [(u8, &str, Vec<u8>); 1] = [(b'x', "decoy.bin", decoy_payload)];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 312, &[]);
        let cookie: Cookie = find_cookie(&archive).expect("real cookie located");
        assert_eq!(
            cookie.python_minor, 12,
            "real trailing cookie chosen, not the decoy in data"
        );
        let out: ExtractOutput =
            extract_archive(&archive).expect("extract with decoy magic in data");
        assert_eq!(out.entries.len(), 1);
    }

    #[test]
    fn carrier_pyc_header_uses_cookie_version_magic_not_312() {
        let body: &[u8] = b"carrier code object body bytes that are not a pyc-zipper container";
        let entries: [(u8, &str, Vec<u8>); 1] = [(b'm', "app_mod", body.to_vec())];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 311, &[]);
        let out: ExtractOutput = extract_archive(&archive).expect("3.11 archive extracts");
        let module: &ExtractedEntry = out
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.toc.name == "app_mod")
            .expect("carrier module present");
        let stamped: u32 = u32::from_le_bytes([
            module.data[0],
            module.data[1],
            module.data[2],
            module.data[3],
        ]);
        let expected: u32 = magic_for(PyVersion::PY311).expect("3.11 magic from marshal oracle");
        assert_eq!(
            stamped, expected,
            "a 3.11 PyInstaller carrier must get the 3.11 pyc magic, not the 3.12 fallback",
        );
        assert_eq!(
            &module.data[16..],
            body,
            "body bytes preserved after the header"
        );
    }

    #[test]
    fn carrier_with_unknown_cookie_version_errors_not_silent_312() {
        let body: &[u8] = b"carrier body for a python version we have no marshal magic for";
        let entries: [(u8, &str, Vec<u8>); 1] = [(b'm', "future_mod", body.to_vec())];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 320, &[]);
        let err: Error = extract_archive(&archive)
            .expect_err("an unknown cookie version must error, never produce a wrong-magic pyc");
        assert!(
            matches!(
                err,
                Error::UnknownPycVersion {
                    major: 3,
                    minor: 20
                }
            ),
            "unknown cookie version must surface UnknownPycVersion, got {err:?}",
        );
    }

    #[test]
    fn ordinary_pyc_carrier_is_not_falsely_unzipped() {
        let body: &[u8] = b"this is not a marshalled code object body, just plain bytes";
        let entries: [(u8, &str, Vec<u8>); 1] = [(b'm', "plain_mod", body.to_vec())];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 312, &[]);
        let out: ExtractOutput = extract_archive(&archive).expect("extract plain module");
        assert_eq!(
            out.pyc_unzipped_count, 0,
            "a non-zipped pyc must never be reported as unzipped"
        );
        let module: &ExtractedEntry = out
            .entries
            .iter()
            .find(|e| e.toc.name == "plain_mod")
            .expect("module present");
        assert!(!module.pyc_unzipped);
        assert_eq!(
            &module.data[16..],
            body,
            "the reconstructed pyc body must be the original carrier bytes, untouched"
        );
    }

    #[test]
    fn zipfile_typecode_entry_passes_through_verbatim_never_pyz_decoded() {
        let empty_pkzip_eocd: Vec<u8> = {
            let mut v: Vec<u8> = vec![0x50, 0x4b, 0x05, 0x06];
            v.extend_from_slice(&[0u8; 18]);
            v
        };
        let entries: [(u8, &str, Vec<u8>); 1] =
            [(b'Z', "vendor/extra.zip", empty_pkzip_eocd.clone())];
        let archive: Vec<u8> = assemble_v21_carchive(&entries, 312, &[]);

        let cookie: Cookie = find_cookie(&archive).expect("cookie located");
        let toc: Vec<TocEntry> = walk_toc(&archive, &cookie).expect("toc walks");
        assert_eq!(toc[0].entry_type, EntryType::Zipfile);
        assert!(!toc[0].entry_type.is_pyz());

        let out: ExtractOutput =
            extract_archive(&archive).expect("a real pkzip payload under 'Z' must extract cleanly");
        assert_eq!(
            out.pyz_module_count, 0,
            "a 'Z' (ARCHIVE_ITEM_ZIPFILE) entry must never be run through the PYZ marshal \
             unpacker; PyInstaller's own CArchiveReader refuses to open it as an embedded archive",
        );
        let zip_entry: &ExtractedEntry = out
            .entries
            .iter()
            .find(|e: &&ExtractedEntry| e.toc.name == "vendor/extra.zip")
            .expect("the zipfile entry itself must survive extraction");
        assert_eq!(
            zip_entry.data, empty_pkzip_eocd,
            "the real bootloader extracts a 'Z' entry byte-for-byte verbatim to disk; disrobe \
             must recover the same untouched bytes, never a corrupted or PYZ-reinterpreted body",
        );
        assert_eq!(zip_entry.toc.entry_type, EntryType::Zipfile);
        assert!(!zip_entry.toc.entry_type.is_pyc_carrier());
    }
}
