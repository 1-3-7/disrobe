use std::io::Cursor;

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};

pub const MACHO_FAT_MAGIC_BE: u32 = 0xcafe_babe;
pub const MACHO_FAT_MAGIC_64_BE: u32 = 0xcafe_babf;
const MACHO_FAT_ARCH_COUNT_CAP: usize = 4096;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaEntry {
    pub container_path: String,
    pub bytes_len: u64,
    pub is_executable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaExtractionReport {
    pub entries: Vec<IpaEntry>,
    pub has_codesignature: bool,
    pub has_provisioning_profile: bool,
    pub primary_executable: Option<String>,
}

pub fn extract_ipa(bytes: &[u8]) -> Result<IpaExtractionReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut entries: Vec<IpaEntry> = Vec::with_capacity(entry_count);
    let mut has_codesignature: bool = false;
    let mut has_provisioning_profile: bool = false;
    let mut primary_executable: Option<String> = None;
    for i in 0..entry_count {
        let f: zip::read::ZipFile<'_> = archive.by_index(i)?;
        let name: String = f.name().to_owned();
        let bytes_len: u64 = f.size();
        let is_executable: bool = is_app_bundle_executable(&name);
        if name.ends_with("/_CodeSignature/CodeResources")
            || name.ends_with("_CodeSignature/CodeResources")
        {
            has_codesignature = true;
        }
        if name.ends_with(".mobileprovision") || name.ends_with("embedded.mobileprovision") {
            has_provisioning_profile = true;
        }
        if is_executable && (primary_executable.is_none() || is_main_bundle_executable(&name)) {
            primary_executable = Some(name.clone());
        }
        entries.push(IpaEntry {
            container_path: name,
            bytes_len,
            is_executable,
        });
    }
    if !entries
        .iter()
        .any(|e: &IpaEntry| e.container_path.starts_with("Payload/"))
    {
        return Err(Error::EntryMissing("Payload/*.app/*".to_owned()));
    }
    Ok(IpaExtractionReport {
        entries,
        has_codesignature,
        has_provisioning_profile,
        primary_executable,
    })
}

fn is_app_bundle_executable(path: &str) -> bool {
    if path.ends_with('/') || !path.contains(".app/") {
        return false;
    }
    if path.contains("/_CodeSignature/") {
        return false;
    }
    let tail: &str = path.rsplit('/').next().unwrap_or("");
    !tail.contains('.')
}

fn is_main_bundle_executable(path: &str) -> bool {
    let Some(app_idx): Option<usize> = path.rfind(".app/") else {
        return false;
    };
    let after_app: &str = &path[app_idx + ".app/".len()..];
    if after_app.contains('/') {
        return false;
    }
    let bundle_stem: &str = path[..app_idx].rsplit('/').next().unwrap_or("");
    !bundle_stem.is_empty() && after_app == bundle_stem
}

pub fn extract_ipa_file_bytes(bytes: &[u8], container_path: &str) -> Result<Vec<u8>> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let f: zip::read::ZipFile<'_> = archive
        .by_name(container_path)
        .map_err(|_| Error::EntryMissing(container_path.to_owned()))?;
    crate::read_zip_file_bounded(f, container_path)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FatArchEntry {
    pub cpu_type: u32,
    pub cpu_subtype: u32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachOFatReport {
    pub magic: u32,
    pub is_64bit: bool,
    pub arches: Vec<FatArchEntry>,
}

pub fn walk_macho_fat(bytes: &[u8]) -> Result<MachOFatReport> {
    if bytes.len() < 8 {
        return Err(Error::MachOFatTruncated {
            need: 8,
            got: bytes.len(),
        });
    }
    let magic: u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let is_64bit: bool = match magic {
        MACHO_FAT_MAGIC_BE => false,
        MACHO_FAT_MAGIC_64_BE => true,
        _ => return Err(Error::MachOFatBadMagic),
    };
    let nfat: u32 = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let entry_size: usize = if is_64bit { 32 } else { 20 };
    let arch_count: usize = usize::try_from(nfat).map_err(|_| Error::MachOFatTooManyArches {
        count: usize::MAX,
        limit: MACHO_FAT_ARCH_COUNT_CAP,
    })?;
    if arch_count > MACHO_FAT_ARCH_COUNT_CAP {
        return Err(Error::MachOFatTooManyArches {
            count: arch_count,
            limit: MACHO_FAT_ARCH_COUNT_CAP,
        });
    }
    let table_bytes: usize =
        arch_count
            .checked_mul(entry_size)
            .ok_or(Error::MachOFatTruncated {
                need: usize::MAX,
                got: bytes.len(),
            })?;
    let need: usize = 8usize
        .checked_add(table_bytes)
        .ok_or(Error::MachOFatTruncated {
            need: usize::MAX,
            got: bytes.len(),
        })?;
    if bytes.len() < need {
        return Err(Error::MachOFatTruncated {
            need,
            got: bytes.len(),
        });
    }
    let mut arches: Vec<FatArchEntry> = Vec::with_capacity(arch_count);
    for i in 0..arch_count {
        let base: usize = 8 + i * entry_size;
        let cpu_type: u32 = u32::from_be_bytes([
            bytes[base],
            bytes[base + 1],
            bytes[base + 2],
            bytes[base + 3],
        ]);
        let cpu_subtype: u32 = u32::from_be_bytes([
            bytes[base + 4],
            bytes[base + 5],
            bytes[base + 6],
            bytes[base + 7],
        ]);
        let (offset, size, align): (u64, u64, u32) = if is_64bit {
            let off: u64 = u64::from_be_bytes([
                bytes[base + 8],
                bytes[base + 9],
                bytes[base + 10],
                bytes[base + 11],
                bytes[base + 12],
                bytes[base + 13],
                bytes[base + 14],
                bytes[base + 15],
            ]);
            let siz: u64 = u64::from_be_bytes([
                bytes[base + 16],
                bytes[base + 17],
                bytes[base + 18],
                bytes[base + 19],
                bytes[base + 20],
                bytes[base + 21],
                bytes[base + 22],
                bytes[base + 23],
            ]);
            let alg: u32 = u32::from_be_bytes([
                bytes[base + 24],
                bytes[base + 25],
                bytes[base + 26],
                bytes[base + 27],
            ]);
            (off, siz, alg)
        } else {
            let off: u32 = u32::from_be_bytes([
                bytes[base + 8],
                bytes[base + 9],
                bytes[base + 10],
                bytes[base + 11],
            ]);
            let siz: u32 = u32::from_be_bytes([
                bytes[base + 12],
                bytes[base + 13],
                bytes[base + 14],
                bytes[base + 15],
            ]);
            let alg: u32 = u32::from_be_bytes([
                bytes[base + 16],
                bytes[base + 17],
                bytes[base + 18],
                bytes[base + 19],
            ]);
            (u64::from(off), u64::from(siz), alg)
        };
        arches.push(FatArchEntry {
            cpu_type,
            cpu_subtype,
            offset,
            size,
            align,
        });
    }
    Ok(MachOFatReport {
        magic,
        is_64bit,
        arches,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    fn synth_minimal_ipa() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (n, c) in [
                ("Payload/MyApp.app/MyApp", &b"fake-macho"[..]),
                ("Payload/MyApp.app/Info.plist", &b"<plist/>"[..]),
                (
                    "Payload/MyApp.app/_CodeSignature/CodeResources",
                    &b"<plist/>"[..],
                ),
                (
                    "Payload/MyApp.app/embedded.mobileprovision",
                    &b"profile"[..],
                ),
                ("Payload/MyApp.app/main.jsbundle", &b"var rn=1;"[..]),
            ] {
                zw.start_file::<&str, ()>(n, opts).expect("start");
                zw.write_all(c).expect("write");
            }
            zw.finish().expect("finish");
        }
        buf
    }

    fn synth_macho_fat() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&MACHO_FAT_MAGIC_BE.to_be_bytes());
        buf.extend_from_slice(&2u32.to_be_bytes());
        for (cpu, sub, off, siz, alg) in [
            (0x0100_0007u32, 3u32, 0x1000u32, 0x2000u32, 12u32),
            (0x0100_000cu32, 0u32, 0x4000u32, 0x2000u32, 14u32),
        ] {
            buf.extend_from_slice(&cpu.to_be_bytes());
            buf.extend_from_slice(&sub.to_be_bytes());
            buf.extend_from_slice(&off.to_be_bytes());
            buf.extend_from_slice(&siz.to_be_bytes());
            buf.extend_from_slice(&alg.to_be_bytes());
        }
        buf
    }

    #[test]
    fn extract_ipa_round_trip() {
        let ipa: Vec<u8> = synth_minimal_ipa();
        let report: IpaExtractionReport = extract_ipa(&ipa).expect("extract");
        assert!(report.has_codesignature);
        assert!(report.has_provisioning_profile);
        assert_eq!(
            report.primary_executable.as_deref(),
            Some("Payload/MyApp.app/MyApp")
        );
    }

    #[test]
    fn extract_ipa_file_bytes_round_trip() {
        let ipa: Vec<u8> = synth_minimal_ipa();
        let bytes: Vec<u8> =
            extract_ipa_file_bytes(&ipa, "Payload/MyApp.app/main.jsbundle").expect("file");
        assert_eq!(bytes, b"var rn=1;");
    }

    #[test]
    fn walk_macho_fat_two_arches() {
        let buf: Vec<u8> = synth_macho_fat();
        let report: MachOFatReport = walk_macho_fat(&buf).expect("fat");
        assert!(!report.is_64bit);
        assert_eq!(report.arches.len(), 2);
        assert_eq!(report.arches[0].offset, 0x1000);
        assert_eq!(report.arches[1].cpu_type, 0x0100_000c);
    }

    #[test]
    fn walk_macho_fat_rejects_bad_magic() {
        let buf: Vec<u8> = vec![0u8; 32];
        let err: Error = walk_macho_fat(&buf).expect_err("must fail");
        assert!(matches!(err, Error::MachOFatBadMagic));
    }

    #[test]
    fn walk_macho_fat_rejects_arch_count_over_cap() {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&MACHO_FAT_MAGIC_BE.to_be_bytes());
        let count: u32 = u32::try_from(MACHO_FAT_ARCH_COUNT_CAP + 1).expect("cap fits u32");
        buf.extend_from_slice(&count.to_be_bytes());
        let err: Error = walk_macho_fat(&buf).expect_err("must fail");
        assert!(matches!(err, Error::MachOFatTooManyArches { .. }));
    }
}
