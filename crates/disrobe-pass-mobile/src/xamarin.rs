use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};

pub const XAMARIN_ASSEMBLY_STORE_V2_MAGIC: u32 = 0x554d_4158;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum XamarinKind {
    LegacyDll,
    AssemblyStoreV1,
    AssemblyStoreV2,
    MauiSingleFile,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XamarinAssembly {
    pub container_path: String,
    pub bytes_len: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XamarinReport {
    pub kind: XamarinKind,
    pub assemblies: Vec<XamarinAssembly>,
    pub assembly_store_header: Option<AssemblyStoreHeader>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct AssemblyStoreHeader {
    pub magic: u32,
    pub version: u32,
    pub entry_count: u32,
    pub index_entry_count: u32,
    pub index_size: u32,
}

const ASSEMBLY_STORE_PATHS: &[&str] = &[
    "assemblies/assemblies.blob",
    "assemblies/assemblies.arm64_v8a.blob",
    "assemblies/assemblies.armeabi_v7a.blob",
    "assemblies/assemblies.x86_64.blob",
];

pub fn extract_xamarin_bundle(bytes: &[u8]) -> Result<XamarinReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = archive.len();
    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let f: zip::read::ZipFile<'_> = archive.by_index(i)?;
        names.push(f.name().to_owned());
    }
    let mut kind: XamarinKind = XamarinKind::Unknown;
    let mut assemblies: Vec<XamarinAssembly> = Vec::new();
    let mut assembly_store_header: Option<AssemblyStoreHeader> = None;
    let store_present: bool = names
        .iter()
        .any(|n: &String| ASSEMBLY_STORE_PATHS.contains(&n.as_str()));
    let legacy_dll_present: bool = names.iter().any(|n: &String| {
        n.starts_with("assemblies/") && (n.ends_with(".dll") || n.ends_with(".dll.so"))
    });
    let maui_present: bool = names.iter().any(|n: &String| n.contains("Microsoft.Maui"));
    if store_present {
        kind = XamarinKind::AssemblyStoreV2;
    } else if legacy_dll_present {
        kind = XamarinKind::LegacyDll;
    } else if maui_present {
        kind = XamarinKind::MauiSingleFile;
    }
    if matches!(kind, XamarinKind::Unknown) {
        return Err(Error::EntryMissing(
            "assemblies/*.dll or assemblies/assemblies.blob".to_owned(),
        ));
    }
    for i in 0..entry_count {
        let mut f: zip::read::ZipFile<'_> = archive.by_index(i)?;
        let name: String = f.name().to_owned();
        let want: bool = ASSEMBLY_STORE_PATHS.contains(&name.as_str())
            || (name.starts_with("assemblies/")
                && (name.ends_with(".dll") || name.ends_with(".dll.so")));
        if !want {
            continue;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)?;
        if ASSEMBLY_STORE_PATHS.contains(&name.as_str())
            && let Ok(header) = parse_assembly_store_header(&buf)
        {
            assembly_store_header = Some(header);
            if header.version == 2 {
                kind = XamarinKind::AssemblyStoreV2;
            } else if header.version == 1 {
                kind = XamarinKind::AssemblyStoreV1;
            }
        }
        let bytes_len: u64 = buf.len() as u64;
        assemblies.push(XamarinAssembly {
            container_path: name,
            bytes_len,
            bytes: buf,
        });
    }
    Ok(XamarinReport {
        kind,
        assemblies,
        assembly_store_header,
    })
}

pub fn parse_assembly_store_header(bytes: &[u8]) -> Result<AssemblyStoreHeader> {
    if bytes.len() < 20 {
        return Err(Error::XamarinHeaderTruncated);
    }
    let magic: u32 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if magic != XAMARIN_ASSEMBLY_STORE_V2_MAGIC {
        return Err(Error::XamarinHeaderTruncated);
    }
    let version: u32 = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    let entry_count: u32 = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let index_entry_count: u32 = u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let index_size: u32 = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    Ok(AssemblyStoreHeader {
        magic,
        version,
        entry_count,
        index_entry_count,
        index_size,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    fn synth_store_blob_v2(entries: u32) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&XAMARIN_ASSEMBLY_STORE_V2_MAGIC.to_le_bytes());
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.extend_from_slice(&entries.to_le_bytes());
        buf.extend_from_slice(&entries.to_le_bytes());
        buf.extend_from_slice(&(entries * 16).to_le_bytes());
        buf.resize(2048, 0u8);
        buf
    }

    fn synth_xamarin_apk(blob: &[u8]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            zw.start_file::<&str, ()>("AndroidManifest.xml", opts)
                .unwrap();
            zw.write_all(b"<manifest/>").unwrap();
            zw.start_file::<&str, ()>("assemblies/assemblies.blob", opts)
                .unwrap();
            zw.write_all(blob).unwrap();
            zw.finish().unwrap();
        }
        buf
    }

    #[test]
    fn parse_assembly_store_v2_header() {
        let blob: Vec<u8> = synth_store_blob_v2(7);
        let h: AssemblyStoreHeader = parse_assembly_store_header(&blob).expect("parse header");
        assert_eq!(h.magic, XAMARIN_ASSEMBLY_STORE_V2_MAGIC);
        assert_eq!(h.version, 2);
        assert_eq!(h.entry_count, 7);
    }

    #[test]
    fn extract_xamarin_apk_with_assembly_store() {
        let blob: Vec<u8> = synth_store_blob_v2(3);
        let apk: Vec<u8> = synth_xamarin_apk(&blob);
        let report: XamarinReport = extract_xamarin_bundle(&apk).expect("extract");
        assert!(matches!(report.kind, XamarinKind::AssemblyStoreV2));
        assert_eq!(report.assembly_store_header.expect("header").entry_count, 3);
        assert_eq!(report.assemblies.len(), 1);
    }

    #[test]
    fn extract_legacy_dll_xamarin() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions = SimpleFileOptions::default();
            zw.start_file::<&str, ()>("assemblies/MyApp.dll", opts)
                .unwrap();
            zw.write_all(b"MZ\x90\x00fake-pe").unwrap();
            zw.finish().unwrap();
        }
        let report: XamarinReport = extract_xamarin_bundle(&buf).expect("extract");
        assert!(matches!(report.kind, XamarinKind::LegacyDll));
        assert_eq!(report.assemblies.len(), 1);
    }
}
