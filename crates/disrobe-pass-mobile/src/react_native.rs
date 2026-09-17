use std::io::Cursor;

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RnBundlePlatform {
    Android,
    Ios,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RnBundleFormat {
    HermesBytecode,
    JavaScriptSource,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RnBundleEntry {
    pub container_path: String,
    pub platform: RnBundlePlatform,
    pub format: RnBundleFormat,
    pub bytes_len: u64,
    pub blake3: [u8; 32],
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RnExtractionReport {
    pub bundles: Vec<RnBundleEntry>,
    pub manifest_entries_scanned: usize,
}

const ANDROID_BUNDLE_NAMES: &[&str] = &[
    "assets/index.android.bundle",
    "assets/index.android.jsbundle",
    "assets/index.bundle",
];

const IOS_BUNDLE_NAMES: &[&str] = &["Payload/main.jsbundle", "main.jsbundle"];

pub fn extract_from_apk_or_ipa(bytes: &[u8]) -> Result<RnExtractionReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut bundles: Vec<RnBundleEntry> = Vec::new();
    for index in 0..entry_count {
        let file: zip::read::ZipFile<'_> = archive.by_index(index)?;
        let raw_name: String = file.name().to_owned();
        let classification: Option<(RnBundlePlatform, RnBundleFormat)> =
            classify_bundle_path(&raw_name);
        let Some((platform, _)): Option<(RnBundlePlatform, RnBundleFormat)> = classification else {
            continue;
        };
        let buf: Vec<u8> = crate::read_zip_file_bounded(file, &raw_name)?;
        let format: RnBundleFormat = detect_bundle_format(&buf);
        let hash: [u8; 32] = blake3::hash(&buf).into();
        let bytes_len: u64 = buf.len() as u64;
        bundles.push(RnBundleEntry {
            container_path: raw_name,
            platform,
            format,
            bytes_len,
            blake3: hash,
            bytes: buf,
        });
    }
    Ok(RnExtractionReport {
        bundles,
        manifest_entries_scanned: entry_count,
    })
}

#[must_use]
pub fn classify_bundle_path(path: &str) -> Option<(RnBundlePlatform, RnBundleFormat)> {
    for name in ANDROID_BUNDLE_NAMES {
        if path == *name {
            return Some((RnBundlePlatform::Android, RnBundleFormat::Unknown));
        }
    }
    for name in IOS_BUNDLE_NAMES {
        if path == *name {
            return Some((RnBundlePlatform::Ios, RnBundleFormat::Unknown));
        }
    }
    if path.ends_with(".hbc") || path.ends_with(".hbcbundle") {
        return Some((RnBundlePlatform::Unknown, RnBundleFormat::HermesBytecode));
    }
    None
}

#[must_use]
pub fn detect_bundle_format(bytes: &[u8]) -> RnBundleFormat {
    if bytes.len() >= 8 {
        let head: [u8; 8] = [
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ];
        if head == crate::hermes::HERMES_MAGIC_LE_BYTES {
            return RnBundleFormat::HermesBytecode;
        }
    }
    if bytes
        .iter()
        .take(256)
        .all(|b: &u8| *b == b'\n' || *b == b'\r' || (*b >= 0x20 && *b < 0x7f))
    {
        return RnBundleFormat::JavaScriptSource;
    }
    RnBundleFormat::Unknown
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    fn build_apk_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, contents) in entries {
                zw.start_file::<&str, ()>(name, opts).expect("start file");
                zw.write_all(contents).expect("write entry");
            }
            zw.finish().expect("finish zip");
        }
        buf
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn zip_with_declared_empty_entry(name: &str, declared: u32) -> Vec<u8> {
        let name_bytes: &[u8] = name.as_bytes();
        let name_len: u16 = u16::try_from(name_bytes.len()).expect("name fits");
        let mut out: Vec<u8> = Vec::new();
        push_u32(&mut out, 0x0403_4b50);
        push_u16(&mut out, 20);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        push_u32(&mut out, declared);
        push_u16(&mut out, name_len);
        push_u16(&mut out, 0);
        out.extend_from_slice(name_bytes);
        let central_offset: u32 = u32::try_from(out.len()).expect("offset fits");
        push_u32(&mut out, 0x0201_4b50);
        push_u16(&mut out, 20);
        push_u16(&mut out, 20);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        push_u32(&mut out, declared);
        push_u16(&mut out, name_len);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        out.extend_from_slice(name_bytes);
        let central_size: u32 =
            u32::try_from(out.len() - central_offset as usize).expect("central size fits");
        push_u32(&mut out, 0x0605_4b50);
        push_u16(&mut out, 0);
        push_u16(&mut out, 0);
        push_u16(&mut out, 1);
        push_u16(&mut out, 1);
        push_u32(&mut out, central_size);
        push_u32(&mut out, central_offset);
        push_u16(&mut out, 0);
        out
    }

    #[test]
    fn classify_paths_known_android() {
        let kind: Option<(RnBundlePlatform, RnBundleFormat)> =
            classify_bundle_path("assets/index.android.bundle");
        assert_eq!(
            kind,
            Some((RnBundlePlatform::Android, RnBundleFormat::Unknown))
        );
    }

    #[test]
    fn classify_paths_known_ios() {
        let kind: Option<(RnBundlePlatform, RnBundleFormat)> =
            classify_bundle_path("Payload/main.jsbundle");
        assert_eq!(kind, Some((RnBundlePlatform::Ios, RnBundleFormat::Unknown)));
    }

    #[test]
    fn classify_paths_hbc_suffix() {
        let kind: Option<(RnBundlePlatform, RnBundleFormat)> = classify_bundle_path("x.hbc");
        assert_eq!(
            kind,
            Some((RnBundlePlatform::Unknown, RnBundleFormat::HermesBytecode))
        );
    }

    #[test]
    fn detect_js_text_bundle() {
        let kind: RnBundleFormat = detect_bundle_format(b"var foo = require('react');\n");
        assert_eq!(kind, RnBundleFormat::JavaScriptSource);
    }

    #[test]
    fn extract_locates_android_bundle_inside_apk() {
        let apk: Vec<u8> = build_apk_with(&[
            ("AndroidManifest.xml", b"<manifest/>"),
            ("assets/index.android.bundle", b"var x=1;\n"),
            ("classes.dex", b"dex\n035"),
        ]);
        let report: RnExtractionReport = extract_from_apk_or_ipa(&apk).expect("extract apk");
        assert_eq!(report.bundles.len(), 1);
        assert_eq!(report.bundles[0].platform, RnBundlePlatform::Android);
        assert_eq!(report.bundles[0].format, RnBundleFormat::JavaScriptSource);
        assert_eq!(report.manifest_entries_scanned, 3);
    }

    #[test]
    fn extract_rejects_forged_declared_bundle_size() {
        let declared: u32 = u32::try_from(crate::ZIP_ENTRY_READ_CAP)
            .expect("cap fits")
            .saturating_add(1);
        let apk: Vec<u8> = zip_with_declared_empty_entry("assets/index.android.bundle", declared);
        let err: crate::error::Error =
            extract_from_apk_or_ipa(&apk).expect_err("forged declared size must reject");
        let message: String = match err {
            crate::error::Error::Zip(message) => message,
            other => panic!("unexpected error {other}"),
        };
        assert!(message.contains("declared size"));
        assert!(message.contains("decompression cap"));
    }
}
