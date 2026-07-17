use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaEntry {
    pub name: String,
    pub size: u64,
    pub is_executable_candidate: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaInventory {
    pub app_dir: String,
    pub bundle_name: String,
    pub entries: Vec<IpaEntry>,
    pub info_plist_path: Option<String>,
    pub main_binary_path: Option<String>,
    pub embedded_provision_path: Option<String>,
    pub frameworks: Vec<String>,
    pub plugins: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpaExtract {
    pub inventory: IpaInventory,
    pub info_plist: Option<Vec<u8>>,
    pub main_binary: Option<Vec<u8>>,
    pub embedded_provision: Option<Vec<u8>>,
}

const PAYLOAD_PREFIX: &str = "Payload/";
const APP_SUFFIX: &str = ".app/";
const MAX_PREALLOC: u64 = 64 * 1024 * 1024;
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
pub(crate) const MAX_ZIP_ENTRY_COUNT: usize = 65_536;

#[inline]
fn entry_prealloc(uncompressed: u64, compressed: u64) -> usize {
    let bound: u64 = uncompressed
        .min(compressed.saturating_mul(2))
        .min(MAX_PREALLOC);
    usize::try_from(bound).unwrap_or(0)
}

pub(crate) fn checked_zip_entry_count(count: usize) -> Result<usize> {
    if count > MAX_ZIP_ENTRY_COUNT {
        return Err(Error::Ipa(format!(
            "zip archive declares {count} entries, exceeding the {MAX_ZIP_ENTRY_COUNT} entry cap"
        )));
    }
    Ok(count)
}

pub fn inventory(image: &[u8]) -> Result<IpaInventory> {
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(Cursor::new(image))
        .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
    let entry_count: usize = checked_zip_entry_count(archive.len())?;
    let mut entries: Vec<IpaEntry> = Vec::with_capacity(entry_count);
    let mut app_dir: Option<String> = None;
    for i in 0..entry_count {
        let entry: zip::read::ZipFile<'_> = archive
            .by_index(i)
            .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
        let name: String = entry.name().to_owned();
        let size: u64 = entry.size();
        let is_exec: bool = is_macho_candidate(&name);
        if app_dir.is_none()
            && let Some(idx) = name.find(APP_SUFFIX)
            && name.starts_with(PAYLOAD_PREFIX)
        {
            app_dir = Some(name[..idx + APP_SUFFIX.len() - 1].to_owned());
        }
        entries.push(IpaEntry {
            name,
            size,
            is_executable_candidate: is_exec,
        });
    }

    let app_dir_value: String = app_dir.ok_or(Error::NotAnIpa)?;
    let bundle_name: String = derive_bundle_name(&app_dir_value);
    let info_plist_path: Option<String> = entries
        .iter()
        .map(|e: &IpaEntry| e.name.clone())
        .find(|n: &String| n == &format!("{app_dir_value}/Info.plist"));
    let declared_executable: Option<String> = info_plist_path
        .as_deref()
        .and_then(|p: &str| read_named(&mut archive, p).ok().flatten())
        .and_then(|raw: Vec<u8>| crate::plist_decode::parse_info_plist(&raw).ok())
        .and_then(|summary: crate::plist_decode::InfoPlistSummary| summary.bundle_executable)
        .filter(|exe: &String| !exe.is_empty());
    let main_binary_entry: String = declared_executable.as_deref().map_or_else(
        || format!("{app_dir_value}/{bundle_name}"),
        |exe: &str| format!("{app_dir_value}/{exe}"),
    );
    let main_binary_path: Option<String> = entries
        .iter()
        .map(|e: &IpaEntry| e.name.clone())
        .find(|n: &String| n == &main_binary_entry);
    let embedded_provision_path: Option<String> = entries
        .iter()
        .map(|e: &IpaEntry| e.name.clone())
        .find(|n: &String| n == &format!("{app_dir_value}/embedded.mobileprovision"));

    let frameworks_prefix: String = format!("{app_dir_value}/Frameworks/");
    let plugins_prefix: String = format!("{app_dir_value}/PlugIns/");
    let frameworks: Vec<String> = entries
        .iter()
        .filter(|e: &&IpaEntry| e.name.starts_with(&frameworks_prefix))
        .map(|e: &IpaEntry| e.name.clone())
        .collect();
    let plugins: Vec<String> = entries
        .iter()
        .filter(|e: &&IpaEntry| e.name.starts_with(&plugins_prefix))
        .map(|e: &IpaEntry| e.name.clone())
        .collect();

    Ok(IpaInventory {
        app_dir: app_dir_value,
        bundle_name,
        entries,
        info_plist_path,
        main_binary_path,
        embedded_provision_path,
        frameworks,
        plugins,
    })
}

pub fn extract(image: &[u8]) -> Result<IpaExtract> {
    let inv: IpaInventory = inventory(image)?;
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(Cursor::new(image))
        .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
    let info_plist: Option<Vec<u8>> = inv
        .info_plist_path
        .as_deref()
        .and_then(|p: &str| read_named(&mut archive, p).transpose())
        .transpose()?;
    let main_binary: Option<Vec<u8>> = inv
        .main_binary_path
        .as_deref()
        .and_then(|p: &str| read_named(&mut archive, p).transpose())
        .transpose()?;
    let embedded_provision: Option<Vec<u8>> = inv
        .embedded_provision_path
        .as_deref()
        .and_then(|p: &str| read_named(&mut archive, p).transpose())
        .transpose()?;
    Ok(IpaExtract {
        inventory: inv,
        info_plist,
        main_binary,
        embedded_provision,
    })
}

fn read_named(archive: &mut ZipArchive<Cursor<&[u8]>>, name: &str) -> Result<Option<Vec<u8>>> {
    match archive.by_name(name) {
        Ok(f) => {
            let uncompressed: u64 = f.size();
            let compressed: u64 = f.compressed_size();
            Ok(Some(read_zip_entry_limited(
                f,
                name,
                uncompressed,
                compressed,
                MAX_ENTRY_BYTES,
            )?))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(Error::Ipa(e.to_string())),
    }
}

pub(crate) fn read_zip_entry_limited<R: Read>(
    reader: R,
    name: &str,
    uncompressed: u64,
    compressed: u64,
    limit: u64,
) -> Result<Vec<u8>> {
    if uncompressed > limit {
        return Err(Error::Ipa(format!(
            "zip entry {name} declared size {uncompressed} exceeds {limit}-byte cap"
        )));
    }
    let limit_usize: usize = usize::try_from(limit)
        .map_err(|_| Error::Ipa(format!("zip entry {name} read cap is not addressable")))?;
    let cap: usize = entry_prealloc(uncompressed, compressed).min(limit_usize);
    let read_limit: u64 = limit
        .checked_add(1)
        .ok_or_else(|| Error::Ipa(format!("zip entry {name} read cap overflow")))?;
    let mut buf: Vec<u8> = Vec::with_capacity(cap);
    reader.take(read_limit).read_to_end(&mut buf)?;
    let len: u64 = u64::try_from(buf.len())
        .map_err(|_| Error::Ipa(format!("zip entry {name} read size is not addressable")))?;
    if len > limit {
        return Err(Error::Ipa(format!(
            "zip entry {name} exceeds {limit}-byte cap"
        )));
    }
    Ok(buf)
}

fn derive_bundle_name(app_dir: &str) -> String {
    let after_payload: &str = app_dir.strip_prefix(PAYLOAD_PREFIX).unwrap_or(app_dir);
    after_payload
        .strip_suffix(".app")
        .unwrap_or(after_payload)
        .to_owned()
}

const SKIP_EXTS: &[&str] = &[
    ".plist",
    ".strings",
    ".png",
    ".jpg",
    ".jpeg",
    ".car",
    ".nib",
    ".storyboardc",
    ".mobileprovision",
    ".pem",
    ".cer",
];

fn is_macho_candidate(name: &str) -> bool {
    if name.ends_with('/') {
        return false;
    }
    let Some(dot): Option<usize> = name.rfind('.') else {
        return true;
    };
    let ext: &str = &name[dot..];
    !SKIP_EXTS.iter().any(|s: &&str| ext.eq_ignore_ascii_case(s))
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn derive_bundle_strips_payload_and_suffix() {
        assert_eq!(derive_bundle_name("Payload/Hello.app"), "Hello");
        assert_eq!(derive_bundle_name("Payload/MyApp.app"), "MyApp");
    }

    #[test]
    fn entry_prealloc_caps_attacker_declared_size() {
        assert_eq!(entry_prealloc(u64::MAX, u64::MAX), MAX_PREALLOC as usize);
        assert_eq!(entry_prealloc(32, u64::MAX), 32);
        assert_eq!(entry_prealloc(u64::MAX, 16), 32);
    }

    #[test]
    fn checked_entry_count_rejects_large_count() {
        let count: usize = MAX_ZIP_ENTRY_COUNT + 1;
        let err: Error = checked_zip_entry_count(count).expect_err("entry count must reject");
        assert!(matches!(err, Error::Ipa(msg) if msg.contains("entry cap")));
    }

    #[test]
    fn read_zip_entry_limited_rejects_declared_size_past_limit() {
        let err: Error = read_zip_entry_limited(
            Cursor::new(Vec::<u8>::new()),
            "Payload/Example.app/Example",
            MAX_ENTRY_BYTES + 1,
            0,
            MAX_ENTRY_BYTES,
        )
        .expect_err("declared size must reject");
        assert!(matches!(err, Error::Ipa(msg) if msg.contains("declared size")));
    }

    #[test]
    fn read_zip_entry_limited_rejects_output_past_limit() {
        let data: Vec<u8> = vec![0x41; 16];
        let err: Error = read_zip_entry_limited(
            Cursor::new(data),
            "Payload/Example.app/Example",
            u64::MAX,
            1,
            8,
        )
        .expect_err("entry must exceed test cap");
        assert!(matches!(err, Error::Ipa(msg) if msg.contains("exceeds 8-byte cap")));
    }
}
