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

#[inline]
fn entry_prealloc(uncompressed: u64, compressed: u64) -> usize {
    let bound: u64 = uncompressed
        .min(compressed.saturating_mul(2))
        .min(MAX_PREALLOC);
    usize::try_from(bound).unwrap_or(0)
}

pub fn inventory(image: &[u8]) -> Result<IpaInventory> {
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(Cursor::new(image))
        .map_err(|e: zip::result::ZipError| Error::Ipa(e.to_string()))?;
    let mut entries: Vec<IpaEntry> = Vec::with_capacity(archive.len());
    let mut app_dir: Option<String> = None;
    for i in 0..archive.len() {
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
    let main_binary_path: Option<String> = entries
        .iter()
        .map(|e: &IpaEntry| e.name.clone())
        .find(|n: &String| n == &format!("{app_dir_value}/{bundle_name}"));
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
        Ok(mut f) => {
            let cap: usize = entry_prealloc(f.size(), f.compressed_size());
            let mut buf: Vec<u8> = Vec::with_capacity(cap);
            f.read_to_end(&mut buf)?;
            Ok(Some(buf))
        }
        Err(zip::result::ZipError::FileNotFound) => Ok(None),
        Err(e) => Err(Error::Ipa(e.to_string())),
    }
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
}
