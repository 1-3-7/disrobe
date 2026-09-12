use std::io::{Cursor, Read};

use disrobe_pass_mobile::{
    ApkReconReport, AxmlAttribute, AxmlDocument, analyze_apk_recon, parse_axml,
};
use serde::Serialize;
use zip::ZipArchive;

const MAX_ENTRIES: usize = 4096;
const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 2 * 1024 * 1024;
const MAX_DECODED_BYTES: u64 = 128 * 1024 * 1024;
const MANIFEST: &str = "AndroidManifest.xml";

#[derive(Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum ResourceTableStatus {
    Missing,
    Decoded,
    Undecoded,
}

#[derive(Debug, Serialize)]
pub struct ApkResult {
    ok: bool,
    format: &'static str,
    entry_count: usize,
    decoded_bytes: u64,
    resource_xml_entries: usize,
    resource_table_status: ResourceTableStatus,
    report: ApkReconReport,
}

fn open(bytes: &[u8]) -> Result<ZipArchive<Cursor<&[u8]>>, String> {
    if bytes.len() > crate::MAX_INPUT_BYTES {
        return Err("APK exceeds the 64 MiB browser input limit; use the CLI".to_string());
    }
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(Cursor::new(bytes))
        .map_err(|error: zip::result::ZipError| format!("APK archive: {error}"))?;
    let eocd: &[u8] = bytes
        .len()
        .checked_sub(22 + archive.comment().len())
        .and_then(|offset: usize| bytes.get(offset..offset + 22))
        .filter(|end: &&[u8]| end.starts_with(b"PK\x05\x06") && end[4..8] == [0; 4])
        .ok_or_else(|| "APK requires a single ZIP archive with a complete directory".to_string())?;
    let count: usize = usize::from(u16::from_le_bytes([eocd[10], eocd[11]]));
    if count > MAX_ENTRIES {
        return Err("APK exceeds the 4096-entry browser limit; use the CLI".to_string());
    }
    if count != archive.len() || eocd[8..10] != eocd[10..12] {
        return Err("APK directory has duplicate entry names or inconsistent counts".to_string());
    }
    if !archive.file_names().any(|name: &str| name == MANIFEST) {
        return Err("APK requires a root AndroidManifest.xml entry".to_string());
    }
    let mut declared_bytes: u64 = 0;
    for index in 0..archive.len() {
        let file: zip::read::ZipFile<'_> =
            archive
                .by_index_raw(index)
                .map_err(|error: zip::result::ZipError| {
                    format!("APK directory entry {index}: {error}")
                })?;
        if file.size() > MAX_ENTRY_BYTES {
            return Err(format!(
                "APK entry {} exceeds the 32 MiB decoded limit; use the CLI",
                file.name()
            ));
        }
        declared_bytes = declared_bytes
            .checked_add(file.size())
            .filter(|total: &u64| *total <= MAX_DECODED_BYTES)
            .ok_or_else(|| {
                "APK exceeds the 128 MiB decoded archive limit; use the CLI".to_string()
            })?;
    }
    Ok(archive)
}

fn validate_manifest(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<(), String> {
    let file: zip::read::ZipFile<'_> = archive
        .by_name(MANIFEST)
        .map_err(|error: zip::result::ZipError| format!("APK manifest: {error}"))?;
    if file.size() > MAX_MANIFEST_BYTES {
        return Err("APK manifest exceeds the 2 MiB decoded limit; use the CLI".to_string());
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error: std::io::Error| format!("APK manifest: {error}"))?;
    if bytes.len() as u64 > MAX_MANIFEST_BYTES {
        return Err("APK manifest exceeds the 2 MiB decoded limit; use the CLI".to_string());
    }
    let document: AxmlDocument = parse_axml(&bytes)
        .map_err(|error: disrobe_pass_mobile::Error| format!("APK manifest: {error}"))?;
    if !is_manifest_document(&document) {
        return Err("APK manifest requires a manifest root and package identifier".to_string());
    }
    Ok(())
}

fn is_manifest_document(document: &AxmlDocument) -> bool {
    let mut packages: std::iter::Filter<_, _> = document
        .root
        .attributes
        .iter()
        .filter(|attribute: &&AxmlAttribute| attribute.name == "package");
    let Some(package) = packages.next() else {
        return false;
    };
    document.root.name == "manifest"
        && document.root.namespace.is_none()
        && package.namespace.is_none()
        && !package.value.trim().is_empty()
        && packages.next().is_none()
}

pub(super) fn recognizes(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
        && open(bytes)
            .and_then(|mut archive: ZipArchive<Cursor<&[u8]>>| validate_manifest(&mut archive))
            .is_ok()
}

pub fn analyze(bytes: &[u8]) -> Result<ApkResult, String> {
    let mut archive: ZipArchive<Cursor<&[u8]>> = open(bytes)?;
    validate_manifest(&mut archive)?;
    let has_resources: bool = archive
        .file_names()
        .any(|name: &str| name == "resources.arsc");
    let resource_xml_entries: usize = archive
        .file_names()
        .filter(|name: &&str| disrobe_pass_mobile::res_decode::is_binary_xml_res_path(name))
        .count();
    let mut decoded_bytes: u64 = 0;
    for index in 0..archive.len() {
        let file: zip::read::ZipFile<'_> = archive
            .by_index(index)
            .map_err(|error: zip::result::ZipError| format!("APK entry {index}: {error}"))?;
        let limit: u64 = MAX_ENTRY_BYTES.min(MAX_DECODED_BYTES - decoded_bytes);
        let size: u64 = std::io::copy(&mut file.take(limit + 1), &mut std::io::sink())
            .map_err(|error: std::io::Error| format!("APK entry {index}: {error}"))?;
        if size > limit {
            return Err(format!(
                "APK entry {index} exceeds the decoded byte budget; use the CLI"
            ));
        }
        decoded_bytes += size;
    }
    let report: ApkReconReport = analyze_apk_recon(bytes)
        .map_err(|error: disrobe_pass_mobile::Error| format!("APK analysis: {error}"))?;
    if !report.manifest_decoded || report.manifest.is_none() || report.manifest_xml.is_none() {
        return Err("APK manifest could not be decoded".to_string());
    }
    let resource_table_status: ResourceTableStatus =
        match (has_resources, report.resources.is_some()) {
            (_, true) => ResourceTableStatus::Decoded,
            (true, false) => ResourceTableStatus::Undecoded,
            (false, false) => ResourceTableStatus::Missing,
        };
    Ok(ApkResult {
        ok: true,
        format: "apk",
        entry_count: archive.len(),
        decoded_bytes,
        resource_xml_entries,
        resource_table_status,
        report,
    })
}

#[cfg(test)]
mod tests {
    use disrobe_pass_mobile::{AxmlAttribute, AxmlDocument, AxmlElement};

    #[test]
    fn manifest_package_is_unique_unqualified_and_nonblank() {
        for (value, namespace, duplicate, accepted) in [
            ("com.example.app", None, false, true),
            (
                "com.example.app",
                Some("http://schemas.android.com/apk/res/android"),
                false,
                false,
            ),
            (" \t ", None, false, false),
            ("com.example.app", None, true, false),
        ] {
            let attribute: AxmlAttribute = AxmlAttribute {
                name: "package".to_string(),
                namespace: namespace.map(str::to_string),
                prefix: None,
                value: value.to_string(),
                resource_id: None,
                attr_id: None,
                value_type: 3,
                raw_data: 0,
            };
            let attributes: Vec<AxmlAttribute> = if duplicate {
                vec![attribute.clone(), attribute]
            } else {
                vec![attribute]
            };
            let document: AxmlDocument = AxmlDocument {
                root: AxmlElement {
                    name: "manifest".to_string(),
                    namespace: None,
                    prefix: None,
                    attributes,
                    children: Vec::new(),
                    cdata: Vec::new(),
                },
                namespaces: Vec::new(),
            };
            assert_eq!(
                super::is_manifest_document(&document),
                accepted,
                "{value:?}, {namespace:?}, duplicate={duplicate}"
            );
        }
    }
}
