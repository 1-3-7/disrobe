use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const APPX_MANIFEST_PATH: &str = "AppxManifest.xml";
const APPX_MANIFEST_READ_CAP: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsixManifest {
    pub package_name: Option<String>,
    pub publisher: Option<String>,
    pub version: Option<String>,
    pub display_name: Option<String>,
    pub raw_xml: String,
}

pub fn parse_appx_manifest(zip_bytes: &[u8]) -> Result<MsixManifest> {
    let cursor: Cursor<&[u8]> = Cursor::new(zip_bytes);
    let mut archive: zip::ZipArchive<Cursor<&[u8]>> =
        zip::ZipArchive::new(cursor).map_err(|e| Error::Zip(e.to_string()))?;
    let mut manifest_xml: Option<String> = None;
    for i in 0..archive.len() {
        let mut entry: zip::read::ZipFile<'_> =
            archive.by_index(i).map_err(|e| Error::Zip(e.to_string()))?;
        if entry.name().eq_ignore_ascii_case(APPX_MANIFEST_PATH) {
            let declared: u64 = entry.size();
            if declared > APPX_MANIFEST_READ_CAP {
                return Err(Error::ZipEntry {
                    name: APPX_MANIFEST_PATH.to_owned(),
                    reason: format!(
                        "declared size {declared} exceeds {APPX_MANIFEST_READ_CAP}-byte cap"
                    ),
                });
            }
            let buf: Vec<u8> = crate::quota::read_entry_to_limit(
                &mut entry,
                APPX_MANIFEST_PATH,
                APPX_MANIFEST_READ_CAP,
            )
            .map_err(|e: Error| Error::ZipEntry {
                name: APPX_MANIFEST_PATH.to_owned(),
                reason: e.to_string(),
            })?;
            manifest_xml = Some(String::from_utf8_lossy(&buf).into_owned());
            break;
        }
    }
    let xml: String = manifest_xml.ok_or_else(|| {
        Error::Zip(format!(
            "msix/appx archive missing required entry `{APPX_MANIFEST_PATH}`"
        ))
    })?;
    let package_name: Option<String> = extract_attr(&xml, "Identity", "Name");
    let publisher: Option<String> = extract_attr(&xml, "Identity", "Publisher");
    let version: Option<String> = extract_attr(&xml, "Identity", "Version");
    let display_name: Option<String> = extract_text(&xml, "DisplayName");
    Ok(MsixManifest {
        package_name,
        publisher,
        version,
        display_name,
        raw_xml: xml,
    })
}

fn extract_attr(xml: &str, element: &str, attribute: &str) -> Option<String> {
    let needle: String = format!("<{element}");
    let start: usize = xml.find(&needle)?;
    let close: usize = xml[start..].find('>').map(|i: usize| start + i)?;
    let slice: &str = &xml[start..close];
    let attr_needle: String = format!("{attribute}=\"");
    let attr_start: usize = slice.find(&attr_needle)? + attr_needle.len();
    let rel_end: usize = slice[attr_start..].find('"')?;
    Some(slice[attr_start..attr_start + rel_end].to_owned())
}

fn extract_text(xml: &str, element: &str) -> Option<String> {
    let open: String = format!("<{element}");
    let close: String = format!("</{element}>");
    let start_tag: usize = xml.find(&open)?;
    let body_start: usize = xml[start_tag..]
        .find('>')
        .map(|i: usize| start_tag + i + 1)?;
    let body_end: usize = xml[body_start..]
        .find(&close)
        .map(|i: usize| body_start + i)?;
    Some(xml[body_start..body_end].trim().to_owned())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Write as _;

    use super::*;

    fn synth_appx(manifest: &str) -> Vec<u8> {
        let buf: Vec<u8> = Vec::new();
        let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(Cursor::new(buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zw.start_file(APPX_MANIFEST_PATH, opts).expect("start");
        zw.write_all(manifest.as_bytes()).expect("write");
        zw.finish().expect("finish").into_inner()
    }

    #[test]
    fn parses_minimal_appx_manifest() {
        let xml: &str = r#"<?xml version="1.0"?>
<Package>
  <Identity Name="Contoso.App" Publisher="CN=Contoso" Version="1.2.3.4"/>
  <Properties>
    <DisplayName>Contoso App</DisplayName>
  </Properties>
</Package>"#;
        let bytes: Vec<u8> = synth_appx(xml);
        let manifest: MsixManifest = parse_appx_manifest(&bytes).expect("parse appx");
        assert_eq!(manifest.package_name.as_deref(), Some("Contoso.App"));
        assert_eq!(manifest.publisher.as_deref(), Some("CN=Contoso"));
        assert_eq!(manifest.version.as_deref(), Some("1.2.3.4"));
        assert_eq!(manifest.display_name.as_deref(), Some("Contoso App"));
    }

    #[test]
    fn errors_when_manifest_missing() {
        let buf: Vec<u8> = Vec::new();
        let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(Cursor::new(buf));
        let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zw.start_file("other.txt", opts).expect("start");
        zw.write_all(b"x").expect("write");
        let bytes: Vec<u8> = zw.finish().expect("fin").into_inner();
        let err: Error = parse_appx_manifest(&bytes).unwrap_err();
        assert!(matches!(err, Error::Zip(_)));
    }

    #[test]
    fn rejects_manifest_over_read_cap() {
        let cap: usize = usize::try_from(APPX_MANIFEST_READ_CAP).expect("cap fits");
        let body: String = "A".repeat(cap + 1);
        let xml: String = format!(
            "<Package><Properties><DisplayName>{body}</DisplayName></Properties></Package>"
        );
        let bytes: Vec<u8> = synth_appx(&xml);
        let err: Error = parse_appx_manifest(&bytes).unwrap_err();
        assert!(
            matches!(err, Error::ZipEntry { name, reason } if name == APPX_MANIFEST_PATH && reason.contains("cap"))
        );
    }
}
