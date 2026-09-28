use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MsiSummary {
    pub tables: Vec<String>,
    pub streams: Vec<String>,
    pub author: Option<String>,
    pub title: Option<String>,
    pub subject: Option<String>,
}

const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
const MSI_INSTALLER_CLSID: [u8; 16] = [
    0x84, 0x10, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
];
const CFB_ROOT_CLSID_OFFSET: usize = 0x50;

pub fn detect_msi(bytes: &[u8]) -> bool {
    if !bytes.starts_with(&CFB_MAGIC) {
        return false;
    }
    let Some(sector_shift): Option<u16> = bytes
        .get(0x1E..0x20)
        .and_then(|s: &[u8]| s.first_chunk::<2>())
        .map(|b: &[u8; 2]| u16::from_le_bytes(*b))
    else {
        return false;
    };
    if sector_shift != 9 && sector_shift != 12 {
        return false;
    }
    let Some(first_dir): Option<u32> = bytes
        .get(0x30..0x34)
        .and_then(|s: &[u8]| s.first_chunk::<4>())
        .map(|b: &[u8; 4]| u32::from_le_bytes(*b))
    else {
        return false;
    };
    let sector_size: usize = 1usize << sector_shift;
    let Some(root): Option<usize> = usize::try_from(first_dir)
        .ok()
        .and_then(|sid: usize| sid.checked_add(1))
        .and_then(|n: usize| n.checked_mul(sector_size))
        .and_then(|offset: usize| offset.checked_add(CFB_ROOT_CLSID_OFFSET))
    else {
        return false;
    };
    bytes.get(root..root + MSI_INSTALLER_CLSID.len()) == Some(MSI_INSTALLER_CLSID.as_slice())
}

pub fn parse_msi_minimal(bytes: &[u8]) -> Result<MsiSummary> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let package: msi::Package<Cursor<&[u8]>> = msi::Package::open(cursor)
        .map_err(|e: std::io::Error| Error::Decompression(format!("msi open: {e}")))?;
    let tables: Vec<String> = package
        .tables()
        .map(|t: &msi::Table| t.name().to_owned())
        .collect();
    let streams: Vec<String> = package.streams().collect();
    let summary: &msi::SummaryInfo = package.summary_info();
    let author: Option<String> = summary.author().map(str::to_owned);
    let title: Option<String> = summary.title().map(str::to_owned);
    let subject: Option<String> = summary.subject().map(str::to_owned);
    Ok(MsiSummary {
        tables,
        streams,
        author,
        title,
        subject,
    })
}

const MAX_STREAM_BYTES: u64 = 4 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct MsiEmbeddedCab {
    pub stream_name: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
pub struct MsiExtractable {
    pub cabs: Vec<MsiEmbeddedCab>,
    pub long_names: std::collections::BTreeMap<String, String>,
    pub external_cabinets: Vec<String>,
    pub violations: Vec<String>,
}

pub fn read_msi_extractable(bytes: &[u8]) -> Result<MsiExtractable> {
    use std::io::Read as _;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut package: msi::Package<Cursor<&[u8]>> = msi::Package::open(cursor)
        .map_err(|e: std::io::Error| Error::Msi(format!("msi open: {e}")))?;

    let mut violations: Vec<String> = Vec::new();
    let long_names: std::collections::BTreeMap<String, String> =
        read_long_names(&mut package, &mut violations);
    let cabinet_refs: Vec<String> = read_media_cabinets(&mut package, &mut violations);

    let mut cabs: Vec<MsiEmbeddedCab> = Vec::new();
    let mut external_cabinets: Vec<String> = Vec::new();
    for cab_ref in cabinet_refs {
        if let Some(stream_name) = cab_ref.strip_prefix('#') {
            if !package.has_stream(stream_name) {
                external_cabinets.push(cab_ref.clone());
                continue;
            }
            let mut reader: msi::StreamReader<Cursor<&[u8]>> = package
                .read_stream(stream_name)
                .map_err(|e: std::io::Error| {
                    Error::Msi(format!("read stream {stream_name}: {e}"))
                })?;
            let mut buf: Vec<u8> = Vec::new();
            reader
                .by_ref()
                .take(MAX_STREAM_BYTES)
                .read_to_end(&mut buf)
                .map_err(|e: std::io::Error| {
                    Error::Msi(format!("drain stream {stream_name}: {e}"))
                })?;
            cabs.push(MsiEmbeddedCab {
                stream_name: stream_name.to_owned(),
                bytes: buf,
            });
        } else if !cab_ref.is_empty() {
            external_cabinets.push(cab_ref);
        }
    }

    Ok(MsiExtractable {
        cabs,
        long_names,
        external_cabinets,
        violations,
    })
}

fn missing_columns(
    package: &msi::Package<Cursor<&[u8]>>,
    table: &str,
    columns: &[&str],
    violations: &mut Vec<String>,
) -> bool {
    let Some(schema): Option<&msi::Table> = package.get_table(table) else {
        return true;
    };
    let missing: Vec<&str> = columns
        .iter()
        .copied()
        .filter(|column: &&str| !schema.has_column(column))
        .collect();
    if missing.is_empty() {
        return false;
    }
    violations.push(format!(
        "msi-missing-column: the {table} table lacks {}, so its rows are not read",
        missing.join(", ")
    ));
    true
}

fn column_str<'row>(row: &'row msi::Row, column: &str) -> Option<&'row str> {
    if row.has_column(column) {
        row[column].as_str()
    } else {
        None
    }
}

fn read_long_names(
    package: &mut msi::Package<Cursor<&[u8]>>,
    violations: &mut Vec<String>,
) -> std::collections::BTreeMap<String, String> {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    if !package.has_table("File")
        || missing_columns(package, "File", &["File", "FileName"], violations)
    {
        return map;
    }
    let Ok(rows): std::result::Result<msi::Rows<'_>, std::io::Error> =
        package.select_rows(msi::Select::table("File"))
    else {
        return map;
    };
    for row in rows {
        let key: Option<&str> = column_str(&row, "File");
        let filename: Option<&str> = column_str(&row, "FileName");
        if let (Some(key), Some(filename)) = (key, filename) {
            map.insert(key.to_owned(), long_component(filename).to_owned());
        }
    }
    map
}

fn long_component(filename: &str) -> &str {
    match filename.split_once('|') {
        Some((_short, long)) => long,
        None => filename,
    }
}

fn read_media_cabinets(
    package: &mut msi::Package<Cursor<&[u8]>>,
    violations: &mut Vec<String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !package.has_table("Media") || missing_columns(package, "Media", &["Cabinet"], violations) {
        return out;
    }
    let Ok(rows): std::result::Result<msi::Rows<'_>, std::io::Error> =
        package.select_rows(msi::Select::table("Media"))
    else {
        return out;
    };
    for row in rows {
        if let Some(cabinet) = column_str(&row, "Cabinet")
            && !cabinet.is_empty()
        {
            out.push(cabinet.to_owned());
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn package_with_file_table(columns: Vec<msi::Column>) -> Vec<u8> {
        let mut package: msi::Package<Cursor<Vec<u8>>> =
            msi::Package::create(msi::PackageType::Installer, Cursor::new(Vec::new()))
                .expect("create package");
        package
            .create_table("File", columns)
            .expect("create File table");
        package
            .insert_rows(msi::Insert::into("File").row(vec![msi::Value::from("f1")]))
            .expect("insert row");
        package.into_inner().expect("finish package").into_inner()
    }

    #[test]
    fn a_file_table_without_file_name_is_a_violation_not_a_panic() {
        let bytes: Vec<u8> =
            package_with_file_table(vec![msi::Column::build("File").primary_key().id_string(72)]);
        let extractable: MsiExtractable = read_msi_extractable(&bytes).expect("read package");
        assert!(extractable.long_names.is_empty());
        assert_eq!(
            extractable.violations,
            ["msi-missing-column: the File table lacks FileName, so its rows are not read"]
        );
    }

    #[test]
    fn an_installer_package_is_detected_and_other_compound_files_are_not() {
        let installer: Vec<u8> =
            package_with_file_table(vec![msi::Column::build("File").primary_key().id_string(72)]);
        assert!(detect_msi(&installer));
        assert_eq!(
            crate::container::detect_container(&installer),
            Some(crate::container::ContainerKind::Msi)
        );
        let mut patch: msi::Package<Cursor<Vec<u8>>> =
            msi::Package::create(msi::PackageType::Patch, Cursor::new(Vec::new()))
                .expect("create patch");
        patch.flush().expect("flush patch");
        let patch_bytes: Vec<u8> = patch.into_inner().expect("finish patch").into_inner();
        assert!(!detect_msi(&patch_bytes));
        assert!(!detect_msi(&installer[..0x200]));
        assert!(!detect_msi(&[0u8; 64]));
    }

    #[test]
    fn errors_on_non_msi_bytes() {
        let bytes: Vec<u8> = vec![0u8; 256];
        let err: Error = parse_msi_minimal(&bytes).unwrap_err();
        assert!(matches!(err, Error::Decompression(_)));
    }

    #[test]
    fn synthesizes_and_parses_empty_msi() {
        use std::io::Cursor as StdCursor;
        let buf: Vec<u8> = Vec::new();
        let cursor: StdCursor<Vec<u8>> = StdCursor::new(buf);
        let mut package: msi::Package<StdCursor<Vec<u8>>> =
            msi::Package::create(msi::PackageType::Installer, cursor).expect("create msi");
        package.flush().expect("flush");
        let inner: Vec<u8> = package.into_inner().expect("inner").into_inner();
        let summary: MsiSummary = parse_msi_minimal(&inner).expect("parse synth msi");
        assert!(!summary.tables.is_empty());
    }
}
