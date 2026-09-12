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
}

pub fn read_msi_extractable(bytes: &[u8]) -> Result<MsiExtractable> {
    use std::io::Read as _;

    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut package: msi::Package<Cursor<&[u8]>> = msi::Package::open(cursor)
        .map_err(|e: std::io::Error| Error::Msi(format!("msi open: {e}")))?;

    let long_names: std::collections::BTreeMap<String, String> = read_long_names(&mut package);
    let cabinet_refs: Vec<String> = read_media_cabinets(&mut package);

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
    })
}

fn read_long_names(
    package: &mut msi::Package<Cursor<&[u8]>>,
) -> std::collections::BTreeMap<String, String> {
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    if !package.has_table("File") {
        return map;
    }
    let Ok(rows): std::result::Result<msi::Rows<'_>, std::io::Error> =
        package.select_rows(msi::Select::table("File"))
    else {
        return map;
    };
    for row in rows {
        let key: Option<&str> = row["File"].as_str();
        let filename: Option<&str> = row["FileName"].as_str();
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

fn read_media_cabinets(package: &mut msi::Package<Cursor<&[u8]>>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if !package.has_table("Media") {
        return out;
    }
    let Ok(rows): std::result::Result<msi::Rows<'_>, std::io::Error> =
        package.select_rows(msi::Select::table("Media"))
    else {
        return out;
    };
    for row in rows {
        if let Some(cabinet) = row["Cabinet"].as_str()
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
