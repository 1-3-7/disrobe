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
