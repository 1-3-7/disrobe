#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::{Cursor, Write as _};

use disrobe_binfmt::containers::msi::{MsiSummary, parse_msi_minimal};
use disrobe_binfmt::containers::msix::{MsixManifest, parse_appx_manifest};

fn synth_appx_archive(manifest: &str) -> Vec<u8> {
    let buf: Vec<u8> = Vec::new();
    let mut zw: zip::ZipWriter<Cursor<Vec<u8>>> = zip::ZipWriter::new(Cursor::new(buf));
    let opts: zip::write::FileOptions<()> = zip::write::FileOptions::default();
    zw.start_file("AppxManifest.xml", opts).expect("start");
    zw.write_all(manifest.as_bytes()).expect("write");
    zw.finish().expect("finish").into_inner()
}

#[test]
fn msix_manifest_round_trip_basic_identity() {
    let xml: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<Package>
  <Identity Name="Vendor.App" Publisher="CN=Vendor" Version="2.5.6.0"/>
  <Properties><DisplayName>Vendor Application</DisplayName></Properties>
</Package>"#;
    let bytes: Vec<u8> = synth_appx_archive(xml);
    let manifest: MsixManifest = parse_appx_manifest(&bytes).expect("parse appx");
    assert_eq!(manifest.package_name.as_deref(), Some("Vendor.App"));
    assert_eq!(manifest.version.as_deref(), Some("2.5.6.0"));
    assert_eq!(manifest.display_name.as_deref(), Some("Vendor Application"));
}

#[test]
fn msi_summary_reports_the_tables_streams_and_metadata_the_writer_put_in() {
    let buf: Vec<u8> = Vec::new();
    let cursor: Cursor<Vec<u8>> = Cursor::new(buf);
    let mut package: msi::Package<Cursor<Vec<u8>>> =
        msi::Package::create(msi::PackageType::Installer, cursor).expect("create msi");
    {
        let info: &mut msi::SummaryInfo = package.summary_info_mut();
        info.set_author("Vendor Packaging".to_owned());
        info.set_title("Installation Database".to_owned());
        info.set_subject("Vendor Application 2.5.6".to_owned());
    }
    package
        .create_table(
            "Media",
            vec![
                msi::Column::build("DiskId").primary_key().int16(),
                msi::Column::build("LastSequence").int16(),
                msi::Column::build("Cabinet").nullable().string(255),
            ],
        )
        .expect("media table");
    package
        .insert_rows(msi::Insert::into("Media").row(vec![
            msi::Value::Int(1),
            msi::Value::Int(4),
            msi::Value::Str("#product.cab".to_owned()),
        ]))
        .expect("media row");
    {
        let mut writer: msi::StreamWriter<Cursor<Vec<u8>>> =
            package.write_stream("product.cab").expect("stream writer");
        writer
            .write_all(b"MSCF placeholder cabinet")
            .expect("write stream");
    }
    package.flush().expect("flush");
    let inner: Vec<u8> = package.into_inner().expect("inner").into_inner();

    let summary: MsiSummary = parse_msi_minimal(&inner).expect("parse synth msi");
    assert!(
        summary.tables.iter().any(|name: &String| name == "Media"),
        "the table the writer created must be named back: {:?}",
        summary.tables
    );
    assert_eq!(
        summary.streams,
        vec!["product.cab".to_owned()],
        "the one stream the writer added must be the one stream reported"
    );
    assert_eq!(summary.author.as_deref(), Some("Vendor Packaging"));
    assert_eq!(summary.title.as_deref(), Some("Installation Database"));
    assert_eq!(summary.subject.as_deref(), Some("Vendor Application 2.5.6"));
}
