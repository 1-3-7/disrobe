#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::io::{Cursor, Write};

use disrobe_pass_mobile::{
    WebviewAsset, WebviewBundleKind, WebviewExtractionReport, extract_webview_bundle,
};
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    {
        let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
        let opts: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for (name, contents) in entries {
            zw.start_file::<&str, ()>(name, opts).expect("start file");
            zw.write_all(contents).expect("write");
        }
        zw.finish().expect("finish");
    }
    buf
}

#[test]
fn cordova_stub_bundle_extracts() {
    let apk: Vec<u8> = build_zip(&[
        ("AndroidManifest.xml", b"<manifest/>"),
        ("assets/www/index.html", b"<html><body></body></html>"),
        ("assets/www/cordova.js", b"// cordova bridge"),
        ("assets/www/cordova_plugins.js", b"module.exports = [];"),
        ("assets/www/js/app.js", b"console.log('hello cordova');"),
        ("assets/www/css/style.css", b"body{margin:0}"),
    ]);
    let report: WebviewExtractionReport = extract_webview_bundle(&apk).expect("extract");
    assert_eq!(report.kind, WebviewBundleKind::Cordova);
    assert_eq!(report.entry_html.as_deref(), Some("assets/www/index.html"));
    let app_js: &WebviewAsset = report
        .assets
        .iter()
        .find(|a: &&WebviewAsset| a.container_path == "assets/www/js/app.js")
        .expect("app.js asset");
    assert_eq!(app_js.mime_hint.as_str(), "application/javascript");
    assert_eq!(app_js.bytes, b"console.log('hello cordova');");
}

#[test]
fn capacitor_stub_bundle_extracts() {
    let apk: Vec<u8> = build_zip(&[
        ("AndroidManifest.xml", b"<manifest/>"),
        ("assets/public/index.html", b"<html></html>"),
        (
            "assets/public/capacitor.config.json",
            b"{\"appId\":\"com.x\"}",
        ),
        ("assets/public/main.js", b"console.log('cap');"),
    ]);
    let report: WebviewExtractionReport = extract_webview_bundle(&apk).expect("extract");
    assert_eq!(report.kind, WebviewBundleKind::Capacitor);
    assert!(
        report
            .assets
            .iter()
            .any(|a: &WebviewAsset| a.container_path == "assets/public/main.js")
    );
}
