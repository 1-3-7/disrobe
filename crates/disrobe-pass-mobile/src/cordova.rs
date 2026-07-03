use std::io::Cursor;

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WebviewBundleKind {
    Cordova,
    Capacitor,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebviewAsset {
    pub container_path: String,
    pub bytes_len: u64,
    pub mime_hint: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebviewExtractionReport {
    pub kind: WebviewBundleKind,
    pub assets: Vec<WebviewAsset>,
    pub entry_html: Option<String>,
}

const CORDOVA_MARKERS: &[&str] = &["assets/www/cordova.js", "assets/www/cordova_plugins.js"];

const CAPACITOR_MARKERS: &[&str] = &[
    "assets/public/capacitor.config.json",
    "assets/capacitor.config.json",
    "App/App/public/capacitor.config.json",
];

pub fn extract_webview_bundle(bytes: &[u8]) -> Result<WebviewExtractionReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = crate::checked_zip_entry_count(archive.len())?;
    let mut all_names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let file: zip::read::ZipFile<'_> = archive.by_index(i)?;
        all_names.push(file.name().to_owned());
    }
    let kind: WebviewBundleKind = if all_names
        .iter()
        .any(|n: &String| CORDOVA_MARKERS.contains(&n.as_str()))
    {
        WebviewBundleKind::Cordova
    } else if all_names
        .iter()
        .any(|n: &String| CAPACITOR_MARKERS.contains(&n.as_str()))
    {
        WebviewBundleKind::Capacitor
    } else {
        WebviewBundleKind::Unknown
    };
    if matches!(kind, WebviewBundleKind::Unknown) {
        return Err(Error::WebviewAssetMissing(
            "cordova.js | capacitor.config.json",
        ));
    }
    let mut assets: Vec<WebviewAsset> = Vec::new();
    let mut entry_html: Option<String> = None;
    for i in 0..entry_count {
        let file: zip::read::ZipFile<'_> = archive.by_index(i)?;
        let name: String = file.name().to_owned();
        if !is_webview_asset(&name) {
            continue;
        }
        let buf: Vec<u8> = crate::read_zip_file_bounded(file, &name)?;
        let mime: &'static str = mime_hint_for(&name);
        if name.ends_with("/index.html") || name.ends_with("\\index.html") {
            entry_html = Some(name.clone());
        }
        assets.push(WebviewAsset {
            container_path: name,
            bytes_len: buf.len() as u64,
            mime_hint: mime.to_owned(),
            bytes: buf,
        });
    }
    Ok(WebviewExtractionReport {
        kind,
        assets,
        entry_html,
    })
}

#[must_use]
pub fn is_webview_asset(path: &str) -> bool {
    let lower_ok: bool = path.starts_with("assets/www/")
        || path.starts_with("assets/public/")
        || path.starts_with("App/App/public/");
    let ext_ok: bool = path.ends_with(".html")
        || path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".json")
        || path.ends_with(".map")
        || path.ends_with(".svg")
        || path.ends_with(".wasm");
    lower_ok && ext_ok
}

#[must_use]
pub fn mime_hint_for(path: &str) -> &'static str {
    if path.ends_with(".html") {
        "text/html"
    } else if path.ends_with(".js") {
        "application/javascript"
    } else if path.ends_with(".css") {
        "text/css"
    } else if path.ends_with(".json") || path.ends_with(".map") {
        "application/json"
    } else if path.ends_with(".svg") {
        "image/svg+xml"
    } else if path.ends_with(".wasm") {
        "application/wasm"
    } else {
        "application/octet-stream"
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    pub(crate) fn synth_cordova_bundle() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, contents) in [
                ("AndroidManifest.xml", &b"<manifest/>"[..]),
                ("assets/www/index.html", &b"<html></html>"[..]),
                ("assets/www/cordova.js", &b"// cordova bridge"[..]),
                ("assets/www/cordova_plugins.js", &b"// plugins"[..]),
                ("assets/www/js/app.js", &b"console.log(1);"[..]),
            ] {
                zw.start_file::<&str, ()>(name, opts).expect("start file");
                zw.write_all(contents).expect("write");
            }
            zw.finish().expect("finish");
        }
        buf
    }

    pub(crate) fn synth_capacitor_bundle() -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (name, contents) in [
                ("assets/public/index.html", &b"<html></html>"[..]),
                (
                    "assets/public/capacitor.config.json",
                    &b"{\"appId\":\"x\"}"[..],
                ),
            ] {
                zw.start_file::<&str, ()>(name, opts).expect("start");
                zw.write_all(contents).expect("write");
            }
            zw.finish().expect("finish");
        }
        buf
    }

    #[test]
    fn detect_cordova_bundle() {
        let apk: Vec<u8> = synth_cordova_bundle();
        let report: WebviewExtractionReport = extract_webview_bundle(&apk).expect("extract");
        assert_eq!(report.kind, WebviewBundleKind::Cordova);
        assert!(report.entry_html.is_some());
        assert!(
            report
                .assets
                .iter()
                .any(|a: &WebviewAsset| a.container_path.ends_with("/app.js"))
        );
    }

    #[test]
    fn detect_capacitor_bundle() {
        let apk: Vec<u8> = synth_capacitor_bundle();
        let report: WebviewExtractionReport = extract_webview_bundle(&apk).expect("extract");
        assert_eq!(report.kind, WebviewBundleKind::Capacitor);
    }

    #[test]
    fn unknown_bundle_rejected() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions = SimpleFileOptions::default();
            zw.start_file::<&str, ()>("AndroidManifest.xml", opts)
                .unwrap();
            zw.write_all(b"<manifest/>").unwrap();
            zw.finish().unwrap();
        }
        let err: Error = extract_webview_bundle(&buf).expect_err("must fail");
        assert!(matches!(err, Error::WebviewAssetMissing(_)));
    }

    #[test]
    fn mime_hint_known_extensions() {
        assert_eq!(mime_hint_for("a/b.js"), "application/javascript");
        assert_eq!(mime_hint_for("a/b.wasm"), "application/wasm");
        assert_eq!(mime_hint_for("a/b.unknown"), "application/octet-stream");
    }
}
