use std::io::{Cursor, Read};

use serde::{Deserialize, Serialize};
use zip::ZipArchive;

use crate::error::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeScriptBundle {
    pub container_path: String,
    pub bytes_len: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeScriptReport {
    pub bundles: Vec<NativeScriptBundle>,
    pub has_runtime_marker: bool,
}

const REQUIRED_PATHS: &[&str] = &[
    "assets/app/bundle.js",
    "assets/app/runtime.js",
    "assets/app/vendor.js",
    "assets/app/starter.js",
    "App/App/app/bundle.js",
];

const RUNTIME_MARKERS: &[&str] = &[
    "assets/app/internal/ts_helpers.js",
    "assets/app/package.json",
];

pub fn extract_nativescript_bundle(bytes: &[u8]) -> Result<NativeScriptReport> {
    let cursor: Cursor<&[u8]> = Cursor::new(bytes);
    let mut archive: ZipArchive<Cursor<&[u8]>> = ZipArchive::new(cursor)?;
    let entry_count: usize = archive.len();
    let mut names: Vec<String> = Vec::with_capacity(entry_count);
    for i in 0..entry_count {
        let f: zip::read::ZipFile<'_> = archive.by_index(i)?;
        names.push(f.name().to_owned());
    }
    let any_required: bool = names
        .iter()
        .any(|n: &String| REQUIRED_PATHS.contains(&n.as_str()));
    if !any_required {
        return Err(Error::NativeScriptBundleMissing);
    }
    let has_runtime_marker: bool = names
        .iter()
        .any(|n: &String| RUNTIME_MARKERS.contains(&n.as_str()));
    let mut bundles: Vec<NativeScriptBundle> = Vec::new();
    for i in 0..entry_count {
        let mut f: zip::read::ZipFile<'_> = archive.by_index(i)?;
        let name: String = f.name().to_owned();
        if !(REQUIRED_PATHS.contains(&name.as_str())
            || name.starts_with("assets/app/")
            || name.starts_with("App/App/app/"))
        {
            continue;
        }
        if !name.ends_with(".js") && !name.ends_with(".json") {
            continue;
        }
        let mut buf: Vec<u8> = Vec::with_capacity(f.size() as usize);
        f.read_to_end(&mut buf)?;
        let bytes_len: u64 = buf.len() as u64;
        bundles.push(NativeScriptBundle {
            container_path: name,
            bytes_len,
            bytes: buf,
        });
    }
    Ok(NativeScriptReport {
        bundles,
        has_runtime_marker,
    })
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    #[test]
    fn detect_nativescript_bundle() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let cursor: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
            let mut zw: ZipWriter<Cursor<&mut Vec<u8>>> = ZipWriter::new(cursor);
            let opts: SimpleFileOptions =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (n, c) in [
                ("AndroidManifest.xml", &b"<manifest/>"[..]),
                ("assets/app/bundle.js", &b"// bundle"[..]),
                ("assets/app/runtime.js", &b"// runtime"[..]),
                ("assets/app/internal/ts_helpers.js", &b"// helpers"[..]),
            ] {
                zw.start_file::<&str, ()>(n, opts).expect("start");
                zw.write_all(c).expect("write");
            }
            zw.finish().expect("finish");
        }
        let report: NativeScriptReport = extract_nativescript_bundle(&buf).expect("extract");
        assert!(report.has_runtime_marker);
        assert!(
            report
                .bundles
                .iter()
                .any(|b: &NativeScriptBundle| b.container_path == "assets/app/bundle.js")
        );
    }

    #[test]
    fn rejects_non_ns_bundle() {
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
        let err: Error = extract_nativescript_bundle(&buf).expect_err("must fail");
        assert!(matches!(err, Error::NativeScriptBundleMissing));
    }
}
