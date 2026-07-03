use std::path::{Path, PathBuf};

use crate::cxfreeze::library_zip::{self, ExtractedEntry};
use crate::error::Result;
use crate::{MAX_LIBRARY_ZIP_BYTES, read_file_bounded};

#[derive(Debug, Clone)]
pub struct BundledModules {
    pub library_zip_path: Option<PathBuf>,
    pub overlay_member_count: usize,
    pub entries: Vec<ExtractedEntry>,
}

pub fn extract_bundled_modules(
    binary_path: &Path,
    overlay_zip: Option<&[u8]>,
    out_dir: &Path,
) -> Result<BundledModules> {
    let mut entries: Vec<ExtractedEntry> = Vec::new();
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut library_zip_path: Option<PathBuf> = None;
    let mut overlay_member_count: usize = 0;

    if let Some(zip_bytes) = overlay_zip {
        let overlay_out: PathBuf = out_dir.join("overlay");
        let overlay_entries: Vec<ExtractedEntry> =
            library_zip::extract_all(zip_bytes, &overlay_out)?;
        overlay_member_count = overlay_entries.len();
        for ent in overlay_entries {
            if seen.insert(ent.name.clone()) {
                entries.push(ent);
            }
        }
    }

    if let Some(zip_path) = locate_sibling_library_zip(binary_path) {
        let zip_bytes: Vec<u8> = read_file_bounded(&zip_path, MAX_LIBRARY_ZIP_BYTES)?;
        let sibling_out: PathBuf = out_dir.join("library");
        let sibling_entries: Vec<ExtractedEntry> =
            library_zip::extract_all(&zip_bytes, &sibling_out)?;
        for ent in sibling_entries {
            if seen.insert(ent.name.clone()) {
                entries.push(ent);
            }
        }
        library_zip_path = Some(zip_path);
    }

    Ok(BundledModules {
        library_zip_path,
        overlay_member_count,
        entries,
    })
}

fn locate_sibling_library_zip(binary_path: &Path) -> Option<PathBuf> {
    let dir: &Path = binary_path.parent()?;
    [dir.join("library.zip"), dir.join("lib").join("library.zip")]
        .into_iter()
        .find(|p: &PathBuf| p.is_file())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use super::*;

    fn tempdir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0x9E2E_0000);
        let p: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-py2exe-lib-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&p).expect("mkdir");
        p
    }

    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use zip::write::SimpleFileOptions;
        let mut writer: zip::ZipWriter<std::io::Cursor<Vec<u8>>> =
            zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options: SimpleFileOptions =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, body) in entries {
            writer.start_file(*name, options).expect("start");
            writer.write_all(body).expect("write");
        }
        writer.finish().expect("finish").into_inner()
    }

    #[test]
    fn extracts_sibling_library_zip_members() {
        let dir: PathBuf = tempdir("sibling");
        let bin: PathBuf = dir.join("hello.exe");
        std::fs::write(&bin, b"MZ stub").expect("write bin");
        let zip: Vec<u8> = build_zip(&[
            ("mod_a.pyc", b"\x00\x01module a"),
            ("pkg/mod_b.pyc", b"\x00\x02module b"),
        ]);
        std::fs::write(dir.join("library.zip"), &zip).expect("write zip");
        let out: PathBuf = tempdir("sibling-out");
        let bundled: BundledModules = extract_bundled_modules(&bin, None, &out).expect("extract");
        assert!(bundled.library_zip_path.is_some());
        assert_eq!(bundled.entries.len(), 2);
        let names: Vec<&str> = bundled.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"mod_a.pyc"));
        assert!(names.contains(&"pkg/mod_b.pyc"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn overlay_and_sibling_dedup_by_name() {
        let dir: PathBuf = tempdir("dedup");
        let bin: PathBuf = dir.join("onefile.exe");
        std::fs::write(&bin, b"MZ stub").expect("write bin");
        let overlay: Vec<u8> = build_zip(&[("shared.pyc", b"overlay copy")]);
        let sibling: Vec<u8> = build_zip(&[
            ("shared.pyc", b"sibling copy"),
            ("only_sibling.pyc", b"unique"),
        ]);
        std::fs::write(dir.join("library.zip"), &sibling).expect("write zip");
        let out: PathBuf = tempdir("dedup-out");
        let bundled: BundledModules =
            extract_bundled_modules(&bin, Some(&overlay), &out).expect("extract");
        assert_eq!(bundled.overlay_member_count, 1);
        let names: Vec<&str> = bundled.entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(
            names.iter().filter(|n| **n == "shared.pyc").count(),
            1,
            "overlay copy must win, sibling duplicate must be skipped"
        );
        assert!(names.contains(&"only_sibling.pyc"));
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&out);
    }

    #[test]
    fn no_overlay_no_sibling_yields_empty() {
        let dir: PathBuf = tempdir("empty");
        let bin: PathBuf = dir.join("plain.exe");
        std::fs::write(&bin, b"MZ stub").expect("write bin");
        let out: PathBuf = tempdir("empty-out");
        let bundled: BundledModules = extract_bundled_modules(&bin, None, &out).expect("extract");
        assert!(bundled.entries.is_empty());
        assert!(bundled.library_zip_path.is_none());
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&out);
    }
}
