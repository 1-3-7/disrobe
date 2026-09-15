use std::path::{Path, PathBuf};

use crate::MAX_FREEZE_DIR_ENTRIES;

#[derive(Debug, Clone)]
pub struct BbfreezeLayout {
    pub library_zip: PathBuf,
    pub python_dll: Option<PathBuf>,
    pub python_dll_name: Option<String>,
    pub py_launcher: Option<PathBuf>,
}

#[must_use]
pub fn probe(binary_path: &Path) -> Option<BbfreezeLayout> {
    let dir: &Path = binary_path.parent()?;
    let library_zip: PathBuf = dir.join("library.zip");
    if !library_zip.is_file() {
        return None;
    }
    if dir.join("frozen_application_license.txt").exists()
        || dir.join("lib").join("library.zip").exists()
    {
        return None;
    }
    let (python_dll, python_dll_name): (Option<PathBuf>, Option<String>) = find_python_runtime(dir);
    python_dll.as_ref()?;
    let py_launcher: Option<PathBuf> = ["py.exe", "py"]
        .iter()
        .map(|n: &&str| dir.join(n))
        .find(|p: &PathBuf| p.is_file());
    Some(BbfreezeLayout {
        library_zip,
        python_dll,
        python_dll_name,
        py_launcher,
    })
}

fn find_python_runtime(dir: &Path) -> (Option<PathBuf>, Option<String>) {
    let Ok(read) = std::fs::read_dir(dir) else {
        return (None, None);
    };
    for entry_result in read.take(MAX_FREEZE_DIR_ENTRIES) {
        let Ok(entry): std::io::Result<std::fs::DirEntry> = entry_result else {
            continue;
        };
        let path: PathBuf = entry.path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if is_python_runtime_dll(name) {
            return (Some(path.clone()), Some(name.to_owned()));
        }
    }
    (None, None)
}

fn is_python_runtime_dll(name: &str) -> bool {
    let lower: String = name.to_ascii_lowercase();
    let Some(after): Option<&str> = lower
        .strip_prefix("libpython")
        .or_else(|| lower.strip_prefix("python"))
    else {
        return false;
    };
    let is_dll: bool = std::path::Path::new(&lower)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("dll"));
    let is_unix: bool = lower.contains(".so");
    if !is_dll && !is_unix {
        return false;
    }
    after
        .chars()
        .next()
        .is_some_and(|c: char| c.is_ascii_digit())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn tempdir(tag: &str) -> disrobe_core::scratch::ScratchDir {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0xBBF0_0000);
        let purpose: String = format!(
            "disrobe-bbfreeze-layout-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        );
        disrobe_core::scratch::ScratchDir::create(&purpose).expect("create scratch dir")
    }

    #[test]
    fn dll_classifier_matches_versioned_runtime() {
        assert!(is_python_runtime_dll("python27.dll"));
        assert!(is_python_runtime_dll("Python34.DLL"));
        assert!(is_python_runtime_dll("libpython3.8.so.1.0"));
        assert!(!is_python_runtime_dll("pythoncom27.dll"));
        assert!(!is_python_runtime_dll("mfc140.dll"));
    }

    #[test]
    fn probe_accepts_library_zip_plus_python_dll() {
        let scratch: disrobe_core::scratch::ScratchDir = tempdir("accept");
        let dir: PathBuf = scratch.path().to_path_buf();
        let bin: PathBuf = dir.join("app.exe");
        std::fs::write(&bin, b"stub").expect("write");
        std::fs::write(dir.join("library.zip"), b"PK\x05\x06").expect("zip");
        std::fs::write(dir.join("python27.dll"), b"MZ").expect("dll");
        let layout: BbfreezeLayout = probe(&bin).expect("must probe");
        assert_eq!(layout.python_dll_name.as_deref(), Some("python27.dll"));
    }

    #[test]
    fn probe_rejects_when_only_library_zip() {
        let scratch: disrobe_core::scratch::ScratchDir = tempdir("only-zip");
        let dir: PathBuf = scratch.path().to_path_buf();
        let bin: PathBuf = dir.join("app.exe");
        std::fs::write(&bin, b"stub").expect("write");
        std::fs::write(dir.join("library.zip"), b"PK\x05\x06").expect("zip");
        assert!(probe(&bin).is_none());
    }

    #[test]
    fn probe_rejects_cxfreeze_license_layout() {
        let scratch: disrobe_core::scratch::ScratchDir = tempdir("cx");
        let dir: PathBuf = scratch.path().to_path_buf();
        let bin: PathBuf = dir.join("app.exe");
        std::fs::write(&bin, b"stub").expect("write");
        std::fs::write(dir.join("library.zip"), b"PK\x05\x06").expect("zip");
        std::fs::write(dir.join("python312.dll"), b"MZ").expect("dll");
        std::fs::write(dir.join("frozen_application_license.txt"), b"lic").expect("lic");
        assert!(
            probe(&bin).is_none(),
            "a cx_Freeze license sibling must not be claimed as bbfreeze"
        );
    }
}
