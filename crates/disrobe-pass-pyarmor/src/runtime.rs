use std::path::{Path, PathBuf};

use crate::MAX_RUNTIME_DIR_ENTRIES;
use crate::error::{Error, Result};

#[derive(Debug, Clone)]
pub(crate) struct RuntimeLocation {
    pub(crate) path: PathBuf,
}

pub(crate) fn locate_runtime(
    wrapper_path: &Path,
    serial_hint: Option<&str>,
) -> Result<RuntimeLocation> {
    let dir: &Path = wrapper_path.parent().unwrap_or_else(|| Path::new("."));
    let mut searched: Vec<String> = Vec::new();

    if let Some(serial) = serial_hint {
        let candidate: PathBuf = dir.join(format!("pyarmor_runtime_{serial}"));
        searched.push(candidate.display().to_string());
        if candidate.is_dir() {
            for ext in ["pyd", "so", "dylib"] {
                let lib: PathBuf = candidate.join(format!("pyarmor_runtime.{ext}"));
                if lib.is_file() {
                    return Ok(RuntimeLocation { path: lib });
                }
            }
        }
    }

    if let Some(lib) = locate_numbered_runtime_dir(dir, &mut searched, MAX_RUNTIME_DIR_ENTRIES)? {
        return Ok(RuntimeLocation { path: lib });
    }

    if let Some(serial) = serial_hint
        && let Some(lib) =
            locate_prefixed_runtime_dir(dir, serial, &mut searched, MAX_RUNTIME_DIR_ENTRIES)?
    {
        return Ok(RuntimeLocation { path: lib });
    }

    let pytransform_dir: PathBuf = dir.join("pytransform");
    searched.push(pytransform_dir.display().to_string());
    if pytransform_dir.is_dir() {
        for prefix in ["_pytransform", "pytransform"] {
            for ext in ["dll", "so", "dylib"] {
                let lib: PathBuf = pytransform_dir.join(format!("{prefix}.{ext}"));
                if lib.is_file() {
                    return Ok(RuntimeLocation { path: lib });
                }
            }
        }
    }

    for super_name in ["pytransform.pyd", "pytransform.so", "pytransform.dylib"] {
        let lib: PathBuf = dir.join(super_name);
        searched.push(lib.display().to_string());
        if lib.is_file() {
            return Ok(RuntimeLocation { path: lib });
        }
    }

    Err(Error::RuntimeNotFound { searched })
}

fn bump_entry_count(seen: &mut usize, max_entries: usize, dir: &Path) -> Result<()> {
    *seen = seen.checked_add(1).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("{} has too many entries", dir.display()),
        )
    })?;
    if *seen > max_entries {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} has more than {} entries while locating PyArmor runtime",
                dir.display(),
                max_entries
            ),
        )
        .into());
    }
    Ok(())
}

fn locate_numbered_runtime_dir(
    dir: &Path,
    searched: &mut Vec<String>,
    max_entries: usize,
) -> Result<Option<PathBuf>> {
    let entries: std::fs::ReadDir = std::fs::read_dir(dir)?;
    let mut seen: usize = 0;
    for entry_result in entries {
        bump_entry_count(&mut seen, max_entries, dir)?;
        let entry: std::fs::DirEntry = entry_result?;
        let file_name: std::ffi::OsString = entry.file_name();
        let name: std::borrow::Cow<'_, str> = file_name.to_string_lossy();
        let entry_path: PathBuf = entry.path();
        if name.starts_with("pyarmor_runtime_") && entry_path.is_dir() {
            for ext in ["pyd", "so", "dylib"] {
                let lib: PathBuf = entry_path.join(format!("pyarmor_runtime.{ext}"));
                searched.push(lib.display().to_string());
                if lib.is_file() {
                    return Ok(Some(lib));
                }
            }
        }
    }
    Ok(None)
}

fn locate_prefixed_runtime_dir(
    dir: &Path,
    serial: &str,
    searched: &mut Vec<String>,
    max_entries: usize,
) -> Result<Option<PathBuf>> {
    let entries: std::fs::ReadDir = std::fs::read_dir(dir)?;
    let mut seen: usize = 0;
    for entry_result in entries {
        bump_entry_count(&mut seen, max_entries, dir)?;
        let entry: std::fs::DirEntry = entry_result?;
        let entry_path: PathBuf = entry.path();
        if !entry_path.is_dir() {
            continue;
        }
        let candidate: PathBuf = entry_path.join(format!("pyarmor_runtime_{serial}"));
        if !candidate.is_dir() {
            continue;
        }
        for ext in ["pyd", "so", "dylib"] {
            let lib: PathBuf = candidate.join(format!("pyarmor_runtime.{ext}"));
            searched.push(lib.display().to_string());
            if lib.is_file() {
                return Ok(Some(lib));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::fs;

    use disrobe_core::scratch::ScratchDir;

    #[test]
    fn locate_v8v9_runtime_layout() {
        let scratch: ScratchDir = ScratchDir::create("pyarmor-runtime-v8").expect("scratch");
        let tmp: &Path = scratch.path();
        let runtime_dir: PathBuf = tmp.join("pyarmor_runtime_000000");
        fs::create_dir_all(&runtime_dir).expect("mkdir");
        let lib: PathBuf = runtime_dir.join("pyarmor_runtime.pyd");
        fs::write(&lib, b"FAKE PE").expect("write lib");
        let wrapper: PathBuf = tmp.join("hello.py");
        fs::write(&wrapper, b"# wrapper").expect("write wrapper");

        let loc: RuntimeLocation = locate_runtime(&wrapper, Some("000000")).expect("locate");
        assert_eq!(loc.path, lib);
    }

    #[test]
    fn locate_v6v7_pytransform_layout() {
        let scratch: ScratchDir = ScratchDir::create("pyarmor-runtime-v6").expect("scratch");
        let tmp: &Path = scratch.path();
        let runtime_dir: PathBuf = tmp.join("pytransform");
        fs::create_dir_all(&runtime_dir).expect("mkdir");
        let lib: PathBuf = runtime_dir.join("_pytransform.dll");
        fs::write(&lib, b"FAKE PE").expect("write lib");
        let wrapper: PathBuf = tmp.join("hello.py");
        fs::write(&wrapper, b"# wrapper").expect("write wrapper");

        let loc: RuntimeLocation = locate_runtime(&wrapper, None).expect("locate");
        assert_eq!(loc.path, lib);
    }

    #[test]
    fn numbered_runtime_scan_caps_entries() {
        let scratch: ScratchDir = ScratchDir::create("pyarmor-runtime-cap").expect("scratch");
        let tmp: &Path = scratch.path();
        fs::write(tmp.join("a"), b"a").expect("write marker");
        fs::write(tmp.join("b"), b"b").expect("write marker");
        let mut searched: Vec<String> = Vec::new();
        let err: Error = locate_numbered_runtime_dir(tmp, &mut searched, 1).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }

    #[test]
    fn locate_prefixed_runtime_layout() {
        let scratch: ScratchDir = ScratchDir::create("pyarmor-runtime-prefixed").expect("scratch");
        let tmp: &Path = scratch.path();
        let runtime_dir: PathBuf = tmp.join("paypal_runtime").join("pyarmor_runtime_000000");
        fs::create_dir_all(&runtime_dir).expect("mkdir");
        let lib: PathBuf = runtime_dir.join("pyarmor_runtime.pyd");
        fs::write(&lib, b"FAKE PE").expect("write lib");
        let wrapper: PathBuf = tmp.join("hello.py");
        fs::write(&wrapper, b"# wrapper").expect("write wrapper");

        let loc: RuntimeLocation = locate_runtime(&wrapper, Some("000000"))
            .expect("a --prefix-nested runtime package must resolve");
        assert_eq!(loc.path, lib);
    }

    #[test]
    fn locate_prefixed_runtime_layout_wrong_serial_falls_through_to_not_found() {
        let scratch: ScratchDir =
            ScratchDir::create("pyarmor-runtime-wrong-serial").expect("scratch");
        let tmp: &Path = scratch.path();
        let runtime_dir: PathBuf = tmp.join("paypal_runtime").join("pyarmor_runtime_000000");
        fs::create_dir_all(&runtime_dir).expect("mkdir");
        fs::write(runtime_dir.join("pyarmor_runtime.pyd"), b"FAKE PE").expect("write lib");
        let wrapper: PathBuf = tmp.join("hello.py");
        fs::write(&wrapper, b"# wrapper").expect("write wrapper");

        let err: Error = locate_runtime(&wrapper, Some("999999")).unwrap_err();
        assert!(matches!(err, Error::RuntimeNotFound { .. }));
    }

    #[test]
    fn locate_prefixed_runtime_dir_caps_entries() {
        let scratch: ScratchDir =
            ScratchDir::create("pyarmor-runtime-prefixed-cap").expect("scratch");
        let tmp: &Path = scratch.path();
        fs::create_dir_all(tmp.join("a")).expect("mkdir a");
        fs::create_dir_all(tmp.join("b")).expect("mkdir b");
        let mut searched: Vec<String> = Vec::new();
        let err: Error = locate_prefixed_runtime_dir(tmp, "000000", &mut searched, 1).unwrap_err();
        assert!(matches!(err, Error::Io(_)));
    }
}
