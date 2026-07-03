pub mod signatures;

use std::path::{Path, PathBuf};

use disrobe_py_marshal::{PyVersion, magic_for};

use crate::common::manifest::{
    EntryKind, EntryOrigin, EntryRecord, FreezerKind, FreezerManifest, ModuleInventoryEntry,
};
use crate::debug::dbg_line;
use crate::error::{Error, Result};
use crate::{MAX_RECOVERY_FILE_BYTES, read_file_bounded};
use signatures::ExtractedModule;

#[derive(Debug, Clone)]
pub struct PyOxidizerExtraction {
    pub manifest: FreezerManifest,
    pub python_dll_hint: Option<String>,
    pub markers_found: Vec<String>,
    pub config_blob_path: Option<PathBuf>,
    pub extracted_modules: usize,
    pub fs_relative_modules_surfaced: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct WriteCounts {
    written: usize,
    fs_relative: usize,
}

pub fn detect_and_extract(
    bytes: &[u8],
    source: &Path,
    out_dir: &Path,
) -> Result<PyOxidizerExtraction> {
    std::fs::create_dir_all(out_dir)?;
    let markers: Vec<String> = signatures::scan(bytes);
    if !signatures::is_present(&markers) {
        return Err(Error::PyOxidizerConfigMissing);
    }
    let (python_major, python_minor, python_dll_hint): (Option<u8>, Option<u8>, Option<String>) =
        signatures::infer_python_version(bytes);

    let blob: Option<&[u8]> = signatures::extract_resources_blob(bytes);
    let config_blob_path: Option<PathBuf> = if let Some(slice) = blob {
        let blob_path: PathBuf = out_dir.join("pyoxidizer_resources.blob");
        std::fs::write(&blob_path, slice)?;
        Some(blob_path)
    } else {
        None
    };

    let mut manifest: FreezerManifest =
        FreezerManifest::new(FreezerKind::PyOxidizer, source.display().to_string());
    manifest.python_major = python_major;
    manifest.python_minor = python_minor;
    manifest.interpreter_hint.clone_from(&python_dll_hint);
    if let Some(ref blob_path) = config_blob_path {
        manifest.push(EntryRecord {
            name: "pyoxidizer_resources.blob".to_owned(),
            kind: EntryKind::Resource,
            size: bytes.len() as u64,
            compressed_size: None,
            python_major,
            python_minor,
            source_path: Some(blob_path.display().to_string()),
            origin: EntryOrigin::Other,
        });
    }

    let counts: WriteCounts = if let Some(slice) = blob {
        let modules: Vec<ExtractedModule> = signatures::extract_modules(slice)
            .map_err(|err| Error::PyOxidizerResourceIndex(err.to_string()))?;
        write_modules(
            &mut manifest,
            out_dir,
            source,
            &modules,
            python_major,
            python_minor,
        )?
    } else {
        WriteCounts::default()
    };

    Ok(PyOxidizerExtraction {
        manifest,
        python_dll_hint,
        markers_found: markers,
        config_blob_path,
        extracted_modules: counts.written,
        fs_relative_modules_surfaced: counts.fs_relative,
    })
}

fn write_modules(
    manifest: &mut FreezerManifest,
    out_dir: &Path,
    source: &Path,
    modules: &[ExtractedModule],
    python_major: Option<u8>,
    python_minor: Option<u8>,
) -> Result<WriteCounts> {
    let modules_dir: PathBuf = out_dir.join("modules");
    if !modules.is_empty() {
        std::fs::create_dir_all(&modules_dir)?;
    }
    let pyc_header: Option<Vec<u8>> = pyc_header_bytes(python_major, python_minor);
    let mut written: usize = 0;
    let mut fs_relative: usize = 0;
    let mut primary: Option<String> = None;
    for module in modules {
        manifest.module_inventory.push(ModuleInventoryEntry {
            name: module.name.clone(),
            is_package: module.is_package,
            has_source: module.source.is_some() || module.fs_relative_source,
            has_bytecode: module.bytecode.is_some() || module.fs_relative_bytecode,
            has_bytecode_opt1: module.bytecode_opt1.is_some(),
            has_bytecode_opt2: module.bytecode_opt2.is_some(),
            has_extension: module.extension_len.is_some() || module.fs_relative_extension,
        });
        let rel_base: String = module.name.replace('.', "/");
        if let Some(bytecode) = module.bytecode.as_deref() {
            let file_name: String = bytecode_file_name(&rel_base, module.is_package);
            let body: Vec<u8> = with_pyc_header(pyc_header.as_deref(), bytecode);
            let disk_path: PathBuf = write_member(&modules_dir, &file_name, &body)?;
            manifest.push(EntryRecord {
                name: file_name.clone(),
                kind: EntryKind::PythonByteCode,
                size: body.len() as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: Some(disk_path.display().to_string()),
                origin: EntryOrigin::Other,
            });
            written += 1;
            if is_entry_module(&module.name) {
                primary = Some(file_name);
            }
        }
        if let Some(source) = module.source.as_deref() {
            let file_name: String = source_file_name(&rel_base, module.is_package);
            let disk_path: PathBuf = write_member(&modules_dir, &file_name, source)?;
            manifest.push(EntryRecord {
                name: file_name,
                kind: EntryKind::PythonModule,
                size: source.len() as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: Some(disk_path.display().to_string()),
                origin: EntryOrigin::Other,
            });
            written += 1;
        }
        if let Some(opt1) = module.bytecode_opt1.as_deref() {
            written += write_opt_bytecode(
                manifest,
                &modules_dir,
                &rel_base,
                module.is_package,
                &with_pyc_header(pyc_header.as_deref(), opt1),
                1,
                python_major,
                python_minor,
            )?;
        }
        if let Some(opt2) = module.bytecode_opt2.as_deref() {
            written += write_opt_bytecode(
                manifest,
                &modules_dir,
                &rel_base,
                module.is_package,
                &with_pyc_header(pyc_header.as_deref(), opt2),
                2,
                python_major,
                python_minor,
            )?;
        }
        if let Some(ext_len) = module.extension_len {
            manifest.push(EntryRecord {
                name: format!("{rel_base}.<extension>"),
                kind: EntryKind::NativeExtension,
                size: ext_len as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: None,
                origin: EntryOrigin::Other,
            });
        }
        let surfaced: usize = surface_fs_relative_members(
            manifest,
            &modules_dir,
            source,
            module,
            &rel_base,
            &mut primary,
            python_major,
            python_minor,
        )?;
        written += surfaced;
        fs_relative += surfaced;
    }
    if manifest.primary_module.is_none() {
        manifest.primary_module = primary;
    }
    Ok(WriteCounts {
        written,
        fs_relative,
    })
}

#[allow(clippy::too_many_arguments)]
fn surface_fs_relative_members(
    manifest: &mut FreezerManifest,
    modules_dir: &Path,
    source: &Path,
    module: &ExtractedModule,
    rel_base: &str,
    primary: &mut Option<String>,
    python_major: Option<u8>,
    python_minor: Option<u8>,
) -> Result<usize> {
    let mut surfaced: usize = 0;
    if module.bytecode.is_none()
        && let Some(rel_path) = module.fs_relative_bytecode_path.as_deref()
    {
        let file_name: String = bytecode_file_name(rel_base, module.is_package);
        if let Some((disk_path, len)) = read_sibling(modules_dir, source, rel_path, &file_name)? {
            manifest.push(EntryRecord {
                name: file_name.clone(),
                kind: EntryKind::PythonByteCode,
                size: len as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: Some(disk_path.display().to_string()),
                origin: EntryOrigin::SiblingFile,
            });
            surfaced += 1;
            if is_entry_module(&module.name) {
                *primary = Some(file_name);
            }
        }
    }
    if module.source.is_none()
        && let Some(rel_path) = module.fs_relative_source_path.as_deref()
    {
        let file_name: String = source_file_name(rel_base, module.is_package);
        if let Some((disk_path, len)) = read_sibling(modules_dir, source, rel_path, &file_name)? {
            manifest.push(EntryRecord {
                name: file_name,
                kind: EntryKind::PythonModule,
                size: len as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: Some(disk_path.display().to_string()),
                origin: EntryOrigin::SiblingFile,
            });
            surfaced += 1;
        }
    }
    for (rel_path, opt) in [
        (module.fs_relative_bytecode_opt1_path.as_deref(), 1u8),
        (module.fs_relative_bytecode_opt2_path.as_deref(), 2u8),
    ] {
        if let Some(path) = rel_path {
            let file_name: String = if module.is_package {
                format!("{rel_base}/__init__.opt-{opt}.pyc")
            } else {
                format!("{rel_base}.opt-{opt}.pyc")
            };
            if let Some((disk_path, len)) = read_sibling(modules_dir, source, path, &file_name)? {
                manifest.push(EntryRecord {
                    name: file_name,
                    kind: EntryKind::PythonByteCode,
                    size: len as u64,
                    compressed_size: None,
                    python_major,
                    python_minor,
                    source_path: Some(disk_path.display().to_string()),
                    origin: EntryOrigin::SiblingFile,
                });
                surfaced += 1;
            }
        }
    }
    if module.extension_len.is_none()
        && let Some(rel_path) = module.fs_relative_extension_path.as_deref()
    {
        let ext: Option<&str> = Path::new(rel_path)
            .extension()
            .and_then(|e: &std::ffi::OsStr| e.to_str());
        let file_name: String = ext.map_or_else(
            || rel_base.to_owned(),
            |suffix: &str| format!("{rel_base}.{suffix}"),
        );
        if let Some((disk_path, len)) = read_sibling(modules_dir, source, rel_path, &file_name)? {
            manifest.push(EntryRecord {
                name: file_name,
                kind: EntryKind::NativeExtension,
                size: len as u64,
                compressed_size: None,
                python_major,
                python_minor,
                source_path: Some(disk_path.display().to_string()),
                origin: EntryOrigin::SiblingFile,
            });
            surfaced += 1;
        }
    }
    Ok(surfaced)
}

fn read_sibling(
    modules_dir: &Path,
    source: &Path,
    rel_path: &str,
    dest_name: &str,
) -> Result<Option<(PathBuf, usize)>> {
    let Some(parent): Option<&Path> = source.parent() else {
        dbg_line(|| {
            format!(
                "pyoxidizer: input `{}` has no parent directory; cannot resolve filesystem-relative `{rel_path}`",
                source.display()
            )
        });
        return Ok(None);
    };
    let candidate: PathBuf = parent.join(rel_path);
    if !path_is_within(parent, &candidate) {
        dbg_line(|| {
            format!(
                "pyoxidizer: filesystem-relative path `{rel_path}` escapes input directory; skipping"
            )
        });
        return Ok(None);
    }
    let bytes: Vec<u8> = match read_file_bounded(&candidate, MAX_RECOVERY_FILE_BYTES) {
        Ok(bytes) => bytes,
        Err(err) => {
            dbg_line(|| {
                format!(
                    "pyoxidizer: filesystem-relative sibling `{}` unreadable ({err}); logged skip",
                    candidate.display()
                )
            });
            return Ok(None);
        }
    };
    if bytes.is_empty() {
        dbg_line(|| {
            format!(
                "pyoxidizer: filesystem-relative sibling `{}` is empty; logged skip",
                candidate.display()
            )
        });
        return Ok(None);
    }
    let disk_path: PathBuf = write_member(modules_dir, dest_name, &bytes)?;
    Ok(Some((disk_path, bytes.len())))
}

#[allow(clippy::too_many_arguments)]
fn write_opt_bytecode(
    manifest: &mut FreezerManifest,
    modules_dir: &Path,
    rel_base: &str,
    is_package: bool,
    body: &[u8],
    opt: u8,
    python_major: Option<u8>,
    python_minor: Option<u8>,
) -> Result<usize> {
    let stem: String = if is_package {
        format!("{rel_base}/__init__.opt-{opt}.pyc")
    } else {
        format!("{rel_base}.opt-{opt}.pyc")
    };
    let disk_path: PathBuf = write_member(modules_dir, &stem, body)?;
    manifest.push(EntryRecord {
        name: stem,
        kind: EntryKind::PythonByteCode,
        size: body.len() as u64,
        compressed_size: None,
        python_major,
        python_minor,
        source_path: Some(disk_path.display().to_string()),
        origin: EntryOrigin::Other,
    });
    Ok(1)
}

fn pyc_header_bytes(major: Option<u8>, minor: Option<u8>) -> Option<Vec<u8>> {
    let (maj, min): (u8, u8) = (major?, minor?);
    let version: PyVersion = PyVersion::new(maj, min);
    let magic: u32 = magic_for(version)?;
    let total_len: usize = version.pyc_header_len();
    let mut header: Vec<u8> = Vec::with_capacity(total_len);
    header.extend_from_slice(&magic.to_le_bytes());
    while header.len() < total_len {
        header.push(0u8);
    }
    Some(header)
}

fn with_pyc_header(header: Option<&[u8]>, marshalled: &[u8]) -> Vec<u8> {
    header.map_or_else(
        || marshalled.to_vec(),
        |h: &[u8]| {
            let mut out: Vec<u8> = Vec::with_capacity(h.len() + marshalled.len());
            out.extend_from_slice(h);
            out.extend_from_slice(marshalled);
            out
        },
    )
}

fn bytecode_file_name(rel_base: &str, is_package: bool) -> String {
    if is_package {
        format!("{rel_base}/__init__.pyc")
    } else {
        format!("{rel_base}.pyc")
    }
}

fn source_file_name(rel_base: &str, is_package: bool) -> String {
    if is_package {
        format!("{rel_base}/__init__.py")
    } else {
        format!("{rel_base}.py")
    }
}

fn is_entry_module(name: &str) -> bool {
    name == "__main__" || name.ends_with(".__main__") || name == "main"
}

fn write_member(modules_dir: &Path, rel_name: &str, body: &[u8]) -> Result<PathBuf> {
    let candidate: PathBuf = modules_dir.join(rel_name);
    let canonical_root: PathBuf = modules_dir.to_path_buf();
    if !path_is_within(&canonical_root, &candidate) {
        return Err(Error::UnsafeEntryPath(rel_name.to_owned()));
    }
    if let Some(parent) = candidate.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&candidate, body)?;
    Ok(candidate)
}

fn path_is_within(root: &Path, candidate: &Path) -> bool {
    let mut depth: i32 = 0;
    for component in candidate
        .strip_prefix(root)
        .unwrap_or(candidate)
        .components()
    {
        match component {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return false,
        }
    }
    true
}

#[must_use]
pub fn looks_like_pyoxidizer(bytes: &[u8]) -> bool {
    let m: Vec<String> = signatures::scan(bytes);
    signatures::is_present(&m)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn rand_suffix() -> u64 {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0x9e37_79b9);
        N.fetch_add(0x517c_c1b7, Ordering::Relaxed)
    }

    fn temp_dir() -> PathBuf {
        let dir: PathBuf = std::env::temp_dir().join(format!(
            "disrobe-pyox-extract-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir temp");
        dir
    }

    const BLOB_START_OF_ENTRY: u8 = 0x01;
    const BLOB_RESOURCE_FIELD_TYPE: u8 = 0x02;
    const BLOB_RAW_PAYLOAD_LENGTH: u8 = 0x03;
    const BLOB_INTERIOR_PADDING: u8 = 0x04;
    const BLOB_END_OF_ENTRY: u8 = 0xff;
    const BLOB_END_OF_INDEX: u8 = 0x00;
    const PADDING_NONE: u8 = 0x01;
    const RES_START_OF_ENTRY: u8 = 0x01;
    const RES_NAME: u8 = 0x03;
    const RES_IS_PYTHON_PACKAGE: u8 = 0x04;
    const RES_IN_MEMORY_BYTECODE: u8 = 0x07;
    const RES_IS_PYTHON_MODULE: u8 = 0x16;
    const RES_END_OF_ENTRY: u8 = 0xff;
    const RES_END_OF_INDEX: u8 = 0x00;

    fn build_blob(modules: &[(&str, bool, &[u8])]) -> Vec<u8> {
        let mut name_section: Vec<u8> = Vec::new();
        let mut bytecode_section: Vec<u8> = Vec::new();
        for (name, _, bc) in modules {
            name_section.extend_from_slice(name.as_bytes());
            bytecode_section.extend_from_slice(bc);
        }
        let mut blob_index: Vec<u8> = Vec::new();
        let mut count: u8 = 0;
        for (field, len) in [
            (RES_NAME, name_section.len()),
            (RES_IN_MEMORY_BYTECODE, bytecode_section.len()),
        ] {
            blob_index.push(BLOB_START_OF_ENTRY);
            blob_index.push(BLOB_RESOURCE_FIELD_TYPE);
            blob_index.push(field);
            blob_index.push(BLOB_RAW_PAYLOAD_LENGTH);
            blob_index.extend_from_slice(&(len as u64).to_le_bytes());
            blob_index.push(BLOB_INTERIOR_PADDING);
            blob_index.push(PADDING_NONE);
            blob_index.push(BLOB_END_OF_ENTRY);
            count += 1;
        }
        blob_index.push(BLOB_END_OF_INDEX);

        let mut resources_index: Vec<u8> = Vec::new();
        for (name, is_pkg, bc) in modules {
            resources_index.push(RES_START_OF_ENTRY);
            resources_index.push(RES_NAME);
            resources_index.extend_from_slice(&(name.len() as u16).to_le_bytes());
            if *is_pkg {
                resources_index.push(RES_IS_PYTHON_PACKAGE);
            }
            resources_index.push(RES_IS_PYTHON_MODULE);
            resources_index.push(RES_IN_MEMORY_BYTECODE);
            resources_index.extend_from_slice(&(bc.len() as u32).to_le_bytes());
            resources_index.push(RES_END_OF_ENTRY);
        }
        resources_index.push(RES_END_OF_INDEX);

        let mut out: Vec<u8> = Vec::new();
        out.extend_from_slice(b"pyembed\x03");
        out.push(count);
        out.extend_from_slice(&(blob_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&(modules.len() as u32).to_le_bytes());
        out.extend_from_slice(&(resources_index.len() as u32).to_le_bytes());
        out.extend_from_slice(&blob_index);
        out.extend_from_slice(&resources_index);
        out.extend_from_slice(&name_section);
        out.extend_from_slice(&bytecode_section);
        out
    }

    #[test]
    fn detect_and_extract_writes_real_module_files() {
        let app_bc: &[u8] = b"\xde\xad app bytecode body";
        let pkg_bc: &[u8] = b"package init bytecode";
        let blob: Vec<u8> = build_blob(&[("app", false, app_bc), ("app.sub", true, pkg_bc)]);
        let mut container: Vec<u8> = vec![0u8; 64];
        container.extend_from_slice(b"PyOxidizer");
        container.extend_from_slice(b"python312.dll");
        container.extend_from_slice(&[0u8; 16]);
        container.extend_from_slice(&blob);

        let out: PathBuf = temp_dir();
        let extraction: PyOxidizerExtraction =
            detect_and_extract(&container, Path::new("app.exe"), &out).expect("extract");

        assert_eq!(extraction.extracted_modules, 2);
        assert_eq!(extraction.manifest.python_minor, Some(12));

        let app_path: PathBuf = out.join("modules").join("app.pyc");
        let pkg_path: PathBuf = out
            .join("modules")
            .join("app")
            .join("sub")
            .join("__init__.pyc");
        assert!(app_path.is_file(), "app.pyc must exist at {app_path:?}");
        assert!(pkg_path.is_file(), "package __init__.pyc must exist");

        let py312_magic: u32 = 0x0A0D_0DCB;
        let mut expected_app: Vec<u8> = Vec::new();
        expected_app.extend_from_slice(&py312_magic.to_le_bytes());
        expected_app.extend_from_slice(&[0u8; 12]);
        expected_app.extend_from_slice(app_bc);
        assert_eq!(
            std::fs::read(&app_path).expect("read app"),
            expected_app,
            "app.pyc must be a real 3.12 pyc: 16-byte PEP 552 header + marshalled body"
        );

        let app_disk: Vec<u8> = std::fs::read(&app_path).expect("read app2");
        assert_eq!(
            &app_disk[16..],
            app_bc,
            "body after header is the exact marshalled bytecode"
        );
        let pkg_disk: Vec<u8> = std::fs::read(&pkg_path).expect("read pkg");
        assert_eq!(
            &pkg_disk[0..4],
            &py312_magic.to_le_bytes(),
            "pkg pyc magic is 3.12"
        );
        assert_eq!(
            &pkg_disk[16..],
            pkg_bc,
            "pkg body is exact marshalled bytecode"
        );

        let names: Vec<String> = extraction
            .manifest
            .entries
            .iter()
            .map(|e| e.name.clone())
            .collect();
        assert!(names.iter().any(|n| n == "app.pyc"));
        assert!(names.iter().any(|n| n == "app/sub/__init__.pyc"));

        let inventory: &[ModuleInventoryEntry] = &extraction.manifest.module_inventory;
        assert_eq!(
            inventory.len(),
            2,
            "the module-name inventory must list every recovered module"
        );
        let app: &ModuleInventoryEntry = inventory
            .iter()
            .find(|m: &&ModuleInventoryEntry| m.name == "app")
            .expect("app must be inventoried by its dotted module name");
        assert!(!app.is_package);
        assert!(app.has_bytecode, "app carries in-memory bytecode");
        assert!(!app.has_source);
        assert!(!app.has_extension);
        let sub: &ModuleInventoryEntry = inventory
            .iter()
            .find(|m: &&ModuleInventoryEntry| m.name == "app.sub")
            .expect("the package must be inventoried under its dotted name");
        assert!(sub.is_package, "app.sub is a package");
        assert!(sub.has_bytecode);
    }

    #[test]
    fn detect_and_extract_rejects_non_pyoxidizer() {
        let out: PathBuf = temp_dir();
        let err: Error = detect_and_extract(b"just random bytes", Path::new("x.bin"), &out)
            .expect_err("must reject");
        assert!(matches!(err, Error::PyOxidizerConfigMissing));
    }

    #[test]
    fn detect_and_extract_rejects_corrupt_v3_module_index() {
        let mut container: Vec<u8> = Vec::new();
        container.extend_from_slice(b"PyOxidizer");
        container.extend_from_slice(b"python312.dll");
        container.extend_from_slice(b"pyembed\x03");

        let out: PathBuf = temp_dir();
        let err: Error =
            detect_and_extract(&container, Path::new("corrupt.exe"), &out).expect_err("must fail");
        assert!(matches!(err, Error::PyOxidizerResourceIndex(_)));
    }
}
