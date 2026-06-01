use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::c_module::{CModuleStructure, parse_c_module};
use crate::const_manifest::{ConstantManifest, parse_constant_manifest};
use crate::constants::{ConstantsPool, ConstantsTable, decode_const_file};
use crate::detect::{Detection, detect_in_bytes};
use crate::error::{Error, Result};
use crate::onefile::{OnefilePayload, extract_onefile};
use crate::surface::{SurfaceModule, build_surface};
use crate::version_db::{NuitkaVersionReport, detect_nuitka_version};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NuitkaDecompilation {
    pub schema: String,
    pub manifest: Option<ConstantManifest>,
    pub constants: ConstantsTable,
    pub version: NuitkaVersionReport,
    pub source_kind: DecompSourceKind,
    pub surface: Option<SurfaceModule>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecompSourceKind {
    BuildDir,
    OnefilePayload,
    EmbeddedStandalone,
}

const SCHEMA: &str = "disrobe.nuitka.decompile/v0";
const BYTECODE_CONST: &str = "__bytecode.const";

pub fn decompile_build_dir(build_dir: &Path) -> Result<NuitkaDecompilation> {
    let mut notes: Vec<String> = Vec::new();

    let manifest: Option<ConstantManifest> = read_manifest(build_dir, &mut notes)?;

    let constants_c: Option<Vec<u8>> = read_optional(&build_dir.join("__constants.c"))?;
    if constants_c.is_none() {
        notes.push("__constants.c absent: exact version unavailable (Tier-A skipped)".to_owned());
    }

    let binary_bytes: Vec<u8> = locate_sibling_binary(build_dir)?.unwrap_or_default();
    let python_abi: Option<(u8, u8)> = python_abi_from_binary(&binary_bytes);
    if python_abi.is_none() {
        notes.push("python ABI not recoverable from sibling binary".to_owned());
    }

    let version: NuitkaVersionReport =
        detect_nuitka_version(&binary_bytes, constants_c.as_deref(), python_abi);

    let const_files: Vec<(String, Vec<u8>)> = list_const_files(build_dir, &mut notes)?;
    if !notes.iter().any(|n: &String| n.contains(BYTECODE_CONST))
        && manifest
            .as_ref()
            .is_some_and(|m: &ConstantManifest| m.by_source_file(BYTECODE_CONST).is_some())
    {
        notes.push(format!(
            "{BYTECODE_CONST} skipped: marshal bytecode table is out of scope for the constants foundation"
        ));
    }
    if const_files.is_empty() {
        return Err(Error::NoConstantsSource);
    }

    let mut constants: ConstantsTable = ConstantsTable::default();
    for (file_name, bytes) in &const_files {
        let blob_name: String = manifest
            .as_ref()
            .and_then(|m: &ConstantManifest| m.by_source_file(file_name))
            .map_or_else(
                || blob_name_from_filename(file_name),
                |e| e.blob_name.clone(),
            );
        let pool: ConstantsPool = decode_const_file(bytes, file_name, &blob_name)?;
        for s in &pool.strings {
            constants.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            constants.all_ints.insert(*i);
        }
        constants.pools.insert(file_name.clone(), pool);
    }

    let surface: Option<SurfaceModule> = build_dir_surface(build_dir, &constants, &mut notes)?;

    Ok(NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest,
        constants,
        version,
        source_kind: DecompSourceKind::BuildDir,
        surface,
        notes,
    })
}

fn build_dir_surface(
    build_dir: &Path,
    constants: &ConstantsTable,
    notes: &mut Vec<String>,
) -> Result<Option<SurfaceModule>> {
    let Some((const_file, primary_blob)): Option<(&String, String)> =
        primary_module_blob(constants)
    else {
        notes.push("no primary module .const pool: surface unavailable".to_owned());
        return Ok(None);
    };
    let c_path: std::path::PathBuf = build_dir.join(format!("module.{primary_blob}.c"));
    let Some(bytes): Option<Vec<u8>> = read_optional(&c_path)? else {
        notes.push(format!(
            "module.{primary_blob}.c absent: surface limited to names-only"
        ));
        return Ok(None);
    };
    let text: String = String::from_utf8_lossy(&bytes).into_owned();
    let cmod: CModuleStructure = parse_c_module(&text)?;
    let Some(pool): Option<&ConstantsPool> = constants.pools.get(const_file) else {
        notes.push("primary module pool vanished before surface build".to_owned());
        return Ok(None);
    };
    let surface: SurfaceModule = build_surface(&cmod, pool, Some(&text))?;
    notes.extend(surface.notes.iter().cloned());
    Ok(Some(surface))
}

fn primary_module_blob(constants: &ConstantsTable) -> Option<(&String, String)> {
    constants.pools.keys().find_map(|file_name: &String| {
        let blob: String = blob_name_from_filename(file_name);
        (!blob.is_empty()).then_some((file_name, blob))
    })
}

pub fn decompile_binary(path: &Path) -> Result<NuitkaDecompilation> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    let detection: Detection = detect_in_bytes(&bytes)?;

    if let Some(offset) = detection.onefile_payload_offset {
        return decompile_onefile(&bytes, offset);
    }

    if let Some(build_dir) = sibling_build_dir(path) {
        return decompile_build_dir(&build_dir);
    }

    let python_abi: Option<(u8, u8)> = match (
        detection.version.python_major,
        detection.version.python_minor,
    ) {
        (Some(major), Some(minor)) => Some((major, minor)),
        _ => None,
    };
    let version: NuitkaVersionReport = detect_nuitka_version(&bytes, None, python_abi);

    Ok(NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest: None,
        constants: ConstantsTable::default(),
        version,
        source_kind: DecompSourceKind::EmbeddedStandalone,
        surface: None,
        notes: vec![
            "embedded-standalone binary: constants live in the in-binary blob; \
             no sibling .build directory found, so no .const recovery performed"
                .to_owned(),
        ],
    })
}

pub fn decompile_const_bytes(
    bytes: &[u8],
    source_file: &str,
    blob_name: &str,
) -> Result<ConstantsPool> {
    decode_const_file(bytes, source_file, blob_name)
}

fn decompile_onefile(bytes: &[u8], offset: usize) -> Result<NuitkaDecompilation> {
    let payload: OnefilePayload = extract_onefile(bytes, offset)?;

    let manifest: Option<ConstantManifest> = payload
        .entries
        .iter()
        .find(|e| e.filename.ends_with("__constant.txt"))
        .and_then(|e| parse_constant_manifest(&e.data).ok());

    let mut notes: Vec<String> = Vec::new();
    let mut constants: ConstantsTable = ConstantsTable::default();
    for entry in &payload.entries {
        if !is_const_filename(&entry.filename) || entry.filename.ends_with(BYTECODE_CONST) {
            continue;
        }
        let file_name: String = entry.filename.clone();
        let blob_name: String = manifest
            .as_ref()
            .and_then(|m: &ConstantManifest| m.by_source_file(&file_name))
            .map_or_else(
                || blob_name_from_filename(&file_name),
                |e| e.blob_name.clone(),
            );
        let pool: ConstantsPool = decode_const_file(&entry.data, &file_name, &blob_name)?;
        for s in &pool.strings {
            constants.all_strings.insert(s.clone());
        }
        for i in &pool.ints {
            constants.all_ints.insert(*i);
        }
        constants.pools.insert(file_name, pool);
    }

    if constants.pools.is_empty() {
        notes.push("onefile payload carried no .const constant files".to_owned());
    }

    let python_abi: Option<(u8, u8)> = python_abi_from_binary(bytes);
    let version: NuitkaVersionReport = detect_nuitka_version(bytes, None, python_abi);

    Ok(NuitkaDecompilation {
        schema: SCHEMA.to_owned(),
        manifest,
        constants,
        version,
        source_kind: DecompSourceKind::OnefilePayload,
        surface: None,
        notes,
    })
}

fn read_manifest(build_dir: &Path, notes: &mut Vec<String>) -> Result<Option<ConstantManifest>> {
    let manifest_path: std::path::PathBuf = build_dir.join("blobs").join("__constant.txt");
    let Some(bytes): Option<Vec<u8>> = read_optional(&manifest_path)? else {
        notes.push("blobs/__constant.txt absent: blob_name fallback from filenames".to_owned());
        return Ok(None);
    };
    Ok(Some(parse_constant_manifest(&bytes)?))
}

fn is_const_filename(file_name: &str) -> bool {
    Path::new(file_name)
        .extension()
        .is_some_and(|ext: &std::ffi::OsStr| ext.eq_ignore_ascii_case("const"))
}

fn list_const_files(build_dir: &Path, notes: &mut Vec<String>) -> Result<Vec<(String, Vec<u8>)>> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for entry in std::fs::read_dir(build_dir)? {
        let entry: std::fs::DirEntry = entry?;
        let file_name_os: std::ffi::OsString = entry.file_name();
        let Some(file_name): Option<&str> = file_name_os.to_str() else {
            continue;
        };
        if !is_const_filename(file_name) {
            continue;
        }
        if file_name == BYTECODE_CONST {
            notes.push(format!(
                "{file_name} skipped: marshal bytecode table is out of scope for the constants foundation"
            ));
            continue;
        }
        let bytes: Vec<u8> = std::fs::read(entry.path())?;
        out.push((file_name.to_owned(), bytes));
    }
    out.sort_by(|a: &(String, Vec<u8>), b: &(String, Vec<u8>)| a.0.cmp(&b.0));
    Ok(out)
}

fn locate_sibling_binary(build_dir: &Path) -> Result<Option<Vec<u8>>> {
    let stem: Option<&str> = build_dir
        .file_name()
        .and_then(|n: &std::ffi::OsStr| n.to_str())
        .and_then(|n: &str| n.strip_suffix(".build"));
    let Some(stem): Option<&str> = stem else {
        return Ok(None);
    };
    let parent: &Path = match build_dir.parent() {
        Some(p) => p,
        None => return Ok(None),
    };
    for extension in ["exe", "bin", "pyd", "so", "dylib", ""] {
        let candidate: std::path::PathBuf = if extension.is_empty() {
            parent.join(stem)
        } else {
            parent.join(format!("{stem}.{extension}"))
        };
        if candidate.is_file()
            && let Some(bytes) = read_optional(&candidate)?
        {
            return Ok(Some(bytes));
        }
    }
    Ok(None)
}

fn sibling_build_dir(binary: &Path) -> Option<std::path::PathBuf> {
    let stem: &str = binary
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())?;
    let parent: &Path = binary.parent()?;
    let candidate: std::path::PathBuf = parent.join(format!("{stem}.build"));
    candidate.is_dir().then_some(candidate)
}

fn python_abi_from_binary(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.is_empty() {
        return None;
    }
    let detection: Detection = detect_in_bytes(bytes).ok()?;
    match (
        detection.version.python_major,
        detection.version.python_minor,
    ) {
        (Some(major), Some(minor)) => Some((major, minor)),
        _ => None,
    }
}

fn blob_name_from_filename(file_name: &str) -> String {
    let stem: &str = file_name.strip_suffix(".const").unwrap_or(file_name);
    if stem == "__constants" {
        return String::new();
    }
    stem.strip_prefix("module.").unwrap_or(stem).to_owned()
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::Io(e)),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::version_db::{ExactNuitkaVersion, VersionConfidence};

    fn fixture(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/python/nuitka")
            .join(rel)
    }

    #[test]
    fn build_dir_recovers_constants_and_exact_version() {
        let d: NuitkaDecompilation =
            decompile_build_dir(&fixture("module/hello.build")).expect("decompile");
        assert_eq!(d.schema, SCHEMA);
        assert_eq!(d.source_kind, DecompSourceKind::BuildDir);
        assert_eq!(d.version.confidence, VersionConfidence::Exact);
        let exact: &ExactNuitkaVersion = d.version.exact.as_ref().expect("exact");
        assert_eq!((exact.major, exact.minor, exact.micro), (4, 1, 1));
        let pool: &ConstantsPool = d
            .constants
            .pools
            .get("module.hello.const")
            .expect("hello pool");
        assert!(pool.strings.contains("greet"));
        assert!(pool.strings.contains("fib"));
        assert!(d.constants.all_strings.contains("disrobe"));
    }

    #[test]
    fn build_dir_skips_bytecode_const() {
        let d: NuitkaDecompilation =
            decompile_build_dir(&fixture("module/hello.build")).expect("decompile");
        assert!(!d.constants.pools.contains_key(BYTECODE_CONST));
        assert!(d.notes.iter().any(|n: &String| n.contains(BYTECODE_CONST)));
    }

    #[test]
    fn blob_name_from_filename_handles_module_and_global() {
        assert_eq!(blob_name_from_filename("module.hello.const"), "hello");
        assert_eq!(blob_name_from_filename("module.__main__.const"), "__main__");
        assert_eq!(blob_name_from_filename("__constants.const"), "");
    }
}
