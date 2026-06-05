use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantBlobEntry {
    pub source_file: String,
    pub blob_name: String,
    pub blob_size: u64,
    pub input_size: u64,
}

impl ConstantBlobEntry {
    #[must_use]
    #[inline]
    pub fn is_bytecode(&self) -> bool {
        self.blob_name == ".bytecode"
    }

    #[must_use]
    #[inline]
    pub const fn is_global_pool(&self) -> bool {
        self.blob_name.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstantManifest {
    pub entries: Vec<ConstantBlobEntry>,
    pub total: u64,
}

impl ConstantManifest {
    #[must_use]
    pub fn by_blob_name(&self, name: &str) -> Option<&ConstantBlobEntry> {
        self.entries
            .iter()
            .find(|e: &&ConstantBlobEntry| e.blob_name == name)
    }

    #[must_use]
    pub fn by_source_file(&self, source_file: &str) -> Option<&ConstantBlobEntry> {
        self.entries
            .iter()
            .find(|e: &&ConstantBlobEntry| e.source_file == source_file)
    }

    #[must_use]
    pub fn module_entries(&self) -> Vec<&ConstantBlobEntry> {
        self.entries
            .iter()
            .filter(|e: &&ConstantBlobEntry| !e.is_bytecode() && !e.is_global_pool())
            .collect()
    }
}

#[derive(Debug, Clone, Deserialize)]
struct RawBlobEntry {
    blob_name: String,
    blob_size: u64,
    input_size: u64,
}

pub fn parse_constant_manifest(bytes: &[u8]) -> Result<ConstantManifest> {
    let raw: BTreeMap<String, serde_json::Value> = serde_json::from_slice(bytes)
        .map_err(|e: serde_json::Error| Error::ConstManifestMalformed(e.to_string()))?;

    let total_value: &serde_json::Value = raw
        .get("total")
        .ok_or_else(|| Error::ConstManifestMalformed("missing \"total\" field".to_owned()))?;
    let total: u64 = total_value.as_u64().ok_or_else(|| {
        Error::ConstManifestMalformed("\"total\" field is not an unsigned integer".to_owned())
    })?;

    let mut entries: Vec<ConstantBlobEntry> = Vec::with_capacity(raw.len().saturating_sub(1));
    for (source_file, value) in &raw {
        if source_file == "total" {
            continue;
        }
        let raw_entry: RawBlobEntry =
            serde_json::from_value(value.clone()).map_err(|e: serde_json::Error| {
                Error::ConstManifestMalformed(format!("entry {source_file:?}: {e}"))
            })?;
        entries.push(ConstantBlobEntry {
            source_file: source_file.clone(),
            blob_name: raw_entry.blob_name,
            blob_size: raw_entry.blob_size,
            input_size: raw_entry.input_size,
        });
    }

    Ok(ConstantManifest { entries, total })
}

pub fn parse_constant_manifest_from_file(path: &Path) -> Result<ConstantManifest> {
    let bytes: Vec<u8> = std::fs::read(path)?;
    parse_constant_manifest(&bytes)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const MODULE_MANIFEST: &[u8] =
        include_bytes!("../../../corpus/python/nuitka/module/hello.build/blobs/__constant.txt");
    const CONSOLE_MANIFEST: &[u8] = include_bytes!(
        "../../../corpus/python/nuitka/console-disable/hello.build/blobs/__constant.txt"
    );

    #[test]
    fn module_manifest_parses_with_expected_entries() {
        let m: ConstantManifest = parse_constant_manifest(MODULE_MANIFEST).expect("parse");
        assert_eq!(m.total, 122);
        assert_eq!(m.entries.len(), 3);

        let hello: &ConstantBlobEntry = m.by_blob_name("hello").expect("hello entry");
        assert_eq!(hello.source_file, "module.hello.const");
        assert_eq!(hello.input_size, 430);
        assert_eq!(hello.blob_size, 186);

        let global: &ConstantBlobEntry = m.by_blob_name("").expect("global entry");
        assert_eq!(global.source_file, "__constants.const");
        assert_eq!(global.input_size, 2185);
        assert!(global.is_global_pool());

        let bytecode: &ConstantBlobEntry = m.by_blob_name(".bytecode").expect("bytecode entry");
        assert!(bytecode.is_bytecode());
    }

    #[test]
    fn console_manifest_parses() {
        let m: ConstantManifest = parse_constant_manifest(CONSOLE_MANIFEST).expect("parse");
        let main: &ConstantBlobEntry = m.by_blob_name("__main__").expect("__main__ entry");
        assert_eq!(main.source_file, "module.__main__.const");
        assert_eq!(main.input_size, 353);
    }

    #[test]
    fn module_entries_excludes_bytecode_and_global() {
        let m: ConstantManifest = parse_constant_manifest(MODULE_MANIFEST).expect("parse");
        let modules: Vec<&ConstantBlobEntry> = m.module_entries();
        assert_eq!(modules.len(), 1);
        assert_eq!(modules[0].blob_name, "hello");
    }

    #[test]
    fn missing_total_is_malformed() {
        let bad: &[u8] = br#"{"x.const": {"blob_name": "x", "blob_size": 1, "input_size": 2}}"#;
        assert!(matches!(
            parse_constant_manifest(bad),
            Err(Error::ConstManifestMalformed(_))
        ));
    }

    #[test]
    fn non_object_entry_is_malformed() {
        let bad: &[u8] = br#"{"x.const": 7, "total": 1}"#;
        assert!(matches!(
            parse_constant_manifest(bad),
            Err(Error::ConstManifestMalformed(_))
        ));
    }

    #[test]
    fn non_integer_total_is_malformed() {
        let bad: &[u8] = br#"{"total": "nope"}"#;
        assert!(matches!(
            parse_constant_manifest(bad),
            Err(Error::ConstManifestMalformed(_))
        ));
    }
}
