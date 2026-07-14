use std::collections::BTreeMap;
use std::path::Path;

use serde::de::{IgnoredAny, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{Error, Result};

pub(crate) const MAX_CONSTANT_MANIFEST_BYTES: u64 = 64 * 1024 * 1024;
const MAX_CONSTANT_MANIFEST_ENTRIES: usize = 4_096;
const MAX_CONSTANT_MANIFEST_MEMBERS: usize = MAX_CONSTANT_MANIFEST_ENTRIES + 1usize;

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
    validate_manifest_size(bytes.len())?;
    let member_count: usize = manifest_member_count(bytes)?;
    if member_count > MAX_CONSTANT_MANIFEST_MEMBERS {
        return Err(Error::ConstManifestTooManyEntries {
            count: member_count,
            max_count: MAX_CONSTANT_MANIFEST_MEMBERS,
        });
    }
    let raw: RawManifest = serde_json::from_slice(bytes)
        .map_err(|e: serde_json::Error| Error::ConstManifestMalformed(e.to_string()))?;

    let entries: Vec<ConstantBlobEntry> = raw
        .entries
        .into_iter()
        .map(
            |(source_file, raw_entry): (String, RawBlobEntry)| ConstantBlobEntry {
                source_file,
                blob_name: raw_entry.blob_name,
                blob_size: raw_entry.blob_size,
                input_size: raw_entry.input_size,
            },
        )
        .collect();

    Ok(ConstantManifest {
        entries,
        total: raw.total,
    })
}

pub fn parse_constant_manifest_from_file(path: &Path) -> Result<ConstantManifest> {
    let bytes: Vec<u8> =
        crate::decompile::read_required_file_bounded(path, MAX_CONSTANT_MANIFEST_BYTES)?;
    parse_constant_manifest(&bytes)
}

struct RawManifest {
    entries: BTreeMap<String, RawBlobEntry>,
    total: u64,
}

struct ManifestMemberCount(usize);

impl<'de> Deserialize<'de> for ManifestMemberCount {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(ManifestMemberCountVisitor)
    }
}

struct ManifestMemberCountVisitor;

impl<'de> Visitor<'de> for ManifestMemberCountVisitor {
    type Value = ManifestMemberCount;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a constants manifest object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut count: usize = 0usize;
        while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {
            count = count.checked_add(1usize).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("constant manifest member count overflow")
            })?;
        }
        Ok(ManifestMemberCount(count))
    }
}

fn manifest_member_count(bytes: &[u8]) -> Result<usize> {
    let member_count: ManifestMemberCount = serde_json::from_slice(bytes)
        .map_err(|error: serde_json::Error| Error::ConstManifestMalformed(error.to_string()))?;
    Ok(member_count.0)
}

impl<'de> Deserialize<'de> for RawManifest {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(RawManifestVisitor)
    }
}

struct RawManifestVisitor;

impl<'de> Visitor<'de> for RawManifestVisitor {
    type Value = RawManifest;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a constants manifest object")
    }

    fn visit_map<A>(self, mut map: A) -> core::result::Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut count: usize = 0usize;
        let mut total: Option<u64> = None;
        let mut entries: BTreeMap<String, RawBlobEntry> = BTreeMap::new();
        while let Some(source_file) = map.next_key::<String>()? {
            count = count.checked_add(1usize).ok_or_else(|| {
                <A::Error as serde::de::Error>::custom("constant manifest member count overflow")
            })?;
            if count > MAX_CONSTANT_MANIFEST_MEMBERS {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "constant manifest has {count} object members, above the {MAX_CONSTANT_MANIFEST_MEMBERS} limit"
                )));
            }
            if source_file == "total" {
                let value: u64 = map.next_value()?;
                if total.replace(value).is_some() {
                    return Err(<A::Error as serde::de::Error>::custom(
                        "duplicate \"total\" field",
                    ));
                }
                continue;
            }
            let raw_entry: RawBlobEntry = map.next_value()?;
            if entries.insert(source_file.clone(), raw_entry).is_some() {
                return Err(<A::Error as serde::de::Error>::custom(format!(
                    "duplicate entry {source_file:?}"
                )));
            }
        }
        let total: u64 = total
            .ok_or_else(|| <A::Error as serde::de::Error>::custom("missing \"total\" field"))?;
        Ok(RawManifest { entries, total })
    }
}

fn validate_manifest_size(bytes: usize) -> Result<()> {
    let bytes: u64 = u64::try_from(bytes).map_or(u64::MAX, |value: u64| value);
    if bytes > MAX_CONSTANT_MANIFEST_BYTES {
        return Err(Error::InputTooLarge {
            resource: "constant manifest",
            bytes,
            max_bytes: MAX_CONSTANT_MANIFEST_BYTES,
        });
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::fmt::Write as _;

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

    #[test]
    fn manifest_member_cap_rejects_before_materialization() {
        let mut manifest: String = String::from("{\"total\":0");
        for index in 0usize..=MAX_CONSTANT_MANIFEST_ENTRIES {
            write!(
                manifest,
                ",\"module_{index}.const\":{{\"blob_name\":\"module_{index}\",\"blob_size\":0,\"input_size\":0}}"
            )
            .expect("write manifest entry");
        }
        manifest.push('}');

        assert!(matches!(
            parse_constant_manifest(manifest.as_bytes()),
            Err(Error::ConstManifestTooManyEntries { count, max_count })
                if count == MAX_CONSTANT_MANIFEST_MEMBERS + 1usize
                    && max_count == MAX_CONSTANT_MANIFEST_MEMBERS
        ));
    }

    #[test]
    fn manifest_byte_cap_rejects_before_deserialization() {
        let bytes: usize =
            usize::try_from(MAX_CONSTANT_MANIFEST_BYTES + 1u64).expect("manifest cap fits usize");
        assert!(matches!(
            validate_manifest_size(bytes),
            Err(Error::InputTooLarge { resource, bytes: actual, max_bytes })
                if resource == "constant manifest"
                    && actual == MAX_CONSTANT_MANIFEST_BYTES + 1u64
                    && max_bytes == MAX_CONSTANT_MANIFEST_BYTES
        ));
    }

    #[test]
    fn manifest_file_reader_rejects_a_bounded_read() {
        let dir: std::path::PathBuf = std::env::temp_dir().join(format!(
            "disrobe-nuitka-manifest-reader-cap-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temporary directory");
        let path: std::path::PathBuf = dir.join("__constant.txt");
        std::fs::write(&path, b"four").expect("write manifest");

        assert!(matches!(
            crate::decompile::read_required_file_bounded(&path, 3u64),
            Err(Error::ArtifactTooLarge { path: actual_path, bytes, max_bytes })
                if actual_path == path
                    && bytes == 4u64
                    && max_bytes == 3u64
        ));

        std::fs::remove_dir_all(&dir).expect("remove temporary directory");
    }
}
