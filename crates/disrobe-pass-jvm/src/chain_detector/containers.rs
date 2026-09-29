use std::borrow::Cow;
use std::collections::BTreeMap;

use disrobe_core::chain::detection::TERMINAL_HINT;
use disrobe_core::chain::{
    ChildArtifact, ChildHandle, ChildMaterialization, DetectVerdict, FAMILY_CONTAINER,
};
use disrobe_core::error::{CoreError, Result as CoreResult};

use crate::dex::DEX_MAGIC_PREFIX;
use crate::error::Error;
use crate::jar::{
    JMOD_MAGIC, Jimage, JimageHeader, JimageMembers, JmodExtract, extract_jmod, jimage_members,
    parse_jimage, parse_jimage_header,
};
use crate::oat::{
    DexOptHeader, ODEX_MAGIC, OatEmbeddedDex, OatFile, OdexFile, extract_oat_dex, parse_oat,
    parse_odex, parse_odex_header,
};

use super::PASS_ID;

const TAG_OAT: &str = "android-oat";
const TAG_ODEX: &str = "android-odex";
const TAG_JMOD: &str = "jmod";
const TAG_JIMAGE: &str = "jimage";

const MANIFEST_NAME: &str = "jvm-container.json";
const MANIFEST_SCHEMA: &str = "disrobe.jvm.container/v1";
const EMBEDDED_DEX_NAME: &str = "classes.dex";
const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ZIP_LOCAL_HEADER: &[u8; 4] = b"PK\x03\x04";
const JIMAGE_HEADER_SIZE: u64 = 28;
const JIMAGE_MAJOR_VERSION: u16 = 1;
const CONTAINER_CONFIDENCE: f32 = 0.95;
const CONTAINER_SPECIFICITY: u16 = 20;

#[derive(Debug)]
pub(super) struct ContainerListing<'a> {
    pub(super) members: BTreeMap<String, Cow<'a, [u8]>>,
    pub(super) refusals: Vec<String>,
    pub(super) manifest: serde_json::Value,
}

pub(super) fn is_container_tag(tag: &str) -> bool {
    matches!(tag, TAG_OAT | TAG_ODEX | TAG_JMOD | TAG_JIMAGE)
}

pub(super) fn detect(bytes: &[u8]) -> Option<DetectVerdict> {
    if bytes.len() >= 8 && bytes[..4] == JMOD_MAGIC && &bytes[4..8] == ZIP_LOCAL_HEADER {
        return Some(verdict(
            TAG_JMOD,
            "jmod-magic+zip-local-header",
            "JDK jmod: 'JM' version 1.0 followed by a zip archive".to_owned(),
        ));
    }
    if let Ok(header) = parse_jimage_header(bytes)
        && header.version_major == JIMAGE_MAJOR_VERSION
        && jimage_index_fits(&header, bytes.len())
    {
        return Some(verdict(
            TAG_JIMAGE,
            "jimage-magic+index-bounds",
            format!(
                "JDK jimage {}.{} with {} resource(s)",
                header.version_major, header.version_minor, header.resource_count
            ),
        ));
    }
    if bytes.starts_with(&ODEX_MAGIC)
        && let Ok(header) = parse_odex_header(bytes)
        && odex_dex_slice(bytes, &header).is_some()
    {
        return Some(verdict(
            TAG_ODEX,
            "dey-magic+embedded-dex-magic",
            format!(
                "Dalvik optimized dex (dexopt {}) holding a {}-byte dex",
                version_label(header.version),
                header.dex_length
            ),
        ));
    }
    if bytes.starts_with(ELF_MAGIC)
        && let Ok(oat) = parse_oat(bytes)
    {
        return Some(verdict(
            TAG_OAT,
            "elf-oatdata-symbol+oat-header",
            format!(
                "ART OAT {} for {} declaring {} dex file(s)",
                oat.header.version.digits(),
                oat.instruction_set.label(),
                oat.header.dex_file_count
            ),
        ));
    }
    None
}

fn verdict(tag: &'static str, marker: &'static str, explain: String) -> DetectVerdict {
    DetectVerdict::new(
        PASS_ID,
        tag,
        FAMILY_CONTAINER,
        CONTAINER_CONFIDENCE,
        CONTAINER_SPECIFICITY,
        vec![marker],
        explain,
    )
}

fn jimage_index_fits(header: &JimageHeader, len: usize) -> bool {
    let tables: u64 = u64::from(header.table_length) * 8;
    let index: u64 = JIMAGE_HEADER_SIZE
        + tables
        + u64::from(header.locations_size)
        + u64::from(header.strings_size);
    u64::try_from(len).is_ok_and(|len: u64| index <= len)
}

fn odex_dex_slice<'a>(bytes: &'a [u8], header: &DexOptHeader) -> Option<&'a [u8]> {
    let start: usize = usize::try_from(header.dex_offset).ok()?;
    let len: usize = usize::try_from(header.dex_length).ok()?;
    let dex: &[u8] = bytes.get(start..start.checked_add(len)?)?;
    dex.starts_with(&DEX_MAGIC_PREFIX).then_some(dex)
}

fn version_label(raw: [u8; 4]) -> String {
    String::from_utf8_lossy(&raw[..3]).into_owned()
}

fn container_failure(tag: &str, error: &Error) -> CoreError {
    CoreError::PassFailure(format!(
        "DR-JVM-0912: jvm.classify: {tag} container: {error}"
    ))
}

pub(super) fn listing<'a>(tag: &str, bytes: &'a [u8]) -> CoreResult<ContainerListing<'a>> {
    match tag {
        TAG_JMOD => jmod_listing(bytes),
        TAG_JIMAGE => jimage_listing(bytes),
        TAG_ODEX => odex_listing(bytes),
        TAG_OAT => oat_listing(bytes),
        other => Err(CoreError::PassFailure(format!(
            "DR-JVM-0913: jvm.classify: {other} is not a JVM container format"
        ))),
    }
}

fn jmod_listing(bytes: &[u8]) -> CoreResult<ContainerListing<'static>> {
    let extract: JmodExtract =
        extract_jmod(bytes).map_err(|e: Error| container_failure(TAG_JMOD, &e))?;
    let sections: [(&str, BTreeMap<String, Vec<u8>>); 8] = [
        ("classes", extract.classes),
        ("native_libs", extract.native_libs),
        ("config", extract.config),
        ("bin", extract.bin),
        ("legal", extract.legal),
        ("headers", extract.headers),
        ("man", extract.man),
        ("resources", extract.resources),
    ];
    let mut section_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut members: BTreeMap<String, Cow<'static, [u8]>> = BTreeMap::new();
    for (section, entries) in sections {
        section_counts.insert(section, entries.len());
        for (path, content) in entries {
            members.insert(path, Cow::Owned(content));
        }
    }
    let manifest: serde_json::Value = serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "format": TAG_JMOD,
        "members": members.len(),
        "sections": section_counts,
    });
    Ok(ContainerListing {
        members,
        refusals: Vec::new(),
        manifest,
    })
}

fn jimage_listing(bytes: &[u8]) -> CoreResult<ContainerListing<'_>> {
    let image: Jimage =
        parse_jimage(bytes).map_err(|e: Error| container_failure(TAG_JIMAGE, &e))?;
    let found: JimageMembers<'_> =
        jimage_members(bytes, &image).map_err(|e: Error| container_failure(TAG_JIMAGE, &e))?;
    let refusals: Vec<String> = found
        .compressed
        .iter()
        .map(|name: &String| {
            format!(
                "jimage resource {name} is stored compressed and its decompressor is not \
                 implemented, so it is not emitted"
            )
        })
        .collect();
    let members: BTreeMap<String, Cow<'_, [u8]>> = found
        .members
        .into_iter()
        .map(|(name, content): (String, &[u8])| (name, Cow::Borrowed(content)))
        .collect();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "format": TAG_JIMAGE,
        "version_major": image.header.version_major,
        "version_minor": image.header.version_minor,
        "big_endian": image.endian_big,
        "resource_count": image.header.resource_count,
        "members": members.len(),
        "compressed_not_emitted": found.compressed.len(),
    });
    Ok(ContainerListing {
        members,
        refusals,
        manifest,
    })
}

fn odex_listing(bytes: &[u8]) -> CoreResult<ContainerListing<'_>> {
    let odex: OdexFile = parse_odex(bytes).map_err(|e: Error| container_failure(TAG_ODEX, &e))?;
    let dex: &[u8] = odex_dex_slice(bytes, &odex.header).ok_or_else(|| {
        container_failure(
            TAG_ODEX,
            &Error::OatOffsetOutOfRange {
                offset: odex.header.dex_offset as usize,
                size: bytes.len(),
            },
        )
    })?;
    let mut members: BTreeMap<String, Cow<'_, [u8]>> = BTreeMap::new();
    members.insert(EMBEDDED_DEX_NAME.to_owned(), Cow::Borrowed(dex));
    let manifest: serde_json::Value = serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "format": TAG_ODEX,
        "dexopt_version": version_label(odex.header.version),
        "dex_offset": odex.header.dex_offset,
        "dex_length": odex.header.dex_length,
        "deps_length": odex.header.deps_length,
        "opt_length": odex.header.opt_length,
        "flags": odex.header.flags,
        "class_count": odex.dex.class_descriptors.len(),
        "members": members.len(),
    });
    Ok(ContainerListing {
        members,
        refusals: Vec::new(),
        manifest,
    })
}

fn oat_listing(bytes: &[u8]) -> CoreResult<ContainerListing<'static>> {
    let oat: OatFile = parse_oat(bytes).map_err(|e: Error| container_failure(TAG_OAT, &e))?;
    let mut members: BTreeMap<String, Cow<'static, [u8]>> = BTreeMap::new();
    let mut refusals: Vec<String> = Vec::new();
    let mut locations: Vec<String> = Vec::new();
    match extract_oat_dex(bytes) {
        Ok(embedded) => {
            for dex in embedded {
                let OatEmbeddedDex {
                    location,
                    bytes: dex_bytes,
                    ..
                }: OatEmbeddedDex = dex;
                locations.push(location);
                members.insert(EMBEDDED_DEX_NAME.to_owned(), Cow::Owned(dex_bytes));
            }
        }
        Err(error) => refusals.push(format!("embedded dex not recovered: {error}")),
    }
    let key_values: BTreeMap<&str, &str> = oat
        .header
        .key_value_store
        .iter()
        .map(|(k, v): &(String, String)| (k.as_str(), v.as_str()))
        .collect();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": MANIFEST_SCHEMA,
        "format": TAG_OAT,
        "oat_version": oat.header.version.digits(),
        "instruction_set": oat.instruction_set.label(),
        "dex_file_count": oat.header.dex_file_count,
        "dex_locations": locations,
        "key_value_store": key_values,
        "members": members.len(),
        "refusals": refusals,
    });
    Ok(ContainerListing {
        members,
        refusals,
        manifest,
    })
}

pub(super) fn manifest_bytes(listing: &ContainerListing<'_>) -> CoreResult<Vec<u8>> {
    serde_json::to_vec_pretty(&listing.manifest).map_err(|e: serde_json::Error| {
        CoreError::PassFailure(format!(
            "DR-JVM-0914: jvm.classify: container manifest serialisation: {e}"
        ))
    })
}

pub(super) fn children(tag: &'static str, bytes: &[u8]) -> CoreResult<Vec<ChildArtifact>> {
    let listing: ContainerListing<'_> = listing(tag, bytes)?;
    let manifest: Vec<u8> = manifest_bytes(&listing)?;
    let mut out: Vec<ChildArtifact> = Vec::with_capacity(listing.members.len() + 1);
    for (path, content) in listing.members {
        out.push(ChildArtifact {
            handle: ChildHandle {
                artifact_index: 0,
                relative_path: path,
                hint: Some(tag.to_owned()),
                materialization: ChildMaterialization::default(),
            },
            bytes: content.into_owned(),
        });
    }
    out.push(ChildArtifact {
        handle: ChildHandle {
            artifact_index: 0,
            relative_path: MANIFEST_NAME.to_owned(),
            hint: Some(TERMINAL_HINT.to_owned()),
            materialization: ChildMaterialization::default(),
        },
        bytes: manifest,
    });
    Ok(out)
}
