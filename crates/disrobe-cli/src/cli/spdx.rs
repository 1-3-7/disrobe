use serde::Serialize;

use crate::cli::cyclonedx::{Component, ComponentType};
use crate::cli::structured_document::{
    StructuredDocumentError, to_bounded_pretty_json, validate_utc_timestamp,
};

const SPDX_VERSION: &str = "SPDX-2.3";
const DATA_LICENSE: &str = "CC0-1.0";
const DOCUMENT_ID: &str = "SPDXRef-DOCUMENT";
const DOCUMENT_NAMESPACE_PREFIX: &str = "urn:disrobe:spdx:";
const COMPONENT_ID_PREFIX: &str = "SPDXRef-Component-";
const PACKAGE_MANAGER: &str = "PACKAGE-MANAGER";
const PURL_REFERENCE_TYPE: &str = "purl";
const NOASSERTION: &str = "NOASSERTION";
const IDENTITY_DOMAIN: &[u8] = b"disrobe:spdx-2.3:component:v1\0";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SpdxDocument {
    #[serde(rename = "SPDXID")]
    spdx_id: &'static str,
    spdx_version: &'static str,
    data_license: &'static str,
    name: String,
    document_namespace: String,
    creation_info: CreationInfo,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    document_describes: Vec<String>,
    packages: Vec<Package>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    relationships: Vec<Relationship>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct CreationInfo {
    created: String,
    creators: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Package {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    version_info: Option<String>,
    download_location: &'static str,
    files_analyzed: bool,
    primary_package_purpose: PackagePurpose,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    checksums: Vec<Checksum>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    external_refs: Vec<ExternalReference>,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_info: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum PackagePurpose {
    Application,
    Library,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Checksum {
    algorithm: ChecksumAlgorithm,
    checksum_value: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
enum ChecksumAlgorithm {
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "BLAKE3")]
    Blake3,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalReference {
    #[serde(rename = "referenceCategory")]
    category: &'static str,
    #[serde(rename = "referenceType")]
    kind: &'static str,
    #[serde(rename = "referenceLocator")]
    locator: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Relationship {
    spdx_element_id: String,
    #[serde(rename = "relationshipType")]
    kind: RelationshipType,
    related_spdx_element: String,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RelationshipType {
    Describes,
    Contains,
}

impl SpdxDocument {
    pub(crate) fn from_components(
        name: &str,
        timestamp: &str,
        components: &[Component],
    ) -> Result<Self, StructuredDocumentError> {
        validate_utc_timestamp(timestamp)?;
        let package_ids: Vec<String> = components.iter().map(component_id).collect();
        let packages: Vec<Package> = components
            .iter()
            .zip(&package_ids)
            .map(|(component, id): (&Component, &String)| package_from_component(component, id))
            .collect();
        let root_id: Option<&String> = components
            .iter()
            .position(|component: &Component| {
                component.component_type == ComponentType::Application
            })
            .and_then(|index: usize| package_ids.get(index));
        let document_describes: Vec<String> =
            root_id.iter().map(|id: &&String| (*id).clone()).collect();
        let mut relationships: Vec<Relationship> = Vec::new();
        if let Some(root) = root_id {
            relationships.push(Relationship {
                spdx_element_id: DOCUMENT_ID.to_owned(),
                kind: RelationshipType::Describes,
                related_spdx_element: root.clone(),
            });
            for id in package_ids.iter().filter(|id: &&String| *id != root) {
                relationships.push(Relationship {
                    spdx_element_id: root.clone(),
                    kind: RelationshipType::Contains,
                    related_spdx_element: id.clone(),
                });
            }
        }
        let document_namespace: String = document_namespace(name, timestamp, &package_ids);
        Ok(Self {
            spdx_id: DOCUMENT_ID,
            spdx_version: SPDX_VERSION,
            data_license: DATA_LICENSE,
            name: name.to_owned(),
            document_namespace,
            creation_info: CreationInfo {
                created: timestamp.to_owned(),
                creators: vec![format!("Tool: disrobe-{}", env!("CARGO_PKG_VERSION"))],
            },
            document_describes,
            packages,
            relationships,
        })
    }
}

pub(crate) fn to_pretty_json(document: &SpdxDocument) -> Result<Vec<u8>, StructuredDocumentError> {
    to_bounded_pretty_json(document)
}

fn component_id(component: &Component) -> String {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher.update(IDENTITY_DOMAIN);
    update_hash(&mut hasher, component.name.as_bytes());
    update_optional_hash(&mut hasher, component.version.as_deref());
    update_optional_hash(&mut hasher, component.purl.as_deref());
    update_optional_hash(&mut hasher, component.bom_ref.as_deref());
    for hash in &component.hashes {
        update_hash(&mut hasher, hash.alg.as_bytes());
        update_hash(&mut hasher, hash.content.as_bytes());
    }
    for property in &component.properties {
        update_hash(&mut hasher, property.name.as_bytes());
        update_hash(&mut hasher, property.value.as_bytes());
    }
    format!("{COMPONENT_ID_PREFIX}{}", hasher.finalize().to_hex())
}

fn update_optional_hash(hasher: &mut blake3::Hasher, value: Option<&str>) {
    match value {
        Some(text) => {
            hasher.update(&[1]);
            update_hash(hasher, text.as_bytes());
        }
        None => {
            hasher.update(&[0]);
        }
    }
}

fn update_hash(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn package_from_component(component: &Component, id: &str) -> Package {
    let checksums: Vec<Checksum> = component
        .hashes
        .iter()
        .filter_map(|hash: &crate::cli::cyclonedx::Hash| {
            let algorithm: ChecksumAlgorithm = match hash.alg {
                "SHA-256" => ChecksumAlgorithm::Sha256,
                "BLAKE3" => ChecksumAlgorithm::Blake3,
                _ => return None,
            };
            Some(Checksum {
                algorithm,
                checksum_value: hash.content.clone(),
            })
        })
        .collect();
    let external_refs: Vec<ExternalReference> = component
        .purl
        .iter()
        .map(|purl: &String| ExternalReference {
            category: PACKAGE_MANAGER,
            kind: PURL_REFERENCE_TYPE,
            locator: purl.clone(),
        })
        .collect();
    let source_info: Option<String> = component
        .properties
        .iter()
        .find(|property: &&crate::cli::cyclonedx::Property| {
            property.name == "cargo-auditable:source"
        })
        .map(|property: &crate::cli::cyclonedx::Property| property.value.clone());
    Package {
        spdx_id: id.to_owned(),
        name: component.name.clone(),
        version_info: component.version.clone(),
        download_location: NOASSERTION,
        files_analyzed: false,
        primary_package_purpose: match component.component_type {
            ComponentType::Application => PackagePurpose::Application,
            ComponentType::Library => PackagePurpose::Library,
        },
        checksums,
        external_refs,
        source_info,
    }
}

fn document_namespace(name: &str, timestamp: &str, package_ids: &[String]) -> String {
    let mut hasher: blake3::Hasher = blake3::Hasher::new();
    hasher.update(b"disrobe:spdx-2.3:document:v1\0");
    update_hash(&mut hasher, name.as_bytes());
    update_hash(&mut hasher, timestamp.as_bytes());
    update_hash(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    for id in package_ids {
        update_hash(&mut hasher, id.as_bytes());
    }
    format!("{DOCUMENT_NAMESPACE_PREFIX}{}", hasher.finalize().to_hex())
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn zero_component_document_serializes_without_relationships() {
        let document: SpdxDocument =
            SpdxDocument::from_components("empty", "2026-08-12T12:34:56Z", &[])
                .expect("valid empty document");
        let value: serde_json::Value =
            serde_json::to_value(document).expect("serialize empty document");
        assert_eq!(value["packages"], serde_json::json!([]));
        assert!(value.get("documentDescribes").is_none());
        assert!(value.get("relationships").is_none());
    }
}
