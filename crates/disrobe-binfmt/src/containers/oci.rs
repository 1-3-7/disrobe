use serde::{Deserialize, Serialize};

use crate::error::Result;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciDescriptor {
    pub media_type: String,
    pub digest: String,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciManifest {
    pub schema_version: u32,
    pub media_type: Option<String>,
    pub config: OciDescriptor,
    pub layers: Vec<OciDescriptor>,
    pub annotations: Vec<(String, String)>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDescriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct RawManifest {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
    config: RawDescriptor,
    #[serde(default)]
    layers: Vec<RawDescriptor>,
    #[serde(default)]
    annotations: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIndex {
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "mediaType", default)]
    media_type: Option<String>,
    #[serde(default)]
    manifests: Vec<RawIndexEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawIndexEntry {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default, rename = "annotations")]
    _annotations: Option<std::collections::BTreeMap<String, String>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OciIndex {
    pub schema_version: u32,
    pub media_type: Option<String>,
    pub manifests: Vec<OciDescriptor>,
}

pub fn parse_oci_manifest(bytes: &[u8]) -> Result<OciManifest> {
    let raw: RawManifest = serde_json::from_slice(bytes)?;
    let layers: Vec<OciDescriptor> = raw
        .layers
        .into_iter()
        .map(|d: RawDescriptor| OciDescriptor {
            media_type: d.media_type,
            digest: d.digest,
            size: d.size,
        })
        .collect();
    let annotations: Vec<(String, String)> = raw.annotations.into_iter().flatten().collect();
    Ok(OciManifest {
        schema_version: raw.schema_version,
        media_type: raw.media_type,
        config: OciDescriptor {
            media_type: raw.config.media_type,
            digest: raw.config.digest,
            size: raw.config.size,
        },
        layers,
        annotations,
    })
}

pub fn parse_oci_index(bytes: &[u8]) -> Result<OciIndex> {
    let raw: RawIndex = serde_json::from_slice(bytes)?;
    let manifests: Vec<OciDescriptor> = raw
        .manifests
        .into_iter()
        .map(|e: RawIndexEntry| OciDescriptor {
            media_type: e.media_type,
            digest: e.digest,
            size: e.size,
        })
        .collect();
    Ok(OciIndex {
        schema_version: raw.schema_version,
        media_type: raw.media_type,
        manifests,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::error::Error;

    #[test]
    fn parses_minimal_image_manifest() {
        let payload: &str = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:aaa",
                "size": 1024
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": "sha256:bbb",
                    "size": 2048
                }
            ],
            "annotations": {"org.opencontainers.image.source": "https://example"}
        }"#;
        let manifest: OciManifest = parse_oci_manifest(payload.as_bytes()).expect("manifest");
        assert_eq!(manifest.schema_version, 2);
        assert_eq!(manifest.config.digest, "sha256:aaa");
        assert_eq!(manifest.layers.len(), 1);
        assert_eq!(manifest.layers[0].size, 2048);
        assert_eq!(manifest.annotations.len(), 1);
    }

    #[test]
    fn parses_index_with_multi_arch_manifests() {
        let payload: &str = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:xxx", "size": 500},
                {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:yyy", "size": 600}
            ]
        }"#;
        let index: OciIndex = parse_oci_index(payload.as_bytes()).expect("index");
        assert_eq!(index.manifests.len(), 2);
        assert_eq!(index.manifests[1].digest, "sha256:yyy");
    }

    #[test]
    fn errors_on_invalid_json() {
        let err: Error = parse_oci_manifest(b"{not json").unwrap_err();
        assert!(matches!(err, Error::Json(_)));
    }
}
