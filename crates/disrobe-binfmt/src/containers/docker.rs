use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DockerManifest {
    pub config: String,
    pub repo_tags: Vec<String>,
    pub layers: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct RawDockerManifest {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags", default)]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

pub fn parse_docker_manifest(bytes: &[u8]) -> Result<Vec<DockerManifest>> {
    let raw: Vec<RawDockerManifest> =
        serde_json::from_slice(bytes).map_err(|e: serde_json::Error| Error::Json(e))?;
    Ok(raw
        .into_iter()
        .map(|m: RawDockerManifest| DockerManifest {
            config: m.config,
            repo_tags: m.repo_tags.unwrap_or_default(),
            layers: m.layers,
        })
        .collect())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_minimal_docker_manifest_array() {
        let payload: &str = r#"[
            {
                "Config": "abc.json",
                "RepoTags": ["alpine:latest"],
                "Layers": ["layer1/layer.tar", "layer2/layer.tar"]
            }
        ]"#;
        let manifests: Vec<DockerManifest> =
            parse_docker_manifest(payload.as_bytes()).expect("docker");
        assert_eq!(manifests.len(), 1);
        let m: &DockerManifest = &manifests[0];
        assert_eq!(m.config, "abc.json");
        assert_eq!(m.layers.len(), 2);
        assert_eq!(m.repo_tags, vec!["alpine:latest".to_owned()]);
    }

    #[test]
    fn missing_repotags_defaults_to_empty() {
        let payload: &str = r#"[{"Config": "x.json", "Layers": ["a"]}]"#;
        let manifests: Vec<DockerManifest> =
            parse_docker_manifest(payload.as_bytes()).expect("docker");
        assert!(manifests[0].repo_tags.is_empty());
    }

    #[test]
    fn errors_on_invalid_json() {
        let err: Error = parse_docker_manifest(b"not json").unwrap_err();
        assert!(matches!(err, Error::Json(_)));
    }
}
