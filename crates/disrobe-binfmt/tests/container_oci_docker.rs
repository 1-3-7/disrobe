#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use disrobe_binfmt::containers::docker::{DockerManifest, parse_docker_manifest};
use disrobe_binfmt::containers::oci::{OciIndex, OciManifest, parse_oci_index, parse_oci_manifest};

#[test]
fn oci_image_manifest_with_two_layers_round_trip() {
    let payload: &str = r#"{
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": "sha256:cfg",
            "size": 1234
        },
        "layers": [
            {"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": "sha256:l1", "size": 10},
            {"mediaType": "application/vnd.oci.image.layer.v1.tar+zstd", "digest": "sha256:l2", "size": 20}
        ]
    }"#;
    let manifest: OciManifest = parse_oci_manifest(payload.as_bytes()).expect("manifest");
    assert_eq!(manifest.schema_version, 2);
    assert_eq!(manifest.layers.len(), 2);
    assert_eq!(manifest.layers[1].digest, "sha256:l2");
}

#[test]
fn oci_index_with_multi_platform_manifests() {
    let payload: &str = r#"{
        "schemaVersion": 2,
        "manifests": [
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:amd64", "size": 1000},
            {"mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": "sha256:arm64", "size": 2000}
        ]
    }"#;
    let index: OciIndex = parse_oci_index(payload.as_bytes()).expect("index");
    assert_eq!(index.manifests.len(), 2);
}

#[test]
fn docker_image_tarball_manifest_layers_extracted() {
    let payload: &str = r#"[
        {
            "Config": "sha256-config.json",
            "RepoTags": ["myapp:1.0", "myapp:latest"],
            "Layers": ["layer1/layer.tar", "layer2/layer.tar", "layer3/layer.tar"]
        }
    ]"#;
    let manifests: Vec<DockerManifest> = parse_docker_manifest(payload.as_bytes()).expect("docker");
    assert_eq!(manifests.len(), 1);
    assert_eq!(manifests[0].layers.len(), 3);
    assert_eq!(manifests[0].repo_tags.len(), 2);
}
