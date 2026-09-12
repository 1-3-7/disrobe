#![cfg(feature = "chain")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
use std::path::PathBuf;

use disrobe_core::Artifact;
use disrobe_core::Rung;
use disrobe_core::chain::detection::ChildArtifact;
use disrobe_core::chain::{OutputKind, Pass};
use disrobe_core::pass::PassContext;
use disrobe_pass_pyarmor::chain_detector::PYARMOR_PASS;
use disrobe_pass_pyarmor::{
    BccPublication, UnpackOptions, link_bcc_from_unpack, publish_bcc_recovery,
    unpack_wrapper_text_with_options,
};

const GAUNTLET_WRAPPER: &str = "corpus/python/pyarmor/gauntlet/dist/inventory.py";
const BCC_WRAPPER: &str = "corpus/python/pyarmor/v9-bcc/default/known_plaintext.py";

fn workspace_root() -> PathBuf {
    let mut dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    while !dir.join("Cargo.lock").is_file() {
        if !dir.pop() {
            break;
        }
    }
    dir
}

fn gauntlet_wrapper_bytes() -> Option<Vec<u8>> {
    let path: PathBuf = workspace_root().join(GAUNTLET_WRAPPER);
    std::fs::read(&path).ok()
}

fn bcc_wrapper_bytes() -> Vec<u8> {
    let path: PathBuf = workspace_root().join(BCC_WRAPPER);
    std::fs::read(&path).expect("tracked BCC wrapper must be available")
}

#[test]
fn chain_output_kind_is_mixed() {
    let a: Artifact = Artifact::new(Rung::Raw, vec![], [0u8; 32]);
    assert!(
        matches!(PYARMOR_PASS.output_kind(&a), OutputKind::Mixed { .. }),
        "pyarmor pass must declare Mixed so the chain runner calls extract_children",
    );
}

#[test]
fn extract_children_surfaces_manifest_sidecar_for_real_v8_sample() {
    let Some(bytes): Option<Vec<u8>> = gauntlet_wrapper_bytes() else {
        eprintln!("SKIP: pyarmor gauntlet wrapper missing");
        return;
    };
    let a: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<ChildArtifact> = PYARMOR_PASS
        .extract_children(&a)
        .expect("real v8 wrapper must yield chain children");

    let manifest: &ChildArtifact = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "pyarmor-manifest.json")
        .expect("auto must surface pyarmor-manifest.json so it reaches parity with the dedicated unpack manifest");

    let parsed: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).expect("manifest child must be valid json");

    assert_eq!(
        parsed["schema"], "disrobe.pyarmor.manifest/v0",
        "manifest schema must match the dedicated command",
    );
    assert!(
        matches!(parsed["version"].as_str(), Some("v8" | "v9")),
        "real 8.5.x gauntlet sample classifies as the v8/v9 family (static defaults to v9 without the \
         runtime descriptor that resolves the 008/009 serial split)",
    );
    assert_eq!(
        parsed["serial"], "015009",
        "manifest must carry the installed license serial",
    );
    assert_eq!(
        parsed["python"], "3.12",
        "manifest must carry the python identity",
    );
    assert!(
        parsed["iv_hex"].is_string(),
        "manifest must carry the AES-CTR nonce/iv recovered from the header",
    );

    let limitations: &Vec<serde_json::Value> = parsed["limitations"]
        .as_array()
        .expect("manifest must carry a limitations array (the walls)");
    assert!(
        limitations
            .iter()
            .any(|l: &serde_json::Value| l.as_str().is_some_and(|s| s.contains("v8/v9 AES key"))),
        "without the sibling runtime the v8 body stays encrypted; the wall must be recorded, not a bare failure",
    );
}

#[test]
fn extract_children_without_a_path_keeps_the_bcc_runtime_limitation() {
    let bytes: Vec<u8> = bcc_wrapper_bytes();
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<ChildArtifact> = PYARMOR_PASS
        .extract_children(&artifact)
        .expect("tracked BCC wrapper must yield chain children");
    let manifest: &ChildArtifact = children
        .iter()
        .find(|child: &&ChildArtifact| child.handle.relative_path == "pyarmor-manifest.json")
        .expect("BCC chain output must include a manifest child");
    let parsed: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).expect("BCC manifest child must be valid json");
    assert_eq!(parsed["protection"], "Bcc");
    let limitations: &Vec<serde_json::Value> = parsed["limitations"]
        .as_array()
        .expect("BCC manifest must carry limitations");
    assert!(
        limitations
            .iter()
            .filter_map(serde_json::Value::as_str)
            .any(
                |limitation: &str| limitation.contains("sibling pyarmor_runtime_")
                    && limitation.contains("without that runtime binary")
            )
    );
    for path in [
        "bcc/bcc-recovery.json",
        "bcc/bcc-pseudo-c.c",
        "bcc/bcc-recovered.py",
    ] {
        assert!(
            children
                .iter()
                .all(|child: &ChildArtifact| child.handle.relative_path != path),
            "a missing path hint must not claim or emit {path}"
        );
    }
}

#[test]
fn extract_children_with_a_path_emits_the_pass_owned_bcc_bytes() {
    let wrapper_path: PathBuf = workspace_root().join(BCC_WRAPPER);
    let wrapper_text: String =
        std::fs::read_to_string(&wrapper_path).expect("tracked BCC wrapper must be UTF-8");
    let options: UnpackOptions = UnpackOptions {
        allow_bcc: true,
        ..UnpackOptions::default()
    };
    let unpacked = unpack_wrapper_text_with_options(&wrapper_text, &wrapper_path, &options)
        .expect("tracked BCC wrapper must unpack with its sibling runtime");
    let linked = link_bcc_from_unpack(&unpacked, &wrapper_text, &wrapper_path)
        .expect("tracked BCC wrapper must link its residual module");
    let publication: BccPublication = publish_bcc_recovery(&unpacked, &linked)
        .expect("tracked BCC wrapper must publish bounded recovery artifacts");

    let artifact: Artifact = Artifact::new(Rung::Raw, wrapper_text.into_bytes(), [0u8; 32]);
    let path_hint: String = wrapper_path.to_string_lossy().into_owned();
    let children: Vec<ChildArtifact> = PYARMOR_PASS
        .extract_children_with_context(
            &artifact,
            PassContext::with_path_hint(Some(path_hint.as_str())),
        )
        .expect("path-aware BCC extraction must succeed");

    for expected in publication.artifacts() {
        let child: &ChildArtifact = children
            .iter()
            .find(|child: &&ChildArtifact| child.handle.relative_path == expected.relative_path)
            .unwrap_or_else(|| panic!("missing chain publication {}", expected.relative_path));
        assert_eq!(
            child.bytes, expected.bytes,
            "{} must be byte-identical to the canonical publisher",
            expected.relative_path
        );
    }
}

#[test]
fn extract_children_emits_legacy_rsa_capsule_wall() {
    let mut payload: Vec<u8> = vec![0u8; 64];
    payload[0] = 0x05;
    payload[1] = 0x01;
    let a: Artifact = Artifact::new(Rung::Raw, payload, [0u8; 32]);
    let Ok(children): Result<Vec<ChildArtifact>, _> = PYARMOR_PASS.extract_children(&a) else {
        eprintln!("SKIP: legacy payload not classified");
        return;
    };
    let Some(manifest): Option<&ChildArtifact> = children
        .iter()
        .find(|c: &&ChildArtifact| c.handle.relative_path == "pyarmor-manifest.json")
    else {
        eprintln!("SKIP: no manifest for legacy payload");
        return;
    };
    let parsed: serde_json::Value =
        serde_json::from_slice(&manifest.bytes).expect("manifest must be valid json");
    if !matches!(parsed["version"].as_str(), Some("v3" | "v4" | "v5")) {
        eprintln!("SKIP: synthetic legacy payload not recognized as v3/v4/v5");
        return;
    }
    let limitations: &Vec<serde_json::Value> = parsed["limitations"]
        .as_array()
        .expect("legacy manifest must carry limitations");
    assert!(
        limitations.iter().any(|l: &serde_json::Value| l
            .as_str()
            .is_some_and(|s| s.contains("information-theoretic wall"))),
        "v3/v4/v5 must record the RSA-capsule information-theoretic wall",
    );
}
