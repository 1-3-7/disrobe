#![cfg(feature = "chain")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::chain::{ChildArtifact, Pass};
use disrobe_core::{Artifact, Rung};
use disrobe_pass_go::chain_detector::GO_PASS;

fn repository_root() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root
}

fn required_bytes(path: &Path) -> Vec<u8> {
    match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => panic!(
            "required reference file {} is unreadable: {error}",
            path.display()
        ),
    }
}

fn reference_tree(root: &Path, base: &str) -> BTreeMap<String, Vec<u8>> {
    let start: PathBuf = root.join(base);
    let mut tree: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![start.clone()];
    while let Some(directory) = stack.pop() {
        let entries: std::fs::ReadDir = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => panic!("{} is unreadable: {error}", directory.display()),
        };
        for entry in entries {
            let entry: std::fs::DirEntry = entry.expect("reference entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative: &Path = path.strip_prefix(root).expect("inside the reference root");
            let key: String = relative
                .components()
                .map(|component: std::path::Component<'_>| {
                    component.as_os_str().to_string_lossy().into_owned()
                })
                .collect::<Vec<String>>()
                .join("/");
            tree.insert(key, required_bytes(&path));
        }
    }
    assert!(
        !tree.is_empty(),
        "{} carries no reference files",
        start.display()
    );
    tree
}

fn carved_children(image: &Path) -> BTreeMap<String, Vec<u8>> {
    let bytes: Vec<u8> = required_bytes(image);
    let artifact: Artifact = Artifact::new(Rung::Raw, bytes, [0u8; 32]);
    let children: Vec<ChildArtifact> = GO_PASS
        .extract_children(&artifact)
        .expect("the registered go pass must extract children from a real go image");
    children
        .into_iter()
        .filter_map(|child: ChildArtifact| {
            let name: String = child.handle.relative_path.clone();
            name.strip_prefix("embed/")
                .map(|relative: &str| (relative.to_owned(), child.bytes.clone()))
        })
        .collect()
}

#[test]
fn the_chain_emits_every_embedded_wails_frontend_file_including_the_empty_one() {
    let root: PathBuf = repository_root();
    let reference: BTreeMap<String, Vec<u8>> = reference_tree(&root, "corpus/webview/wails")
        .into_iter()
        .filter_map(|(key, bytes): (String, Vec<u8>)| {
            key.strip_prefix("corpus/webview/wails/")
                .map(|relative: &str| (relative.to_owned(), bytes))
        })
        .filter(|(relative, _): &(String, Vec<u8>)| relative.starts_with("frontend/"))
        .collect();
    assert_eq!(reference.len(), 11, "the tracked Wails frontend tree size");

    let carved: BTreeMap<String, Vec<u8>> =
        carved_children(&root.join("corpus/webview/wails/wvfix.exe"));

    assert_eq!(
        carved.keys().collect::<Vec<&String>>(),
        reference.keys().collect::<Vec<&String>>(),
        "the chain must emit exactly the tracked frontend tree, so what `disrobe auto` reaches is \
         no smaller than what the dedicated command writes"
    );
    for (name, want) in &reference {
        assert_eq!(
            carved.get(name),
            Some(want),
            "{name} carved through the chain must be byte-identical to the tracked file"
        );
    }
    assert_eq!(
        carved.get("frontend/dist/empty.txt").map(Vec::len),
        Some(0),
        "a zero-length member must reach the chain as an empty child rather than be dropped"
    );
}

#[test]
fn the_chain_emits_every_embedded_file_of_the_matrix_image_including_the_empty_one() {
    let root: PathBuf = repository_root();
    let fixtures: PathBuf = root.join("crates/disrobe-pass-go/tests/fixtures/goembed");
    let reference: BTreeMap<String, Vec<u8>> = reference_tree(&fixtures, "assets");
    assert_eq!(reference.len(), 7, "the tracked reference tree size");

    let carved: BTreeMap<String, Vec<u8>> = carved_children(&fixtures.join("goembed_pe64_le.exe"));
    assert_eq!(
        carved.keys().collect::<Vec<&String>>(),
        reference.keys().collect::<Vec<&String>>(),
        "the chain must emit exactly the tracked reference tree"
    );
    for (name, want) in &reference {
        assert_eq!(
            carved.get(name),
            Some(want),
            "{name} carved through the chain must be byte-identical"
        );
    }
    assert_eq!(
        carved.get("assets/empty.txt").map(Vec::len),
        Some(0),
        "a zero-length member must reach the chain as an empty child"
    );
}
