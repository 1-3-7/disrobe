#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_pass_go::{EmbedFile, GoAnalysis, analyze};

const MEDIA_TYPE_TABLE_NAMES: [&str; 6] = [
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/zip",
    "ppt/handoutMasters/",
    "ppt/tableStyles.xml",
    "xl/drawings/",
    "xl/styles.xml",
];

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
            "required reference file {} is unreadable: {error}. This grader compares recovered \
             bytes against a tracked build input and cannot report a result without it.",
            path.display()
        ),
    }
}

fn committed_tree(root: &Path, subdirectory: &str) -> BTreeMap<String, Vec<u8>> {
    let base: PathBuf = root.join(subdirectory);
    let mut tree: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    let mut stack: Vec<PathBuf> = vec![base.clone()];
    while let Some(directory) = stack.pop() {
        let entries: std::fs::ReadDir = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => panic!(
                "reference tree {} is unreadable: {error}",
                directory.display()
            ),
        };
        for entry in entries {
            let entry: std::fs::DirEntry = entry.expect("reference tree entry");
            let path: PathBuf = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let relative: &Path = path
                .strip_prefix(root)
                .expect("reference file inside the reference root");
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
        "reference tree {} is empty; the grader has no reference to compare against",
        base.display()
    );
    tree
}

fn recovered_by_name(analysis: &GoAnalysis) -> BTreeMap<String, Vec<u8>> {
    analysis
        .embed
        .files
        .iter()
        .filter(|file: &&EmbedFile| !file.is_dir)
        .map(|file: &EmbedFile| (file.name.clone(), file.data.clone()))
        .collect()
}

#[test]
fn wails_embed_recovers_the_committed_frontend_tree_byte_for_byte() {
    let root: PathBuf = repository_root();
    let image_path: PathBuf = root.join("corpus/webview/wails/wvfix.exe");
    let image: Vec<u8> = required_bytes(&image_path);
    let reference: BTreeMap<String, Vec<u8>> = committed_tree(&root, "corpus/webview/wails");

    let expected: BTreeMap<String, Vec<u8>> = reference
        .into_iter()
        .filter_map(|(key, bytes): (String, Vec<u8>)| {
            key.strip_prefix("corpus/webview/wails/")
                .map(|relative: &str| (relative.to_owned(), bytes))
        })
        .filter(|(relative, _): &(String, Vec<u8>)| relative.starts_with("frontend/"))
        .collect();
    assert_eq!(
        expected.len(),
        11,
        "the tracked Wails frontend tree must hold 11 files; found {}",
        expected.len()
    );

    let analysis: GoAnalysis = analyze(&image).expect("analyze the tracked Wails image");
    let recovered: BTreeMap<String, Vec<u8>> = recovered_by_name(&analysis);

    let recovered_names: Vec<&String> = recovered.keys().collect();
    let expected_names: Vec<&String> = expected.keys().collect();
    assert_eq!(
        recovered_names, expected_names,
        "recovered path set must equal the tracked frontend tree exactly"
    );

    let mut identical: usize = 0;
    let mut divergent: Vec<String> = Vec::new();
    for (name, want) in &expected {
        let Some(got): Option<&Vec<u8>> = recovered.get(name) else {
            divergent.push(format!("{name}: absent"));
            continue;
        };
        if got == want {
            identical += 1;
        } else {
            divergent.push(format!(
                "{name}: recovered {} bytes, tracked {} bytes",
                got.len(),
                want.len()
            ));
        }
    }
    assert_eq!(
        identical,
        expected.len(),
        "byte-identical {identical} of {}; divergent: {divergent:?}",
        expected.len()
    );
}

#[test]
fn wails_embed_rejects_the_media_type_string_table() {
    let root: PathBuf = repository_root();
    let image: Vec<u8> = required_bytes(&root.join("corpus/webview/wails/wvfix.exe"));
    let analysis: GoAnalysis = analyze(&image).expect("analyze the tracked Wails image");
    let names: Vec<&str> = analysis
        .embed
        .files
        .iter()
        .map(|file: &EmbedFile| file.name.as_str())
        .collect();

    for entry in MEDIA_TYPE_TABLE_NAMES {
        assert!(
            !names.contains(&entry),
            "the media-type string table entry {entry:?} was reported as an embedded file; \
             recovered set was {names:?}"
        );
    }
}
