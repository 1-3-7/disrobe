#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};

use disrobe_pass_go::{EmbedDigestFamily, EmbedFile, EmbedMap, GoAnalysis, analyze};

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
            "required reference image {} is unreadable: {error}",
            path.display()
        ),
    }
}

fn sole_map(analysis: &GoAnalysis, image: &str) -> EmbedMap {
    assert_eq!(
        analysis.embed.maps.len(),
        1,
        "{image} must yield exactly one embed map; got {:?}",
        analysis.embed.maps
    );
    analysis.embed.maps[0].clone()
}

#[test]
fn the_tracked_go_images_resolve_one_digest_construction_for_every_file() {
    let root: PathBuf = repository_root();
    let cases: [(&str, PathBuf, usize, usize); 2] = [
        (
            "wvfix.exe",
            root.join("corpus/webview/wails/wvfix.exe"),
            11,
            4,
        ),
        (
            "hello_embed.exe",
            root.join("crates/disrobe-pass-go/tests/fixtures/hello_embed.exe"),
            2,
            1,
        ),
    ];

    let mut resolved: Vec<EmbedDigestFamily> = Vec::new();
    for (label, path, files, directories) in cases {
        let bytes: Vec<u8> = required_bytes(&path);
        let analysis: GoAnalysis = analyze(&bytes).expect("analyze the tracked image");
        let map: EmbedMap = sole_map(&analysis, label);
        assert_eq!(map.file_count, files, "{label} file count");
        assert_eq!(map.directory_count, directories, "{label} directory count");
        let family: EmbedDigestFamily = map.digest_family.unwrap_or_else(|| {
            panic!(
                "{label} produced no digest family that verifies all {files} files; \
                 the compiler digest could not be reproduced by any candidate"
            )
        });
        assert_eq!(
            map.verified_files,
            files,
            "{label} verified {} of {files} files under {}",
            map.verified_files,
            family.label()
        );
        let unverified: Vec<&str> = analysis
            .embed
            .files
            .iter()
            .filter(|file: &&EmbedFile| !file.is_dir && !file.digest_verified)
            .map(|file: &EmbedFile| file.name.as_str())
            .collect();
        assert!(
            unverified.is_empty(),
            "{label} reported unverified files: {unverified:?}"
        );
        resolved.push(family);
    }

    assert_eq!(
        resolved[0], resolved[1],
        "both tracked images were built by go1.26.3 and must resolve the same construction"
    );
    assert_eq!(
        resolved[0],
        EmbedDigestFamily::Sha256LowByte,
        "the go1.26.3 toolchain digest family changed; measured {} ({})",
        resolved[0].label(),
        resolved[0].toolchain_range()
    );
}
