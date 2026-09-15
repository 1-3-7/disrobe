#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::fs;
use std::path::{Path, PathBuf};

const ASSETS: [&str; 3] = ["recovery.svg", "python-versions.svg", "architecture.svg"];

const REQUIRED_CANVAS: &str = "#111111";
const REQUIRED_TEXT: &str = "#f5f5f5";

fn workspace_root() -> PathBuf {
    let manifest: &str = env!("CARGO_MANIFEST_DIR");
    Path::new(manifest)
        .parent()
        .expect("xtask manifest dir has a parent")
        .to_path_buf()
}

fn assets_dir() -> PathBuf {
    workspace_root().join("docs").join("assets")
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e: std::io::Error| {
        panic!("reading {}: {e}", path.display());
    })
}

#[test]
fn committed_graphs_exist_and_are_lf_only() {
    let dir: PathBuf = assets_dir();
    for name in ASSETS {
        let path: PathBuf = dir.join(name);
        assert!(path.is_file(), "missing committed graph {}", path.display());
        let bytes: Vec<u8> = fs::read(&path).expect("read svg bytes");
        assert!(
            !bytes.contains(&b'\r'),
            "{} contains a CR byte; SVG output must be LF-only",
            path.display()
        );
    }
}

#[test]
fn committed_graphs_are_well_formed_svg() {
    let dir: PathBuf = assets_dir();
    for name in ASSETS {
        let body: String = read(&dir.join(name));
        assert!(
            body.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<svg "),
            "{name} missing the XML declaration / <svg> root"
        );
        assert!(body.trim_end().ends_with("</svg>"), "{name} missing </svg>");
        assert!(
            !body.contains("font-family=\"\""),
            "{name} has an empty/broken font-family attribute (quoting bug)"
        );
        let opens: usize = body.matches("<rect").count();
        assert!(opens > 0, "{name} renders no rects; generator likely broke");
        let open_tags: usize = body.matches("<text").count();
        let close_tags: usize = body.matches("</text>").count();
        assert_eq!(
            open_tags, close_tags,
            "{name} has unbalanced <text> tags ({open_tags} open, {close_tags} close)"
        );
    }
}

#[test]
fn committed_graphs_use_neutral_colors() {
    let dir: PathBuf = assets_dir();
    for name in ASSETS {
        let body: String = read(&dir.join(name));
        let lower: String = body.to_ascii_lowercase();
        assert!(
            lower.contains(REQUIRED_CANVAS),
            "{name} does not use the dark canvas {REQUIRED_CANVAS}"
        );
        assert!(
            lower.contains(REQUIRED_TEXT),
            "{name} does not use the light ink {REQUIRED_TEXT}"
        );
        for (index, _) in lower.match_indices('#') {
            let Some(rgb) = lower.as_bytes().get(index + 1..index + 7) else {
                continue;
            };
            if rgb.iter().all(u8::is_ascii_hexdigit) {
                assert_eq!(&rgb[..2], &rgb[2..4], "{name} contains a non-neutral color");
                assert_eq!(&rgb[2..4], &rgb[4..], "{name} contains a non-neutral color");
            }
        }
        assert!(
            body.contains("JetBrains Mono"),
            "{name} mono stack must lead with JetBrains Mono"
        );
    }
}

#[test]
fn readme_links_the_evidence_index_and_its_graphs() {
    let readme: String = read(&workspace_root().join("README.md"));
    assert!(readme.contains("(evidence/README.md)"));
    let evidence: String = read(&workspace_root().join("evidence").join("README.md"));
    for name in ASSETS {
        let raster: String = name.replace(".svg", ".png");
        let needle: String = format!("../docs/assets/{raster}");
        assert!(
            evidence.contains(&needle),
            "evidence/README.md does not link {needle}"
        );
        assert!(assets_dir().join(raster).is_file());
    }
}

#[test]
fn data_sources_are_cited() {
    let data: PathBuf = workspace_root().join("xtask").join("data");
    for file in ["recovery.json", "python_versions.json", "architecture.json"] {
        let body: String = read(&data.join(file));
        let parsed: serde_json::Value =
            serde_json::from_str(&body).unwrap_or_else(|e| panic!("{file} is not valid JSON: {e}"));
        assert!(parsed.is_object(), "{file} root must be an object");
    }
    let recovery: String = read(&data.join("recovery.json"));
    assert!(
        recovery.matches("\"source\"").count() >= 10,
        "recovery.json must cite a source for every plotted value"
    );
    let python: String = read(&data.join("python_versions.json"));
    assert!(
        python.matches("\"source\"").count() >= 5,
        "python_versions.json must cite a source for every tool"
    );
}
