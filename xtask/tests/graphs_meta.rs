#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::case_sensitive_file_extension_comparisons
)]

use std::fs;
use std::path::{Path, PathBuf};

const ASSETS: [&str; 3] = ["recovery.svg", "python-versions.svg", "architecture.svg"];

const BANNED_COLORS: [&str; 9] = [
    "#58a6ff", "58a6ff", "#388bc4", "0d1117", "#0d1117", "a371f7", "#a371f7", "#4d9375", "#d4b483",
];

const REQUIRED_CANVAS: &str = "#0a0a0a";
const REQUIRED_ACCENT: &str = "#8fb3d9";
const REQUIRED_TEXT: &str = "#ededed";
const REQUIRED_HAIRLINE: &str = "#333333";
const REQUIRED_WARN: &str = "#c9a98e";

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
fn committed_graphs_use_the_graphite_palette() {
    let dir: PathBuf = assets_dir();
    for name in ASSETS {
        let body: String = read(&dir.join(name));
        let lower: String = body.to_ascii_lowercase();
        assert!(
            body.contains(REQUIRED_CANVAS),
            "{name} does not use the Graphite canvas {REQUIRED_CANVAS}"
        );
        assert!(
            body.contains(REQUIRED_TEXT),
            "{name} does not use the Graphite ink {REQUIRED_TEXT}"
        );
        assert!(
            body.contains(REQUIRED_HAIRLINE),
            "{name} does not use the Graphite hairline-strong {REQUIRED_HAIRLINE}"
        );
        assert!(
            body.contains(REQUIRED_ACCENT) || body.contains(REQUIRED_WARN),
            "{name} carries neither the Graphite accent {REQUIRED_ACCENT} nor warn {REQUIRED_WARN}"
        );
        for banned in BANNED_COLORS {
            assert!(
                !lower.contains(&banned.to_ascii_lowercase()),
                "{name} still contains banned color `{banned}`"
            );
        }
        assert!(
            body.contains("JetBrains Mono"),
            "{name} mono stack must lead with JetBrains Mono"
        );
    }
}

#[test]
fn readme_embeds_every_graph() {
    let readme: String = read(&workspace_root().join("README.md"));
    for name in ASSETS {
        let needle: String = format!("docs/assets/{name}");
        assert!(
            readme.contains(&needle),
            "README.md does not embed {needle}"
        );
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
