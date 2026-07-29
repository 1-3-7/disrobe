use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use sha2::{Digest, Sha256};

use crate::fileio::read_bytes_bounded;

const MAX_ASSET_BYTES: u64 = 4 * 1024 * 1024;

const ASSETS: [&str; 7] = [
    "recovery.svg",
    "python-versions.svg",
    "architecture.svg",
    "ir-ladder.svg",
    "ecosystems.svg",
    "crate-graph.svg",
    "verification.svg",
];

const DATA_BACKED: [(&str, &str); 7] = [
    ("recovery.svg", "recovery.json"),
    ("python-versions.svg", "python_versions.json"),
    ("architecture.svg", "architecture.json"),
    ("ir-ladder.svg", "ir_ladder.json"),
    ("ecosystems.svg", "ecosystems.json"),
    ("crate-graph.svg", "crate_graph.json"),
    ("verification.svg", "verification.json"),
];

const MAX_DATA_BYTES: u64 = 4 * 1024 * 1024;

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let assets_dir: PathBuf = root.join("docs").join("assets");
    for name in ASSETS {
        let path: PathBuf = assets_dir.join(name);
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_ASSET_BYTES)
            .wrap_err_with(|| format!("reading committed chart asset {}", path.display()))?;
        validate_svg(&path, &bytes)?;
        let rendered: &str = std::str::from_utf8(&bytes)
            .wrap_err_with(|| format!("{} is not valid utf-8", path.display()))?;
        if let Some((_, data_file)) = DATA_BACKED
            .iter()
            .find(|(chart, _): &&(&str, &str)| *chart == name)
        {
            svg_reflects_its_data(root, name, data_file, rendered)?;
        }
    }
    if check {
        println!(
            "xtask graphs --check: {} committed chart assets present and well-formed",
            ASSETS.len()
        );
    } else {
        println!(
            "xtask graphs: validated {} chart assets; regenerate them with `node xtask/graphgen/build.mjs`",
            ASSETS.len()
        );
    }
    Ok(())
}

fn source_digest(raw: &[u8]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    hasher.update(raw);
    let full: String = format!("{:x}", hasher.finalize());
    full.chars().take(32).collect()
}

fn svg_reflects_its_data(root: &Path, asset: &str, data_file: &str, rendered: &str) -> Result<()> {
    let data_path: PathBuf = root.join("xtask").join("data").join(data_file);
    let raw: Vec<u8> = read_bytes_bounded(&data_path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading chart data {}", data_path.display()))?;
    let expected: String = format!(
        "<desc>generated from {data_file} sha256:{}</desc>",
        source_digest(&raw)
    );
    if !rendered.contains(&expected) {
        bail!(
            "docs/assets/{asset} was rendered from a different {data_file} than the one committed, \
             so the chart no longer shows the current data; regenerate it with `node \
             xtask/graphgen/build.mjs`"
        );
    }
    Ok(())
}

fn validate_svg(path: &Path, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() {
        bail!("{} is empty", path.display());
    }
    let text: &str = std::str::from_utf8(bytes)
        .wrap_err_with(|| format!("{} is not valid utf-8", path.display()))?;
    if !text.contains("<svg") {
        bail!("{} has no <svg> root element", path.display());
    }
    if !text.trim_end().ends_with("</svg>") {
        bail!(
            "{} is a truncated svg (missing closing tag)",
            path.display()
        );
    }
    Ok(())
}
