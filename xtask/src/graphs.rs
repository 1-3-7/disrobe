use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use sha2::{Digest, Sha256};

use crate::datamodel::{VerificationDoc, load_verification};
use crate::fileio::read_bytes_bounded;

const MAX_ASSET_BYTES: u64 = 4 * 1024 * 1024;

const ASSETS: [&str; 6] = [
    "recovery.svg",
    "python-versions.svg",
    "architecture.svg",
    "ir-ladder.svg",
    "ecosystems.svg",
    "verification.svg",
];

const DATA_BACKED: [(&str, &str); 6] = [
    ("recovery.svg", "recovery.json"),
    ("python-versions.svg", "python_versions.json"),
    ("architecture.svg", "architecture.json"),
    ("ir-ladder.svg", "ir_ladder.json"),
    ("ecosystems.svg", "ecosystems.json"),
    ("verification.svg", "verification.json"),
];

const MAX_DATA_BYTES: u64 = 4 * 1024 * 1024;

const MIRRORED: [&str; 2] = ["recovery.svg", "social-card.png"];

const VERIFICATION_CHART: &str = "verification.svg";

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
        if name == VERIFICATION_CHART {
            verification_cells_are_rendered(root, name, rendered)?;
        }
    }
    for name in MIRRORED {
        published_copy_matches(root, name)?;
    }
    if check {
        println!(
            "xtask graphs --check: {} committed chart assets well-formed, and each of the {} \
             data-backed ones carries the digest of the committed data file it was rendered from, \
             so a chart cannot show numbers its data no longer states",
            ASSETS.len(),
            DATA_BACKED.len()
        );
    } else {
        println!(
            "xtask graphs: validated {} chart assets; regenerate them with `node xtask/graphgen/build.mjs`",
            ASSETS.len()
        );
    }
    Ok(())
}

fn published_copy_matches(root: &Path, name: &str) -> Result<()> {
    let rendered_path: PathBuf = root.join("docs").join("assets").join(name);
    let published_path: PathBuf = root.join("docs").join("src").join("assets").join(name);
    let rendered: Vec<u8> = read_bytes_bounded(&rendered_path, MAX_ASSET_BYTES)
        .wrap_err_with(|| format!("reading {}", rendered_path.display()))?;
    let published: Vec<u8> =
        read_bytes_bounded(&published_path, MAX_ASSET_BYTES).wrap_err_with(|| {
            format!(
                "reading {}, which mdbook publishes and docs/theme/head.hbs links",
                published_path.display()
            )
        })?;
    if rendered != published {
        bail!(
            "docs/src/assets/{name} does not match docs/assets/{name}; mdbook serves the copy under \
             docs/src, so readers get the stale one while the fresh render sits unpublished. copy \
             docs/assets/{name} over docs/src/assets/{name}"
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

fn verification_cells_are_rendered(root: &Path, asset: &str, rendered: &str) -> Result<()> {
    let doc: VerificationDoc = load_verification(root)?;
    let mut missing: Vec<String> = Vec::new();
    for row in &doc.rows {
        for cell in [row.ecosystem.as_str(), row.result.as_str()] {
            if cell.is_empty() {
                continue;
            }
            let escaped: String = escape_svg_text(cell);
            if !rendered.contains(&escaped) {
                missing.push(format!("{} -> {cell:?}", row.ecosystem));
            }
        }
    }
    if !missing.is_empty() {
        bail!(
            "docs/assets/{asset} does not render {} cell(s) that verification.json states, so the \
             published chart shows something other than the data behind it: {}. the digest stamp \
             cannot catch this on its own, because editing the chart text by hand leaves the data \
             file untouched. regenerate with `node xtask/graphgen/build.mjs`",
            missing.len(),
            missing.join("; ")
        );
    }
    Ok(())
}

fn escape_svg_text(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
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
