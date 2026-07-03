use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};

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

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let assets_dir: PathBuf = root.join("docs").join("assets");
    for name in ASSETS {
        let path: PathBuf = assets_dir.join(name);
        let bytes: Vec<u8> = read_bytes_bounded(&path, MAX_ASSET_BYTES)
            .wrap_err_with(|| format!("reading committed chart asset {}", path.display()))?;
        validate_svg(&path, &bytes)?;
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
