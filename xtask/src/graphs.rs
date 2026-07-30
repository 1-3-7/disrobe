use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
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
const RECOVERY_CHART: &str = "recovery.svg";
const RECOVERY_DATA: &str = "recovery.json";
const PERCENT_KIND: &str = "percent";

#[derive(Debug, Deserialize)]
struct RecoveryDoc {
    groups: Vec<RecoveryGroup>,
}

#[derive(Debug, Deserialize)]
struct RecoveryGroup {
    heading: String,
    kind: String,
    bars: Vec<RecoveryBar>,
}

#[derive(Debug, Deserialize)]
struct RecoveryBar {
    label: String,
    #[serde(default)]
    value: Option<f64>,
}

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
        if name == RECOVERY_CHART {
            recovery_percentages_are_rendered(root, name, rendered)?;
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

fn rendered_percentages(rendered: &str) -> Vec<String> {
    let mut found: Vec<String> = Vec::new();
    for chunk in rendered.split('>').skip(1) {
        let Some((text, _)): Option<(&str, &str)> = chunk.split_once('<') else {
            continue;
        };
        let trimmed: &str = text.trim();
        let Some(number): Option<&str> = trimmed.strip_suffix('%') else {
            continue;
        };
        let Some((whole, fraction)): Option<(&str, &str)> = number.split_once('.') else {
            continue;
        };
        if whole.is_empty()
            || !whole.bytes().all(|byte: u8| byte.is_ascii_digit())
            || fraction.len() != 2
            || !fraction.bytes().all(|byte: u8| byte.is_ascii_digit())
        {
            continue;
        }
        found.push(trimmed.to_owned());
    }
    found
}

fn tally(values: impl IntoIterator<Item = String>) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for value in values {
        *counts.entry(value).or_default() += 1;
    }
    counts
}

fn percentage_disagreements(
    expected: &BTreeMap<String, usize>,
    drawn: &BTreeMap<String, usize>,
    owner: &BTreeMap<String, String>,
) -> (Vec<String>, Vec<String>) {
    let mut missing: Vec<String> = Vec::new();
    for (cell, wanted) in expected {
        let shown: usize = drawn.get(cell).copied().unwrap_or_default();
        if shown < *wanted {
            let source: &str = owner.get(cell).map_or("an unnamed bar", String::as_str);
            missing.push(format!(
                "{cell} ({source}) drawn {shown} of {wanted} time(s)"
            ));
        }
    }
    let mut invented: Vec<String> = Vec::new();
    for (cell, shown) in drawn {
        let wanted: usize = expected.get(cell).copied().unwrap_or_default();
        if *shown > wanted {
            invented.push(format!(
                "{cell} drawn {shown} time(s) against {wanted} bar(s)"
            ));
        }
    }
    (missing, invented)
}

fn recovery_percentages_are_rendered(root: &Path, asset: &str, rendered: &str) -> Result<()> {
    let data_path: PathBuf = root.join("xtask").join("data").join(RECOVERY_DATA);
    let raw: Vec<u8> = read_bytes_bounded(&data_path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading chart data {}", data_path.display()))?;
    let doc: RecoveryDoc = serde_json::from_slice(&raw)
        .wrap_err_with(|| format!("parsing {}", data_path.display()))?;

    let mut expected: Vec<String> = Vec::new();
    let mut owner: BTreeMap<String, String> = BTreeMap::new();
    for group in &doc.groups {
        if group.kind != PERCENT_KIND {
            continue;
        }
        for bar in &group.bars {
            let Some(value): Option<f64> = bar.value else {
                bail!(
                    "the `{}` bar under `{}` sits in a {PERCENT_KIND} group and carries no value, \
                     so the chart has nothing to plot for it and this check has nothing to compare",
                    bar.label,
                    group.heading
                );
            };
            let cell: String = format!("{value:.2}%");
            owner
                .entry(cell.clone())
                .or_insert_with(|| format!("{} / {}", group.heading, bar.label));
            expected.push(cell);
        }
    }

    let expected_counts: BTreeMap<String, usize> = tally(expected);
    let drawn_counts: BTreeMap<String, usize> = tally(rendered_percentages(rendered));
    let (missing, invented): (Vec<String>, Vec<String>) =
        percentage_disagreements(&expected_counts, &drawn_counts, &owner);

    if !missing.is_empty() || !invented.is_empty() {
        bail!(
            "docs/assets/{asset} and {RECOVERY_DATA} disagree on the numbers a reader is shown. \
             the digest stamp cannot catch this on its own, because editing a figure inside the \
             chart leaves the data file untouched. missing from the chart: [{}]. drawn by the chart \
             and stated by no bar: [{}]. regenerate with `node xtask/graphgen/build.mjs`",
            missing.join("; "),
            invented.join("; ")
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

#[cfg(test)]
mod tests {
    use super::*;

    const CHART: &str = "<svg><text>95.09%</text><text>96.60%</text><text>strong</text>\
                         <text>96%</text><text>1.234%</text><text>go linux/386</text></svg>";

    #[test]
    fn only_two_decimal_percentages_are_read_as_plotted_figures() {
        assert_eq!(
            rendered_percentages(CHART),
            vec!["95.09%".to_owned(), "96.60%".to_owned()]
        );
    }

    #[test]
    fn a_figure_the_chart_drops_is_reported_with_the_bar_that_states_it() {
        let expected: BTreeMap<String, usize> = tally(vec!["95.09%".to_owned()]);
        let drawn: BTreeMap<String, usize> = tally(Vec::new());
        let mut owner: BTreeMap<String, String> = BTreeMap::new();
        owner.insert("95.09%".to_owned(), "python / full stdlib".to_owned());
        let (missing, invented): (Vec<String>, Vec<String>) =
            percentage_disagreements(&expected, &drawn, &owner);
        assert_eq!(missing.len(), 1);
        assert!(missing[0].contains("python / full stdlib"), "{missing:?}");
        assert!(invented.is_empty());
    }

    #[test]
    fn a_figure_hand_edited_into_the_chart_is_reported_as_stated_by_no_bar() {
        let expected: BTreeMap<String, usize> = tally(vec!["95.09%".to_owned()]);
        let drawn: BTreeMap<String, usize> = tally(vec!["99.99%".to_owned()]);
        let (missing, invented): (Vec<String>, Vec<String>) =
            percentage_disagreements(&expected, &drawn, &BTreeMap::new());
        assert_eq!(missing.len(), 1, "the real figure is no longer drawn");
        assert_eq!(invented.len(), 1, "the invented figure is named");
        assert!(invented[0].starts_with("99.99%"), "{invented:?}");
    }

    #[test]
    fn a_chart_that_agrees_with_its_data_reports_nothing() {
        let cells: Vec<String> = vec!["95.09%".to_owned(), "96.60%".to_owned()];
        let expected: BTreeMap<String, usize> = tally(cells.clone());
        let drawn: BTreeMap<String, usize> = tally(cells);
        let (missing, invented): (Vec<String>, Vec<String>) =
            percentage_disagreements(&expected, &drawn, &BTreeMap::new());
        assert!(missing.is_empty() && invented.is_empty());
    }

    #[test]
    fn a_figure_plotted_more_often_than_it_is_stated_is_reported() {
        let expected: BTreeMap<String, usize> = tally(vec!["96.60%".to_owned()]);
        let drawn: BTreeMap<String, usize> = tally(vec!["96.60%".to_owned(), "96.60%".to_owned()]);
        let (missing, invented): (Vec<String>, Vec<String>) =
            percentage_disagreements(&expected, &drawn, &BTreeMap::new());
        assert!(missing.is_empty());
        assert_eq!(invented.len(), 1, "{invented:?}");
    }
}
