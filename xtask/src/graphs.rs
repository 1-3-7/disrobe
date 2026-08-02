use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::datamodel::{VerificationDoc, load_verification};
use crate::fileio::read_bytes_bounded;
use crate::metrics::group_thousands;

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
const COUNT_PAIR_KIND: &str = "count_pair";
const DEFAULT_COUNT_PAIR_DENOMINATOR: &str = "detected";
const MAX_RECOVERY_SVG_NODES: u32 = 16_384;
const MAX_JAVASCRIPT_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const RECOVERY_WIDTH: f64 = 920.0;
const RECOVERY_LEFT: f64 = 28.0;
const RECOVERY_INNER: f64 = RECOVERY_WIDTH - RECOVERY_LEFT * 2.0;
const RECOVERY_VALUE_LABEL_SIZE: f64 = 11.5;
const RECOVERY_PERCENT_LABEL_GAP: f64 = 8.0;
const RECOVERY_PAIR_LABEL_GAP: f64 = 10.0;
const RECOVERY_LABEL_GUTTER_PAD: f64 = 8.0;
const RECOVERY_PERCENT_CHART_TOP: f64 = 130.0;
const RECOVERY_PERCENT_GRID_TOP: f64 = 8.0;
const RECOVERY_PERCENT_ROW_HEIGHT: f64 = 27.0;
const RECOVERY_PAIR_GRID_TOP: f64 = 7.0;
const RECOVERY_PAIR_ROW_HEIGHT: f64 = 30.0;
const RECOVERY_PERCENT_CHART_BASE_HEIGHT: f64 = 16.0;
const RECOVERY_PAIR_SECTION_GAP: f64 = 34.0;
const RECOVERY_MONO_FONT: &str = "'JetBrains Mono', ui-monospace, 'Cascadia Mono', 'Fira Code', SFMono-Regular, Menlo, Consolas, monospace";
const RECOVERY_VALUE_ID_PREFIX: &str = "disrobe-recovery-";
const RECOVERY_PERCENT_VALUE_ID_PREFIX: &str = "disrobe-recovery-percent-value-";
const RECOVERY_COUNT_PAIR_VALUE_ID_PREFIX: &str = "disrobe-recovery-count-pair-value-";
const SVG_NAMESPACE: &str = "http://www.w3.org/2000/svg";
const XML_NAMESPACE: &str = "http://www.w3.org/XML/1998/namespace";
const RECOVERY_FORBIDDEN_PRESENTATION_ATTRIBUTES: [&str; 9] = [
    "style",
    "transform",
    "display",
    "visibility",
    "opacity",
    "filter",
    "mask",
    "clip-path",
    "overflow",
];

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
    #[serde(default)]
    detected: Option<u64>,
    #[serde(default)]
    delivered: Option<u64>,
    #[serde(default)]
    delivered_label: Option<String>,
    #[serde(default)]
    denominator_label: Option<String>,
}

#[derive(Debug, Eq, PartialEq)]
struct RecoveryLabelSlot {
    id: String,
    text: String,
    x: String,
    y: String,
}

#[derive(Debug, Clone, Copy)]
struct RecoveryViewport {
    left: f64,
    top: f64,
    width: f64,
    height: f64,
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
            recovery_value_labels_are_rendered(root, name, rendered)?;
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

fn recovery_value_labels_are_rendered(root: &Path, asset: &str, rendered: &str) -> Result<()> {
    let doc: RecoveryDoc = load_recovery_doc(root)?;
    let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&doc)?;
    let document: roxmltree::Document<'_> = parse_recovery_svg(rendered)?;
    verify_recovery_label_slots(asset, &document, &slots)
}

fn load_recovery_doc(root: &Path) -> Result<RecoveryDoc> {
    let data_path: PathBuf = root.join("xtask").join("data").join(RECOVERY_DATA);
    let raw: Vec<u8> = read_bytes_bounded(&data_path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading chart data {}", data_path.display()))?;
    serde_json::from_slice(&raw).wrap_err_with(|| format!("parsing {}", data_path.display()))
}

fn recovery_label_slots(doc: &RecoveryDoc) -> Result<Vec<RecoveryLabelSlot>> {
    let mut percent_labels: Vec<String> = Vec::new();
    let mut count_pair_labels: Vec<String> = Vec::new();
    for group in &doc.groups {
        for bar in &group.bars {
            if (bar.delivered_label.is_some() || bar.denominator_label.is_some())
                && group.kind != COUNT_PAIR_KIND
            {
                bail!(
                    "the `{}` bar under `{}` has a count-pair label outside a {COUNT_PAIR_KIND} group",
                    bar.label,
                    group.heading
                );
            }
            if group.kind == PERCENT_KIND {
                let Some(value): Option<f64> = bar.value else {
                    bail!(
                        "the `{}` bar under `{}` sits in a {PERCENT_KIND} group and carries no value",
                        bar.label,
                        group.heading
                    );
                };
                percent_labels.push(format!("{value:.2}%"));
            }
            if group.kind == COUNT_PAIR_KIND {
                count_pair_labels.push(count_pair_svg_label(bar)?);
            }
        }
    }

    let percent_grid_right: f64 =
        recovery_label_gutter(&percent_labels, RECOVERY_PERCENT_LABEL_GAP)?;
    let pair_grid_right: f64 = recovery_label_gutter(&count_pair_labels, RECOVERY_PAIR_LABEL_GAP)?;
    let percent_x: f64 =
        RECOVERY_LEFT + RECOVERY_INNER - percent_grid_right + RECOVERY_PERCENT_LABEL_GAP;
    let pair_x: f64 = RECOVERY_LEFT + RECOVERY_INNER - pair_grid_right + RECOVERY_PAIR_LABEL_GAP;
    let pair_chart_top: f64 = (percent_labels.len() as f64).mul_add(
        RECOVERY_PERCENT_ROW_HEIGHT,
        RECOVERY_PERCENT_CHART_TOP + RECOVERY_PERCENT_CHART_BASE_HEIGHT,
    ) + RECOVERY_PAIR_SECTION_GAP;
    let mut slots: Vec<RecoveryLabelSlot> =
        Vec::with_capacity(percent_labels.len() + count_pair_labels.len());
    for (index, text) in percent_labels.into_iter().enumerate() {
        let y: f64 = (index as f64 + 0.5).mul_add(
            RECOVERY_PERCENT_ROW_HEIGHT,
            RECOVERY_PERCENT_CHART_TOP + RECOVERY_PERCENT_GRID_TOP,
        );
        slots.push(recovery_label_slot(
            format!("{RECOVERY_PERCENT_VALUE_ID_PREFIX}{index}"),
            text,
            percent_x,
            y,
        ));
    }
    for (index, text) in count_pair_labels.into_iter().enumerate() {
        let y: f64 = (index as f64 + 0.5).mul_add(
            RECOVERY_PAIR_ROW_HEIGHT,
            pair_chart_top + RECOVERY_PAIR_GRID_TOP,
        );
        slots.push(recovery_label_slot(
            format!("{RECOVERY_COUNT_PAIR_VALUE_ID_PREFIX}{index}"),
            text,
            pair_x,
            y,
        ));
    }
    Ok(slots)
}

fn recovery_label_gutter(labels: &[String], gap: f64) -> Result<f64> {
    let Some(widest): Option<f64> = labels
        .iter()
        .map(|label: &String| recovery_label_width(label))
        .max_by(f64::total_cmp)
    else {
        bail!("recovery.json has no labels for a recovery chart value section");
    };
    Ok((widest + gap + RECOVERY_LABEL_GUTTER_PAD).ceil())
}

fn recovery_label_width(label: &str) -> f64 {
    label.chars().count() as f64 * RECOVERY_VALUE_LABEL_SIZE * 0.6
}

fn recovery_label_slot(id: String, text: String, x: f64, y: f64) -> RecoveryLabelSlot {
    RecoveryLabelSlot {
        id,
        text,
        x: format!("{x:.2}"),
        y: format!("{y:.2}"),
    }
}

fn count_pair_denominator_label(bar: &RecoveryBar) -> Result<&str> {
    count_pair_label(
        bar,
        "denominator_label",
        bar.denominator_label.as_deref(),
        DEFAULT_COUNT_PAIR_DENOMINATOR,
    )
}

fn count_pair_delivered_label(bar: &RecoveryBar) -> Result<&str> {
    count_pair_label(
        bar,
        "delivered_label",
        bar.delivered_label.as_deref(),
        "delivered",
    )
}

fn count_pair_label<'a>(
    bar: &RecoveryBar,
    field: &str,
    value: Option<&'a str>,
    fallback: &'a str,
) -> Result<&'a str> {
    let Some(label): Option<&str> = value else {
        return Ok(fallback);
    };
    let unsafe_cell: bool = label
        .chars()
        .any(|character: char| character.is_control() || character == '|');
    if label.is_empty() || label.trim() != label || unsafe_cell {
        bail!("count_pair bar `{}` has an invalid {field}", bar.label,);
    }
    Ok(label)
}

fn count_pair_svg_label(bar: &RecoveryBar) -> Result<String> {
    let delivered: u64 = bar.delivered.ok_or_else(|| {
        eyre::eyre!(
            "count_pair bar `{}` has no delivered numerator for the recovery chart",
            bar.label
        )
    })?;
    let detected: u64 = bar.detected.ok_or_else(|| {
        eyre::eyre!(
            "count_pair bar `{}` has no detected denominator for the recovery chart",
            bar.label
        )
    })?;
    if delivered > MAX_JAVASCRIPT_SAFE_INTEGER || detected > MAX_JAVASCRIPT_SAFE_INTEGER {
        bail!(
            "count_pair bar `{}` exceeds the JavaScript safe-integer ceiling",
            bar.label
        );
    }
    if detected == 0 || delivered > detected {
        bail!(
            "count_pair bar `{}` must carry a positive detected count no smaller than delivered",
            bar.label
        );
    }
    count_pair_denominator_label(bar)?;
    let delivered_label: &str = count_pair_delivered_label(bar)?;
    Ok(format!(
        "{} {delivered_label} / {}",
        group_thousands(delivered),
        group_thousands(detected)
    ))
}

fn parse_recovery_svg(rendered: &str) -> Result<roxmltree::Document<'_>> {
    let options: roxmltree::ParsingOptions<'_> = roxmltree::ParsingOptions {
        nodes_limit: MAX_RECOVERY_SVG_NODES,
        ..roxmltree::ParsingOptions::default()
    };
    roxmltree::Document::parse_with_options(rendered, options)
        .map_err(|error: roxmltree::Error| eyre::eyre!("parsing recovery SVG: {error}"))
}

fn verify_recovery_label_slots(
    asset: &str,
    document: &roxmltree::Document<'_>,
    slots: &[RecoveryLabelSlot],
) -> Result<()> {
    let root: roxmltree::Node<'_, '_> = document.root_element();
    let viewport: RecoveryViewport = verify_recovery_svg_root(asset, document, root)?;
    let expected: BTreeMap<&str, &RecoveryLabelSlot> = slots
        .iter()
        .map(|slot: &RecoveryLabelSlot| (slot.id.as_str(), slot))
        .collect();
    let mut drawn: BTreeMap<&str, roxmltree::Node<'_, '_>> = BTreeMap::new();
    for node in document.descendants() {
        let Some(id): Option<&str> = node.attribute("id") else {
            continue;
        };
        if !id.starts_with(RECOVERY_VALUE_ID_PREFIX) {
            continue;
        }
        if !expected.contains_key(id) {
            bail!(
                "docs/assets/{asset} carries an unknown recovery value label id `{id}`; regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
        if drawn.insert(id, node).is_some() {
            bail!(
                "docs/assets/{asset} repeats recovery value label id `{id}`; regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
    }
    for slot in slots {
        let Some(node): Option<&roxmltree::Node<'_, '_>> = drawn.get(slot.id.as_str()) else {
            bail!(
                "docs/assets/{asset} omits recovery value label `{}`; regenerate with `node xtask/graphgen/build.mjs`",
                slot.id
            );
        };
        verify_recovery_label_slot(asset, *node, root, &viewport, slot)?;
    }
    for node in document
        .descendants()
        .filter(|node: &roxmltree::Node<'_, '_>| node.has_tag_name("text"))
    {
        if node
            .attribute("id")
            .is_some_and(|id: &str| id.starts_with(RECOVERY_VALUE_ID_PREFIX))
        {
            continue;
        }
        let text: String = svg_text(node);
        if is_recovery_metric_label(&text) {
            bail!(
                "docs/assets/{asset} carries an unowned recovery value label {text:?}; regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
    }
    Ok(())
}

fn verify_recovery_svg_root(
    asset: &str,
    document: &roxmltree::Document<'_>,
    root: roxmltree::Node<'_, '_>,
) -> Result<RecoveryViewport> {
    let name: roxmltree::ExpandedName<'_, '_> = root.tag_name();
    if name.name() != "svg" || name.namespace() != Some(SVG_NAMESPACE) {
        bail!(
            "docs/assets/{asset} has a non-SVG root; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    for forbidden in RECOVERY_FORBIDDEN_PRESENTATION_ATTRIBUTES {
        if root.attribute(forbidden).is_some() {
            bail!(
                "docs/assets/{asset} gives its SVG root forbidden `{forbidden}`; regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
    }
    if root
        .attribute("preserveAspectRatio")
        .is_some_and(|value: &str| value != "xMidYMid meet")
    {
        bail!(
            "docs/assets/{asset} gives its SVG root a cropping preserveAspectRatio; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    if document
        .descendants()
        .any(|node: roxmltree::Node<'_, '_>| node.is_element() && node.tag_name().name() == "style")
    {
        bail!(
            "docs/assets/{asset} carries a style element that can hide recovery labels; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    if document
        .descendants()
        .any(|node: roxmltree::Node<'_, '_>| node.is_pi())
    {
        bail!(
            "docs/assets/{asset} carries a processing instruction that can load external styling; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    let width: f64 = recovery_root_dimension(asset, root, "width")?;
    let height: f64 = recovery_root_dimension(asset, root, "height")?;
    let viewport: RecoveryViewport = recovery_viewport(asset, root)?;
    if !same_svg_measurement(width, RECOVERY_WIDTH) {
        bail!(
            "docs/assets/{asset} has width {width}, but recovery charts render at {RECOVERY_WIDTH}; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    if !same_svg_measurement(width, viewport.width)
        || !same_svg_measurement(height, viewport.height)
    {
        bail!(
            "docs/assets/{asset} has physical dimensions that differ from its viewBox; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    Ok(viewport)
}

fn recovery_root_dimension(asset: &str, root: roxmltree::Node<'_, '_>, name: &str) -> Result<f64> {
    let raw: &str = root.attribute(name).ok_or_else(|| {
        eyre::eyre!(
            "docs/assets/{asset} has no SVG root {name}; regenerate with `node xtask/graphgen/build.mjs`"
        )
    })?;
    let value: f64 = recovery_svg_number(asset, name, raw)?;
    if value <= 0.0 {
        bail!(
            "docs/assets/{asset} has a non-positive SVG root {name}; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    Ok(value)
}

fn recovery_viewport(asset: &str, root: roxmltree::Node<'_, '_>) -> Result<RecoveryViewport> {
    let raw: &str = root.attribute("viewBox").ok_or_else(|| {
        eyre::eyre!(
            "docs/assets/{asset} has no SVG root viewBox; regenerate with `node xtask/graphgen/build.mjs`"
        )
    })?;
    let mut values: std::str::SplitAsciiWhitespace<'_> = raw.split_ascii_whitespace();
    let left: f64 = recovery_viewport_component(asset, &mut values, "viewBox left")?;
    let top: f64 = recovery_viewport_component(asset, &mut values, "viewBox top")?;
    let width: f64 = recovery_viewport_component(asset, &mut values, "viewBox width")?;
    let height: f64 = recovery_viewport_component(asset, &mut values, "viewBox height")?;
    if values.next().is_some() {
        bail!(
            "docs/assets/{asset} has an SVG root viewBox with more than four components; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    if left != 0.0 || top != 0.0 || width <= 0.0 || height <= 0.0 {
        bail!(
            "docs/assets/{asset} has a non-canonical SVG root viewBox; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    Ok(RecoveryViewport {
        left,
        top,
        width,
        height,
    })
}

fn recovery_viewport_component(
    asset: &str,
    values: &mut std::str::SplitAsciiWhitespace<'_>,
    name: &str,
) -> Result<f64> {
    let raw: &str = values.next().ok_or_else(|| {
        eyre::eyre!(
            "docs/assets/{asset} has an SVG root viewBox without {name}; regenerate with `node xtask/graphgen/build.mjs`"
        )
    })?;
    recovery_svg_number(asset, name, raw)
}

fn recovery_svg_number(asset: &str, name: &str, raw: &str) -> Result<f64> {
    let value: f64 = raw.parse::<f64>().map_err(|error: std::num::ParseFloatError| {
        eyre::eyre!(
            "docs/assets/{asset} has an invalid SVG {name} {raw:?}: {error}; regenerate with `node xtask/graphgen/build.mjs`"
        )
    })?;
    if !value.is_finite() {
        bail!(
            "docs/assets/{asset} has a non-finite SVG {name}; regenerate with `node xtask/graphgen/build.mjs`"
        );
    }
    Ok(value)
}

fn same_svg_measurement(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON * left.abs().max(right.abs()).max(1.0)
}

fn verify_recovery_label_slot(
    asset: &str,
    node: roxmltree::Node<'_, '_>,
    root: roxmltree::Node<'_, '_>,
    viewport: &RecoveryViewport,
    slot: &RecoveryLabelSlot,
) -> Result<()> {
    let name: roxmltree::ExpandedName<'_, '_> = node.tag_name();
    if name.name() != "text"
        || name.namespace() != Some(SVG_NAMESPACE)
        || node.parent() != Some(root)
    {
        bail!(
            "docs/assets/{asset} places recovery value label `{}` outside the root SVG layer; regenerate with `node xtask/graphgen/build.mjs`",
            slot.id
        );
    }
    for forbidden in RECOVERY_FORBIDDEN_PRESENTATION_ATTRIBUTES {
        if node.attribute(forbidden).is_some() {
            bail!(
                "docs/assets/{asset} decorates recovery value label `{}` with forbidden `{forbidden}`; regenerate with `node xtask/graphgen/build.mjs`",
                slot.id
            );
        }
    }
    if node.attributes().count() != 10 {
        bail!(
            "docs/assets/{asset} gives recovery value label `{}` unexpected attributes; regenerate with `node xtask/graphgen/build.mjs`",
            slot.id
        );
    }
    for (name, value) in [
        ("id", slot.id.as_str()),
        ("x", slot.x.as_str()),
        ("y", slot.y.as_str()),
        ("font-size", "11.5"),
        ("fill", "#ededed"),
        ("font-family", RECOVERY_MONO_FONT),
        ("text-anchor", "start"),
        ("font-weight", "500"),
        ("dominant-baseline", "central"),
    ] {
        if node.attribute(name) != Some(value) {
            bail!(
                "docs/assets/{asset} gives recovery value label `{}` a stale {name}; regenerate with `node xtask/graphgen/build.mjs`",
                slot.id
            );
        }
    }
    if node.attribute((XML_NAMESPACE, "space")) != Some("preserve") {
        bail!(
            "docs/assets/{asset} does not preserve whitespace in recovery value label `{}`; regenerate with `node xtask/graphgen/build.mjs`",
            slot.id
        );
    }
    let children: Vec<roxmltree::Node<'_, '_>> = node.children().collect();
    if children.len() != 1
        || !children[0].is_text()
        || children[0].text() != Some(slot.text.as_str())
    {
        bail!(
            "docs/assets/{asset} does not render recovery value label `{}` as its exact plain text; regenerate with `node xtask/graphgen/build.mjs`",
            slot.id
        );
    }
    verify_recovery_label_viewport(asset, viewport, slot)?;
    Ok(())
}

fn verify_recovery_label_viewport(
    asset: &str,
    viewport: &RecoveryViewport,
    slot: &RecoveryLabelSlot,
) -> Result<()> {
    let x: f64 = recovery_svg_number(asset, "recovery label x", &slot.x)?;
    let y: f64 = recovery_svg_number(asset, "recovery label y", &slot.y)?;
    let left: f64 = x;
    let right: f64 = x + recovery_label_width(&slot.text) + RECOVERY_LABEL_GUTTER_PAD;
    let half_height: f64 = RECOVERY_VALUE_LABEL_SIZE / 2.0;
    let top: f64 = y - half_height;
    let bottom: f64 = y + half_height;
    if left < viewport.left
        || right > viewport.left + viewport.width
        || top < viewport.top
        || bottom > viewport.top + viewport.height
    {
        bail!(
            "docs/assets/{asset} crops recovery value label `{}` outside its SVG viewport; regenerate with `node xtask/graphgen/build.mjs`",
            slot.id
        );
    }
    Ok(())
}

fn svg_text(node: roxmltree::Node<'_, '_>) -> String {
    node.descendants()
        .filter(|descendant: &roxmltree::Node<'_, '_>| descendant.is_text())
        .filter_map(|descendant: roxmltree::Node<'_, '_>| descendant.text())
        .collect()
}

fn is_recovery_metric_label(value: &str) -> bool {
    is_svg_percentage(value) || is_count_pair_svg_label(value)
}

fn is_svg_percentage(value: &str) -> bool {
    let Some(number): Option<&str> = value.strip_suffix('%') else {
        return false;
    };
    let Some((whole, fraction)): Option<(&str, &str)> = number.split_once('.') else {
        return false;
    };
    !whole.is_empty()
        && whole.bytes().all(|byte: u8| byte.is_ascii_digit())
        && fraction.len() == 2
        && fraction.bytes().all(|byte: u8| byte.is_ascii_digit())
}

fn is_count_pair_svg_label(value: &str) -> bool {
    let Some(left_number): Option<&str> = value.split_whitespace().next() else {
        return false;
    };
    if !is_svg_count(left_number) {
        return false;
    }
    value.match_indices(" / ").any(|(index, _): (usize, &str)| {
        let right: &str = &value[index + " / ".len()..];
        right.split_whitespace().next().is_some_and(is_svg_count)
    })
}

fn is_svg_count(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte: u8| byte.is_ascii_digit() || byte == b',')
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

    fn test_recovery_doc() -> RecoveryDoc {
        RecoveryDoc {
            groups: vec![
                RecoveryGroup {
                    heading: "python".to_owned(),
                    kind: PERCENT_KIND.to_owned(),
                    bars: vec![
                        RecoveryBar {
                            label: "one".to_owned(),
                            value: Some(95.09),
                            detected: None,
                            delivered: None,
                            delivered_label: None,
                            denominator_label: None,
                        },
                        RecoveryBar {
                            label: "two".to_owned(),
                            value: Some(96.60),
                            detected: None,
                            delivered: None,
                            delivered_label: None,
                            denominator_label: None,
                        },
                    ],
                },
                RecoveryGroup {
                    heading: "coverage".to_owned(),
                    kind: COUNT_PAIR_KIND.to_owned(),
                    bars: vec![RecoveryBar {
                        label: "pyarmor".to_owned(),
                        value: None,
                        detected: Some(1200),
                        delivered: Some(1000),
                        delivered_label: Some("decoded root CodeObjects".to_owned()),
                        denominator_label: Some(
                            "manifest-named v8/v9 wrappers & samples".to_owned(),
                        ),
                    }],
                },
            ],
        }
    }

    fn render_test_label(slot: &RecoveryLabelSlot) -> String {
        format!(
            "<text x=\"{}\" y=\"{}\" font-size=\"11.5\" fill=\"#ededed\" font-family=\"{}\" text-anchor=\"start\" font-weight=\"500\" id=\"{}\" dominant-baseline=\"central\" xml:space=\"preserve\">{}</text>",
            slot.x,
            slot.y,
            RECOVERY_MONO_FONT,
            slot.id,
            escape_svg_text(&slot.text),
        )
    }

    fn render_test_svg(slots: &[RecoveryLabelSlot]) -> String {
        let labels: String = slots.iter().map(render_test_label).collect();
        format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"920\" height=\"300\" viewBox=\"0 0 920 300\">{labels}</svg>"
        )
    }

    fn slot_validation_error(rendered: &str, slots: &[RecoveryLabelSlot]) -> Result<String> {
        let document: roxmltree::Document<'_> = parse_recovery_svg(rendered)?;
        match verify_recovery_label_slots(RECOVERY_CHART, &document, slots) {
            Ok(()) => bail!("expected recovery label slot validation to fail"),
            Err(error) => Ok(error.to_string()),
        }
    }

    #[test]
    fn recovery_value_labels_bind_data_to_root_svg_slots() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&test_recovery_doc())?;
        let rendered: String = render_test_svg(&slots);
        let document: roxmltree::Document<'_> = parse_recovery_svg(&rendered)?;
        verify_recovery_label_slots(RECOVERY_CHART, &document, &slots)?;
        assert!(
            rendered.contains("1,000 decoded root CodeObjects / 1,200"),
            "count-pair data must remain visible in its owned root label"
        );
        Ok(())
    }

    #[test]
    fn recovery_value_labels_reject_a_cropped_root_viewport() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&test_recovery_doc())?;
        let rendered: String = render_test_svg(&slots);
        let cropped: String = rendered.replacen(
            "height=\"300\" viewBox=\"0 0 920 300\"",
            "height=\"256\" viewBox=\"0 0 920 256\"",
            1,
        );
        let document: roxmltree::Document<'_> = parse_recovery_svg(&cropped)?;
        assert!(
            verify_recovery_label_slots(RECOVERY_CHART, &document, &slots).is_err(),
            "a root viewBox that crops an owned recovery label must fail validation"
        );
        Ok(())
    }

    #[test]
    fn recovery_value_label_parser_rejects_a_dtd() {
        assert!(parse_recovery_svg("<!DOCTYPE svg><svg/>").is_err());
    }

    #[test]
    fn recovery_value_labels_reject_document_wide_style_elements() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&test_recovery_doc())?;
        let rendered: String = render_test_svg(&slots);
        let styled: String = rendered.replacen(
            "</svg>",
            "<style>#disrobe-recovery-percent-value-0 { display: none; }</style></svg>",
            1,
        );
        let error: String = slot_validation_error(&styled, &slots)?;
        assert!(error.contains("style element"), "{error}");
        Ok(())
    }

    #[test]
    fn recovery_value_labels_reject_changed_or_duplicate_slots() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&test_recovery_doc())?;
        let rendered: String = render_test_svg(&slots);
        let moved: String = rendered.replacen(&format!("x=\"{}\"", slots[0].x), "x=\"0.00\"", 1);
        let moved_error: String = slot_validation_error(&moved, &slots)?;
        assert!(moved_error.contains("stale x"), "{moved_error}");

        let duplicate: String = rendered.replacen(
            "</svg>",
            &format!("{}</svg>", render_test_label(&slots[0])),
            1,
        );
        let duplicate_error: String = slot_validation_error(&duplicate, &slots)?;
        assert!(duplicate_error.contains("repeats"), "{duplicate_error}");
        Ok(())
    }

    #[test]
    fn recovery_value_labels_reject_nested_and_unowned_metrics() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&test_recovery_doc())?;
        let first_label: String = render_test_label(&slots[0]);
        let nested: String =
            render_test_svg(&slots).replacen(&first_label, &format!("<g>{first_label}</g>"), 1);
        let nested_error: String = slot_validation_error(&nested, &slots)?;
        assert!(
            nested_error.contains("outside the root SVG layer"),
            "{nested_error}"
        );

        let decoy: String = format!(
            "{}<text>99.99%</text></svg>",
            render_test_svg(&slots).trim_end_matches("</svg>")
        );
        let decoy_error: String = slot_validation_error(&decoy, &slots)?;
        assert!(decoy_error.contains("unowned"), "{decoy_error}");
        Ok(())
    }

    #[test]
    fn count_pair_svg_label_rejects_invalid_counts() -> Result<()> {
        let unsafe_count: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detected: Some(MAX_JAVASCRIPT_SAFE_INTEGER + 1),
            delivered: Some(1),
            delivered_label: None,
            denominator_label: None,
        };
        let unsafe_error: String = match count_pair_svg_label(&unsafe_count) {
            Ok(_) => bail!("expected safe-integer validation to fail"),
            Err(error) => error.to_string(),
        };
        assert!(unsafe_error.contains("safe-integer"), "{unsafe_error}");

        let zero_denominator: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detected: Some(0),
            delivered: Some(0),
            delivered_label: None,
            denominator_label: None,
        };
        assert!(count_pair_svg_label(&zero_denominator).is_err());

        let over_delivered: RecoveryBar = RecoveryBar {
            label: "pair".to_owned(),
            value: None,
            detected: Some(1),
            delivered: Some(2),
            delivered_label: None,
            denominator_label: None,
        };
        assert!(count_pair_svg_label(&over_delivered).is_err());
        Ok(())
    }
}
