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

const MIRRORED: [&str; 1] = ["recovery.svg"];

const MAX_RENDERER_SOURCE_BYTES: u64 = 8 * 1024 * 1024;

const CHART_RENDERER_SOURCES: [&str; 13] = [
    "build.mjs",
    "charts/architecture.mjs",
    "charts/ecosystems.mjs",
    "charts/ladder.mjs",
    "charts/python.mjs",
    "charts/recovery.mjs",
    "charts/verification.mjs",
    "lib/data.mjs",
    "lib/echart.mjs",
    "lib/kit.mjs",
    "lib/tiers.mjs",
    "package.json",
    "pnpm-lock.yaml",
];

const CHART_RENDERER_OWNED_ELSEWHERE: [&str; 3] = [
    "lib/social_card.mjs",
    "render_social_card.mjs",
    "rasterize_all.mjs",
];

const CHART_RENDERER_SCANNED_DIRS: [&str; 3] = [".", "charts", "lib"];

const CHART_RENDERER_DIGEST: &str = "e598e6c1574a700b0cc57c88bf099220";

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
const RECOVERY_PERCENT_CHART_TOP: f64 = 145.0;
const RECOVERY_PERCENT_GRID_TOP: f64 = 8.0;
const RECOVERY_PERCENT_ROW_HEIGHT: f64 = 27.0;
const RECOVERY_PAIR_GRID_TOP: f64 = 7.0;
const RECOVERY_PAIR_ROW_HEIGHT: f64 = 36.0;
const RECOVERY_PAIR_STACKED_OFFSET: f64 = 8.0;
const RECOVERY_TAG_SIZE: f64 = 9.5;
const RECOVERY_TAG_MARKER: f64 = 8.0;
const RECOVERY_TAG_MARKER_GAP: f64 = 5.0;
const RECOVERY_TAG_GUTTER_PAD: f64 = 10.0;
const RECOVERY_STRENGTH_TAGS: [&str; 4] = ["strong", "recompile", "pass-gated", "self-reported"];
const RECOVERY_STRENGTH_NAMES: [&str; 4] = [
    "strong",
    "recompile-only",
    "pass-gated",
    "coverage-self-reported",
];
const RECOVERY_REPRODUCIBILITY_TAGS: [&str; 2] = ["CI", "local"];
const RECOVERY_PERCENT_CHART_BASE_HEIGHT: f64 = 16.0;
const RECOVERY_PAIR_SECTION_GAP: f64 = 34.0;
const RECOVERY_MONO_FONT: &str = "'JetBrains Mono', ui-monospace, 'Cascadia Mono', 'Fira Code', SFMono-Regular, Menlo, Consolas, monospace";
const RECOVERY_VALUE_ID_PREFIX: &str = "disrobe-recovery-";
const RECOVERY_PERCENT_VALUE_ID_PREFIX: &str = "disrobe-recovery-percent-value-";
const RECOVERY_COUNT_PAIR_VALUE_ID_PREFIX: &str = "disrobe-recovery-count-pair-value-";
const RECOVERY_PERCENT_TIER_ID_PREFIX: &str = "disrobe-recovery-percent-tier-";
const RECOVERY_COUNT_PAIR_TIER_ID_PREFIX: &str = "disrobe-recovery-count-pair-tier-";
const RECOVERY_STAT_TIER_ID_PREFIX: &str = "disrobe-recovery-stat-tier-";
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
struct EcosystemsDoc {
    title: String,
    subtitle: String,
    kinds: BTreeMap<String, String>,
    cells: Vec<EcosystemsCell>,
}

#[derive(Debug, Deserialize)]
struct EcosystemsCell {
    label: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ArchitectureDoc {
    title: String,
    subtitle: String,
    chains: Vec<ArchitectureChain>,
}

#[derive(Debug, Deserialize)]
struct ArchitectureChain {
    name: String,
    nodes: Vec<ArchitectureNode>,
}

#[derive(Debug, Deserialize)]
struct ArchitectureNode {
    label: String,
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct LadderDoc {
    title: String,
    subtitle: String,
    #[serde(default)]
    footnote: Option<String>,
    rungs: Vec<LadderRung>,
}

#[derive(Debug, Deserialize)]
struct LadderRung {
    label: String,
    sub: String,
}

#[derive(Debug, Deserialize)]
struct PythonVersionsDoc {
    title: String,
    subtitle: String,
    tools: Vec<PythonVersionsTool>,
    legend: Vec<PythonVersionsLegend>,
}

#[derive(Debug, Deserialize)]
struct PythonVersionsTool {
    name: String,
}

#[derive(Debug, Deserialize)]
struct PythonVersionsLegend {
    label: String,
}

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
        data_cells_are_rendered(root, name, rendered)?;
        if name == RECOVERY_CHART {
            recovery_value_labels_are_rendered(root, name, rendered)?;
            recovery_tiers_match_their_evidence(root, name, rendered)?;
        }
    }
    for name in MIRRORED {
        published_copy_matches(root, name)?;
    }
    chart_renderer_is_complete(root)?;
    chart_renderer_is_pinned(root)?;
    if check {
        println!(
            "xtask graphs --check: {} committed chart assets well-formed, each of the {} \
             data-backed ones carries the digest of the committed data file it was rendered from, \
             so a chart cannot show numbers its data no longer states, and the {} renderer \
             source(s) that draw them still hash to the digest the committed charts were pinned to",
            ASSETS.len(),
            DATA_BACKED.len(),
            CHART_RENDERER_SOURCES.len()
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

fn renderer_root(root: &Path) -> PathBuf {
    root.join("xtask").join("graphgen")
}

fn renderer_source_path(root: &Path, relative: &str) -> PathBuf {
    let mut path: PathBuf = renderer_root(root);
    for part in relative.split('/') {
        path.push(part);
    }
    path
}

fn chart_renderer_digest(root: &Path) -> Result<String> {
    let mut hasher: Sha256 = Sha256::new();
    for relative in CHART_RENDERER_SOURCES {
        let path: PathBuf = renderer_source_path(root, relative);
        let raw: Vec<u8> = read_bytes_bounded(&path, MAX_RENDERER_SOURCE_BYTES)
            .wrap_err_with(|| format!("reading chart renderer source {}", path.display()))?;
        let len: u64 = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        hasher.update(relative.as_bytes());
        hasher.update([0_u8]);
        hasher.update(len.to_le_bytes());
        hasher.update(&raw);
    }
    let full: String = format!("{:x}", hasher.finalize());
    Ok(full.chars().take(32).collect())
}

fn chart_renderer_is_pinned(root: &Path) -> Result<()> {
    let computed: String = chart_renderer_digest(root)?;
    if computed != CHART_RENDERER_DIGEST {
        bail!(
            "the chart renderer under xtask/graphgen hashes to sha256:{computed}, but the \
             committed charts under docs/assets were pinned to sha256:{CHART_RENDERER_DIGEST}. \
             the charts are drawn out of process, so their committed bytes cannot be rebuilt \
             here; a renderer change with no re-render leaves a picture the current renderer \
             would not draw. re-render with `node xtask/graphgen/build.mjs`, then set \
             CHART_RENDERER_DIGEST in xtask/src/graphs.rs to sha256:{computed}"
        );
    }
    Ok(())
}

fn chart_renderer_is_complete(root: &Path) -> Result<()> {
    let base: PathBuf = renderer_root(root);
    let mut unlisted: Vec<String> = Vec::new();
    for dir in CHART_RENDERER_SCANNED_DIRS {
        let scanned: PathBuf = if dir == "." {
            base.clone()
        } else {
            base.join(dir)
        };
        if !scanned.is_dir() {
            bail!(
                "{} is scanned for chart renderer sources but is not a directory",
                scanned.display()
            );
        }
        for entry in std::fs::read_dir(&scanned)
            .wrap_err_with(|| format!("reading {}", scanned.display()))?
        {
            let dirent: std::fs::DirEntry =
                entry.wrap_err_with(|| format!("reading entry in {}", scanned.display()))?;
            let path: PathBuf = dirent.path();
            if !path.is_file() {
                continue;
            }
            let Some(name): Option<&str> = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            let is_module: bool = path
                .extension()
                .and_then(|ext| ext.to_str())
                .is_some_and(|ext: &str| ext.eq_ignore_ascii_case("mjs"));
            if !is_module || name.ends_with(".test.mjs") {
                continue;
            }
            let relative: String = if dir == "." {
                name.to_owned()
            } else {
                format!("{dir}/{name}")
            };
            if !CHART_RENDERER_SOURCES.contains(&relative.as_str())
                && !CHART_RENDERER_OWNED_ELSEWHERE.contains(&relative.as_str())
            {
                unlisted.push(relative);
            }
        }
    }
    if !unlisted.is_empty() {
        bail!(
            "{} chart renderer source(s) under xtask/graphgen are outside the digest that pins \
             the committed charts to the renderer that drew them, so editing them would change \
             the charts with nothing to notice: {}. add each one to CHART_RENDERER_SOURCES in \
             xtask/src/graphs.rs, or to CHART_RENDERER_OWNED_ELSEWHERE when another check \
             re-executes it",
            unlisted.len(),
            unlisted.join(", ")
        );
    }
    Ok(())
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

fn recovery_tiers_match_their_evidence(root: &Path, asset: &str, rendered: &str) -> Result<()> {
    let readme: Vec<u8> = read_bytes_bounded(&root.join("README.md"), MAX_DATA_BYTES)
        .wrap_err_with(|| "reading README.md, which defines the grading vocabulary".to_string())?;
    let readme_text: &str =
        std::str::from_utf8(&readme).wrap_err("README.md is not valid utf-8")?;
    for name in RECOVERY_STRENGTH_NAMES {
        if !readme_text.contains(&format!("`{name}`")) {
            bail!(
                "docs/assets/{asset} prints a legend entry for grading strength `{name}`, which \
                 README.md no longer defines under its section on how the numbers are checked. one \
                 definition serves both, so a reader cannot be shown a word the prose has dropped"
            );
        }
        if !rendered.contains(&format!(">{name}<")) {
            bail!(
                "docs/assets/{asset} omits the legend entry for grading strength `{name}` that \
                 README.md defines; a colour with no legend entry tells a reader nothing. \
                 regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
    }
    let digest: String = crate::evidence::chart_binding_digest(root)?;
    let expected: String = format!("<desc>graded from evidence/descriptors sha256:{digest}</desc>");
    if !rendered.contains(&expected) {
        bail!(
            "docs/assets/{asset} colours its bars by a grading strength that evidence/descriptors \
             no longer states. the chart reserves its strongest colour for a figure an external \
             reference could reject, so a descriptor whose oracle_strength or ci changed without a \
             re-render leaves the picture claiming more than the evidence does. regenerate it with \
             `node xtask/graphgen/build.mjs`"
        );
    }
    Ok(())
}

fn load_chart_data<T: serde::de::DeserializeOwned>(root: &Path, data_file: &str) -> Result<T> {
    let path: PathBuf = root.join("xtask").join("data").join(data_file);
    let raw: Vec<u8> = read_bytes_bounded(&path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading chart data {}", path.display()))?;
    serde_json::from_slice(&raw).wrap_err_with(|| format!("parsing {}", path.display()))
}

fn ecosystems_cells(root: &Path) -> Result<Vec<(String, String)>> {
    let doc: EcosystemsDoc = load_chart_data(root, "ecosystems.json")?;
    let mut cells: Vec<(String, String)> = vec![
        ("title".to_owned(), doc.title),
        ("subtitle".to_owned(), doc.subtitle),
    ];
    for (key, name) in doc.kinds {
        cells.push((format!("kinds.{key}"), name));
    }
    for cell in doc.cells {
        cells.push((format!("cell `{}` label", cell.label), cell.label.clone()));
        if let Some(note) = cell.note {
            cells.push((format!("cell `{}` note", cell.label), note));
        }
    }
    Ok(cells)
}

fn architecture_cells(root: &Path) -> Result<Vec<(String, String)>> {
    let doc: ArchitectureDoc = load_chart_data(root, "architecture.json")?;
    let mut cells: Vec<(String, String)> = vec![
        ("title".to_owned(), doc.title),
        ("subtitle".to_owned(), doc.subtitle),
    ];
    for chain in doc.chains {
        cells.push((format!("chain `{}` name", chain.name), chain.name.clone()));
        for node in chain.nodes {
            cells.push((
                format!("chain `{}` node label", chain.name),
                node.label.clone(),
            ));
            if let Some(note) = node.note {
                cells.push((
                    format!("chain `{}` node `{}` note", chain.name, node.label),
                    note,
                ));
            }
        }
    }
    Ok(cells)
}

fn ladder_cells(root: &Path) -> Result<Vec<(String, String)>> {
    let doc: LadderDoc = load_chart_data(root, "ir_ladder.json")?;
    let mut cells: Vec<(String, String)> = vec![
        ("title".to_owned(), doc.title),
        ("subtitle".to_owned(), doc.subtitle),
    ];
    if let Some(footnote) = doc.footnote {
        cells.push(("footnote".to_owned(), footnote));
    }
    for rung in doc.rungs {
        cells.push((format!("rung `{}` label", rung.label), rung.label.clone()));
        cells.push((format!("rung `{}` sub", rung.label), rung.sub));
    }
    Ok(cells)
}

fn python_versions_cells(root: &Path) -> Result<Vec<(String, String)>> {
    let doc: PythonVersionsDoc = load_chart_data(root, "python_versions.json")?;
    let mut cells: Vec<(String, String)> = vec![
        ("title".to_owned(), doc.title),
        ("subtitle".to_owned(), doc.subtitle),
    ];
    for tool in doc.tools {
        cells.push((format!("tool `{}` name", tool.name), tool.name.clone()));
    }
    for entry in doc.legend {
        cells.push((
            format!("legend `{}` label", entry.label),
            entry.label.clone(),
        ));
    }
    Ok(cells)
}

fn missing_data_cells(cells: &[(String, String)], rendered: &str) -> Vec<String> {
    cells
        .iter()
        .filter(|(_, text): &&(String, String)| {
            !text.is_empty() && !rendered.contains(&escape_svg_text(text))
        })
        .map(|(origin, text): &(String, String)| format!("{origin} -> {text:?}"))
        .collect()
}

fn data_cells_are_rendered(root: &Path, asset: &str, rendered: &str) -> Result<()> {
    let Some((data_file, cells)): Option<(&str, Vec<(String, String)>)> = (match asset {
        "ecosystems.svg" => Some(("ecosystems.json", ecosystems_cells(root)?)),
        "architecture.svg" => Some(("architecture.json", architecture_cells(root)?)),
        "ir-ladder.svg" => Some(("ir_ladder.json", ladder_cells(root)?)),
        "python-versions.svg" => Some(("python_versions.json", python_versions_cells(root)?)),
        _ => None,
    }) else {
        return Ok(());
    };
    let missing: Vec<String> = missing_data_cells(&cells, rendered);
    if !missing.is_empty() {
        bail!(
            "docs/assets/{asset} does not render {} of the {} cell(s) {data_file} states, so the \
             published chart shows something other than the data behind it: {}. the digest stamp \
             cannot catch this on its own, because editing the chart text by hand leaves the data \
             file untouched. regenerate with `node xtask/graphgen/build.mjs`",
            missing.len(),
            cells.len(),
            missing.join("; ")
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
    let document: roxmltree::Document<'_> = parse_recovery_svg(rendered)?;
    let tags: Vec<String> = verify_recovery_tier_tags(asset, &document, &doc)?;
    let slots: Vec<RecoveryLabelSlot> = recovery_label_slots(&doc, recovery_tag_gutter(&tags))?;
    verify_recovery_label_slots(asset, &document, &slots)
}

fn recovery_tag_gutter(tags: &[String]) -> f64 {
    let widest: f64 = tags
        .iter()
        .map(|tag: &String| tag.chars().count() as f64 * RECOVERY_TAG_SIZE * 0.6)
        .fold(0.0_f64, f64::max);
    (RECOVERY_TAG_MARKER + RECOVERY_TAG_MARKER_GAP + widest + RECOVERY_TAG_GUTTER_PAD).ceil()
}

fn verify_recovery_tier_tags(
    asset: &str,
    document: &roxmltree::Document<'_>,
    doc: &RecoveryDoc,
) -> Result<Vec<String>> {
    let expected: BTreeMap<&'static str, usize> = recovery_tier_populations(doc);
    let mut seen: BTreeMap<&'static str, BTreeMap<usize, String>> = BTreeMap::new();
    for node in document.descendants() {
        let Some(id): Option<&str> = node.attribute("id") else {
            continue;
        };
        let Some((prefix, index)): Option<(&'static str, usize)> = recovery_tier_id(id) else {
            continue;
        };
        let text: String = svg_text(node);
        if !recovery_tier_tag_is_legal(&text) {
            bail!(
                "docs/assets/{asset} tags bar `{id}` {text:?}, which is not one of the {} grading \
                 strengths followed by {} or {}; the tag beside a bar is the only channel a reader \
                 without colour has, so it may not say something the tier vocabulary does not \
                 define. regenerate with `node xtask/graphgen/build.mjs`",
                RECOVERY_STRENGTH_TAGS.len(),
                RECOVERY_REPRODUCIBILITY_TAGS[0],
                RECOVERY_REPRODUCIBILITY_TAGS[1]
            );
        }
        if seen
            .entry(prefix)
            .or_default()
            .insert(index, text)
            .is_some()
        {
            bail!(
                "docs/assets/{asset} repeats grading tag id `{id}`; regenerate with `node xtask/graphgen/build.mjs`"
            );
        }
    }
    let mut tags: Vec<String> = Vec::new();
    for (prefix, count) in &expected {
        let drawn: &BTreeMap<usize, String> = match seen.get(prefix) {
            Some(drawn) => drawn,
            None if *count == 0 => continue,
            None => bail!(
                "docs/assets/{asset} draws no `{prefix}` grading tag at all, though recovery.json \
                 carries {count} bar(s) of that kind; every bar must state how it was graded, or \
                 the chart presents a self-reported count as strongly as a proven one. regenerate \
                 with `node xtask/graphgen/build.mjs`"
            ),
        };
        if drawn.len() != *count {
            bail!(
                "docs/assets/{asset} draws {} `{prefix}` grading tag(s) for {count} bar(s) in \
                 recovery.json; regenerate with `node xtask/graphgen/build.mjs`",
                drawn.len()
            );
        }
        for index in 0..*count {
            let Some(tag): Option<&String> = drawn.get(&index) else {
                bail!(
                    "docs/assets/{asset} skips grading tag `{prefix}{index}`; regenerate with `node xtask/graphgen/build.mjs`"
                );
            };
            tags.push(tag.clone());
        }
    }
    Ok(tags)
}

fn recovery_tier_id(id: &str) -> Option<(&'static str, usize)> {
    for prefix in [
        RECOVERY_PERCENT_TIER_ID_PREFIX,
        RECOVERY_COUNT_PAIR_TIER_ID_PREFIX,
        RECOVERY_STAT_TIER_ID_PREFIX,
    ] {
        if let Some(rest) = id.strip_prefix(prefix) {
            return rest
                .parse::<usize>()
                .ok()
                .map(|index: usize| (prefix, index));
        }
    }
    None
}

fn load_recovery_doc(root: &Path) -> Result<RecoveryDoc> {
    let data_path: PathBuf = root.join("xtask").join("data").join(RECOVERY_DATA);
    let raw: Vec<u8> = read_bytes_bounded(&data_path, MAX_DATA_BYTES)
        .wrap_err_with(|| format!("reading chart data {}", data_path.display()))?;
    serde_json::from_slice(&raw).wrap_err_with(|| format!("parsing {}", data_path.display()))
}

fn recovery_tier_populations(doc: &RecoveryDoc) -> BTreeMap<&'static str, usize> {
    let mut population: BTreeMap<&'static str, usize> = BTreeMap::new();
    for group in &doc.groups {
        let prefix: &'static str = match group.kind.as_str() {
            PERCENT_KIND => RECOVERY_PERCENT_TIER_ID_PREFIX,
            COUNT_PAIR_KIND => RECOVERY_COUNT_PAIR_TIER_ID_PREFIX,
            _ => RECOVERY_STAT_TIER_ID_PREFIX,
        };
        *population.entry(prefix).or_default() += group.bars.len();
    }
    population
}

fn recovery_tier_tag_is_legal(text: &str) -> bool {
    let Some((strength, reproducibility)): Option<(&str, &str)> = text.split_once(' ') else {
        return false;
    };
    RECOVERY_STRENGTH_TAGS.contains(&strength)
        && RECOVERY_REPRODUCIBILITY_TAGS.contains(&reproducibility)
}

fn recovery_label_slots(doc: &RecoveryDoc, tag_gutter: f64) -> Result<Vec<RecoveryLabelSlot>> {
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
        recovery_label_gutter(&percent_labels, RECOVERY_PERCENT_LABEL_GAP)? + tag_gutter;
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
        ) - RECOVERY_PAIR_STACKED_OFFSET;
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
        if !id.starts_with(RECOVERY_VALUE_ID_PREFIX) || recovery_tier_id(id).is_some() {
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

    const TEST_TAG_GUTTER: f64 = 0.0;

    #[test]
    fn recovery_value_labels_bind_data_to_root_svg_slots() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> =
            recovery_label_slots(&test_recovery_doc(), TEST_TAG_GUTTER)?;
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
        let slots: Vec<RecoveryLabelSlot> =
            recovery_label_slots(&test_recovery_doc(), TEST_TAG_GUTTER)?;
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

    fn seed_renderer_tree(root: &Path) -> Result<()> {
        for relative in CHART_RENDERER_SOURCES {
            let path: PathBuf = renderer_source_path(root, relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&path, relative.as_bytes())?;
        }
        Ok(())
    }

    #[test]
    fn a_renderer_source_edit_moves_the_pinned_digest() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        seed_renderer_tree(dir.path())?;
        let before: String = chart_renderer_digest(dir.path())?;
        std::fs::write(
            renderer_source_path(dir.path(), "charts/ecosystems.mjs"),
            b"const CELL_H = 52;",
        )?;
        let after: String = chart_renderer_digest(dir.path())?;
        assert_ne!(
            before, after,
            "a chart renderer edit must move the digest the committed charts are pinned to"
        );
        Ok(())
    }

    #[test]
    fn a_renderer_source_the_digest_does_not_cover_is_reported() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        seed_renderer_tree(dir.path())?;
        chart_renderer_is_complete(dir.path())?;
        std::fs::write(
            renderer_source_path(dir.path(), "charts/unlisted.mjs"),
            b"export const x = 1;",
        )?;
        let error: String = match chart_renderer_is_complete(dir.path()) {
            Ok(()) => bail!("an unlisted renderer source must be reported"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("charts/unlisted.mjs"), "{error}");
        Ok(())
    }

    #[test]
    fn a_renderer_test_file_is_not_a_renderer_source() -> Result<()> {
        let dir: tempfile::TempDir = tempfile::tempdir()?;
        seed_renderer_tree(dir.path())?;
        std::fs::write(
            renderer_source_path(dir.path(), "charts/recovery.test.mjs"),
            b"import test from 'node:test';",
        )?;
        chart_renderer_is_complete(dir.path())?;
        Ok(())
    }

    #[test]
    fn a_chart_that_drops_a_data_cell_is_reported() {
        let cells: Vec<(String, String)> = vec![
            (
                "cell `Python pyc` label".to_owned(),
                "Python pyc".to_owned(),
            ),
            ("cell `PyArmor` label".to_owned(), "PyArmor".to_owned()),
        ];
        let rendered: &str = "<svg><text>Python pyd</text><text>PyArmor</text></svg>";
        let missing: Vec<String> = missing_data_cells(&cells, rendered);
        assert_eq!(missing.len(), 1, "{missing:?}");
        assert!(missing[0].contains("Python pyc"), "{missing:?}");
    }

    #[test]
    fn a_chart_that_renders_every_data_cell_reports_nothing() {
        let cells: Vec<(String, String)> =
            vec![("kinds.unpack".to_owned(), "unpack & extract".to_owned())];
        let rendered: &str = "<svg><text>unpack &amp; extract</text></svg>";
        assert!(missing_data_cells(&cells, rendered).is_empty());
    }

    #[test]
    fn recovery_value_label_parser_rejects_a_dtd() {
        assert!(parse_recovery_svg("<!DOCTYPE svg><svg/>").is_err());
    }

    #[test]
    fn recovery_value_labels_reject_document_wide_style_elements() -> Result<()> {
        let slots: Vec<RecoveryLabelSlot> =
            recovery_label_slots(&test_recovery_doc(), TEST_TAG_GUTTER)?;
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
        let slots: Vec<RecoveryLabelSlot> =
            recovery_label_slots(&test_recovery_doc(), TEST_TAG_GUTTER)?;
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
        let slots: Vec<RecoveryLabelSlot> =
            recovery_label_slots(&test_recovery_doc(), TEST_TAG_GUTTER)?;
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
