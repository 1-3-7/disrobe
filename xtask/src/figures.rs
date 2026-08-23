use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use sha2::{Digest, Sha256};

use crate::fileio::read_text_bounded;

const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;
const EMPTY_DIGEST: &str = "e3b0c44298fc1c14";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum FigureShape {
    Percent,
    OfPair,
    SlashPair,
    CountedNoun,
    Version,
}

impl FigureShape {
    const ALL: [Self; 5] = [
        Self::Percent,
        Self::OfPair,
        Self::SlashPair,
        Self::CountedNoun,
        Self::Version,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Percent => "percentage",
            Self::OfPair => "`N of M` pair",
            Self::SlashPair => "`N/M` pair",
            Self::CountedNoun => "count before a noun",
            Self::Version => "version-like figure",
        }
    }

    const fn is_budgeted(self) -> bool {
        matches!(self, Self::Percent | Self::OfPair | Self::SlashPair)
    }

    const fn excluded_reason(self) -> &'static str {
        match self {
            Self::Percent | Self::OfPair | Self::SlashPair => {
                "budgeted: a published measurement with a data file behind it"
            }
            Self::CountedNoun => {
                "not budgeted here: the metrics backstop in xtask/src/metrics.rs already refuses a \
                 bare count before any noun its key registry declares, and a count before an \
                 undeclared noun has no data file to drift from"
            }
            Self::Version => {
                "not budgeted: a version-like figure names a tool or language release, not a \
                 measurement, so no data file states it"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Figure {
    pub(crate) shape: FigureShape,
    pub(crate) line: usize,
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) covered: bool,
    pub(crate) suppressed: bool,
}

const SKIPPED_DIR_NAMES: [&str; 6] = [
    "target",
    "node_modules",
    "dist",
    "out",
    "venv",
    "site-packages",
];

const SCANNED_DOT_DIR_NAMES: [&str; 1] = [".github"];

const EXCLUDED_TREES: [(&str, &str); 4] = [
    (
        "docs/errors",
        "every page is regenerated from the error registry and byte-compared by \
         xtask/src/errdocs.rs, so a figure in one cannot move without the diff failing",
    ),
    (
        "evidence/results",
        "every page is rendered from evidence/descriptors and byte-compared by \
         xtask/src/evidence.rs",
    ),
    (
        "editors",
        "every file is rendered from xtask/data/ecosystems.json and byte-compared by \
         xtask/src/plugins.rs",
    ),
    (
        "bindings",
        "every stub is generated from schemas/v0/json and byte-compared by xtask/src/codegen.rs",
    ),
];

#[derive(Debug, Clone, Copy)]
pub(crate) struct FigureBudget {
    pub(crate) path: &'static str,
    pub(crate) figures: usize,
    pub(crate) digest: &'static str,
}

const DOCUMENT_FIGURE_BUDGET: [FigureBudget; 40] = [
    FigureBudget {
        path: "LEGAL.md",
        figures: 4,
        digest: "cb9b04898696158d",
    },
    FigureBudget {
        path: "README.md",
        figures: 36,
        digest: "0d28fed05a9d40d2",
    },
    FigureBudget {
        path: "SECURITY.md",
        figures: 1,
        digest: "d421517d22280741",
    },
    FigureBudget {
        path: "benches/decompile-quality/results.md",
        figures: 185,
        digest: "351c3029bda83cca",
    },
    FigureBudget {
        path: "benches/head-to-head/results.md",
        figures: 14,
        digest: "e828e8cb7779edd6",
    },
    FigureBudget {
        path: "benches/native-unpack/results.md",
        figures: 7,
        digest: "9d58e0b88c551267",
    },
    FigureBudget {
        path: "corpus/v8/node-18/BUILD.md",
        figures: 1,
        digest: "85c1415a91aa0023",
    },
    FigureBudget {
        path: "corpus/v8/node-20/BUILD.md",
        figures: 1,
        digest: "85c1415a91aa0023",
    },
    FigureBudget {
        path: "corpus/v8/node-22/BUILD.md",
        figures: 1,
        digest: "f2ba53ce24094c30",
    },
    FigureBudget {
        path: "crates/disrobe-lift-x86/tests/corpus/PROVENANCE.md",
        figures: 1,
        digest: "272fb4393eb0e59c",
    },
    FigureBudget {
        path: "crates/disrobe-sleigh/README.md",
        figures: 23,
        digest: "9c877d151fdaf624",
    },
    FigureBudget {
        path: "docs/legal/digital-ai-arxan-stance.md",
        figures: 3,
        digest: "f6c43b3a0624799c",
    },
    FigureBudget {
        path: "docs/legal/jscrambler-stance.md",
        figures: 3,
        digest: "f6c43b3a0624799c",
    },
    FigureBudget {
        path: "docs/legal/jsdefender-stance.md",
        figures: 3,
        digest: "f6c43b3a0624799c",
    },
    FigureBudget {
        path: "docs/legal/pace-js-stance.md",
        figures: 3,
        digest: "f6c43b3a0624799c",
    },
    FigureBudget {
        path: "docs/legal/pyarmor-stance.md",
        figures: 3,
        digest: "f6c43b3a0624799c",
    },
    FigureBudget {
        path: "docs/src/anti-analysis.md",
        figures: 6,
        digest: "28b6b8962ef83d04",
    },
    FigureBudget {
        path: "docs/src/architecture/whitepaper.md",
        figures: 47,
        digest: "ff9aed317ca06e78",
    },
    FigureBudget {
        path: "docs/src/catalog.md",
        figures: 12,
        digest: "00e640ce74f221eb",
    },
    FigureBudget {
        path: "docs/src/chain.md",
        figures: 4,
        digest: "d6046809296ff93f",
    },
    FigureBudget {
        path: "docs/src/frisk.md",
        figures: 1,
        digest: "0faa3145a0a69da1",
    },
    FigureBudget {
        path: "docs/src/installation.md",
        figures: 1,
        digest: "cc65c411b13e3f28",
    },
    FigureBudget {
        path: "docs/src/introduction.md",
        figures: 3,
        digest: "5346993cf3a04118",
    },
    FigureBudget {
        path: "docs/src/languages/containers.md",
        figures: 4,
        digest: "3fee0bbc9553d74d",
    },
    FigureBudget {
        path: "docs/src/languages/dotnet.md",
        figures: 3,
        digest: "a1727cb174b2b88b",
    },
    FigureBudget {
        path: "docs/src/languages/go.md",
        figures: 1,
        digest: "075810309917240f",
    },
    FigureBudget {
        path: "docs/src/languages/javascript.md",
        figures: 1,
        digest: "55a2157e92feb36a",
    },
    FigureBudget {
        path: "docs/src/languages/jvm-android.md",
        figures: 7,
        digest: "658e8884c7a67017",
    },
    FigureBudget {
        path: "docs/src/languages/lua.md",
        figures: 3,
        digest: "2cb321399baa9d22",
    },
    FigureBudget {
        path: "docs/src/languages/mobile.md",
        figures: 1,
        digest: "e0dc0d94f197b8e7",
    },
    FigureBudget {
        path: "docs/src/languages/native-unpack.md",
        figures: 3,
        digest: "deef74772b6cd26a",
    },
    FigureBudget {
        path: "docs/src/languages/native.md",
        figures: 18,
        digest: "3ff1dda9497fc5bc",
    },
    FigureBudget {
        path: "docs/src/languages/pickle.md",
        figures: 2,
        digest: "58d1594d36f4a5cf",
    },
    FigureBudget {
        path: "docs/src/languages/python.md",
        figures: 4,
        digest: "0bb6b944909c0fb9",
    },
    FigureBudget {
        path: "docs/src/languages/ruby.md",
        figures: 3,
        digest: "e8b9dc14d16b62be",
    },
    FigureBudget {
        path: "docs/src/languages/shell.md",
        figures: 3,
        digest: "d10f2626f4000ca4",
    },
    FigureBudget {
        path: "docs/src/legal.md",
        figures: 1,
        digest: "86224fb7a4985054",
    },
    FigureBudget {
        path: "docs/src/python-bindings.md",
        figures: 7,
        digest: "d5b2926b3b343af7",
    },
    FigureBudget {
        path: "evidence/README.md",
        figures: 1,
        digest: "164b090acd56d131",
    },
    FigureBudget {
        path: "evidence/edge-comparison.md",
        figures: 6,
        digest: "fc5e06867f3cd019",
    },
];

pub(crate) fn detect(text: &str, covered: &[(usize, usize)], suppressed: &[usize]) -> Vec<Figure> {
    let mut figures: Vec<Figure> = Vec::new();
    let bytes: &[u8] = text.as_bytes();
    let mut in_fence: bool = false;
    let mut offset: usize = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = index + 1;
        let trimmed: &str = line.trim_start();
        let is_fence_delim: bool = trimmed.starts_with("```") || trimmed.starts_with("~~~");
        if !in_fence && !is_fence_delim {
            scan_line(
                line,
                offset,
                line_no,
                bytes,
                covered,
                suppressed,
                &mut figures,
            );
        }
        if is_fence_delim {
            in_fence = !in_fence;
        }
        offset += line.len();
    }
    figures
}

fn scan_line(
    line: &str,
    line_offset: usize,
    line_no: usize,
    file_bytes: &[u8],
    covered: &[(usize, usize)],
    suppressed: &[usize],
    figures: &mut Vec<Figure>,
) {
    let raw: &[u8] = line.as_bytes();
    let mut index: usize = 0;
    while index < raw.len() {
        let Some(byte): Option<&u8> = raw.get(index) else {
            break;
        };
        if !byte.is_ascii_digit() {
            index += 1;
            continue;
        }
        let start_abs: usize = line_offset + index;
        if is_word_byte(prev_byte(file_bytes, start_abs)) || continues_an_identifier(raw, index) {
            index += 1;
            continue;
        }
        let token_end: usize = numeric_token_end(raw, index);
        let matched: Option<FigureMatch> = classify(line, raw, index, token_end);
        let advance: usize = matched.map_or(token_end, |found: FigureMatch| {
            figures.push(Figure {
                shape: found.shape,
                line: line_no,
                start: start_abs,
                end: line_offset + found.end,
                covered: covered
                    .iter()
                    .any(|(from, to): &(usize, usize)| start_abs >= *from && start_abs < *to),
                suppressed: suppressed.contains(&line_no),
            });
            found.end
        });
        index = advance.max(index + 1);
    }
}

#[derive(Debug, Clone, Copy)]
struct FigureMatch {
    shape: FigureShape,
    end: usize,
}

fn continues_an_identifier(raw: &[u8], at: usize) -> bool {
    at >= 2
        && raw.get(at - 1) == Some(&b'-')
        && raw
            .get(at - 2)
            .is_some_and(|byte: &u8| byte.is_ascii_alphanumeric())
}

fn numeric_token_end(raw: &[u8], start: usize) -> usize {
    let mut end: usize = start;
    while raw
        .get(end)
        .is_some_and(|byte: &u8| byte.is_ascii_digit() || matches!(byte, b'.' | b','))
    {
        end += 1;
    }
    while end > start
        && raw
            .get(end - 1)
            .is_some_and(|byte: &u8| matches!(byte, b'.' | b','))
    {
        end -= 1;
    }
    end
}

fn classify(line: &str, raw: &[u8], start: usize, token_end: usize) -> Option<FigureMatch> {
    if token_end <= start {
        return None;
    }
    let token: &str = line.get(start..token_end).unwrap_or_default();
    let rest: &str = line.get(token_end..).unwrap_or_default();
    if rest.starts_with('%') {
        return Some(FigureMatch {
            shape: FigureShape::Percent,
            end: token_end + 1,
        });
    }
    if let Some(end) = denominator_end(raw, token_end, " of ") {
        return Some(FigureMatch {
            shape: FigureShape::OfPair,
            end,
        });
    }
    if let Some(end) = slash_denominator_end(raw, token_end) {
        return Some(FigureMatch {
            shape: FigureShape::SlashPair,
            end,
        });
    }
    if token.contains('.') {
        return Some(FigureMatch {
            shape: FigureShape::Version,
            end: token_end,
        });
    }
    if is_ordered_list_marker(line, start, rest) {
        return None;
    }
    if counted_noun_follows(rest) {
        return Some(FigureMatch {
            shape: FigureShape::CountedNoun,
            end: token_end,
        });
    }
    None
}

fn denominator_end(raw: &[u8], token_end: usize, separator: &str) -> Option<usize> {
    let after: usize = token_end + separator.len();
    if raw.get(token_end..after) != Some(separator.as_bytes()) {
        return None;
    }
    if !raw
        .get(after)
        .is_some_and(|byte: &u8| byte.is_ascii_digit())
    {
        return None;
    }
    Some(numeric_token_end(raw, after))
}

fn slash_denominator_end(raw: &[u8], token_end: usize) -> Option<usize> {
    let mut at: usize = token_end;
    while raw.get(at).is_some_and(|byte: &u8| matches!(byte, b' ')) {
        at += 1;
    }
    if raw.get(at) != Some(&b'/') {
        return None;
    }
    at += 1;
    while raw.get(at).is_some_and(|byte: &u8| matches!(byte, b' ')) {
        at += 1;
    }
    if !raw.get(at).is_some_and(|byte: &u8| byte.is_ascii_digit()) {
        return None;
    }
    Some(numeric_token_end(raw, at))
}

fn counted_noun_follows(rest: &str) -> bool {
    let trimmed: &str = rest.trim_start_matches([' ', '\t']);
    if trimmed.len() == rest.len() {
        return false;
    }
    trimmed.starts_with(|character: char| character.is_ascii_alphabetic())
}

fn is_ordered_list_marker(line: &str, token_start: usize, rest: &str) -> bool {
    let before: &str = line.get(..token_start).unwrap_or_default();
    before.trim().is_empty()
        && (rest.starts_with(". ") || rest.starts_with(") ") || rest.starts_with('.'))
}

const fn prev_byte(bytes: &[u8], at: usize) -> Option<u8> {
    if at == 0 { None } else { Some(bytes[at - 1]) }
}

const fn is_word_byte(byte: Option<u8>) -> bool {
    match byte {
        Some(value) => value.is_ascii_alphanumeric() || value == b'_',
        None => false,
    }
}

fn excluded_tree(relative: &str) -> Option<&'static str> {
    EXCLUDED_TREES
        .iter()
        .find(|(prefix, _): &&(&str, &str)| relative.starts_with(&format!("{prefix}/")))
        .map(|(_, reason): &(&str, &str)| *reason)
}

fn budget_for(relative: &str) -> FigureBudget {
    DOCUMENT_FIGURE_BUDGET
        .iter()
        .find(|budget: &&FigureBudget| budget.path == relative)
        .copied()
        .unwrap_or(FigureBudget {
            path: "",
            figures: 0,
            digest: EMPTY_DIGEST,
        })
}

const MAX_REPORTED_FIGURES: usize = 12;

fn summarize(figures: &[&str]) -> String {
    let head: String = figures
        .iter()
        .take(MAX_REPORTED_FIGURES)
        .copied()
        .collect::<Vec<&str>>()
        .join(", ");
    match figures.len().checked_sub(MAX_REPORTED_FIGURES) {
        Some(rest) if rest > 0 => format!("{head}, and {rest} more"),
        _ => head,
    }
}

fn figure_digest(texts: &[&str]) -> String {
    let mut hasher: Sha256 = Sha256::new();
    for text in texts {
        let len: u64 = u64::try_from(text.len()).unwrap_or(u64::MAX);
        hasher.update(len.to_le_bytes());
        hasher.update(text.as_bytes());
    }
    let full: String = format!("{:x}", hasher.finalize());
    full.chars().take(16).collect()
}

fn manifest(root: &Path) -> Result<Vec<PathBuf>> {
    let walker: walkdir::IntoIter = walkdir::WalkDir::new(root).into_iter();
    let mut files: Vec<PathBuf> = Vec::new();
    for entry in walker.filter_entry(|dirent: &walkdir::DirEntry| !skipped_dir(dirent)) {
        let dirent: walkdir::DirEntry =
            entry.wrap_err_with(|| format!("walking {}", root.display()))?;
        let path: &Path = dirent.path();
        if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md") {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn skipped_dir(dirent: &walkdir::DirEntry) -> bool {
    dirent.file_type().is_dir()
        && dirent.file_name().to_str().is_some_and(|name: &str| {
            !SCANNED_DOT_DIR_NAMES.contains(&name)
                && (name.starts_with('.')
                    || name.starts_with("__")
                    || SKIPPED_DIR_NAMES.contains(&name))
        })
}

fn relative_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let files: Vec<PathBuf> = manifest(root)?;
    let mut faults: Vec<String> = Vec::new();
    let mut scanned: usize = 0;
    let mut excluded: usize = 0;
    let mut wrapped: usize = 0;
    let mut ignored: usize = 0;
    let mut budgeted: usize = 0;
    let mut unbudgeted_shapes: usize = 0;

    let mut visited: Vec<String> = Vec::with_capacity(files.len());
    for path in &files {
        let relative: String = relative_label(root, path);
        if excluded_tree(&relative).is_some() {
            excluded += 1;
            continue;
        }
        scanned += 1;
        visited.push(relative.clone());
        let text: String = read_text_bounded(path, MAX_DOC_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let coverage: crate::metrics::MarkerCoverage = match crate::metrics::marker_coverage(&text)
        {
            Ok(coverage) => coverage,
            Err(error) => {
                faults.push(format!(
                    "{relative}: its marker spans do not parse, so no figure in it can be proven \
                     to track a data file: {error}"
                ));
                continue;
            }
        };
        let figures: Vec<Figure> = detect(&text, &coverage.spans, &coverage.suppressed_lines);
        let mut loose: Vec<&str> = Vec::new();
        for figure in &figures {
            if figure.covered {
                wrapped += 1;
                continue;
            }
            if !figure.shape.is_budgeted() {
                unbudgeted_shapes += 1;
                continue;
            }
            if figure.suppressed {
                ignored += 1;
                continue;
            }
            budgeted += 1;
            loose.push(text.get(figure.start..figure.end).unwrap_or_default());
        }
        let declared: FigureBudget = budget_for(&relative);
        let digest: String = figure_digest(&loose);
        if loose.len() != declared.figures || digest != declared.digest {
            faults.push(format!(
                "{relative} carries {} published figure(s) outside every marker span hashing to \
                 {digest}, but DOCUMENT_FIGURE_BUDGET in xtask/src/figures.rs declares {} hashing \
                 to {}. the figures now written there are [{}]. wrap the figure in a marker span \
                 so xtask/src/metrics.rs compares it against the data file behind it, mark its \
                 line with the metrics ignore marker, or pin what is written now with \
                 `FigureBudget {{ path: {relative:?}, figures: {}, digest: {digest:?} }},`",
                loose.len(),
                declared.figures,
                declared.digest,
                summarize(&loose),
                loose.len()
            ));
        }
    }

    for budget in &DOCUMENT_FIGURE_BUDGET {
        if !visited.iter().any(|seen: &String| seen == budget.path) {
            faults.push(format!(
                "{} is pinned in DOCUMENT_FIGURE_BUDGET but no longer reaches the scan, so its \
                 entry guards nothing; drop the entry or restore the file",
                budget.path
            ));
        }
    }

    if !faults.is_empty() {
        bail!(
            "{} committed markdown file(s) disagree with the published-figure budget:\n  {}",
            faults.len(),
            faults.join("\n  ")
        )
    }

    let shapes: String = FigureShape::ALL
        .iter()
        .map(|shape: &FigureShape| format!("{} ({})", shape.label(), shape.excluded_reason()))
        .collect::<Vec<String>>()
        .join("; ");
    println!(
        "xtask regen: published-figure census ok ({scanned} committed markdown file(s) scanned, \
         {excluded} under a generated tree excluded by explicit path and reason, {wrapped} figure(s) \
         inside a marker span that xtask/src/metrics.rs compares against xtask/data/recovery.json, \
         {ignored} figure(s) on a line the ignore marker suppresses, {budgeted} figure(s) declared \
         in DOCUMENT_FIGURE_BUDGET, {unbudgeted_shapes} figure(s) of a shape this budget does not \
         gate). a wrapped figure is proven to agree with the data file behind it, never proven \
         true; a budgeted figure is proven only not to have appeared, vanished or changed its \
         written value since it was pinned, with no data file behind it at all. shapes detected: \
         {shapes}"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shapes_of(text: &str) -> Vec<FigureShape> {
        detect(text, &[], &[])
            .into_iter()
            .map(|figure: Figure| figure.shape)
            .collect()
    }

    #[test]
    fn every_listed_numeric_shape_is_detected() {
        assert_eq!(shapes_of("recovery reached 95%\n"), [FigureShape::Percent]);
        assert_eq!(
            shapes_of("recovery reached 95.09%\n"),
            [FigureShape::Percent]
        );
        assert_eq!(
            shapes_of("recovered 131 of 131 methods\n"),
            [FigureShape::OfPair]
        );
        assert_eq!(
            shapes_of("verifier-clean 118/118\n"),
            [FigureShape::SlashPair]
        );
        assert_eq!(
            shapes_of("verifier-clean 118 / 118\n"),
            [FigureShape::SlashPair]
        );
        assert_eq!(
            shapes_of("the tree carries 62 crates\n"),
            [FigureShape::CountedNoun]
        );
        assert_eq!(shapes_of("targets CPython 3.14\n"), [FigureShape::Version]);
        assert_eq!(shapes_of("pinned at 1.2.3\n"), [FigureShape::Version]);
    }

    #[test]
    fn a_percentage_wins_over_a_version_reading() {
        assert_eq!(shapes_of("floor 96.60%\n"), [FigureShape::Percent]);
    }

    #[test]
    fn a_figure_inside_a_marker_span_is_marked_covered() {
        let text: &str = "rate <!-- m:key -->95.09%<!-- /m --> today\n";
        let start: usize = text.find("95.09%").unwrap_or_default();
        let figures: Vec<Figure> = detect(text, &[(start, start + "95.09%".len())], &[]);
        assert_eq!(figures.len(), 1);
        assert!(figures[0].covered);
    }

    #[test]
    fn a_suppressed_line_keeps_its_figure_but_marks_it() {
        let figures: Vec<Figure> = detect("rate 95.09% today\n", &[], &[1]);
        assert_eq!(figures.len(), 1);
        assert!(figures[0].suppressed);
        assert!(!figures[0].covered);
    }

    #[test]
    fn a_fenced_block_carries_no_published_figure() {
        assert!(shapes_of("```\nrate 95.09%\n```\n").is_empty());
    }

    #[test]
    fn an_ordered_list_marker_is_not_a_count() {
        assert!(shapes_of("1. Confirm the workspace root\n").is_empty());
        assert!(shapes_of("2) Confirm the branch\n").is_empty());
    }

    #[test]
    fn a_figure_inside_a_word_is_not_a_figure() {
        assert!(shapes_of("see DR-CLI-0001 for detail\n").is_empty());
        assert!(shapes_of("the x86_64 lifter\n").is_empty());
    }

    #[test]
    fn a_seeded_document_reports_each_shape_once() {
        let text: &str = concat!(
            "# seeded\n",
            "\n",
            "recovery reached 95.09% on the pinned corpus.\n",
            "the gate accepted 131 of 131 methods.\n",
            "the verifier accepted 118/118 classes.\n",
            "the tree carries 62 crates.\n",
            "it targets CPython 3.14.\n",
        );
        let mut shapes: Vec<FigureShape> = shapes_of(text);
        shapes.sort_unstable();
        shapes.dedup();
        assert_eq!(shapes, FigureShape::ALL);
    }

    #[test]
    fn a_long_figure_list_is_summarized_rather_than_printed_whole() {
        let many: Vec<&str> = vec!["1 of 2"; MAX_REPORTED_FIGURES + 5];
        let summary: String = summarize(&many);
        assert!(summary.ends_with(", and 5 more"), "{summary}");
        let few: Vec<&str> = vec!["1 of 2", "3 of 4"];
        assert_eq!(summarize(&few), "1 of 2, 3 of 4");
    }

    #[test]
    fn the_empty_digest_constant_is_the_digest_of_no_figures() {
        assert_eq!(figure_digest(&[]), EMPTY_DIGEST);
    }

    #[test]
    fn editing_a_figure_value_changes_the_pinned_digest() {
        let before: String = figure_digest(&["95.09%", "131 of 131"]);
        let after: String = figure_digest(&["95.19%", "131 of 131"]);
        assert_ne!(before, after);
    }

    #[test]
    fn reordering_two_figures_changes_the_pinned_digest() {
        let forward: String = figure_digest(&["1 of 2", "3 of 4"]);
        let reversed: String = figure_digest(&["3 of 4", "1 of 2"]);
        assert_ne!(forward, reversed);
    }

    #[test]
    fn a_split_figure_cannot_forge_a_neighbour() {
        let split: String = figure_digest(&["12", "34"]);
        let joined: String = figure_digest(&["1234"]);
        assert_ne!(split, joined);
    }

    #[test]
    fn every_excluded_tree_carries_a_reason() {
        for (prefix, reason) in EXCLUDED_TREES {
            assert!(!prefix.is_empty());
            assert!(
                reason.len() > 40,
                "{prefix} must record why nothing else checks its figures"
            );
        }
    }

    #[test]
    fn an_excluded_tree_is_matched_by_prefix_and_nothing_else() {
        assert!(excluded_tree("docs/errors/DR-CLI-0001.md").is_some());
        assert!(excluded_tree("docs/src/introduction.md").is_none());
        assert!(excluded_tree("docs/errors-notes.md").is_none());
    }

    #[test]
    fn a_figure_added_to_a_file_with_no_budget_entry_is_detected() {
        let unlisted: FigureBudget = budget_for("docs/src/a-page-nobody-pinned.md");
        assert_eq!(unlisted.figures, 0);
        assert_eq!(unlisted.digest, EMPTY_DIGEST);
        let text: &str = "the new page states 42.5% recovery\n";
        let figures: Vec<Figure> = detect(text, &[], &[]);
        let loose: Vec<&str> = figures
            .iter()
            .filter(|figure: &&Figure| figure.shape.is_budgeted())
            .map(|figure: &Figure| text.get(figure.start..figure.end).unwrap_or_default())
            .collect();
        assert_eq!(loose, ["42.5%"]);
        assert_ne!(loose.len(), unlisted.figures);
        assert_ne!(figure_digest(&loose), unlisted.digest);
    }

    #[test]
    fn a_budget_entry_for_a_vanished_file_cannot_be_satisfied_silently() {
        let paths: Vec<&'static str> = DOCUMENT_FIGURE_BUDGET
            .iter()
            .map(|budget: &FigureBudget| budget.path)
            .collect();
        let mut sorted: Vec<&'static str> = paths.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            paths.len(),
            "one path is pinned twice, so one entry would never be reached"
        );
        for path in paths {
            assert!(
                !path.is_empty() && !path.starts_with('/') && !path.contains('\\'),
                "{path} must be a repository-relative path with forward slashes"
            );
        }
    }
}
