use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

const MAX_README_BYTES: u64 = 4 * 1024 * 1024;
const MAX_DESCRIPTOR_BYTES: u64 = 256 * 1024;

const BENCHMARKS_HEADING: &str = "## Benchmarks";
const NEXT_SECTION_HEADING: &str = "## Ecosystem maturity matrix";

const TABLE_HEADER_ROW: &str = "| Metric | Measured | Oracle | Reproduce |";

const RECOMPILE_ONLY_MARKER: &str = "recompile-only";
const SELF_REPORTED_MARKER: &str = "coverage-self-reported";

const STRONG_TIER: &str = "Strong";
const RECOMPILE_ONLY_TIER: &str = "Recompile-only";
const SELF_REPORTED_TIER: &str = "Self-reported coverage";

struct TierTable {
    heading: &'static str,
    next_heading: Option<&'static str>,
    tier_name: &'static str,
}

const TIER_TABLES: [TierTable; 3] = [
    TierTable {
        heading: "### Strong",
        next_heading: Some("### Recompile-only"),
        tier_name: STRONG_TIER,
    },
    TierTable {
        heading: "### Recompile-only",
        next_heading: Some("### Self-reported coverage"),
        tier_name: RECOMPILE_ONLY_TIER,
    },
    TierTable {
        heading: "### Self-reported coverage",
        next_heading: None,
        tier_name: SELF_REPORTED_TIER,
    },
];

struct TableRow {
    metric: String,
    raw_line: String,
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let readme_path: PathBuf = root.join("README.md");
    let readme: String = read_text_bounded(&readme_path, MAX_README_BYTES)
        .wrap_err_with(|| format!("reading {}", readme_path.display()))?;

    let benchmarks_section: &str =
        extract_section(&readme, BENCHMARKS_HEADING, NEXT_SECTION_HEADING)?;

    let recorded: BTreeMap<String, DescriptorTier> = descriptor_tiers(root)?;
    let mut drift: Vec<String> = Vec::new();
    let mut placed_rows: usize = 0;
    let mut bound_rows: usize = 0;

    for table in &TIER_TABLES {
        let table_section: &str = match table.next_heading {
            Some(next) => extract_section(benchmarks_section, table.heading, next)?,
            None => extract_section_to_end(benchmarks_section, table.heading)?,
        };
        let rows: Vec<TableRow> = parse_table_rows(table_section);
        if rows.is_empty() {
            bail!(
                "README.md's `{}` benchmark table under `{}` has no data rows",
                table.tier_name,
                table.heading
            );
        }
        placed_rows += rows.len();
        for row in &rows {
            let declared_tier: &'static str = declared_tier_for_row(&row.raw_line);
            if declared_tier != table.tier_name {
                drift.push(format!(
                    "`{}` sits in the `{}` table but its own row text declares tier `{}`",
                    row.metric, table.tier_name, declared_tier
                ));
            }
            let mut bound: bool = false;
            for test_name in cited_test_names(&row.raw_line) {
                let Some(descriptor): Option<&DescriptorTier> = recorded.get(&test_name) else {
                    continue;
                };
                bound = true;
                if descriptor.tier != table.tier_name {
                    drift.push(format!(
                        "`{}` sits in the `{}` table, but evidence/descriptors/{}.toml records its oracle strength as `{}`, which is the `{}` tier; the README row and the descriptor cannot both be right",
                        row.metric,
                        table.tier_name,
                        descriptor.id,
                        descriptor.strength,
                        descriptor.tier
                    ));
                }
            }
            if bound {
                bound_rows += 1;
            }
        }
    }

    let all_rows: Vec<TableRow> = parse_table_rows(benchmarks_section);
    if all_rows.len() != placed_rows {
        drift.push(format!(
            "README.md's Benchmarks section has {} total table row(s) but only {} sit inside the three recognized `### Strong` / `### Recompile-only` / `### Self-reported coverage` tables; a row is orphaned outside all three, or an unexpected table exists",
            all_rows.len(),
            placed_rows
        ));
    }

    if drift.is_empty() {
        println!(
            "xtask regen: tiered-results cross-check ok ({placed_rows} benchmark row(s) across Strong/Recompile-only/Self-reported coverage all match their own declared tier; {bound_rows} of them also match the oracle strength recorded in evidence/descriptors, and the remaining {} cite no descriptor-backed test)",
            placed_rows.saturating_sub(bound_rows)
        );
        Ok(())
    } else {
        bail!(
            "README.md's Benchmarks tables place a row under a tier its own text doesn't declare; move the row to the table matching its own `recompile-only` / `coverage-self-reported` marker (or absence of either, for `strong`):\n  {}",
            drift.join("\n  ")
        )
    }
}

struct DescriptorTier {
    id: String,
    strength: String,
    tier: &'static str,
}

fn tier_for_strength(strength: &str) -> Option<&'static str> {
    match strength {
        "strong" => Some(STRONG_TIER),
        RECOMPILE_ONLY_MARKER => Some(RECOMPILE_ONLY_TIER),
        SELF_REPORTED_MARKER => Some(SELF_REPORTED_TIER),
        _ => None,
    }
}

fn descriptor_tiers(root: &Path) -> Result<BTreeMap<String, DescriptorTier>> {
    let dir: PathBuf = root.join("evidence").join("descriptors");
    let mut tiers: BTreeMap<String, DescriptorTier> = BTreeMap::new();
    if !dir.is_dir() {
        return Ok(tiers);
    }
    let entries: std::fs::ReadDir =
        std::fs::read_dir(&dir).wrap_err_with(|| format!("listing {}", dir.display()))?;
    for entry in entries {
        let path: PathBuf = entry
            .wrap_err_with(|| format!("reading an entry of {}", dir.display()))?
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("toml") {
            continue;
        }
        let raw: String = read_text_bounded(&path, MAX_DESCRIPTOR_BYTES)
            .wrap_err_with(|| format!("reading {}", path.display()))?;
        let parsed: toml::Table = raw
            .parse::<toml::Table>()
            .wrap_err_with(|| format!("parsing {}", path.display()))?;
        let Some(strength): Option<&str> =
            parsed.get("oracle_strength").and_then(toml::Value::as_str)
        else {
            continue;
        };
        let Some(tier): Option<&'static str> = tier_for_strength(strength) else {
            bail!(
                "{} declares oracle_strength `{strength}`, which is not one of `strong`, `{RECOMPILE_ONLY_MARKER}`, `{SELF_REPORTED_MARKER}`",
                path.display()
            );
        };
        let id: String = parsed
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| eyre!("{} has no id", path.display()))?
            .to_owned();
        let reproduce: Option<&str> = parsed
            .get("oracle")
            .and_then(|oracle: &toml::Value| oracle.get("reproduce"))
            .and_then(toml::Value::as_str);
        for test_name in reproduce.map(cited_test_names).unwrap_or_default() {
            tiers.insert(
                test_name,
                DescriptorTier {
                    id: id.clone(),
                    strength: strength.to_owned(),
                    tier,
                },
            );
        }
    }
    Ok(tiers)
}

pub(crate) fn cited_test_names(text: &str) -> Vec<String> {
    let mut names: Vec<String> = Vec::new();
    for (index, token) in text.split_whitespace().enumerate() {
        let cleaned: &str = token.trim_matches(|c: char| c == '`' || c == '|' || c == ',');
        if let Some(stem) = cleaned.strip_suffix(".rs")
            && let Some((_, file)) = stem.rsplit_once('/')
        {
            names.push(file.to_owned());
        }
        if index > 0
            && text.split_whitespace().nth(index - 1) == Some("--test")
            && !cleaned.is_empty()
        {
            names.push(cleaned.to_owned());
        }
    }
    names.sort_unstable();
    names.dedup();
    names
}

fn extract_section<'doc>(
    markdown: &'doc str,
    start_marker: &str,
    end_marker: &str,
) -> Result<&'doc str> {
    let start: usize = markdown
        .find(start_marker)
        .ok_or_else(|| eyre!("README.md is missing the heading `{start_marker}`"))?;
    let after_start: usize = start + start_marker.len();
    let end_offset: usize = markdown[after_start..].find(end_marker).ok_or_else(|| {
        eyre!("README.md is missing the heading `{end_marker}` after `{start_marker}`")
    })?;
    Ok(&markdown[after_start..after_start + end_offset])
}

fn extract_section_to_end<'doc>(markdown: &'doc str, start_marker: &str) -> Result<&'doc str> {
    let start: usize = markdown
        .find(start_marker)
        .ok_or_else(|| eyre!("README.md is missing the heading `{start_marker}`"))?;
    Ok(&markdown[start + start_marker.len()..])
}

fn parse_table_rows(section: &str) -> Vec<TableRow> {
    section
        .lines()
        .map(str::trim)
        .filter(|line: &&str| line.starts_with('|'))
        .filter(|line: &&str| *line != TABLE_HEADER_ROW && !is_separator_row(line))
        .map(|line: &str| TableRow {
            metric: row_metric(line),
            raw_line: line.to_owned(),
        })
        .collect()
}

fn is_separator_row(line: &str) -> bool {
    let trimmed: &str = line.trim_matches('|');
    !trimmed.is_empty()
        && trimmed.split('|').all(|cell: &str| {
            let cell: &str = cell.trim();
            !cell.is_empty() && cell.chars().all(|c: char| c == '-' || c == ':')
        })
}

pub(crate) fn row_metric(line: &str) -> String {
    line.trim_matches('|')
        .split('|')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned()
}

fn declared_tier_for_row(raw_line: &str) -> &'static str {
    if raw_line.contains(SELF_REPORTED_MARKER) {
        SELF_REPORTED_TIER
    } else if raw_line.contains(RECOMPILE_ONLY_MARKER) {
        RECOMPILE_ONLY_TIER
    } else {
        STRONG_TIER
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn extract_section_slices_between_markers() -> core::result::Result<(), String> {
        let markdown: &str = "prefix\n## A\nbody\n## B\nsuffix";
        let section: &str = extract_section(markdown, "## A", "## B").map_err(|e| e.to_string())?;
        assert_eq!(section, "\nbody\n");
        Ok(())
    }

    #[test]
    fn extract_section_to_end_slices_from_marker_to_eof() -> core::result::Result<(), String> {
        let markdown: &str = "prefix\n### Tail\nbody here";
        let section: &str =
            extract_section_to_end(markdown, "### Tail").map_err(|e| e.to_string())?;
        assert_eq!(section, "\nbody here");
        Ok(())
    }

    #[test]
    fn is_separator_row_matches_dash_only_cells() {
        assert!(is_separator_row("|---|---|---|---|"));
        assert!(is_separator_row("| --- | :--- | ---: | :---: |"));
        assert!(!is_separator_row(
            "| Metric | Measured | Oracle | Reproduce |"
        ));
        assert!(!is_separator_row("| foo | bar |"));
    }

    #[test]
    fn row_metric_extracts_first_cell() {
        assert_eq!(
            row_metric("| JVM classfile | 131 / 131 `recompile-only` | real javac | tests/x.rs |"),
            "JVM classfile"
        );
    }

    #[test]
    fn declared_tier_for_row_prioritizes_self_reported_over_recompile_only() {
        assert_eq!(
            declared_tier_for_row("a coverage-self-reported and recompile-only row"),
            SELF_REPORTED_TIER
        );
    }

    #[test]
    fn declared_tier_for_row_defaults_to_strong() {
        assert_eq!(
            declared_tier_for_row("byte-identity vs committed original"),
            STRONG_TIER
        );
    }

    #[test]
    fn declared_tier_for_row_detects_each_marker() {
        assert_eq!(
            declared_tier_for_row("compiles but not byte-equivalent `recompile-only`"),
            RECOMPILE_ONLY_TIER
        );
        assert_eq!(
            declared_tier_for_row("a coverage count `coverage-self-reported`"),
            SELF_REPORTED_TIER
        );
    }

    fn fake_readme(strong_rows: &str, recompile_rows: &str, self_reported_rows: &str) -> String {
        format!(
            "{BENCHMARKS_HEADING}\n\nlegend text\n\n### Strong\n\none-liner\n\n{TABLE_HEADER_ROW}\n|---|---|---|---|\n{strong_rows}\n\n### Recompile-only\n\none-liner\n\n{TABLE_HEADER_ROW}\n|---|---|---|---|\n{recompile_rows}\n\n### Self-reported coverage\n\none-liner\n\n{TABLE_HEADER_ROW}\n|---|---|---|---|\n{self_reported_rows}\n\n{NEXT_SECTION_HEADING}\n\nnext section\n"
        )
    }

    #[test]
    fn run_passes_on_a_correctly_tiered_readme() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let strong: &str =
            "| Native UPX | byte-identical | byte-identity vs committed original | tests/x.rs |";
        let recompile: &str = "| JVM classfile | 131 / 131 `recompile-only` | real javac; recompile-only | tests/y.rs |";
        let self_reported: &str = "| Android DEX, real APKs | 92.5% `coverage-self-reported` | per-method body-recovery count, self-reported | tests/z.rs |";
        let readme: String = fake_readme(strong, recompile, self_reported);
        std::fs::write(dir.path().join("README.md"), &readme).map_err(|e| e.to_string())?;
        run(dir.path()).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[test]
    fn run_fails_on_a_row_mutated_into_the_wrong_table() -> core::result::Result<(), String> {
        let dir: tempfile::TempDir = tempfile::tempdir().map_err(|e| e.to_string())?;
        let recompile: &str = "| JVM classfile | 131 / 131 `recompile-only` | real javac; recompile-only | tests/y.rs |";
        let mutated_strong: &str = "| Native UPX | byte-identical | byte-identity vs committed original | tests/x.rs |\n| Android DEX, real APKs | 92.5% `coverage-self-reported` | per-method body-recovery count, self-reported | tests/z.rs |";
        let empty_self_reported: &str =
            "| frisk IOC detection | 6 / 6 | known-planted endpoints | tests/w.rs |";
        let readme: String = fake_readme(mutated_strong, recompile, empty_self_reported);
        std::fs::write(dir.path().join("README.md"), &readme).map_err(|e| e.to_string())?;
        let err: eyre::Error = run(dir.path()).expect_err("mutated row must be rejected");
        let message: String = format!("{err}");
        assert!(message.contains("Android DEX, real APKs"));
        assert!(message.contains(STRONG_TIER));
        assert!(message.contains(SELF_REPORTED_TIER));
        Ok(())
    }
}
