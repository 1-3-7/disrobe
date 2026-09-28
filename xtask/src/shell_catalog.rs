use std::collections::BTreeMap;
use std::path::Path;

use eyre::{Result, WrapErr, bail, eyre};
use toml::Value;

use crate::fileio::read_text_bounded;

pub(crate) const MANIFEST: &str = "corpus/shell/MANIFEST.toml";
pub(crate) const CATALOG_DOC: &str = "docs/src/catalog.md";
const CORPUS_ROOT: &str = "corpus/shell";
const MAX_TEXT_BYTES: u64 = 1024 * 1024;
const ROW_PREFIX: &str = "| **Shell obfuscators** |";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Evidence {
    ToolOutput,
    SpecGenerator,
    HandWritten,
    SignatureOnly,
}

impl Evidence {
    fn from_status(status: &str) -> Option<Self> {
        match status {
            "REAL-FIXTURE" => Some(Self::ToolOutput),
            "FROM-SPEC-GENERATOR" => Some(Self::SpecGenerator),
            "HAND-WRITTEN" => Some(Self::HandWritten),
            "TOOL-PAID-DEFER" | "TOOL-DEAD-DOCUMENT" => Some(Self::SignatureOnly),
            _ => None,
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::ToolOutput => "Graded on the tool's own output:",
            Self::SpecGenerator => "Graded on output of a from-spec generator",
            Self::HandWritten => "Graded on hand-written snippets:",
            Self::SignatureOnly => "Detected by signature with no committed sample:",
        }
    }

    const ALL: [Self; 4] = [
        Self::ToolOutput,
        Self::SpecGenerator,
        Self::HandWritten,
        Self::SignatureOnly,
    ];
}

#[derive(Debug)]
struct Family {
    section: String,
    catalog_name: String,
    evidence: Evidence,
    fixtures: Vec<String>,
    graded_by: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ShellCatalogScan {
    pub(crate) families: usize,
    pub(crate) problems: Vec<String>,
}

pub(crate) fn scan(root: &Path) -> Result<ShellCatalogScan> {
    let manifest: String = read_text_bounded(&root.join(MANIFEST), MAX_TEXT_BYTES)
        .wrap_err_with(|| format!("reading {MANIFEST}"))?;
    let catalog: String = read_text_bounded(&root.join(CATALOG_DOC), MAX_TEXT_BYTES)
        .wrap_err_with(|| format!("reading {CATALOG_DOC}"))?;
    let families: Vec<Family> = parse_families(&manifest)?;
    let groups: BTreeMap<Evidence, String> = catalog_groups(&catalog)?;
    let mut problems: Vec<String> = judge(&families, &groups);
    for family in &families {
        for fixture in &family.fixtures {
            if !root.join(CORPUS_ROOT).join(fixture).is_file() {
                problems.push(format!(
                    "{}: fixture {CORPUS_ROOT}/{fixture} is missing",
                    family.section
                ));
            }
        }
        if let Some(test) = &family.graded_by
            && !root.join(test).is_file()
        {
            problems.push(format!("{}: graded_by {test} is missing", family.section));
        }
    }
    Ok(ShellCatalogScan {
        families: families.len(),
        problems,
    })
}

fn parse_families(manifest: &str) -> Result<Vec<Family>> {
    let document: toml::Table =
        toml::from_str(manifest).wrap_err_with(|| format!("parsing {MANIFEST}"))?;
    let mut families: Vec<Family> = Vec::new();
    for (language, value) in &document {
        let Value::Table(sections) = value else {
            continue;
        };
        for (name, entry) in sections {
            let Value::Table(entry) = entry else {
                continue;
            };
            let section: String = format!("{language}.{name}");
            let Some(catalog_name) = entry.get("catalog_name") else {
                continue;
            };
            let catalog_name: &str = catalog_name
                .as_str()
                .ok_or_else(|| eyre!("{section}: catalog_name is not a string"))?;
            let status: &str = entry
                .get("status")
                .and_then(Value::as_str)
                .ok_or_else(|| eyre!("{section}: a catalogued family needs a status"))?;
            let evidence: Evidence = Evidence::from_status(status).ok_or_else(|| {
                eyre!("{section}: status {status} does not name how the family is graded")
            })?;
            let fixtures: Vec<String> = match entry.get("fixtures") {
                None => Vec::new(),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item: &Value| {
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| eyre!("{section}: a fixture path is not a string"))
                    })
                    .collect::<Result<_>>()?,
                Some(_) => bail!("{section}: fixtures is not an array"),
            };
            let graded_by: Option<String> = match entry.get("graded_by") {
                None => None,
                Some(Value::String(path)) => Some(path.clone()),
                Some(_) => bail!("{section}: graded_by is not a string"),
            };
            families.push(Family {
                section,
                catalog_name: catalog_name.to_owned(),
                evidence,
                fixtures,
                graded_by,
            });
        }
    }
    if families.is_empty() {
        bail!("{MANIFEST} names no catalogued shell family");
    }
    Ok(families)
}

fn catalog_groups(catalog: &str) -> Result<BTreeMap<Evidence, String>> {
    let row: &str = catalog
        .lines()
        .find(|line: &&str| line.starts_with(ROW_PREFIX))
        .ok_or_else(|| eyre!("{CATALOG_DOC} has no `{ROW_PREFIX}` row"))?;
    let families: &str = row
        .trim_end()
        .trim_end_matches('|')
        .rsplit('|')
        .next()
        .ok_or_else(|| eyre!("the shell obfuscator row has no families cell"))?;
    let mut starts: Vec<(usize, Evidence)> = Evidence::ALL
        .iter()
        .filter_map(|evidence: &Evidence| {
            families
                .find(evidence.label())
                .map(|at: usize| (at, *evidence))
        })
        .collect();
    starts.sort_unstable();
    let mut groups: BTreeMap<Evidence, String> = BTreeMap::new();
    for (index, (start, evidence)) in starts.iter().enumerate() {
        let end: usize = starts
            .get(index + 1)
            .map_or(families.len(), |(next, _): &(usize, Evidence)| *next);
        let body: &str = &families[start + evidence.label().len()..end];
        let body: &str = if *evidence == Evidence::SpecGenerator {
            body.split_once(':')
                .map_or(body, |(_, rest): (&str, &str)| rest)
        } else {
            body
        };
        groups.insert(*evidence, body.trim().trim_end_matches('.').to_owned());
    }
    Ok(groups)
}

fn judge(families: &[Family], groups: &BTreeMap<Evidence, String>) -> Vec<String> {
    let mut problems: Vec<String> = Vec::new();
    for family in families {
        let named_in: Vec<Evidence> = groups
            .iter()
            .filter(|(_, text): &(&Evidence, &String)| text.contains(&family.catalog_name))
            .map(|(evidence, _): (&Evidence, &String)| *evidence)
            .collect();
        if !named_in.contains(&family.evidence) {
            problems.push(format!(
                "{}: `{}` is not listed after \"{}\" in the shell row of {CATALOG_DOC}",
                family.section,
                family.catalog_name,
                family.evidence.label()
            ));
        }
        if let Some(other) = named_in
            .iter()
            .find(|evidence: &&Evidence| **evidence != family.evidence)
        {
            problems.push(format!(
                "{}: `{}` is also listed after \"{}\"",
                family.section,
                family.catalog_name,
                other.label()
            ));
        }
        let graded_on_samples: bool = matches!(
            family.evidence,
            Evidence::ToolOutput | Evidence::SpecGenerator
        );
        if graded_on_samples && family.fixtures.is_empty() {
            problems.push(format!(
                "{}: graded on samples but lists no fixture",
                family.section
            ));
        }
        if family.evidence == Evidence::HandWritten && family.graded_by.is_none() {
            problems.push(format!(
                "{}: hand-written snippets need a graded_by test",
                family.section
            ));
        }
    }
    if let Some(tool_group) = groups.get(&Evidence::ToolOutput) {
        let residue: String = unaccounted(
            tool_group,
            families
                .iter()
                .filter(|family: &&Family| family.evidence == Evidence::ToolOutput)
                .map(|family: &Family| family.catalog_name.as_str()),
        );
        if !residue.is_empty() {
            problems.push(format!(
                "the shell row claims tool-output grading for `{residue}`, which no REAL-FIXTURE entry in {MANIFEST} names"
            ));
        }
    }
    problems
}

fn unaccounted<'a>(group: &str, names: impl Iterator<Item = &'a str>) -> String {
    let mut text: String = String::with_capacity(group.len());
    let mut depth: usize = 0;
    for c in group.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => text.push(c),
            _ => {}
        }
    }
    for name in names {
        text = text.replace(name, " ");
    }
    text.split(|c: char| c == ',' || c.is_whitespace())
        .filter(|word: &&str| !word.is_empty() && *word != "and")
        .collect::<Vec<&str>>()
        .join(" ")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const MANIFEST_TEXT: &str = r#"
[powershell.stealth]
status = "REAL-FIXTURE"
catalog_name = "Invoke-Stealth"
fixtures = ["powershell/invoke-stealth/hello.ps1"]

[powershell.generated]
status = "FROM-SPEC-GENERATOR"
catalog_name = "Invoke-Obfuscation"
fixtures = ["powershell/invoke-obfuscation/token/hello.ps1"]

[bash.indirection]
status = "HAND-WRITTEN"
catalog_name = "bash IFS/eval indirection"
graded_by = "crates/disrobe-pass-shell/tests/bash_indirection_real.rs"

[powershell.powerhell]
status = "TOOL-DEAD-DOCUMENT"
catalog_name = "PowerHell"

[powershell.megafile]
status = "SYNTHESIZED"
"#;

    const ROW: &str = "| **Shell obfuscators** | 19 | Graded on the tool's own output: Invoke-Stealth (ReverseB64). Graded on output of a from-spec generator because the upstream tool cannot run here: PowerShell Invoke-Obfuscation (Token; Defender blocks the module). Graded on hand-written snippets: bash IFS/eval indirection. Detected by signature with no committed sample: PowerHell (upstream removed) |";

    fn problems(manifest: &str, row: &str) -> Vec<String> {
        let families: Vec<Family> = parse_families(manifest).expect("families");
        let groups: BTreeMap<Evidence, String> = catalog_groups(row).expect("groups");
        judge(&families, &groups)
    }

    #[test]
    fn a_row_that_matches_the_manifest_has_no_problem() {
        assert_eq!(problems(MANIFEST_TEXT, ROW), Vec::<String>::new());
    }

    #[test]
    fn a_family_listed_under_the_wrong_evidence_fails() {
        let demoted: String = MANIFEST_TEXT.replacen("REAL-FIXTURE", "TOOL-DEAD-DOCUMENT", 1);
        let found: Vec<String> = problems(&demoted, ROW);
        assert!(
            found
                .iter()
                .any(|problem: &String| problem.contains("powershell.stealth")),
            "{found:?}"
        );
    }

    #[test]
    fn a_tool_output_claim_without_a_real_fixture_fails() {
        let row: String = ROW.replace("Invoke-Stealth (ReverseB64)", "Invoke-Stealth and Chimera");
        let found: Vec<String> = problems(MANIFEST_TEXT, &row);
        assert!(
            found
                .iter()
                .any(|problem: &String| problem.contains("`Chimera`")),
            "{found:?}"
        );
    }

    #[test]
    fn a_graded_family_without_fixtures_fails() {
        let bare: String =
            MANIFEST_TEXT.replace("fixtures = [\"powershell/invoke-stealth/hello.ps1\"]\n", "");
        let found: Vec<String> = problems(&bare, ROW);
        assert!(
            found
                .iter()
                .any(|problem: &String| problem.contains("lists no fixture")),
            "{found:?}"
        );
    }

    #[test]
    fn an_unknown_status_is_an_error() {
        let unknown: String = MANIFEST_TEXT.replacen("REAL-FIXTURE", "MAYBE", 1);
        assert!(parse_families(&unknown).is_err());
    }
}
