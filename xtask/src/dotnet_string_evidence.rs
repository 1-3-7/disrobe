use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};
use toml::{Table, Value};

use crate::doc_region::{self, Mode, Region, RegionSyntax};
use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

const PROTECTOR_SOURCE: &str = "crates/disrobe-pass-dotnet/src/protectors.rs";
const CATALOG_DOC: &str = "docs/src/catalog.md";
const CORPUS_ROOT: &str = "corpus";
const MANIFEST_NAME: &str = "MANIFEST.toml";

const ALL_ARRAY: &str = "pub const ALL: [Self;";
const LABEL_FN: &str = "pub const fn label(self) -> &'static str {";
const EVIDENCE_FN: &str = "pub const fn string_evidence(self) -> StringEvidence {";
const EVIDENCE_PATH: &str = "StringEvidence::";
const SELF_PATH: &str = "Self::";

const REAL_SAMPLE: &str = "RealSample";
const MODELLED_ALGORITHM: &str = "ModelledAlgorithm";
const RUNTIME_KEYED: &str = "RuntimeKeyed";
const NOT_CLAIMED: &str = "NotClaimed";

const REAL_PROVENANCE: &str = "real";

const MIN_FAMILIES: usize = 20;

const SYNTAX: RegionSyntax = RegionSyntax {
    open_prefix: "<!-- dotnet-string-evidence:",
    close: "<!-- /dotnet-string-evidence -->",
};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tier {
    NotClaimed,
    RealSample(String),
    ModelledAlgorithm,
    RuntimeKeyed,
}

impl Tier {
    const fn variant(&self) -> &'static str {
        match self {
            Self::NotClaimed => NOT_CLAIMED,
            Self::RealSample(_) => REAL_SAMPLE,
            Self::ModelledAlgorithm => MODELLED_ALGORITHM,
            Self::RuntimeKeyed => RUNTIME_KEYED,
        }
    }

    const fn published(&self) -> bool {
        !matches!(self, Self::NotClaimed)
    }
}

#[derive(Debug, Clone)]
struct ProtectorFamily {
    ident: String,
    label: String,
    tier: Tier,
}

impl ProtectorFamily {
    fn spellings(&self) -> Vec<String> {
        let mut out: Vec<String> = vec![normalize(&self.ident), normalize(&self.label)];
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug)]
struct EvidenceRoster {
    families: Vec<ProtectorFamily>,
}

impl EvidenceRoster {
    fn tier(&self, variant: &str) -> Vec<&ProtectorFamily> {
        self.families
            .iter()
            .filter(|family: &&ProtectorFamily| family.tier.variant() == variant)
            .collect()
    }

    fn published_variants(&self) -> Vec<&'static str> {
        let mut out: Vec<&'static str> = self
            .families
            .iter()
            .filter(|family: &&ProtectorFamily| family.tier.published())
            .map(|family: &ProtectorFamily| family.tier.variant())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    fn render_tier(&self, variant: &str) -> String {
        self.tier(variant)
            .into_iter()
            .map(|family: &ProtectorFamily| family.label.as_str())
            .collect::<Vec<&str>>()
            .join(", ")
    }

    fn resolver(&self) -> Result<BTreeMap<String, String>> {
        let mut out: BTreeMap<String, String> = BTreeMap::new();
        for family in &self.families {
            for spelling in family.spellings() {
                if let Some(previous) = out.insert(spelling.clone(), family.ident.clone())
                    && previous != family.ident
                {
                    bail!(
                        "`{previous}` and `{}` in {PROTECTOR_SOURCE} both answer to the name \
                         `{spelling}` once casing and punctuation are removed, so a published \
                         roster naming it cannot be attributed to one family",
                        family.ident
                    );
                }
            }
        }
        Ok(out)
    }
}

fn normalize(text: &str) -> String {
    text.chars()
        .filter(char::is_ascii_alphanumeric)
        .map(|c: char| c.to_ascii_lowercase())
        .collect()
}

fn kebab(ident: &str) -> String {
    let mut out: String = String::with_capacity(ident.len() + 4);
    for (index, ch) in ident.char_indices() {
        if ch.is_ascii_uppercase() && index > 0 {
            out.push('-');
        }
        out.push(ch.to_ascii_lowercase());
    }
    out
}

fn block_after<'src>(text: &'src str, opener: &str, terminator: &str) -> Option<&'src str> {
    let head: usize = text.find(opener)?;
    let after: &str = text.get(head + opener.len()..)?;
    let close: usize = after.find(terminator)?;
    after.get(..close)
}

fn paths_in(text: &str, prefix: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut rest: &str = text;
    while let Some(at) = rest.find(prefix) {
        let after: &str = rest.get(at + prefix.len()..).unwrap_or_default();
        let ident: String = after
            .chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        if !ident.is_empty() {
            out.push(ident);
        }
        rest = after;
    }
    out
}

fn first_quoted(text: &str) -> Option<&str> {
    let opened: (&str, &str) = text.split_once('"')?;
    opened
        .1
        .split_once('"')
        .map(|closed: (&str, &str)| closed.0)
}

fn parse_declared_order(source: &str) -> Result<Vec<String>> {
    let body: &str = block_after(source, ALL_ARRAY, "\n    ];").ok_or_else(|| {
        eyre!(
            "{PROTECTOR_SOURCE} no longer declares `{ALL_ARRAY}` as a readable array, so the \
             protector roster every page publishes is derived from nothing"
        )
    })?;
    let declared: Vec<String> = paths_in(body, SELF_PATH);
    if declared.len() < MIN_FAMILIES {
        bail!(
            "{PROTECTOR_SOURCE} yielded {} protector famil(y/ies) from `{ALL_ARRAY}`, fewer than \
             the {MIN_FAMILIES} this check requires; the declaration shape moved and every \
             published roster would be compared against a truncated list",
            declared.len()
        );
    }
    let unique: BTreeSet<&String> = declared.iter().collect();
    if unique.len() != declared.len() {
        bail!("`{ALL_ARRAY}` in {PROTECTOR_SOURCE} lists a protector twice");
    }
    Ok(declared)
}

fn parse_labels(source: &str) -> Result<BTreeMap<String, String>> {
    let body: &str = block_after(source, LABEL_FN, "\n    }").ok_or_else(|| {
        eyre!(
            "{PROTECTOR_SOURCE} no longer declares `label` in a shape this check can read, so the \
             name each published row carries is derived from nothing"
        )
    })?;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut segments: std::str::Split<'_, &str> = body.split("=>");
    let mut pending: Vec<String> = segments
        .next()
        .map(|head: &str| paths_in(head, SELF_PATH))
        .unwrap_or_default();
    for segment in segments {
        let label: &str = first_quoted(segment).ok_or_else(|| {
            eyre!("an arm of `label` in {PROTECTOR_SOURCE} resolves to no quoted name")
        })?;
        for ident in std::mem::take(&mut pending) {
            out.insert(ident, label.to_owned());
        }
        let after: &str = segment
            .split_once(label)
            .map_or("", |split: (&str, &str)| split.1);
        pending = paths_in(after, SELF_PATH);
    }
    Ok(out)
}

fn parse_tiers(source: &str) -> Result<BTreeMap<String, Tier>> {
    let body: &str = block_after(source, EVIDENCE_FN, "\n    }").ok_or_else(|| {
        eyre!(
            "{PROTECTOR_SOURCE} no longer declares `string_evidence` in a shape this check can \
             read, so the string-recovery claim each published row makes is derived from nothing"
        )
    })?;
    let mut out: BTreeMap<String, Tier> = BTreeMap::new();
    let mut segments: std::str::Split<'_, &str> = body.split("=>");
    let mut pending: Vec<String> = segments
        .next()
        .map(|head: &str| paths_in(head, SELF_PATH))
        .unwrap_or_default();
    for segment in segments {
        let Some(at) = segment.find(EVIDENCE_PATH) else {
            bail!(
                "an arm of `string_evidence` in {PROTECTOR_SOURCE} resolves to something other \
                 than a `StringEvidence` value, so the tier it assigns cannot be read"
            );
        };
        let tail: &str = segment.get(at..).unwrap_or_default();
        let variant: String = paths_in(tail, EVIDENCE_PATH)
            .first()
            .cloned()
            .ok_or_else(|| eyre!("a `string_evidence` arm in {PROTECTOR_SOURCE} names no tier"))?;
        let after_variant: &str = tail
            .get(EVIDENCE_PATH.len() + variant.len()..)
            .unwrap_or_default();
        let tier: Tier = match variant.as_str() {
            REAL_SAMPLE => {
                let path: &str = first_quoted(after_variant).ok_or_else(|| {
                    eyre!(
                        "a `{REAL_SAMPLE}` arm in {PROTECTOR_SOURCE} names no committed artifact, \
                         so the claim it publishes points at nothing"
                    )
                })?;
                Tier::RealSample(path.to_owned())
            }
            MODELLED_ALGORITHM => Tier::ModelledAlgorithm,
            RUNTIME_KEYED => Tier::RuntimeKeyed,
            NOT_CLAIMED => Tier::NotClaimed,
            other => bail!(
                "`string_evidence` in {PROTECTOR_SOURCE} assigns the unknown tier `{other}`, which \
                 no published roster can describe"
            ),
        };
        for ident in std::mem::take(&mut pending) {
            if let Some(previous) = out.insert(ident.clone(), tier.clone())
                && previous != tier
            {
                bail!(
                    "`{ident}` is assigned both the {} and the {} tier by `string_evidence` in \
                     {PROTECTOR_SOURCE}",
                    previous.variant(),
                    tier.variant()
                );
            }
        }
        pending = paths_in(after_variant, SELF_PATH);
    }
    if !pending.is_empty() {
        bail!(
            "`string_evidence` in {PROTECTOR_SOURCE} ends with {} unmatched pattern(s) ({}), so \
             this check read the arm list wrong and would compare the published tiers against a \
             partial map",
            pending.len(),
            pending.join(", ")
        );
    }
    Ok(out)
}

fn read_repo_text(root: &Path, relative: &str, max_bytes: u64) -> Result<String> {
    let path: PathBuf = root.join(relative);
    read_text_bounded(&path, max_bytes).wrap_err_with(|| format!("reading {relative}"))
}

fn roster(root: &Path) -> Result<EvidenceRoster> {
    let source: String = read_repo_text(root, PROTECTOR_SOURCE, MAX_SOURCE_BYTES)?;
    let declared: Vec<String> = parse_declared_order(&source)?;
    let labels: BTreeMap<String, String> = parse_labels(&source)?;
    let tiers: BTreeMap<String, Tier> = parse_tiers(&source)?;

    let known: BTreeSet<&str> = declared.iter().map(String::as_str).collect();
    for ident in tiers.keys() {
        if !known.contains(ident.as_str()) {
            bail!(
                "`string_evidence` in {PROTECTOR_SOURCE} assigns a tier to `{ident}`, which \
                 `{ALL_ARRAY}` does not declare"
            );
        }
    }

    let mut families: Vec<ProtectorFamily> = Vec::with_capacity(declared.len());
    for ident in declared {
        let tier: Tier = tiers.get(&ident).cloned().ok_or_else(|| {
            eyre!(
                "`{ident}` is declared in `{ALL_ARRAY}` but `string_evidence` in \
                 {PROTECTOR_SOURCE} assigns it no tier, so no published row can state whether its \
                 string recovery rests on a committed sample"
            )
        })?;
        let label: String = labels.get(&ident).cloned().ok_or_else(|| {
            eyre!("`{ident}` is declared in `{ALL_ARRAY}` but `label` names it nothing")
        })?;
        families.push(ProtectorFamily { ident, label, tier });
    }

    let roster: EvidenceRoster = EvidenceRoster { families };
    if roster.tier(REAL_SAMPLE).is_empty() && roster.tier(MODELLED_ALGORITHM).is_empty() {
        bail!(
            "no protector in {PROTECTOR_SOURCE} claims string decryption under either tier, so \
             this check would compare every published roster against an empty set"
        );
    }
    Ok(roster)
}

fn manifest_dir_for(root: &Path, file: &Path) -> Option<PathBuf> {
    let corpus: PathBuf = root.join(CORPUS_ROOT);
    let mut cursor: Option<&Path> = file.parent();
    while let Some(dir) = cursor {
        if !dir.starts_with(&corpus) {
            return None;
        }
        if dir.join(MANIFEST_NAME).is_file() {
            return Some(dir.to_path_buf());
        }
        cursor = dir.parent();
    }
    None
}

fn table_string(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn root_string(manifest: &Table, key: &str) -> Option<String> {
    manifest.get(key)?.as_str().map(str::to_owned)
}

fn fixture_entry<'doc>(manifest: &'doc Table, relative: &str) -> Option<&'doc Value> {
    manifest
        .get("fixture")?
        .as_array()?
        .iter()
        .find(|entry: &&Value| {
            table_string(entry, "path").is_some_and(|declared: String| {
                declared.replace('\\', "/").trim_start_matches("./") == relative
            })
        })
}

fn tool_statements(manifest: &Table, entry: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for key in ["protector", "protector_tool", "protector_repo"] {
        if let Some(text) = table_string(entry, key) {
            out.push(text);
        }
    }
    if let Some(text) = root_string(manifest, "toolchain") {
        out.push(text);
    }
    if let Some(provenance) = manifest.get("provenance")
        && let Some(text) = table_string(provenance, "obfuscator")
    {
        out.push(text);
    }
    out
}

fn check_committed_sample(
    root: &Path,
    family: &ProtectorFamily,
    relative: &str,
    issues: &mut Vec<String>,
) -> Result<()> {
    let file: PathBuf = root.join(relative);
    let metadata: std::fs::Metadata = match std::fs::metadata(&file) {
        Ok(found) => found,
        Err(error) => {
            issues.push(format!(
                "{PROTECTOR_SOURCE}: `{}` publishes string decryption on the committed sample \
                 `{relative}`, which is not in the tree ({error}); the claim rests on no artifact",
                family.ident
            ));
            return Ok(());
        }
    };
    if metadata.len() == 0 {
        issues.push(format!(
            "{PROTECTOR_SOURCE}: the committed sample `{relative}` for `{}` is empty",
            family.ident
        ));
        return Ok(());
    }
    let Some(manifest_dir): Option<PathBuf> = manifest_dir_for(root, &file) else {
        issues.push(format!(
            "{PROTECTOR_SOURCE}: `{}` names `{relative}` as a real protected sample, but no \
             {MANIFEST_NAME} above it records where that artifact came from",
            family.ident
        ));
        return Ok(());
    };
    let manifest_path: PathBuf = manifest_dir.join(MANIFEST_NAME);
    let text: String = read_text_bounded(&manifest_path, MAX_MANIFEST_BYTES)
        .wrap_err_with(|| format!("reading {}", manifest_path.display()))?;
    let manifest: Table = text
        .parse::<Table>()
        .wrap_err_with(|| format!("parsing {}", manifest_path.display()))?;
    let within: String = file.strip_prefix(&manifest_dir).map_or_else(
        |_| relative.to_owned(),
        |rest: &Path| rest.to_string_lossy().replace('\\', "/"),
    );
    let Some(entry): Option<&Value> = fixture_entry(&manifest, &within) else {
        issues.push(format!(
            "{PROTECTOR_SOURCE}: `{}` names `{relative}` as a real protected sample, but \
             {MANIFEST_NAME} beside it records no fixture entry for that file",
            family.ident
        ));
        return Ok(());
    };
    match table_string(entry, "provenance").as_deref() {
        Some(REAL_PROVENANCE) => {}
        Some(other) => issues.push(format!(
            "{PROTECTOR_SOURCE}: `{}` publishes `{relative}` as output of the protector itself, \
             but its {MANIFEST_NAME} entry records `provenance = \"{other}\"`",
            family.ident
        )),
        None => issues.push(format!(
            "{PROTECTOR_SOURCE}: the {MANIFEST_NAME} entry for `{relative}` records no provenance, \
             so the claim `{}` makes on it cannot be traced to a producing tool",
            family.ident
        )),
    }
    let statements: Vec<String> = tool_statements(&manifest, entry);
    let wanted: Vec<String> = family.spellings();
    let named: bool = statements.iter().any(|statement: &String| {
        let flattened: String = normalize(statement);
        wanted
            .iter()
            .any(|spelling: &String| flattened.contains(spelling.as_str()))
    });
    if !named {
        issues.push(format!(
            "{PROTECTOR_SOURCE}: `{relative}` backs the string-decryption claim for `{}`, but \
             nothing in {MANIFEST_NAME} names {} as the tool that produced it",
            family.ident, family.label
        ));
    }
    Ok(())
}

fn check_samples(root: &Path, roster: &EvidenceRoster, issues: &mut Vec<String>) -> Result<()> {
    for family in &roster.families {
        if let Tier::RealSample(relative) = &family.tier {
            check_committed_sample(root, family, relative, issues)?;
        }
    }
    Ok(())
}

fn variant_for_slug(roster: &EvidenceRoster, slug: &str) -> Option<&'static str> {
    roster
        .published_variants()
        .into_iter()
        .find(|variant: &&'static str| kebab(variant) == slug)
}

fn check_region(
    roster: &EvidenceRoster,
    resolver: &BTreeMap<String, String>,
    region: &Region,
    label: &str,
    issues: &mut Vec<String>,
) {
    let Some(variant): Option<&'static str> = variant_for_slug(roster, &region.slug) else {
        issues.push(format!(
            "{label}:{}: `{}` is not a published string-evidence tier; the tiers on record are {}",
            region.line,
            region.slug,
            roster
                .published_variants()
                .into_iter()
                .map(kebab)
                .collect::<Vec<String>>()
                .join(", ")
        ));
        return;
    };

    let mut named: BTreeSet<String> = BTreeSet::new();
    for item in region.content.split(',') {
        let cleaned: &str = item.trim().trim_matches(['`', '*', '_']).trim();
        if cleaned.is_empty() {
            issues.push(format!(
                "{label}:{}: the `{}` roster carries an empty entry",
                region.line, region.slug
            ));
            continue;
        }
        match resolver.get(&normalize(cleaned)) {
            Some(ident) => {
                if !named.insert(ident.clone()) {
                    issues.push(format!(
                        "{label}:{}: the `{}` roster names `{cleaned}` twice",
                        region.line, region.slug
                    ));
                }
            }
            None => issues.push(format!(
                "{label}:{}: the `{}` roster claims `{cleaned}`, which no protector in \
                 {PROTECTOR_SOURCE} answers to",
                region.line, region.slug
            )),
        }
    }

    let expected: BTreeSet<String> = roster
        .tier(variant)
        .into_iter()
        .map(|family: &ProtectorFamily| family.ident.clone())
        .collect();
    for ident in expected.difference(&named) {
        issues.push(format!(
            "{label}:{}: the `{}` roster omits `{ident}`, which {PROTECTOR_SOURCE} places in that \
             tier, so the page publishes string decryption for it without stating what backs the \
             claim",
            region.line, region.slug
        ));
    }
    for ident in named.difference(&expected) {
        let carried: String = roster
            .families
            .iter()
            .find(|family: &&ProtectorFamily| family.ident == *ident)
            .map_or_else(
                || "no".to_owned(),
                |family: &ProtectorFamily| kebab(family.tier.variant()),
            );
        issues.push(format!(
            "{label}:{}: the `{}` roster claims `{ident}`, which {PROTECTOR_SOURCE} places in the \
             {carried} tier instead, so the page credits it with the wrong evidence",
            region.line, region.slug
        ));
    }
}

fn check_published_tiers(
    roster: &EvidenceRoster,
    seen: &BTreeSet<String>,
    issues: &mut Vec<String>,
) {
    for variant in roster.published_variants() {
        let slug: String = kebab(variant);
        if !seen.contains(&slug) {
            issues.push(format!(
                "{CATALOG_DOC} publishes no `{slug}` roster region, so the {} famil(y/ies) in that \
                 tier state their evidence nowhere a check can read",
                roster.tier(variant).len()
            ));
        }
    }
}

fn render_tier(roster: &EvidenceRoster, slug: &str) -> Result<String> {
    let Some(variant): Option<&'static str> = variant_for_slug(roster, slug) else {
        bail!("`{slug}` is not a published string-evidence tier");
    };
    Ok(roster.render_tier(variant))
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let roster: EvidenceRoster = roster(root)?;
    let resolver: BTreeMap<String, String> = roster.resolver()?;
    let files: Vec<PathBuf> = doc_region::manifest(root)?;

    match mode {
        Mode::Write => {
            let mut rewritten: usize = 0;
            for path in &files {
                let text: String = doc_region::read_doc(path)?;
                let updated: String =
                    doc_region::rewrite(SYNTAX, &text, &|slug: &str| render_tier(&roster, slug))
                        .wrap_err_with(|| {
                            format!("rewriting string-evidence rosters in {}", path.display())
                        })?;
                if updated != text {
                    std::fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                    rewritten += 1;
                }
            }
            println!(
                "xtask dotnet-string-evidence: {rewritten} file(s) rewritten from the {} protector \
                 families {PROTECTOR_SOURCE} declares",
                roster.families.len()
            );
            Ok(())
        }
        Mode::Check => {
            let mut issues: Vec<String> = Vec::new();
            let mut seen: BTreeSet<String> = BTreeSet::new();
            check_samples(root, &roster, &mut issues)?;
            for path in &files {
                let text: String = doc_region::read_doc(path)?;
                let label: String = doc_region::label(root, path);
                let regions: Vec<Region> = doc_region::parse(SYNTAX, &text)
                    .wrap_err_with(|| format!("parsing string-evidence regions in {label}"))?;
                for region in &regions {
                    if label == CATALOG_DOC {
                        seen.insert(region.slug.clone());
                    }
                    check_region(&roster, &resolver, region, &label, &mut issues);
                }
            }
            check_published_tiers(&roster, &seen, &mut issues);

            if issues.is_empty() {
                println!(
                    "xtask dotnet-string-evidence: every .NET protector published as \
                     string-decrypting names either a committed sample the producing tool is \
                     recorded for, or the tier that states the limit ({} on a committed sample, {} \
                     modelled from the published algorithm, {} keyed at run time)",
                    roster.tier(REAL_SAMPLE).len(),
                    roster.tier(MODELLED_ALGORITHM).len(),
                    roster.tier(RUNTIME_KEYED).len()
                );
                Ok(())
            } else {
                bail!(
                    "{} published .NET string-recovery claim(s) disagree with the evidence the \
                     repository carries; run `cargo run -p xtask -- regen` to rewrite the \
                     rosters:\n  {}",
                    issues.len(),
                    issues.join("\n  ")
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE_FIXTURE: &str = r#"impl Protector {
    pub const ALL: [Self; 3] = [
        Self::Alpha,
        Self::Beta,
        Self::Gamma,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::Alpha => "Alpha",
            Self::Beta => "Beta .NET",
            Self::Gamma => "Gamma",
        }
    }

    pub const fn string_evidence(self) -> StringEvidence {
        match self {
            Self::Alpha => StringEvidence::RealSample("corpus/dotnet/alpha.dll"),
            Self::Beta => StringEvidence::ModelledAlgorithm,
            Self::Gamma => StringEvidence::NotClaimed,
        }
    }
}
"#;

    fn fixture_roster() -> EvidenceRoster {
        EvidenceRoster {
            families: vec![
                ProtectorFamily {
                    ident: "Alpha".to_owned(),
                    label: "Alpha".to_owned(),
                    tier: Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()),
                },
                ProtectorFamily {
                    ident: "Beta".to_owned(),
                    label: "Beta .NET".to_owned(),
                    tier: Tier::ModelledAlgorithm,
                },
                ProtectorFamily {
                    ident: "Delta".to_owned(),
                    label: "Delta".to_owned(),
                    tier: Tier::ModelledAlgorithm,
                },
                ProtectorFamily {
                    ident: "Gamma".to_owned(),
                    label: "Gamma".to_owned(),
                    tier: Tier::NotClaimed,
                },
            ],
        }
    }

    fn region_issues(slug: &str, content: &str) -> Result<Vec<String>> {
        let roster: EvidenceRoster = fixture_roster();
        let resolver: BTreeMap<String, String> = roster.resolver()?;
        let text: String = format!(
            "| row | <!-- dotnet-string-evidence:{slug} -->{content}<!-- /dotnet-string-evidence \
             --> |\n"
        );
        let regions: Vec<Region> = doc_region::parse(SYNTAX, &text)?;
        let mut issues: Vec<String> = Vec::new();
        for region in &regions {
            check_region(&roster, &resolver, region, "fixture.md", &mut issues);
        }
        Ok(issues)
    }

    #[test]
    fn tiers_and_sample_paths_read_from_the_declaration() -> Result<()> {
        let tiers: BTreeMap<String, Tier> = parse_tiers(SOURCE_FIXTURE)?;
        assert_eq!(
            tiers.get("Alpha"),
            Some(&Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()))
        );
        assert_eq!(tiers.get("Beta"), Some(&Tier::ModelledAlgorithm));
        assert_eq!(tiers.get("Gamma"), Some(&Tier::NotClaimed));
        let labels: BTreeMap<String, String> = parse_labels(SOURCE_FIXTURE)?;
        assert_eq!(labels.get("Beta").map(String::as_str), Some("Beta .NET"));
        Ok(())
    }

    #[test]
    fn a_truncated_roster_declaration_is_refused() {
        assert!(parse_declared_order(SOURCE_FIXTURE).is_err());
    }

    #[test]
    fn a_real_sample_arm_without_a_path_is_refused() {
        let source: &str = "    pub const fn string_evidence(self) -> StringEvidence {
        match self {
            Self::Alpha => StringEvidence::RealSample,
        }
    }
";
        assert!(parse_tiers(source).is_err());
    }

    #[test]
    fn a_roster_matching_its_tier_reports_nothing() -> Result<()> {
        assert!(region_issues("modelled-algorithm", "Beta .NET, Delta")?.is_empty());
        assert!(region_issues("real-sample", "Alpha")?.is_empty());
        Ok(())
    }

    #[test]
    fn a_modelled_family_missing_from_the_published_roster_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("modelled-algorithm", "Beta .NET")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("omits `Delta`"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_modelled_family_published_as_backed_by_a_sample_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("real-sample", "Alpha, Delta")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(
            issues[0].contains("modelled-algorithm tier instead"),
            "{issues:?}"
        );
        Ok(())
    }

    #[test]
    fn a_roster_claiming_a_family_the_code_lacks_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("modelled-algorithm", "Beta .NET, Delta, Omega")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("claims `Omega`"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_tier_with_no_published_region_is_reported() {
        let roster: EvidenceRoster = fixture_roster();
        let seen: BTreeSet<String> = std::iter::once("real-sample".to_owned()).collect();
        let mut issues: Vec<String> = Vec::new();
        check_published_tiers(&roster, &seen, &mut issues);
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("modelled-algorithm"), "{issues:?}");
    }

    #[test]
    fn a_sample_path_that_is_not_in_the_tree_is_reported() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let family: ProtectorFamily = ProtectorFamily {
            ident: "Alpha".to_owned(),
            label: "Alpha".to_owned(),
            tier: Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()),
        };
        let mut issues: Vec<String> = Vec::new();
        check_committed_sample(root.path(), &family, "corpus/dotnet/alpha.dll", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("rests on no artifact"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_sample_whose_manifest_records_another_provenance_is_reported() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let dir: PathBuf = root.path().join("corpus").join("dotnet");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("alpha.dll"), [0x4Du8, 0x5A])?;
        std::fs::write(
            dir.join(MANIFEST_NAME),
            "toolchain = \"Alpha 1.0\"\n\n[[fixture]]\npath = \"alpha.dll\"\nprovenance = \
             \"self-authored\"\n",
        )?;
        let family: ProtectorFamily = ProtectorFamily {
            ident: "Alpha".to_owned(),
            label: "Alpha".to_owned(),
            tier: Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()),
        };
        let mut issues: Vec<String> = Vec::new();
        check_committed_sample(root.path(), &family, "corpus/dotnet/alpha.dll", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("self-authored"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_sample_whose_manifest_names_no_producing_tool_is_reported() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let dir: PathBuf = root.path().join("corpus").join("dotnet");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("alpha.dll"), [0x4Du8, 0x5A])?;
        std::fs::write(
            dir.join(MANIFEST_NAME),
            "toolchain = \"dotnet SDK 9.0.314\"\n\n[[fixture]]\npath = \
             \"alpha.dll\"\nprovenance = \"real\"\n",
        )?;
        let family: ProtectorFamily = ProtectorFamily {
            ident: "Alpha".to_owned(),
            label: "Alpha".to_owned(),
            tier: Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()),
        };
        let mut issues: Vec<String> = Vec::new();
        check_committed_sample(root.path(), &family, "corpus/dotnet/alpha.dll", &mut issues)?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("names Alpha as the tool"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_recorded_sample_reports_nothing() -> Result<()> {
        let root: tempfile::TempDir = tempfile::tempdir()?;
        let dir: PathBuf = root.path().join("corpus").join("dotnet");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join("alpha.dll"), [0x4Du8, 0x5A])?;
        std::fs::write(
            dir.join(MANIFEST_NAME),
            "toolchain = \"Alpha Obfuscator 1.0\"\n\n[[fixture]]\npath = \
             \"alpha.dll\"\nprovenance = \"real\"\n",
        )?;
        let family: ProtectorFamily = ProtectorFamily {
            ident: "Alpha".to_owned(),
            label: "Alpha".to_owned(),
            tier: Tier::RealSample("corpus/dotnet/alpha.dll".to_owned()),
        };
        let mut issues: Vec<String> = Vec::new();
        check_committed_sample(root.path(), &family, "corpus/dotnet/alpha.dll", &mut issues)?;
        assert!(issues.is_empty(), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_rewrite_is_a_fixpoint() -> Result<()> {
        let roster: EvidenceRoster = fixture_roster();
        let source: &str = "| tier | <!-- dotnet-string-evidence:modelled-algorithm -->stale<!-- \
                            /dotnet-string-evidence --> |\n";
        let render = |slug: &str| -> Result<String> { render_tier(&roster, slug) };
        let once: String = doc_region::rewrite(SYNTAX, source, &render)?;
        let twice: String = doc_region::rewrite(SYNTAX, &once, &render)?;
        assert!(once.contains("Beta .NET, Delta"), "{once}");
        assert_eq!(once, twice);
        Ok(())
    }
}
