use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 8 * 1024 * 1024;

const FAMILY_SOURCE: &str = "crates/disrobe-pass-native/src/packers/mod.rs";
const DISPATCH_SOURCE: &str = "crates/disrobe-pass-native/src/chain_detector.rs";
const CATALOG_DOC: &str = "docs/src/catalog.md";

const FAMILY_MACRO: &str = "packer_families! {";
const STATUS_FN: &str = "pub const fn unpacker_status(self) -> UnpackerStatus {";
const DISPATCH_FN: &str = "fn run_rust_unpacker(packer: Packer, artifact: &Artifact)";
const DISPATCH_GUARD: &str = "matches!(packer,";
const CATALOG_ARRAY: &str = "static CATALOG: [PackerEntry;";
const CATALOG_COUNT_CONST: &str = "const CATALOG_COUNT: usize =";

const SELF_PATH: &str = "Self::";
const PACKER_PATH: &str = "Packer::";
const STATUS_PATH: &str = "UnpackerStatus::";

const IMPLEMENTED_STATUS: &str = "Implemented";
const DELEGATED_STATUS: &str = "DelegatedToDotnet";

const REGION_OPEN_PREFIX: &str = "<!-- packer-roster:";
const REGION_OPEN_SUFFIX: &str = " -->";
const REGION_CLOSE: &str = "<!-- /packer-roster -->";

const MIN_FAMILIES: usize = 20;

#[derive(Debug, Clone, Copy)]
pub(crate) enum Mode {
    Write,
    Check,
}

#[derive(Debug, Clone)]
struct PackerFamily {
    ident: String,
    label: String,
    status: String,
    display_name: Option<String>,
}

impl PackerFamily {
    fn published_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(&self.ident)
    }

    fn spellings(&self) -> Vec<String> {
        let mut out: Vec<String> = vec![normalise(&self.ident), normalise(&self.label)];
        if let Some(display) = self.display_name.as_deref() {
            out.push(normalise(display));
        }
        out.sort();
        out.dedup();
        out
    }
}

#[derive(Debug)]
struct PackerRoster {
    families: Vec<PackerFamily>,
    unpack_dispatch: BTreeSet<String>,
    catalog_idents: BTreeSet<String>,
    catalog_count_const: usize,
}

impl PackerRoster {
    fn tier(&self, status: &str) -> Vec<&PackerFamily> {
        self.families
            .iter()
            .filter(|family: &&PackerFamily| family.status == status)
            .collect()
    }

    fn statuses(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .families
            .iter()
            .map(|family: &PackerFamily| family.status.clone())
            .collect();
        out.sort();
        out.dedup();
        out
    }

    fn render_tier(&self, status: &str) -> String {
        self.tier(status)
            .into_iter()
            .map(PackerFamily::published_name)
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
                        "`{previous}` and `{}` in {FAMILY_SOURCE} both answer to the name \
                         `{spelling}` once casing and punctuation are removed, so a roster entry \
                         naming it cannot be attributed to one family and this check would pass a \
                         roster that names the wrong one",
                        family.ident
                    );
                }
            }
        }
        Ok(out)
    }
}

fn normalise(text: &str) -> String {
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

fn read_repo_text(root: &Path, relative: &str, max_bytes: u64) -> Result<String> {
    let path: PathBuf = root.join(relative);
    read_text_bounded(&path, max_bytes).wrap_err_with(|| format!("reading {relative}"))
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

fn read_family_lines(source: &str) -> Result<Vec<(String, String)>> {
    let body: &str = block_after(source, FAMILY_MACRO, "\n}").ok_or_else(|| {
        eyre!(
            "{FAMILY_SOURCE} no longer declares `{FAMILY_MACRO}` as a readable block, so the packer \
             roster every page publishes is derived from nothing"
        )
    })?;
    let mut out: Vec<(String, String)> = Vec::new();
    for line in body.lines() {
        let trimmed: &str = line.trim();
        let Some((ident, tail)) = trimmed.split_once("=>") else {
            continue;
        };
        let ident: &str = ident.trim();
        if ident.is_empty() || !ident.chars().all(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let Some(opened) = tail.split_once('"') else {
            bail!("the roster line `{trimmed}` in {FAMILY_SOURCE} carries no quoted label");
        };
        let Some((label, _)) = opened.1.split_once('"') else {
            bail!("the roster line `{trimmed}` in {FAMILY_SOURCE} carries an unterminated label");
        };
        out.push((ident.to_owned(), label.to_owned()));
    }
    Ok(out)
}

fn parse_families(source: &str) -> Result<Vec<(String, String)>> {
    let out: Vec<(String, String)> = read_family_lines(source)?;
    if out.len() < MIN_FAMILIES {
        bail!(
            "{FAMILY_SOURCE} yielded {} packer famil(y/ies) from `{FAMILY_MACRO}`, fewer than the \
             {MIN_FAMILIES} this check requires; the declaration shape moved and every published \
             roster would be compared against a truncated list",
            out.len()
        );
    }
    Ok(out)
}

fn parse_statuses(source: &str) -> Result<BTreeMap<String, String>> {
    let body: &str = block_after(source, STATUS_FN, "\n    }").ok_or_else(|| {
        eyre!(
            "{FAMILY_SOURCE} no longer declares `unpacker_status` in a shape this check can read, \
             so the tier each published row claims is derived from nothing"
        )
    })?;
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    let mut segments: std::str::Split<'_, &str> = body.split("=>");
    let mut pending: Vec<String> = segments
        .next()
        .map(|head: &str| paths_in(head, SELF_PATH))
        .unwrap_or_default();
    for segment in segments {
        let Some(status_at) = segment.find(STATUS_PATH) else {
            bail!(
                "an arm of `unpacker_status` in {FAMILY_SOURCE} resolves to something other than an \
                 `UnpackerStatus` value, so the tier it assigns cannot be read"
            );
        };
        let tail: &str = segment.get(status_at..).unwrap_or_default();
        let status: String = paths_in(tail, STATUS_PATH)
            .first()
            .cloned()
            .ok_or_else(|| eyre!("an `unpacker_status` arm in {FAMILY_SOURCE} names no tier"))?;
        for ident in std::mem::take(&mut pending) {
            if let Some(previous) = out.insert(ident.clone(), status.clone())
                && previous != status
            {
                bail!(
                    "`{ident}` is assigned both the {previous} and the {status} tier by \
                     `unpacker_status` in {FAMILY_SOURCE}"
                );
            }
        }
        let after_status: &str = tail
            .get(STATUS_PATH.len() + status.len()..)
            .unwrap_or_default();
        pending = paths_in(after_status, SELF_PATH);
    }
    if !pending.is_empty() {
        bail!(
            "`unpacker_status` in {FAMILY_SOURCE} ends with {} unmatched pattern(s) ({}), so this \
             check read the arm list wrong and would compare the published tiers against a partial \
             map",
            pending.len(),
            pending.join(", ")
        );
    }
    Ok(out)
}

fn parse_unpack_dispatch(source: &str) -> Result<BTreeSet<String>> {
    let body: &str = block_after(source, DISPATCH_FN, "\nfn ").ok_or_else(|| {
        eyre!(
            "{DISPATCH_SOURCE} no longer declares `run_rust_unpacker` in a shape this check can \
             read, so which packers the binary actually unpacks is derived from nothing"
        )
    })?;
    let mut out: BTreeSet<String> = BTreeSet::new();
    if let Some(guard) = block_after(body, DISPATCH_GUARD, ")") {
        for ident in paths_in(guard, PACKER_PATH) {
            out.insert(ident);
        }
    }
    let mut rest: &str = body;
    while let Some(at) = rest.find(PACKER_PATH) {
        let after: &str = rest.get(at + PACKER_PATH.len()..).unwrap_or_default();
        let ident: String = after
            .chars()
            .take_while(|c: &char| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        let tail: &str = after.get(ident.len()..).unwrap_or_default().trim_start();
        if !ident.is_empty() && (tail.starts_with("=>") || tail.starts_with('|')) {
            out.insert(ident);
        }
        rest = after;
    }
    if out.is_empty() {
        bail!(
            "`run_rust_unpacker` in {DISPATCH_SOURCE} yielded no packer arms, so the recover tier \
             every page publishes would be compared against an empty dispatch"
        );
    }
    Ok(out)
}

fn parse_catalog(source: &str) -> Result<(BTreeSet<String>, BTreeMap<String, String>, usize)> {
    let body: &str = block_after(source, CATALOG_ARRAY, "\n];").ok_or_else(|| {
        eyre!(
            "{DISPATCH_SOURCE} no longer declares `static CATALOG` as a readable array, so the \
             names `disrobe native unpack --list` prints are derived from nothing"
        )
    })?;
    let mut idents: BTreeSet<String> = BTreeSet::new();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    let mut pending: Option<String> = None;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if let Some(rest) = trimmed.strip_prefix("packer: Packer::") {
            let ident: String = rest.trim_end_matches(',').to_owned();
            if !idents.insert(ident.clone()) {
                bail!("`{ident}` appears twice in `static CATALOG` in {DISPATCH_SOURCE}");
            }
            pending = Some(ident);
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("display_name: ") {
            let Some(opened) = rest.split_once('"') else {
                continue;
            };
            let Some((name, _)) = opened.1.split_once('"') else {
                continue;
            };
            let Some(ident) = pending.take() else {
                bail!(
                    "a `display_name` in `static CATALOG` in {DISPATCH_SOURCE} precedes the entry \
                     it names, so published names cannot be attributed"
                );
            };
            names.insert(ident, name.to_owned());
        }
    }
    let declared: usize = block_after(source, CATALOG_COUNT_CONST, ";")
        .and_then(|text: &str| text.trim().parse::<usize>().ok())
        .ok_or_else(|| {
            eyre!("{DISPATCH_SOURCE} no longer declares `{CATALOG_COUNT_CONST}` as a plain integer")
        })?;
    if idents.len() != names.len() {
        bail!(
            "`static CATALOG` in {DISPATCH_SOURCE} yielded {} entr(y/ies) but {} display name(s), \
             so at least one entry publishes a name this check cannot read",
            idents.len(),
            names.len()
        );
    }
    Ok((idents, names, declared))
}

fn roster(root: &Path) -> Result<PackerRoster> {
    let family_src: String = read_repo_text(root, FAMILY_SOURCE, MAX_SOURCE_BYTES)?;
    let dispatch_src: String = read_repo_text(root, DISPATCH_SOURCE, MAX_SOURCE_BYTES)?;
    let declared: Vec<(String, String)> = parse_families(&family_src)?;
    let statuses: BTreeMap<String, String> = parse_statuses(&family_src)?;
    let (catalog_idents, catalog_names, catalog_count_const): (
        BTreeSet<String>,
        BTreeMap<String, String>,
        usize,
    ) = parse_catalog(&dispatch_src)?;

    let mut families: Vec<PackerFamily> = Vec::with_capacity(declared.len());
    for (ident, label) in declared {
        let status: String = statuses.get(&ident).cloned().ok_or_else(|| {
            eyre!(
                "`{ident}` is declared in `{FAMILY_MACRO}` but `unpacker_status` in {FAMILY_SOURCE} \
                 assigns it no tier, so no published row can state what the binary does with it"
            )
        })?;
        let display_name: Option<String> = catalog_names.get(&ident).cloned();
        families.push(PackerFamily {
            ident,
            label,
            status,
            display_name,
        });
    }

    let known: BTreeSet<&str> = families
        .iter()
        .map(|family: &PackerFamily| family.ident.as_str())
        .collect();
    for ident in statuses.keys() {
        if !known.contains(ident.as_str()) {
            bail!(
                "`unpacker_status` in {FAMILY_SOURCE} assigns a tier to `{ident}`, which \
                 `{FAMILY_MACRO}` does not declare"
            );
        }
    }
    for ident in &catalog_idents {
        if !known.contains(ident.as_str()) {
            bail!(
                "`static CATALOG` in {DISPATCH_SOURCE} lists `{ident}`, which `{FAMILY_MACRO}` in \
                 {FAMILY_SOURCE} does not declare"
            );
        }
    }

    Ok(PackerRoster {
        families,
        unpack_dispatch: parse_unpack_dispatch(&dispatch_src)?,
        catalog_idents,
        catalog_count_const,
    })
}

fn check_dispatch(roster: &PackerRoster, issues: &mut Vec<String>) {
    let recovers: BTreeSet<&str> = roster
        .tier(IMPLEMENTED_STATUS)
        .into_iter()
        .map(|family: &PackerFamily| family.ident.as_str())
        .collect();
    let dispatched: BTreeSet<&str> = roster.unpack_dispatch.iter().map(String::as_str).collect();
    for ident in recovers.difference(&dispatched) {
        issues.push(format!(
            "`{ident}` sits in the {IMPLEMENTED_STATUS} tier, which every page publishes as the \
             tier that recovers original bytes, but `run_rust_unpacker` in {DISPATCH_SOURCE} has no \
             arm for it, so the binary detects it and stops there"
        ));
    }
    for ident in dispatched.difference(&recovers) {
        issues.push(format!(
            "`run_rust_unpacker` in {DISPATCH_SOURCE} carries an unpack arm for `{ident}`, but its \
             tier keeps that arm unreachable, so the published tier credits the recovery to the \
             wrong row"
        ));
    }
}

fn check_catalog_membership(roster: &PackerRoster, issues: &mut Vec<String>) {
    if roster.catalog_idents.len() != roster.catalog_count_const {
        issues.push(format!(
            "`static CATALOG` in {DISPATCH_SOURCE} holds {} entr(y/ies) against a declared \
             `CATALOG_COUNT` of {}",
            roster.catalog_idents.len(),
            roster.catalog_count_const
        ));
    }
    for family in &roster.families {
        let listed: bool = roster.catalog_idents.contains(&family.ident);
        let delegated: bool = family.status == DELEGATED_STATUS;
        if listed && delegated {
            issues.push(format!(
                "`{}` is delegated to the .NET pass yet `static CATALOG` in {DISPATCH_SOURCE} \
                 lists it, so `disrobe native unpack --list` offers a family this pass does not own",
                family.ident
            ));
        }
        if !listed && !delegated {
            issues.push(format!(
                "`{}` is carried by the packer roster but absent from `static CATALOG` in \
                 {DISPATCH_SOURCE}, so `disrobe native unpack --list` prints a shorter roster than \
                 the pages publish",
                family.ident
            ));
        }
    }
}

#[derive(Debug)]
struct Region {
    slug: String,
    line: usize,
    content: String,
    content_start: usize,
    content_end: usize,
}

fn parse_regions(text: &str) -> Result<Vec<Region>> {
    let mut out: Vec<Region> = Vec::new();
    let mut offset: usize = 0;
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let line_no: usize = index + 1;
        let mut search_from: usize = 0;
        while let Some(rel) = line
            .get(search_from..)
            .and_then(|rest: &str| rest.find(REGION_OPEN_PREFIX))
        {
            let open_at: usize = search_from + rel;
            let after_prefix: usize = open_at + REGION_OPEN_PREFIX.len();
            let Some(suffix_rel) = line
                .get(after_prefix..)
                .and_then(|rest: &str| rest.find(REGION_OPEN_SUFFIX))
            else {
                bail!(
                    "line {line_no}: a `{REGION_OPEN_PREFIX}` opening has no `{REGION_OPEN_SUFFIX}` \
                     on the same line"
                );
            };
            let slug: &str = line
                .get(after_prefix..after_prefix + suffix_rel)
                .unwrap_or_default();
            let content_from: usize = after_prefix + suffix_rel + REGION_OPEN_SUFFIX.len();
            let Some(close_rel) = line
                .get(content_from..)
                .and_then(|rest: &str| rest.find(REGION_CLOSE))
            else {
                bail!(
                    "line {line_no}: the packer roster region `{slug}` has no `{REGION_CLOSE}` on \
                     the same line"
                );
            };
            let content_end: usize = content_from + close_rel;
            let content: &str = line.get(content_from..content_end).unwrap_or_default();
            out.push(Region {
                slug: slug.to_owned(),
                line: line_no,
                content: content.to_owned(),
                content_start: offset + content_from,
                content_end: offset + content_end,
            });
            search_from = content_end + REGION_CLOSE.len();
        }
        offset += line.len();
    }
    Ok(out)
}

fn status_for_slug(roster: &PackerRoster, slug: &str) -> Option<String> {
    roster
        .statuses()
        .into_iter()
        .find(|status: &String| kebab(status) == slug)
}

fn check_region(
    roster: &PackerRoster,
    resolver: &BTreeMap<String, String>,
    region: &Region,
    label: &str,
    issues: &mut Vec<String>,
) {
    let Some(status): Option<String> = status_for_slug(roster, &region.slug) else {
        issues.push(format!(
            "{label}:{}: `{}` is not an `UnpackerStatus` tier any packer carries; the tiers on \
             record are {}",
            region.line,
            region.slug,
            roster
                .statuses()
                .into_iter()
                .map(|status: String| kebab(&status))
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
        match resolver.get(&normalise(cleaned)) {
            Some(ident) => {
                if !named.insert(ident.clone()) {
                    issues.push(format!(
                        "{label}:{}: the `{}` roster names `{cleaned}` twice",
                        region.line, region.slug
                    ));
                }
            }
            None => issues.push(format!(
                "{label}:{}: the `{}` roster claims `{cleaned}`, which no packer in \
                 {FAMILY_SOURCE} answers to, so the page advertises a family the binary cannot \
                 detect or unpack",
                region.line, region.slug
            )),
        }
    }

    let expected: BTreeSet<String> = roster
        .tier(&status)
        .into_iter()
        .map(|family: &PackerFamily| family.ident.clone())
        .collect();
    for ident in expected.difference(&named) {
        issues.push(format!(
            "{label}:{}: the `{}` roster omits `{ident}`, which {FAMILY_SOURCE} places in that \
             tier, so the page under-states what the binary handles",
            region.line, region.slug
        ));
    }
    for ident in named.difference(&expected) {
        let carried: String = roster
            .families
            .iter()
            .find(|family: &&PackerFamily| family.ident == *ident)
            .map_or_else(
                || "no".to_owned(),
                |family: &PackerFamily| kebab(&family.status),
            );
        issues.push(format!(
            "{label}:{}: the `{}` roster claims `{ident}`, which {FAMILY_SOURCE} places in the \
             {carried} tier instead, so the page credits it with the wrong capability",
            region.line, region.slug
        ));
    }
}

fn manifest(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files: Vec<PathBuf> = vec![root.join("README.md")];
    let docs_src: PathBuf = root.join("docs").join("src");
    if docs_src.is_dir() {
        for entry in walkdir::WalkDir::new(&docs_src) {
            let dirent: walkdir::DirEntry =
                entry.wrap_err_with(|| format!("walking {}", docs_src.display()))?;
            let path: &Path = dirent.path();
            if path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("md") {
                files.push(path.to_path_buf());
            }
        }
    }
    files.sort();
    Ok(files)
}

fn display_label(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn rewrite_text(text: &str, roster: &PackerRoster) -> Result<String> {
    let regions: Vec<Region> = parse_regions(text)?;
    if regions.is_empty() {
        return Ok(text.to_owned());
    }
    let mut out: String = String::with_capacity(text.len());
    let mut cursor: usize = 0;
    for region in &regions {
        let Some(status): Option<String> = status_for_slug(roster, &region.slug) else {
            bail!(
                "line {}: `{}` is not an `UnpackerStatus` tier any packer carries",
                region.line,
                region.slug
            );
        };
        out.push_str(text.get(cursor..region.content_start).unwrap_or_default());
        out.push_str(&roster.render_tier(&status));
        cursor = region.content_end;
    }
    out.push_str(text.get(cursor..).unwrap_or_default());
    Ok(out)
}

fn check_published_tiers(roster: &PackerRoster, seen: &BTreeSet<String>, issues: &mut Vec<String>) {
    for status in roster.statuses() {
        let slug: String = kebab(&status);
        if !seen.contains(&slug) {
            issues.push(format!(
                "{CATALOG_DOC} publishes no `{slug}` roster region, so the {} famil(y/ies) in that \
                 tier are documented by nothing a check can read",
                roster.tier(&status).len()
            ));
        }
    }
}

pub(crate) fn run(root: &Path, mode: Mode) -> Result<()> {
    let roster: PackerRoster = roster(root)?;
    let resolver: BTreeMap<String, String> = roster.resolver()?;
    let files: Vec<PathBuf> = manifest(root)?;

    match mode {
        Mode::Write => {
            let mut rewritten: usize = 0;
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let updated: String = rewrite_text(&text, &roster)
                    .wrap_err_with(|| format!("rewriting packer rosters in {}", path.display()))?;
                if updated != text {
                    std::fs::write(path, &updated)
                        .wrap_err_with(|| format!("writing {}", path.display()))?;
                    rewritten += 1;
                }
            }
            println!(
                "xtask packer-roster: {rewritten} file(s) rewritten from the {} packer families \
                 {FAMILY_SOURCE} declares",
                roster.families.len()
            );
            Ok(())
        }
        Mode::Check => {
            let mut issues: Vec<String> = Vec::new();
            let mut seen: BTreeSet<String> = BTreeSet::new();
            check_dispatch(&roster, &mut issues);
            check_catalog_membership(&roster, &mut issues);
            for path in &files {
                let text: String = read_text_bounded(path, MAX_DOC_BYTES)
                    .wrap_err_with(|| format!("reading {}", path.display()))?;
                let label: String = display_label(root, path);
                let regions: Vec<Region> = parse_regions(&text)
                    .wrap_err_with(|| format!("parsing packer roster regions in {label}"))?;
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
                    "xtask packer-roster: every published packer roster names exactly the families \
                     {FAMILY_SOURCE} declares for its tier ({} families, {} of them unpacked by \
                     {DISPATCH_SOURCE}, {} listed by `disrobe native unpack --list`)",
                    roster.families.len(),
                    roster.unpack_dispatch.len(),
                    roster.catalog_idents.len()
                );
                Ok(())
            } else {
                bail!(
                    "{} published packer roster claim(s) disagree with the families the binary \
                     carries; run `cargo run -p xtask -- regen` to rewrite the rosters:\n  {}",
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

    const FAMILY_FIXTURE: &str = r#"packer_families! {
    Upx => "upx",
    Themida => "themida",
    NetCryptor => "netcryptor",
}

impl Packer {
    pub const fn unpacker_status(self) -> UnpackerStatus {
        match self {
            Self::Upx => UnpackerStatus::Implemented,
            Self::NetCryptor => UnpackerStatus::DelegatedToDotnet,
            Self::Themida => {
                UnpackerStatus::GreyZoneDetectAndCarve
            }
        }
    }
}
"#;

    const DISPATCH_FIXTURE: &str = r"fn run_rust_unpacker(packer: Packer, artifact: &Artifact) -> CoreResult<PackerRecovery> {
    if matches!(packer, Packer::Donut | Packer::Srdi) {
        return loader_packer_recovery(out);
    }
    let recovered = match packer {
        Packer::Upx => {
            unpack_upx(packed)
        }
        other => Err(other.label()),
    };
    Ok(recovered)
}

fn next_function() {}
";

    const CATALOG_FIXTURE: &str = r#"const CATALOG_COUNT: usize = 2;

static CATALOG: [PackerEntry; CATALOG_COUNT] = [
    PackerEntry {
        packer: Packer::Upx,
        display_name: "UPX",
        aliases: &[],
    },
    PackerEntry {
        packer: Packer::Themida,
        display_name: "Themida / WinLicense",
        aliases: &[],
    },
];
"#;

    fn fixture_roster() -> PackerRoster {
        PackerRoster {
            families: vec![
                PackerFamily {
                    ident: "Upx".to_owned(),
                    label: "upx".to_owned(),
                    status: "Implemented".to_owned(),
                    display_name: Some("UPX".to_owned()),
                },
                PackerFamily {
                    ident: "Kkrunchy".to_owned(),
                    label: "kkrunchy".to_owned(),
                    status: "Implemented".to_owned(),
                    display_name: Some("kkrunchy".to_owned()),
                },
                PackerFamily {
                    ident: "Themida".to_owned(),
                    label: "themida".to_owned(),
                    status: "GreyZoneDetectAndCarve".to_owned(),
                    display_name: Some("Themida / WinLicense".to_owned()),
                },
                PackerFamily {
                    ident: "NetCryptor".to_owned(),
                    label: "netcryptor".to_owned(),
                    status: "DelegatedToDotnet".to_owned(),
                    display_name: None,
                },
            ],
            unpack_dispatch: ["Upx".to_owned(), "Kkrunchy".to_owned()]
                .into_iter()
                .collect(),
            catalog_idents: [
                "Upx".to_owned(),
                "Kkrunchy".to_owned(),
                "Themida".to_owned(),
            ]
            .into_iter()
            .collect(),
            catalog_count_const: 3,
        }
    }

    fn region_issues(content: &str) -> Result<Vec<String>> {
        let roster: PackerRoster = fixture_roster();
        let resolver: BTreeMap<String, String> = roster.resolver()?;
        let text: String = format!(
            "| row | {REGION_OPEN_PREFIX}implemented{REGION_OPEN_SUFFIX}{content}{REGION_CLOSE} |\n"
        );
        let regions: Vec<Region> = parse_regions(&text)?;
        let mut issues: Vec<String> = Vec::new();
        for region in &regions {
            check_region(&roster, &resolver, region, "fixture.md", &mut issues);
        }
        Ok(issues)
    }

    #[test]
    fn families_and_tiers_read_from_the_declaration() -> Result<()> {
        let families: Vec<(String, String)> = read_family_lines(FAMILY_FIXTURE)?;
        assert_eq!(
            families,
            vec![
                ("Upx".to_owned(), "upx".to_owned()),
                ("Themida".to_owned(), "themida".to_owned()),
                ("NetCryptor".to_owned(), "netcryptor".to_owned()),
            ]
        );
        let statuses: BTreeMap<String, String> = parse_statuses(FAMILY_FIXTURE)?;
        assert_eq!(statuses.get("Upx").map(String::as_str), Some("Implemented"));
        assert_eq!(
            statuses.get("Themida").map(String::as_str),
            Some("GreyZoneDetectAndCarve")
        );
        assert_eq!(
            statuses.get("NetCryptor").map(String::as_str),
            Some("DelegatedToDotnet")
        );
        Ok(())
    }

    #[test]
    fn a_truncated_family_declaration_is_refused() {
        assert!(parse_families(FAMILY_FIXTURE).is_err());
    }

    #[test]
    fn the_unpack_dispatch_reads_guard_and_match_arms() -> Result<()> {
        let dispatch: BTreeSet<String> = parse_unpack_dispatch(DISPATCH_FIXTURE)?;
        assert_eq!(
            dispatch,
            ["Donut".to_owned(), "Srdi".to_owned(), "Upx".to_owned()]
                .into_iter()
                .collect::<BTreeSet<String>>()
        );
        Ok(())
    }

    #[test]
    fn catalog_entries_pair_with_their_published_names() -> Result<()> {
        let (idents, names, declared): (BTreeSet<String>, BTreeMap<String, String>, usize) =
            parse_catalog(CATALOG_FIXTURE)?;
        assert_eq!(declared, 2);
        assert_eq!(idents.len(), 2);
        assert_eq!(
            names.get("Themida").map(String::as_str),
            Some("Themida / WinLicense")
        );
        Ok(())
    }

    #[test]
    fn a_tier_slug_is_the_kebab_form_of_its_status() {
        assert_eq!(kebab("Implemented"), "implemented");
        assert_eq!(kebab("StubEvalPending"), "stub-eval-pending");
        assert_eq!(
            kebab("GreyZoneDetectAndCarve"),
            "grey-zone-detect-and-carve"
        );
    }

    #[test]
    fn a_roster_matching_its_tier_reports_nothing() -> Result<()> {
        assert!(region_issues("UPX, kkrunchy")?.is_empty());
        Ok(())
    }

    #[test]
    fn a_roster_claiming_a_family_the_code_lacks_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("UPX, kkrunchy, HyperPack")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("claims `HyperPack`"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_roster_omitting_a_family_the_code_carries_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("UPX")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("omits `Kkrunchy`"), "{issues:?}");
        Ok(())
    }

    #[test]
    fn a_family_listed_under_the_wrong_tier_is_reported() -> Result<()> {
        let issues: Vec<String> = region_issues("UPX, kkrunchy, Themida")?;
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(
            issues[0].contains("grey-zone-detect-and-carve tier instead"),
            "{issues:?}"
        );
        Ok(())
    }

    #[test]
    fn names_resolve_through_casing_and_punctuation() -> Result<()> {
        assert!(region_issues("upx, KKRUNCHY")?.is_empty());
        Ok(())
    }

    #[test]
    fn a_tier_that_stops_unpacking_is_reported() {
        let mut roster: PackerRoster = fixture_roster();
        roster.unpack_dispatch.remove("Kkrunchy");
        let mut issues: Vec<String> = Vec::new();
        check_dispatch(&roster, &mut issues);
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(
            issues[0].contains("detects it and stops there"),
            "{issues:?}"
        );
    }

    #[test]
    fn a_delegated_family_listed_by_the_catalog_is_reported() {
        let mut roster: PackerRoster = fixture_roster();
        roster.catalog_idents.insert("NetCryptor".to_owned());
        roster.catalog_count_const = 4;
        let mut issues: Vec<String> = Vec::new();
        check_catalog_membership(&roster, &mut issues);
        assert_eq!(issues.len(), 1, "expected one issue: {issues:?}");
        assert!(issues[0].contains("does not own"), "{issues:?}");
    }

    #[test]
    fn a_rewrite_is_a_fixpoint() -> Result<()> {
        let roster: PackerRoster = fixture_roster();
        let source: String = format!(
            "| tier | {REGION_OPEN_PREFIX}implemented{REGION_OPEN_SUFFIX}stale{REGION_CLOSE} |\n"
        );
        let once: String = rewrite_text(&source, &roster)?;
        let twice: String = rewrite_text(&once, &roster)?;
        assert!(once.contains("UPX, kkrunchy"), "{once}");
        assert_eq!(once, twice);
        Ok(())
    }

    #[test]
    fn an_unclosed_region_is_refused() {
        let source: String =
            format!("| tier | {REGION_OPEN_PREFIX}implemented{REGION_OPEN_SUFFIX}UPX |\n");
        assert!(parse_regions(&source).is_err());
    }

    #[test]
    fn a_missing_tier_region_is_reported() {
        let roster: PackerRoster = fixture_roster();
        let seen: BTreeSet<String> = std::iter::once("implemented".to_owned()).collect();
        let mut issues: Vec<String> = Vec::new();
        check_published_tiers(&roster, &seen, &mut issues);
        assert_eq!(issues.len(), 2, "expected two issues: {issues:?}");
    }
}
