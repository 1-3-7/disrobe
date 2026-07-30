use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail, eyre};

use crate::fileio::read_text_bounded;

const MAX_SOURCE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_DOC_BYTES: u64 = 4 * 1024 * 1024;

const REGISTRY_SOURCE: &str = "crates/disrobe-cli/src/cli/catalog_registry.rs";
const PIN_SOURCE: &str = "crates/disrobe-cli/src/cli/catalog.rs";
const PACKER_SOURCE: &str = "crates/disrobe-pass-native/src/packers/mod.rs";
const DOTNET_ROSTER_SOURCE: &str = "crates/disrobe-pass-dotnet/src/protectors.rs";
const RASP_ROSTER_SOURCE: &str = "crates/disrobe-pass-jvm/src/rasp.rs";
const CATALOG_DOC: &str = "docs/src/catalog.md";
const REFERENCE_DOC: &str = "docs/src/cli/reference.md";
const README_DOC: &str = "README.md";
const JVM_ANDROID_DOC: &str = "docs/src/languages/jvm-android.md";

const REGISTRY_ENTRY_MARKER: &str = "::chain_detector::";
const MIN_REGISTRY_MEMBERS: usize = 8;

const NATIVE_PASS: &str = "native.packer-unpack";
const LUA_PASS: &str = "lua.deob";
const LUA_OBFUSCATOR_ROW: &str = "**Obfuscators**";
const LUA_DIALECT_ROW: &str = "**Dialect detectors**";

const COUNT_CELL: usize = 1;
const FAMILIES_CELL: usize = 2;

#[derive(Debug)]
struct PassCatalog {
    crate_dir: String,
    families: usize,
}

#[derive(Debug)]
struct TierClaim {
    constant: &'static str,
    anchor: &'static str,
}

const NATIVE_TIERS: [TierClaim; 5] = [
    TierClaim {
        constant: "IMPLEMENTED",
        anchor: "**Implemented**",
    },
    TierClaim {
        constant: "STUB_EVAL_PENDING",
        anchor: "**StubEvalPending**",
    },
    TierClaim {
        constant: "GREY_CARVE",
        anchor: "**GreyZoneDetectAndCarve**",
    },
    TierClaim {
        constant: "GREY_DETECT_ONLY",
        anchor: "**GreyZoneDetectOnly**",
    },
    TierClaim {
        constant: "DELEGATED",
        anchor: "**DelegatedToDotnet**",
    },
];

#[derive(Debug)]
struct PassRowClaim {
    pass_id: &'static str,
    anchor: &'static str,
}

const PASS_ROWS: [PassRowClaim; 6] = [
    PassRowClaim {
        pass_id: "pyarmor.unpack",
        anchor: "**Protector (PyArmor)**",
    },
    PassRowClaim {
        pass_id: "py.deob",
        anchor: "**Source obfuscators (AST-evaluator)**",
    },
    PassRowClaim {
        pass_id: "js.deob",
        anchor: "**JS chain catalog**",
    },
    PassRowClaim {
        pass_id: "wasm.deob",
        anchor: "**WASM obfuscators**",
    },
    PassRowClaim {
        pass_id: "php.peel",
        anchor: "**Commercial encoders**",
    },
    PassRowClaim {
        pass_id: "jvm.classify",
        anchor: "**JVM / Android protectors**",
    },
];

#[derive(Debug, Clone, Copy)]
enum RosterShape {
    ArrayLength,
    EnumVariants,
}

#[derive(Debug)]
struct RosterClaim {
    source: &'static str,
    shape: RosterShape,
    symbol: &'static str,
    anchor: &'static str,
}

const ROSTER_ROWS: [RosterClaim; 2] = [
    RosterClaim {
        source: DOTNET_ROSTER_SOURCE,
        shape: RosterShape::ArrayLength,
        symbol: "ALL",
        anchor: "**.NET protectors**",
    },
    RosterClaim {
        source: RASP_ROSTER_SOURCE,
        shape: RosterShape::EnumVariants,
        symbol: "RaspVendor",
        anchor: "**Android RASP vendors**",
    },
];

const ROSTERLESS_ROWS: [&str; 2] = ["**Freezers / packagers**", "**JS bundlers (unbundler)**"];

#[derive(Debug)]
struct DerivedPhrase {
    source: &'static str,
    shape: RosterShape,
    symbol: &'static str,
    doc: &'static str,
    template: &'static str,
    consequence: &'static str,
}

const DERIVED_PHRASES: [DerivedPhrase; 3] = [
    DerivedPhrase {
        source: RASP_ROSTER_SOURCE,
        shape: RosterShape::EnumVariants,
        symbol: "RaspVendor",
        doc: README_DOC,
        template: "Android RASP ({} vendors)",
        consequence: "the RASP roster carries that many vendors, so the capability table offers a \
                      reader a different breadth than the fingerprinter can detect",
    },
    DerivedPhrase {
        source: RASP_ROSTER_SOURCE,
        shape: RosterShape::EnumVariants,
        symbol: "RaspVendor",
        doc: JVM_ANDROID_DOC,
        template: "RASP vendors ({})",
        consequence: "the RASP roster carries that many vendors, so the per-language page and the \
                      catalog page would publish two different rosters for one enum",
    },
    DerivedPhrase {
        source: PACKER_SOURCE,
        shape: RosterShape::ArrayLength,
        symbol: "EVERY_PACKER",
        doc: README_DOC,
        template: "Packers ({} families)",
        consequence: "the `Packer` roster carries that many variants, so the headline capability \
                      row states a packer breadth the binary does not carry, which is the exact \
                      drift that once left three different totals published at once",
    },
];

#[derive(Debug, Default)]
struct Findings {
    issues: Vec<String>,
    checked: usize,
}

impl Findings {
    fn compare(&mut self, published: usize, derived: usize, context: &str) {
        self.checked += 1;
        if published != derived {
            self.issues.push(format!(
                "{context}: the page publishes {published}, the code carries {derived}"
            ));
        }
    }

    fn require_phrase(&mut self, doc: &str, text: &str, expected: &str, consequence: &str) {
        self.checked += 1;
        if !text.contains(expected) {
            self.issues
                .push(format!("{doc} does not state `{expected}`; {consequence}"));
        }
    }
}

pub(crate) fn run(root: &Path) -> Result<()> {
    let registry_src: String = read_repo_text(root, REGISTRY_SOURCE, MAX_SOURCE_BYTES)?;
    let pin_src: String = read_repo_text(root, PIN_SOURCE, MAX_SOURCE_BYTES)?;
    let packer_src: String = read_repo_text(root, PACKER_SOURCE, MAX_SOURCE_BYTES)?;
    let catalog_md: String = read_repo_text(root, CATALOG_DOC, MAX_DOC_BYTES)?;
    let reference_md: String = read_repo_text(root, REFERENCE_DOC, MAX_DOC_BYTES)?;

    let catalogs: BTreeMap<String, PassCatalog> = read_registry_catalogs(root, &registry_src)?;
    let mut findings: Findings = Findings::default();

    check_headline(
        &catalogs,
        &pin_src,
        &catalog_md,
        &reference_md,
        &mut findings,
    )?;
    check_native_tiers(&packer_src, &catalogs, &catalog_md, &mut findings)?;
    check_pass_rows(&catalogs, &catalog_md, &mut findings)?;
    check_lua_split(&catalogs, &catalog_md, &mut findings)?;
    check_roster_rows(root, &catalog_md, &mut findings)?;
    check_rosterless_rows(&catalog_md, &mut findings)?;
    check_derived_phrases(root, &mut findings)?;

    if findings.issues.is_empty() {
        println!(
            "xtask regen: catalog count cross-check ok ({} published count(s) across {}, {}, {} \
             and {} match the catalog tables the binary carries)",
            findings.checked, CATALOG_DOC, REFERENCE_DOC, README_DOC, JVM_ANDROID_DOC
        );
        Ok(())
    } else {
        bail!(
            "xtask regen: {} published catalog count(s) disagree with the tables the binary \
             carries:\n  {}",
            findings.issues.len(),
            findings.issues.join("\n  ")
        )
    }
}

fn read_repo_text(root: &Path, relative: &str, max_bytes: u64) -> Result<String> {
    let path: PathBuf = root.join(relative);
    read_text_bounded(&path, max_bytes).wrap_err_with(|| format!("reading {relative}"))
}

fn read_registry_catalogs(
    root: &Path,
    registry_src: &str,
) -> Result<BTreeMap<String, PassCatalog>> {
    let members: Vec<String> = registry_member_crates(registry_src);
    if members.len() < MIN_REGISTRY_MEMBERS {
        bail!(
            "{REGISTRY_SOURCE} yielded {} catalog member(s), fewer than the {MIN_REGISTRY_MEMBERS} \
             this check requires; the registry moved and every count on {CATALOG_DOC} would be \
             compared against a truncated total",
            members.len()
        );
    }

    let mut catalogs: BTreeMap<String, PassCatalog> = BTreeMap::new();
    for crate_dir in members {
        let relative: String = format!("crates/{crate_dir}/src/chain_detector.rs");
        let source: String = read_repo_text(root, &relative, MAX_SOURCE_BYTES)?;
        let pass_id: String = string_literal_constant(&source, "PASS_ID").ok_or_else(|| {
            eyre!("{relative} no longer declares a `PASS_ID` string literal, so its catalog cannot be matched to the row that publishes it")
        })?;
        let families: usize = usize_constant(&source, "CATALOG_COUNT").ok_or_else(|| {
            eyre!("{relative} no longer declares `CATALOG_COUNT`, so the family count it advertises is checked against nothing")
        })?;
        if let Some(previous) = catalogs.insert(
            pass_id.clone(),
            PassCatalog {
                crate_dir: crate_dir.clone(),
                families,
            },
        ) {
            bail!(
                "pass id `{pass_id}` is claimed by both crates/{} and crates/{crate_dir}; the \
                 published per-pass counts cannot be attributed",
                previous.crate_dir
            );
        }
    }
    Ok(catalogs)
}

fn registry_member_crates(registry_src: &str) -> Vec<String> {
    let mut members: Vec<String> = Vec::new();
    for line in registry_src.lines() {
        let trimmed: &str = line.trim();
        let Some(reference) = trimmed.strip_prefix('&') else {
            continue;
        };
        if !reference.contains(REGISTRY_ENTRY_MARKER) {
            continue;
        }
        let Some((krate, _)) = reference.split_once("::") else {
            continue;
        };
        let crate_dir: String = krate.replace('_', "-");
        if !members.contains(&crate_dir) {
            members.push(crate_dir);
        }
    }
    members
}

fn catalog_families(
    catalogs: &BTreeMap<String, PassCatalog>,
    pass_id: &str,
) -> Result<(usize, String)> {
    let catalog: &PassCatalog = catalogs.get(pass_id).ok_or_else(|| {
        eyre!(
            "no catalog in {REGISTRY_SOURCE} declares the pass id `{pass_id}`, so the row {CATALOG_DOC} publishes for it describes a catalog the binary no longer registers"
        )
    })?;
    Ok((
        catalog.families,
        format!("crates/{}/src/chain_detector.rs", catalog.crate_dir),
    ))
}

fn check_headline(
    catalogs: &BTreeMap<String, PassCatalog>,
    pin_src: &str,
    catalog_md: &str,
    reference_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    let derived_total: usize = catalogs
        .values()
        .map(|catalog: &PassCatalog| catalog.families)
        .sum();
    let pinned_total: usize = usize_constant(pin_src, "PUBLISHED_FAMILY_TOTAL").ok_or_else(|| {
        eyre!("{PIN_SOURCE} no longer declares `PUBLISHED_FAMILY_TOTAL`, so the headline total on {CATALOG_DOC} is checked against nothing")
    })?;
    let ecosystems: usize =
        array_length_constant(pin_src, "PUBLISHED_ECOSYSTEM_SLUGS").ok_or_else(|| {
            eyre!("{PIN_SOURCE} no longer declares `PUBLISHED_ECOSYSTEM_SLUGS` as a fixed-length array, so the ecosystem count on {CATALOG_DOC} is checked against nothing")
        })?;

    findings.compare(
        pinned_total,
        derived_total,
        &format!(
            "`PUBLISHED_FAMILY_TOTAL` in {PIN_SOURCE} against the sum of `CATALOG_COUNT` over the \
             {} registered catalogs",
            catalogs.len()
        ),
    );

    let headline: String =
        format!("reports {derived_total} families across {ecosystems} ecosystems");
    for (doc, text) in [(CATALOG_DOC, catalog_md), (REFERENCE_DOC, reference_md)] {
        findings.require_phrase(
            doc,
            text,
            &headline,
            "the registered catalogs sum to that many families over that many ecosystems for the \
             `full` feature set, so the page states a breadth the binary does not report",
        );
    }
    Ok(())
}

fn check_native_tiers(
    packer_src: &str,
    catalogs: &BTreeMap<String, PassCatalog>,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    let variants: usize = array_length_constant(packer_src, "EVERY_PACKER").ok_or_else(|| {
        eyre!("{PACKER_SOURCE} no longer declares `EVERY_PACKER` as a fixed-length array, so the packer total on {CATALOG_DOC} is checked against nothing")
    })?;

    let mut tier_counts: Vec<usize> = Vec::with_capacity(NATIVE_TIERS.len());
    for tier in &NATIVE_TIERS {
        let derived: usize = array_length_constant(packer_src, tier.constant).ok_or_else(|| {
            eyre!(
                "{PACKER_SOURCE} no longer declares `{}` as a fixed-length array, so the `{}` tier count on {CATALOG_DOC} is checked against nothing",
                tier.constant,
                tier.anchor
            )
        })?;
        let published: usize = row_count(catalog_md, tier.anchor)?;
        findings.compare(
            published,
            derived,
            &format!(
                "{CATALOG_DOC} row `{}` against `{}` in {PACKER_SOURCE}",
                tier.anchor, tier.constant
            ),
        );
        tier_counts.push(derived);
    }

    let tier_total: usize = tier_counts.iter().sum();
    findings.compare(
        variants,
        tier_total,
        &format!(
            "the packer roster in {PACKER_SOURCE} against the five tier rosters it is partitioned \
             into"
        ),
    );

    let split: String = tier_counts
        .iter()
        .map(usize::to_string)
        .collect::<Vec<String>>()
        .join(" + ");
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!("## Native packers and protectors ({variants})"),
        "the `Packer` roster carries that many variants, so the section heading understates or \
         overstates the packers the binary knows",
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!(
            "The `Packer` enum carries {variants} variants across five `UnpackerStatus` tiers \
             ({split} = {variants})."
        ),
        "that is the partition the tier rosters declare, so the sentence describes a split the \
         binary does not carry",
    );

    let (native_families, native_source): (usize, String) =
        catalog_families(catalogs, NATIVE_PASS)?;
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!("catalog advertises {native_families} of them"),
        &format!(
            "`CATALOG_COUNT` in {native_source} is {native_families}, so the page states a \
             different number of packers than `disrobe catalog native` lists"
        ),
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!("`disrobe catalog native` lists {native_families}"),
        &format!(
            "`CATALOG_COUNT` in {native_source} is {native_families}, so the page states a \
             different number of packers than the command prints"
        ),
    );
    Ok(())
}

fn check_pass_rows(
    catalogs: &BTreeMap<String, PassCatalog>,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    for row in &PASS_ROWS {
        let (derived, source): (usize, String) = catalog_families(catalogs, row.pass_id)?;
        let published: usize = row_count(catalog_md, row.anchor)?;
        findings.compare(
            published,
            derived,
            &format!(
                "{CATALOG_DOC} row `{}` against `CATALOG_COUNT` in {source}",
                row.anchor
            ),
        );
    }
    Ok(())
}

fn check_lua_split(
    catalogs: &BTreeMap<String, PassCatalog>,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    let (derived, source): (usize, String) = catalog_families(catalogs, LUA_PASS)?;
    let obfuscators: usize = row_count(catalog_md, LUA_OBFUSCATOR_ROW)?;
    let dialects: usize = row_count(catalog_md, LUA_DIALECT_ROW)?;
    findings.compare(
        obfuscators.saturating_add(dialects),
        derived,
        &format!(
            "{CATALOG_DOC} rows `{LUA_OBFUSCATOR_ROW}` plus `{LUA_DIALECT_ROW}` against \
             `CATALOG_COUNT` in {source}"
        ),
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!(
            "The Lua chain catalog is {derived} entries: {obfuscators} obfuscator families plus"
        ),
        &format!(
            "`CATALOG_COUNT` in {source} is {derived} and the table splits it {obfuscators} plus \
             {dialects}, so the prose and the table below it disagree"
        ),
    );
    Ok(())
}

fn roster_count(source_text: &str, shape: RosterShape, symbol: &str) -> Option<usize> {
    match shape {
        RosterShape::ArrayLength => array_length_constant(source_text, symbol),
        RosterShape::EnumVariants => enum_variant_count(source_text, symbol),
    }
}

fn check_derived_phrases(root: &Path, findings: &mut Findings) -> Result<()> {
    let mut sources: BTreeMap<&'static str, String> = BTreeMap::new();
    let mut docs: BTreeMap<&'static str, String> = BTreeMap::new();

    for phrase in &DERIVED_PHRASES {
        if let Entry::Vacant(slot) = sources.entry(phrase.source) {
            slot.insert(read_repo_text(root, phrase.source, MAX_SOURCE_BYTES)?);
        }
        if let Entry::Vacant(slot) = docs.entry(phrase.doc) {
            slot.insert(read_repo_text(root, phrase.doc, MAX_DOC_BYTES)?);
        }
    }

    for phrase in &DERIVED_PHRASES {
        let source_text: &str = sources
            .get(phrase.source)
            .map(String::as_str)
            .ok_or_else(|| eyre!("{} was not loaded", phrase.source))?;
        let doc_text: &str = docs
            .get(phrase.doc)
            .map(String::as_str)
            .ok_or_else(|| eyre!("{} was not loaded", phrase.doc))?;
        let derived: usize = roster_count(source_text, phrase.shape, phrase.symbol).ok_or_else(|| {
            eyre!(
                "{} no longer declares `{}` in a shape this check can count, so the count {} publishes for it is checked against nothing",
                phrase.source,
                phrase.symbol,
                phrase.doc
            )
        })?;
        findings.require_phrase(
            phrase.doc,
            doc_text,
            &phrase.template.replace("{}", &derived.to_string()),
            phrase.consequence,
        );
    }
    Ok(())
}

fn check_roster_rows(root: &Path, catalog_md: &str, findings: &mut Findings) -> Result<()> {
    for row in &ROSTER_ROWS {
        let source: String = read_repo_text(root, row.source, MAX_SOURCE_BYTES)?;
        let derived: usize = roster_count(&source, row.shape, row.symbol).ok_or_else(|| {
            eyre!(
                "{} no longer declares `{}` in a shape this check can count, so the `{}` count on {CATALOG_DOC} is checked against nothing",
                row.source,
                row.symbol,
                row.anchor
            )
        })?;
        let published: usize = row_count(catalog_md, row.anchor)?;
        findings.compare(
            published,
            derived,
            &format!(
                "{CATALOG_DOC} row `{}` against `{}` in {}",
                row.anchor, row.symbol, row.source
            ),
        );
    }
    Ok(())
}

fn check_rosterless_rows(catalog_md: &str, findings: &mut Findings) -> Result<()> {
    for anchor in ROSTERLESS_ROWS {
        let cells: Vec<&str> = row_cells(catalog_md, anchor)?;
        let published: usize = cell_count(cells.get(COUNT_CELL).copied().unwrap_or_default())
            .ok_or_else(|| {
                eyre!("the count cell of the `{anchor}` row in {CATALOG_DOC} holds no number")
            })?;
        let listed: usize = cell_item_count(cells.get(FAMILIES_CELL).copied().unwrap_or_default());
        findings.compare(
            published,
            listed,
            &format!(
                "{CATALOG_DOC} row `{anchor}`, whose count has no catalog table behind it and is \
                 compared against the family list beside it"
            ),
        );
    }
    Ok(())
}

fn declaration_line<'src>(text: &'src str, symbol: &str) -> Option<&'src str> {
    let needle: String = format!("const {symbol}:");
    let mut found: Option<&'src str> = None;
    for line in text.lines() {
        if !line.contains(&needle) {
            continue;
        }
        if found.is_some() {
            return None;
        }
        found = Some(line);
    }
    found
}

fn string_literal_constant(text: &str, symbol: &str) -> Option<String> {
    let line: &str = declaration_line(text, symbol)?;
    let after: &str = line.split_once('=')?.1;
    let opened: &str = after.split_once('"')?.1;
    Some(opened.split_once('"')?.0.to_owned())
}

fn usize_constant(text: &str, symbol: &str) -> Option<usize> {
    let line: &str = declaration_line(text, symbol)?;
    let after: &str = line.split_once('=')?.1;
    digit_run(after)
}

fn array_length_constant(text: &str, symbol: &str) -> Option<usize> {
    let line: &str = declaration_line(text, symbol)?;
    let open: usize = line.find('[')?;
    let inner: &str = line.get(open + 1..)?;
    let close: usize = inner.find(']')?;
    let bounds: &str = inner.get(..close)?;
    digit_run(bounds.rsplit_once(';')?.1)
}

fn enum_variant_count(text: &str, symbol: &str) -> Option<usize> {
    let head: usize = text.find(&format!("enum {symbol} {{"))?;
    let body: &str = text.get(head..)?.split_once('{')?.1;
    let mut variants: usize = 0;
    for line in body.lines() {
        let trimmed: &str = line.trim();
        if trimmed == "}" {
            return (variants > 0).then_some(variants);
        }
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed
            .starts_with(|c: char| c.is_ascii_uppercase() || c == '_' || c.is_ascii_lowercase())
        {
            variants += 1;
        }
    }
    None
}

fn digit_run(text: &str) -> Option<usize> {
    let digits: String = text
        .chars()
        .skip_while(|c: &char| !c.is_ascii_digit())
        .take_while(char::is_ascii_digit)
        .collect();
    digits.parse::<usize>().ok()
}

fn table_cells(line: &str) -> Option<Vec<&str>> {
    let trimmed: &str = line.trim();
    let inner: &str = trimmed.strip_prefix('|')?.strip_suffix('|')?;
    let cells: Vec<&str> = inner.split('|').map(str::trim).collect();
    (cells.len() >= 2).then_some(cells)
}

fn row_cells<'doc>(catalog_md: &'doc str, anchor: &str) -> Result<Vec<&'doc str>> {
    let mut hits: Vec<Vec<&'doc str>> = catalog_md
        .lines()
        .filter_map(table_cells)
        .filter(|cells: &Vec<&'doc str>| {
            cells
                .first()
                .is_some_and(|first: &&str| first.starts_with(anchor))
        })
        .collect();
    match (hits.len(), hits.pop()) {
        (1, Some(cells)) => Ok(cells),
        (0, _) => bail!(
            "{CATALOG_DOC} has no table row whose first cell starts with `{anchor}`, so the count \
             that row publishes is compared against nothing"
        ),
        (found, _) => bail!(
            "{CATALOG_DOC} has {found} table rows whose first cell starts with `{anchor}`, so this \
             check cannot tell which one publishes the count"
        ),
    }
}

fn row_count(catalog_md: &str, anchor: &str) -> Result<usize> {
    let cells: Vec<&str> = row_cells(catalog_md, anchor)?;
    let cell: &str = cells.get(COUNT_CELL).copied().unwrap_or_default();
    cell_count(cell).ok_or_else(|| {
        eyre!("the count cell of the `{anchor}` row in {CATALOG_DOC} holds no number, so nothing on that row can be compared")
    })
}

fn cell_count(cell: &str) -> Option<usize> {
    digit_run(&strip_html_comments(cell))
}

fn cell_item_count(cell: &str) -> usize {
    let visible: String = strip_html_comments(cell);
    let mut depth: usize = 0;
    let mut items: usize = 0;
    let mut carries_text: bool = false;
    for ch in visible.chars() {
        match ch {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' | ';' if depth == 0 => {
                items += usize::from(carries_text);
                carries_text = false;
            }
            _ if ch.is_alphanumeric() => carries_text = true,
            _ => {}
        }
    }
    items + usize::from(carries_text)
}

fn strip_html_comments(text: &str) -> String {
    let mut visible: String = String::with_capacity(text.len());
    let mut rest: &str = text;
    while let Some(start) = rest.find("<!--") {
        visible.push_str(rest.get(..start).unwrap_or_default());
        let after: &str = rest.get(start + 4..).unwrap_or_default();
        let Some(end): Option<usize> = after.find("-->") else {
            rest = "";
            break;
        };
        rest = after.get(end + 3..).unwrap_or_default();
    }
    visible.push_str(rest);
    visible
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_members_map_module_idents_to_crate_directories() {
        let source: &str = "pub(crate) fn registry() -> Vec<&'static dyn ObfuscatorCatalog> {\n    vec![\n        &disrobe_pass_native::chain_detector::PackerDetector,\n        #[cfg(feature = \"lua\")]\n        &disrobe_pass_lua::chain_detector::LuaDetector,\n    ]\n}\n";
        assert_eq!(
            registry_member_crates(source),
            vec![
                "disrobe-pass-native".to_owned(),
                "disrobe-pass-lua".to_owned()
            ]
        );
    }

    #[test]
    fn constants_read_totals_and_array_lengths() {
        let source: &str = "const PUBLISHED_FAMILY_TOTAL: usize = 169;\nconst PUBLISHED_ECOSYSTEM_SLUGS: [&str; 15] = [\n];\npub const ALL: [Self; 23] = [\n];\n";
        assert_eq!(usize_constant(source, "PUBLISHED_FAMILY_TOTAL"), Some(169));
        assert_eq!(
            array_length_constant(source, "PUBLISHED_ECOSYSTEM_SLUGS"),
            Some(15)
        );
        assert_eq!(array_length_constant(source, "ALL"), Some(23));
        assert_eq!(usize_constant(source, "MISSING"), None);
    }

    #[test]
    fn a_duplicated_constant_reads_as_unresolvable() {
        let source: &str = "const CATALOG_COUNT: usize = 3;\nconst CATALOG_COUNT: usize = 4;\n";
        assert_eq!(usize_constant(source, "CATALOG_COUNT"), None);
    }

    #[test]
    fn enum_variants_are_counted_without_the_impl_block() {
        let source: &str = "#[derive(Debug)]\npub enum RaspVendor {\n    PromonShield,\n    OneSpan,\n    Zimperium,\n}\n\nimpl RaspVendor {\n    pub const fn name(self) -> &'static str {\n        \"x\"\n    }\n}\n";
        assert_eq!(enum_variant_count(source, "RaspVendor"), Some(3));
        assert_eq!(enum_variant_count(source, "Absent"), None);
    }

    #[test]
    fn count_cells_read_through_marker_spans_and_trailing_words() {
        assert_eq!(cell_count("12"), Some(12));
        assert_eq!(cell_count("7 versions"), Some(7));
        assert_eq!(cell_count("5 (catalog)"), Some(5));
        assert_eq!(
            cell_count("<!-- m:py_source_obfuscators -->20<!-- /m -->"),
            Some(20)
        );
        assert_eq!(cell_count("separate detectors"), None);
    }

    #[test]
    fn family_lists_count_parenthesised_detail_as_one_item() {
        assert_eq!(
            cell_item_count(
                "PyInstaller 2.x-6.20+, Nuitka (onefile / standalone / module / wheel), cx_Freeze, py2exe, PyOxidizer, shiv, pex, Briefcase, SourceDefender `.pye`"
            ),
            9
        );
        assert_eq!(
            cell_item_count("Promon SHIELD, Arxan / Digital.ai, Licel DexProtector"),
            3
        );
    }

    #[test]
    fn rows_are_located_by_their_leading_cell() -> core::result::Result<(), String> {
        let doc: &str = "| Surface | Count | Families |\n|---|---|---|\n| **Obfuscators** | 14 | IronBrew2 (full VM devirtualization), Prometheus |\n| **Dialect detectors** | 2 | Luau bytecode, Garry's Mod Lua (GLua) |\n";
        let cells: Vec<&str> = row_cells(doc, "**Obfuscators**").map_err(|e| e.to_string())?;
        assert_eq!(cells.first().copied(), Some("**Obfuscators**"));
        assert_eq!(
            row_count(doc, "**Dialect detectors**").map_err(|e| e.to_string())?,
            2
        );
        assert!(row_cells(doc, "**Absent**").is_err());
        Ok(())
    }

    #[test]
    fn a_published_count_that_disagrees_with_the_code_is_reported() {
        let mut findings: Findings = Findings::default();
        findings.compare(168, 169, "the headline total");
        assert_eq!(findings.checked, 1);
        assert_eq!(
            findings.issues,
            vec!["the headline total: the page publishes 168, the code carries 169".to_owned()]
        );
    }
}
