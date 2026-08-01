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
const LUA_CATALOG_SYMBOL: &str = "CATALOG";
const LUA_OBFUSCATOR_KEY: &str = "key: CatalogKey::Obfuscator(";
const LUA_DIALECT_KEY: &str = "key: CatalogKey::Dialect(";

const PACKER_ROSTER: &str = "EVERY_PACKER";
const FAMILY_TOTAL_PIN: &str = "PUBLISHED_FAMILY_TOTAL";
const ECOSYSTEM_PIN: &str = "PUBLISHED_ECOSYSTEM_SLUGS";
const DOTNET_ROSTER_SYMBOL: &str = "ALL";
const RASP_ROSTER_SYMBOL: &str = "RaspVendor";

const IMPLEMENTED_TIER: &str = "IMPLEMENTED";
const STUB_EVAL_PENDING_TIER: &str = "STUB_EVAL_PENDING";
const GREY_CARVE_TIER: &str = "GREY_CARVE";
const GREY_DETECT_ONLY_TIER: &str = "GREY_DETECT_ONLY";
const DELEGATED_TIER: &str = "DELEGATED";

const COUNT_CELL: usize = 1;
const FAMILIES_CELL: usize = 2;

#[derive(Debug)]
struct PassCatalog {
    crate_dir: String,
    families: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct NativeTierCounts {
    pub(crate) implemented: usize,
    pub(crate) stub_eval_pending: usize,
    pub(crate) grey_carve: usize,
    pub(crate) grey_detect_only: usize,
    pub(crate) delegated: usize,
}

impl NativeTierCounts {
    const fn total(self) -> usize {
        self.implemented
            + self.stub_eval_pending
            + self.grey_carve
            + self.grey_detect_only
            + self.delegated
    }

    fn split(self) -> String {
        [
            self.implemented,
            self.stub_eval_pending,
            self.grey_carve,
            self.grey_detect_only,
            self.delegated,
        ]
        .iter()
        .map(usize::to_string)
        .collect::<Vec<String>>()
        .join(" + ")
    }
}

#[derive(Debug)]
pub(crate) struct CatalogTables {
    passes: BTreeMap<String, PassCatalog>,
    pub(crate) family_total: usize,
    pub(crate) ecosystems: usize,
    pub(crate) pinned_family_total: usize,
    pub(crate) packer_variants: usize,
    pub(crate) native_tiers: NativeTierCounts,
    pub(crate) dotnet_protectors: usize,
    pub(crate) rasp_vendors: usize,
    pub(crate) lua_obfuscators: usize,
    pub(crate) lua_dialects: usize,
}

impl CatalogTables {
    pub(crate) fn pass_count(&self, pass_id: &str) -> Result<usize> {
        Ok(catalog_families(&self.passes, pass_id)?.0)
    }
}

#[cfg(test)]
pub(crate) fn sample_tables() -> CatalogTables {
    let mut passes: BTreeMap<String, PassCatalog> = BTreeMap::new();
    passes.insert(
        NATIVE_PASS.to_owned(),
        PassCatalog {
            crate_dir: "disrobe-pass-native".to_owned(),
            families: 27,
        },
    );
    passes.insert(
        LUA_PASS.to_owned(),
        PassCatalog {
            crate_dir: "disrobe-pass-lua".to_owned(),
            families: 16,
        },
    );
    CatalogTables {
        passes,
        family_total: 169,
        ecosystems: 15,
        pinned_family_total: 169,
        packer_variants: 29,
        native_tiers: NativeTierCounts {
            implemented: 12,
            stub_eval_pending: 6,
            grey_carve: 3,
            grey_detect_only: 6,
            delegated: 2,
        },
        dotnet_protectors: 23,
        rasp_vendors: 8,
        lua_obfuscators: 14,
        lua_dialects: 2,
    }
}

#[derive(Debug)]
struct TierClaim {
    constant: &'static str,
    anchor: &'static str,
    count: fn(NativeTierCounts) -> usize,
}

const NATIVE_TIERS: [TierClaim; 5] = [
    TierClaim {
        constant: IMPLEMENTED_TIER,
        anchor: "**Implemented**",
        count: |tiers: NativeTierCounts| tiers.implemented,
    },
    TierClaim {
        constant: STUB_EVAL_PENDING_TIER,
        anchor: "**StubEvalPending**",
        count: |tiers: NativeTierCounts| tiers.stub_eval_pending,
    },
    TierClaim {
        constant: GREY_CARVE_TIER,
        anchor: "**GreyZoneDetectAndCarve**",
        count: |tiers: NativeTierCounts| tiers.grey_carve,
    },
    TierClaim {
        constant: GREY_DETECT_ONLY_TIER,
        anchor: "**GreyZoneDetectOnly**",
        count: |tiers: NativeTierCounts| tiers.grey_detect_only,
    },
    TierClaim {
        constant: DELEGATED_TIER,
        anchor: "**DelegatedToDotnet**",
        count: |tiers: NativeTierCounts| tiers.delegated,
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

#[derive(Debug)]
struct RosterClaim {
    source: &'static str,
    symbol: &'static str,
    anchor: &'static str,
    count: fn(&CatalogTables) -> usize,
}

const ROSTER_ROWS: [RosterClaim; 2] = [
    RosterClaim {
        source: DOTNET_ROSTER_SOURCE,
        symbol: DOTNET_ROSTER_SYMBOL,
        anchor: "**.NET protectors**",
        count: |tables: &CatalogTables| tables.dotnet_protectors,
    },
    RosterClaim {
        source: RASP_ROSTER_SOURCE,
        symbol: RASP_ROSTER_SYMBOL,
        anchor: "**Android RASP vendors**",
        count: |tables: &CatalogTables| tables.rasp_vendors,
    },
];

const ROSTERLESS_ROWS: [&str; 3] = [
    "**Freezers / packagers**",
    "**Freezers / packagers (experimental, unvalidated)**",
    "**JS bundlers (unbundler)**",
];

#[derive(Debug)]
struct DerivedPhrase {
    doc: &'static str,
    template: &'static str,
    consequence: &'static str,
    count: fn(&CatalogTables) -> usize,
}

const DERIVED_PHRASES: [DerivedPhrase; 3] = [
    DerivedPhrase {
        doc: README_DOC,
        template: "Android RASP ({} vendors)",
        consequence: "the RASP roster carries that many vendors, so the capability table offers a \
                      reader a different breadth than the fingerprinter can detect",
        count: |tables: &CatalogTables| tables.rasp_vendors,
    },
    DerivedPhrase {
        doc: JVM_ANDROID_DOC,
        template: "RASP vendors ({})",
        consequence: "the RASP roster carries that many vendors, so the per-language page and the \
                      catalog page would publish two different rosters for one enum",
        count: |tables: &CatalogTables| tables.rasp_vendors,
    },
    DerivedPhrase {
        doc: README_DOC,
        template: "Packers ({} families)",
        consequence: "the `Packer` roster carries that many variants, so the headline capability \
                      row states a packer breadth the binary does not carry, which is the exact \
                      drift that once left three different totals published at once",
        count: |tables: &CatalogTables| tables.packer_variants,
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
    let tables: CatalogTables = tables(root)?;
    let catalog_md: String = read_doc_visible(root, CATALOG_DOC)?;
    let reference_md: String = read_doc_visible(root, REFERENCE_DOC)?;
    let mut findings: Findings = Findings::default();

    check_headline(&tables, &catalog_md, &reference_md, &mut findings);
    check_native_tiers(&tables, &catalog_md, &mut findings)?;
    check_pass_rows(&tables, &catalog_md, &mut findings)?;
    check_lua_split(&tables, &catalog_md, &mut findings)?;
    check_roster_rows(&tables, &catalog_md, &mut findings)?;
    check_rosterless_rows(&catalog_md, &mut findings)?;
    check_derived_phrases(root, &tables, &mut findings)?;

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

pub(crate) fn tables(root: &Path) -> Result<CatalogTables> {
    let registry_src: String = read_repo_text(root, REGISTRY_SOURCE, MAX_SOURCE_BYTES)?;
    let pin_src: String = read_repo_text(root, PIN_SOURCE, MAX_SOURCE_BYTES)?;
    let packer_src: String = read_repo_text(root, PACKER_SOURCE, MAX_SOURCE_BYTES)?;
    let passes: BTreeMap<String, PassCatalog> = read_registry_catalogs(root, &registry_src)?;

    let family_total: usize = passes
        .values()
        .map(|catalog: &PassCatalog| catalog.families)
        .sum();
    let pinned_family_total: usize = usize_constant(&pin_src, FAMILY_TOTAL_PIN).ok_or_else(|| {
        eyre!("{PIN_SOURCE} no longer declares `{FAMILY_TOTAL_PIN}`, so the headline total on {CATALOG_DOC} is derived from nothing")
    })?;
    let ecosystems: usize = array_length_constant(&pin_src, ECOSYSTEM_PIN).ok_or_else(|| {
        eyre!("{PIN_SOURCE} no longer declares `{ECOSYSTEM_PIN}` as a fixed-length array, so the ecosystem count on {CATALOG_DOC} is derived from nothing")
    })?;
    let packer_variants: usize =
        array_length_constant(&packer_src, PACKER_ROSTER).ok_or_else(|| {
            eyre!("{PACKER_SOURCE} no longer declares `{PACKER_ROSTER}` as a fixed-length array, so the packer total on {CATALOG_DOC} is derived from nothing")
        })?;
    let native_tiers: NativeTierCounts = NativeTierCounts {
        implemented: tier_count(&packer_src, IMPLEMENTED_TIER)?,
        stub_eval_pending: tier_count(&packer_src, STUB_EVAL_PENDING_TIER)?,
        grey_carve: tier_count(&packer_src, GREY_CARVE_TIER)?,
        grey_detect_only: tier_count(&packer_src, GREY_DETECT_ONLY_TIER)?,
        delegated: tier_count(&packer_src, DELEGATED_TIER)?,
    };
    let dotnet_protectors: usize = read_roster(
        root,
        DOTNET_ROSTER_SOURCE,
        DOTNET_ROSTER_SYMBOL,
        array_length_constant,
    )?;
    let rasp_vendors: usize = read_roster(
        root,
        RASP_ROSTER_SOURCE,
        RASP_ROSTER_SYMBOL,
        enum_variant_count,
    )?;
    let (lua_obfuscators, lua_dialects): (usize, usize) = read_lua_split(root, &passes)?;

    Ok(CatalogTables {
        passes,
        family_total,
        ecosystems,
        pinned_family_total,
        packer_variants,
        native_tiers,
        dotnet_protectors,
        rasp_vendors,
        lua_obfuscators,
        lua_dialects,
    })
}

fn tier_count(packer_src: &str, constant: &str) -> Result<usize> {
    array_length_constant(packer_src, constant).ok_or_else(|| {
        eyre!("{PACKER_SOURCE} no longer declares `{constant}` as a fixed-length array, so that tier count on {CATALOG_DOC} is derived from nothing")
    })
}

fn read_roster(
    root: &Path,
    source: &'static str,
    symbol: &'static str,
    count: fn(&str, &str) -> Option<usize>,
) -> Result<usize> {
    let text: String = read_repo_text(root, source, MAX_SOURCE_BYTES)?;
    count(&text, symbol).ok_or_else(|| {
        eyre!(
            "{source} no longer declares `{symbol}` in a shape this check can count, so every count \
             published for that roster is derived from nothing"
        )
    })
}

fn read_lua_split(root: &Path, passes: &BTreeMap<String, PassCatalog>) -> Result<(usize, usize)> {
    let (entries, source): (usize, String) = catalog_families(passes, LUA_PASS)?;
    let text: String = read_repo_text(root, &source, MAX_SOURCE_BYTES)?;
    let body: &str = static_array_body(&text, LUA_CATALOG_SYMBOL).ok_or_else(|| {
        eyre!("{source} no longer declares `static {LUA_CATALOG_SYMBOL}` as a readable array, so the two halves of the Lua table on {CATALOG_DOC} are derived from nothing")
    })?;
    let obfuscators: usize = body.matches(LUA_OBFUSCATOR_KEY).count();
    let dialects: usize = body.matches(LUA_DIALECT_KEY).count();
    if obfuscators == 0 || dialects == 0 {
        bail!(
            "the `{LUA_CATALOG_SYMBOL}` array in {source} yielded {obfuscators} obfuscator and \
             {dialects} dialect entr(y/ies); the entry shape changed and the Lua rows on \
             {CATALOG_DOC} would publish a truncated split"
        );
    }
    if obfuscators + dialects != entries {
        bail!(
            "the `{LUA_CATALOG_SYMBOL}` array in {source} splits {obfuscators} obfuscator plus \
             {dialects} dialect entries, which is not the {entries} its `CATALOG_COUNT` declares, so \
             one entry kind is neither counted nor published"
        );
    }
    Ok((obfuscators, dialects))
}

fn read_repo_text(root: &Path, relative: &str, max_bytes: u64) -> Result<String> {
    let path: PathBuf = root.join(relative);
    read_text_bounded(&path, max_bytes).wrap_err_with(|| format!("reading {relative}"))
}

fn read_doc_visible(root: &Path, relative: &str) -> Result<String> {
    let raw: String = read_repo_text(root, relative, MAX_DOC_BYTES)?;
    Ok(strip_html_comments(&raw))
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
    passes: &BTreeMap<String, PassCatalog>,
    pass_id: &str,
) -> Result<(usize, String)> {
    let catalog: &PassCatalog = passes.get(pass_id).ok_or_else(|| {
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
    tables: &CatalogTables,
    catalog_md: &str,
    reference_md: &str,
    findings: &mut Findings,
) {
    findings.compare(
        tables.pinned_family_total,
        tables.family_total,
        &format!(
            "`{FAMILY_TOTAL_PIN}` in {PIN_SOURCE} against the sum of `CATALOG_COUNT` over the {} \
             registered catalogs",
            tables.passes.len()
        ),
    );

    let headline: String = format!(
        "reports {} families across {} ecosystems",
        tables.family_total, tables.ecosystems
    );
    for (doc, text) in [(CATALOG_DOC, catalog_md), (REFERENCE_DOC, reference_md)] {
        findings.require_phrase(
            doc,
            text,
            &headline,
            "the registered catalogs sum to that many families over that many ecosystems for the \
             `full` feature set, so the page states a breadth the binary does not report",
        );
    }
}

fn check_native_tiers(
    tables: &CatalogTables,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    let tiers: NativeTierCounts = tables.native_tiers;
    for tier in &NATIVE_TIERS {
        let derived: usize = (tier.count)(tiers);
        let published: usize = row_count(catalog_md, tier.anchor)?;
        findings.compare(
            published,
            derived,
            &format!(
                "{CATALOG_DOC} row `{}` against `{}` in {PACKER_SOURCE}",
                tier.anchor, tier.constant
            ),
        );
    }

    findings.compare(
        tables.packer_variants,
        tiers.total(),
        &format!(
            "the packer roster in {PACKER_SOURCE} against the five tier rosters it is partitioned \
             into"
        ),
    );

    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!(
            "## Native packers and protectors ({})",
            tables.packer_variants
        ),
        "the `Packer` roster carries that many variants, so the section heading understates or \
         overstates the packers the binary knows",
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!(
            "The `Packer` enum carries {} variants across five `UnpackerStatus` tiers ({} = {}).",
            tables.packer_variants,
            tiers.split(),
            tables.packer_variants
        ),
        "that is the partition the tier rosters declare, so the sentence describes a split the \
         binary does not carry",
    );

    let native_families: usize = tables.pass_count(NATIVE_PASS)?;
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!("catalog advertises {native_families} of them"),
        &format!(
            "`CATALOG_COUNT` for `{NATIVE_PASS}` is {native_families}, so the page states a \
             different number of packers than `disrobe catalog native` lists"
        ),
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!("`disrobe catalog native` lists {native_families}"),
        &format!(
            "`CATALOG_COUNT` for `{NATIVE_PASS}` is {native_families}, so the page states a \
             different number of packers than the command prints"
        ),
    );
    Ok(())
}

fn check_pass_rows(
    tables: &CatalogTables,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    for row in &PASS_ROWS {
        let (derived, source): (usize, String) = catalog_families(&tables.passes, row.pass_id)?;
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
    tables: &CatalogTables,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    let (entries, source): (usize, String) = catalog_families(&tables.passes, LUA_PASS)?;
    findings.compare(
        row_count(catalog_md, LUA_OBFUSCATOR_ROW)?,
        tables.lua_obfuscators,
        &format!(
            "{CATALOG_DOC} row `{LUA_OBFUSCATOR_ROW}` against the `CatalogKey::Obfuscator` entries \
             in {source}"
        ),
    );
    findings.compare(
        row_count(catalog_md, LUA_DIALECT_ROW)?,
        tables.lua_dialects,
        &format!(
            "{CATALOG_DOC} row `{LUA_DIALECT_ROW}` against the `CatalogKey::Dialect` entries in \
             {source}"
        ),
    );
    findings.compare(
        tables.lua_obfuscators.saturating_add(tables.lua_dialects),
        entries,
        &format!(
            "the two entry kinds in {source} against the `CATALOG_COUNT` the same file declares"
        ),
    );
    findings.require_phrase(
        CATALOG_DOC,
        catalog_md,
        &format!(
            "The Lua chain catalog is {entries} entries: {} obfuscator families plus",
            tables.lua_obfuscators
        ),
        &format!(
            "`CATALOG_COUNT` in {source} is {entries} and its entries split {} plus {}, so the \
             prose and the table below it disagree",
            tables.lua_obfuscators, tables.lua_dialects
        ),
    );
    Ok(())
}

fn check_derived_phrases(
    root: &Path,
    tables: &CatalogTables,
    findings: &mut Findings,
) -> Result<()> {
    let mut docs: BTreeMap<&'static str, String> = BTreeMap::new();
    for phrase in &DERIVED_PHRASES {
        if let Entry::Vacant(slot) = docs.entry(phrase.doc) {
            slot.insert(read_doc_visible(root, phrase.doc)?);
        }
    }

    for phrase in &DERIVED_PHRASES {
        let doc_text: &str = docs
            .get(phrase.doc)
            .map(String::as_str)
            .ok_or_else(|| eyre!("{} was not loaded", phrase.doc))?;
        let derived: usize = (phrase.count)(tables);
        findings.require_phrase(
            phrase.doc,
            doc_text,
            &phrase.template.replace("{}", &derived.to_string()),
            phrase.consequence,
        );
    }
    Ok(())
}

fn check_roster_rows(
    tables: &CatalogTables,
    catalog_md: &str,
    findings: &mut Findings,
) -> Result<()> {
    for row in &ROSTER_ROWS {
        let derived: usize = (row.count)(tables);
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

fn static_array_body<'src>(text: &'src str, symbol: &str) -> Option<&'src str> {
    let head: usize = text.find(&format!("static {symbol}:"))?;
    let after: &str = text.get(head..)?;
    let open: usize = after.find('[')?;
    let close: usize = after.find("\n];")?;
    if close <= open {
        return None;
    }
    after.get(open..close)
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
    fn a_static_array_body_stops_at_its_own_terminator() -> core::result::Result<(), String> {
        let source: &str = "static CATALOG: [LuaCatalogEntry; 3] = [\n    LuaCatalogEntry {\n        key: CatalogKey::Obfuscator(LuaObfuscatorKind::Ironbrew2),\n        aliases: &[\"a\", \"b\"],\n    },\n    LuaCatalogEntry {\n        key: CatalogKey::Dialect(DetectedFormat::Luau),\n    },\n];\n\nstatic OTHER: [u8; 1] = [\n    key: CatalogKey::Obfuscator(Trailing),\n];\n";
        let body: &str = static_array_body(source, "CATALOG")
            .ok_or_else(|| "the CATALOG array body did not parse".to_owned())?;
        assert_eq!(body.matches(LUA_OBFUSCATOR_KEY).count(), 1);
        assert_eq!(body.matches(LUA_DIALECT_KEY).count(), 1);
        assert_eq!(static_array_body(source, "ABSENT"), None);
        Ok(())
    }

    #[test]
    fn a_tier_split_renders_in_roster_order() {
        let tiers: NativeTierCounts = NativeTierCounts {
            implemented: 12,
            stub_eval_pending: 6,
            grey_carve: 3,
            grey_detect_only: 6,
            delegated: 2,
        };
        assert_eq!(tiers.split(), "12 + 6 + 3 + 6 + 2");
        assert_eq!(tiers.total(), 29);
        assert_eq!(
            NATIVE_TIERS
                .iter()
                .map(|tier: &TierClaim| (tier.count)(tiers))
                .collect::<Vec<usize>>(),
            vec![12, 6, 3, 6, 2]
        );
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
    fn a_phrase_check_reads_through_the_marker_spans_around_its_numbers() {
        let doc: &str = "reports <!-- m:catalog_family_total -->169<!-- /m --> families across <!-- m:catalog_ecosystems -->15<!-- /m --> ecosystems, and\n";
        let visible: String = strip_html_comments(doc);
        assert!(visible.contains("reports 169 families across 15 ecosystems"));
    }

    #[test]
    fn family_lists_count_parenthesised_detail_as_one_item() {
        assert_eq!(
            cell_item_count(
                "PyInstaller 2.x-6.20+, Nuitka (onefile / standalone / module / wheel), cx_Freeze, py2exe, shiv, pex, Briefcase, SourceDefender `.pye`"
            ),
            8
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
