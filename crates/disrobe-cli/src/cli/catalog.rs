use disrobe_core::chain::{Ecosystem, ObfuscatorCatalog, SupportQuality};
use serde::Serialize;

use super::catalog_registry::registry;
use super::output::{self, OutputFormat};

#[derive(Debug, Clone, Serialize)]
struct CatalogRow {
    family: &'static str,
    aliases: Vec<&'static str>,
    pass: &'static str,
    ecosystem: &'static str,
    support: SupportQuality,
}

#[derive(Debug, Clone, Serialize)]
struct EcosystemGroup {
    ecosystem: &'static str,
    label: &'static str,
    families: Vec<CatalogRow>,
}

#[derive(Debug, Clone, Serialize)]
struct CatalogReport {
    filter: Option<&'static str>,
    family_count: usize,
    ecosystem_count: usize,
    ecosystems: Vec<EcosystemGroup>,
}

pub(crate) fn run(ecosystem: Option<String>, fmt: OutputFormat) -> miette::Result<()> {
    let filter: Option<Ecosystem> = match ecosystem {
        None => None,
        Some(raw) => Some(Ecosystem::parse(&raw).ok_or_else(|| {
            let valid: Vec<&'static str> = Ecosystem::all()
                .iter()
                .map(|e| e.slug())
                .collect::<Vec<_>>();
            miette::miette!(
                "DR-CATALOG-0001: unknown ecosystem `{raw}`; valid ecosystems: {}",
                valid.join(", ")
            )
        })?),
    };

    let catalogs: Vec<&'static dyn ObfuscatorCatalog> = registry();
    let report: CatalogReport = build_report(&catalogs, filter);

    if filter.is_some() && report.ecosystems.is_empty() {
        let valid: Vec<&'static str> = Ecosystem::all().iter().map(|e| e.slug()).collect();
        return Err(miette::miette!(
            "DR-CATALOG-0002: no obfuscator/packer families registered for ecosystem `{}`; ecosystems with families: {}",
            filter.map_or("?", Ecosystem::slug),
            valid.join(", ")
        ));
    }

    output::emit(fmt, &report, || print_text(&report))
}

fn build_report(
    catalogs: &[&'static dyn ObfuscatorCatalog],
    filter: Option<Ecosystem>,
) -> CatalogReport {
    let mut groups: Vec<EcosystemGroup> = Vec::new();
    for eco in Ecosystem::all() {
        if filter.is_some_and(|f: Ecosystem| f != *eco) {
            continue;
        }
        let mut families: Vec<CatalogRow> = Vec::new();
        for catalog in catalogs {
            if catalog.ecosystem() != *eco {
                continue;
            }
            let pass: &'static str = catalog.pass_id();
            for entry in catalog.catalog() {
                families.push(CatalogRow {
                    family: entry.display_name(),
                    aliases: entry.aliases().to_vec(),
                    pass,
                    ecosystem: eco.slug(),
                    support: entry.support_quality(),
                });
            }
        }
        if families.is_empty() {
            continue;
        }
        families.sort_by(|a: &CatalogRow, b: &CatalogRow| {
            a.family
                .to_ascii_lowercase()
                .cmp(&b.family.to_ascii_lowercase())
        });
        groups.push(EcosystemGroup {
            ecosystem: eco.slug(),
            label: eco.label(),
            families,
        });
    }

    let family_count: usize = groups
        .iter()
        .map(|g: &EcosystemGroup| g.families.len())
        .sum();
    CatalogReport {
        filter: filter.map(Ecosystem::slug),
        family_count,
        ecosystem_count: groups.len(),
        ecosystems: groups,
    }
}

fn print_text(report: &CatalogReport) {
    let name_width: usize = report
        .ecosystems
        .iter()
        .flat_map(|g: &EcosystemGroup| g.families.iter())
        .map(|r: &CatalogRow| display_label(r).len())
        .max()
        .unwrap_or(0)
        .clamp(8, 56);
    let pass_width: usize = report
        .ecosystems
        .iter()
        .flat_map(|g: &EcosystemGroup| g.families.iter())
        .map(|r: &CatalogRow| r.pass.len())
        .max()
        .unwrap_or(0)
        .max(4);

    for group in &report.ecosystems {
        println!("{} ({})", group.label, group.families.len());
        for row in &group.families {
            let label: String = display_label(row);
            let quality: &'static str = row.support.label();
            println!(
                "  {label:<name_width$}  {:<pass_width$}  [{quality}]",
                row.pass
            );
        }
        println!();
    }

    println!(
        "support quality: {} = recovers output, {} = partial recovery, {} = detection only",
        SupportQuality::Full.label(),
        SupportQuality::Partial.label(),
        SupportQuality::DetectOnly.label(),
    );
    match report.filter {
        Some(slug) => println!("{} families in ecosystem `{slug}`", report.family_count),
        None => println!(
            "{} families across {} ecosystems",
            report.family_count, report.ecosystem_count
        ),
    }
}

fn display_label(row: &CatalogRow) -> String {
    if row.aliases.is_empty() {
        row.family.to_owned()
    } else {
        format!("{} (aka {})", row.family, row.aliases.join(", "))
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    fn collect(eco: Ecosystem) -> Vec<CatalogRow> {
        let mut rows: Vec<CatalogRow> = Vec::new();
        for catalog in registry() {
            if catalog.ecosystem() != eco {
                continue;
            }
            let pass: &'static str = catalog.pass_id();
            for entry in catalog.catalog() {
                rows.push(CatalogRow {
                    family: entry.display_name(),
                    aliases: entry.aliases().to_vec(),
                    pass,
                    ecosystem: eco.slug(),
                    support: entry.support_quality(),
                });
            }
        }
        rows
    }

    fn families(eco: Ecosystem) -> Vec<&'static str> {
        collect(eco)
            .into_iter()
            .map(|r: CatalogRow| r.family)
            .collect()
    }

    #[test]
    fn python_lists_known_families() {
        let py: Vec<&'static str> = families(Ecosystem::Python);
        assert!(
            py.iter().any(|f: &&str| f.contains("PyArmor")),
            "python catalog must list PyArmor, got {py:?}"
        );
        assert!(
            py.contains(&"Berserker"),
            "python catalog must list the py-deob Berserker family, got {py:?}"
        );
    }

    #[test]
    fn native_lists_upx() {
        let native: Vec<&'static str> = families(Ecosystem::Native);
        assert!(
            native.contains(&"UPX"),
            "native catalog must list the UPX packer, got {native:?}"
        );
    }

    #[test]
    #[cfg(feature = "js")]
    fn javascript_lists_obfuscator_io() {
        let js: Vec<&'static str> = families(Ecosystem::JavaScript);
        assert!(
            js.contains(&"obfuscator.io"),
            "js catalog must list obfuscator.io, got {js:?}"
        );
    }

    #[test]
    #[cfg(feature = "dotnet")]
    fn dotnet_lists_a_protector() {
        let dotnet: Vec<&'static str> = families(Ecosystem::Dotnet);
        assert!(
            dotnet.iter().any(|f: &&str| f.contains("ConfuserEx")),
            "dotnet catalog must list a ConfuserEx protector, got {dotnet:?}"
        );
    }

    const PUBLISHED_FAMILY_TOTAL: usize = 170;
    const CATALOG_REFERENCE: &str = include_str!("../../../../docs/src/cli/reference.md");
    const CATALOG_CHAIN_BUILD_SCOPE: &str =
        "Builds that include the `chain` feature report the registry compiled into that binary.";

    const PUBLISHED_ECOSYSTEM_SLUGS: [&str; 15] = [
        "as3",
        "beam",
        "dotnet",
        "go",
        "javascript",
        "jvm",
        "lua",
        "mobile",
        "native",
        "php",
        "python",
        "ruby",
        "shell",
        "swift",
        "wasm",
    ];

    #[derive(Debug, Clone, Copy)]
    struct CatalogExpectation {
        pass: &'static str,
        ecosystem: &'static str,
        families: usize,
        enabled: bool,
    }

    const REGISTRY_EXPECTATIONS: [CatalogExpectation; 16] = [
        CatalogExpectation {
            pass: "native.packer-unpack",
            ecosystem: "native",
            families: 27,
            enabled: true,
        },
        CatalogExpectation {
            pass: "py.deob",
            ecosystem: "python",
            families: 20,
            enabled: true,
        },
        CatalogExpectation {
            pass: "pyarmor.unpack",
            ecosystem: "python",
            families: 7,
            enabled: true,
        },
        CatalogExpectation {
            pass: "wasm.deob",
            ecosystem: "wasm",
            families: 5,
            enabled: cfg!(feature = "wasm"),
        },
        CatalogExpectation {
            pass: "js.deob",
            ecosystem: "javascript",
            families: 10,
            enabled: cfg!(feature = "js"),
        },
        CatalogExpectation {
            pass: "lua.deob",
            ecosystem: "lua",
            families: 16,
            enabled: cfg!(feature = "lua"),
        },
        CatalogExpectation {
            pass: "php.peel",
            ecosystem: "php",
            families: 3,
            enabled: cfg!(feature = "php"),
        },
        CatalogExpectation {
            pass: "dotnet.classify",
            ecosystem: "dotnet",
            families: 22,
            enabled: cfg!(feature = "dotnet"),
        },
        CatalogExpectation {
            pass: "shell.deob",
            ecosystem: "shell",
            families: 20,
            enabled: cfg!(feature = "shell"),
        },
        CatalogExpectation {
            pass: "jvm.classify",
            ecosystem: "jvm",
            families: 10,
            enabled: cfg!(feature = "jvm"),
        },
        CatalogExpectation {
            pass: "go.classify",
            ecosystem: "go",
            families: 1,
            enabled: cfg!(feature = "go"),
        },
        CatalogExpectation {
            pass: "ruby.classify",
            ecosystem: "ruby",
            families: 6,
            enabled: cfg!(feature = "ruby"),
        },
        CatalogExpectation {
            pass: "beam.classify",
            ecosystem: "beam",
            families: 2,
            enabled: cfg!(feature = "beam"),
        },
        CatalogExpectation {
            pass: "as3.classify",
            ecosystem: "as3",
            families: 7,
            enabled: cfg!(feature = "as3"),
        },
        CatalogExpectation {
            pass: "mobile.classify",
            ecosystem: "mobile",
            families: 11,
            enabled: cfg!(feature = "mobile"),
        },
        CatalogExpectation {
            pass: "swift-objc.classify",
            ecosystem: "swift",
            families: 3,
            enabled: cfg!(feature = "swift"),
        },
    ];

    fn observed_counts(report: &CatalogReport) -> BTreeMap<(&'static str, &'static str), usize> {
        let mut counts: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
        for group in &report.ecosystems {
            for row in &group.families {
                *counts.entry((row.ecosystem, row.pass)).or_default() += 1;
            }
        }
        counts
    }

    fn expectation_mismatches(report: &CatalogReport) -> Vec<String> {
        let observed: BTreeMap<(&'static str, &'static str), usize> = observed_counts(report);
        let mut pinned: BTreeMap<(&'static str, &'static str), usize> = BTreeMap::new();
        for exp in REGISTRY_EXPECTATIONS
            .iter()
            .filter(|e: &&CatalogExpectation| e.enabled)
        {
            pinned.insert((exp.ecosystem, exp.pass), exp.families);
        }

        let mut findings: Vec<String> = Vec::new();
        for (key, want) in &pinned {
            match observed.get(key) {
                None => findings.push(format!(
                    "{} / {} is absent from the registry, pinned at {want} families",
                    key.0, key.1
                )),
                Some(got) if got != want => findings.push(format!(
                    "{} / {} lists {got} families, pinned at {want}",
                    key.0, key.1
                )),
                Some(_) => {}
            }
        }
        for (key, got) in &observed {
            if !pinned.contains_key(key) {
                findings.push(format!(
                    "{} / {} lists {got} families and is not pinned",
                    key.0, key.1
                ));
            }
        }
        findings
    }

    #[test]
    fn published_catalog_totals_match_the_registry() {
        let full_total: usize = REGISTRY_EXPECTATIONS
            .iter()
            .map(|e: &CatalogExpectation| e.families)
            .sum();
        assert_eq!(
            full_total, PUBLISHED_FAMILY_TOTAL,
            "docs/src/catalog.md and docs/src/cli/reference.md publish {PUBLISHED_FAMILY_TOTAL} families for the `full` feature set; the pinned per-pass table sums to {full_total}"
        );
        let reference_claim: String = format!(
            "The default `full` build's live binary reports <!-- m:catalog_family_total -->{PUBLISHED_FAMILY_TOTAL}<!-- /m --> families across <!-- m:catalog_ecosystems -->{}<!-- /m --> ecosystems.",
            PUBLISHED_ECOSYSTEM_SLUGS.len()
        );
        assert!(
            CATALOG_REFERENCE.contains(&reference_claim),
            "docs/src/cli/reference.md must scope the {PUBLISHED_FAMILY_TOTAL}-family catalog claim to the default `full` build"
        );
        assert!(
            CATALOG_REFERENCE.contains(CATALOG_CHAIN_BUILD_SCOPE),
            "docs/src/cli/reference.md must state that `chain` builds report their compiled registry"
        );
        let full_ecosystems: Vec<&'static str> = REGISTRY_EXPECTATIONS
            .iter()
            .map(|e: &CatalogExpectation| e.ecosystem)
            .collect::<BTreeSet<&'static str>>()
            .into_iter()
            .collect();
        assert_eq!(
            full_ecosystems, PUBLISHED_ECOSYSTEM_SLUGS,
            "the published ecosystem list must be exactly the ecosystems the `full` registry covers"
        );

        let catalogs: Vec<&'static dyn ObfuscatorCatalog> = registry();
        let report: CatalogReport = build_report(&catalogs, None);
        let mismatches: Vec<String> = expectation_mismatches(&report);
        assert!(
            mismatches.is_empty(),
            "registry no longer matches the pinned catalog table: {mismatches:#?}"
        );

        let active_total: usize = REGISTRY_EXPECTATIONS
            .iter()
            .filter(|e: &&CatalogExpectation| e.enabled)
            .map(|e: &CatalogExpectation| e.families)
            .sum();
        assert_eq!(
            report.family_count, active_total,
            "`disrobe catalog` must report {active_total} families for this feature set"
        );
        let active_ecosystems: BTreeSet<&'static str> = REGISTRY_EXPECTATIONS
            .iter()
            .filter(|e: &&CatalogExpectation| e.enabled)
            .map(|e: &CatalogExpectation| e.ecosystem)
            .collect();
        let reported_ecosystems: BTreeSet<&'static str> = report
            .ecosystems
            .iter()
            .map(|g: &EcosystemGroup| g.ecosystem)
            .collect();
        assert_eq!(reported_ecosystems, active_ecosystems);
        assert_eq!(report.ecosystem_count, active_ecosystems.len());
        if !cfg!(any(
            feature = "as3",
            feature = "beam",
            feature = "dotnet",
            feature = "go",
            feature = "js",
            feature = "jvm",
            feature = "lua",
            feature = "mobile",
            feature = "php",
            feature = "ruby",
            feature = "shell",
            feature = "swift",
            feature = "wasm",
        )) {
            assert_eq!(report.family_count, 54);
            assert_eq!(report.ecosystem_count, 2);
        }
    }

    #[test]
    fn catalog_pin_reports_a_dropped_registry_catalog() {
        let dropped: &'static str = disrobe_pass_native::chain_detector::PASS_ID;
        let dropped_families: usize = REGISTRY_EXPECTATIONS
            .iter()
            .find(|e: &&CatalogExpectation| e.pass == dropped)
            .expect("native catalog is pinned")
            .families;

        let catalogs: Vec<&'static dyn ObfuscatorCatalog> = registry();
        let thinned: Vec<&'static dyn ObfuscatorCatalog> = catalogs
            .iter()
            .copied()
            .filter(|c: &&'static dyn ObfuscatorCatalog| c.pass_id() != dropped)
            .collect();

        let intact: CatalogReport = build_report(&catalogs, None);
        let mutated: CatalogReport = build_report(&thinned, None);
        assert_eq!(
            intact.family_count - mutated.family_count,
            dropped_families,
            "dropping {dropped} must remove exactly its {dropped_families} families"
        );
        assert!(
            expectation_mismatches(&intact).is_empty(),
            "control requires the intact registry to pass"
        );

        let mismatches: Vec<String> = expectation_mismatches(&mutated);
        assert!(
            mismatches.iter().any(|m: &String| m.contains(dropped)),
            "the pin must name {dropped} once it leaves the registry, got {mismatches:#?}"
        );
    }

    #[test]
    #[cfg(feature = "jvm")]
    fn jvm_lists_proguard_and_allatori() {
        let jvm: Vec<&'static str> = families(Ecosystem::Jvm);
        assert!(
            jvm.iter().any(|f: &&str| f.contains("ProGuard")),
            "jvm catalog must list ProGuard, got {jvm:?}"
        );
        assert!(
            jvm.contains(&"Allatori"),
            "jvm catalog must list Allatori, got {jvm:?}"
        );
    }

    #[test]
    #[cfg(feature = "go")]
    fn go_lists_garble() {
        let go: Vec<&'static str> = families(Ecosystem::Go);
        assert!(
            go.contains(&"garble"),
            "go catalog must list garble, got {go:?}"
        );
    }

    #[test]
    #[cfg(feature = "ruby")]
    fn ruby_lists_yarv() {
        let ruby: Vec<&'static str> = families(Ecosystem::Ruby);
        assert!(
            ruby.iter().any(|f: &&str| f.contains("YARV")),
            "ruby catalog must list YARV, got {ruby:?}"
        );
    }

    #[test]
    fn unknown_ecosystem_is_typed_error() {
        let err: miette::Report =
            run(Some("boguslang".to_owned()), OutputFormat::Text).expect_err("unknown rejected");
        let msg: String = format!("{err}");
        assert!(msg.contains("DR-CATALOG-0001"), "got: {msg}");
        assert!(msg.contains("boguslang"), "got: {msg}");
        assert!(
            msg.contains("python"),
            "error must list valid ecosystems, got: {msg}"
        );
    }
}
