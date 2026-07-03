use disrobe_core::chain::{Ecosystem, SupportQuality};
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

    let mut groups: Vec<EcosystemGroup> = Vec::new();
    for eco in Ecosystem::all() {
        if filter.is_some_and(|f: Ecosystem| f != *eco) {
            continue;
        }
        let mut families: Vec<CatalogRow> = Vec::new();
        for catalog in registry() {
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

    if filter.is_some() && groups.is_empty() {
        let valid: Vec<&'static str> = Ecosystem::all().iter().map(|e| e.slug()).collect();
        return Err(miette::miette!(
            "DR-CATALOG-0002: no obfuscator/packer families registered for ecosystem `{}`; ecosystems with families: {}",
            filter.map_or("?", Ecosystem::slug),
            valid.join(", ")
        ));
    }

    let family_count: usize = groups
        .iter()
        .map(|g: &EcosystemGroup| g.families.len())
        .sum();
    let report: CatalogReport = CatalogReport {
        filter: filter.map(Ecosystem::slug),
        family_count,
        ecosystem_count: groups.len(),
        ecosystems: groups,
    };

    output::emit(fmt, &report, || print_text(&report))
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

    #[test]
    fn registry_spans_multiple_ecosystems() {
        let mut distinct: std::collections::BTreeSet<Ecosystem> = std::collections::BTreeSet::new();
        for catalog in registry() {
            if !catalog.catalog().is_empty() {
                distinct.insert(catalog.ecosystem());
            }
        }
        assert!(
            distinct.len() >= 14,
            "registry must span at least 14 ecosystems, got {} {distinct:?}",
            distinct.len()
        );
        for eco in [
            Ecosystem::Python,
            Ecosystem::Native,
            Ecosystem::Jvm,
            Ecosystem::Go,
            Ecosystem::Ruby,
            Ecosystem::Beam,
            Ecosystem::As3,
            Ecosystem::Mobile,
            Ecosystem::Swift,
        ] {
            assert!(distinct.contains(&eco), "missing ecosystem {eco:?}");
        }
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
