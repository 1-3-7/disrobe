use std::path::PathBuf;

use disrobe_core::ioc::{self, Indicator, IocKind, IocReport};

use crate::cli::output::OutputFormat;
use crate::cli::sarif::{
    ArtifactLocation, Driver, Location, Message, PhysicalLocation, ReportingDescriptor, SarifLevel,
    SarifLog, SarifResult,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum IocFormat {
    #[default]
    Text,
    Json,
    Sarif,
}

fn native_import_text(bytes: &[u8]) -> Vec<String> {
    match disrobe_binfmt::native::parse_native(bytes) {
        Ok(native) => native
            .imports
            .into_iter()
            .map(|i: disrobe_binfmt::native::ImportInfo| format!("{}!{}", i.library, i.name))
            .collect(),
        Err(_) => Vec::new(),
    }
}

fn render_text(report: &IocReport, defang: bool) {
    if report.indicators.is_empty() {
        println!("no indicators found");
        return;
    }
    for ind in &report.indicators {
        let value: String = if defang {
            ioc::defang(&ind.value, ind.kind)
        } else {
            ind.value.clone()
        };
        println!(
            "{}\t{}\t@{}\t{}",
            ind.kind.label(),
            ind.encoding.label(),
            ind.offset,
            value
        );
    }
    println!("\n{} indicator(s)", report.total);
}

fn sarif_rule_id(kind: IocKind) -> String {
    format!("DR-IOC-{}", kind.label().to_uppercase().replace('_', "-"))
}

const fn sarif_level(kind: IocKind) -> SarifLevel {
    match kind {
        IocKind::Url
        | IocKind::Ipv4
        | IocKind::Ipv6
        | IocKind::BitcoinAddress
        | IocKind::EthereumAddress
        | IocKind::MoneroAddress
        | IocKind::LitecoinAddress
        | IocKind::TronAddress
        | IocKind::CreditCard => SarifLevel::Warning,
        IocKind::CryptoConstant
        | IocKind::Domain
        | IocKind::Email
        | IocKind::WindowsPath
        | IocKind::RegistryKey
        | IocKind::UnixPath
        | IocKind::MacAddress
        | IocKind::Uuid
        | IocKind::PdbPath => SarifLevel::Note,
    }
}

fn to_sarif(report: &IocReport, uri: &str, defang: bool) -> SarifLog {
    let kinds: std::collections::BTreeSet<IocKind> = report
        .indicators
        .iter()
        .map(|i: &Indicator| i.kind)
        .collect();
    let rules: Vec<ReportingDescriptor> = kinds
        .iter()
        .map(|kind: &IocKind| ReportingDescriptor {
            id: sarif_rule_id(*kind),
            name: Some(kind.label().to_owned()),
            short_description: None,
            full_description: None,
        })
        .collect();
    let results: Vec<SarifResult> = report
        .indicators
        .iter()
        .map(|ind: &Indicator| {
            let value: String = if defang {
                ioc::defang(&ind.value, ind.kind)
            } else {
                ind.value.clone()
            };
            SarifResult {
                rule_id: sarif_rule_id(ind.kind),
                kind: None,
                level: sarif_level(ind.kind),
                message: Message {
                    text: format!(
                        "{} ({}) at offset {}: {value}",
                        ind.kind.label(),
                        ind.encoding.label(),
                        ind.offset
                    ),
                },
                locations: vec![Location {
                    physical_location: PhysicalLocation {
                        artifact_location: ArtifactLocation::at(uri.to_owned()),
                        region: None,
                    },
                }],
                properties: None,
            }
        })
        .collect();
    SarifLog::new(Driver::disrobe(rules), results)
}

pub(crate) fn run(
    path: PathBuf,
    format: IocFormat,
    defang: bool,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-IOC-0050: cannot read target: {e}"))?;
    let uri: String = path.display().to_string();
    let imports: Vec<String> = native_import_text(&bytes);
    let import_refs: Vec<&str> = imports.iter().map(String::as_str).collect();
    let report: IocReport = ioc::report_with_extra(&bytes, Some(&uri), &import_refs);

    let effective: IocFormat = if fmt.is_machine() {
        if matches!(fmt, OutputFormat::Sarif) {
            IocFormat::Sarif
        } else {
            IocFormat::Json
        }
    } else {
        format
    };

    match effective {
        IocFormat::Text => {
            render_text(&report, defang);
            Ok(())
        }
        IocFormat::Json => {
            let payload: IocReport = if defang {
                defanged_report(report)
            } else {
                report
            };
            let s: String = serde_json::to_string_pretty(&payload)
                .map_err(|e| miette::miette!("DR-IOC-0051: json serialize: {e}"))?;
            println!("{s}");
            Ok(())
        }
        IocFormat::Sarif => {
            let log: SarifLog = to_sarif(&report, &uri, defang);
            crate::cli::output::emit_sarif_log(&log)
        }
    }
}

fn defanged_report(mut report: IocReport) -> IocReport {
    for ind in &mut report.indicators {
        ind.value = ioc::defang(&ind.value, ind.kind);
    }
    report
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn sarif_log_maps_indicators_to_results() {
        let report: IocReport =
            ioc::report(b"reach http://c2.example.com/ and 1.2.3.4", Some("a.bin"));
        let log: SarifLog = to_sarif(&report, "a.bin", false);
        let v: serde_json::Value = serde_json::to_value(&log).expect("serialize");
        assert_eq!(v["version"], "2.1.0");
        let results: &Vec<serde_json::Value> = v["runs"][0]["results"].as_array().expect("results");
        assert!(!results.is_empty());
        assert!(results.iter().all(|r: &serde_json::Value| {
            r["ruleId"]
                .as_str()
                .is_some_and(|s: &str| s.starts_with("DR-IOC-"))
        }));
        let rule_ids: std::collections::BTreeSet<&str> = v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .filter_map(|r: &serde_json::Value| r["id"].as_str())
            .collect();
        assert!(
            results.iter().all(|r: &serde_json::Value| {
                r["ruleId"]
                    .as_str()
                    .is_some_and(|id: &str| rule_ids.contains(id))
            }),
            "every result ruleId must resolve to a declared rule descriptor: rules={rule_ids:?}"
        );
    }

    #[test]
    fn defanged_report_neutralizes_values() {
        let report: IocReport = ioc::report(b"hit http://1.2.3.4/x", None);
        let defanged: IocReport = defanged_report(report);
        assert!(
            defanged
                .indicators
                .iter()
                .any(|i: &Indicator| i.value.contains("[.]")),
            "{:?}",
            defanged.indicators
        );
    }

    #[test]
    fn win16_ne_imports_reach_ioc_enrichment() {
        const REAL_NE: &[u8] = include_bytes!("../../../../corpus/native/formats/hello_ne.exe");
        let imports: Vec<String> = native_import_text(REAL_NE);
        assert_eq!(imports.len(), 81);
        assert!(imports.iter().any(|import: &String| import == "KERNEL!#3"));
        assert!(imports.iter().any(|import: &String| import == "USER!#141"));
    }
}
