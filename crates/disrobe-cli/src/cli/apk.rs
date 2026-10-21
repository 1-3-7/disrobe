use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use disrobe_core::neutralize::{
    Applied, NeutralizationPlan, NeutralizationReport, Selection, apply, neutralized_path,
};
use disrobe_pass_jvm::{
    AndroidAuditReport, ApkResourceReport, CertificateInfo, DexNeutralization, JniSurfaceReport,
    ManifestFacts, ResolvedNative, ResourceEntrySummary, analyze_apk_resources, audit_android_apk,
    plan_apk_neutralization,
};
use serde::Serialize;

use crate::cli::native::NeutralizeMode;
use crate::cli::output::{self, OutputFormat};

use super::util::push_format;

const RESOURCE_PREVIEW_LIMIT: usize = 50;

#[derive(Debug, Clone, Serialize)]
struct JniUnresolvedEntry {
    class: String,
    method: String,
    descriptor: String,
    jni_short_symbol: String,
}

#[derive(Debug, Clone, Serialize)]
struct JniAmbiguousEntry {
    symbol: String,
    libraries: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ApkAnalysis {
    #[serde(flatten)]
    report: ApkResourceReport,
    jni_unresolved: Vec<JniUnresolvedEntry>,
    jni_ambiguous: Vec<JniAmbiguousEntry>,
    audit: AndroidAuditReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    neutralization: Option<NeutralizationSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct NeutralizedDex {
    entry: String,
    audited_sites: usize,
    plan: NeutralizationPlan,
    report: NeutralizationReport,
    output: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct NeutralizationSummary {
    schema: &'static str,
    mode: &'static str,
    report_path: String,
    dex: Vec<NeutralizedDex>,
}

const NEUTRALIZATION_REPORT_FILE: &str = "android-neutralization.json";

fn neutralize_apk(
    input: &Path,
    bytes: &[u8],
    out: Option<&Path>,
    mode: NeutralizeMode,
) -> miette::Result<NeutralizationSummary> {
    let stem: String = input
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("apk")
        .to_owned();
    let out_dir: PathBuf = out.map_or_else(
        || PathBuf::from(format!("./out/{stem}-apk")),
        Path::to_path_buf,
    );
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0996: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;
    let plans: Vec<DexNeutralization> = plan_apk_neutralization(bytes)
        .map_err(|e| miette::miette!("DR-CLI-0997: cannot plan apk neutralization: {e}"))?;
    let mut dex: Vec<NeutralizedDex> = Vec::with_capacity(plans.len());
    for planned in plans {
        let selection: Selection = match mode {
            NeutralizeMode::Apply => Selection::All,
            NeutralizeMode::Skip => Selection::Skip,
            NeutralizeMode::Ask if planned.plan.is_empty() => Selection::Skip,
            NeutralizeMode::Ask => {
                eprintln!("{}:", planned.entry);
                super::native::ask_each_patch(&planned.plan)
            }
        };
        let applied: Applied = apply(&planned.bytes, &planned.plan, &selection)
            .map_err(|e| miette::miette!("DR-CLI-0998: neutralization refused: {e}"))?;
        let output: Option<String> = if applied.report.applied.is_empty() {
            None
        } else {
            let path: PathBuf = neutralized_path(&out_dir.join(&planned.entry));
            std::fs::write(&path, &applied.bytes).map_err(|e| {
                miette::miette!("DR-CLI-0999: cannot write {}: {e}", path.display())
            })?;
            Some(path.display().to_string())
        };
        eprintln!(
            "apk neutralize ({}) {}: {} patch(es) offered, {} refused; applied {}, declined {}, skipped {}{}",
            mode.label(),
            planned.entry,
            planned.plan.patches.len(),
            planned.plan.refusals.len(),
            applied.report.applied.len(),
            applied.report.declined.len(),
            applied.report.skipped.len(),
            output
                .as_deref()
                .map_or_else(String::new, |p: &str| format!("; wrote {p}")),
        );
        dex.push(NeutralizedDex {
            entry: planned.entry,
            audited_sites: planned.audited_sites,
            plan: planned.plan,
            report: applied.report,
            output,
        });
    }
    let summary: NeutralizationSummary = NeutralizationSummary {
        schema: "disrobe.apk.neutralization/v1",
        mode: mode.label(),
        report_path: out_dir
            .join(NEUTRALIZATION_REPORT_FILE)
            .display()
            .to_string(),
        dex,
    };
    let encoded: Vec<u8> = serde_json::to_vec_pretty(&summary)
        .map_err(|e| miette::miette!("DR-CLI-0989: serialize neutralization report: {e}"))?;
    std::fs::write(&summary.report_path, encoded)
        .map_err(|e| miette::miette!("DR-CLI-0988: cannot write {}: {e}", summary.report_path))?;
    Ok(summary)
}

fn derive_jni_unresolved(surface: &JniSurfaceReport) -> Vec<JniUnresolvedEntry> {
    let mut out: Vec<JniUnresolvedEntry> = surface
        .native_methods
        .iter()
        .filter(|m: &&ResolvedNative| m.resolved_in.is_none())
        .map(|m: &ResolvedNative| JniUnresolvedEntry {
            class: m.class.clone(),
            method: m.method.clone(),
            descriptor: m.descriptor.clone(),
            jni_short_symbol: m.jni_short_symbol.clone(),
        })
        .collect();
    out.sort_by(|a: &JniUnresolvedEntry, b: &JniUnresolvedEntry| {
        (a.class.as_str(), a.method.as_str(), a.descriptor.as_str()).cmp(&(
            b.class.as_str(),
            b.method.as_str(),
            b.descriptor.as_str(),
        ))
    });
    out
}

fn derive_jni_ambiguous(surface: &JniSurfaceReport) -> Vec<JniAmbiguousEntry> {
    let mut symbol_to_libs: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for lib in &surface.libraries {
        for sym in &lib.jni_exports {
            symbol_to_libs
                .entry(sym.as_str())
                .or_default()
                .push(lib.path.as_str());
        }
    }
    let mut out: Vec<JniAmbiguousEntry> = symbol_to_libs
        .into_iter()
        .filter(|(_, libs): &(&str, Vec<&str>)| libs.len() > 1)
        .map(|(symbol, libs): (&str, Vec<&str>)| JniAmbiguousEntry {
            symbol: symbol.to_owned(),
            libraries: libs.into_iter().map(str::to_owned).collect(),
        })
        .collect();
    out.sort_by(|a: &JniAmbiguousEntry, b: &JniAmbiguousEntry| a.symbol.cmp(&b.symbol));
    out
}

pub(crate) fn run(
    path: PathBuf,
    out: Option<PathBuf>,
    neutralize: Option<NeutralizeMode>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> =
        std::fs::read(&path).map_err(|e| miette::miette!("DR-CLI-0700: cannot read apk: {e}"))?;
    let report: ApkResourceReport = analyze_apk_resources(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0701: apk resource analysis: {e}"))?;
    if let Some(out_dir) = out.as_deref() {
        write_outputs(out_dir, &report)?;
    }
    let neutralization: Option<NeutralizationSummary> = match neutralize {
        Some(mode) => Some(neutralize_apk(&path, &bytes, out.as_deref(), mode)?),
        None => None,
    };
    let audit: AndroidAuditReport = audit_android_apk(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0995: apk code-pattern audit: {e}"))?;
    let analysis: ApkAnalysis = ApkAnalysis {
        jni_unresolved: derive_jni_unresolved(&report.jni),
        jni_ambiguous: derive_jni_ambiguous(&report.jni),
        audit,
        neutralization,
        report,
    };
    output::emit(fmt, &analysis, || render_text(&path, &analysis))
}

fn write_outputs(out_dir: &Path, report: &ApkResourceReport) -> miette::Result<()> {
    std::fs::create_dir_all(out_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0702: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;
    if let Some(xml) = report.manifest_xml.as_deref() {
        let manifest_path: PathBuf = out_dir.join("AndroidManifest.xml");
        std::fs::write(&manifest_path, xml.as_bytes()).map_err(|e| {
            miette::miette!("DR-CLI-0703: cannot write {}: {e}", manifest_path.display())
        })?;
        eprintln!(
            "  wrote manifest:  {} ({} bytes)",
            manifest_path.display(),
            xml.len()
        );
    }
    let table: String = render_resource_table(&report.resources);
    let resources_path: PathBuf = out_dir.join("resources.txt");
    std::fs::write(&resources_path, table.as_bytes()).map_err(|e| {
        miette::miette!(
            "DR-CLI-0704: cannot write {}: {e}",
            resources_path.display()
        )
    })?;
    eprintln!(
        "  wrote resources: {} ({} entr{})",
        resources_path.display(),
        report.resources.len(),
        plural(report.resources.len(), "y", "ies")
    );
    Ok(())
}

fn render_resource_table(resources: &[ResourceEntrySummary]) -> String {
    let mut out: String = String::new();
    for entry in resources {
        push_format(
            &mut out,
            format_args!("0x{:08x}\t{}\n", entry.id, entry.name),
        );
    }
    out
}

fn render_text(path: &std::path::Path, analysis: &ApkAnalysis) {
    let report: &ApkResourceReport = &analysis.report;
    println!("apk: OK");
    println!("  input:        {}", path.display());
    println!(
        "  package:      {}",
        report.package.as_deref().unwrap_or("(none)")
    );
    println!(
        "  resources:    {} entr{} across {} package{}",
        report.resource_entry_count,
        plural(report.resource_entry_count, "y", "ies"),
        report.package_count,
        plural(report.package_count, "", "s"),
    );
    render_resources(&report.resources);
    render_certificates(&report.certificates);
    render_manifest(report.manifest_xml.as_deref());
    render_manifest_facts(report.manifest.as_ref());
    render_jni(report, analysis);
    render_audit(&analysis.audit);
}

fn render_audit(audit: &AndroidAuditReport) {
    println!(
        "  audit:        {} finding{} over {} method{}{}",
        audit.findings.len(),
        plural(audit.findings.len(), "", "s"),
        audit.methods_scanned,
        plural(audit.methods_scanned, "", "s"),
        if audit.truncated { " (truncated)" } else { "" },
    );
    for finding in &audit.findings {
        println!(
            "    {} [{}] {}->{} @{:#x}: {}",
            finding.rule_id,
            finding.severity.label(),
            finding.class,
            finding.method,
            finding.pc,
            finding.evidence
        );
    }
}

fn render_manifest_facts(facts: Option<&ManifestFacts>) {
    let Some(facts): Option<&ManifestFacts> = facts else {
        return;
    };
    println!(
        "  facts:        version {} ({}), sdk min {} target {}, debuggable {}, backup {}, cleartext {}, network-security-config {}",
        facts
            .version_code
            .map_or_else(|| "(none)".to_owned(), |v: i64| v.to_string()),
        facts.version_name.as_deref().unwrap_or("(none)"),
        facts
            .min_sdk
            .map_or_else(|| "(none)".to_owned(), |v: i64| v.to_string()),
        facts
            .target_sdk
            .map_or_else(|| "(none)".to_owned(), |v: i64| v.to_string()),
        facts
            .debuggable
            .map_or("(unset)", |b: bool| if b { "true" } else { "false" }),
        facts
            .allow_backup
            .map_or("(unset)", |b: bool| if b { "true" } else { "false" }),
        facts
            .uses_cleartext_traffic
            .map_or("(unset)", |b: bool| if b { "true" } else { "false" }),
        facts.network_security_config.as_deref().unwrap_or("(none)"),
    );
    println!(
        "  permissions:  {} used, {} declared",
        facts.uses_permissions.len(),
        facts.declared_permissions.len()
    );
    for permission in &facts.uses_permissions {
        println!("    {permission}");
    }
    println!(
        "  components:   {} ({} exported, {} launchable{})",
        facts.components.len(),
        facts.exported_components,
        facts.launchable_activities.len(),
        if facts.components_truncated {
            ", truncated"
        } else {
            ""
        },
    );
    for component in &facts.components {
        println!(
            "    {} {} exported={}{} filters={}{}{}",
            component.kind.label(),
            component.name,
            if component.effectively_exported {
                "true"
            } else {
                "false"
            },
            match component.exported {
                Some(_) => "",
                None => " (default)",
            },
            component.intent_filters,
            if component.launchable {
                " launchable"
            } else {
                ""
            },
            component
                .permission
                .as_deref()
                .map_or_else(String::new, |p: &str| format!(" permission={p}")),
        );
    }
}

fn render_jni(report: &ApkResourceReport, analysis: &ApkAnalysis) {
    println!(
        "  dex files:    {} ({} native libraries embedded)",
        report.dex_count, report.native_lib_count
    );
    let jni: &JniSurfaceReport = &report.jni;
    println!(
        "  jni:          {} native method{}, {} resolved statically, {} dynamic-only",
        jni.native_method_count,
        plural(jni.native_method_count, "", "s"),
        jni.resolved_statically,
        jni.dynamic_only,
    );
    for lib in &jni.libraries {
        println!(
            "    - {} (abi={} format={} arch={} exports={})",
            lib.path,
            lib.abi.as_deref().unwrap_or("?"),
            lib.format,
            lib.arch,
            lib.jni_exports.len()
        );
    }
    if !jni.registered_natives.is_empty() {
        println!(
            "    registered natives (RegisterNatives): {}",
            jni.registered_natives.len()
        );
        for reg in &jni.registered_natives {
            println!(
                "      - {} {} @ 0x{:x} in {}",
                reg.name, reg.signature, reg.fn_addr, reg.library
            );
        }
    }
    if !jni.code_scan_complete {
        println!(
            "    code scan:  INCOMPLETE ({} decode error(s))",
            jni.decode_error_count
        );
    }
    if !analysis.jni_unresolved.is_empty() {
        println!("    unresolved: {}", analysis.jni_unresolved.len());
        for u in &analysis.jni_unresolved {
            println!(
                "      - {}.{}{} ({})",
                u.class, u.method, u.descriptor, u.jni_short_symbol
            );
        }
    }
    if !analysis.jni_ambiguous.is_empty() {
        println!("    ambiguous:  {}", analysis.jni_ambiguous.len());
        for a in &analysis.jni_ambiguous {
            println!(
                "      - {} exported by {}",
                a.symbol,
                a.libraries.join(", ")
            );
        }
    }
}

fn render_resources(resources: &[ResourceEntrySummary]) {
    if resources.is_empty() {
        return;
    }
    let shown: usize = resources.len().min(RESOURCE_PREVIEW_LIMIT);
    for entry in &resources[..shown] {
        println!("    0x{:08x}  {}", entry.id, entry.name);
    }
    if resources.len() > shown {
        println!(
            "    ... {} more (use --json for the full table)",
            resources.len() - shown
        );
    }
}

fn render_certificates(certificates: &[CertificateInfo]) {
    println!(
        "  certificates: {} signer cert{}",
        certificates.len(),
        plural(certificates.len(), "", "s"),
    );
    for cert in certificates {
        println!("    subject:    {}", cert.subject);
        println!("    issuer:     {}", cert.issuer);
        println!("    serial:     {}", cert.serial_hex);
        println!("    sha256:     {}", cert.sha256_fingerprint);
    }
}

fn render_manifest(manifest_xml: Option<&str>) {
    let Some(xml): Option<&str> = manifest_xml else {
        println!("  manifest:     (no AndroidManifest.xml)");
        return;
    };
    println!(
        "  manifest:     decoded AndroidManifest.xml ({} bytes)",
        xml.len()
    );
    for line in xml.lines() {
        println!("    {line}");
    }
}

const fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 { one } else { many }
}
