use std::path::{Path, PathBuf};

use disrobe_pass_jvm::{
    ApkResourceReport, CertificateInfo, ResourceEntrySummary, analyze_apk_resources,
};

use crate::cli::output::{self, OutputFormat};

use super::util::push_format;

const RESOURCE_PREVIEW_LIMIT: usize = 50;

pub(crate) fn run(path: PathBuf, out: Option<PathBuf>, fmt: OutputFormat) -> miette::Result<()> {
    let bytes: Vec<u8> =
        std::fs::read(&path).map_err(|e| miette::miette!("DR-CLI-0700: cannot read apk: {e}"))?;
    let report: ApkResourceReport = analyze_apk_resources(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0701: apk resource analysis: {e}"))?;
    if let Some(out_dir) = out.as_deref() {
        write_outputs(out_dir, &report)?;
    }
    output::emit(fmt, &report, || render_text(&path, &report))
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

fn render_text(path: &std::path::Path, report: &ApkResourceReport) {
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
