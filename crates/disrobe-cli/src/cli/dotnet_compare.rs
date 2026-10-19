use std::path::Path;

use disrobe_pass_dotnet::build_compare::{
    AssemblySummary, BuildComparison, ChangeCounts, CompareError, compare,
};

const INPUT_MAX_BYTES: u64 = 1 << 29;

pub(crate) fn run(old: &Path, new: &Path, json: bool) -> miette::Result<()> {
    let old_bytes: Vec<u8> = read(old)?;
    let new_bytes: Vec<u8> = read(new)?;
    let report: BuildComparison = compare(&old_bytes, &new_bytes)
        .map_err(|error: CompareError| miette::miette!("{error}"))?;
    if json {
        let rendered: String =
            serde_json::to_string_pretty(&report).map_err(|error: serde_json::Error| {
                miette::miette!("DR-DOTNET-0964: cannot serialize the comparison: {error}")
            })?;
        println!("{rendered}");
        return Ok(());
    }
    render_text(old, new, &report);
    Ok(())
}

fn read(path: &Path) -> miette::Result<Vec<u8>> {
    let metadata: std::fs::Metadata =
        std::fs::metadata(path).map_err(|error: std::io::Error| {
            miette::miette!("DR-DOTNET-0963: cannot read {}: {error}", path.display())
        })?;
    if metadata.len() > INPUT_MAX_BYTES {
        return Err(miette::miette!(
            "DR-DOTNET-0965: {} is {} bytes, above the {INPUT_MAX_BYTES}-byte cap",
            path.display(),
            metadata.len()
        ));
    }
    std::fs::read(path).map_err(|error: std::io::Error| {
        miette::miette!("DR-DOTNET-0963: cannot read {}: {error}", path.display())
    })
}

fn label(path: &Path, summary: &AssemblySummary) -> String {
    match (&summary.name, &summary.version) {
        (Some(name), Some(version)) => format!("{} ({name} {version})", path.display()),
        _ => format!("{} (module without an assembly manifest)", path.display()),
    }
}

fn render_text(old: &Path, new: &Path, report: &BuildComparison) {
    println!(
        "dotnet compare: {} -> {}",
        label(old, &report.old),
        label(new, &report.new)
    );
    if report.findings.is_empty() {
        println!("no differences");
        return;
    }
    for (entity, counts) in &report.counts {
        let ChangeCounts {
            added,
            removed,
            changed,
        } = counts;
        println!(
            "  {:<13} {added} added, {removed} removed, {changed} changed",
            entity.as_str()
        );
    }
    println!();
    for line in report.lines() {
        println!("{line}");
    }
}
