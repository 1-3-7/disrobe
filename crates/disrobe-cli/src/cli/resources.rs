use std::path::{Path, PathBuf};

use disrobe_binfmt::pe_resources::{
    ResourceEntry, ResourceId, ResourceReport, pe_resources, resource_data,
};

use crate::cli::output::{self, OutputFormat};

const MAX_INPUT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

fn label(id: &ResourceId) -> String {
    match id {
        ResourceId::Id(number) => number.to_string(),
        ResourceId::Name(name) => name.clone(),
    }
}

fn safe_component(text: &str) -> String {
    text.chars()
        .map(|c: char| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub(crate) fn run(
    path: PathBuf,
    extract: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let size: u64 = std::fs::metadata(&path)
        .map_err(|e| miette::miette!("DR-CLI-0418: cannot read {}: {e}", path.display()))?
        .len();
    if size > MAX_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-CLI-0418: {} is {size} bytes, above the {MAX_INPUT_BYTES}-byte limit",
            path.display()
        ));
    }
    let bytes: Vec<u8> = std::fs::read(&path)
        .map_err(|e| miette::miette!("DR-CLI-0418: cannot read {}: {e}", path.display()))?;
    let report: ResourceReport = pe_resources(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0418: {}: {e}", path.display()))?;
    if let Some(dir) = &extract {
        write_resources(&bytes, &report, dir)?;
    }
    output::emit(fmt, &report, || render(&report, extract.as_deref()))?;
    Ok(())
}

fn write_resources(bytes: &[u8], report: &ResourceReport, dir: &Path) -> miette::Result<()> {
    std::fs::create_dir_all(dir)
        .map_err(|e| miette::miette!("DR-CLI-0418: cannot create {}: {e}", dir.display()))?;
    for entry in &report.entries {
        let Some(data): Option<&[u8]> = resource_data(bytes, entry) else {
            continue;
        };
        let kind: String = entry
            .kind_name
            .map_or_else(|| label(&entry.kind), str::to_owned);
        let name: String = format!(
            "{}-{}-{}.{}",
            safe_component(&kind),
            safe_component(&label(&entry.name)),
            entry.language,
            entry.content.unwrap_or("bin")
        );
        let target: PathBuf = dir.join(name);
        std::fs::write(&target, data)
            .map_err(|e| miette::miette!("DR-CLI-0418: cannot write {}: {e}", target.display()))?;
    }
    Ok(())
}

fn render(report: &ResourceReport, extract: Option<&Path>) {
    println!("{} resources", report.entries.len());
    for entry in &report.entries {
        render_entry(entry);
    }
    if let Some(version) = &report.version {
        println!(
            "version: file {} product {} (flags 0x{:x}, os 0x{:x}, type {})",
            version.file_version,
            version.product_version,
            version.flags,
            version.os,
            version.file_type
        );
        for (table, values) in &version.strings {
            for (key, value) in values {
                println!("  [{table}] {key}: {value}");
            }
        }
    }
    for table in &report.string_tables {
        println!(
            "string table, language {} ({} strings)",
            table.language,
            table.strings.len()
        );
        for (id, text) in &table.strings {
            println!("  {id}: {text:?}");
        }
    }
    for manifest in &report.manifests {
        println!(
            "manifest: {} execution level {} ui access {} dpi aware {}",
            manifest.assembly_name.as_deref().unwrap_or("(unnamed)"),
            manifest.execution_level.as_deref().unwrap_or("(not set)"),
            manifest
                .ui_access
                .map_or_else(|| "(not set)".to_owned(), |v| v.to_string()),
            manifest.dpi_aware.as_deref().unwrap_or("(not set)")
        );
        for dependency in &manifest.dependencies {
            println!("  depends on {dependency}");
        }
    }
    for group in &report.icon_groups {
        let sizes: Vec<String> = group
            .images
            .iter()
            .map(|image| format!("{}x{} {}bpp", image.width, image.height, image.bit_count))
            .collect();
        println!("icon group {}: {}", label(&group.name), sizes.join(", "));
    }
    if let Some(dir) = extract {
        println!("resources written to {}", dir.display());
    }
    for problem in &report.problems {
        println!("problem: {problem}");
    }
}

fn render_entry(entry: &ResourceEntry) {
    let kind: String = entry
        .kind_name
        .map_or_else(|| label(&entry.kind), str::to_owned);
    let content: String = entry
        .content
        .map(|kind: &str| format!(" [{kind}]"))
        .unwrap_or_default();
    println!(
        "  {kind}/{}/{} {} bytes sha256 {}{content}",
        label(&entry.name),
        entry.language,
        entry.size,
        entry.sha256
    );
}
