use std::io::Read as _;
use std::path::{Path, PathBuf};

use clap::Subcommand;

use disrobe_pass_nativelang::rust_inventory::{
    AuditableEdge, AuditableEvidence, AuditableGraph, AuditablePackage, CrateSource, CrateSymbols,
    DependencyKind, InventoryTruncation, RecoveredCrate, RustInventory, SymbolInventory,
    rust_inventory,
};

const MAX_INPUT_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Subcommand, Debug)]
pub(crate) enum RustCmd {
    #[command(
        about = "list the rustc release, crates, cargo-auditable dependency graph and per-crate symbol counts of a Rust PE / ELF / Mach-O binary"
    )]
    Inventory {
        #[arg(help = "input Rust binary")]
        input: PathBuf,
        #[arg(long, help = "print the inventory as JSON")]
        json: bool,
    },
}

pub(crate) fn run(action: RustCmd) -> miette::Result<()> {
    match action {
        RustCmd::Inventory { input, json } => inventory(&input, json),
    }
}

fn read_input(path: &Path) -> miette::Result<Vec<u8>> {
    let file: std::fs::File = std::fs::File::open(path).map_err(|error| {
        miette::miette!("DR-RUSTINV-0101: cannot read {}: {error}", path.display())
    })?;
    let length: u64 = file
        .metadata()
        .map_err(|error| {
            miette::miette!("DR-RUSTINV-0101: cannot read {}: {error}", path.display())
        })?
        .len();
    if length > MAX_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-RUSTINV-0102: {} is {length} bytes, above the {MAX_INPUT_BYTES}-byte limit",
            path.display()
        ));
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(MAX_INPUT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            miette::miette!("DR-RUSTINV-0101: cannot read {}: {error}", path.display())
        })?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err(miette::miette!(
            "DR-RUSTINV-0102: {} grew past the {MAX_INPUT_BYTES}-byte limit while it was read",
            path.display()
        ));
    }
    Ok(bytes)
}

fn inventory(input: &Path, json: bool) -> miette::Result<()> {
    let bytes: Vec<u8> = read_input(input)?;
    let inventory: RustInventory = rust_inventory(&bytes)
        .map_err(|error| miette::miette!("DR-RUSTINV-0103: {}: {error}", input.display()))?;
    if json {
        let text: String = serde_json::to_string_pretty(&inventory).map_err(|error| {
            miette::miette!("DR-RUSTINV-0104: serialize the inventory: {error}")
        })?;
        println!("{text}");
    } else {
        for line in render(input, &inventory) {
            println!("{line}");
        }
    }
    Ok(())
}

fn plural(count: u64, noun: &str) -> String {
    if count == 1 {
        format!("{count} {noun}")
    } else {
        format!("{count} {noun}s")
    }
}

fn crate_line(krate: &RecoveredCrate) -> String {
    let name: &str = krate.name.as_deref().unwrap_or("(unnamed)");
    let version: &str = krate.version.as_deref().unwrap_or("-");
    let source: String = match &krate.source {
        CrateSource::Registry { index } => format!("registry {index}"),
        CrateSource::Git {
            repository,
            url_hash,
            revision,
            directory,
        } => directory.as_deref().map_or_else(
            || format!("git {repository}-{url_hash} rev {revision}"),
            |directory: &str| format!("git {repository}-{url_hash} rev {revision} dir {directory}"),
        ),
        CrateSource::Vendored { root } => format!("vendored {root}"),
        CrateSource::Path { root } => format!("path {root}"),
        CrateSource::Workspace { root } => format!("workspace {root}"),
    };
    format!(
        "  {name} {version}  {source}  {}  @{:#x} {}",
        plural(krate.occurrences, "path"),
        krate.evidence.offset,
        krate.evidence.text
    )
}

fn graph_lines(graph: &AuditableGraph, out: &mut Vec<String>) {
    out.push(format!(
        "auditable: {} @{}, {} compressed, {} JSON, format {}: {} packages, {} edges",
        graph.section.name,
        graph
            .section
            .offset
            .map_or_else(|| "-".to_owned(), |offset: u64| format!("{offset:#x}")),
        plural(graph.section.compressed_bytes, "byte"),
        plural(graph.decompressed_bytes, "byte"),
        graph.format,
        graph.packages.len(),
        graph.dependencies.len()
    ));
    for (index, package) in graph.packages.iter().enumerate() {
        let dependencies: Vec<String> = graph
            .dependencies
            .iter()
            .filter(|edge: &&AuditableEdge| edge.from == index)
            .filter_map(|edge: &AuditableEdge| graph.packages.get(edge.to))
            .map(|dependency: &AuditablePackage| {
                format!("{} {}", dependency.package.name, dependency.package.version)
            })
            .collect();
        let kind: &str = match package.kind {
            DependencyKind::Runtime => "runtime",
            DependencyKind::Build => "build",
        };
        out.push(format!(
            "  {} {} ({}, {kind}{}) -> [{}]",
            package.package.name,
            package.package.version,
            package
                .package
                .source
                .as_deref()
                .unwrap_or("unknown source"),
            if package.root { ", root" } else { "" },
            dependencies.join(", ")
        ));
    }
}

fn render(input: &Path, inventory: &RustInventory) -> Vec<String> {
    let mut out: Vec<String> = vec![format!(
        "rust inventory: {} ({:?}, {})",
        input.display(),
        inventory.container,
        plural(inventory.input_bytes, "byte")
    )];
    if inventory.rustc.is_empty() {
        out.push("rustc: no /rustc/<commit>/ path".to_owned());
    }
    for commit in &inventory.rustc {
        out.push(format!(
            "rustc: {} {}  {}  @{:#x} {}",
            commit.release.as_deref().unwrap_or("unreleased"),
            commit.commit,
            plural(commit.occurrences, "path"),
            commit.evidence.offset,
            commit.evidence.text
        ));
    }
    out.push(format!("crates: {}", inventory.crates.len()));
    out.extend(inventory.crates.iter().map(crate_line));
    match &inventory.auditable {
        AuditableEvidence::Absent => out.push("auditable: no .dep-v0 section".to_owned()),
        AuditableEvidence::Present(graph) => graph_lines(graph, &mut out),
        AuditableEvidence::Refused { section, reason } => {
            out.push(format!("auditable: {} refused: {reason}", section.name));
        }
    }
    let symbols: &SymbolInventory = &inventory.symbols;
    if symbols.symbol_table {
        out.push(format!(
            "symbols: {} defined, {} legacy, {} v0, {} unattributed",
            symbols.defined, symbols.legacy, symbols.v0, symbols.unattributed
        ));
        out.extend(symbols.crates.iter().map(|krate: &CrateSymbols| {
            format!(
                "  {}  {} legacy  {} v0  e.g. #{} {}",
                krate.name, krate.legacy, krate.v0, krate.evidence.index, krate.evidence.demangled
            )
        }));
    } else {
        out.push("symbols: no symbol table".to_owned());
    }
    let truncated: InventoryTruncation = inventory.truncated;
    if truncated.paths || truncated.crates || truncated.rustc_commits || truncated.symbols {
        out.push(format!("truncated: {truncated:?}"));
    }
    out
}
