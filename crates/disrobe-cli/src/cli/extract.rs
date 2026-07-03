use std::path::{Path, PathBuf};

use disrobe_binfmt::{
    CarveConfig, CarveNode, CarveReport, CarvedChunk, ChunkClass, ContainerKind, ExtractionResult,
    carve_recursive, detect_and_extract_with_hint,
};

use crate::cli::output::{self, OutputFormat};
use crate::cli::progress_ui::StageSpinner;

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    recursive: bool,
    max_depth: u32,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input).map_err(|e| {
        miette::miette!(
            "DR-EXTRACT-0050: cannot read input {}: {e}",
            input.display()
        )
    })?;
    if recursive {
        run_recursive(&input, &bytes, out, max_depth, fmt)
    } else {
        run_flat(&input, &bytes, out, fmt)
    }
}

fn run_flat(
    input: &Path,
    bytes: &[u8],
    out: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let out_dir: PathBuf = out.unwrap_or_else(|| default_out_dir(input));
    let label: String = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("extract")
        .to_owned();
    let spinner: StageSpinner =
        StageSpinner::start(&label, &format!("extracting {} bytes", bytes.len()));
    let result: ExtractionResult = detect_and_extract_with_hint(bytes, Some(input), &out_dir)
        .map_err(|e| miette::miette!("DR-EXTRACT-0051: extract failed: {e}"))?;
    spinner.finish(&format!("{} entries", result.entries.len()));
    output::emit(fmt, &result, || render_flat(&result, &out_dir))
}

fn render_flat(result: &ExtractionResult, out_dir: &Path) {
    println!("format: {}", result.kind.label());
    println!("output: {}", out_dir.display());
    println!("entries: {}", result.entries.len());
    for entry in &result.entries {
        println!("  {} ({} bytes)", entry.name, entry.uncompressed_size);
    }
    for violation in &result.integrity_violations {
        println!("  ! {violation}");
    }
}

fn run_recursive(
    input: &Path,
    bytes: &[u8],
    out: Option<PathBuf>,
    max_depth: u32,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let out_dir: PathBuf = out.unwrap_or_else(|| default_out_dir(input));
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-EXTRACT-0052: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;
    let config: CarveConfig = CarveConfig::new(max_depth.max(1));
    let label: String = input.display().to_string();
    let spinner: StageSpinner = StageSpinner::start(
        &label,
        &format!("carving {} bytes (depth <= {max_depth})", bytes.len()),
    );
    let report: CarveReport = carve_recursive(bytes, &label, config);
    spinner.finish(&format!(
        "{} nodes, {} bytes carved",
        report.nodes_visited, report.bytes_carved
    ));
    let report_path: PathBuf = out_dir.join("carve.json");
    let report_bytes: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-EXTRACT-0053: carve.json serialize: {e}"))?;
    std::fs::write(&report_path, &report_bytes)
        .map_err(|e| miette::miette!("DR-EXTRACT-0054: cannot write carve.json: {e}"))?;
    write_carved_chunks(&report.root, bytes, &out_dir)?;
    output::emit(fmt, &report, || render_recursive(&report, &out_dir))
}

fn write_carved_chunks(node: &CarveNode, bytes: &[u8], out_dir: &Path) -> miette::Result<()> {
    for chunk in &node.chunks {
        match chunk.class {
            ChunkClass::Unknown => {
                let name: String = format!("{:08}-{:08}.unknown", chunk.start, chunk.end);
                write_slice(out_dir, &name, bytes, chunk)?;
            }
            ChunkClass::Padding => {
                let name: String = format!("{:08}-{:08}.padding", chunk.start, chunk.end);
                write_slice(out_dir, &name, bytes, chunk)?;
            }
            ChunkClass::Valid => {}
        }
    }
    Ok(())
}

fn write_slice(
    out_dir: &Path,
    name: &str,
    bytes: &[u8],
    chunk: &CarvedChunk,
) -> miette::Result<()> {
    let start: usize = usize::try_from(chunk.start).unwrap_or(usize::MAX);
    let end: usize = usize::try_from(chunk.end).unwrap_or(usize::MAX);
    let Some(slice) = bytes.get(start..end) else {
        return Ok(());
    };
    let path: PathBuf = out_dir.join(name);
    std::fs::write(&path, slice)
        .map_err(|e| miette::miette!("DR-EXTRACT-0055: cannot write chunk {name}: {e}"))?;
    Ok(())
}

fn render_recursive(report: &CarveReport, out_dir: &Path) {
    println!("output: {}", out_dir.display());
    println!(
        "max-depth: {} | nodes: {} | chunks: {} | bytes carved: {}",
        report.max_depth, report.nodes_visited, report.chunks_total, report.bytes_carved
    );
    if report.work_budget_exhausted {
        println!("! work budget exhausted: traversal bounded to prevent runaway nesting");
    }
    render_node(&report.root, 0);
}

fn render_node(node: &CarveNode, indent: usize) {
    let pad: String = "  ".repeat(indent);
    let kind: String = node
        .extraction_kind
        .map_or_else(|| "raw".to_owned(), |k: ContainerKind| k.label().to_owned());
    println!(
        "{pad}[depth {}] {} ({} bytes, {kind})",
        node.depth, node.source, node.size
    );
    for chunk in &node.chunks {
        println!("{pad}  {}", format_chunk(chunk));
    }
    for note in &node.notes {
        println!("{pad}  - {note}");
    }
    for child in &node.children {
        render_node(child, indent + 1);
    }
}

fn format_chunk(chunk: &CarvedChunk) -> String {
    let class: &str = match chunk.class {
        ChunkClass::Valid => "valid",
        ChunkClass::Unknown => "unknown",
        ChunkClass::Padding => "padding",
    };
    let kind: String = chunk
        .kind
        .map_or_else(String::new, |k: ContainerKind| format!(" {}", k.label()));
    let pad: String = chunk
        .padding_byte
        .map_or_else(String::new, |b: u8| format!(" byte=0x{b:02x}"));
    format!(
        "{class}{kind} [{}-{}] {} bytes entropy={:.2}{pad}",
        chunk.start,
        chunk.end,
        chunk.len(),
        chunk.entropy
    )
}

fn default_out_dir(input: &Path) -> PathBuf {
    let stem: &str = input
        .file_stem()
        .and_then(|s: &std::ffi::OsStr| s.to_str())
        .unwrap_or("extract");
    PathBuf::from(format!("./out/{stem}-extract"))
}
