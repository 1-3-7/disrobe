use std::io::Read as _;
use std::path::{Path, PathBuf};

use disrobe_binfmt::containers::{
    BlazorFile, DotnetBundleEntry, detect_blazor_bundle, extract_blazor_bundle,
};
use disrobe_binfmt::{
    CarveConfig, CarveNode, CarveReport, CarvedChunk, ChunkClass, ContainerKind, ExtractionQuota,
    ExtractionResult, carve_recursive, detect_and_extract_with_hint, sanitize_entry_path,
};
use serde::Serialize;
use walkdir::WalkDir;
use zeroize::Zeroizing;

use crate::cli::output::{self, OutputFormat};
use crate::cli::progress_ui::StageSpinner;

const BLAZOR_DIR_MAX_DEPTH: usize = 16;
const RAW_VOLUME_KEY_READ_SLACK: u64 = 1;

pub(crate) fn run(
    input: PathBuf,
    out: Option<PathBuf>,
    recursive: bool,
    max_depth: u32,
    luks1_raw_volume_key_file: Option<PathBuf>,
    fmt: OutputFormat,
) -> miette::Result<()> {
    if input.is_dir() {
        return run_blazor_dir(&input, out, fmt);
    }
    let luks1_probe: Option<crate::cli::luks1_input::Luks1FileProbe> =
        crate::cli::luks1_input::probe(&input).map_err(
            |error: crate::cli::luks1_input::Luks1ProbeError| match error {
                crate::cli::luks1_input::Luks1ProbeError::Input(error) => miette::miette!(
                    "DR-EXTRACT-0050: cannot read input {}: {error}",
                    input.display()
                ),
                crate::cli::luks1_input::Luks1ProbeError::Refused(error) => miette::miette!(
                    "DR-CLI-0844: LUKS1 input {} was refused before payload allocation: {error}",
                    input.display()
                ),
            },
        )?;
    if let Some(probe) = luks1_probe {
        let Some(key_file): Option<PathBuf> = luks1_raw_volume_key_file else {
            return run_luks1_wall(&probe.prefix, fmt);
        };
        let bytes: Vec<u8> = crate::cli::luks1_input::read_luks1_bounded(&input, &probe)?;
        return run_luks1_raw_key(&input, &bytes, out, &key_file, recursive, max_depth, fmt);
    }
    let bytes: Vec<u8> = std::fs::read(&input).map_err(|e| {
        miette::miette!(
            "DR-EXTRACT-0050: cannot read input {}: {e}",
            input.display()
        )
    })?;
    if let Some(key_file) = luks1_raw_volume_key_file {
        return run_luks1_raw_key(&input, &bytes, out, &key_file, recursive, max_depth, fmt);
    }
    if recursive {
        run_recursive(&input, &bytes, out, max_depth, fmt)
    } else {
        run_flat(&input, &bytes, out, fmt)
    }
}

fn run_luks1_raw_key(
    input: &Path,
    bytes: &[u8],
    out: Option<PathBuf>,
    key_file: &Path,
    recursive: bool,
    max_depth: u32,
    fmt: OutputFormat,
) -> miette::Result<()> {
    let header: disrobe_binfmt::containers::luks1::Luks1Header =
        disrobe_binfmt::containers::luks1::parse_luks1(bytes).map_err(|error| {
            miette::miette!("DR-EXTRACT-0063: cannot read LUKS1 header before key input: {error}")
        })?;
    disrobe_binfmt::containers::luks1::validate_luks1_raw_key_support(&header).map_err(
        |error: disrobe_binfmt::Error| {
            miette::miette!("DR-EXTRACT-0063: unsupported LUKS1 header before key input: {error}")
        },
    )?;
    let key: Zeroizing<Vec<u8>> = read_raw_volume_key(key_file, header.key_bytes)?;
    let decrypted: Vec<u8> =
        disrobe_binfmt::containers::luks1::decrypt_luks1_aes_cbc_plain_with_raw_volume_key(
            bytes,
            key.as_slice(),
        )
        .map_err(|error| {
            miette::miette!("DR-EXTRACT-0066: LUKS1 raw-volume-key recovery refused: {error}")
        })?;
    drop(key);
    if recursive {
        return run_recursive(input, &decrypted, out, max_depth, fmt);
    }
    let out_dir: PathBuf = out.unwrap_or_else(|| default_out_dir(input));
    let kind: ContainerKind = disrobe_binfmt::detect_container(&decrypted).ok_or_else(|| {
        miette::miette!(
            "DR-EXTRACT-0067: decrypted LUKS1 payload did not enter the container pipeline: container not recognized"
        )
    })?;
    let result: ExtractionResult = disrobe_binfmt::extract_to_with_quota(
        kind,
        &decrypted,
        &out_dir,
        ExtractionQuota::default_safe(),
    )
    .map_err(|error| {
        miette::miette!(
            "DR-EXTRACT-0067: decrypted LUKS1 payload did not enter the container pipeline: {error}"
        )
    })?;
    output::emit(fmt, &result, || render_flat(&result, &out_dir))
}

fn read_raw_volume_key(path: &Path, expected_bytes: usize) -> miette::Result<Zeroizing<Vec<u8>>> {
    let cap: u64 = u64::try_from(expected_bytes)
        .ok()
        .and_then(|bytes: u64| bytes.checked_add(RAW_VOLUME_KEY_READ_SLACK))
        .ok_or_else(|| {
            miette::miette!("DR-EXTRACT-0065: raw volume-key size is not addressable")
        })?;
    let mut key: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(expected_bytes));
    let read_result: std::io::Result<usize> = if path.as_os_str() == "-" {
        let stdin: std::io::Stdin = std::io::stdin();
        let locked: std::io::StdinLock<'_> = stdin.lock();
        locked.take(cap).read_to_end(&mut key)
    } else {
        let file: std::fs::File = std::fs::File::open(path).map_err(|error: std::io::Error| {
            miette::miette!(
                "DR-EXTRACT-0065: cannot open raw LUKS1 volume-key file {}: {error}",
                path.display()
            )
        })?;
        let mut limited: std::io::Take<std::fs::File> = file.take(cap);
        limited.read_to_end(&mut key)
    };
    read_result.map_err(|error: std::io::Error| {
        miette::miette!(
            "DR-EXTRACT-0065: cannot read raw LUKS1 volume key from {}: {error}",
            if path.as_os_str() == "-" {
                "standard input".to_owned()
            } else {
                path.display().to_string()
            }
        )
    })?;
    if key.len() != expected_bytes {
        return Err(miette::miette!(
            "DR-EXTRACT-0065: raw LUKS1 volume key must contain exactly {expected_bytes} bytes; read {}",
            key.len()
        ));
    }
    Ok(key)
}

#[derive(Debug, Serialize)]
struct Luks1WallReport {
    format: &'static str,
    cipher: String,
    mode: String,
    digest: String,
    iteration_count: u32,
    key_derivation: String,
    missing_input: &'static str,
    wall: disrobe_core::CryptoWall,
}

fn run_luks1_wall(bytes: &[u8], fmt: OutputFormat) -> miette::Result<()> {
    let header: disrobe_binfmt::containers::luks1::Luks1Header =
        disrobe_binfmt::containers::luks1::parse_luks1(bytes).map_err(|error| {
            miette::miette!("DR-EXTRACT-0064: malformed detected LUKS1 header: {error}")
        })?;
    let wall: disrobe_core::CryptoWall =
        disrobe_binfmt::containers::luks1::luks1_raw_volume_key_wall(bytes).map_err(|error| {
            miette::miette!("DR-EXTRACT-0064: cannot report LUKS1 wall: {error}")
        })?;
    let report: Luks1WallReport = Luks1WallReport {
        format: "luks1",
        cipher: header.cipher_name,
        mode: header.cipher_mode,
        digest: header.hash_spec.clone(),
        iteration_count: header.digest_iterations,
        key_derivation: format!("pbkdf2-{}", header.hash_spec),
        missing_input: "raw volume key",
        wall,
    };
    output::emit(fmt, &report, || render_luks1_wall(&report))
}

fn render_luks1_wall(report: &Luks1WallReport) {
    println!("format: {}", report.format);
    println!("cipher: {}", report.cipher);
    println!("mode: {}", report.mode);
    println!("key derivation: {}", report.key_derivation);
    println!("iterations: {}", report.iteration_count);
    println!("wall: missing {}", report.missing_input);
}

#[derive(Debug, Serialize)]
struct BlazorBundleReport {
    format: &'static str,
    out_dir: String,
    assemblies: Vec<BlazorAssemblyOut>,
    files_scanned: usize,
}

#[derive(Debug, Serialize)]
struct BlazorAssemblyOut {
    name: String,
    bytes: u64,
}

fn collect_bundle_files(
    dir: &Path,
    quota: ExtractionQuota,
) -> miette::Result<Vec<(String, Vec<u8>)>> {
    let mut collected: Vec<(String, Vec<u8>)> = Vec::new();
    let mut total: u64 = 0;
    for entry in WalkDir::new(dir)
        .follow_links(false)
        .max_depth(BLAZOR_DIR_MAX_DEPTH)
        .into_iter()
        .filter_map(Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }
        if collected.len() >= quota.max_entries {
            break;
        }
        let path: &Path = entry.path();
        let Ok(meta): Result<std::fs::Metadata, walkdir::Error> = entry.metadata() else {
            continue;
        };
        if meta.len() > quota.max_per_entry_uncompressed {
            continue;
        }
        total = total.saturating_add(meta.len());
        if total > quota.max_total_uncompressed {
            break;
        }
        let relative: &Path = path.strip_prefix(dir).unwrap_or(path);
        let name: String = relative.to_string_lossy().replace('\\', "/");
        let data: Vec<u8> = std::fs::read(path).map_err(|e| {
            miette::miette!(
                "DR-EXTRACT-0056: cannot read bundle file {}: {e}",
                path.display()
            )
        })?;
        collected.push((name, data));
    }
    Ok(collected)
}

fn run_blazor_dir(input: &Path, out: Option<PathBuf>, fmt: OutputFormat) -> miette::Result<()> {
    let quota: ExtractionQuota = ExtractionQuota::default_safe();
    let raw_files: Vec<(String, Vec<u8>)> = collect_bundle_files(input, quota)?;
    let bundle_files: Vec<BlazorFile<'_>> = raw_files
        .iter()
        .map(|(name, data): &(String, Vec<u8>)| BlazorFile {
            name: name.as_str(),
            data: data.as_slice(),
        })
        .collect();
    if !detect_blazor_bundle(&bundle_files) {
        return Err(miette::miette!(
            "DR-EXTRACT-0057: {} is a directory but is not a recognized Blazor WebAssembly bundle (no blazor.boot.json). Point at a published `wwwroot`/`_framework` folder, or pass a single-file container.",
            input.display()
        ));
    }
    let out_dir: PathBuf = out.unwrap_or_else(|| default_out_dir(input));
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-EXTRACT-0058: cannot create out dir {}: {e}",
            out_dir.display()
        )
    })?;
    let label: String = input.display().to_string();
    let spinner: StageSpinner = StageSpinner::start(
        &label,
        &format!("carving blazor bundle from {} files", raw_files.len()),
    );
    let entries: Vec<DotnetBundleEntry> = extract_blazor_bundle(&bundle_files, quota)
        .map_err(|e| miette::miette!("DR-EXTRACT-0059: blazor carve failed: {e}"))?;
    spinner.finish(&format!("{} assemblies recovered", entries.len()));

    let mut assemblies: Vec<BlazorAssemblyOut> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let safe: String = sanitize_entry_path(&entry.relative_path)
            .map_err(|e| miette::miette!("DR-EXTRACT-0060: unsafe entry path: {e}"))?;
        let disk_path: PathBuf = out_dir.join(&safe);
        if let Some(parent) = disk_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                miette::miette!("DR-EXTRACT-0061: cannot create {}: {e}", parent.display())
            })?;
        }
        std::fs::write(&disk_path, &entry.data).map_err(|e| {
            miette::miette!("DR-EXTRACT-0062: cannot write {}: {e}", disk_path.display())
        })?;
        assemblies.push(BlazorAssemblyOut {
            name: safe,
            bytes: entry.data.len() as u64,
        });
    }

    let report: BlazorBundleReport = BlazorBundleReport {
        format: "blazor-webassembly",
        out_dir: out_dir.display().to_string(),
        assemblies,
        files_scanned: raw_files.len(),
    };
    output::emit(fmt, &report, || render_blazor(&report))
}

fn render_blazor(report: &BlazorBundleReport) {
    println!("format: {}", report.format);
    println!("output: {}", report.out_dir);
    println!(
        "assemblies: {} (from {} scanned files)",
        report.assemblies.len(),
        report.files_scanned
    );
    for asm in &report.assemblies {
        println!("  {} ({} bytes)", asm.name, asm.bytes);
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
    let report: CarveReport = carve_recursive(bytes, &label, config, Some(out_dir.as_path()));
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
