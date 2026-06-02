#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub(crate) enum NuitkaCmd {
    #[command(
        about = "detect a Nuitka build flavor (--onefile, --standalone, --module, signed-PE, wheel) & report the Python version"
    )]
    Detect {
        #[arg(help = "Nuitka-built executable to inspect")]
        input: PathBuf,
    },
    #[command(
        about = "extract a Nuitka --onefile payload (kax / kay + zstd) to its embedded files"
    )]
    Extract {
        #[arg(help = "Nuitka --onefile executable to extract")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-extracted)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "scan a Nuitka --standalone binary's symbol table for impl_* & module-init functions"
    )]
    Symbols {
        #[arg(help = "Nuitka binary to scan")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the symbol graph JSON")]
        out: Option<PathBuf>,
    },
    #[command(
        about = "decompile recoverable Nuitka constants (literals, identifiers, annotations) from a build dir or binary, plus version + module map"
    )]
    Decompile {
        #[arg(help = "Nuitka binary or its <name>.build directory")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the decompilation JSON (default: ./out/<stem>.nuitka-constants.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "also emit the recovered Python surface skeleton to this path"
        )]
        python: Option<PathBuf>,
    },
    #[command(
        about = "decode a single Nuitka .const file (concatenated pickle streams) to its constant pool"
    )]
    Constants {
        #[arg(help = "path to a *.const file (e.g. module.hello.const)")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "blob_name from __constant.txt (\"\" global pool, else module name)",
            default_value = ""
        )]
        blob_name: String,
        #[arg(short, long, help = "output path for the constant pool JSON")]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: NuitkaCmd) -> miette::Result<()> {
    match action {
        NuitkaCmd::Detect { input } => detect(input),
        NuitkaCmd::Extract { input, out } => extract(input, out),
        NuitkaCmd::Symbols { input, out } => symbols(input, out),
        NuitkaCmd::Decompile { input, out, python } => decompile(input, out, python),
        NuitkaCmd::Constants {
            input,
            blob_name,
            out,
        } => constants(input, blob_name, out),
    }
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let det: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_file(&input).map_err(|e| miette::miette!("{e}"))?;
    println!("nuitka detect: OK");
    println!("  flavor:       {:?}", det.flavor);
    println!("  signatures:   {:?}", det.hits);
    if let (Some(maj), Some(min)) = (det.version.python_major, det.version.python_minor) {
        println!("  python:       {maj}.{min}");
    }
    if let Some(off) = det.onefile_payload_offset {
        println!("  onefile payload @ offset {off}");
    }
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0016: cannot read input: {e}"))?;
    let det: disrobe_pass_nuitka::Detection =
        disrobe_pass_nuitka::detect_in_bytes(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let Some(offset): Option<usize> = det.onefile_payload_offset else {
        return Err(miette::miette!(
            "DR-CLI-0017: input is not a Nuitka --onefile build (no KA[XY] payload detected); use `nuitka symbols` for --standalone builds"
        ));
    };
    let payload: disrobe_pass_nuitka::OnefilePayload =
        disrobe_pass_nuitka::extract_onefile(&bytes, offset).map_err(|e| miette::miette!("{e}"))?;
    let out_dir: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nuitka-out");
        PathBuf::from(format!("./out/{stem}-extracted"))
    });
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0018: cannot create out dir: {e}"))?;
    let mut written: usize = 0usize;
    for entry in &payload.entries {
        if entry.symlink_target.is_some() {
            continue;
        }
        let Some(target): Option<PathBuf> = safe_join(&out_dir, &entry.filename) else {
            return Err(miette::miette!(
                "DR-CLI-0023: refusing unsafe payload path '{}' (traversal)",
                entry.filename
            ));
        };
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0018: cannot create out dir: {e}"))?;
        }
        std::fs::write(&target, &entry.data)
            .map_err(|e| miette::miette!("DR-CLI-0019: cannot write {}: {e}", target.display()))?;
        written += 1;
    }
    println!("nuitka extract: OK");
    println!("  flavor:        {:?}", det.flavor);
    println!("  encoding:      {:?}", payload.encoding);
    println!("  checksums:     {}", payload.has_checksums);
    println!("  entries:       {}", payload.entries.len());
    println!("  files written: {written}");
    println!("  payload bytes: {}", payload.payload_size);
    println!("  out dir:       {}", out_dir.display());
    for entry in &payload.entries {
        println!("    - {} ({} bytes)", entry.filename, entry.size);
    }
    Ok(())
}

/// Join a payload-relative filename under `root`, normalising `/` and `\` separators and
/// rejecting any absolute, root, drive-prefixed, or `..`-bearing component so a malicious
/// payload cannot escape the output directory.
fn safe_join(root: &std::path::Path, filename: &str) -> Option<PathBuf> {
    let mut result: PathBuf = root.to_path_buf();
    let mut components: usize = 0usize;
    for raw in filename.split(['/', '\\']) {
        if raw.is_empty() || raw == "." {
            continue;
        }
        if raw == ".." || raw.contains(':') {
            return None;
        }
        result.push(raw);
        components += 1;
    }
    if components == 0 {
        return None;
    }
    Some(result)
}

fn symbols(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0020: cannot read input: {e}"))?;
    let graph: disrobe_pass_nuitka::SymbolGraph =
        disrobe_pass_nuitka::scan_symbols(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let target: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nuitka-symbols");
        PathBuf::from(format!("./out/{stem}.symbols.json"))
    });
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0021: cannot create dir: {e}"))?;
    }
    std::fs::write(
        &target,
        serde_json::to_vec_pretty(&graph).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0022: cannot write symbols: {e}"))?;
    println!("nuitka symbols: OK");
    println!("  impl_functions:   {}", graph.impl_functions.len());
    println!("  module_inits:     {}", graph.module_inits.len());
    println!("  make_func_count:  {}", graph.make_function_count);
    println!("  interesting strs: {}", graph.strings.len());
    println!("  wrote:            {}", target.display());
    Ok(())
}

fn decompile(input: PathBuf, out: Option<PathBuf>, python: Option<PathBuf>) -> miette::Result<()> {
    let result: disrobe_pass_nuitka::NuitkaDecompilation = if input.is_dir() {
        disrobe_pass_nuitka::decompile_build_dir(&input).map_err(|e| miette::miette!("{e}"))?
    } else {
        disrobe_pass_nuitka::decompile_binary(&input).map_err(|e| miette::miette!("{e}"))?
    };

    let target: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("nuitka");
        PathBuf::from(format!("./out/{stem}.nuitka-constants.json"))
    });
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0026: cannot create dir: {e}"))?;
    }
    let json: Vec<u8> = serde_json::to_vec_pretty(&result)
        .map_err(|e| miette::miette!("DR-CLI-0027: cannot serialize decompilation: {e}"))?;
    std::fs::write(&target, &json)
        .map_err(|e| miette::miette!("DR-CLI-0028: cannot write decompilation: {e}"))?;

    let distinct_strings: usize = result.constants.all_strings.len();
    let distinct_ints: usize = result.constants.all_ints.len();
    let stream_total: usize = result
        .constants
        .pools
        .values()
        .map(|p: &disrobe_pass_nuitka::ConstantsPool| p.stream_count)
        .sum();

    println!("nuitka decompile: OK");
    println!("  source kind:      {:?}", result.source_kind);
    print_version(&result.version);
    println!("  const files:      {}", result.constants.pools.len());
    println!("  pickle streams:   {stream_total}");
    println!("  distinct strings: {distinct_strings}");
    println!("  distinct ints:    {distinct_ints}");
    for (name, pool) in &result.constants.pools {
        println!(
            "    - {name}: {} streams, {} strings, {} ints",
            pool.stream_count,
            pool.strings.len(),
            pool.ints.len()
        );
    }
    if let Some(surface) = &result.surface {
        println!(
            "  surface:          {} ({} functions, fidelity {:?})",
            surface.module_name,
            surface.functions.len(),
            surface.fidelity
        );
    }
    for note in &result.notes {
        println!("  note: {note}");
    }
    println!("  wrote:            {}", target.display());

    if let Some(python_path) = python {
        let Some(surface): Option<&disrobe_pass_nuitka::SurfaceModule> = result.surface.as_ref()
        else {
            return Err(miette::miette!(
                "DR-CLI-0030: --python requested but no surface was recovered (need a .build dir with module.<name>.c)"
            ));
        };
        if let Some(parent) = python_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0031: cannot create dir: {e}"))?;
        }
        std::fs::write(&python_path, surface.python_source.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0032: cannot write python skeleton: {e}"))?;
        println!("  wrote python skeleton: {}", python_path.display());
    }

    Ok(())
}

fn constants(input: PathBuf, blob_name: String, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0029: cannot read .const file: {e}"))?;
    let source_file: String = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("input.const")
        .to_owned();
    let pool: disrobe_pass_nuitka::ConstantsPool =
        disrobe_pass_nuitka::decompile_const_bytes(&bytes, &source_file, &blob_name)
            .map_err(|e| miette::miette!("{e}"))?;

    if let Some(target) = out {
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| miette::miette!("DR-CLI-0026: cannot create dir: {e}"))?;
        }
        let json: Vec<u8> = serde_json::to_vec_pretty(&pool)
            .map_err(|e| miette::miette!("DR-CLI-0027: cannot serialize pool: {e}"))?;
        std::fs::write(&target, &json)
            .map_err(|e| miette::miette!("DR-CLI-0028: cannot write pool: {e}"))?;
        println!("  wrote:            {}", target.display());
    }

    println!("nuitka constants: OK");
    println!("  source file:      {source_file}");
    println!("  blob name:        {blob_name:?}");
    println!("  bytes consumed:   {}", pool.bytes_consumed);
    println!("  pickle streams:   {}", pool.stream_count);
    println!("  distinct strings: {}", pool.strings.len());
    println!("  distinct ints:    {}", pool.ints.len());
    println!("  globals:          {}", pool.globals.len());
    println!("  strings:          {:?}", pool.strings);
    println!("  ints:             {:?}", pool.ints);
    Ok(())
}

fn print_version(version: &disrobe_pass_nuitka::NuitkaVersionReport) {
    if let Some(exact) = &version.exact {
        println!(
            "  version:          {}.{}.{} {} ({:?})",
            exact.major, exact.minor, exact.micro, exact.release_level, version.confidence
        );
    } else {
        let era: &str = version.era_label.as_deref().unwrap_or("unknown");
        println!("  version:          {era} ({:?})", version.confidence);
    }
}
