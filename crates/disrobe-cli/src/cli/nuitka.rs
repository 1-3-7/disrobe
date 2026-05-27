#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub(crate) enum NuitkaCmd {
    #[command(
        about = "detect a Nuitka build flavor (--onefile, --standalone, --module, signed-PE, wheel) and report the Python version"
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
        about = "scan a Nuitka --standalone binary's symbol table for impl_* and module-init functions"
    )]
    Symbols {
        #[arg(help = "Nuitka binary to scan")]
        input: PathBuf,
        #[arg(short, long, help = "output path for the symbol graph JSON")]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: NuitkaCmd) -> miette::Result<()> {
    match action {
        NuitkaCmd::Detect { input } => detect(input),
        NuitkaCmd::Extract { input, out } => extract(input, out),
        NuitkaCmd::Symbols { input, out } => symbols(input, out),
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
    for entry in &payload.entries {
        let safe: String = entry
            .filename
            .replace(['/', '\\'], "_")
            .trim_start_matches('.')
            .to_owned();
        if safe.is_empty() {
            continue;
        }
        std::fs::write(out_dir.join(&safe), &entry.data)
            .map_err(|e| miette::miette!("DR-CLI-0019: cannot write {}: {e}", safe))?;
    }
    println!("nuitka extract: OK");
    println!("  flavor:        {:?}", det.flavor);
    println!("  entries:       {}", payload.entries.len());
    println!("  payload bytes: {}", payload.payload_size);
    println!("  out dir:       {}", out_dir.display());
    Ok(())
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
