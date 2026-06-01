#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_go::{GoAnalysis, analyze as analyze_go};

#[derive(Subcommand, Debug)]
pub(crate) enum GoCmd {
    #[command(
        about = "recover symbols, pclntab, moduledata, garble obfuscation report, & embed.FS contents from a Go PE / ELF / Mach-O"
    )]
    Recover {
        #[arg(help = "input Go binary")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the analysis JSON (default: ./out/<stem>-go.json)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "report Go build version, pclntab version, & stripped/garble fingerprint")]
    Info {
        #[arg(help = "input Go binary")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: GoCmd) -> miette::Result<()> {
    match action {
        GoCmd::Recover { input, out, emit } => recover(input, out, emit),
        GoCmd::Info { input } => info(input),
    }
}

fn recover(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0650: cannot read input: {e}"))?;
    let analysis: GoAnalysis =
        analyze_go(&bytes).map_err(|e| miette::miette!("DR-CLI-0651: go analyze: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("go-recover")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-go.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0652: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&analysis)
        .map_err(|e| miette::miette!("DR-CLI-0653: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0654: cannot write output: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    crate::cli::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem,
        "go-recover",
        "not implemented for the go pass in this build",
    )?;
    println!("go recover: OK");
    println!("  input:        {}", input.display());
    println!("  image kind:   {}", analysis.image_kind);
    println!("  ptr size:     {}", analysis.ptr_size);
    println!("  pclntab ver:  {}", analysis.pclntab_version);
    if let Some(v) = analysis.buildversion.as_ref() {
        println!("  buildversion: {v}");
    }
    println!("  funcs:        {}", analysis.symbols.funcs.len());
    println!("  packages:     {}", analysis.symbols.package_set.len());
    println!("  garble:       {:?}", analysis.garble.quality);
    println!(
        "  embed.FS:     used={} directives={}",
        analysis.embed.uses_embed_fs,
        analysis.embed.directives.len()
    );
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn info(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0660: cannot read input: {e}"))?;
    let analysis: GoAnalysis =
        analyze_go(&bytes).map_err(|e| miette::miette!("DR-CLI-0661: go analyze: {e}"))?;
    println!("go info: OK");
    println!("  input:        {}", input.display());
    println!("  image kind:   {}", analysis.image_kind);
    println!("  ptr size:     {}", analysis.ptr_size);
    println!("  pclntab ver:  {}", analysis.pclntab_version);
    if let Some(v) = analysis.buildversion.as_ref() {
        println!("  buildversion: {v}");
    }
    println!("  garble:       {:?}", analysis.garble.quality);
    println!(
        "  stripped:     stripped={} recovered_funcs={} stdlib_ratio={:.2}",
        analysis.stripped.stripped,
        analysis.stripped.recovered_funcs,
        analysis.stripped.stdlib_ratio
    );
    Ok(())
}
