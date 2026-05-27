#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum RubyCmd {
    #[command(
        about = "analyze a Ruby artefact (MRI source / YARV binary / mruby RITE / JRuby class / TruffleRuby AOT / Ruby2Exe / Ocra)"
    )]
    Decompile {
        #[arg(help = "input Ruby file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the analysis JSON (default: ./out/<stem>-ruby.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "detect the Ruby flavor and exit (no output written)")]
    Detect {
        #[arg(help = "input Ruby file")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: RubyCmd) -> miette::Result<()> {
    match action {
        RubyCmd::Decompile { input, out } => decompile(input, out),
        RubyCmd::Detect { input } => detect(input),
    }
}

fn decompile(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0600: cannot read input: {e}"))?;
    let g: globals::Globals = globals::current();
    let source_path: String = input.display().to_string();
    let analysis: RubyAnalysis = analyze_bytes(&bytes, &source_path)
        .map_err(|e| miette::miette!("DR-CLI-0601: ruby analyze: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("ruby-decompile")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-ruby.json")));
    if g.dry_run {
        println!("ruby decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  flavor:       {:?}", analysis.flavor);
        return Ok(());
    }
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0602: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&analysis)
        .map_err(|e| miette::miette!("DR-CLI-0603: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0604: cannot write output: {e}"))?;
    println!("ruby decompile: OK");
    println!("  input:        {}", input.display());
    println!("  flavor:       {:?}", analysis.flavor);
    println!("  input bytes:  {}", analysis.input_len);
    if let Some(mri) = analysis.mri.as_ref() {
        println!("  mri tokens:   {}", mri.tokens.len());
        println!("  mri defs:     {}", mri.definitions.len());
    }
    if let Some(yarv) = analysis.yarv.as_ref() {
        println!(
            "  yarv header:  major={} minor={}",
            yarv.header.major, yarv.header.minor
        );
        println!("  yarv ops:     {}", yarv.disasm.instructions.len());
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        println!(
            "  mruby ver:    {}",
            String::from_utf8_lossy(&mruby.binary.header.compiler_version)
        );
        println!("  mruby irep:   {}", mruby.binary.irep_count);
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0610: cannot read input: {e}"))?;
    let source_path: String = input.display().to_string();
    let analysis: RubyAnalysis = analyze_bytes(&bytes, &source_path)
        .map_err(|e| miette::miette!("DR-CLI-0611: ruby detect: {e}"))?;
    println!("ruby detect: OK");
    println!("  input:        {}", input.display());
    println!("  flavor:       {:?}", analysis.flavor);
    println!("  input bytes:  {}", analysis.input_len);
    let _ = Flavor::MriSource;
    Ok(())
}
