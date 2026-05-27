#![allow(clippy::needless_pass_by_value)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_beam::{
    BeamFile, CoreModule, Disassembly, ErlangSurface, disassemble, lift as lift_core_erlang,
    recover_erlang,
};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum BeamCmd {
    #[command(
        about = "parse a .beam IFF chunk file and report its sections (AtU8, Code, ExpT, ImpT, FunT, Dbgi, Docs, LitT, ...)"
    )]
    Parse {
        #[arg(help = "input .beam file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the parse JSON (default: ./out/<stem>-beam.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "lift a .beam file to Core Erlang surface (best-effort)")]
    Lift {
        #[arg(help = "input .beam file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-beam-lift)"
        )]
        out: Option<PathBuf>,
    },
    #[command(about = "disassemble the Code chunk of a .beam file into per-instruction trace")]
    Disasm {
        #[arg(help = "input .beam file")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the disasm JSON (default: ./out/<stem>-beam.disasm.json)"
        )]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: BeamCmd) -> miette::Result<()> {
    match action {
        BeamCmd::Parse { input, out } => parse(input, out),
        BeamCmd::Lift { input, out } => lift(input, out),
        BeamCmd::Disasm { input, out } => disasm(input, out),
    }
}

fn parse(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0620: cannot read input: {e}"))?;
    let beam: BeamFile =
        BeamFile::parse(&bytes).map_err(|e| miette::miette!("DR-CLI-0621: beam parse: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("beam-parse")
        .to_owned();
    let out_path: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-beam.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0622: cannot create dir: {e}"))?;
    }
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.beam.parse/v0",
        "input": input.display().to_string(),
        "form_length": beam.form_length,
        "module_name": beam.module_name(),
        "atom_count": beam.chunks.atoms.atoms.len(),
        "export_count": beam.chunks.exports.len(),
        "import_count": beam.chunks.imports.len(),
        "local_count": beam.chunks.locals.len(),
        "fun_count": beam.chunks.funs.len(),
        "has_code": beam.chunks.code.is_some(),
        "has_attributes": beam.chunks.attributes.is_some(),
        "has_compile_info": beam.chunks.compile_info.is_some(),
        "has_dbgi": beam.chunks.dbgi.is_some(),
        "has_docs": beam.chunks.docs.is_some(),
        "has_literals": beam.chunks.literals.is_some(),
        "has_line": beam.chunks.line.is_some(),
        "other_chunks": beam.chunks.other.keys().collect::<Vec<_>>(),
    });
    std::fs::write(
        &out_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0623: cannot write output: {e}"))?;
    println!("beam parse: OK");
    println!("  input:        {}", input.display());
    println!(
        "  module:       {}",
        beam.module_name().unwrap_or("<unknown>")
    );
    println!("  atoms:        {}", beam.chunks.atoms.atoms.len());
    println!("  exports:      {}", beam.chunks.exports.len());
    println!("  imports:      {}", beam.chunks.imports.len());
    println!("  funs:         {}", beam.chunks.funs.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn lift(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0630: cannot read input: {e}"))?;
    let beam: BeamFile =
        BeamFile::parse(&bytes).map_err(|e| miette::miette!("DR-CLI-0631: beam parse: {e}"))?;
    let surface: ErlangSurface =
        recover_erlang(&beam).map_err(|e| miette::miette!("DR-CLI-0632: erlang recover: {e}"))?;
    let core: CoreModule = lift_core_erlang(&beam)
        .map_err(|e| miette::miette!("DR-CLI-0633: core erlang lift: {e}"))?;
    let g: globals::Globals = globals::current();
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("beam-lift")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-beam-lift")));
    if g.dry_run {
        println!("beam lift: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0634: cannot create dir: {e}"))?;
    let surface_path: PathBuf = out_dir.join(format!("{stem}.surface.json"));
    let core_path: PathBuf = out_dir.join(format!("{stem}.core.json"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    std::fs::write(
        &surface_path,
        serde_json::to_vec_pretty(&surface).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0635: cannot write surface: {e}"))?;
    std::fs::write(
        &core_path,
        serde_json::to_vec_pretty(&core).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0636: cannot write core: {e}"))?;
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.beam.lift/v0",
        "input": input.display().to_string(),
        "module_name": beam.module_name(),
        "surface_path": surface_path.display().to_string(),
        "core_path": core_path.display().to_string(),
        "core_functions": core.functions.len(),
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0637: cannot write manifest: {e}"))?;
    println!("beam lift: OK");
    println!("  input:        {}", input.display());
    println!(
        "  module:       {}",
        beam.module_name().unwrap_or("<unknown>")
    );
    println!("  core fns:     {}", core.functions.len());
    println!("  surface:      {}", surface_path.display());
    println!("  core erlang:  {}", core_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn disasm(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0640: cannot read input: {e}"))?;
    let beam: BeamFile =
        BeamFile::parse(&bytes).map_err(|e| miette::miette!("DR-CLI-0641: beam parse: {e}"))?;
    let code = beam
        .chunks
        .code
        .as_ref()
        .ok_or_else(|| miette::miette!("DR-CLI-0642: .beam file has no Code chunk"))?;
    let dis: Disassembly =
        disassemble(code).map_err(|e| miette::miette!("DR-CLI-0643: beam disasm: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("beam-disasm")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-beam.disasm.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0644: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&dis)
        .map_err(|e| miette::miette!("DR-CLI-0645: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0646: cannot write output: {e}"))?;
    println!("beam disasm: OK");
    println!("  input:        {}", input.display());
    println!("  instructions: {}", dis.instructions.len());
    println!("  wrote:        {}", out_path.display());
    Ok(())
}
