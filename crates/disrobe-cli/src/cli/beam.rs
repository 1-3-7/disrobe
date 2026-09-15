#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_beam::{
    BeamFile, CoreModule, Disassembly, ErlangSurface, disassemble, lift as lift_core_erlang,
    recover_erlang,
};

use super::globals;
use super::util::push_format;

#[derive(Subcommand, Debug)]
pub(crate) enum BeamCmd {
    #[command(
        about = "parse a .beam IFF chunk file & report its sections (AtU8, Code, ExpT, ImpT, FunT, Dbgi, Docs, LitT, ...)"
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
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
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
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
}

pub(crate) fn run(action: BeamCmd) -> miette::Result<()> {
    match action {
        BeamCmd::Parse { input, out } => parse(input, out),
        BeamCmd::Lift { input, out, emit } => lift(input, out, emit),
        BeamCmd::Disasm { input, out, emit } => disasm(input, out, emit),
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
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0647: serialize manifest: {e}"))?;
    std::fs::write(&out_path, manifest_bytes)
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

fn lift(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
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
    let source_ext: &str = match surface.recovered_from {
        disrobe_pass_beam::RecoverySource::ElixirDbgiForm => "ex",
        disrobe_pass_beam::RecoverySource::AbstractCode
        | disrobe_pass_beam::RecoverySource::CoreLifted => "erl",
    };
    let erl_path: PathBuf = out_dir.join(format!("{stem}.{source_ext}"));
    let surface_path: PathBuf = out_dir.join(format!("{stem}.surface.json"));
    let core_path: PathBuf = out_dir.join(format!("{stem}.core.json"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let erl_source: String = if surface.source.ends_with('\n') {
        surface.source.clone()
    } else {
        format!("{}\n", surface.source)
    };
    std::fs::write(&erl_path, erl_source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0650: cannot write erlang source: {e}"))?;
    let surface_bytes: Vec<u8> = serde_json::to_vec_pretty(&surface)
        .map_err(|e| miette::miette!("DR-CLI-0648: serialize surface: {e}"))?;
    std::fs::write(&surface_path, surface_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0635: cannot write surface: {e}"))?;
    let core_bytes: Vec<u8> = serde_json::to_vec_pretty(&core)
        .map_err(|e| miette::miette!("DR-CLI-0649: serialize core: {e}"))?;
    std::fs::write(&core_path, core_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0636: cannot write core: {e}"))?;
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.beam.lift/v0",
        "input": input.display().to_string(),
        "module_name": beam.module_name(),
        "erl_path": erl_path.display().to_string(),
        "recovered_from": format!("{:?}", surface.recovered_from),
        "surface_path": surface_path.display().to_string(),
        "core_path": core_path.display().to_string(),
        "core_functions": core.functions.len(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0625: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0637: cannot write manifest: {e}"))?;
    super::emit::apply_not_applicable_stubs(
        &emit,
        &out_dir,
        &stem,
        "beam-lift",
        "not implemented for the beam pass in this build",
    )?;
    println!("beam lift: OK");
    println!("  input:        {}", input.display());
    println!(
        "  module:       {}",
        beam.module_name().unwrap_or("<unknown>")
    );
    println!("  core fns:     {}", core.functions.len());
    println!("  recovered:    {:?}", surface.recovered_from);
    println!("  source:       {}", erl_path.display());
    println!("  surface:      {}", surface_path.display());
    println!("  core erlang:  {}", core_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn disasm(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0640: cannot read input: {e}"))?;
    let beam: BeamFile =
        BeamFile::parse(&bytes).map_err(|e| miette::miette!("DR-CLI-0641: beam parse: {e}"))?;
    let code: &disrobe_pass_beam::CodeChunk = beam
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
    let listing_path: PathBuf = out_path.with_extension("txt");
    let listing: String = render_disasm_listing(&dis);
    std::fs::write(&listing_path, listing.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0651: cannot write disasm listing: {e}"))?;
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    super::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem,
        "beam-disasm",
        "not implemented for the beam pass in this build",
    )?;
    println!("beam disasm: OK");
    println!("  input:        {}", input.display());
    println!("  instructions: {}", dis.instructions.len());
    println!("  wrote:        {}", out_path.display());
    println!("  listing:      {}", listing_path.display());
    Ok(())
}

fn render_disasm_listing(dis: &Disassembly) -> String {
    let mut out: String = String::with_capacity(dis.instructions.len() * 48);
    for ins in &dis.instructions {
        let disrobe_pass_beam::Instruction {
            offset,
            opcode,
            name,
            operands,
        } = ins;
        if operands.is_empty() {
            push_format(
                &mut out,
                format_args!("{offset:08x}: {name:<24} ; op={opcode}\n"),
            );
        } else {
            let rendered: Vec<String> = operands.iter().map(|o| format!("{o:?}")).collect();
            push_format(
                &mut out,
                format_args!(
                    "{offset:08x}: {name:<24} {} ; op={opcode}\n",
                    rendered.join(", ")
                ),
            );
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use disrobe_pass_beam::{EzArchive, EzEntry};

    fn extract_beam(scratch: &std::path::Path) -> Option<PathBuf> {
        let ez_path: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("beam")
            .join("megafile")
            .join("edge_cases.ez");
        if !ez_path.is_file() {
            return None;
        }
        let bytes: Vec<u8> = std::fs::read(&ez_path).expect("read ez");
        let archive: EzArchive = EzArchive::parse(&bytes).expect("parse ez");
        let entry: &EzEntry = archive
            .beam_files()
            .into_iter()
            .find(|e: &&EzEntry| {
                std::path::Path::new(&e.path)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("beam"))
            })
            .expect("a .beam inside the ez");
        let beam_path: PathBuf = scratch.join("edge_cases.beam");
        std::fs::write(&beam_path, &entry.data).expect("write beam");
        Some(beam_path)
    }

    #[test]
    fn lift_writes_real_erlang_source_text() {
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("beam-lift-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let Some(beam_path): Option<PathBuf> = extract_beam(&scratch) else {
            return;
        };
        let out_dir: PathBuf = scratch.join("lift");

        lift(beam_path, Some(out_dir.clone()), Vec::new()).expect("lift ok");

        let source_path: PathBuf = ["erl", "ex"]
            .iter()
            .map(|ext: &&str| out_dir.join(format!("edge_cases.{ext}")))
            .find(|p: &PathBuf| p.is_file())
            .expect("a recovered .erl or .ex source must land");
        let source: String = std::fs::read_to_string(&source_path).expect("read source");
        assert!(
            source.contains("-module(") || source.contains("defmodule "),
            "recovered source must contain a real module declaration: {source}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }

    #[test]
    fn disasm_writes_flat_text_listing_next_to_json() {
        let scratch: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("beam-disasm-test");
        let _ = std::fs::remove_dir_all(&scratch);
        std::fs::create_dir_all(&scratch).expect("mk scratch");
        let Some(beam_path): Option<PathBuf> = extract_beam(&scratch) else {
            return;
        };
        let out_path: PathBuf = scratch.join("edge_cases-beam.disasm.json");

        disasm(beam_path, Some(out_path.clone()), Vec::new()).expect("disasm ok");

        assert!(out_path.is_file(), "disasm json must land");
        let listing_path: PathBuf = out_path.with_extension("txt");
        assert!(
            listing_path.is_file(),
            "a flat .txt disasm listing must land next to the json"
        );
        let listing: String = std::fs::read_to_string(&listing_path).expect("read listing");
        assert!(
            !listing.trim().is_empty() && listing.contains("; op="),
            "flat disasm must contain real instruction lines: {listing}"
        );
        let _ = std::fs::remove_dir_all(&scratch);
    }
}
