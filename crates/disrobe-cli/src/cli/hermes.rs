#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_mobile::{
    DecompileReport, DisassemblyReport, HermesModule, decompile_hermes_module, disassemble_hermes,
    parse_hermes_module,
};

use super::emit::EmitSpec;
use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum HermesCmd {
    #[command(
        about = "lift a React Native Hermes bundle (.hbc / index.android.bundle) back to a JavaScript surface"
    )]
    Decompile {
        #[arg(help = "input Hermes bundle (.hbc / index.android.bundle)")]
        input: PathBuf,
        #[arg(short, long, help = "output directory (default: ./out/<stem>-hermes)")]
        out: Option<PathBuf>,
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "disassemble a Hermes bundle into a per-function summary (no JS surface)")]
    Disasm {
        #[arg(help = "input Hermes bundle")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output path for the disasm JSON (default: ./out/<stem>-hermes.disasm.json)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "parse the Hermes header and report version, function count, string/identifier counts"
    )]
    Info {
        #[arg(help = "input Hermes bundle")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: HermesCmd) -> miette::Result<()> {
    match action {
        HermesCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        HermesCmd::Disasm { input, out } => disasm(input, out),
        HermesCmd::Info { input } => info(input),
    }
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit_kinds: Vec<String>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0450: cannot read input: {e}"))?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("hermes-decompile")
        .to_owned();
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-hermes")));
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("hermes decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        return Ok(());
    }
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0451: hermes parse: {e}"))?;
    let report: DecompileReport = decompile_hermes_module(&module);

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0452: cannot create out dir: {e}"))?;
    let source_path: PathBuf = out_dir.join(format!("{stem}.js"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let source: String = render_decompiled_source(&module, &report);
    std::fs::write(&source_path, source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0453: cannot write lifted source: {e}"))?;

    let if_funcs: usize = report.functions.iter().filter(|f| f.has_if).count();
    let loop_funcs: usize = report.functions.iter().filter(|f| f.has_loop).count();
    let try_funcs: usize = report.functions.iter().filter(|f| f.has_try_catch).count();
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.hermes.decompile/v1",
        "input": input.display().to_string(),
        "hermes_version": module.header.version,
        "function_count": module.functions.len(),
        "functions_with_body": report.functions_with_body,
        "identifier_count": module.identifiers.len(),
        "string_count": module.strings.len(),
        "reconstructed_ops": report.total_reconstructed_ops,
        "fallback_ops": report.total_fallback_ops,
        "functions_with_if": if_funcs,
        "functions_with_loop": loop_funcs,
        "functions_with_try_catch": try_funcs,
        "raw_bytecode_size": module.raw_bytecode_size,
        "source_path": source_path.display().to_string(),
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0455: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0454: cannot write manifest: {e}"))?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "hermes-decompile")?;

    let total_ops: usize = report.total_reconstructed_ops + report.total_fallback_ops;
    let coverage: f64 = if total_ops == 0 {
        0.0
    } else {
        (report.total_reconstructed_ops as f64 / total_ops as f64) * 100.0
    };
    println!("hermes decompile: OK");
    println!("  input:        {}", input.display());
    println!("  hermes ver:   {}", module.header.version);
    println!("  functions:    {}", module.functions.len());
    println!("  with body:    {}", report.functions_with_body);
    println!("  identifiers:  {}", module.identifiers.len());
    println!("  strings:      {}", module.strings.len());
    println!(
        "  opcode cov:   {:.1}% ({} reconstructed / {} fallback)",
        coverage, report.total_reconstructed_ops, report.total_fallback_ops
    );
    println!("  if/loop/try:  {if_funcs}/{loop_funcs}/{try_funcs}");
    println!("  source:       {}", source_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn disasm(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0460: cannot read input: {e}"))?;
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0461: hermes parse: {e}"))?;
    let report: DisassemblyReport = disassemble_hermes(&module);
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("hermes-disasm")
        .to_owned();
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-hermes.disasm.json")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0462: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&report)
        .map_err(|e| miette::miette!("DR-CLI-0463: serialize: {e}"))?;
    std::fs::write(&out_path, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0464: cannot write output: {e}"))?;
    println!("hermes disasm: OK");
    println!("  input:        {}", input.display());
    println!("  functions:    {}", report.function_count);
    println!("  identifiers:  {}", report.identifier_count);
    println!("  strings:      {}", report.string_count);
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn info(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0470: cannot read input: {e}"))?;
    let module: HermesModule = parse_hermes_module(&bytes)
        .map_err(|e| miette::miette!("DR-CLI-0471: hermes parse: {e}"))?;
    println!("hermes info: OK");
    println!("  input:           {}", input.display());
    println!("  hermes ver:      {}", module.header.version);
    println!("  function count:  {}", module.header.function_count);
    println!("  string count:    {}", module.header.string_count);
    println!("  identifier ct:   {}", module.header.identifier_count);
    println!("  bytecode size:   {} bytes", module.raw_bytecode_size);
    println!("  file length:     {}", module.header.file_length);
    Ok(())
}

fn render_decompiled_source(module: &HermesModule, report: &DecompileReport) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(report.functions.len() * 160 + 256);
    out.push_str("// disrobe hermes decompile: reconstructed pseudo-JavaScript.\n");
    out.push_str(
        "// register-VM lifting; unreconstructed opcodes shown in <Opcode>(args) disasm form.\n",
    );
    let _ = writeln!(
        out,
        "// hermes_version={}, functions={}, identifiers={}, strings={}\n",
        module.header.version,
        module.functions.len(),
        module.identifiers.len(),
        module.strings.len()
    );
    for f in &report.functions {
        let _ = writeln!(
            out,
            "// fn #{} blocks={} ops={}r/{}f{}{}{}",
            f.index,
            f.block_count,
            f.reconstructed_ops,
            f.fallback_ops,
            if f.has_if { " if" } else { "" },
            if f.has_loop { " loop" } else { "" },
            if f.has_try_catch { " try" } else { "" },
        );
        out.push_str(&f.source);
        out.push_str("\n\n");
    }
    out
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds)?;
    if spec.is_empty() {
        return Ok(());
    }
    for kind in spec.iter() {
        let _: PathBuf = super::emit::write_not_applicable_stub(
            out_dir,
            stem,
            pass,
            kind,
            "not implemented for the hermes pass in this build",
        )?;
    }
    Ok(())
}
