#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]

use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_mobile::{
    DisassemblyReport, HermesModule, JsLiftReport, disassemble_hermes, hermes_lift_to_js_surface,
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
    let lift: JsLiftReport = hermes_lift_to_js_surface(&module);

    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0452: cannot create out dir: {e}"))?;
    let source_path: PathBuf = out_dir.join(format!("{stem}.js"));
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let source: String = render_lifted_surface(&module, &lift);
    std::fs::write(&source_path, source.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0453: cannot write lifted source: {e}"))?;

    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.hermes.decompile/v0",
        "input": input.display().to_string(),
        "hermes_version": module.header.version,
        "function_count": module.functions.len(),
        "identifier_count": module.identifiers.len(),
        "string_count": module.strings.len(),
        "lifted_functions": lift.function_surface.len(),
        "raw_bytecode_size": module.raw_bytecode_size,
        "source_path": source_path.display().to_string(),
    });
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0454: cannot write manifest: {e}"))?;

    apply_emit_stubs(&emit_kinds, &out_dir, &stem, "hermes-decompile")?;

    println!("hermes decompile: OK");
    println!("  input:        {}", input.display());
    println!("  hermes ver:   {}", module.header.version);
    println!("  functions:    {}", module.functions.len());
    println!("  identifiers:  {}", module.identifiers.len());
    println!("  strings:      {}", module.strings.len());
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

fn render_lifted_surface(module: &HermesModule, lift: &JsLiftReport) -> String {
    use std::fmt::Write as _;
    let mut out: String = String::with_capacity(lift.function_surface.len() * 80 + 128);
    out.push_str(
        "// disrobe hermes decompile: surface only — bytecode bodies are not yet lifted.\n",
    );
    let _ = writeln!(
        out,
        "// hermes_version={}, functions={}, identifiers={}, strings={}\n",
        module.header.version,
        module.functions.len(),
        module.identifiers.len(),
        module.strings.len()
    );
    for line in &lift.function_surface {
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn apply_emit_stubs(
    emit_kinds: &[String],
    out_dir: &std::path::Path,
    stem: &str,
    pass: &'static str,
) -> miette::Result<()> {
    let spec: EmitSpec = EmitSpec::parse(emit_kinds);
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
