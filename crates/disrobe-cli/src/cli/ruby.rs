#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_ruby::{Flavor, RubyAnalysis, analyze_bytes};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum RubyCmd {
    #[command(
        about = "analyze a Ruby artifact (MRI source / YARV binary / mruby RITE / JRuby class / TruffleRuby AOT / Ruby2Exe / Ocra)"
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
        #[arg(
            long,
            value_delimiter = ',',
            help = "comma-separated emit kinds: source, disasm, ast, cfg, ir, manifest, sourcemap, symbols, strings, imports, signatures, report"
        )]
        emit: Vec<String>,
    },
    #[command(about = "detect the Ruby flavor & exit (no output written)")]
    Detect {
        #[arg(help = "input Ruby file")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: RubyCmd) -> miette::Result<()> {
    match action {
        RubyCmd::Decompile { input, out, emit } => decompile(input, out, emit),
        RubyCmd::Detect { input } => detect(input),
    }
}

fn decompile(input: PathBuf, out: Option<PathBuf>, emit: Vec<String>) -> miette::Result<()> {
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
    let stub_dir: &std::path::Path = out_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let rb_path: PathBuf = out_path.with_extension("rb");
    let (rb_text, rb_kind): (Option<String>, &str) = render_decompiled_ruby(&analysis);
    if let Some(text) = rb_text.as_ref() {
        std::fs::write(&rb_path, text.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0605: cannot write decompiled ruby: {e}"))?;
    }
    super::emit::apply_not_applicable_stubs(
        &emit,
        stub_dir,
        &stem,
        "ruby-decompile",
        "not implemented for the ruby pass in this build",
    )?;
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
        println!("  yarv iseqs:   {}", yarv.ibf.iseq_offsets.len());
        println!("  yarv bodies:  {}", yarv.ibf.iseqs.len());
        println!("  yarv objects: {}", yarv.ibf.objects.len());
        println!("  yarv literals:{}", yarv.ibf.recovered_literal_count);
        println!("  yarv insns:   {}", yarv.ibf.recovered_instruction_count);
        println!("  yarv decomp:  {:?}", yarv.decompiled.fidelity);
        println!("  yarv stmts:   {}", yarv.decompiled.statement_count);
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        println!(
            "  mruby ver:    {}",
            String::from_utf8_lossy(&mruby.binary.header.compiler_version)
        );
        println!("  mruby irep:   {}", mruby.binary.irep_count);
        println!("  mruby insns:  {}", mruby.decompiled.instruction_count);
        println!("  mruby body:   {}", mruby.decompiled.has_body);
    }
    match (rb_text.as_ref(), rb_kind) {
        (Some(_), kind) => println!("  decompiled:   {} ({kind})", rb_path.display()),
        (None, kind) => println!("  decompiled:   none ({kind})"),
    }
    println!("  wrote:        {}", out_path.display());
    Ok(())
}

fn render_decompiled_ruby(analysis: &RubyAnalysis) -> (Option<String>, &'static str) {
    use core::fmt::Write as _;
    if let Some(yarv) = analysis.yarv.as_ref() {
        let mut out: String = String::new();
        out.push_str("# disrobe ruby yarv decompile (in-house IBF/ISeq recovery)\n");
        let _: core::result::Result<(), core::fmt::Error> = writeln!(
            out,
            "# fidelity: {:?} | statements: {}\n",
            yarv.decompiled.fidelity, yarv.decompiled.statement_count
        );
        out.push_str(&yarv.decompiled.source);
        if !yarv.disasm_text.is_empty() {
            out.push_str("\n# ---- yarv disassembly ----\n");
            for line in yarv.disasm_text.lines() {
                out.push_str("# ");
                out.push_str(line);
                out.push('\n');
            }
        }
        return (Some(out), "yarv");
    }
    if let Some(mruby) = analysis.mruby.as_ref() {
        return (Some(mruby.decompiled.source.clone()), "mruby");
    }
    (None, "no-bytecode-body")
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

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn decompile_writes_real_ruby_source_from_yarv() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("ruby")
            .join("mri")
            .join("yarv")
            .join("greeter.rb.yarvc");
        if !input.is_file() {
            return;
        }
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("ruby-decompile-test");
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).expect("mk out dir");
        let out_path: PathBuf = out_dir.join("greeter.json");

        decompile(input, Some(out_path.clone()), Vec::new()).expect("decompile ok");

        let rb_path: PathBuf = out_path.with_extension("rb");
        let rb: String = std::fs::read_to_string(&rb_path).expect("read decompiled rb");
        assert!(
            rb.contains("def greet") && rb.contains("def initialize"),
            "decompiled ruby must contain recovered method definitions: {rb}"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
