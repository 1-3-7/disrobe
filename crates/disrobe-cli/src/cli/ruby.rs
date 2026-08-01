#![allow(clippy::needless_pass_by_value)]
use std::ffi::OsStr;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

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

struct RubyOutputPaths {
    analysis_json: PathBuf,
    recovered_source: PathBuf,
}

impl RubyOutputPaths {
    fn from_analysis_json(analysis_json: PathBuf) -> miette::Result<Self> {
        if analysis_json
            .extension()
            .and_then(OsStr::to_str)
            .is_some_and(|extension: &str| extension.eq_ignore_ascii_case("rb"))
        {
            return Err(miette::miette!(
                "DR-CLI-0606: analysis output cannot use the .rb source extension"
            ));
        }
        let recovered_source: PathBuf = analysis_json.with_extension("rb");
        Ok(Self {
            analysis_json,
            recovered_source,
        })
    }
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
    let output_paths: RubyOutputPaths = RubyOutputPaths::from_analysis_json(
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}-ruby.json"))),
    )?;
    if g.dry_run {
        println!("ruby decompile: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  flavor:       {:?}", analysis.flavor);
        return Ok(());
    }
    if let Some(parent) = output_paths.analysis_json.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0602: cannot create dir: {e}"))?;
    }
    let bytes_out: Vec<u8> = serde_json::to_vec_pretty(&analysis)
        .map_err(|e| miette::miette!("DR-CLI-0603: serialize: {e}"))?;
    std::fs::write(&output_paths.analysis_json, bytes_out)
        .map_err(|e| miette::miette!("DR-CLI-0604: cannot write output: {e}"))?;
    let stub_dir: &Path = output_paths
        .analysis_json
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let (rb_text, rb_kind): (Option<String>, &str) = render_decompiled_ruby(&analysis);
    if let Some(text) = rb_text.as_ref() {
        std::fs::write(&output_paths.recovered_source, text.as_bytes())
            .map_err(|e| miette::miette!("DR-CLI-0605: cannot write decompiled ruby: {e}"))?;
    } else {
        match std::fs::remove_file(&output_paths.recovered_source) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => {
                return Err(miette::miette!(
                    "DR-CLI-0605: cannot remove stale decompiled ruby: {error}"
                ));
            }
        }
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
        (Some(_), kind) => println!(
            "  decompiled:   {} ({kind})",
            output_paths.recovered_source.display()
        ),
        (None, kind) => println!("  decompiled:   none ({kind})"),
    }
    println!("  wrote:        {}", output_paths.analysis_json.display());
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
        if mruby.decompiled.has_body {
            return (Some(mruby.decompiled.source.clone()), "mruby");
        }
        return (None, "mruby");
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

    #[test]
    fn render_withholds_incomplete_mruby_source() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("ruby")
            .join("mruby")
            .join("breadth")
            .join("exceptions.mrb");
        let bytes: Vec<u8> = std::fs::read(&input)
            .unwrap_or_else(|error: std::io::Error| panic!("read {}: {error}", input.display()));
        let analysis: RubyAnalysis = analyze_bytes(&bytes, "exceptions.mrb").expect("analyze");
        let (source, kind): (Option<String>, &str) = render_decompiled_ruby(&analysis);
        assert_eq!(kind, "mruby");
        assert!(
            source.is_none(),
            "partial mruby recovery must not write a source file"
        );
    }

    #[test]
    fn decompile_removes_stale_source_when_mruby_recovery_is_withheld() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("ruby")
            .join("mruby")
            .join("breadth")
            .join("exceptions.mrb");
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("ruby-decompile-stale-source-test");
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).expect("mk out dir");
        let out_path: PathBuf = out_dir.join("exceptions.json");
        let rb_path: PathBuf = out_path.with_extension("rb");
        std::fs::write(&rb_path, b"puts 'stale'\n").expect("write stale ruby");

        decompile(input, Some(out_path.clone()), Vec::new()).expect("decompile ok");

        assert!(out_path.is_file(), "analysis JSON must still be written");
        assert!(
            !rb_path.exists(),
            "an abstaining rerun must remove the exact stale sibling source file"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }

    #[test]
    fn decompile_rejects_ruby_extension_for_analysis_output() {
        let input: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("corpus")
            .join("ruby")
            .join("mruby")
            .join("breadth")
            .join("exceptions.mrb");
        let out_dir: PathBuf = std::env::current_dir()
            .expect("cwd")
            .join("tmp")
            .join("ruby-decompile-output-collision-test");
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).expect("mk out dir");
        let out_path: PathBuf = out_dir.join("analysis.RB");

        let error: miette::Report = decompile(input, Some(out_path.clone()), Vec::new())
            .expect_err("a Ruby source extension cannot hold analysis JSON");

        assert!(error.to_string().contains("DR-CLI-0606"));
        assert!(
            !out_path.exists(),
            "preflight must not write analysis output"
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}
