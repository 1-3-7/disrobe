#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_shell::{Detection, Dialect, decode_script_bytes, detect as detect_shell};

use super::globals;

#[derive(Subcommand, Debug)]
pub(crate) enum ShellCmd {
    #[command(
        about = "deobfuscate a PowerShell / Bash / Batch / VBA script (Invoke-Obfuscation, Invoke-Stealth, Bashfuscator, PowerHell, Chameleon, psobf, ...)"
    )]
    Deob {
        #[arg(help = "obfuscated shell / batch / VBA script")]
        input: Option<PathBuf>,
        #[arg(
            short,
            long,
            help = "output path for the deobfuscated source (default: ./out/<stem>.deob.<ext>)"
        )]
        out: Option<PathBuf>,
        #[arg(
            long,
            help = "list the obfuscators/protectors disrobe can detect for this pass, then exit"
        )]
        list: bool,
    },
    #[command(about = "detect the shell dialect & obfuscator family and report markers")]
    Detect {
        #[arg(help = "shell / batch / VBA script")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: ShellCmd) -> miette::Result<()> {
    match action {
        ShellCmd::Deob { input, out, list } => deob(input, out, list),
        ShellCmd::Detect { input } => detect(input),
    }
}

fn deob(input: Option<PathBuf>, out: Option<PathBuf>, list: bool) -> miette::Result<()> {
    if list {
        super::emit::print_obfuscator_catalog(
            &disrobe_pass_shell::chain_detector::ShellDetector,
            "disrobe shell deob <input.ps1> --out <output.ps1>",
        );
        return Ok(());
    }
    let Some(input): Option<PathBuf> = input else {
        return Err(miette::miette!(
            "DR-CLI-0590: shell deob needs an input file (or `--list` to show supported obfuscators)"
        ));
    };
    let raw: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0591: cannot read input: {e}"))?;
    let decoded: Option<String> = decode_script_bytes(&raw);
    let bytes: &[u8] = decoded.as_deref().map_or(raw.as_slice(), str::as_bytes);
    let detection: Detection = detect_shell(bytes);
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("shell deob: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  dialect:      {:?}", detection.dialect);
        println!("  family:       {:?}", detection.family);
        return Ok(());
    }

    let recovered: String = disrobe_pass_shell::chain_detector::recover_detected(&detection, bytes)
        .map_err(
            |refusal: disrobe_pass_shell::chain_detector::ShellRefusal| {
                miette::miette!("{}", refusal.into_error())
            },
        )?;
    let stem: String = input
        .file_stem()
        .and_then(OsStr::to_str)
        .unwrap_or("shell-deob")
        .to_owned();
    let ext: &str = dialect_ext(detection.dialect);
    let out_path: PathBuf =
        out.unwrap_or_else(|| PathBuf::from(format!("./out/{stem}.deob.{ext}")));
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| miette::miette!("DR-CLI-0592: cannot create dir: {e}"))?;
    }
    std::fs::write(&out_path, recovered.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0593: cannot write output: {e}"))?;
    let manifest_path: PathBuf = out_path.with_extension("manifest.json");
    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.shell.deob/v0",
        "input": input.display().to_string(),
        "dialect": format!("{:?}", detection.dialect),
        "family": format!("{:?}", detection.family),
        "confidence": detection.confidence,
        "markers": detection.markers,
    });
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&manifest)
        .map_err(|e| miette::miette!("DR-CLI-0595: serialize manifest: {e}"))?;
    std::fs::write(&manifest_path, manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0594: cannot write manifest: {e}"))?;

    println!("shell deob: OK");
    println!("  input:        {}", input.display());
    println!("  dialect:      {:?}", detection.dialect);
    println!("  family:       {:?}", detection.family);
    println!("  confidence:   {:.2}", detection.confidence);
    println!("  markers:      {:?}", detection.markers);
    println!("  wrote:        {}", out_path.display());
    println!("  manifest:     {}", manifest_path.display());
    Ok(())
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0596: cannot read input: {e}"))?;
    let detection: Detection = detect_shell(&bytes);
    println!("shell detect: OK");
    println!("  input:        {}", input.display());
    println!("  dialect:      {:?}", detection.dialect);
    println!("  family:       {:?}", detection.family);
    println!("  confidence:   {:.2}", detection.confidence);
    println!("  markers:      {:?}", detection.markers);
    Ok(())
}

const fn dialect_ext(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::PowerShell => "ps1",
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh | Dialect::Unknown => "sh",
        Dialect::Batch => "bat",
        Dialect::Vba => "bas",
        Dialect::Xlm => "xlm.txt",
        Dialect::Pdf => "txt",
        Dialect::Vbs | Dialect::Wsh => "vbs",
    }
}
