#![allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
use std::ffi::OsStr;
use std::path::PathBuf;

use clap::Subcommand;

use disrobe_pass_shell::{
    Detection, Dialect, Family, ModuleStompReport, StompReport, StompVerdict, XlmRecovery,
    analyze_stomp, deobfuscate_batch, deobfuscate_vbs, detect as detect_shell, extract_from_bytes,
    format_identity, peel_indirection, recover_xlm, reverse_bashfuscator_auto, reverse_chameleon,
    reverse_compress, reverse_encoding, reverse_invoke_stealth, reverse_isesteroids,
    reverse_launcher, reverse_node_bash_obfuscate, reverse_powerhell, reverse_psobf,
    reverse_string, reverse_token,
};

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
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0591: cannot read input: {e}"))?;
    let detection: Detection = detect_shell(&bytes);
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("shell deob: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  dialect:      {:?}", detection.dialect);
        println!("  family:       {:?}", detection.family);
        return Ok(());
    }

    let recovered: String = recover_source(&detection, &bytes)?;
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

fn recover_source(detection: &Detection, bytes: &[u8]) -> miette::Result<String> {
    if detection.dialect == Dialect::Batch
        && let Ok(text) = std::str::from_utf8(bytes)
    {
        return Ok(deobfuscate_batch(text, &[]).output);
    }
    if detection.dialect == Dialect::Vba
        && let Some(rendered) = recover_vba(bytes)
    {
        return Ok(rendered);
    }
    if detection.dialect == Dialect::Xlm
        && let Some(rendered) = recover_xlm_text(bytes)
    {
        return Ok(rendered);
    }
    let text: &str = match std::str::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            return Ok(format!(
                "/* non-utf8 shell payload of {} bytes */",
                bytes.len()
            ));
        }
    };
    if matches!(detection.dialect, Dialect::Vbs | Dialect::Wsh) {
        return Ok(deobfuscate_vbs(text).output);
    }
    Ok(reverse_for_family(detection.family, text))
}

fn reverse_for_family(family: Family, text: &str) -> String {
    match family {
        Family::InvokeObfuscationToken => reverse_token(text).output,
        Family::InvokeObfuscationAst => disrobe_pass_shell::reverse_ast(text).output,
        Family::InvokeObfuscationString => reverse_string(text).output,
        Family::InvokeObfuscationEncoding => {
            reverse_encoding(text).map_or_else(|_| text.to_owned(), |r| r.output)
        }
        Family::InvokeObfuscationCompress => {
            reverse_compress(text).map_or_else(|_| text.to_owned(), |r| r.output)
        }
        Family::InvokeObfuscationLauncher => reverse_launcher(text).output,
        Family::InvokeStealth => reverse_invoke_stealth(text).output,
        Family::PowerHell => reverse_powerhell(text).map_or_else(|_| text.to_owned(), |r| r.output),
        Family::Chameleon => reverse_chameleon(text).output,
        Family::Psobf => reverse_psobf(text).map_or_else(|_| text.to_owned(), |r| r.output),
        Family::IseSteroids => reverse_isesteroids(text).output,
        Family::BashfuscatorToken
        | Family::BashfuscatorString
        | Family::BashfuscatorObfuscate
        | Family::BashfuscatorCompress => {
            reverse_bashfuscator_auto(text).map_or_else(|_| text.to_owned(), |r| r.output)
        }
        Family::BashIndirection => {
            peel_indirection(text).map_or_else(|_| text.to_owned(), |r| r.output)
        }
        Family::NodeBashObfuscate => {
            reverse_node_bash_obfuscate(text).map_or_else(|| text.to_owned(), |r| r.output)
        }
        Family::Plain
        | Family::Unknown
        | Family::BatchRandom
        | Family::BatchSetIndirection
        | Family::VbaMacro
        | Family::VbsWshObfuscated => format_identity(text),
    }
}

fn recover_vba(bytes: &[u8]) -> Option<String> {
    let mut modules: Vec<(String, String)> = extract_from_bytes(bytes)
        .map(|project: disrobe_pass_shell::ExtractedProject| {
            project
                .modules
                .into_iter()
                .filter(|m: &disrobe_pass_shell::ExtractedModule| {
                    !m.recovered_source.trim().is_empty()
                })
                .map(|m: disrobe_pass_shell::ExtractedModule| {
                    (m.name, m.recovered_source.replace("\r\n", "\n"))
                })
                .collect::<Vec<(String, String)>>()
        })
        .unwrap_or_default();
    for (name, source) in recover_vba_from_pcode(bytes) {
        match modules
            .iter_mut()
            .find(|(existing, _): &&mut (String, String)| existing.eq_ignore_ascii_case(&name))
        {
            Some(slot) => slot.1 = source,
            None => modules.push((name, source)),
        }
    }
    if modules.is_empty() {
        return None;
    }
    let mut out: String = String::new();
    for (name, source) in &modules {
        out.push_str("' ===== module: ");
        out.push_str(name);
        out.push_str(" =====\n");
        out.push_str(source.trim_end());
        out.push_str("\n\n");
    }
    out.truncate(out.trim_end().len());
    Some(out)
}

fn recover_vba_from_pcode(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(report): disrobe_pass_shell::Result<StompReport> = analyze_stomp(bytes) else {
        return Vec::new();
    };
    report
        .modules
        .into_iter()
        .filter(|m: &ModuleStompReport| {
            matches!(m.verdict, StompVerdict::Stomped | StompVerdict::PCodeOnly)
                && !m.recovered_source.trim().is_empty()
        })
        .map(|m: ModuleStompReport| (m.module, m.recovered_source.replace("\r\n", "\n")))
        .collect()
}

fn recover_xlm_text(bytes: &[u8]) -> Option<String> {
    let report: XlmRecovery = recover_xlm(bytes)?;
    if report.total_formulas() == 0 && report.entry_points.is_empty() {
        return None;
    }
    let mut out: String = String::new();
    for entry in &report.entry_points {
        out.push_str(&format!("' entry: {} -> {}\n", entry.name, entry.target));
    }
    for sheet in &report.sheets {
        out.push_str(&format!("' ===== {} sheet: {} =====\n", sheet.kind, sheet.name));
        for cell in &sheet.cells {
            out.push_str(&format!("{}!{}\t{}\n", sheet.name, cell.cell, cell.formula));
        }
    }
    out.truncate(out.trim_end().len());
    Some(out)
}

const fn dialect_ext(dialect: Dialect) -> &'static str {
    match dialect {
        Dialect::PowerShell => "ps1",
        Dialect::Bash | Dialect::Dash | Dialect::Ksh | Dialect::Zsh | Dialect::Unknown => "sh",
        Dialect::Batch => "bat",
        Dialect::Vba => "bas",
        Dialect::Xlm => "xlm.txt",
        Dialect::Vbs | Dialect::Wsh => "vbs",
    }
}
