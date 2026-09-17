#![allow(clippy::needless_pass_by_value)]
use std::path::PathBuf;

use clap::Subcommand;

#[derive(Subcommand, Debug)]
pub(crate) enum PyfreezeCmd {
    #[command(
        about = "detect which Python freezer produced the input (cx_Freeze, py2exe, shiv, pex, PyOxidizer (experimental, unvalidated), Briefcase) without extracting"
    )]
    Detect {
        #[arg(help = "executable to inspect")]
        input: PathBuf,
    },
    #[command(
        about = "extract a cx_Freeze / py2exe / shiv / pex / PyOxidizer (experimental, unvalidated) / Briefcase container"
    )]
    Extract {
        #[arg(help = "executable to extract")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-extracted)"
        )]
        out: Option<PathBuf>,
    },
}

pub(crate) fn run(action: PyfreezeCmd) -> miette::Result<()> {
    match action {
        PyfreezeCmd::Detect { input } => detect(input),
        PyfreezeCmd::Extract { input, out } => extract(input, out),
    }
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let det: disrobe_pass_pyfreeze::Detection =
        disrobe_pass_pyfreeze::detect(&input).map_err(|e| miette::miette!("{e}"))?;
    println!("pyfreeze detect: OK");
    println!("  input:      {}", input.display());
    println!("  kind:       {}", human_kind(det.kind));
    println!("  confidence: {:.2}", det.confidence);
    for r in &det.reasons {
        println!("  reason:     {r}");
    }
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let out_dir: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("pyfreeze-out");
        PathBuf::from(format!("./out/{stem}-extracted"))
    });
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0060: cannot create out dir: {e}"))?;
    let result: disrobe_pass_pyfreeze::PyfreezeOutput =
        disrobe_pass_pyfreeze::extract(&input, &out_dir).map_err(|e| miette::miette!("{e}"))?;
    let manifest_path: PathBuf = out_dir.join("manifest.json");
    let manifest_bytes: Vec<u8> = serde_json::to_vec_pretty(&result.manifest)
        .map_err(|e| miette::miette!("DR-CLI-0062: manifest serialize: {e}"))?;
    std::fs::write(&manifest_path, &manifest_bytes)
        .map_err(|e| miette::miette!("DR-CLI-0061: cannot write manifest: {e}"))?;
    println!("pyfreeze extract: OK");
    println!("  input:           {}", input.display());
    println!("  kind:            {}", human_kind(result.detection.kind));
    println!("  entries:         {}", result.extracted_count);
    if !result.manifest.module_inventory.is_empty() {
        println!(
            "  modules named:   {}",
            result.manifest.module_inventory.len()
        );
        for entry in &result.manifest.module_inventory {
            let kind: &str = if entry.is_package { "pkg" } else { "mod" };
            let mut tiers: Vec<&str> = Vec::new();
            if entry.has_source {
                tiers.push("src");
            }
            if entry.has_bytecode {
                tiers.push("pyc");
            }
            if entry.has_bytecode_opt1 {
                tiers.push("pyc1");
            }
            if entry.has_bytecode_opt2 {
                tiers.push("pyc2");
            }
            if entry.has_extension {
                tiers.push("ext");
            }
            let tiers_str: String = if tiers.is_empty() {
                "name-only".to_owned()
            } else {
                tiers.join("+")
            };
            println!("    {kind} {} [{tiers_str}]", entry.name);
        }
    }
    if let Some(ref p) = result.manifest.primary_module {
        println!("  primary module:  {p}");
    }
    if let (Some(maj), Some(min)) = (result.manifest.python_major, result.manifest.python_minor) {
        println!("  python:          {maj}.{min}");
    }
    if let Some(ref hint) = result.manifest.interpreter_hint {
        println!("  shebang:         {hint}");
    }
    println!("  out dir:         {}", out_dir.display());
    println!("  manifest:        {}", manifest_path.display());
    Ok(())
}

fn human_kind(kind: disrobe_pass_pyfreeze::FreezerKind) -> String {
    match kind {
        disrobe_pass_pyfreeze::FreezerKind::PyOxidizer => {
            "PyOxidizer (experimental, unvalidated)".to_owned()
        }
        other => format!("{other:?}"),
    }
}
