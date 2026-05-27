#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use clap::Subcommand;
use disrobe_core::progress::Progress as _;

use super::globals;
use super::progress_ui;
use super::util::hex_bytes;

#[derive(Subcommand, Debug)]
pub(crate) enum PyinstallerCmd {
    #[command(
        about = "extract every entry from a PyInstaller onefile / onedir build (PyInstaller 2.1 .. 6.x, AES-CTR / CFB decrypt when keyed)"
    )]
    Extract {
        #[arg(help = "PyInstaller executable to extract")]
        input: PathBuf,
        #[arg(
            short,
            long,
            help = "output directory (default: ./out/<stem>-extracted)"
        )]
        out: Option<PathBuf>,
    },
    #[command(
        about = "detect a PyInstaller build and report its cookie, Python version, and TOC offsets without extracting"
    )]
    Detect {
        #[arg(help = "PyInstaller executable to inspect")]
        input: PathBuf,
    },
}

pub(crate) fn run(action: PyinstallerCmd) -> miette::Result<()> {
    match action {
        PyinstallerCmd::Extract { input, out } => extract(input, out),
        PyinstallerCmd::Detect { input } => detect(input),
    }
}

fn detect(input: PathBuf) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0011: cannot read input {}: {e}", input.display()))?;
    let cookie: disrobe_pass_pyinstaller::Cookie =
        disrobe_pass_pyinstaller::find_cookie(&bytes).map_err(|e| miette::miette!("{e}"))?;
    println!("pyinstaller detect: OK");
    println!("  variant:        {:?}", cookie.variant);
    println!(
        "  python:         {}.{}",
        cookie.python_major, cookie.python_minor
    );
    println!("  length_of_pkg:  {}", cookie.length_of_package);
    println!("  toc_offset:     {}", cookie.toc_offset);
    println!("  toc_length:     {}", cookie.toc_length);
    if let Some(ref lib) = cookie.python_libname {
        println!("  python_libname: {lib}");
    }
    Ok(())
}

fn extract(input: PathBuf, out: Option<PathBuf>) -> miette::Result<()> {
    let bytes: Vec<u8> = std::fs::read(&input)
        .map_err(|e| miette::miette!("DR-CLI-0012: cannot read input {}: {e}", input.display()))?;
    let g: globals::Globals = globals::current();
    if g.dry_run {
        println!("disrobe pyinstaller extract: DRY-RUN");
        println!("  input:        {}", input.display());
        println!("  would extract: {} bytes", bytes.len());
        return Ok(());
    }
    let result: disrobe_pass_pyinstaller::ExtractOutput =
        disrobe_pass_pyinstaller::extract_archive(&bytes).map_err(|e| miette::miette!("{e}"))?;
    let out_dir: PathBuf = out.unwrap_or_else(|| {
        let stem: &str = input
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("pyinst-out");
        PathBuf::from(format!("./out/{stem}-extracted"))
    });
    if out_dir.exists() && !g.force {
        let has_entries: bool = std::fs::read_dir(&out_dir).is_ok_and(|mut it| it.next().is_some());
        if has_entries {
            return Err(miette::miette!(
                "DR-CLI-0031: out dir {} already exists; pass --force to overwrite",
                out_dir.display()
            ));
        }
    }
    std::fs::create_dir_all(&out_dir)
        .map_err(|e| miette::miette!("DR-CLI-0013: cannot create out dir: {e}"))?;

    let bar: progress_ui::ActiveProgress = progress_ui::make_progress("pyinstaller extract");
    let total: u64 = u64::try_from(result.entries.len()).unwrap_or(u64::MAX);
    bar.set_total(total);
    bar.set_message("writing TOC entries");

    let manifest: serde_json::Value = serde_json::json!({
        "schema": "disrobe.pyinstaller.manifest/v0",
        "input": input.display().to_string(),
        "python": format!("{}.{}", result.cookie.python_major, result.cookie.python_minor),
        "variant": format!("{:?}", result.cookie.variant),
        "encryption_key_hex": result.encryption_key.map(hex_bytes),
        "entries": result.entries.iter().map(|e| serde_json::json!({
            "name": e.toc.name,
            "type": format!("{:?}", e.toc.entry_type),
            "compressed_size": e.toc.compressed_size,
            "uncompressed_size": e.toc.uncompressed_size,
            "data_size": e.data.len(),
            "decrypted": e.decrypted,
        })).collect::<Vec<_>>(),
    });
    std::fs::write(
        out_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&manifest).unwrap_or_default(),
    )
    .map_err(|e| miette::miette!("DR-CLI-0014: cannot write manifest: {e}"))?;

    for entry in &result.entries {
        let safe_name: String = entry
            .toc
            .name
            .replace(['/', '\\'], "_")
            .trim_start_matches('.')
            .to_owned();
        if safe_name.is_empty() {
            bar.tick();
            continue;
        }
        let suffix: &'static str = if entry.toc.entry_type.is_pyc_carrier() {
            ".pyc"
        } else {
            ""
        };
        let path: PathBuf = out_dir.join(format!("{safe_name}{suffix}"));
        std::fs::write(&path, &entry.data).map_err(|e| {
            miette::miette!("DR-CLI-0015: cannot write entry {}: {e}", path.display())
        })?;
        bar.tick();
    }
    bar.finish("done");

    println!("pyinstaller extract: OK");
    println!("  input:        {}", input.display());
    println!(
        "  python:       {}.{}",
        result.cookie.python_major, result.cookie.python_minor
    );
    println!("  entries:      {}", result.entries.len());
    println!("  encrypted:    {}", result.encryption_key.is_some());
    println!("  out dir:      {}", out_dir.display());
    Ok(())
}
