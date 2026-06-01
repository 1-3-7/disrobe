#![allow(clippy::needless_pass_by_value)]

use std::path::PathBuf;

use clap::CommandFactory;

pub(crate) fn run<C: CommandFactory>(out: Option<PathBuf>) -> miette::Result<()> {
    let out_dir: PathBuf = out.unwrap_or_else(|| PathBuf::from("./man/man1"));
    std::fs::create_dir_all(&out_dir).map_err(|e| {
        miette::miette!(
            "DR-CLI-0130: cannot create man dir {}: {e}",
            out_dir.display()
        )
    })?;
    let cmd: clap::Command = C::command();
    let mut written: Vec<PathBuf> = Vec::new();
    render_command(&cmd, "disrobe", &out_dir, &mut written)?;
    println!("disrobe man: OK");
    println!("  out dir: {}", out_dir.display());
    println!("  pages:   {}", written.len());
    for p in &written {
        println!("    - {}", p.display());
    }
    Ok(())
}

fn render_command(
    cmd: &clap::Command,
    full_name: &str,
    out_dir: &std::path::Path,
    written: &mut Vec<PathBuf>,
) -> miette::Result<()> {
    let man: clap_mangen::Man = clap_mangen::Man::new(cmd.clone()).title(full_name.to_owned());
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    man.render(&mut buf)
        .map_err(|e| miette::miette!("DR-CLI-0131: render failed for {full_name}: {e}"))?;
    let filename: String = format!("{}.1", full_name.replace(' ', "-"));
    let path: PathBuf = out_dir.join(&filename);
    std::fs::write(&path, &buf)
        .map_err(|e| miette::miette!("DR-CLI-0132: cannot write {}: {e}", path.display()))?;
    written.push(path);
    for sub in cmd.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let sub_full: String = format!("{full_name}-{}", sub.get_name());
        render_command(sub, &sub_full, out_dir, written)?;
    }
    Ok(())
}
