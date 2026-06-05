#![allow(clippy::needless_pass_by_value)]

use std::io::Write as _;
use std::path::PathBuf;

use clap::CommandFactory;
use clap_complete::Shell;

const INSTALL_MARKER: &str = "# >>> disrobe completions >>>";
const INSTALL_END: &str = "# <<< disrobe completions <<<";

pub(crate) fn run<C: CommandFactory>(
    shell: Shell,
    install: bool,
    rc_override: Option<PathBuf>,
) -> miette::Result<()> {
    let mut cmd: clap::Command = C::command();
    if install {
        return install_to_rc(shell, rc_override);
    }
    clap_complete::generate(shell, &mut cmd, "disrobe", &mut std::io::stdout());
    Ok(())
}

fn install_to_rc(shell: Shell, rc_override: Option<PathBuf>) -> miette::Result<()> {
    let rc_path: PathBuf = match rc_override {
        Some(p) => p,
        None => default_rc_for_shell(shell).ok_or_else(|| {
            miette::miette!(
                "DR-CLI-0140: cannot locate rc file for {shell:?}; pass `--rc-file <path>`"
            )
        })?,
    };
    if let Some(parent) = rc_path.parent() {
        let _: std::io::Result<()> = std::fs::create_dir_all(parent);
    }
    let existing: String = std::fs::read_to_string(&rc_path).unwrap_or_default();
    if existing.contains(INSTALL_MARKER) {
        println!(
            "disrobe completions install: already present in {}",
            rc_path.display()
        );
        return Ok(());
    }
    let snippet: String = snippet_for_shell(shell);
    let mut file: std::fs::File = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&rc_path)
        .map_err(|e| miette::miette!("DR-CLI-0141: cannot open {}: {e}", rc_path.display()))?;
    let block: String = format!("\n{INSTALL_MARKER}\n{snippet}\n{INSTALL_END}\n");
    file.write_all(block.as_bytes())
        .map_err(|e| miette::miette!("DR-CLI-0141: cannot append to {}: {e}", rc_path.display()))?;
    println!("disrobe completions install: OK");
    println!("  shell:   {shell:?}");
    println!("  rc file: {}", rc_path.display());
    println!(
        "  re-source your rc (e.g. `source {}`) to activate",
        rc_path.display()
    );
    Ok(())
}

fn default_rc_for_shell(shell: Shell) -> Option<PathBuf> {
    let home: PathBuf = home_dir()?;
    match shell {
        Shell::Bash => Some(home.join(".bashrc")),
        Shell::Zsh => Some(home.join(".zshrc")),
        Shell::Fish => Some(home.join(".config/fish/config.fish")),
        Shell::PowerShell => powershell_profile(),
        Shell::Elvish => Some(home.join(".elvish/rc.elv")),
        _ => None,
    }
}

fn powershell_profile() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("PROFILE") {
        return Some(PathBuf::from(p));
    }
    let docs: PathBuf = std::env::var_os("USERPROFILE")
        .map(PathBuf::from)?
        .join("Documents")
        .join("PowerShell")
        .join("Microsoft.PowerShell_profile.ps1");
    Some(docs)
}

fn snippet_for_shell(shell: Shell) -> String {
    match shell {
        Shell::Bash => "source <(disrobe completions bash)".to_owned(),
        Shell::Zsh => "source <(disrobe completions zsh)".to_owned(),
        Shell::Fish => "disrobe completions fish | source".to_owned(),
        Shell::PowerShell => {
            "disrobe completions powershell | Out-String | Invoke-Expression".to_owned()
        }
        Shell::Elvish => "eval (disrobe completions elvish | slurp)".to_owned(),
        _ => format!("# disrobe completions for {shell:?} unsupported"),
    }
}

fn home_dir() -> Option<PathBuf> {
    if cfg!(windows) {
        std::env::var_os("USERPROFILE").map(PathBuf::from)
    } else {
        std::env::var_os("HOME").map(PathBuf::from)
    }
}
