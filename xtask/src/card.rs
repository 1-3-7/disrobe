use std::path::Path;
use std::process::{Command, ExitStatus};

use eyre::{Result, WrapErr, bail};

pub(crate) fn run(root: &Path, check: bool) -> Result<()> {
    let mut command: Command = Command::new("node");
    command.current_dir(root).arg("xtask/graphgen/brand.mjs");
    if check {
        command.arg("--check");
    }
    let status: ExitStatus = command
        .status()
        .wrap_err("running brand renderer; install Node.js and graphgen dependencies first")?;
    if !status.success() {
        bail!("brand renderer failed with {status}; inspect its artifact or contrast diagnostic");
    }
    Ok(())
}
