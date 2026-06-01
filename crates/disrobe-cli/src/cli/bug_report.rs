#![allow(clippy::needless_pass_by_value)]

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

pub(crate) fn run(out: Option<PathBuf>) -> miette::Result<()> {
    let report: String = build_report();
    match out.as_deref() {
        Some(p) if p == std::path::Path::new("-") => {
            print!("{report}");
            return Ok(());
        }
        Some(p) => {
            std::fs::write(p, report.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0120: cannot write bug report: {e}"))?;
            println!("disrobe bug-report: OK");
            println!("  wrote: {}", p.display());
            println!(
                "  open an issue at https://github.com/1-3-7/disrobe/issues and attach the report"
            );
        }
        None => {
            let pid: u32 = std::process::id();
            let path: PathBuf = std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(format!("disrobe-bug-report-pid{pid}.md"));
            std::fs::write(&path, report.as_bytes())
                .map_err(|e| miette::miette!("DR-CLI-0120: cannot write bug report: {e}"))?;
            println!("disrobe bug-report: OK");
            println!("  wrote: {}", path.display());
            println!(
                "  open an issue at https://github.com/1-3-7/disrobe/issues and attach the report"
            );
        }
    }
    Ok(())
}

fn build_report() -> String {
    let mut s: String = String::with_capacity(4096);
    let _: core::fmt::Result = writeln!(s, "# disrobe bug report");
    let _: core::fmt::Result = writeln!(s);
    let _: core::fmt::Result = writeln!(s, "## environment");
    let _: core::fmt::Result = writeln!(s);
    let _: core::fmt::Result = writeln!(s, "- disrobe: {}", env!("CARGO_PKG_VERSION"));
    let _: core::fmt::Result = writeln!(
        s,
        "- os: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );
    let _: core::fmt::Result = writeln!(
        s,
        "- cwd: {}",
        std::env::current_dir().map_or_else(|_| "?".to_owned(), |p| p.display().to_string())
    );
    let _: core::fmt::Result = writeln!(s, "- rustc: {}", first_line_of("rustc", &["--version"]));
    let _: core::fmt::Result = writeln!(s, "- cargo: {}", first_line_of("cargo", &["--version"]));
    let _: core::fmt::Result = writeln!(s, "- python: {}", first_line_of("python", &["--version"]));
    let _: core::fmt::Result = writeln!(s, "- node: {}", first_line_of("node", &["--version"]));

    let _: core::fmt::Result = writeln!(s);
    let _: core::fmt::Result = writeln!(s, "## env vars (DISROBE_*, RUST_*)");
    let _: core::fmt::Result = writeln!(s);
    let mut keys: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with("DISROBE_") || k.starts_with("RUST_"))
        .collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    if keys.is_empty() {
        let _: core::fmt::Result = writeln!(s, "(none set)");
    } else {
        for (k, v) in &keys {
            let safe_v: &str = if k.contains("KEY") || k.contains("TOKEN") || k.contains("SECRET") {
                "(redacted)"
            } else {
                v.as_str()
            };
            let _: core::fmt::Result = writeln!(s, "- {k} = {safe_v}");
        }
    }

    let _: core::fmt::Result = writeln!(s);
    let _: core::fmt::Result = writeln!(s, "## out/ manifests (last 50 lines per stage)");
    let _: core::fmt::Result = writeln!(s);
    let out_dir: PathBuf = std::env::current_dir()
        .unwrap_or_else(|_| PathBuf::from("."))
        .join("out");
    if out_dir.is_dir() {
        let entries: Vec<PathBuf> = std::fs::read_dir(&out_dir).map_or_else(
            |_| Vec::new(),
            |rd| rd.filter_map(|e| e.ok().map(|d| d.path())).collect(),
        );
        let mut sorted: Vec<PathBuf> = entries.into_iter().filter(|p| p.is_dir()).collect();
        sorted.sort();
        for dir in &sorted {
            let manifest: PathBuf = dir.join("manifest.json");
            if !manifest.is_file() {
                continue;
            }
            let _: core::fmt::Result = writeln!(s, "### {}", manifest.display());
            let _: core::fmt::Result = writeln!(s);
            let _: core::fmt::Result = writeln!(s, "```json");
            if let Ok(text) = std::fs::read_to_string(&manifest) {
                let lines: Vec<&str> = text.lines().collect();
                let start: usize = lines.len().saturating_sub(50);
                for line in &lines[start..] {
                    let _: core::fmt::Result = writeln!(s, "{line}");
                }
            } else {
                let _: core::fmt::Result = writeln!(s, "(could not read)");
            }
            let _: core::fmt::Result = writeln!(s, "```");
            let _: core::fmt::Result = writeln!(s);
        }
    } else {
        let _: core::fmt::Result = writeln!(s, "no `./out/` directory present");
    }

    let _: core::fmt::Result = writeln!(s, "## reproduction");
    let _: core::fmt::Result = writeln!(s);
    let _: core::fmt::Result = writeln!(
        s,
        "_describe the exact command you ran & the input file (size, sha256, source)_"
    );

    s
}

fn first_line_of(cmd: &str, args: &[&str]) -> String {
    let child: std::process::Child = match Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return "(not installed)".to_owned(),
    };
    let out: std::process::Output = match wait_with_timeout(child, Duration::from_secs(3)) {
        Some(o) => o,
        None => return "(timed out)".to_owned(),
    };
    let s_out: String = String::from_utf8_lossy(&out.stdout).trim().to_owned();
    let s_err: String = String::from_utf8_lossy(&out.stderr).trim().to_owned();
    s_out
        .lines()
        .next()
        .or_else(|| s_err.lines().next())
        .unwrap_or("(no output)")
        .to_owned()
}

fn wait_with_timeout(
    mut child: std::process::Child,
    timeout: Duration,
) -> Option<std::process::Output> {
    use std::time::Instant;
    let deadline: Instant = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return child.wait_with_output().ok(),
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    return None;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(_) => return None,
        }
    }
}
