#![allow(clippy::needless_pass_by_value)]
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use super::process_capture::{CapturedOutput, wait_with_output_timeout};
use super::util::push_format;

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
    s.push_str("# disrobe bug report\n\n");
    s.push_str("## environment\n\n");
    push_format(
        &mut s,
        format_args!("- disrobe: {}\n", env!("CARGO_PKG_VERSION")),
    );
    push_format(
        &mut s,
        format_args!(
            "- os: {} {}\n",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    );
    let current_dir: String =
        std::env::current_dir().map_or_else(|_| "?".to_owned(), |p| p.display().to_string());
    push_format(&mut s, format_args!("- cwd: {current_dir}\n"));
    push_format(
        &mut s,
        format_args!("- rustc: {}\n", first_line_of("rustc", &["--version"])),
    );
    push_format(
        &mut s,
        format_args!("- cargo: {}\n", first_line_of("cargo", &["--version"])),
    );
    push_format(
        &mut s,
        format_args!("- python: {}\n", first_line_of("python", &["--version"])),
    );
    push_format(
        &mut s,
        format_args!("- node: {}\n", first_line_of("node", &["--version"])),
    );

    s.push_str("\n## env vars (DISROBE_*, RUST_*)\n\n");
    let mut keys: Vec<(String, String)> = std::env::vars()
        .filter(|(k, _)| k.starts_with("DISROBE_") || k.starts_with("RUST_"))
        .collect();
    keys.sort_by(|a, b| a.0.cmp(&b.0));
    if keys.is_empty() {
        s.push_str("(none set)\n");
    } else {
        for (k, v) in &keys {
            let safe_v: &str = if k.contains("KEY") || k.contains("TOKEN") || k.contains("SECRET") {
                "(redacted)"
            } else {
                v.as_str()
            };
            push_format(&mut s, format_args!("- {k} = {safe_v}\n"));
        }
    }

    s.push_str("\n## out/ manifests (last 50 lines per stage)\n\n");
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
            push_format(&mut s, format_args!("### {}\n\n", manifest.display()));
            s.push_str("```json\n");
            if let Ok(text) = std::fs::read_to_string(&manifest) {
                let lines: Vec<&str> = text.lines().collect();
                let start: usize = lines.len().saturating_sub(50);
                for line in &lines[start..] {
                    push_format(&mut s, format_args!("{line}\n"));
                }
            } else {
                s.push_str("(could not read)\n");
            }
            s.push_str("```\n\n");
        }
    } else {
        s.push_str("no `./out/` directory present\n");
    }

    s.push_str("## reproduction\n\n");
    s.push_str("_describe the exact command you ran & the input file (size, sha256, source)_\n");

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
    let out: CapturedOutput = match wait_with_output_timeout(child, Duration::from_secs(3)) {
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
