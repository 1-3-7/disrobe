#![deny(unreachable_pub)]
pub mod apk;
pub mod apkleaks_capture;
pub mod frisk;
pub mod gate;
#[cfg(test)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "pub(crate) is the right visibility for this crate-internal published-figure pinning \
              module; redundant_pub_crate (nursery) and the workspace unreachable_pub lint cannot \
              both hold for a private submodule, matching the allow already shipped across the \
              workspace"
)]
mod published;
pub mod tool;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::Value;

use crate::tool::{MAX_TEXT_BYTES, read_bounded_string};

#[derive(Debug, Eq, PartialEq)]
struct Options {
    check: bool,
    only: Option<String>,
}

fn main() -> std::process::ExitCode {
    let options: Result<Options> = parse_options(std::env::args());
    match options.and_then(run) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("disrobe-bench-head-to-head: {err:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn parse_options<I>(args: I) -> Result<Options>
where
    I: IntoIterator<Item = String>,
{
    let mut args = args.into_iter();
    let _program: Option<String> = args.next();
    let mut options: Options = Options {
        check: false,
        only: None,
    };
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--check" if options.check => bail!("--check was supplied more than once"),
            "--check" => options.check = true,
            "--only" => {
                let Some(id) = args.next() else {
                    bail!("--only requires a measured result id");
                };
                if options.only.replace(id).is_some() {
                    bail!("--only was supplied more than once");
                }
            }
            other => bail!("unknown argument `{other}`"),
        }
    }
    Ok(options)
}

fn run(options: Options) -> Result<()> {
    let bench_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root: PathBuf = workspace_root(&bench_dir)?;
    let measured_dir: PathBuf = root.join("evidence").join("results").join("measured");

    let outputs: Vec<(String, Value)> = measure_outputs(&root, options.only.as_deref())?;
    if options.check {
        for (id, value) in &outputs {
            verify_json(&measured_dir.join(format!("{id}.json")), value)?;
        }
        if options.only.is_none() {
            let report_md: String = render_report(&outputs);
            verify_text(&bench_dir.join("results.md"), &report_md)?;
        }
        let scope: &str = options.only.as_deref().unwrap_or("all results");
        println!("disrobe-bench-head-to-head --check: {scope} match regeneration");
    } else {
        for (id, value) in &outputs {
            write_json(&measured_dir.join(format!("{id}.json")), value)?;
        }
        println!(
            "disrobe-bench-head-to-head: wrote {} measured result(s) into {}",
            outputs.len(),
            measured_dir.display()
        );
        if options.only.is_none() {
            write_file(&bench_dir.join("results.md"), &render_report(&outputs))?;
        } else {
            println!(
                "disrobe-bench-head-to-head: {} was left as it is, because one selected result \
                 cannot rebuild a table that reports all three; rerun without --only to refresh it",
                bench_dir.join("results.md").display()
            );
        }
    }
    Ok(())
}

fn measure_outputs(root: &Path, only: Option<&str>) -> Result<Vec<(String, Value)>> {
    match only {
        None => Ok(vec![
            apk::measure(root)?,
            frisk::measure(root)?,
            gate::measure(root),
        ]),
        Some("apk-jadx-cfr") => Ok(vec![apk::measure(root)?]),
        Some("frisk-apkleaks") => Ok(vec![frisk::measure(root)?]),
        Some("gate-harvest") => Ok(vec![gate::measure(root)]),
        Some(id) => bail!("unknown measured result id `{id}`"),
    }
}

fn workspace_root(bench_dir: &Path) -> Result<PathBuf> {
    let Some(benches): Option<&Path> = bench_dir.parent() else {
        bail!("bench manifest dir has no parent: {}", bench_dir.display());
    };
    let Some(root): Option<&Path> = benches.parent() else {
        bail!("benches dir has no parent: {}", benches.display());
    };
    Ok(root.to_path_buf())
}

fn render_report(outputs: &[(String, Value)]) -> String {
    let mut md: String = String::with_capacity(8192);
    md.push_str("# Head-to-head\n\n");
    md.push_str(
        "Each leg gives `disrobe` and its leading tool the same input and scoring rule. The DEX and \
         JAR legs use their respective committed inputs. Missing or crashing tools remain explicit \
         result statuses, never dropped samples. Losses stay in the table.\n\n",
    );
    md.push_str(
        "Regenerate with `cargo run -p disrobe-bench-head-to-head`; `--check` fails if the committed \
         measured JSON or this table drifts from a fresh run. `cargo run --locked -p \
         disrobe-bench-head-to-head -- --check --only apk-jadx-cfr` checks only the APK result \
         without writing it. The numbers are surfaced into the public evidence report by `cargo run \
         -p xtask -- evidence` (the `headtohead-import` and `gate-test-harvest` oracle kinds).\n\n",
    );
    for (id, value) in outputs {
        md.push_str(&render_block(id, value));
    }
    finish_markdown(md)
}

fn finish_markdown(mut md: String) -> String {
    while md.ends_with("\n\n") {
        md.pop();
    }
    if !md.ends_with('\n') {
        md.push('\n');
    }
    md
}

fn render_block(id: &str, value: &Value) -> String {
    let mut md: String = String::with_capacity(2048);
    let title: &str = value.get("title").and_then(Value::as_str).unwrap_or(id);
    let _ = writeln!(md, "## {title}\n");
    if let Some(status) = value.get("status").and_then(Value::as_str)
        && status != "ok"
    {
        let reason: &str = value
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("(no reason recorded)");
        let _ = writeln!(md, "Status: **{status}** - {reason}\n");
    }
    if let Some(dataset) = value.get("dataset").and_then(Value::as_str) {
        let _ = writeln!(md, "- dataset: {dataset}");
    }
    if let Some(oracle) = value.get("oracle").and_then(Value::as_str) {
        let _ = writeln!(md, "- oracle: {oracle}");
    }
    if let Some(denom) = value.get("denominator").and_then(Value::as_str) {
        let _ = writeln!(md, "- shared denominator: {denom}");
    }
    if let Some(reproduce) = value.get("reproduce").and_then(Value::as_str) {
        let _ = writeln!(md, "- reproduce: `{reproduce}`");
    }
    md.push('\n');
    if let Some(tools) = value.get("tools").and_then(Value::as_array)
        && !tools.is_empty()
    {
        md.push_str("| tool | version | metric | value | status |\n");
        md.push_str("|---|---|---|---|---|\n");
        for tool in tools {
            let name: &str = tool.get("name").and_then(Value::as_str).unwrap_or("?");
            let version: &str = tool.get("version").and_then(Value::as_str).unwrap_or("n/a");
            let metric: &str = tool.get("metric").and_then(Value::as_str).unwrap_or("?");
            let display: &str = tool.get("display").and_then(Value::as_str).unwrap_or("?");
            let status: &str = tool.get("status").and_then(Value::as_str).unwrap_or("ok");
            let _ = writeln!(
                md,
                "| {} | {} | {} | {} | {} |",
                esc(name),
                esc(version),
                esc(metric),
                esc(display),
                esc(status),
            );
        }
        md.push('\n');
    }
    if let Some(note) = value.get("honest_note").and_then(Value::as_str) {
        let _ = writeln!(md, "{note}\n");
    }
    md
}

fn esc(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    write_file(path, &to_pretty(value))
}

fn to_pretty(value: &Value) -> String {
    let mut out: String = serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_owned());
    out.push('\n');
    out
}

fn write_file(path: &Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).wrap_err_with(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, content.as_bytes()).wrap_err_with(|| format!("writing {}", path.display()))
}

fn verify_json(path: &Path, value: &Value) -> Result<()> {
    verify_text(path, &to_pretty(value))
}

fn verify_text(path: &Path, expected: &str) -> Result<()> {
    match read_bounded_string(path, MAX_TEXT_BYTES) {
        Ok(on_disk) if on_disk == expected => Ok(()),
        Ok(_) => bail!(
            "{} is stale; run `cargo run -p disrobe-bench-head-to-head`",
            path.display()
        ),
        Err(err) => bail!("{} unreadable: {err}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<Options> {
        parse_options(values.iter().map(|value: &&str| (*value).to_owned()))
    }

    #[test]
    fn targeted_check_selects_one_measured_result() -> Result<()> {
        assert_eq!(
            parse(&[
                "disrobe-bench-head-to-head",
                "--check",
                "--only",
                "apk-jadx-cfr",
            ])?,
            Options {
                check: true,
                only: Some("apk-jadx-cfr".to_owned()),
            }
        );
        Ok(())
    }

    #[test]
    fn one_result_can_be_regenerated_on_its_own() -> Result<()> {
        assert_eq!(
            parse(&["disrobe-bench-head-to-head", "--only", "apk-jadx-cfr"])?,
            Options {
                check: false,
                only: Some("apk-jadx-cfr".to_owned()),
            }
        );
        Ok(())
    }

    #[test]
    fn target_selection_rejects_a_missing_or_repeated_id() {
        assert!(parse(&["disrobe-bench-head-to-head", "--check", "--only"]).is_err());
        assert!(
            parse(&[
                "disrobe-bench-head-to-head",
                "--check",
                "--only",
                "apk-jadx-cfr",
                "--only",
                "frisk-apkleaks",
            ])
            .is_err()
        );
    }
}
