#![deny(unreachable_pub)]
pub mod apk;
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

fn main() -> std::process::ExitCode {
    let check: bool = std::env::args().any(|a: String| a == "--check");
    match run(check) {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("disrobe-bench-head-to-head: {err:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(check: bool) -> Result<()> {
    let bench_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root: PathBuf = workspace_root(&bench_dir)?;
    let measured_dir: PathBuf = root.join("evidence").join("results").join("measured");

    let outputs: Vec<(String, Value)> = vec![
        apk::measure(&root)?,
        frisk::measure(&root)?,
        gate::measure(&root),
    ];

    let report_md: String = render_report(&outputs);

    if check {
        for (id, value) in &outputs {
            verify_json(&measured_dir.join(format!("{id}.json")), value)?;
        }
        verify_text(&bench_dir.join("results.md"), &report_md)?;
        println!(
            "disrobe-bench-head-to-head --check: {} measured result(s) match regeneration",
            outputs.len()
        );
    } else {
        for (id, value) in &outputs {
            write_json(&measured_dir.join(format!("{id}.json")), value)?;
        }
        write_file(&bench_dir.join("results.md"), &report_md)?;
        println!(
            "disrobe-bench-head-to-head: wrote {} measured result(s) into {}",
            outputs.len(),
            measured_dir.display()
        );
    }
    Ok(())
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
        "Each comparison gives `disrobe` and the leading tool the same input, same oracle, and same \
         denominator. Missing or crashing tools count as misses, not dropped samples. Losses stay in \
         the table.\n\n",
    );
    md.push_str(
        "Regenerate with `cargo run -p disrobe-bench-head-to-head`; `--check` fails if the committed \
         measured JSON or this table drifts from a fresh run. The numbers are surfaced into the \
         public evidence report by `cargo run -p xtask -- evidence` (the `headtohead-import` and \
         `gate-test-harvest` oracle kinds).\n\n",
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
