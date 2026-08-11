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

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use eyre::{Result, WrapErr, bail};
use serde_json::Value;

use crate::tool::{MAX_TEXT_BYTES, find_on_path, read_bounded_string};

#[derive(Debug, Eq, PartialEq)]
struct Options {
    check: bool,
    only: Option<String>,
}

#[derive(Debug)]
struct MeasurementGenerator {
    id: &'static str,
    kind: MeasurementKind,
}

#[derive(Clone, Copy, Debug)]
enum MeasurementKind {
    Apk,
    Frisk,
    Gate,
}

impl MeasurementKind {
    fn measure(self, root: &Path) -> Result<(String, Value)> {
        match self {
            Self::Apk => apk::measure(root),
            Self::Frisk => frisk::measure(root),
            Self::Gate => Ok(gate::measure(root)),
        }
    }

    fn require(self, root: &Path) -> Result<()> {
        match self {
            Self::Apk => require_apk_tools(root),
            Self::Frisk => require_frisk_tools(root),
            Self::Gate => Ok(()),
        }
    }
}

const MEASUREMENT_GENERATORS: &[MeasurementGenerator] = &[
    MeasurementGenerator {
        id: "apk-jadx-cfr",
        kind: MeasurementKind::Apk,
    },
    MeasurementGenerator {
        id: "frisk-apkleaks",
        kind: MeasurementKind::Frisk,
    },
    MeasurementGenerator {
        id: "gate-harvest",
        kind: MeasurementKind::Gate,
    },
];

fn require_apk_tools(root: &Path) -> Result<()> {
    require_program(
        requirement_enabled("DISROBE_REQUIRE_JAVAC"),
        "javac",
        "DISROBE_REQUIRE_JAVAC",
    )?;
    require_program(
        requirement_enabled("DISROBE_REQUIRE_JADX"),
        "jadx",
        "DISROBE_REQUIRE_JADX",
    )?;
    if requirement_enabled("DISROBE_REQUIRE_CFR") {
        require_program(true, "java", "DISROBE_REQUIRE_CFR")?;
        let cfr_jar: PathBuf = root.join("evidence/competitors/jars/cfr.jar");
        if find_on_path("cfr").is_none() && !cfr_jar.is_file() {
            bail!(
                "DISROBE_REQUIRE_CFR requires `cfr` on PATH or {}, but neither is available",
                cfr_jar.display()
            );
        }
    }
    apk::require_pinned_versions(root).map_err(|error: String| eyre::eyre!(error))?;
    Ok(())
}

fn require_frisk_tools(root: &Path) -> Result<()> {
    require_program(
        requirement_enabled("DISROBE_REQUIRE_APKLEAKS"),
        "apkleaks",
        "DISROBE_REQUIRE_APKLEAKS",
    )?;
    require_program(
        requirement_enabled("DISROBE_REQUIRE_JADX"),
        "jadx",
        "DISROBE_REQUIRE_JADX",
    )?;
    frisk::require_pinned_versions(root).map_err(|error: String| eyre::eyre!(error))
}

fn require_program(required: bool, program: &str, variable: &str) -> Result<()> {
    if required && find_on_path(program).is_none() {
        bail!("{variable} requires `{program}` on PATH, but it is unavailable");
    }
    Ok(())
}

pub(crate) fn requirement_enabled(variable: &str) -> bool {
    let value: Option<std::ffi::OsString> = std::env::var_os(variable);
    requirement_value_enabled(value.as_deref())
}

fn requirement_value_enabled(value: Option<&OsStr>) -> bool {
    let Some(raw): Option<&OsStr> = value else {
        return false;
    };
    let normalized: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    !matches!(
        normalized.as_str(),
        "" | "0" | "false" | "no" | "off" | "optional"
    )
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

    let outputs: Vec<(String, Value)> =
        measure_outputs(&root, &measured_dir, options.only.as_deref())?;
    if options.check {
        for (id, value) in &outputs {
            verify_json(&measured_dir.join(format!("{id}.json")), value)?;
        }
        if options.only.is_none() {
            let report_md: String = render_report(&outputs);
            verify_text(&bench_dir.join("results.md"), &report_md)?;
        }
        let scope: &str = options.only.as_deref().unwrap_or("all results");
        println!(
            "disrobe-bench-head-to-head --check: re-derived {} measured result(s); {scope} match regeneration",
            outputs.len()
        );
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
                 cannot rebuild a table that reports every committed result; rerun without --only \
                 to refresh it",
                bench_dir.join("results.md").display()
            );
        }
    }
    Ok(())
}

fn measure_outputs(
    root: &Path,
    measured_dir: &Path,
    only: Option<&str>,
) -> Result<Vec<(String, Value)>> {
    let generators: Vec<&MeasurementGenerator> = if let Some(id) = only {
        vec![measurement_generator(id)?]
    } else {
        committed_generators(measured_dir)?
    };
    let mut outputs: Vec<(String, Value)> = Vec::with_capacity(generators.len());
    for generator in generators {
        generator.kind.require(root)?;
        let output: (String, Value) = generator.kind.measure(root)?;
        if output.0 != generator.id {
            bail!(
                "generator `{}` produced measured result id `{}`",
                generator.id,
                output.0
            );
        }
        outputs.push(output);
    }
    Ok(outputs)
}

fn measurement_generator(id: &str) -> Result<&'static MeasurementGenerator> {
    MEASUREMENT_GENERATORS
        .iter()
        .find(|generator: &&MeasurementGenerator| generator.id == id)
        .ok_or_else(|| eyre::eyre!("unknown measured result id `{id}`"))
}

fn committed_generators(measured_dir: &Path) -> Result<Vec<&'static MeasurementGenerator>> {
    const MAX_MEASURED_RESULTS: usize = 256;
    let entries: fs::ReadDir = fs::read_dir(measured_dir)
        .wrap_err_with(|| format!("reading {}", measured_dir.display()))?;
    let mut ids: Vec<String> = Vec::new();
    for entry in entries {
        if ids.len() >= MAX_MEASURED_RESULTS {
            bail!(
                "{} contains more than {MAX_MEASURED_RESULTS} measured results",
                measured_dir.display()
            );
        }
        let entry: fs::DirEntry =
            entry.wrap_err_with(|| format!("reading an entry in {}", measured_dir.display()))?;
        let path: PathBuf = entry.path();
        let file_type: fs::FileType = entry
            .file_type()
            .wrap_err_with(|| format!("reading the type of {}", path.display()))?;
        if !file_type.is_file() || path.extension().and_then(|value| value.to_str()) != Some("json")
        {
            bail!(
                "{} is not a registered measured-result JSON file",
                path.display()
            );
        }
        let Some(id): Option<&str> = path.file_stem().and_then(|value| value.to_str()) else {
            bail!("{} has a non-Unicode measured result id", path.display());
        };
        ids.push(id.to_owned());
    }
    ids.sort();

    let mut registered: Vec<&str> = MEASUREMENT_GENERATORS
        .iter()
        .map(|generator: &MeasurementGenerator| generator.id)
        .collect();
    registered.sort_unstable();
    if let Some(unknown) = ids
        .iter()
        .find(|id: &&String| !registered.contains(&id.as_str()))
    {
        bail!(
            "{}.json is committed under {} but no generator owns it",
            unknown,
            measured_dir.display()
        );
    }
    if let Some(missing) = registered
        .iter()
        .find(|id: &&&str| !ids.iter().any(|committed: &String| committed == **id))
    {
        bail!(
            "{missing}.json is registered but absent from {}; regenerate it with `cargo run -p \
             disrobe-bench-head-to-head`",
            measured_dir.display()
        );
    }
    ids.iter()
        .map(|id: &String| measurement_generator(id))
        .collect()
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
    use disrobe_core::scratch::ScratchDir;

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

    #[test]
    fn committed_inventory_is_complete_and_rejects_unknown_generators() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-inventory")?;
        for id in ["apk-jadx-cfr", "frisk-apkleaks", "gate-harvest"] {
            fs::write(scratch.path().join(format!("{id}.json")), b"{}")?;
        }
        let generators: Vec<&'static MeasurementGenerator> = committed_generators(scratch.path())?;
        let ids: Vec<&str> = generators
            .iter()
            .map(|generator: &&MeasurementGenerator| generator.id)
            .collect();
        assert_eq!(ids, ["apk-jadx-cfr", "frisk-apkleaks", "gate-harvest"]);

        fs::write(scratch.path().join("unregistered.json"), b"{}")?;
        let Some(unknown_error) = committed_generators(scratch.path()).err() else {
            bail!("an unregistered measured result was accepted");
        };
        let unknown: String = unknown_error.to_string();
        assert!(unknown.contains("unregistered.json"));
        fs::remove_file(scratch.path().join("unregistered.json"))?;
        fs::remove_file(scratch.path().join("gate-harvest.json"))?;
        let Some(missing_error) = committed_generators(scratch.path()).err() else {
            bail!("a registered generator without committed output was accepted");
        };
        let missing: String = missing_error.to_string();
        assert!(missing.contains("gate-harvest.json"));
        Ok(())
    }

    #[test]
    fn committed_byte_drift_is_a_named_failure() -> Result<()> {
        let scratch: ScratchDir = ScratchDir::create("disrobe-h2h-drift")?;
        let path: PathBuf = scratch.path().join("gate-harvest.json");
        fs::write(&path, b"changed\n")?;
        let Some(drift_error) = verify_text(&path, "expected\n").err() else {
            bail!("edited committed bytes matched regeneration");
        };
        let failure: String = drift_error.to_string();
        assert!(failure.contains("gate-harvest.json"));
        assert!(failure.contains("cargo run -p disrobe-bench-head-to-head"));
        Ok(())
    }

    #[test]
    fn a_required_missing_competitor_is_fatal() -> Result<()> {
        let Some(requirement_error) = require_program(
            true,
            "disrobe-tool-that-must-not-exist-1f466433",
            "DISROBE_REQUIRE_TEST_TOOL",
        )
        .err() else {
            bail!("a required absent competitor was accepted");
        };
        let failure: String = requirement_error.to_string();
        assert!(failure.contains("disrobe-tool-that-must-not-exist-1f466433"));
        assert!(failure.contains("DISROBE_REQUIRE_TEST_TOOL"));
        Ok(())
    }

    #[test]
    fn requirement_values_match_the_repository_off_switches() {
        for value in ["", "0", "false", "no", "off", "optional", " OFF "] {
            assert!(
                !requirement_value_enabled(Some(OsStr::new(value))),
                "{value}"
            );
        }
        assert!(!requirement_value_enabled(None));
        for value in ["1", "true", "required", "yes"] {
            assert!(
                requirement_value_enabled(Some(OsStr::new(value))),
                "{value}"
            );
        }
    }
}
