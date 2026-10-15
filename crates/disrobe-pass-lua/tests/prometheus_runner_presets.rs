#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

mod common;

#[path = "support/prometheus_residue.rs"]
#[allow(clippy::redundant_pub_crate, dead_code)]
mod prometheus_residue;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use common::lua_toolchain::{Dialect, interpreter};
use disrobe_core::scratch::ScratchDir;
use disrobe_pass_lua::error::Error;
use disrobe_pass_lua::obfuscator::{DeobfOptions, PeelResult};
use disrobe_pass_lua::prometheus;
use prometheus_residue::prometheus_layer_residue;

const PROGRAMS: [&str; 3] = ["values", "loops", "branches"];
const PRESETS: [&str; 4] = ["Minify", "Weak", "Medium", "Strong"];
const RUN_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Grade {
    Recovered,
    Refused(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LuaRun {
    status: ExitStatus,
    stdout: String,
}

fn corpus_path(rel: &str) -> PathBuf {
    let manifest_dir: &str = env!("CARGO_MANIFEST_DIR");
    let mut path: PathBuf = PathBuf::from(manifest_dir);
    path.push("..");
    path.push("..");
    path.push("corpus");
    path.push("lua");
    for component in rel.split('/') {
        path.push(component);
    }
    path
}

fn read_text(rel: &str) -> String {
    let path: PathBuf = corpus_path(rel);
    fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{rel}: the committed corpus text is unavailable at {}: {error}",
            path.display()
        )
    })
}

fn read_bytes(rel: &str) -> Vec<u8> {
    let path: PathBuf = corpus_path(rel);
    fs::read(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{rel}: the committed corpus input is unavailable at {}: {error}",
            path.display()
        )
    })
}

fn run_source(lua: &str, directory: &Path, label: &str, source: &str) -> LuaRun {
    let path: PathBuf = directory.join(format!("{label}.lua"));
    fs::write(&path, source).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{label}: cannot stage approved source {}: {error}",
            path.display()
        )
    });
    let stdout_path: PathBuf = directory.join(format!("{label}.stdout.txt"));
    let stderr_path: PathBuf = directory.join(format!("{label}.stderr.txt"));
    let stdout: fs::File = fs::File::create(&stdout_path)
        .unwrap_or_else(|error: std::io::Error| panic!("{label}: create stdout: {error}"));
    let stderr: fs::File = fs::File::create(&stderr_path)
        .unwrap_or_else(|error: std::io::Error| panic!("{label}: create stderr: {error}"));
    let mut child: Child = Command::new(lua)
        .arg(&path)
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
        .unwrap_or_else(|error: std::io::Error| {
            panic!("{label}: Lua 5.1 at {lua:?} did not start: {error}")
        });
    let deadline: Instant = Instant::now() + RUN_TIMEOUT;
    let status: ExitStatus = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(15));
            }
            Ok(None) => {
                drop(child.kill());
                drop(child.wait());
                panic!("{label}: Lua 5.1 did not finish within {RUN_TIMEOUT:?}");
            }
            Err(error) => panic!("{label}: cannot poll Lua 5.1: {error}"),
        }
    };
    let stdout: String = fs::read_to_string(&stdout_path)
        .unwrap_or_else(|error: std::io::Error| panic!("{label}: read stdout: {error}"));
    LuaRun {
        status,
        stdout: stdout.replace("\r\n", "\n"),
    }
}

const fn peel_refusal(error: &Error) -> &'static str {
    match error {
        Error::PrometheusVmifyRefused(_) => "vmify-typed-refusal",
        Error::LimitExceeded { .. } => "recovery-budget-exceeded",
        Error::NoObfuscatorSignature(_) => "detection-missing",
        _ => "typed-prometheus-peel-error",
    }
}

fn incomplete_refusal(markers: &[String]) -> &'static str {
    if markers
        .iter()
        .any(|marker: &String| marker.contains("uses a live upvalue-box handle"))
    {
        return "live-upvalue-box-handle";
    }
    if markers.iter().any(|marker: &String| {
        marker.contains("post-dispatch return helper is not bound to the exact")
    }) {
        return "return-helper-not-exact";
    }
    if markers
        .iter()
        .any(|marker: &String| marker.contains("handlers 32/93 (34%), functions 17/18"))
    {
        return "handler-coverage-32-of-93";
    }
    if markers
        .iter()
        .any(|marker: &String| marker.contains("handlers 70/190 (36%), functions 25/26"))
    {
        return "handler-coverage-70-of-190";
    }
    if markers.iter().any(|marker: &String| {
        marker.contains("minify-only shape leaves source strings in cleartext")
    }) {
        return "minify-only-passthrough";
    }
    if markers.iter().any(|marker: &String| {
        marker.contains("recovery was refused rather than emitted partly wrong")
    }) {
        return "vmify-refused-before-emission";
    }
    if markers
        .iter()
        .any(|marker: &String| marker.contains("not lifted back to structured Lua by this pass"))
    {
        return "vmify-dispatch-remains-unlifted";
    }
    if markers
        .iter()
        .any(|marker: &String| marker.contains("Vmify container devirtualized"))
    {
        return "vmify-recovery-not-full";
    }
    "recovery-not-marked-full"
}

fn grade_cell(lua: &str, directory: &Path, program: &str, preset: &str) -> (Grade, Option<String>) {
    let source_rel: String = format!("behaviour/{program}.lua");
    let protected_rel: String = format!("obfuscators/prometheus-runner/{program}.{preset}.lua");
    let source: String = read_text(&source_rel);
    let expected: LuaRun = run_source(
        lua,
        directory,
        &format!("{program}_{preset}_source"),
        &source,
    );
    assert!(
        expected.status.success(),
        "{source_rel}: the authored program exited {}, so its runner-presets grade is invalid",
        expected.status
    );
    let protected: Vec<u8> = read_bytes(&protected_rel);
    let detected: bool = prometheus::detect(&protected).is_some();
    let peeled: PeelResult = match prometheus::peel(&protected, &DeobfOptions::default()) {
        Ok(peeled) => peeled,
        Err(error) => return (Grade::Refused(peel_refusal(&error)), None),
    };
    if !detected {
        return (Grade::Refused("detection-missing"), None);
    }
    if !peeled.fully_recovered {
        eprintln!(
            "{program} x {preset}: passes={:?} residual={:?}",
            peeled.passes_run, peeled.residual_markers
        );
        return (
            Grade::Refused(incomplete_refusal(&peeled.residual_markers)),
            None,
        );
    }
    let recovered: String = match String::from_utf8(peeled.deobfuscated) {
        Ok(recovered) => recovered,
        Err(_) => return (Grade::Refused("recovered-not-utf8"), None),
    };
    if prometheus_layer_residue(&recovered).is_some() {
        return (Grade::Refused("prometheus-residue"), None);
    }
    let actual: LuaRun = run_source(
        lua,
        directory,
        &format!("{program}_{preset}_recovered"),
        &recovered,
    );
    if actual.status != expected.status {
        return (Grade::Refused("exit-status-mismatch"), Some(recovered));
    }
    if actual.stdout != expected.stdout {
        return (Grade::Refused("stdout-mismatch"), Some(recovered));
    }
    (Grade::Recovered, Some(recovered))
}

fn expected_grade(program: &str, preset: &str) -> Grade {
    match (program, preset) {
        ("values" | "branches", "Minify") => Grade::Refused("detection-missing"),
        ("values", "Weak" | "Medium") => Grade::Refused("live-upvalue-box-handle"),
        ("values" | "loops" | "branches", "Strong") => Grade::Refused("return-helper-not-exact"),
        ("loops", "Minify") => Grade::Refused("minify-only-passthrough"),
        ("loops", "Weak") => Grade::Refused("handler-coverage-32-of-93"),
        ("loops", "Medium") => Grade::Refused("handler-coverage-70-of-190"),
        ("branches", "Weak" | "Medium") => Grade::Recovered,
        _ => panic!("unlisted Prometheus runner matrix cell {program}/{preset}"),
    }
}

fn matrix_line(program: &str, preset: &str, grade: Grade) -> String {
    match grade {
        Grade::Recovered => format!("{program} x {preset}: recovered"),
        Grade::Refused(reason) => format!("{program} x {preset}: refused ({reason})"),
    }
}

fn mutation_is_caught(
    lua: &str,
    directory: &Path,
    program: &str,
    preset: &str,
    recovered: &str,
) -> bool {
    let source: String = read_text(&format!("behaviour/{program}.lua"));
    let expected: LuaRun = run_source(
        lua,
        directory,
        &format!("{program}_{preset}_mutation_source"),
        &source,
    );
    let mutated: String = recovered.replacen("97", "98", 1);
    assert_ne!(
        mutated, recovered,
        "{program} x {preset}: recovered source must retain the modulo-97 constant"
    );
    let actual: LuaRun = run_source(
        lua,
        directory,
        &format!("{program}_{preset}_mutation_recovered"),
        &mutated,
    );
    actual != expected
}

#[test]
fn prometheus_runner_presets_recover_or_refuse_by_pinned_reason() {
    let lua: String = interpreter(Dialect::Lua51).unwrap_or_else(|| {
        panic!("Prometheus runner preset re-execution requires Lua 5.1 by name")
    });
    let scratch: ScratchDir = ScratchDir::create("disrobe_prometheus_runner_presets")
        .expect("create runner-preset grading scratch directory");
    let directory: &Path = scratch.path();
    let mut matrix: String = String::new();
    let mut mutation_control: Option<(&str, &str, String)> = None;
    let mut changes: Vec<String> = Vec::new();
    for program in PROGRAMS {
        for preset in PRESETS {
            let (actual, recovered): (Grade, Option<String>) =
                grade_cell(&lua, directory, program, preset);
            if actual == Grade::Recovered && mutation_control.is_none() {
                mutation_control = recovered.map(|source: String| (program, preset, source));
            }
            let _ = writeln!(matrix, "{}", matrix_line(program, preset, actual));
            let expected: Grade = expected_grade(program, preset);
            if actual != expected {
                changes.push(format!(
                    "{program} x {preset}: expected {expected:?}, got {actual:?}"
                ));
            }
        }
    }
    eprintln!("Prometheus runner matrix:\n{matrix}");
    match mutation_control {
        Some((program, preset, recovered)) => {
            if !mutation_is_caught(&lua, directory, program, preset, &recovered) {
                changes.push(format!(
                    "{program} x {preset}: changing one recovered numeric constant did not turn the cell red"
                ));
            }
        }
        None => {
            changes.push("the Prometheus runner matrix has no recovered cell to mutate".to_owned());
        }
    }
    assert!(
        changes.is_empty(),
        "Prometheus runner matrix changed:\n{matrix}changes={changes:?}"
    );
}
