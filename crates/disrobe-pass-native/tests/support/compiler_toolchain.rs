use std::process::{Command, Output};

pub(crate) const TOOLCHAIN_CAPABILITY: &str = "disrobe-pass-native::toolchain-capability";

pub(crate) const INSTALL_HINT: &str =
    "install a native C compiler (gcc or clang) and a Rust toolchain (rustc) and put them on PATH";

fn unavailable(prerequisite: &str, defect: &str) {
    let what: String = format!("{defect}; to fix it, {INSTALL_HINT}");
    if let Err(error) = disrobe_testkit::require::<()>(prerequisite, &what, None) {
        panic!("a recompile-equivalence check cannot be measured: {error}");
    }
}

fn tool_prerequisite(tool: &str) -> String {
    format!("disrobe-pass-native::toolchain::{tool}")
}

#[allow(dead_code)]
pub(crate) fn unmeasured(defect: &str) {
    unavailable(TOOLCHAIN_CAPABILITY, defect);
}

fn tool_runs(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output: Output| output.status.success())
}

#[allow(dead_code)]
pub(crate) fn require_one(tool: &'static str) -> String {
    assert!(
        tool_runs(tool),
        "`{tool}` is not callable on PATH, and every CI test runner provisions it, so this oracle \
         requires it. To fix it, {INSTALL_HINT}."
    );
    tool.to_owned()
}

#[allow(dead_code)]
pub(crate) fn require_any(candidates: &[&'static str]) -> String {
    let found: Option<&&'static str> = candidates
        .iter()
        .find(|candidate: &&&'static str| tool_runs(candidate));
    let Some(tool): Option<&&'static str> = found else {
        panic!(
            "none of {candidates:?} is callable on PATH, and every CI test runner provisions a C \
             compiler, so this oracle requires one. To fix it, {INSTALL_HINT}."
        );
    };
    (*tool).to_owned()
}

#[allow(dead_code)]
pub(crate) fn probe_one(tool: &'static str) -> Option<String> {
    if tool_runs(tool) {
        return Some(tool.to_owned());
    }
    unavailable(
        &tool_prerequisite(tool),
        &format!("`{tool}` callable on PATH"),
    );
    None
}

#[allow(dead_code)]
pub(crate) fn probe_any(candidates: &[&'static str]) -> Option<String> {
    for candidate in candidates {
        if tool_runs(candidate) {
            return Some((*candidate).to_owned());
        }
    }
    unavailable(
        &tool_prerequisite(&candidates.join("-or-")),
        &format!(
            "one of {} callable on PATH",
            candidates
                .iter()
                .map(|c: &&'static str| format!("`{c}`"))
                .collect::<Vec<String>>()
                .join(", ")
        ),
    );
    None
}

const CALIBRATED_CLANG_MAJORS: std::ops::RangeInclusive<u32> = 18..=21;

#[allow(dead_code)]
pub(crate) fn calibrated_clang() -> Option<String> {
    let bin: String = probe_one("clang")?;
    let output: Output = Command::new(&bin)
        .arg("--version")
        .output()
        .unwrap_or_else(|error: std::io::Error| panic!("run {bin} --version: {error}"));
    let banner: String = String::from_utf8_lossy(&output.stdout).into_owned();
    let first_line: &str = banner.lines().next().unwrap_or_default();
    let major: Option<u32> = first_line
        .split("clang version ")
        .nth(1)
        .and_then(|rest: &str| rest.split('.').next())
        .and_then(|digits: &str| digits.trim().parse::<u32>().ok());
    assert!(
        major.is_some_and(|found: u32| CALIBRATED_CLANG_MAJORS.contains(&found)),
        "the first clang on PATH reports `{first_line}`; the native graders are calibrated \
         against clang 18 to 21 (CI: 18 on Linux, 20 on macOS; this repository's fixtures: \
         19.1.7), so put one of those first on PATH"
    );
    Some(bin)
}

#[allow(dead_code)]
pub(crate) fn require_calibrated_clang() -> String {
    calibrated_clang().unwrap_or_else(|| {
        panic!(
            "clang is not callable on PATH, and every CI test runner provisions it, so this \
             oracle requires it. To fix it, {INSTALL_HINT}."
        )
    })
}
