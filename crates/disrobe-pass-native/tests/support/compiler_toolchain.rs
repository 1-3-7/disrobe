use std::ffi::OsStr;
use std::io::Write as _;
use std::process::{Command, Output};
use std::sync::{Mutex, OnceLock};

pub(crate) const REQUIRE_VAR: &str = "DISROBE_REQUIRE_NATIVE_TOOLCHAIN";

pub(crate) const INSTALL_HINT: &str =
    "install a native C compiler (gcc or clang) and a Rust toolchain (rustc) and put them on PATH";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolchainRequirement {
    Optional,
    Mandatory,
}

pub(crate) fn requirement_from_value(value: Option<&OsStr>) -> ToolchainRequirement {
    let Some(raw): Option<&OsStr> = value else {
        return ToolchainRequirement::Optional;
    };
    let text: String = raw.to_string_lossy().trim().to_ascii_lowercase();
    match text.as_str() {
        "" | "0" | "false" | "no" | "off" | "optional" => ToolchainRequirement::Optional,
        _ => ToolchainRequirement::Mandatory,
    }
}

pub(crate) fn requirement() -> ToolchainRequirement {
    requirement_from_value(std::env::var_os(REQUIRE_VAR).as_deref())
}

fn announced() -> &'static Mutex<Vec<String>> {
    static ANNOUNCED: OnceLock<Mutex<Vec<String>>> = OnceLock::new();
    ANNOUNCED.get_or_init(|| Mutex::new(Vec::new()))
}

fn announce_unmeasured(defect: &str) {
    let already_announced: bool = {
        let mut seen: std::sync::MutexGuard<'_, Vec<String>> = announced()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let known: bool = seen.iter().any(|line: &String| line == defect);
        if !known {
            seen.push(defect.to_owned());
        }
        known
    };
    if already_announced {
        return;
    }
    let line: String = format!(
        "\nNOT MEASURED: a recompile-equivalence check was skipped because {defect}. Set \
         {REQUIRE_VAR}=1 to fail instead of skipping when a native toolchain is absent. To fix \
         it, {INSTALL_HINT}.\n"
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

fn enforce_requirement(defect: &str, requirement: ToolchainRequirement) {
    assert!(
        requirement == ToolchainRequirement::Optional,
        "{REQUIRE_VAR} makes a native toolchain mandatory for this run, so a \
         recompile-equivalence check cannot be measured and this case must not report success: \
         {defect}. To fix it, {INSTALL_HINT}; to permit a run that measures nothing here, clear \
         {REQUIRE_VAR}."
    );
    announce_unmeasured(defect);
}

fn tool_runs(tool: &str) -> bool {
    Command::new(tool)
        .arg("--version")
        .output()
        .is_ok_and(|output: Output| output.status.success())
}

pub(crate) fn probe_one(tool: &'static str) -> Option<String> {
    if tool_runs(tool) {
        return Some(tool.to_owned());
    }
    enforce_requirement(&format!("`{tool}` is not callable on PATH"), requirement());
    None
}

pub(crate) fn probe_any(candidates: &[&'static str]) -> Option<String> {
    for candidate in candidates {
        if tool_runs(candidate) {
            return Some((*candidate).to_owned());
        }
    }
    enforce_requirement(
        &format!(
            "none of {} is callable on PATH",
            candidates
                .iter()
                .map(|c: &&'static str| format!("`{c}`"))
                .collect::<Vec<String>>()
                .join(", ")
        ),
        requirement(),
    );
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requirement_from_value_treats_unset_and_falsy_as_optional() {
        assert_eq!(requirement_from_value(None), ToolchainRequirement::Optional);
        for falsy in ["", "0", "false", "no", "off", "optional", "OFF", "False"] {
            assert_eq!(
                requirement_from_value(Some(OsStr::new(falsy))),
                ToolchainRequirement::Optional,
                "{falsy} should parse as optional"
            );
        }
    }

    #[test]
    fn requirement_from_value_treats_any_other_text_as_mandatory() {
        for truthy in ["1", "true", "yes", "on", "mandatory", "anything"] {
            assert_eq!(
                requirement_from_value(Some(OsStr::new(truthy))),
                ToolchainRequirement::Mandatory,
                "{truthy} should parse as mandatory"
            );
        }
    }
}
