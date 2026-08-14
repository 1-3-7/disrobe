use std::ffi::{OsStr, OsString};
use std::io::{ErrorKind, Write};
use std::process::{Command, Output};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Toolchain {
    pub(crate) program: &'static str,
    pub(crate) require_var: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) const MRI: Toolchain = Toolchain {
    program: "ruby",
    require_var: "DISROBE_REQUIRE_RUBY",
    install_hint: "install ruby 3.4.x and put it on PATH",
};

pub(crate) const MRBC: Toolchain = Toolchain {
    program: "mrbc",
    require_var: "DISROBE_REQUIRE_MRUBY",
    install_hint: "build mruby with rake and put build/host/bin on PATH",
};

pub(crate) const MRUBY: Toolchain = Toolchain {
    program: "mruby",
    require_var: "DISROBE_REQUIRE_MRUBY",
    install_hint: "build mruby with rake and put build/host/bin on PATH",
};

pub(crate) const MRI_MEASURED_SERIES: &str = "ruby 3.4";
pub(crate) const MRUBY_MEASURED_SERIES: &[&str] = &["mruby 3.3.", "mruby 3.4."];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ToolchainRequirement {
    Optional,
    Mandatory,
}

#[derive(Debug, Clone)]
pub(crate) struct ToolchainBanner {
    pub(crate) program: &'static str,
    pub(crate) banner: String,
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

pub(crate) fn requirement(toolchain: &Toolchain) -> ToolchainRequirement {
    let raw: Option<OsString> = std::env::var_os(toolchain.require_var);
    requirement_from_value(raw.as_deref())
}

pub(crate) fn enforce_requirement(
    toolchain: &Toolchain,
    graded: &str,
    defect: &str,
    requirement: ToolchainRequirement,
) {
    assert!(
        requirement == ToolchainRequirement::Optional,
        "{var} makes the {program} toolchain mandatory for this run, so {graded} cannot be measured \
         and this case must not report success: {defect}. To fix it, {hint}; to permit a run that \
         measures nothing here, clear {var}.",
        var = toolchain.require_var,
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    announce_unmeasured(toolchain, graded, defect);
}

fn announce_unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    let line: String = format!(
        "\nNOT MEASURED: {graded} was compared against nothing and graded nothing, because the \
         {program} toolchain is not usable here ({defect}). Set {var}=1 to fail instead of skipping \
         when {program} cannot be run.\n",
        program = toolchain.program,
        var = toolchain.require_var,
    );
    let mut sink: std::io::StdoutLock<'static> = std::io::stdout().lock();
    drop(sink.write_all(line.as_bytes()));
    drop(sink.flush());
}

fn version_output(toolchain: &Toolchain, graded: &str) -> Result<Output, String> {
    match Command::new(toolchain.program).arg("--version").output() {
        Ok(output) if output.status.success() => Ok(output),
        Ok(output) => panic!(
            "{program} was launched but `{program} --version` exited with {status}, so {graded} \
             cannot be measured. A toolchain that runs and fails is never a skip, because that is \
             how a half-installed interpreter silently stops grading.",
            program = toolchain.program,
            status = output.status,
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            Err(format!("{} was not found on PATH", toolchain.program))
        }
        Err(err) => panic!(
            "{program} could not be launched here ({err}), so {graded} cannot be measured. A \
             toolchain that is present but unrunnable is never a skip, because that is how a \
             permissions or quarantine problem silently stops grading.",
            program = toolchain.program,
        ),
    }
}

pub(crate) fn require_with_requirement(
    toolchain: &Toolchain,
    version_marker: Option<&str>,
    graded: &str,
    requirement: ToolchainRequirement,
) -> Option<ToolchainBanner> {
    version_marker.map_or_else(
        || require_measured_series(toolchain, &[], graded, requirement),
        |marker: &str| require_measured_series(toolchain, &[marker], graded, requirement),
    )
}

pub(crate) fn require_measured_series(
    toolchain: &Toolchain,
    series: &[&str],
    graded: &str,
    requirement: ToolchainRequirement,
) -> Option<ToolchainBanner> {
    let output: Output = match version_output(toolchain, graded) {
        Ok(output) => output,
        Err(defect) => {
            enforce_requirement(toolchain, graded, &defect, requirement);
            return None;
        }
    };
    let banner: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !series.is_empty() && !series.iter().any(|marker: &&str| banner.contains(*marker)) {
        let defect: String = format!(
            "it reports `{banner}`, which is not one of the `{}` series these expectations were \
             measured against",
            series.join("`, `")
        );
        enforce_requirement(toolchain, graded, &defect, requirement);
        return None;
    }
    Some(ToolchainBanner {
        program: toolchain.program,
        banner,
    })
}

pub(crate) fn require(toolchain: &Toolchain, graded: &str) -> Option<ToolchainBanner> {
    require_with_requirement(toolchain, None, graded, requirement(toolchain))
}

pub(crate) fn require_version(
    toolchain: &Toolchain,
    version_marker: &str,
    graded: &str,
) -> Option<ToolchainBanner> {
    require_with_requirement(
        toolchain,
        Some(version_marker),
        graded,
        requirement(toolchain),
    )
}

pub(crate) fn require_mri(graded: &str) -> Option<ToolchainBanner> {
    require(&MRI, graded)
}

pub(crate) fn require_mri_measured_series(graded: &str) -> Option<ToolchainBanner> {
    require_version(&MRI, MRI_MEASURED_SERIES, graded)
}
