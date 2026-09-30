use std::ffi::OsString;
use std::io::ErrorKind;
use std::process::{Command, Output};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Toolchain {
    pub(crate) program: &'static str,
    pub(crate) prerequisite: &'static str,
    pub(crate) install_hint: &'static str,
}

pub(crate) const MRI: Toolchain = Toolchain {
    program: "ruby",
    prerequisite: "disrobe-pass-ruby::ruby",
    install_hint: "install ruby 3.4.x and put it on PATH",
};

pub(crate) const MRBC: Toolchain = Toolchain {
    program: "mrbc",
    prerequisite: "disrobe-pass-ruby::mrbc",
    install_hint: "build mruby with rake and put build/host/bin on PATH",
};

pub(crate) const MRUBY: Toolchain = Toolchain {
    program: "mruby",
    prerequisite: "disrobe-pass-ruby::mruby",
    install_hint: "build mruby with rake and put build/host/bin on PATH",
};

pub(crate) const MRI_MEASURED_SERIES: &str = "ruby 3.4";
pub(crate) const MRI_RECOMPILE_VERSION: &str = "ruby 3.4.10 ";
pub(crate) const MRUBY_MEASURED_SERIES: &[&str] = &["mruby 3.3.", "mruby 3.4."];

#[derive(Debug, Clone)]
pub(crate) struct ToolchainBanner {
    pub(crate) program: &'static str,
    pub(crate) executable: OsString,
    pub(crate) banner: String,
}

pub(crate) fn unmeasured(toolchain: &Toolchain, graded: &str, defect: &str) {
    let what: String = format!(
        "{program} to grade {graded} ({defect}); {hint}",
        program = toolchain.program,
        hint = toolchain.install_hint,
    );
    if let Err(error) = disrobe_testkit::require::<()>(toolchain.prerequisite, &what, None) {
        panic!("{error}");
    }
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

pub(crate) fn require_measured_series(
    toolchain: &Toolchain,
    series: &[&str],
    graded: &str,
) -> Option<ToolchainBanner> {
    let output: Output = match version_output(toolchain, graded) {
        Ok(output) => output,
        Err(defect) => {
            unmeasured(toolchain, graded, &defect);
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
        unmeasured(toolchain, graded, &defect);
        return None;
    }
    Some(ToolchainBanner {
        program: toolchain.program,
        executable: OsString::from(toolchain.program),
        banner,
    })
}

pub(crate) fn require_exact_mri_recompile(graded: &str) -> ToolchainBanner {
    let executable: OsString =
        std::env::var_os("DISROBE_RUBY").unwrap_or_else(|| OsString::from(MRI.program));
    let output: Output = Command::new(&executable)
        .arg("--version")
        .output()
        .unwrap_or_else(|error: std::io::Error| {
            panic!(
                "the required Ruby executable `{}` could not be launched ({error}), so {graded} \
                 cannot be measured; set DISROBE_RUBY to the Ruby 3.4.10 executable",
                executable.to_string_lossy()
            )
        });
    assert!(
        output.status.success(),
        "the required Ruby executable `{}` returned {} for --version, so {graded} cannot be \
         measured",
        executable.to_string_lossy(),
        output.status
    );
    let banner: String = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    assert!(
        banner.starts_with(MRI_RECOMPILE_VERSION),
        "the required Ruby executable `{}` reports `{banner}`; {graded} is pinned to Ruby 3.4.10 \
         and a different patch release must fail instead of skipping",
        executable.to_string_lossy()
    );
    ToolchainBanner {
        program: MRI.program,
        executable,
        banner,
    }
}

pub(crate) fn require(toolchain: &Toolchain, graded: &str) -> Option<ToolchainBanner> {
    require_measured_series(toolchain, &[], graded)
}

pub(crate) fn require_version(
    toolchain: &Toolchain,
    version_marker: &str,
    graded: &str,
) -> Option<ToolchainBanner> {
    require_measured_series(toolchain, &[version_marker], graded)
}

pub(crate) fn require_mri(graded: &str) -> Option<ToolchainBanner> {
    require(&MRI, graded)
}

pub(crate) fn require_mri_measured_series(graded: &str) -> Option<ToolchainBanner> {
    require_version(&MRI, MRI_MEASURED_SERIES, graded)
}
