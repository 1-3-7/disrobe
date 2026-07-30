#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use std::ffi::OsStr;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};

use common::repository_root;
use common::requirement::{
    MAKECAB, MAKENSIS, REQUIRE_ALL_VAR, Requirement, SEVEN_ZIP, Toolchain, WIX, enforce, locate_in,
    required_fixture, requirement_from_values,
};

const GATED: [Toolchain; 4] = [MAKECAB, SEVEN_ZIP, WIX, MAKENSIS];

const PROBE: Toolchain = Toolchain {
    program: "7z",
    programs: &["7z"],
    install_paths: &[],
    identity: Some("7-Zip"),
    require_var: "DISROBE_REQUIRE_SEVEN_ZIP",
    install_hint: "install 7-Zip and put 7z, 7za, 7zz or 7zr on PATH",
};

const CI_WORKFLOW: &str = ".github/workflows/ci.yml";

fn shim_directory(purpose: &str) -> (disrobe_core::scratch::ScratchDir, PathBuf) {
    let scratch: disrobe_core::scratch::ScratchDir =
        disrobe_core::scratch::ScratchDir::create(purpose).expect("create scratch directory");
    let directory: PathBuf = scratch.path().join("bin");
    std::fs::create_dir_all(&directory).expect("create shim directory");
    (scratch, directory)
}

#[cfg(windows)]
fn shim_that_prints(directory: &Path, stem: &str, banner: &str) -> PathBuf {
    let path: PathBuf = directory.join(format!("{stem}.bat"));
    std::fs::write(&path, format!("@echo off\r\necho {banner}\r\n")).expect("write batch shim");
    path
}

#[cfg(unix)]
fn shim_that_prints(directory: &Path, stem: &str, banner: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let path: PathBuf = directory.join(stem);
    std::fs::write(&path, format!("#!/bin/sh\necho '{banner}'\n")).expect("write shell shim");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
        .expect("mark the shim executable");
    path
}

#[cfg(windows)]
fn shell_shim_windows_cannot_start(directory: &Path, stem: &str) -> PathBuf {
    let path: PathBuf = directory.join(stem);
    std::fs::write(
        &path,
        "#!/bin/sh\nDIR=${0%/*}\n\"$DIR/../lib/7-Zip/7z.exe\" \"$@\"\nexit $?\n",
    )
    .expect("write shell shim");
    path
}

fn value(text: &str) -> &OsStr {
    OsStr::new(text)
}

fn panic_message(body: impl FnOnce()) -> String {
    let previous: Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send> =
        std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome: Result<(), Box<dyn std::any::Any + Send>> =
        std::panic::catch_unwind(AssertUnwindSafe(body));
    std::panic::set_hook(previous);
    let payload: Box<dyn std::any::Any + Send> = outcome.expect_err("the call must panic");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            payload
                .downcast_ref::<&'static str>()
                .map(|text: &&str| (*text).to_owned())
        })
        .expect("a panic payload carries its message")
}

#[test]
fn an_unset_variable_leaves_a_toolchain_optional() {
    assert_eq!(requirement_from_values(None, None), Requirement::Optional);
    for text in ["", " ", "0", "false", "no", "off", "optional", "OPTIONAL"] {
        assert_eq!(
            requirement_from_values(Some(value(text)), None),
            Requirement::Optional,
            "{text:?} must not make a toolchain mandatory"
        );
    }
}

#[test]
fn either_variable_makes_a_toolchain_mandatory() {
    for text in ["1", "true", "yes", "on", "all", "please"] {
        assert_eq!(
            requirement_from_values(Some(value(text)), None),
            Requirement::Mandatory,
            "the per-tool variable set to {text:?} must make the toolchain mandatory"
        );
        assert_eq!(
            requirement_from_values(None, Some(value(text))),
            Requirement::Mandatory,
            "the blanket variable set to {text:?} must make the toolchain mandatory"
        );
    }
    assert_eq!(
        requirement_from_values(Some(value("0")), Some(value("1"))),
        Requirement::Mandatory,
        "the blanket variable must not be overridden by an unset-looking per-tool value"
    );
}

#[test]
fn a_mandatory_toolchain_turns_an_unmeasured_case_into_a_failure() {
    for toolchain in GATED {
        let message: String = panic_message(|| {
            enforce(
                &toolchain,
                "the byte-exact recovery this case exists to measure",
                "the tool was not found",
                Requirement::Mandatory,
            );
        });
        assert!(
            message.contains(toolchain.require_var)
                && message.contains(REQUIRE_ALL_VAR)
                && message.contains("must not report success"),
            "the failure for {} must name both variables and say the case cannot pass: {message}",
            toolchain.program
        );
    }
}

#[test]
fn an_optional_toolchain_lets_an_unmeasured_case_continue() {
    for toolchain in GATED {
        enforce(
            &toolchain,
            "the byte-exact recovery this case exists to measure",
            "the tool was not found",
            Requirement::Optional,
        );
    }
}

#[test]
fn a_fixture_that_is_not_committed_is_never_treated_as_absent_by_choice() {
    let message: String = panic_message(|| {
        let _ignored: Vec<u8> = required_fixture("cython", "no-such-fixture.pyd");
    });
    assert!(
        message.contains("corpus/binfmt/cython/no-such-fixture.pyd")
            && message.contains("damaged checkout"),
        "a missing tracked fixture must name the path and refuse to pass: {message}"
    );
}

#[test]
fn an_empty_search_path_names_the_programs_it_looked_for() {
    let failure: String = locate_in(&SEVEN_ZIP, &[]).expect_err("nothing can be found in nowhere");
    for program in SEVEN_ZIP.programs {
        assert!(
            failure.contains(program),
            "the failure must name every program it looked for, and it omits {program}: {failure}"
        );
    }
}

#[test]
fn a_program_that_answers_to_another_name_is_not_taken_for_the_archiver() {
    let (_scratch, directory): (disrobe_core::scratch::ScratchDir, PathBuf) =
        shim_directory("disrobe_requirement_impostor");
    let shim: PathBuf = shim_that_prints(&directory, "7z", "definitely not the archiver");
    let failure: String = locate_in(&PROBE, std::slice::from_ref(&directory))
        .expect_err("a program that never names itself 7-Zip cannot stand in for the writer");
    assert!(
        failure.contains("never named itself 7-Zip")
            && failure.contains(&shim.display().to_string()),
        "the failure must name the impostor and say what it failed to prove: {failure}"
    );
}

#[test]
fn a_shim_that_runs_and_names_itself_is_accepted() {
    let (_scratch, directory): (disrobe_core::scratch::ScratchDir, PathBuf) =
        shim_directory("disrobe_requirement_shim");
    let shim: PathBuf = shim_that_prints(&directory, "7z", "7-Zip 24.09 (x64)");
    let found: PathBuf = locate_in(&PROBE, std::slice::from_ref(&directory))
        .expect("a shim that runs and names itself is the reference writer");
    assert_eq!(found, shim);
}

#[cfg(windows)]
#[test]
fn a_shell_shim_windows_cannot_start_is_never_offered_as_the_writer() {
    let (_scratch, directory): (disrobe_core::scratch::ScratchDir, PathBuf) =
        shim_directory("disrobe_requirement_shell_shim");
    let shim: PathBuf = shell_shim_windows_cannot_start(&directory, "7z");
    let failure: String = locate_in(&PROBE, std::slice::from_ref(&directory)).expect_err(
        "a shell script that Windows refuses to run cannot be reported as a located writer",
    );
    assert!(
        failure.contains("cannot start") && failure.contains(&shim.display().to_string()),
        "the failure must name the file and say the process could not start it: {failure}"
    );
}

#[cfg(windows)]
#[test]
fn a_batch_shim_wins_over_the_shell_shim_that_sits_beside_it() {
    let (_scratch, directory): (disrobe_core::scratch::ScratchDir, PathBuf) =
        shim_directory("disrobe_requirement_both_shims");
    let _shell: PathBuf = shell_shim_windows_cannot_start(&directory, "7z");
    let batch: PathBuf = shim_that_prints(&directory, "7z", "7-Zip 24.09 (x64)");
    let found: PathBuf = locate_in(&PROBE, std::slice::from_ref(&directory))
        .expect("the runnable shim beside an unrunnable one is the reference writer");
    assert_eq!(
        found, batch,
        "the extensionless shell shim must not shadow the batch shim that Windows can run"
    );
}

#[test]
fn the_workflow_demands_the_same_programs_the_search_accepts() {
    let path: PathBuf = repository_root().join(CI_WORKFLOW);
    let workflow: String = std::fs::read_to_string(&path).unwrap_or_else(|error: std::io::Error| {
        panic!(
            "{CI_WORKFLOW} arms {} and this case exists to keep that demand and this search on the \
             same programs, so its absence is a damaged checkout: {error} ({})",
            SEVEN_ZIP.require_var,
            path.display()
        )
    });
    let loop_header: &str = workflow
        .lines()
        .map(str::trim)
        .find(|line: &&str| line.starts_with("for candidate in "))
        .unwrap_or_else(|| {
            panic!(
                "{CI_WORKFLOW} no longer carries a `for candidate in ...` probe, so the demand \
                 that arms {} can no longer be checked against the programs this search accepts",
                SEVEN_ZIP.require_var
            )
        });
    let listed: Vec<&str> = loop_header
        .trim_start_matches("for candidate in ")
        .trim_end_matches("; do")
        .split_whitespace()
        .collect();
    assert_eq!(
        listed, SEVEN_ZIP.programs,
        "{CI_WORKFLOW} probes {listed:?} but the measurement accepts {:?}, so the run can demand a \
         program the tests never look for",
        SEVEN_ZIP.programs
    );
}

#[test]
fn a_committed_fixture_is_read_back_whole() {
    let bytes: Vec<u8> = required_fixture("elf-dynamic", "sample.elf");
    assert_eq!(
        bytes.get(..4),
        Some(&[0x7f, b'E', b'L', b'F'][..]),
        "the loader must return the fixture bytes, not an empty stand-in"
    );
}
