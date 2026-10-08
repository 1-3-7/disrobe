#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};

use disrobe_core::anti_analysis::{AntiAnalysisFinding, AntiAnalysisReport, Technique, scan};
use disrobe_core::neutralize::{
    Applied, NeutralizationPlan, NeutralizeError, Patch, RuntimeCheck, Selection, apply,
};
use disrobe_core::scratch::ScratchDir;
use disrobe_core::subprocess::run_captured;
use disrobe_pass_native::{RuntimeCheckScan, plan_runtime_check_neutralization};
use object::{Object as _, ObjectSection as _};

use crate::common::{COMPILE_TIMEOUT, MAX_CAPTURE_BYTES, PROBE_TIMEOUT, require_gcc, scratch_dir};

const RUNTIME_DIR: &str = "corpus/native/anti-analysis/runtime";

struct Program {
    file: &'static str,
    check: &'static str,
    planned: &'static [RuntimeCheck],
    armable: bool,
    link: &'static [&'static str],
}

const PATCHABLE: &[Program] = &[
    Program {
        file: "is_debugger_present.c",
        check: "is_debugger_present",
        planned: &[RuntimeCheck::IsDebuggerPresent],
        armable: true,
        link: &[],
    },
    Program {
        file: "check_remote_debugger_present.c",
        check: "check_remote_debugger_present",
        planned: &[RuntimeCheck::CheckRemoteDebuggerPresent],
        armable: false,
        link: &[],
    },
    Program {
        file: "peb_being_debugged.c",
        check: "peb_being_debugged",
        planned: &[RuntimeCheck::PebBeingDebugged],
        armable: true,
        link: &[],
    },
    Program {
        file: "peb_nt_global_flag.c",
        check: "peb_nt_global_flag",
        planned: &[RuntimeCheck::PebNtGlobalFlag],
        armable: true,
        link: &[],
    },
    Program {
        file: "nt_query_information_process.c",
        check: "nt_query_information_process",
        planned: &[RuntimeCheck::NtQueryInformationProcessDebugPort],
        armable: false,
        link: &["-lntdll"],
    },
    Program {
        file: "rdtsc_delta.c",
        check: "rdtsc_delta",
        planned: &[RuntimeCheck::RdtscDelta],
        armable: true,
        link: &[],
    },
    Program {
        file: "tick_count_delta.c",
        check: "tick_count_delta",
        planned: &[RuntimeCheck::TickCountDelta],
        armable: true,
        link: &[],
    },
    Program {
        file: "qpc_delta.c",
        check: "qpc_delta",
        planned: &[RuntimeCheck::PerformanceCounterDelta],
        armable: true,
        link: &[],
    },
    Program {
        file: "cpuid_hypervisor_bit.c",
        check: "cpuid_hypervisor_bit",
        planned: &[RuntimeCheck::CpuidHypervisorBit],
        armable: false,
        link: &[],
    },
    Program {
        file: "int2d_trap.c",
        check: "int2d_trap",
        planned: &[RuntimeCheck::Int2dTrap],
        armable: true,
        link: &[],
    },
];

struct DetectOnly {
    file: &'static str,
    refused: RuntimeCheck,
}

const DETECT_ONLY: &[DetectOnly] = &[
    DetectOnly {
        file: "veh_control_flow.c",
        refused: RuntimeCheck::VectoredExceptionHandler,
    },
    DetectOnly {
        file: "tls_callback.c",
        refused: RuntimeCheck::TlsCallback,
    },
];

fn runtime_dir() -> PathBuf {
    let mut root: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    root.pop();
    root.pop();
    root.join(RUNTIME_DIR)
}

fn compile(gcc: &str, file: &str, armed: bool, link: &[&str], dir: &Path) -> (PathBuf, Vec<u8>) {
    let src: PathBuf = runtime_dir().join(file);
    assert!(
        src.is_file(),
        "{} is a tracked fixture and must be present",
        src.display()
    );
    let stem: &str = file.trim_end_matches(".c");
    let exe: PathBuf = dir.join(format!("{stem}{}.exe", if armed { ".armed" } else { "" }));
    let mut args: Vec<OsString> = vec![OsStr::new("-O0").to_owned()];
    if armed {
        args.push(OsStr::new("-DARMED").to_owned());
    }
    args.push(OsStr::new("-o").to_owned());
    args.push(exe.as_os_str().to_owned());
    args.push(src.as_os_str().to_owned());
    for flag in link {
        args.push(OsStr::new(flag).to_owned());
    }
    let captured = run_captured(Path::new(gcc), &args, COMPILE_TIMEOUT, MAX_CAPTURE_BYTES)
        .expect("gcc spawns")
        .unwrap_or_else(|| panic!("gcc timed out compiling {file}"));
    assert_eq!(
        captured.exit_code,
        Some(0),
        "gcc failed on {file}: {}",
        String::from_utf8_lossy(&captured.stderr)
    );
    let bytes: Vec<u8> = std::fs::read(&exe).expect("compiled program is readable");
    (exe, bytes)
}

fn run(exe: &Path) -> String {
    let no_args: [&str; 0] = [];
    let captured = run_captured(exe, &no_args, PROBE_TIMEOUT, MAX_CAPTURE_BYTES)
        .unwrap_or_else(|e| panic!("{} failed to launch: {e}", exe.display()))
        .unwrap_or_else(|| panic!("{} timed out", exe.display()));
    String::from_utf8_lossy(&captured.stdout).into_owned()
}

fn result_line(stdout: &str, check: &str) -> String {
    let needle: String = format!("check={check} result=");
    stdout
        .lines()
        .find(|line: &&str| line.starts_with(&needle))
        .unwrap_or_else(|| panic!("no result line for {check} in: {stdout}"))
        .to_owned()
}

fn text_range(bytes: &[u8]) -> std::ops::Range<u64> {
    let file: object::File<'_> = object::File::parse(bytes).expect("compiled PE parses");
    let text = file
        .section_by_name(".text")
        .expect("gcc output has a .text section");
    text.address()..text.address() + text.size()
}

fn write_patched(dir: &Path, stem: &str, bytes: &[u8]) -> PathBuf {
    let path: PathBuf = dir.join(format!("{stem}.neutralized.exe"));
    std::fs::write(&path, bytes).expect("write patched copy");
    path
}

fn plan_of(bytes: &[u8]) -> NeutralizationPlan {
    let scan: RuntimeCheckScan = plan_runtime_check_neutralization(bytes).expect("plan");
    assert_eq!(scan.bits, 64);
    assert!(scan.decoded_instructions > 0);
    scan.plan
}

#[test]
fn authored_runtime_checks_are_planned_and_their_patched_copies_print_clean() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime");
    let dir: &Path = scratch.path();
    let mut armed_demonstrations: usize = 0;
    for program in PATCHABLE {
        let stem: &str = program.file.trim_end_matches(".c");
        let (exe, bytes): (PathBuf, Vec<u8>) =
            compile(&gcc, program.file, false, program.link, dir);
        let plan: NeutralizationPlan = plan_of(&bytes);
        let expected: BTreeSet<RuntimeCheck> = program.planned.iter().copied().collect();
        assert_eq!(
            plan.checks(),
            expected,
            "{stem}: planned checks differ; patches {:#?} refusals {:#?}",
            plan.patches,
            plan.refusals
        );
        let text: std::ops::Range<u64> = text_range(&bytes);
        for patch in &plan.patches {
            assert!(
                text.contains(&patch.anchor.address),
                "{stem}: patch {} anchors outside .text: {:?}",
                patch.id,
                patch.anchor
            );
            assert_eq!(patch.original.len(), patch.replacement.len());
            assert!(!patch.risk.is_empty() && !patch.anchor.pattern.is_empty());
            let start: usize = usize::try_from(patch.file_offset).unwrap();
            assert_eq!(
                &bytes[start..start + patch.original.len()],
                patch.original.as_slice(),
                "{stem}: the plan's original bytes must be the file's bytes"
            );
        }
        let clean_before: String = result_line(&run(&exe), program.check);
        let patched: Applied = apply(&bytes, &plan, &Selection::All).expect("apply");
        let patched_exe: PathBuf = write_patched(dir, stem, &patched.bytes);
        let line: String = result_line(&run(&patched_exe), program.check);
        assert_eq!(
            line,
            format!("check={} result=clean", program.check),
            "{stem}: the patched copy must take the clean path (unpatched printed {clean_before})"
        );
        assert_eq!(patched.report.applied.len(), plan.patches.len());

        if program.armable {
            let (armed_exe, armed_bytes): (PathBuf, Vec<u8>) =
                compile(&gcc, program.file, true, program.link, dir);
            let armed_line: String = result_line(&run(&armed_exe), program.check);
            assert_eq!(
                armed_line,
                format!("check={} result=debugged", program.check),
                "{stem}: the armed build must trip its own check without a debugger"
            );
            let armed_plan: NeutralizationPlan = plan_of(&armed_bytes);
            assert_eq!(
                armed_plan.checks(),
                expected,
                "{stem} (armed): {armed_plan:#?}"
            );
            let armed_patched: Applied =
                apply(&armed_bytes, &armed_plan, &Selection::All).expect("apply armed");
            let armed_patched_exe: PathBuf =
                write_patched(dir, &format!("{stem}.armed"), &armed_patched.bytes);
            let neutralized_line: String = result_line(&run(&armed_patched_exe), program.check);
            assert_eq!(
                neutralized_line,
                format!("check={} result=clean", program.check),
                "{stem}: neutralising the armed build must flip it to the clean path"
            );
            armed_demonstrations += 1;

            let cross: Result<Applied, NeutralizeError> =
                apply(&bytes, &armed_plan, &Selection::All);
            assert!(
                matches!(cross, Err(NeutralizeError::InputMismatch { .. })),
                "{stem}: a plan made for the armed build is refused on the plain build: {cross:?}"
            );
        }
    }
    assert_eq!(
        armed_demonstrations,
        PATCHABLE
            .iter()
            .filter(|program: &&Program| program.armable)
            .count()
    );
}

#[test]
fn a_plan_whose_original_bytes_were_tampered_is_refused_before_any_write() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime-mutation");
    let (_, bytes): (PathBuf, Vec<u8>) =
        compile(&gcc, "is_debugger_present.c", false, &[], scratch.path());
    let mut plan: NeutralizationPlan = plan_of(&bytes);
    let patch: &mut Patch = plan.patches.first_mut().expect("one patch");
    patch.original[0] ^= 0x01;
    let outcome: Result<Applied, NeutralizeError> = apply(&bytes, &plan, &Selection::All);
    assert!(
        matches!(outcome, Err(NeutralizeError::OriginalMismatch { .. })),
        "{outcome:?}"
    );
    let declined: Applied = apply(&bytes, &plan, &Selection::Skip).expect("skip never writes");
    assert_eq!(declined.bytes, bytes);
    assert_eq!(declined.report.skipped.len(), 1);
    assert_eq!(
        declined.report.declined_checks(),
        BTreeSet::from([RuntimeCheck::IsDebuggerPresent])
    );
}

#[test]
fn the_clean_control_yields_an_empty_plan_with_no_refusals() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime-clean");
    let (exe, bytes): (PathBuf, Vec<u8>) =
        compile(&gcc, "clean_control.c", false, &[], scratch.path());
    let plan: NeutralizationPlan = plan_of(&bytes);
    assert!(
        plan.is_empty() && plan.refusals.is_empty(),
        "benign timer use must not be planned: {:#?} {:#?}",
        plan.patches,
        plan.refusals
    );
    assert_eq!(
        result_line(&run(&exe), "clean_control"),
        "check=clean_control result=clean"
    );
}

#[test]
fn detect_only_fixtures_are_refused_by_name_and_never_patched() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime-detect");
    for fixture in DETECT_ONLY {
        let (exe, bytes): (PathBuf, Vec<u8>) =
            compile(&gcc, fixture.file, false, &[], scratch.path());
        let plan: NeutralizationPlan = plan_of(&bytes);
        assert!(
            plan.refusals
                .iter()
                .any(|r| r.check == fixture.refused && !r.reason.is_empty()),
            "{}: expected a named refusal for {:?}: {:#?}",
            fixture.file,
            fixture.refused,
            plan.refusals
        );
        assert!(
            plan.patches
                .iter()
                .all(|p: &Patch| p.check != fixture.refused),
            "{}: detect-only checks are never patched",
            fixture.file
        );
        let stem: &str = fixture.file.trim_end_matches(".c");
        assert!(
            run(&exe).contains(&format!("check={stem} result=clean")),
            "{stem} runs clean on this host"
        );
    }
}

fn finding(report: &AntiAnalysisReport, technique: Technique) -> Option<&AntiAnalysisFinding> {
    report
        .findings
        .iter()
        .find(|f: &&AntiAnalysisFinding| f.technique == technique && f.detected)
}

#[test]
fn the_core_scan_attributes_the_anti_dump_program_and_not_the_control() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime-dump");
    let (exe, bytes): (PathBuf, Vec<u8>) = compile(&gcc, "anti_dump.c", false, &[], scratch.path());
    let report: AntiAnalysisReport = scan(&bytes, Some("anti_dump.exe"));
    let dump: &AntiAnalysisFinding = finding(&report, Technique::AntiDump)
        .expect("anti-dump attributed on the authored program");
    assert!(
        dump.evidence
            .iter()
            .any(|e: &String| e.contains("SizeOfImage") || e.contains("mapped header")),
        "{dump:?}"
    );
    assert!(run(&exe).contains("header_erased=1"));

    let (_, clean): (PathBuf, Vec<u8>) =
        compile(&gcc, "clean_control.c", false, &[], scratch.path());
    let clean_report: AntiAnalysisReport = scan(&clean, Some("clean_control.exe"));
    assert!(
        finding(&clean_report, Technique::AntiDump).is_none(),
        "{:#?}",
        clean_report.findings
    );
}

#[test]
fn the_core_scan_names_the_instruction_level_checks_and_stays_quiet_on_the_control() {
    let gcc: String = require_gcc();
    let scratch: ScratchDir = scratch_dir("disrobe-anti-runtime-core");
    for (file, technique, needle) in [
        (
            "peb_being_debugged.c",
            Technique::AntiDebug,
            "beingdebugged",
        ),
        ("peb_nt_global_flag.c", Technique::AntiDebug, "ntglobalflag"),
        ("int2d_trap.c", Technique::AntiDebug, "int 2d"),
    ] {
        let (_, bytes): (PathBuf, Vec<u8>) = compile(&gcc, file, false, &[], scratch.path());
        let report: AntiAnalysisReport = scan(&bytes, Some(file));
        let f: &AntiAnalysisFinding = finding(&report, technique).unwrap_or_else(|| {
            panic!(
                "{file}: {technique:?} must be detected: {:#?}",
                report.findings
            )
        });
        assert!(
            f.evidence.iter().any(|e: &String| e.contains(needle)),
            "{file}: evidence must cite {needle}: {f:?}"
        );
    }
    let (_, clean): (PathBuf, Vec<u8>) =
        compile(&gcc, "clean_control.c", false, &[], scratch.path());
    let report: AntiAnalysisReport = scan(&clean, Some("clean_control.exe"));
    assert!(
        !report.any_detected(),
        "the control carries no detected technique: {:#?}",
        report.findings
    );
}
